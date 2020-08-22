package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/cheggaaa/pb"
	badger "github.com/dgraph-io/badger/v2"
	"github.com/elastic/gosigar"
	"github.com/kelseyhightower/envconfig"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/message"
)

// Config is loaded from environment. See .env file
type Config struct {
	RoDbHost          string `envconfig:"BH_RO_DB_HOST"`
	RoDbPort          int    `envconfig:"BH_RO_DB_PORT"`
	RoDbUser          string `envconfig:"BH_RO_DB_USER"`
	RoDbPassword      string `envconfig:"BH_RO_DB_PASSWORD"`
	RwDbHost          string `envconfig:"BH_RW_DB_HOST"`
	RwDbPort          int    `envconfig:"BH_RW_DB_PORT"`
	RwDbUser          string `envconfig:"BH_RW_DB_USER"`
	RwDbPassword      string `envconfig:"BH_RW_DB_PASSWORD"`
	DbName            string `envconfig:"BH_DB_NAME"`
	HistoryTableName  string `envconfig:"BH_DB_HISTORY_TABLE_NAME"`
	HistoryTableRows  uint64 `envconfig:"BH_DB_HISTORY_TABLE_ROWS"`
	NumQueueWorkers   int    `envconfig:"BH_NUM_QUEUE_WORKERS"`
	QueueFeedLimit    uint64 `envconfig:"BH_QUEUE_FEED_LIMIT"`
	QueueBuffer       uint64 `envconfig:"BH_QUEUE_BUFFER"`
	NumCleanupWorkers int    `envconfig:"BH_NUM_CLEANUP_WORKERS"`
	CleanupBuffer     int    `envconfig:"BH_CLEANUP_BUFFER"`
	MbiHashPepper     string `envconfig:"BH_MBI_HASH_PEPPER"`
	MbiHashIterations int    `envconfig:"BH_MBI_HASH_ITERATIONS"`
	MbiHashLength     int    `envconfig:"BH_MBI_HASH_LENGTH"`
}

// queueBatch represents the sql our queue workers will process to find unique bene id's
// e.g., 'select foo from bigtable offset 1000 limit 1000'. The limit (how many rows per
// batch to process) is configured via the environment variable BH_QUEUE_FEED_LIMIT. The
// offset is used as a sort of pagination.
type queueBatch struct {
	Offset uint64 `json:"offset"`
	Limit  uint64 `json:"limit"`
}

// default number of workers adding benes to the queue. (keep this small to reduce lock contention in badger)
const numQueueWorkersDefault = 3

// queue query pattern
const queuePattern = "SELECT \"beneficiaryId\" FROM \"BeneficiariesHistory\" OFFSET $1 LIMIT $2 ;"

// delete query pattern
const deletePattern = `WITH x AS (SELECT "beneficiaryHistoryId" FROM (SELECT
	"beneficiaryHistoryId",
 	ROW_NUMBER() OVER(PARTITION BY 
 	"beneficiaryId", 
 	"birthDate", 
 	hicn, 
 	sex, 
 	"hicnUnhashed", 
 	"medicareBeneficiaryId",
 	"mbiHash"
 	ORDER BY "beneficiaryHistoryId" asc) AS row
FROM
 "BeneficiariesHistory" t1
WHERE
 t1."beneficiaryId" = $1
) dups 
WHERE dups.row > 1)
DELETE FROM "BeneficiariesHistory" WHERE "beneficiaryId" = $1 AND "beneficiaryHistoryId" IN (SELECT "beneficiaryHistoryId" FROM x)`

// mbi hash select pattern
const mbiHashSelector = `SELECT "beneficiaryHistoryId" FROM "BeneficiariesHistory" WHERE "beneficiaryId" = $1 AND "mbiHash" IS NULL`

// mbi hash update pattern
const updateHashPattern = `UPDATE "BeneficiariesHistory" SET "mbiHash" = $1 WHERE "beneficiaryHistoryId" = $2`

// gets the current amount of "actual" free memory.
func freeMem() gosigar.Mem {
	mem := gosigar.Mem{}
	mem.Get()
	return mem
}

// convert bytes to mb
func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

// badger read operation. Sets v to the value of k
func badgerRead(b *badger.DB, k []byte, v []byte) error {
	err := b.View(func(txn *badger.Txn) error {
		bi, err := txn.Get(k)
		if bi.ValueSize() > 0 {
			// the key was found and has a value, fetch the value and update v
			if _, err := bi.ValueCopy(v); err != nil {
				return err
			}
		}
		return err
	})
	return err
}

// badger write k with v
func badgerWrite(b *badger.DB, k []byte, v []byte) (bool, error) {
	err := b.Update(func(txn *badger.Txn) error {
		err := txn.Set(k, v)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return true, err
}

// return true if key exists
func badgerCheck(b *badger.DB, k []byte) (bool, error) {
	err := b.View(func(txn *badger.Txn) error {
		_, err := txn.Get(k)
		return err
	})
	switch {
	case err == badger.ErrKeyNotFound:
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

func badgerCloseHandler(queue *badger.DB) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("closing badger.")
		if err := queue.Close(); err != nil {
			os.Exit(1)
		} else {
			os.Exit(0)
		}
	}()
}

// hashes mbi using PBKDF2-HMAC-SHA256 and sets *hashedMBI to the result
func hashMBI(mbi []byte, hashedMBI *string, cfg *Config) error {
	// decode the pepper from hex
	pepper, err := hex.DecodeString(cfg.MbiHashPepper)
	if err != nil {
		return err
	}

	// hash the mbi and set *hashedMbi to the result
	tmp := pbkdf2.Key(mbi, pepper, cfg.MbiHashIterations, cfg.MbiHashLength, sha256.New)
	*hashedMBI = fmt.Sprintf("%x", string(tmp))
	return nil
}

// test hashing function
func testHash(testmbi string, expected string, cfg *Config) bool {
	beneMbi := []byte(testmbi)
	var mbiHash string
	hashMBI(beneMbi, &mbiHash, cfg)
	result := mbiHash == expected
	return result
}

// searches the history table for unique benes to add to the queue
func queueWorker(id int, db *sql.DB, queue *badger.DB, batches <-chan *queueBatch, wg *sync.WaitGroup, logger *log.Logger, rowsLeft *uint64, feedLimit uint64) {

	// poll the channel for batches to process
	for qry := range batches {
		// create new instance of qry to ensure it's unique in each goroutine
		qry := qry

		// execute the batch query
		rows, err := db.Query(queuePattern, qry.Offset, qry.Limit)
		if err != nil {
			log.Fatal(err)
		}

		// parse the results
		var benecount int32
		var skipcount int32
		for rows.Next() {
			var beneid string
			_ = rows.Scan(&beneid)

			// check if bene is in the queue.. add them if not
			exists, _ := badgerCheck(queue, []byte(beneid))
			if exists != true {
				added, err := badgerWrite(queue, []byte(beneid), nil)
				if added != true {
					logger.Fatal(err)
				}
				benecount++
			} else {
				skipcount++
			}
		}

		// close the sql rows and update our progress
		rows.Close()
		*rowsLeft -= feedLimit

		// log the current memory stats after each batch
		mem := freeMem()
		fmt.Printf("added %v benes - current mem used (MB): %v mem free (MB): %v\n", benecount, bToMb(mem.ActualUsed), bToMb(mem.ActualFree))

		// admin
		queue.Sync() // sync badger to disk after each batch
		runtime.GC() // force garbage collection

		// back off if needed
		mem = freeMem()
		if bToMb(mem.ActualFree) < 512 {
			logger.Println("backing off due to low memory")
			time.Sleep(time.Minute)
		}
	}

	// when there no more batches to process, close this worker
	wg.Done()
}

// builds (or continues building) the queue of bene id's
func buildQueue(queue *badger.DB, cfg *Config, logger *log.Logger) {
	// postgres - (use reader db settings)
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", cfg.RoDbHost, cfg.RoDbPort, cfg.RoDbUser, cfg.RoDbPassword, cfg.DbName)
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		logger.Fatal(err)
	}
	defer db.Close()

	// test the connection
	if err = db.Ping(); err != nil {
		logger.Fatal(err)
	}
	fmt.Printf("connected to %v.\n", cfg.RoDbHost)
	fmt.Println("building the queue.")

	// get the size of the history table
	var bhRowCount uint64
	if cfg.HistoryTableRows > 0 {
		// row count was manually set, use it
		bhRowCount = cfg.HistoryTableRows
	} else {
		// grab an estimated row count (doing a 'select count(*) from' query on the history table can take 25 minutes or more to run)
		row := db.QueryRow("SELECT reltuples::bigint AS ct FROM pg_class WHERE oid = 'public.\"BeneficiariesHistory\"'::regclass;")
		if err := row.Scan(&bhRowCount); err != nil {
			logger.Fatal(err)
		}
	}

	// dynamically set the number of rows to process based on free memory
	var feedLimit uint64
	if cfg.QueueFeedLimit > 0 {
		// was set via env
		feedLimit = cfg.QueueFeedLimit
	} else {
		// dynamic
		mem := freeMem()
		feedLimit = (mem.ActualFree / 64) //swag
	}
	if feedLimit > bhRowCount {
		feedLimit = bhRowCount
	}
	rowsLeft := bhRowCount
	logger.Printf("setting feed limit to %v rows.\n", feedLimit)

	// determine how many workers to use
	var numQueueWorkers int
	if cfg.NumQueueWorkers > 0 {
		numQueueWorkers = cfg.NumQueueWorkers
	} else {
		numQueueWorkers = runtime.NumCPU()
	}

	// spin up the workers
	var queueChan = make(chan *queueBatch, cfg.QueueBuffer)
	fmt.Println("preparing workers.")
	var wg sync.WaitGroup
	var i int
	for i = 0; i < numQueueWorkers; i++ {
		wg.Add(1)
		go queueWorker(i, db, queue, queueChan, &wg, logger, &rowsLeft, feedLimit)
	}

	// send workers batches to process
	fmt.Println("scanning the history table for benes.")
	var offset uint64
	for counter := uint64(0); counter < bhRowCount; counter += feedLimit {
		qb := queueBatch{offset, feedLimit}
		queueChan <- &qb
		offset += feedLimit
	}
	close(queueChan)

	// wait for the workers to finish
	wg.Wait()
}

func cleanupWorker(id int, queue *badger.DB, beneChan <-chan *badger.Item, db *sql.DB, logger *log.Logger, beneDoneChan chan<- bool) {
	for bene := range beneChan {
		bene := bene
		beneid := bene.Key()

		// check if we have already processed this bene
		completed := false
		if err := bene.Value(func(v []byte) error {
			if len(v) > 0 {
				completed = true
			}
			return nil
		}); err != nil {
			logger.Fatal(err)
		}

		// skip if we have
		if completed == true {
			continue
		}

		// else, delete dups
		_, err := db.Exec(deletePattern, beneid)
		if err != nil {
			logger.Fatal(err)
		}

		// TODO: update mbi hash

		// mark as completed
		ok, _ := badgerWrite(queue, beneid, []byte("1"))
		if ok {
			logger.Println(beneid)
			beneDoneChan <- true
		} else {
			logger.Println("error updating ", beneid)
		}

		// update stats
		// atomic.AddUint64(doneCounter, 1)

		// back off if low on free mem
		mem := freeMem()
		if bToMb(mem.ActualFree) < 128 {
			// force garbage collection and sleep for a few seconds
			runtime.GC()
			logger.Println("backing off due to low memory")
			time.Sleep(time.Duration(rand.Intn(60)) * time.Second)
		}

		// logger.Printf("processed bene %v\n", string(beneid))
	}
}

// manages the processing of the queue (deleting duplicates, updating badger, etc)
func processQueue(queue *badger.DB, cfg *Config, logger *log.Logger, beneDoneChan chan<- bool) {

	// postgres - (use reader db settings)
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", cfg.RwDbHost, cfg.RwDbPort, cfg.RwDbUser, cfg.RwDbPassword, cfg.DbName)
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		logger.Fatal(err)
	}
	defer db.Close()

	// test the connection
	if err = db.Ping(); err != nil {
		logger.Fatal(err)
	}
	fmt.Printf("connected to %v.\n", cfg.RwDbHost)

	// determine how many workers to use
	var numCleanupWorkers int
	if cfg.NumQueueWorkers > 0 {
		numCleanupWorkers = cfg.NumCleanupWorkers
	} else {
		numCleanupWorkers = runtime.NumCPU()
	}

	// set buffer value
	var cleanupBuffer int
	if cfg.CleanupBuffer > 1 {
		cleanupBuffer = cfg.CleanupBuffer
	} else {
		cleanupBuffer = 1
	}

	// launch the cleanup workers
	fmt.Printf("spawning %v cleanup workers.\n", numCleanupWorkers)
	var beneChan = make(chan *badger.Item, cleanupBuffer)
	var wg sync.WaitGroup
	var i int
	for i = 0; i < numCleanupWorkers; i++ {
		wg.Add(1)
		go cleanupWorker(i, queue, beneChan, db, logger, beneDoneChan)
	}

	// loop through all the keys and send incompletes to workers for processing
	err = queue.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			if !(it.Item().ValueSize() > 0) {
				bene := it.Item()
				beneChan <- bene
			}
		}
		return nil
	})
	if err != nil {
		logger.Fatal(err)
	}
	wg.Wait()
}

func main() {

	// custom error logger with date and time
	logger := log.New(os.Stderr, "", log.Ldate|log.Ltime)

	// load app settings from environment
	var cfg Config
	err := envconfig.Process("BH_", &cfg)
	if err != nil {
		logger.Fatal(err)
	}

	// test hashing function
	fmt.Println("testing hashing function.")
	var testCfg Config
	testCfg.MbiHashIterations = 1000
	testCfg.MbiHashLength = 32
	testCfg.MbiHashPepper = hex.EncodeToString([]byte("nottherealpepper"))
	t1Start := time.Now()
	t1 := testHash("123456789A", "d95a418b0942c7910fb1d0e84f900fe12e5a7fd74f312fa10730cc0fda230e9a", &testCfg)
	t1Duration := time.Since(t1Start)
	t2Start := time.Now()
	t2 := testHash("987654321E", "6357f16ebd305103cf9f2864c56435ad0de5e50f73631159772f4a4fcdfe39a5", &testCfg)
	t2Duration := time.Since(t2Start)
	if !t1 || !t2 {
		logger.Fatal("error testing hashing function")
	}
	var hashCost time.Duration
	hashCost = ((t1Duration + t2Duration) / 2)
	hashPerMil := hashCost * 1000000
	fmt.Printf("mbi hashing will add ~ %v seconds per bene (around %v per million)\n", hashCost.Seconds(), fmt.Sprintf("%s", hashPerMil))

	// parse flags
	buildQueueFlag := flag.Bool("build-queue", false, "build the queue")
	processQueueFlag := flag.Bool("process-queue", false, "process the queue (delete dups)")
	flag.Parse()

	// exit if no flag was set
	if *buildQueueFlag != true && *processQueueFlag != true {
		fmt.Println("nothing to do.")
		flag.Usage()
		os.Exit(1)
	}

	// badger steals stdout/err breaking progress bars.. let's prevent that by passing it a pipe instead
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		logger.Fatal(err)
	}
	os.Stdout = w

	stdOutChan := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		stdOutChan <- buf.String()
	}()

	queue, err := badger.Open(badger.DefaultOptions("dup.queue"))
	if err != nil {
		logger.Fatal(err)
	}
	defer queue.Close()
	badgerCloseHandler(queue)

	// close the pipe and go back to normal stdout. badger really only writes to stderr anyway.
	w.Close()
	os.Stdout = oldStdout
	<-stdOutChan //just ignore

	// build the queue
	if *buildQueueFlag {
		buildQueue(queue, &cfg, logger)
	}

	// get/display queue status
	var qCount uint64
	var doneCount uint64
	err = queue.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			if it.Item().ValueSize() > 0 {
				doneCount++
			}
			qCount++
		}
		return nil
	})
	if err != nil {
		logger.Fatal(err)
	}
	numBenesToProcess := (qCount - doneCount)
	p := message.NewPrinter(message.MatchLanguage("en")) // used to print numbers with comma's
	p.Printf("queue stats: %v bene's in queue - %v completed - %v remain.\n", qCount, doneCount, numBenesToProcess)

	// progress bar
	count := int64(numBenesToProcess)
	bar := pb.New64(count)
	beneDoneChan := make(chan bool)
	barStart := false
	bar.ShowPercent = true
	bar.ShowBar = true
	bar.ShowCounters = true
	bar.ShowTimeLeft = true
	go func() {
		for <-beneDoneChan {
			if barStart {
				bar.Increment()
			} else {
				bar.Start()
				barStart = true
			}
		}
	}()

	// process the queue
	if *processQueueFlag == true {
		fmt.Println("processing the queue.")
		processQueue(queue, &cfg, logger, beneDoneChan)
	}
	bar.FinishPrint("complete.")

}
