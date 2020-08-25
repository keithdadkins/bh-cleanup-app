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
	BeneTableRows     uint64 `envconfig:"BH_DB_BENE_TABLE_ROWS"`
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

// row count pattern
const rowCountPattern = `SELECT count(*)  FROM "Beneficiaries";`

// queue query pattern
const queuePattern = `SELECT "beneficiaryId" FROM "Beneficiaries" OFFSET $1 LIMIT $2 ;`

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

// missing mbi hash pattern
const missingMbiPattern = `SELECT "beneficiaryHistoryId", "medicareBeneficiaryId" FROM "BeneficiariesHistory" WHERE "beneficiaryId" = $1 AND "mbiHash" IS NULL AND "medicareBeneficiaryId" IS NOT NULL`
const missingMbiCountPattern = `SELECT count(*) FROM "BeneficiariesHistory" WHERE "beneficiaryId" = $1 AND "mbiHash" IS NULL AND "medicareBeneficiaryId" IS NOT NULL`

// update missing hash pattern
const updateHashPattern = `UPDATE "BeneficiariesHistory" SET "mbiHash" = $1 WHERE "beneficiaryId" = $2 AND "beneficiaryHistoryId" = $3`

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

// trap ctl-c, kill, etc and try to gracefully close badger
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

	// get number of benes we are processing
	var beneRowCount uint64
	if cfg.BeneTableRows > 0 {
		// row count was manually set, use it
		beneRowCount = cfg.BeneTableRows
	} else {
		// get the row count
		row := db.QueryRow(rowCountPattern)
		if err := row.Scan(&beneRowCount); err != nil {
			logger.Panicln("error getting bene row count")
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
	if feedLimit > beneRowCount {
		feedLimit = beneRowCount
	}
	rowsLeft := beneRowCount
	logger.Printf("setting feed limit to %v rows.\n", feedLimit)

	// determine how many workers to use
	var numQueueWorkers int
	if cfg.NumQueueWorkers > 0 {
		numQueueWorkers = cfg.NumQueueWorkers
	} else {
		numQueueWorkers = runtime.NumCPU()
	}

	// progress bar
	numBatches := beneRowCount / feedLimit
	count := int(numBatches)
	bar := pb.New(count)
	batchDoneChan := make(chan bool)
	barStart := false
	bar.ShowPercent = true
	bar.ShowBar = true
	bar.ShowCounters = false
	bar.ShowTimeLeft = true
	go func() {
		for <-batchDoneChan {
			if barStart {
				bar.Increment()
			} else {
				bar.Start()
				barStart = true
			}
		}
	}()

	// spin up the workers
	var queueChan = make(chan *queueBatch, cfg.QueueBuffer)
	logger.Printf("launching %v workers.\n", numQueueWorkers)
	var wg sync.WaitGroup
	var i int
	for i = 0; i < numQueueWorkers; i++ {
		wg.Add(1)
		go queueWorker(i, db, queue, queueChan, &wg, logger, &rowsLeft, feedLimit, batchDoneChan)
	}

	// send workers batches to process
	fmt.Println("adding benes to the queue.")
	var offset uint64
	for counter := uint64(0); counter < beneRowCount; counter += feedLimit {
		qb := queueBatch{offset, feedLimit}
		queueChan <- &qb
		offset += feedLimit
	}
	close(queueChan)

	// wait for the workers to finish
	wg.Wait()
	bar.FinishPrint("complete.")
}

// searches the history table for unique benes to add to the queue
func queueWorker(id int, db *sql.DB, queue *badger.DB, batches <-chan *queueBatch, wg *sync.WaitGroup, logger *log.Logger, rowsLeft *uint64, feedLimit uint64, batchDoneChan chan<- bool) {

	// poll the channel for batches to process
	for qry := range batches {
		// create new instance of qry to ensure it's unique in each goroutine
		qry := qry

		// execute the batch query
		rows, err := db.Query(queuePattern, qry.Offset, qry.Limit)
		defer rows.Close()
		if err != nil {
			logger.Println("error fetching query batch")
			logger.Fatal(err)
		}

		txn := queue.NewTransaction(true)
		defer txn.Discard()

		// parse the results
		for rows.Next() {
			var beneid string
			_ = rows.Scan(&beneid)
			_ = txn.Set([]byte(beneid), nil)
		}
		txn.Commit()

		*rowsLeft -= feedLimit
		batchDoneChan <- true
	}

	// when there no more batches to process, close this worker
	wg.Done()
}

// runs cleanup workers for each bene in the queue
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
		go cleanupWorker(i, queue, beneChan, db, logger, cfg, beneDoneChan)
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
		logger.Println("error sending benes to cleanup")
		logger.Fatal(err)
	}
	wg.Wait()
}

func cleanupWorker(id int, queue *badger.DB, beneChan <-chan *badger.Item, db *sql.DB, logger *log.Logger, cfg *Config, beneDoneChan chan<- bool) {
	for bene := range beneChan {
		bene := bene
		beneid := bene.Key()

		// check if we have already processed this bene, skip if so
		completed := false
		if err := bene.Value(func(v []byte) error {
			if len(v) > 0 {
				completed = true
			}
			return nil
		}); err != nil {
			logger.Println("error fetching bene from badger - ", string(beneid))
			logger.Fatal(err)
		}
		if completed == true {
			continue
		}

		// delete any dups
		txn, err := db.Begin()
		if err != nil {
			fmt.Println("error connecting to db to delete dups")
			logger.Fatal(err)
		}
		_, err = txn.Exec(deletePattern, beneid)
		if err != nil {
			txn.Rollback()
			logger.Println("error deleting dups for ", string(beneid))
			logger.Fatal(err)
		}
		txn.Commit()

		// check for missing mbi hashes, skip if none
		var missingRowCount int
		row := db.QueryRow(missingMbiCountPattern, string(beneid))
		if err := row.Scan(&missingRowCount); err != nil {
			fmt.Println("error fetching missing row count")
			logger.Fatal(err)
		}
		if missingRowCount < 1 {
			continue
		}

		// grab the records with missing hashes
		rows, err := db.Query(missingMbiPattern, string(beneid))
		defer rows.Close()
		if err != nil {
			logger.Println("error querying missing mbi hashes for ", string(beneid))
			logger.Fatal(err)
		}

		for rows.Next() {
			// hash the mbi
			var beneHistoryID string
			var mbi string
			var mbiHash string
			rows.Scan(&beneHistoryID, &mbi)
			if err := hashMBI([]byte(mbi), &mbiHash, cfg); err != nil {
				logger.Printf("error hashing mbi for %v bh id %v\n", string(beneid), beneHistoryID)
				logger.Fatal(err)
			}

			// update the record
			txn, err := db.Begin()
			if err != nil {
				fmt.Println("error connecting to db to update mbi hash")
				logger.Fatal(err)
			}
			results, err := txn.Exec(updateHashPattern, mbiHash, beneid, beneHistoryID)
			if err != nil {
				txn.Rollback()
				logger.Printf("error executing query bene %v's bh history entry %v\n", string(beneid), beneHistoryID)
				logger.Fatal(err)
			}
			_, err = results.RowsAffected()
			if err != nil {
				fmt.Println("error getting RowsAffected")
				txn.Rollback()
				logger.Fatal(err)
			}
			txn.Commit()
		}

		// mark bene as completed
		ok, _ := badgerWrite(queue, beneid, []byte("1"))
		if ok {
			beneDoneChan <- true
		}
	}
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

	// parse flags
	buildQueueFlag := flag.Bool("build-queue", false, "build the queue")
	processQueueFlag := flag.Bool("process-queue", false, "process the queue")
	flag.Parse()

	// exit if no flag was set
	if *buildQueueFlag != true && *processQueueFlag != true {
		fmt.Println("nothing to do.")
		flag.Usage()
		os.Exit(1)
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
	fmt.Printf("mbi hashing will add ~ %v seconds per bene to process (around %v per million)\n", hashCost.Seconds(), fmt.Sprintf("%s", hashPerMil))

	// badger steals stdout/err breaking progress bars.. let's prevent that by passing it a pipe instead
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		logger.Fatal(err)
	}
	os.Stdout = w

	// send stdout to buffer
	stdOutChan := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		stdOutChan <- buf.String()
	}()

	// open badger db
	queue, err := badger.Open(badger.DefaultOptions("cleanup.queue"))
	if err != nil {
		logger.Fatal(err)
	}
	defer queue.Close()
	badgerCloseHandler(queue)

	// close the pipe and go back to normal stdout. badger really only writes to stderr anyway.
	w.Close()
	os.Stdout = oldStdout
	<-stdOutChan //so just ignore

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
	bar.ShowCounters = false
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
