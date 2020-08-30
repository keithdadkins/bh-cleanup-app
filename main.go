package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cheggaaa/pb"
	badger "github.com/dgraph-io/badger/v2"
	"github.com/elastic/gosigar"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/kelseyhightower/envconfig"
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
	DbMaxConns        int    `envconfig:"BH_DB_MAX_CONNS"`
	HistoryTableName  string `envconfig:"BH_DB_HISTORY_TABLE_NAME"`
	HistoryTableRows  uint64 `envconfig:"BH_DB_HISTORY_TABLE_ROWS"`
	BeneTableRows     uint64 `envconfig:"BH_DB_BENE_TABLE_ROWS"`
	NumQueueWorkers   int    `envconfig:"BH_NUM_QUEUE_WORKERS"`
	QueueFeedLimit    uint64 `envconfig:"BH_QUEUE_FEED_LIMIT"`
	QueueBuffer       uint64 `envconfig:"BH_QUEUE_BUFFER"`
	NumDupWorkers     int    `envconfig:"BH_NUM_DUP_WORKERS"`
	DupBuffer         int    `envconfig:"BH_DUP_BUFFER"`
	NumMbiHashWorkers int    `envconfig:"BH_MBI_NUM_HASH_WORKERS"`
	MbiHashBuffer     int    `envconfig:"BH_MBI_HASH_BUFFER"`
	MbiHashPepper     string `envconfig:"BH_MBI_HASH_PEPPER"`
	MbiHashIterations int    `envconfig:"BH_MBI_HASH_ITERATIONS"`
	MbiHashLength     int    `envconfig:"BH_MBI_HASH_LENGTH"`
}

// queueBatch represents the sql our queue workers will process to find unique bene id's
// e.g., 'select foo from bigtable offset 1000 limit 1000'. The limit (how many rows per
// batch to process) is configured via the environment variable BH_QUEUE_FEED_LIMIT. The
// offset is used as a sort of pagination.
type queueBatch struct {
	Offset uint64
	Limit  uint64
}

type beneEntry struct {
	key   []byte
	value []byte
}

// return the key as a string
func (b beneEntry) Key() string {
	return string(b.key)
}

// return the value as a string
func (b beneEntry) Value() string {
	return string(b.value)
}

// default number of workers adding benes to the queue. (keep this small to reduce lock contention in badger)
const numQueueWorkersDefault = 3

// queue query pattern (gets the bene id's into a local queue for later processing)
const queuePattern = `SELECT "beneficiaryId" FROM "Beneficiaries" "beneficiaryId" ORDER BY "beneficiaryId" OFFSET $1 LIMIT $2 ;`

// row count pattern. assumption here is that there is a one->many relation between bene and bene history table
// if there are benes in the history table that are not in the bene table, change 'FROM "Beneficiaries"' to
// 'FROM "BeneficiariesHistory"'. This will *GREATLY* increase the time to build the queue however.
const rowCountPattern = `SELECT count(*) FROM "Beneficiaries";`

// delete query pattern - this takes advantage of indexes and 'ROW_NUMBER OVER PARTITION' pattern to make this query
// very fast.
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
		item, err := txn.Get(k)
		if err != nil {
			return err
		}
		var value []byte
		err = item.Value(func(val []byte) error {
			v = value
			return nil
		})
		return err
	})
	return err
}

// badger write k with v.
func badgerWrite(b *badger.DB, k []byte, v []byte) (bool, error) {
	txn := b.NewTransaction(true)
	defer txn.Discard()
	if err := txn.Set(k, v); err == badger.ErrTxnTooBig {
		fmt.Printf(".")
		if err := txn.Commit(); err != nil {
			return false, err
		}
		txn = b.NewTransaction(true)
		if err := txn.Commit(); err != nil {
			return false, err
		}
	}
	txn.Commit()
	return true, nil
}

// returns number of benes in the queue, dedups completed, mbi completed, and an error (nil if success)
func badgerStatus(b *badger.DB) (qCount uint64, dupCount uint64, mbiCount uint64, err error) {
	// get/display queue status
	err = b.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			var status string
			err := item.Value(func(v []byte) error {
				status = string(v)
				return nil
			})
			if err != nil {
				return err
			}
			switch status {
			case "1":
				dupCount++
			case "2":
				mbiCount++
			case "3":
				dupCount++
				mbiCount++
			}
			qCount++
		}
		return nil
	})
	if err != nil {
		dupCount, mbiCount, qCount = 0, 0, 0
		return dupCount, mbiCount, qCount, err
	}
	return qCount, dupCount, mbiCount, err
}

// trap ctl-c, kill, etc and try to gracefully close badger (50/50 chance this will work, so try to let jobs finish and do not count on this.)
// TODO: could use context package to gracefully handle it
func badgerCloseHandler(queue *badger.DB) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Printf("closing badger.\n")
		if err := queue.Close(); err != nil {
			// backoff and try again
			time.Sleep(time.Second * 5)
			if err = queue.Close(); err != nil {
				os.Exit(1)
			}
		}
		os.Exit(0)
	}()
}

// returns the total number of benes that should be in the queue
func getTotalBenes(db *pgxpool.Pool, logger *log.Logger, cfg *Config) (uint64, error) {
	var totalBenes uint64
	if cfg.BeneTableRows > 0 {
		// row count was manually set via env vars, use it
		totalBenes = uint64(cfg.BeneTableRows)
	} else {
		row := db.QueryRow(context.Background(), rowCountPattern)
		if err := row.Scan(&totalBenes); err != nil {
			logger.Println("error getting bene row count")
			return 0, err
		}
	}
	return totalBenes, nil
}

// builds (or continues building) the queue of bene id's
func buildQueue(db *pgxpool.Pool, queue *badger.DB, cfg *Config, logger *log.Logger) error {
	fmt.Println("building the queue.")
	var totalBenes uint64
	totalBenes, err := getTotalBenes(db, logger, cfg)
	if err != nil {
		return err
	}
	entryCount, _, _, err := badgerStatus(queue)
	if err != nil {
		fmt.Println("error getting queue stats")
		return err
	}
	numLeft := totalBenes - entryCount

	// determine how many workers to use
	var numQueueWorkers int
	if cfg.NumQueueWorkers > 0 {
		numQueueWorkers = cfg.NumQueueWorkers
	} else {
		numQueueWorkers = runtime.NumCPU()
	}

	// set feed limit
	var feedLimit uint64
	if cfg.QueueFeedLimit > 0 {
		// was set via env os use it
		feedLimit = cfg.QueueFeedLimit
	} else {
		// dynamically based on free meme, but don't go nuts
		mem := freeMem()
		feedLimit = (mem.ActualFree / 1000) / uint64(numQueueWorkers)
		if feedLimit < 1 {
			feedLimit = 1
		}
	}

	// fixup if limit is > num rows
	if feedLimit > totalBenes {
		feedLimit = totalBenes
	}

	// we do not need more workers than batches
	numBatches := totalBenes / feedLimit
	if uint64(numQueueWorkers) > numBatches {
		numQueueWorkers = int(numBatches)
	}

	// progress bar
	count := int64(numLeft)
	bar := pb.New64(count)
	batchDoneChan := make(chan int64)
	barStart := false
	bar.ShowPercent = true
	bar.ShowBar = true
	bar.ShowCounters = false
	bar.ShowTimeLeft = false
	bar.ShowElapsedTime = true
	go func() {
		for num := range batchDoneChan {
			if barStart == false {
				bar.Start()
				barStart = true
			}
			bar.Add64(num)
			numLeft -= uint64(num)
		}
	}()

	// spin up the workers
	var queueChan = make(chan *queueBatch, cfg.QueueBuffer)
	fmt.Printf("launching %v workers.\n", numQueueWorkers)
	var wg sync.WaitGroup
	for i := 0; i < numQueueWorkers; i++ {
		wg.Add(1)
		go queueWorker(i, db, queue, queueChan, &wg, logger, &totalBenes, batchDoneChan)
	}

	// send workers batches to process
	fmt.Printf("adding benes to the queue.\n")
	var offset uint64
	for counter := uint64(0); counter < totalBenes; counter += feedLimit {
		qb := queueBatch{offset, feedLimit}
		queueChan <- &qb
		offset += feedLimit
	}
	close(queueChan)

	// wait for the workers to finish
	wg.Wait()
	bar.Set64(count)
	bar.Finish()

	// verify
	fmt.Println("verifying.")
	queue.RunValueLogGC(0.5)
	entryCount, _, _, err = badgerStatus(queue)
	if err != nil {
		fmt.Println("error getting queue stats")
		return err
	}
	p := message.NewPrinter(message.MatchLanguage("en")) // used to pretty print numbers
	p.Printf("queue stats: %v benes of %v in the queue.\n", entryCount, totalBenes)
	numLeft = totalBenes - entryCount
	if numLeft > 0 {
		fmt.Printf("%v benes were missed. replaying.\n\n", numLeft)
		buildQueue(db, queue, cfg, logger)
	}
	fmt.Printf("done.\n\n")
	return nil
}

// adds benes to the queue
func queueWorker(id int, db *pgxpool.Pool, queue *badger.DB, batches <-chan *queueBatch, wg *sync.WaitGroup, logger *log.Logger, numLeft *uint64, batchDoneChan chan<- int64) {
	defer wg.Done()
	// poll the channel for batches to process
	for qry := range batches {
		// create a shadow instance of qry to ensure it's unique in each goroutine
		qry := qry

		// execute the batch query
		rows, err := db.Query(context.Background(), queuePattern, qry.Offset, qry.Limit)
		if err != nil {
			logger.Println("error fetching query batch")
			logger.Fatal(err)
		}
		defer rows.Close()

		// parse the results
		var benesToProcess []beneEntry
		var rowsDone int64
		for rows.Next() {
			var bene beneEntry
			err = rows.Scan(&bene.key)
			if err != nil {
				logger.Fatal(err)
			}
			err = badgerRead(queue, bene.key, bene.value)
			if err != nil {
				benesToProcess = append(benesToProcess, bene)
			}
		}
		rows.Close()

		// process the results
		txn := queue.NewTransaction(true)
		for _, bene := range benesToProcess {
			key := bene.key
			if err := txn.Set(key, nil); err == badger.ErrTxnTooBig {
				_ = txn.Commit()
				txn = queue.NewTransaction(true)
				_ = txn.Set(key, nil)
			}
			rowsDone++
		}
		if err := txn.Commit(); err != nil {
			logger.Println("error processing batch")
			logger.Fatal(err)
		}
		batchDoneChan <- rowsDone
	}
}

// run dedup process
func processDups(db *pgxpool.Pool, queue *badger.DB, cfg *Config, logger *log.Logger, dupCounter *uint64) error {
	// determine how many benes need to be processed
	qCount, doneCount, _, err := badgerStatus(queue)
	if err != nil {
		logger.Println("error getting queue status")
		return err
	}
	numLeft := qCount - doneCount

	// quit if done
	if numLeft < 1 {
		return nil
	}

	// determine how many workers to use
	var numDupWorkers int
	if cfg.NumDupWorkers > 0 {
		numDupWorkers = cfg.NumDupWorkers
	} else {
		numDupWorkers = runtime.NumCPU()
	}

	// set buffer value
	var dupBuffer int
	if cfg.DupBuffer > 1 {
		dupBuffer = cfg.DupBuffer
	} else {
		dupBuffer = 1
	}

	// setup progress bar
	count := int64(numLeft)
	bar := pb.New64(count)
	dupDoneChan := make(chan bool, 1)
	barStart := false
	bar.ShowPercent = true
	bar.ShowBar = true
	bar.ShowCounters = true
	bar.ShowTimeLeft = false
	go func() {
		for <-dupDoneChan {
			if barStart == false {
				bar.Start()
				barStart = true
			}
			bar.Increment()
		}
	}()

	// launch the dup workers
	fmt.Printf("spawning %v dedup workers.\n", numDupWorkers)
	var beneChan = make(chan *beneEntry, dupBuffer)
	var wg sync.WaitGroup
	for i := 0; i < numDupWorkers; i++ {
		wg.Add(1)
		go dupWorker(i, queue, beneChan, db, logger, cfg, dupDoneChan, dupCounter, &wg, &numLeft)
	}

	// run garbage collections and flush the queue to disk before we hammer it
	runtime.GC()
	queue.RunValueLogGC(0.5)
	fmt.Println("deduping.")
	err = queue.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			err := it.Item().Value(func(v []byte) error {
				status := string(v)
				if status == "" || status == "2" {
					var bene beneEntry
					bene.key = it.Item().KeyCopy(nil)
					bene.value = []byte(status)
					beneChan <- &bene
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		it.Close()
		return nil
	})
	if err != nil {
		logger.Println("error processing dups")
		return err
	}
	close(beneChan)
	wg.Wait()
	bar.Increment()
	finMsg := fmt.Sprintf("%v duplicates were deleted.", *dupCounter)
	bar.FinishPrint(finMsg)

	// make sure everyone was processed.. replay until they are.
	qCount, doneCount, _, err = badgerStatus(queue)
	if err != nil {
		return err
	}
	if (qCount - doneCount) != 0 {
		fmt.Printf("replaying missed benes.\n")
		processDups(db, queue, cfg, logger, dupCounter)
	}
	return nil
}

func dupWorker(id int, queue *badger.DB, beneChan <-chan *beneEntry, db *pgxpool.Pool, logger *log.Logger, cfg *Config, dupDoneChan chan<- bool, dupCounter *uint64, wg *sync.WaitGroup, numLeft *uint64) {
	defer wg.Done()
	for bene := range beneChan {
		bene := bene

		// grab a connection from the pool
		conn, err := db.Acquire(context.Background())
		if err != nil {
			logger.Println(err)
		}
		defer conn.Release()

		// delete the dups
		result, err := conn.Exec(context.Background(), deletePattern, bene.Key())
		if err != nil {
			logger.Printf("%v", err)
			logger.Printf("error deleting dups for %v.. skipping.\n", bene.Key())
			conn.Release()
			continue
		}
		rowsDeleted := result.RowsAffected()

		// update the bene
		var newStatus string
		if bene.Key() == "2" {
			newStatus = "3"
		} else {
			newStatus = "1"
		}
		ok, err := badgerWrite(queue, bene.key, []byte(newStatus))
		if !ok {
			conn.Release()
			logger.Println(err)
			continue
		}

		// update stats
		atomic.AddUint64(numLeft, ^uint64(0))
		if rowsDeleted > 0 {
			atomic.AddUint64(dupCounter, uint64(rowsDeleted))
		}

		// update progress
		dupDoneChan <- true
		conn.Release()
	}
}

func resetQueue(db *pgxpool.Pool, logger *log.Logger, queue *badger.DB, cfg *Config) error {
	fmt.Println("Warning! This will delete and rebuild the queue. Type 'yes' to continue.")
	var response string
	_, err := fmt.Scanln(&response)
	if err != nil {
		logger.Fatal(err)
	}
	switch strings.ToLower(response) {
	case "yes":
		fmt.Println("resetting.")
	default:
		fmt.Println("aborting.")
		os.Exit(0)
	}
	queue.DropAll()
	if err := buildQueue(db, queue, cfg, logger); err != nil {
		return err
	}
	queue.RunValueLogGC(1)
	return nil
}

func displayQueueStats(queue *badger.DB) error {
	// get queue stats
	qCount, dupCount, mbiCount, err := badgerStatus(queue)
	if err != nil {
		fmt.Println("error getting stats")
		return err
	}
	dupRemain := qCount - dupCount
	mbiRemain := qCount - mbiCount
	p := message.NewPrinter(message.MatchLanguage("en")) // pretty print numbers
	p.Printf("there are %v benes in the queue.\n", qCount)
	p.Printf("%v have been deduped. %v remain.\n", dupCount, dupRemain)
	p.Printf("%v have had their mbi hashes checked/processed. %v remain.\n", mbiCount, mbiRemain)
	return nil
}

func main() {
	// custom error logger with date and time
	logger := log.New(os.Stderr, "", log.Ldate|log.Ltime)

	// global counter for tracking number of duplicates deleted
	var dupCounter uint64

	// load app settings from environment
	var cfg Config
	err := envconfig.Process("BH_", &cfg)
	if err != nil {
		logger.Fatal(err)
	}

	// open postgres
	psqlInfo := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", cfg.RwDbUser, cfg.RwDbPassword, cfg.RwDbHost, cfg.RwDbPort, cfg.DbName)
	config, err := pgxpool.ParseConfig(psqlInfo)
	config.MaxConns = int32(cfg.DbMaxConns)
	config.MaxConnIdleTime = time.Duration(5) * time.Second
	db, err := pgxpool.ConnectConfig(context.Background(), config)
	if err != nil {
		logger.Fatal(err)
	}
	defer db.Close()
	fmt.Println("connected to fhir db.")

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

	// parse flags
	flag.CommandLine.SetOutput(os.Stdout)
	buildQueueFlag := flag.Bool("build-queue", false, "build the queue")
	processDupsFlag := flag.Bool("process-dups", false, "run dedup process")
	resetQueueFlag := flag.Bool("reset-queue", false, "resets all benes to an unprocessed state")
	statsFlag := flag.Bool("stats", false, "display queue stats")
	flag.Parse()

	// if no flags, show stats and exit
	if *buildQueueFlag != true && *processDupsFlag != true && *resetQueueFlag != true && *statsFlag != true {
		fmt.Println("nothing to do.")
		flag.Usage()
		os.Exit(1)
	}

	// rebuild/reset the queue
	if *resetQueueFlag {
		err := resetQueue(db, logger, queue, &cfg)
		if err != nil {
			logger.Fatal(err)
		}
	}

	// build the queue
	if *buildQueueFlag {
		err := buildQueue(db, queue, &cfg, logger)
		if err != nil {
			logger.Fatal(err)
		}
	}

	// process the queue for dups
	if *processDupsFlag == true {
		// used to track progress on replays
		err := processDups(db, queue, &cfg, logger, &dupCounter)
		if err != nil {
			logger.Fatal(err)
		}
	}

	// display queue stats
	if *statsFlag == true {
		fmt.Println("gathering stats.")
		if err := displayQueueStats(queue); err != nil {
			logger.Fatal(err)
		}
		os.Exit(0)
	}
}
