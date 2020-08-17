package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	badger "github.com/dgraph-io/badger/v2"
	"github.com/elastic/gosigar"
	"github.com/kelseyhightower/envconfig"
	_ "github.com/lib/pq"
	"golang.org/x/text/message"
)

// Config is loaded from environment. See .env file
type Config struct {
	RoDbHost         string `envconfig:"BH_RO_DB_HOST"`
	RoDbPort         int    `envconfig:"BH_RO_DB_PORT"`
	RoDbUser         string `envconfig:"BH_RO_DB_USER"`
	RoDbPassword     string `envconfig:"BH_RO_DB_PASSWORD"`
	RwDbHost         string `envconfig:"BH_RW_DB_HOST"`
	RwDbPort         int    `envconfig:"BH_RW_DB_PORT"`
	RwDbUser         string `envconfig:"BH_RW_DB_USER"`
	RwDbPassword     string `envconfig:"BH_RW_DB_PASSWORD"`
	DbName           string `envconfig:"BH_DB_NAME"`
	HistoryTableName string `envconfig:"BH_DB_HISTORY_TABLE_NAME"`
	HistoryTableRows uint64 `envconfig:"BH_DB_HISTORY_TABLE_ROWS"`
	NumQueueWorkers  int    `envconfig:"BH_NUM_QUEUE_WORKERS"`
	QueueFeedLimit   uint64 `envconfig:"BH_QUEUE_FEED_LIMIT"`
	QueueBuffer      uint64 `envconfig:"BH_QUEUE_BUFFER"`
	NumDupWorkers    int    `envconfig:"BH_NUM_DUP_WORKERS"`
	DupBuffer        int    `envconfig:"BH_DUP_BUFFER"`
}

// queueBatch represents the sql statement our queue workers will process to find unique bene id's
type queueBatch struct {
	Offset uint64 `json:"offset"`
	Limit  uint64 `json:"limit"`
}

// tuning defaults
const (
	numQueueWorkersDefault = 2  // number of workers adding benes to the queue. (keep this small)
	numDupWorkersDefault   = 16 // number of workers running delete from queries
)

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

// builds/adds to the queue if -build-queue flag is set
func buildQueue(queue *badger.DB, cfg *Config, logger *log.Logger, processQueueFlag *bool) {
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

	// process the queue (this happens if both -build-queue and -process-queue flags are set)
	if *processQueueFlag {
		fmt.Println("processing the queue.")
		var dupCounter uint64 = 0
		processQueue(queue, cfg, logger, &dupCounter)
	}
}

func dupWorker(id int, queue *badger.DB, dupChan <-chan *badger.Item, db *sql.DB, logger *log.Logger, dupCounter *uint64) {
	for bene := range dupChan {
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

		// else, delete the dups and mark them as completed
		result, err := db.Exec(deletePattern, beneid)
		if err != nil {
			logger.Fatal(err)
		}
		count, err := result.RowsAffected()
		if err != nil {
			logger.Fatal(err)
		}

		// mark as completed
		badgerWrite(queue, beneid, []byte("1"))

		// update stats
		if count > 0 {
			atomic.AddUint64(dupCounter, uint64(count))
			fmt.Printf("%v duplicates deleted\n", *dupCounter)
		}

		logger.Printf("processed bene %v\n", string(beneid))
	}
}

// manages the processing of the queue (deleting duplicates, updating badger, etc)
func processQueue(queue *badger.DB, cfg *Config, logger *log.Logger, dupCounter *uint64) {

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
	var numDupWorkers int
	if cfg.NumQueueWorkers > 0 {
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

	// spin up the workers
	var dupChan = make(chan *badger.Item, dupBuffer)
	var wg sync.WaitGroup
	var i int
	for i = 0; i < numDupWorkers; i++ {
		wg.Add(1)
		go dupWorker(i, queue, dupChan, db, logger, dupCounter)
	}

	// loop through all the keys in the queue, sending them to be processed by the dup worker
	err = queue.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			bene := it.Item()
			dupChan <- bene
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

	// load our settings from env vars
	var cfg Config
	err := envconfig.Process("BH_", &cfg)
	if err != nil {
		logger.Fatal(err)
	}

	// we are using badger db (a fast embedded kv store) for serializing our very large queue of benes
	queue, err := badger.Open(badger.DefaultOptions("dup.queue"))
	if err != nil {
		logger.Fatal(err)
	}
	defer queue.Close()
	badgerCloseHandler(queue)

	// build the queue (will also process the queue when complete if flag is set)
	if *buildQueueFlag {
		buildQueue(queue, &cfg, logger, processQueueFlag)
	}

	// display queue stats
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
	p := message.NewPrinter(message.MatchLanguage("en")) // used to print numbers with comma's
	p.Printf("queue stats: %v bene's in queue - %v completed - %v remain.\n", qCount, doneCount, (qCount - doneCount))

	// just process the queue
	if *processQueueFlag && *buildQueueFlag == false {
		fmt.Println("processing the queue.")
		var dupCounter uint64 = 0
		processQueue(queue, &cfg, logger, &dupCounter)
	}

}
