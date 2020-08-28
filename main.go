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
	Offset uint64 `json:"offset"`
	Limit  uint64 `json:"limit"`
}

type beneEntry struct {
	key   []byte
	value []byte
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
	txn := b.NewTransaction(true)
	err := txn.Set(k, v)
	switch {
	case err == badger.ErrTxnTooBig:
		// too many writes queued up, try creating another transaction
		_ = txn.Commit()
		txn = b.NewTransaction(true)
		if err = txn.Set([]byte(k), []byte(v)); err != nil {
			return false, err
		}
	case err != nil:
		return false, nil
	}
	_ = txn.Commit()
	return true, err
}

// returns number of benes in the queue, number of benes completed, and an error (nil if success)
func badgerStatus(b *badger.DB) (uint64, uint64, error) {
	// get/display queue status
	var qCount uint64
	var doneCount uint64
	err := b.View(func(txn *badger.Txn) error {
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
			if status == "1" || status == "3" {
				doneCount++
			}
			qCount++
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	return qCount, doneCount, err
}

// trap ctl-c, kill, etc and try to gracefully close badger (50/50 chance this will work, so try to let jobs finish and do not count on this.)
func badgerCloseHandler(queue *badger.DB, dupCounter *uint64) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Printf("closing badger. %v dups deleted.\n", *dupCounter)
		if err := queue.Close(); err != nil {
			time.Sleep(time.Second * 5)
			if err = queue.Close(); err != nil {
				os.Exit(1)
			}
			os.Exit(0)
		}
		os.Exit(0)
	}()
}

// builds (or continues building) the queue of bene id's
func buildQueue(db *pgxpool.Pool, queue *badger.DB, cfg *Config, logger *log.Logger) {
	// get number of benes we are processing
	var beneRowCount uint64
	if cfg.BeneTableRows > 0 {
		// row count was manually set, use it
		beneRowCount = cfg.BeneTableRows
	} else {
		// get the row count
		row := db.QueryRow(context.Background(), rowCountPattern)
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
	bar.Set(count)
	bar.FinishPrint("complete.")
	os.Exit(0)
}

// adds benes to the queue
func queueWorker(id int, db *pgxpool.Pool, queue *badger.DB, batches <-chan *queueBatch, wg *sync.WaitGroup, logger *log.Logger, rowsLeft *uint64, feedLimit uint64, batchDoneChan chan<- bool) {
	// poll the channel for batches to process
	for qry := range batches {
		// create new instance of qry to ensure it's unique in each goroutine
		qry := qry

		// execute the batch query
		rows, err := db.Query(context.Background(), queuePattern, qry.Offset, qry.Limit)
		if err != nil {
			logger.Println("error fetching query batch")
			logger.Fatal(err)
		}

		// parse the results
		for rows.Next() {
			var beneid string
			_ = rows.Scan(&beneid)
			ok, err := badgerWrite(queue, []byte(beneid), nil)
			if ok != true {
				logger.Println("could not write to badger db")
				logger.Fatal(err)
			}
		}
		rows.Close()
		*rowsLeft -= feedLimit
		batchDoneChan <- true
	}
	wg.Done()
}

// proccessing the queue for benes to cleanup
func processQueue(db *pgxpool.Pool, queue *badger.DB, cfg *Config, logger *log.Logger, dupDoneChan chan<- bool, dupCounter *uint64) {
	// determine how many workers to use
	var numDupWorkers int
	if cfg.NumDupWorkers > 0 {
		numDupWorkers = cfg.NumDupWorkers
	} else {
		numDupWorkers = runtime.NumCPU()
	}

	// set dup buffer value
	var dupBuffer int
	if cfg.DupBuffer > 1 {
		dupBuffer = cfg.DupBuffer
	} else {
		dupBuffer = 1
	}

	// launch the dup workers
	fmt.Printf("spawning %v dup workers.\n", numDupWorkers)
	var beneChan = make(chan *beneEntry, dupBuffer)
	var wg sync.WaitGroup
	for i := 0; i < numDupWorkers; i++ {
		wg.Add(1)
		go dupWorker(i, queue, beneChan, db, logger, cfg, dupDoneChan, dupCounter, &wg)
	}

	// send unprocessed benes to the workers
	fmt.Println("deleting dups.")
	err := queue.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = true
		opts.PrefetchSize = dupBuffer
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			if item.ValueSize() > 0 {
				// parse status
				var s []byte
				_ = badgerRead(queue, item.Key(), s)
				status := string(s)
				fmt.Printf(status)
			} else {
				bene := beneEntry{key: item.Key(), value: nil}
				beneChan <- &bene
			}
		}
		return nil
	})
	if err != nil {
		logger.Println("error processing dups")
		logger.Fatal(err)
	}
	close(beneChan)
	wg.Wait()
	fmt.Printf("%v rows were deleted", dupCounter)

	// make sure everyone was processed
	qCount, doneCount, err := badgerStatus(queue)
	numLeft := qCount - doneCount
	if numLeft > 0 {
		logger.Println("***** not all benes were processed - please run again ******")
		logger.Printf("%v remain.\n", numLeft)
		os.Exit(int(numLeft))
	}
}

func dupWorker(id int, queue *badger.DB, beneChan <-chan *beneEntry, db *pgxpool.Pool, logger *log.Logger, cfg *Config, dupDoneChan chan<- bool, dupCounter *uint64, wg *sync.WaitGroup) {
	defer wg.Done()
	for bene := range beneChan {
		beneid := bene.key

		// delete the dups
		conn, err := db.Acquire(context.Background())
		if err != nil {
			logger.Println(err)
		}
		defer conn.Release()

		result, err := conn.Exec(context.Background(), deletePattern, beneid)
		if err != nil {
			logger.Printf("error deleting dups for %v.. skipping.\n", string(beneid))
			conn.Release()
			continue
		}
		rowsDeleted := result.RowsAffected()

		// mark bene as completed
		go func() {
			status := ""
			switch string(bene.value) {
			case "":
				status = "1"
			case "2":
				status = "3"
			}

			txn := queue.NewTransaction(true)
			err := txn.Set(beneid, []byte(status))
			if err != nil {
				txn.Discard()
				badgerWrite(queue, bene.key, []byte(status))
			}
			txn.Commit()
		}()

		// update progress
		atomic.AddUint64(dupCounter, uint64(rowsDeleted))
		dupDoneChan <- true
		conn.Release()
	}
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
	fmt.Println("Connecting to postgres max conns: ", cfg.NumDupWorkers)
	psqlInfo := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", cfg.RwDbUser, cfg.RwDbPassword, cfg.RwDbHost, cfg.RwDbPort, cfg.DbName)
	config, err := pgxpool.ParseConfig(psqlInfo)
	config.MaxConns = int32(cfg.NumDupWorkers)
	config.MaxConnIdleTime = time.Duration(5) * time.Second
	db, err := pgxpool.ConnectConfig(context.Background(), config)
	if err != nil {
		logger.Fatal(err)
	}
	defer db.Close()

	// parse flags
	buildQueueFlag := flag.Bool("build-queue", false, "build the queue")
	processQueueFlag := flag.Bool("process-queue", false, "process the queue")
	resetQueueFlag := flag.Bool("reset-queue", false, "resets all benes to 'unprocessed'")
	flag.Parse()

	// exit if no flag was set
	if *buildQueueFlag != true && *processQueueFlag != true && *resetQueueFlag != true {
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
	badgerCloseHandler(queue, &dupCounter)

	// close the pipe and go back to normal stdout. badger really only writes to stderr anyway.
	w.Close()
	os.Stdout = oldStdout
	<-stdOutChan //so just ignore

	// reset the queue (mark as benes to nil)
	if *resetQueueFlag {
		fmt.Println("Warning! Resetting all benes in the queue to nil. Type 'yes' to continue.")
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
		err = queue.View(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions
			opts.PrefetchValues = false
			it := txn.NewIterator(opts)
			defer it.Close()
			for it.Rewind(); it.Valid(); it.Next() {
				badgerWrite(queue, it.Item().Key(), nil)
			}
			return nil
		})
		if err != nil {
			logger.Println("error processing dups")
			logger.Fatal(err)
		}
		qCount, doneCount, err := badgerStatus(queue)
		numBenesToProcess := (qCount - doneCount)
		p := message.NewPrinter(message.MatchLanguage("en")) // used to print numbers with comma's
		p.Printf("queue stats: %v bene's in queue - %v completed - %v remain.\n", qCount, doneCount, numBenesToProcess)
	}

	// build the queue
	if *buildQueueFlag {
		buildQueue(db, queue, &cfg, logger)
	}

	// get total and done count
	qCount, doneCount, err := badgerStatus(queue)
	if err != nil {
		logger.Println("error getting queue status")
		logger.Fatal(err)
	}
	numBenesToProcess := qCount - doneCount
	p := message.NewPrinter(message.MatchLanguage("en")) // used to print numbers with comma's
	p.Printf("queue stats: %v bene's in queue - %v completed - %v remain.\n", qCount, doneCount, numBenesToProcess)

	// setup the progress bar
	count := int64(numBenesToProcess)
	bar := pb.New64(count)
	dupDoneChan := make(chan bool)
	barStart := false
	bar.ShowPercent = true
	bar.ShowBar = true
	bar.ShowCounters = false
	bar.ShowTimeLeft = true
	go func() {
		for <-dupDoneChan {
			if barStart == true {
				bar.Increment()
			} else {
				bar.Start()
				barStart = true
			}
		}
	}()

	// process the queue
	if *processQueueFlag == true {
		fmt.Println("processing the queue for duplicates.")
		processQueue(db, queue, &cfg, logger, dupDoneChan, &dupCounter)
	}
	finMsg := fmt.Sprintf("completed. %v duplicates were deleted.", dupCounter)
	bar.FinishPrint(finMsg)
}
