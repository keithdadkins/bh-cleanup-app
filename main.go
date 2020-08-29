package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
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

// row count pattern
const rowCountPattern = `SELECT count(*) FROM "Beneficiaries";`

// queue query pattern
const queuePattern = `SELECT "beneficiaryId" FROM "Beneficiaries" "beneficiaryId" OFFSET $1 LIMIT $2 ;`

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

// badger write k with v
func badgerWrite(b *badger.DB, k []byte, v []byte) (bool, error) {
	txn := b.NewTransaction(true)
	err := txn.Set(k, v)
	if err != nil {
		err = txn.Commit()
		if err != nil {
			// try again
			txn.Discard()
			txn = b.NewTransaction(true)
			if err = txn.Set([]byte(k), []byte(v)); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	err = txn.Commit()
	if err != nil {
		return false, err
	}
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
func buildQueue(db *pgxpool.Pool, queue *badger.DB, cfg *Config, logger *log.Logger, rowsLeft *uint64) error {
	// get number of benes we are processing
	if *rowsLeft < 1 {
		if cfg.BeneTableRows > 0 {
			// row count was manually set via env vars, use it
			*rowsLeft = cfg.BeneTableRows
		} else {
			fmt.Println("getting row count from server.. this could take some time.")
			row := db.QueryRow(context.Background(), rowCountPattern)
			if err := row.Scan(rowsLeft); err != nil {
				logger.Println("error getting bene row count")
				return err
			}
		}
	}

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
	if feedLimit > *rowsLeft {
		feedLimit = *rowsLeft
	}

	// we do not need more workers than batches
	numBatches := *rowsLeft / feedLimit
	if numQueueWorkers > int(numBatches) {
		numQueueWorkers = int(numBatches)
	}

	// progress bar
	count := int64(*rowsLeft)
	bar := pb.New64(count)
	batchDoneChan := make(chan bool)
	barStart := false
	bar.ShowPercent = true
	bar.ShowBar = true
	bar.ShowCounters = false
	bar.ShowTimeLeft = true
	go func() {
		for <-batchDoneChan {
			if barStart == false {
				bar.Start()
				barStart = true
			}
			bar.Increment()
		}
	}()

	// spin up the workers
	var queueChan = make(chan *queueBatch, cfg.QueueBuffer)
	fmt.Printf("launching %v workers.\n", numQueueWorkers)
	var wg sync.WaitGroup
	for i := 0; i < numQueueWorkers; i++ {
		wg.Add(1)
		go queueWorker(i, db, queue, queueChan, &wg, logger, rowsLeft, feedLimit, batchDoneChan)
	}

	// send workers batches to process
	fmt.Println("adding benes to the queue.")
	var offset uint64
	for counter := uint64(0); counter < *rowsLeft; counter += feedLimit {
		qb := queueBatch{offset, feedLimit}
		queueChan <- &qb
		offset += feedLimit
	}
	close(queueChan)

	// wait for the workers to finish
	wg.Wait()
	bar.Set64(count)
	bar.Finish()

	// make sure all benes have valid badger entries.. replay until they do.
	entryCount, _, err := badgerStatus(queue)
	if err != nil {
		fmt.Println("error getting queue stats")
		return err
	}
	p := message.NewPrinter(message.MatchLanguage("en")) // used to print numbers with comma's
	p.Printf("queue stats: number of benes in queue %v - number remaining %v.\n", entryCount, *rowsLeft)

	if *rowsLeft > 0 {
		fmt.Printf("replaying missed benes.\n---\n")
		buildQueue(db, queue, cfg, logger, rowsLeft)
	}

	return nil
}

// adds benes to the queue
func queueWorker(id int, db *pgxpool.Pool, queue *badger.DB, batches <-chan *queueBatch, wg *sync.WaitGroup, logger *log.Logger, rowsLeft *uint64, feedLimit uint64, batchDoneChan chan<- bool) {
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
		for rows.Next() {
			var beneid string
			err = rows.Scan(&beneid)
			if err != nil {
				logger.Fatal(err)
			}
			ok, err := badgerWrite(queue, []byte(beneid), nil)
			if !ok {
				logger.Println(err)
			}
		}
		rows.Close()
		result := rows.CommandTag()
		*rowsLeft -= uint64(result.RowsAffected())
		batchDoneChan <- true

		// periodically run a garbage collection on the queue. this helps speed up badger and helps keep
		// the size down
		if rand.Intn(5) == 1 {
			queue.RunValueLogGC(0.5)
		}

	}
	wg.Done()
}

// proccessing the queue for benes to cleanup
func processQueue(db *pgxpool.Pool, queue *badger.DB, cfg *Config, logger *log.Logger, dupCounter *uint64) error {
	// determine how many benes need to be processed
	qCount, doneCount, err := badgerStatus(queue)
	if err != nil {
		logger.Println("error getting queue status")
		return err
	}
	numLeft := qCount - doneCount

	// quit if done
	if numLeft < 1 {
		return nil
	}

	// display stats
	p := message.NewPrinter(message.MatchLanguage("en")) // used to print numbers with comma's
	p.Printf("queue stats: %v bene's in queue - %v completed - %v remain.\n", qCount, doneCount, numLeft)

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
	bar.ShowTimeLeft = true
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
	fmt.Printf("spawning %v dup workers.\n", numDupWorkers)
	var beneChan = make(chan *beneEntry, dupBuffer)
	var wg sync.WaitGroup
	for i := 0; i < numDupWorkers; i++ {
		wg.Add(1)
		go dupWorker(i, queue, beneChan, db, logger, cfg, dupDoneChan, dupCounter, &wg, &numLeft)
	}

	// run garbage collection on the queue and send unprocessed benes to the workers
	queue.RunValueLogGC(0.5)
	fmt.Println("processing queue.")
	err = queue.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			var status string
			err := item.Value(func(v []byte) error {
				status = string(v)
				if status == "" || status == "2" {
					var bene beneEntry
					bene.key = item.KeyCopy(nil)
					bene.value = v
					beneChan <- &bene
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return err
	})
	if err != nil {
		logger.Println("error processing dups")
		return err
	}
	close(beneChan)
	wg.Wait()
	finMsg := fmt.Sprintf("%v duplicates were deleted.", *dupCounter)
	bar.FinishPrint(finMsg)

	// make sure everyone was processed.. replay until they are.
	queue.RunValueLogGC(0.5)
	queue.Sync()
	qCount, doneCount, err = badgerStatus(queue)
	if err != nil {
		logger.Println("error getting queue status")
		return err
	}
	if (qCount - doneCount) != 0 {
		fmt.Printf("replaying missed benes.\n")
		processQueue(db, queue, cfg, logger, dupCounter)
	}

	// display stats
	numLeft = qCount - doneCount
	p.Printf("queue stats: %v bene's in queue - %v completed - %v remain.\n", qCount, doneCount, numLeft)

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

		// delete teh dups
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
		switch bene.Value() {
		case "2":
			// mbi hash has been completed. set to both.
			newStatus = "3"
		default:
			// mark dedup as done
			newStatus = "1"
		}
		_, err = badgerWrite(queue, bene.key, []byte(newStatus))
		if err != nil {
			// just log the error.. we will replay if missed
			logger.Println(err)
		}
		conn.Release()

		// update progress
		dupDoneChan <- true

		// update stats
		atomic.AddUint64(numLeft, ^uint64(0))
		if rowsDeleted > 0 {
			atomic.AddUint64(dupCounter, uint64(rowsDeleted))
		}
	}
}

func resetQueue(logger *log.Logger, queue *badger.DB) {
	fmt.Println("Warning! Resetting all benes in the queue to nil. This will reset the status of each bene in the queue to nil.")
	fmt.Println("This process will take some time and there is no progress meter. Type 'yes' to continue.")
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
	config.MaxConns = int32(cfg.NumDupWorkers)
	config.MaxConnIdleTime = time.Duration(5) * time.Second
	db, err := pgxpool.ConnectConfig(context.Background(), config)
	if err != nil {
		logger.Fatal(err)
	}
	defer db.Close()
	fmt.Println("connected to fhir db.")

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

	// reset the queue (mark benes nil)
	if *resetQueueFlag {
		resetQueue(logger, queue)
	}

	// build the queue
	if *buildQueueFlag {
		// used to track progress on replays
		var rowsLeft uint64
		err := buildQueue(db, queue, &cfg, logger, &rowsLeft)
		if err != nil {
			logger.Fatal(err)
		}
		fmt.Println("build queue complete.")
	}

	// process the queue
	if *processQueueFlag == true {
		// used to track progress on replays
		err := processQueue(db, queue, &cfg, logger, &dupCounter)
		if err != nil {
			logger.Fatal(err)
		}
		fmt.Println("processing duplicates complete.")
	}
}
