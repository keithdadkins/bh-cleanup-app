package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cheggaaa/pb"
	badger "github.com/dgraph-io/badger/v2"
	"github.com/elastic/gosigar"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/kelseyhightower/envconfig"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/message"
)

// Config is loaded from environment. See .env file
type Config struct {
	RoDbHost            string `envconfig:"BH_RO_DB_HOST"`
	RoDbPort            int    `envconfig:"BH_RO_DB_PORT"`
	RoDbUser            string `envconfig:"BH_RO_DB_USER"`
	RoDbPassword        string `envconfig:"BH_RO_DB_PASSWORD"`
	RwDbHost            string `envconfig:"BH_RW_DB_HOST"`
	RwDbPort            int    `envconfig:"BH_RW_DB_PORT"`
	RwDbUser            string `envconfig:"BH_RW_DB_USER"`
	RwDbPassword        string `envconfig:"BH_RW_DB_PASSWORD"`
	DbName              string `envconfig:"BH_DB_NAME"`
	DbMaxConns          int32  `envconfig:"BH_DB_MAX_CONNS"`
	BeneTableRows       uint64 `envconfig:"BH_DB_BENE_TABLE_ROWS"`
	MissingMbiTableRows uint64 `envconfig:"BH_DB_MISSING_MBI_TABLE_ROWS"`
	NumQueueWorkers     int    `envconfig:"BH_NUM_QUEUE_WORKERS"`
	QueueFeedLimit      uint64 `envconfig:"BH_QUEUE_FEED_LIMIT"`
	QueueBuffer         uint64 `envconfig:"BH_QUEUE_BUFFER"`
	NumDupWorkers       int    `envconfig:"BH_NUM_DUP_WORKERS"`
	DupBuffer           int    `envconfig:"BH_DUP_BUFFER"`
	NumMbiHashWorkers   int    `envconfig:"BH_MBI_NUM_HASH_WORKERS"`
	MbiHashBuffer       int    `envconfig:"BH_MBI_HASH_BUFFER"`
	MbiHashPepper       string `envconfig:"BH_MBI_HASH_PEPPER"`
	MbiHashIterations   int    `envconfig:"BH_MBI_HASH_ITERATIONS"`
	MbiHashLength       int    `envconfig:"BH_MBI_HASH_LENGTH"`
}

// missing mbi hash patterns
const (
	missingMbiPattern      = `SELECT "beneficiaryHistoryId", "medicareBeneficiaryId" FROM "BeneficiariesHistory" WHERE "beneficiaryId" = $1 AND "mbiHash" IS NULL;`
	missingMbiCountPattern = `SELECT count(*) FROM "BeneficiariesHistory" WHERE "beneficiaryId" = $1 AND "mbiHash" IS NULL AND "medicareBeneficiaryId" IS NOT NULL;`
	updateHashPattern      = `UPDATE "BeneficiariesHistory" SET "mbiHash" = $1 WHERE "beneficiaryId" = $2 AND "beneficiaryHistoryId" = $3;`
)

// queue query pattern (gets the bene id's into a local queue for later processing)
const queuePattern = `SELECT "beneficiaryId" FROM "Beneficiaries" "beneficiaryId" ORDER BY "beneficiaryId" OFFSET $1 LIMIT $2;`

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
DELETE FROM "BeneficiariesHistory" WHERE "beneficiaryId" = $1 AND "beneficiaryHistoryId" IN (SELECT "beneficiaryHistoryId" FROM x);`

// run this when done to cleanup after all the deletes
const vacuumPattern = `VACUUM ANALYZE`

var (
	logger *log.Logger   // pointer to our stderr logfile
	queue  *badger.DB    // pointer to our badger db (aka 'the queue')
	db     *pgxpool.Pool // pointer to our postgres db
	cfg    Config        // config is loaded from env vars starting with 'BH_'
	force  bool          // -f flag to force processing the bene no matter their current status
)

// used by missing mbi hash workers
type hashBatch struct {
	beneHistoryID int64
	mbiHash       string
}

// queueBatches are used to paginate through the database to build the queue.
// e.g., 'select foo from bigtable offset 1000 limit 1000', '... offset 2000 limit 1000', and so on
type queueBatch struct {
	Offset uint64
	Limit  uint64
}

// beneEntry represents an entry in the queue.
// .key and .status are in []byte's
// .Key() and .Status() returns the bytes as a string
type beneEntry struct {
	key    []byte
	status []byte
}

// returns the key as a string (the key is the "beneficiaryId")
func (b beneEntry) Key() string {
	return string(b.key)
}

// returns the benes status as a string
// "1" == dedup process has been run
// "2" == mbi hash check has been run
// "3" == both dedup and mbi has been run
// "" == nothing has been run
func (b beneEntry) Status() string {
	if len(b.status) == 0 {
		b.status = []byte("")
	}
	return string(b.status)
}

// Sets bene.status to the current value from the queue.
func (b beneEntry) GetStatus() error {
	err := badgerRead(b.key, b.status)
	return err
}

// updates the benes status in the queue
func (b beneEntry) Update() (bool, error) {
	ok, err := badgerWrite(b.key, b.status)
	return ok, err
}

// adds the bene to the queue
func (b beneEntry) New() (bool, error) {
	ok, err := badgerWrite(b.key, nil)
	return ok, err
}

// gets the current amount of "actual" free memory.
func freeMem() gosigar.Mem {
	mem := gosigar.Mem{}
	mem.Get()
	return mem
}

// helper func to handle errors. returns true if there was an error
func handleErr(err error, msg string, txn pgx.Tx, conn *pgxpool.Conn) bool {
	if err != nil {
		if msg != "" {
			logger.Println(err)
		}
		logger.Println(err)
		txn.Rollback(context.Background())
		conn.Release()
		return true
	}
	return false
}

// badger read operation. Sets v to the value of k. e.g.,
// err := badgerRead(queue, bene.key, bene.value) would set bene.value to v
func badgerRead(k []byte, v []byte) error {
	err := queue.View(func(txn *badger.Txn) error {
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

// badger write k with v. returns true/false and an err
func badgerWrite(k []byte, v []byte) (bool, error) {
	txn := queue.NewTransaction(true)
	defer txn.Discard()
	if err := txn.Set(k, v); err == badger.ErrTxnTooBig {
		fmt.Printf(".")
		if err := txn.Commit(); err != nil {
			return false, err
		}
		txn = queue.NewTransaction(true)
		if err := txn.Commit(); err != nil {
			return false, err
		}
	}
	txn.Commit()
	return true, nil
}

// returns number of benes in the queue, dedups completed, mbi completed, and an error (nil if success)
func badgerStatus() (qCount uint64, dupCount uint64, mbiCount uint64, err error) {
	// get/display queue status
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
	}
	return qCount, dupCount, mbiCount, err
}

// trap ctl-c, kill, etc and try to gracefully close badger (50/50 chance this will work, so try to let jobs finish and do not count on this.)
// TODO: we could use context package to handle this better
func badgerCloseHandler() {
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

// runs VACUUM ANALYZE on the db to free up space and update db stats
func runVacuum() bool {
	_, err := db.Exec(context.Background(), vacuumPattern)
	if err != nil {
		handleErr(err, "unable to execute vacuum", nil, nil)
		return false
	}
	return true
}

// returns the total number of benes that should be in the queue
func getTotalBenes() (uint64, error) {
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

// delete and rebuild the queue
func resetQueue() error {
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
		os.Exit(1)
	}
	queue.DropAll()
	if err := buildQueue(); err != nil {
		return err
	}
	queue.RunValueLogGC(1)
	return nil
}

func displayQueueStats() error {
	// get queue stats
	qCount, dupCount, mbiCount, err := badgerStatus()
	handleErr(err, "error getting stats", nil, nil)

	dupRemain := qCount - dupCount
	mbiRemain := qCount - mbiCount
	p := message.NewPrinter(message.MatchLanguage("en")) // pretty print numbers
	p.Printf("there are %v benes in the queue.\n", qCount)
	p.Printf("%v have been deduped. %v remain.\n", dupCount, dupRemain)
	p.Printf("%v have had their mbi hashes checked/processed. %v remain.\n", mbiCount, mbiRemain)
	return nil
}

// builds (or continues building) the queue of bene id's
func buildQueue() error {
	fmt.Println("building the queue.")
	var totalBenes uint64
	totalBenes, err := getTotalBenes()
	if err != nil {
		return err
	}
	entryCount, _, _, err := badgerStatus()
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
	bar.ShowCounters = true
	bar.ShowTimeLeft = false
	bar.ShowElapsedTime = false
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
		go queueWorker(i, queueChan, &wg, &totalBenes, batchDoneChan)
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
	entryCount, _, _, err = badgerStatus()
	if err != nil {
		fmt.Println("error getting queue stats")
		return err
	}
	p := message.NewPrinter(message.MatchLanguage("en")) // used to pretty print numbers
	p.Printf("queue stats: %v benes of %v in the queue.\n", entryCount, totalBenes)
	numLeft = totalBenes - entryCount
	if numLeft > 0 {
		fmt.Printf("%v benes were missed. replaying.\n\n", numLeft)
		buildQueue()
	}
	fmt.Printf("done.\n\n")
	return nil
}

// adds benes sent from buildQueue() to the queue
func queueWorker(id int, batches <-chan *queueBatch, wg *sync.WaitGroup, numLeft *uint64, batchDoneChan chan<- int64) {
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
			bene.GetStatus()
			if bene.Status() == "" {
				benesToProcess = append(benesToProcess, bene)
			}
		}
		rows.Close()

		// process the results
		txn := queue.NewTransaction(true)
		for _, bene := range benesToProcess {
			// add the bene to the queue
			if err := txn.Set(bene.key, nil); err == badger.ErrTxnTooBig {
				err = txn.Commit()
				if err != nil {
					// try again with new transaction
					txn = queue.NewTransaction(true)
					_ = txn.Set(bene.key, nil)
					if err := txn.Commit(); err != nil {
						logger.Fatal("could not update bene")
					}
				}
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
func processDups(dupCounter *uint64) error {
	// determine how many benes need to be processed
	qCount, doneCount, _, err := badgerStatus()
	if err != nil {
		logger.Println("error getting queue status")
		return err
	}
	numLeft := qCount - doneCount

	// do them all if -force
	if force == true {
		numLeft = qCount
	}

	// quit if done
	if numLeft < 1 {
		fmt.Println("all benes have been processed.")
		_ = displayQueueStats()
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
	fmt.Printf("spawning %v dedup workers.\n", numDupWorkers)
	var beneChan = make(chan beneEntry, dupBuffer)
	var wg sync.WaitGroup
	for i := 0; i < numDupWorkers; i++ {
		wg.Add(1)
		go dupWorker(i, beneChan, dupDoneChan, dupCounter, &wg, &numLeft)
	}

	// loop through the queue and send unworked benes to be deduped
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
			item := it.Item()
			var bene beneEntry
			bene.key = item.KeyCopy(nil)

			// run them all all if -force
			if force == true {
				beneChan <- bene
				continue
			}

			// item.ValueSize is much faster than grabbing the value from the log, so try that first
			if item.ValueSize() > 0 {
				// check the status
				err := item.Value(func(v []byte) error {
					bene.status = v
					if bene.Status() == "" || bene.Status() == "2" {
						beneChan <- bene
					}
					return nil
				})
				if err != nil {
					return err
				}
			} else {
				// unworked bene
				beneChan <- bene
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

	// wait for workers to finish, display stats, and replay if needed
	wg.Wait()
	finMsg := fmt.Sprintf("%v duplicates were deleted.", *dupCounter)
	bar.FinishPrint(finMsg)
	logger.Println("STAT: ", finMsg)

	// replay?
	qCount, doneCount, _, err = badgerStatus()
	if err != nil {
		return err
	}
	if (qCount - doneCount) > 0 {
		fmt.Printf("replaying missed benes.\n")
		processDups(dupCounter)
	}
	fmt.Printf("done.\n\n")
	return nil
}

// dedups benes sent from processDups()
func dupWorker(id int, beneChan <-chan beneEntry, dupDoneChan chan<- bool, dupCounter *uint64, wg *sync.WaitGroup, numLeft *uint64) {
	// handle benes received on the beneChan
	for bene := range beneChan {
		bene := bene

		// try to avoid going oom
		for mem := freeMem(); mem.ActualFree < 1024; mem = freeMem() {
			// cleanup and backoff
			queue.RunValueLogGC(.5)
			runtime.GC()
			time.Sleep(time.Duration(5) * time.Second)
		}

		// grab a connection from the pool
		conn, err := db.Acquire(context.Background())
		handleErr(err, "pools empty", nil, nil)
		defer conn.Release()

		// start a transaction
		txn, err := conn.Begin(context.Background())
		handleErr(err, "txn err", txn, conn)

		// delete the dups
		result, err := txn.Exec(context.Background(), deletePattern, bene.Key())
		if err != nil {
			handleErr(err, "could not run delete query", txn, conn)
			continue
		}

		// commit
		err = txn.Commit(context.Background())
		if err != nil {
			handleErr(err, "could not commit", txn, conn)
			continue
		}
		rowsDeleted := result.RowsAffected()

		// update the bene
		if force == false {
			switch bene.Status() {
			case "":
				bene.status = []byte("1")
			case "2":
				bene.status = []byte("3")
			}
			ok, err := bene.Update()
			if !ok {
				handleErr(err, "error updating bene status", nil, conn)
				continue
			}
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
	wg.Done()
}

// hashes mbi using PBKDF2-HMAC-SHA256 and sets *hashedMBI to the result
func hashMBI(mbi []byte, hashedMBI *string, hashCfg *Config) error {
	// make sure there is something to hash
	if string(mbi) == "" {
		return errors.New("null mbi passed to hashMBI function")
	}

	// decode the pepper from hex
	pepper, err := hex.DecodeString(hashCfg.MbiHashPepper)
	if err != nil {
		return err
	}

	// hash the mbi and set *hashedMbi to the result
	tmp := pbkdf2.Key(mbi, pepper, hashCfg.MbiHashIterations, hashCfg.MbiHashLength, sha256.New)
	*hashedMBI = fmt.Sprintf("%x", string(tmp))
	return nil
}

// test hashing function
func testHash(testmbi string, expected string, testCfg *Config) bool {
	beneMbi := []byte(testmbi)
	var mbiHash string
	hashMBI(beneMbi, &mbiHash, testCfg)
	result := mbiHash == expected
	return result
}

// process the queue for missing mbi hashes
func processHashes(hashCounter *uint64) error {

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
		err := errors.New("error testing hashing function")
		return err
	}
	var hashCost time.Duration
	hashCost = ((t1Duration + t2Duration) / 2)
	hashPerMil := (hashCost * 1000000) / time.Duration(runtime.NumCPU())
	fmt.Printf("mbi hashing will take around %v seconds per bene to process (around %v seconds per million with %v CPU's.)\n", hashCost.Seconds(), fmt.Sprintf("%s", hashPerMil), runtime.NumCPU())

	qCount, _, mbiCount, err := badgerStatus()
	handleErr(err, "", nil, nil)
	numLeft := qCount - mbiCount

	if force {
		numLeft = qCount
	}

	if numLeft == 0 {
		fmt.Println("all benes have been checked.")
		displayQueueStats()
		return nil
	}

	// determine how many workers to use
	var numHashWorkers int
	if cfg.NumMbiHashWorkers > 0 {
		numHashWorkers = cfg.NumMbiHashWorkers
	} else {
		numHashWorkers = runtime.NumCPU()
	}

	// set hash buffer value
	var hashBuffer int
	if cfg.MbiHashBuffer > 1 {
		hashBuffer = cfg.MbiHashBuffer
	} else {
		hashBuffer = 1
	}

	// progress bar
	count := int64(numLeft)
	bar := pb.New64(count)
	hashDoneChan := make(chan bool, 1)
	barStart := false
	bar.ShowPercent = true
	bar.ShowBar = true
	bar.ShowCounters = true
	bar.ShowTimeLeft = true
	go func() {
		for <-hashDoneChan {
			if barStart == false {
				bar.Start()
				barStart = true
			}
			bar.Increment()
		}
	}()

	// launch the Hash workers
	fmt.Printf("spawning %v workers.\n", numHashWorkers)
	var beneChan = make(chan beneEntry, hashBuffer)
	var wg sync.WaitGroup
	var i int
	for i = 0; i < numHashWorkers; i++ {
		wg.Add(1)
		go hashWorker(i, beneChan, &wg, hashDoneChan, hashCounter)
	}

	fmt.Println("finding/updating missing mbi hashes.")
	err = queue.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			err := it.Item().Value(func(v []byte) error {
				var bene beneEntry
				bene.key = it.Item().KeyCopy(nil)
				bene.status = v
				if bene.Status() == "" || bene.Status() == "1" || force == true {
					beneChan <- bene
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
	finMsg := fmt.Sprintf("%v MBI hashes were updated.", *hashCounter)
	bar.FinishPrint(finMsg)
	logger.Println("STAT: ", finMsg)
	fmt.Printf("done.\n\n")
	return nil
}

// checks/updates missing mbi hashes for each bene sent from processHashes()
func hashWorker(id int, beneChan <-chan beneEntry, wg *sync.WaitGroup, hashDoneChan chan<- bool, hashCounter *uint64) {
	defer wg.Done()
	// used to log a few beneficiariesHistoryId's were mbi hashes were generated for later verification. to grep the entries, run:
	// $> grep "VERIFY_HASH" log
	var hashSampleCounter int32

	for bene := range beneChan {
		bene := bene

		// try to avoid going oom.. cleanup and backoff
		for mem := freeMem(); mem.ActualFree < 1024; mem = freeMem() {
			queue.RunValueLogGC(.5)
			runtime.GC()
			time.Sleep(time.Duration(5) * time.Second)
		}

		// look for missing mbi's
		rows, err := db.Query(context.Background(), missingMbiPattern, bene.Key())
		if err != nil {
			handleErr(err, "", nil, nil)
			continue
		}
		defer rows.Close()

		// append hash results to []hashQueue
		var hashQueue []hashBatch
		for rows.Next() {
			// hash the mbi
			var beneHistoryID int64
			var medicareBenecificaryID []byte
			var mbiHash string
			rows.Scan(&beneHistoryID, &medicareBenecificaryID)
			mbi := string(medicareBenecificaryID)
			if mbi == "" {
				// no medicareBenecificaryId to hash
				continue
			}
			err := hashMBI([]byte(mbi), &mbiHash, &cfg)
			if err != nil {
				logger.Fatal(err)
			}
			// add to the batch
			batch := hashBatch{beneHistoryID: beneHistoryID, mbiHash: mbiHash}
			hashQueue = append(hashQueue, batch)
		}
		rows.Close()

		// grab a connection from the pool
		conn, err := db.Acquire(context.Background())
		handleErr(err, "pools empty", nil, nil)
		defer conn.Release()

		// start a transaction
		txn, err := conn.Begin(context.Background())
		defer txn.Rollback(context.Background())

		// loop through []hashQueue and update the bene history table
		for _, hash := range hashQueue {
			// UPDATE "BeneficiariesHistory" SET "mbiHash" = $1 WHERE "beneficiaryId" = $2 AND "beneficiaryHistoryId" = $3;
			result, err := txn.Exec(context.Background(), updateHashPattern, hash.mbiHash, bene.Key(), hash.beneHistoryID)
			if err != nil {
				handleErr(err, "", txn, conn)
				continue
			}
			if result.RowsAffected() > 0 {
				// will log ~ one entry per worker for later verification
				if hashSampleCounter < 1 {
					logger.Println("VERIFY_HASH beneficiaryHistoryId: ", strconv.FormatInt(hash.beneHistoryID, 10))
					atomic.AddInt32(&hashSampleCounter, 1)
				}
				atomic.AddUint64(hashCounter, uint64(result.RowsAffected()))
			}
		}
		if err := txn.Commit(context.Background()); err != nil {
			fmt.Println("error commit transaction")
		}

		if force == false {
			// update queue status
			switch bene.Status() {
			case "1":
				bene.status = []byte("3")
			default:
				bene.status = []byte("2")
			}
			ok, err := bene.Update()
			if !ok {
				handleErr(err, "error marking bene complete", nil, conn)
				continue
			}
		}

		conn.Release()
		hashDoneChan <- true
	}
}

func main() {
	// custom error logger with date and time
	logger = log.New(os.Stderr, "", log.Ldate|log.Ltime)

	// load app settings from environment
	err := envconfig.Process("BH_", &cfg)
	if err != nil {
		logger.Fatal(err)
	}

	// open postgres
	psqlInfo := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", cfg.RwDbUser, cfg.RwDbPassword, cfg.RwDbHost, cfg.RwDbPort, cfg.DbName)
	config, err := pgxpool.ParseConfig(psqlInfo)
	config.MaxConns = int32(cfg.DbMaxConns)
	config.MaxConnIdleTime = time.Duration(5) * time.Second
	db, err = pgxpool.ConnectConfig(context.Background(), config)
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

	// open dup queue
	queue, err = badger.Open(badger.DefaultOptions("cleanup.queue"))
	if err != nil {
		logger.Fatal(err)
	}
	defer queue.Close()
	badgerCloseHandler()

	// close the pipe and go back to normal stdout. badger really only writes to stderr anyway.
	w.Close()
	os.Stdout = oldStdout
	<-stdOutChan

	// parse flags
	flag.CommandLine.SetOutput(os.Stdout)
	buildQueueFlag := flag.Bool("build-queue", false, "build the queue")
	processDupsFlag := flag.Bool("process-dups", false, "run dedup process")
	processHashesFlag := flag.Bool("process-hashes", false, "update missing mbi hashes.")
	resetQueueFlag := flag.Bool("reset-queue", false, "resets all benes to an unprocessed state")
	statsFlag := flag.Bool("stats", false, "display queue stats")
	vacuumFlag := flag.Bool("vacuum", false, "runs 'VACUUM ANALYZE' on the db to free up space and update db statistics")
	forceFlag := flag.Bool("force", false, "process the bene no matter their current status")
	verifyFlag := flag.Bool("verify", false, "verify mbi hash. must provide -mbi and -expected args. Returns true or false.")
	mbiFlag := flag.String("mbi", "", "mbi used with -verify")
	expectedFlag := flag.String("expected", "", "expected hash used with -verify")
	flagged := false
	flag.Parse()

	// force
	if *forceFlag {
		force = true
	}

	// rebuild/reset the queue
	if *resetQueueFlag {
		flagged = true
		err := resetQueue()
		if err != nil {
			logger.Fatal(err)
		}
	}

	// build the queue
	if *buildQueueFlag {
		flagged = true
		err := buildQueue()
		if err != nil {
			logger.Fatal(err)
		}
	}

	// process the queue for dups
	if *processDupsFlag == true {
		flagged = true
		// used to track progress on replays
		var dupCounter uint64
		err := processDups(&dupCounter)
		if err != nil {
			logger.Fatal(err)
		}
	}

	// process the queue for missing hashes
	if *processHashesFlag == true {
		flagged = true
		var hashCounter uint64
		err := processHashes(&hashCounter)
		if err != nil {
			logger.Fatal(err)
		}
	}

	// verify mbi hash
	if *verifyFlag == true {
		flagged = true
		fmt.Println(testHash(*mbiFlag, *expectedFlag, &cfg))
		os.Exit(0)
	}

	// display queue stats
	if *statsFlag == true {
		flagged = true
		fmt.Println("gathering stats.")
		if err := displayQueueStats(); err != nil {
			logger.Fatal(err)
		}
	}

	// vacuum
	if *vacuumFlag == true {
		flagged = true
		fmt.Println("running 'VACUUM ANALYZE'. This may take ~30 minutes or longer.")
		if runVacuum() {
			fmt.Println("done.")
		} else {
			os.Exit(1)
		}
	}

	// no flags were passed
	if !flagged {
		fmt.Println("nothing to do.")
		flag.Usage()
		os.Exit(1)
	}
}
