package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cheggaaa/pb"
	badger "github.com/dgraph-io/badger/v2"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/kelseyhightower/envconfig"
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
	MbiNumHashWorkers int    `envconfig:"BH_MBI_NUM_HASH_WORKERS"`
	MbiHashBuffer     int    `envconfig:"BH_MBI_HASH_BUFFER"`
	MbiHashPepper     string `envconfig:"BH_MBI_HASH_PEPPER"`
	MbiHashIterations int    `envconfig:"BH_MBI_HASH_ITERATIONS"`
	MbiHashLength     int    `envconfig:"BH_MBI_HASH_LENGTH"`
}

// missing mbi hash patterns
const (
	missingMbiPattern      = `SELECT "beneficiaryHistoryId", "medicareBeneficiaryId" FROM "BeneficiariesHistory" WHERE "beneficiaryId" = $1 AND "mbiHash" IS NULL AND "medicareBeneficiaryId" IS NOT NULL`
	missingMbiCountPattern = `SELECT count(*) FROM "BeneficiariesHistory" WHERE "beneficiaryId" = $1 AND "mbiHash" IS NULL AND "medicareBeneficiaryId" IS NOT NULL`
	updateHashPattern      = `UPDATE "BeneficiariesHistory" SET "mbiHash" = $1 WHERE "beneficiaryId" = $2 AND "beneficiaryHistoryId" = $3`
)

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
			if status == "2" || status == "3" {
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

// runs cleanup workers for each bene in the queue
func processQueue(db *pgxpool.Pool, queue *badger.DB, cfg *Config, logger *log.Logger, hashDoneChan chan<- bool) {
	// determine how many workers to use
	var numHashWorkers int
	if cfg.MbiNumHashWorkers > 0 {
		numHashWorkers = cfg.MbiNumHashWorkers
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

	// launch the Hash workers
	var hashesUpdated uint64
	fmt.Printf("spawning %v workers.\n", numHashWorkers)
	var beneChan = make(chan *badger.Item, hashBuffer)
	var wg sync.WaitGroup
	var i int
	for i = 0; i < numHashWorkers; i++ {
		wg.Add(1)
		go hashWorker(i, queue, beneChan, db, logger, cfg, hashDoneChan, &hashesUpdated)
	}

	// loop through all the keys and to workers for processing TODO: update
	fmt.Println("updating missing mbi hashes.")
	err := queue.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			var status []byte
			err = badgerRead(queue, it.Item().Key(), status)
			if err != nil {
				logger.Fatal(err)
			}
			if string(status) == "" || string(status) == "2" {
				beneChan <- it.Item()
			}
		}
		return nil
	})
	if err != nil {
		logger.Println("error queuing work")
		logger.Fatal(err)
	}
	wg.Wait()
	fmt.Printf("%v missing mbi hashes were updated.", hashesUpdated)

}

func hashWorker(id int, queue *badger.DB, beneChan <-chan *badger.Item, db *pgxpool.Pool, logger *log.Logger, cfg *Config, hashDoneChan chan<- bool, hashesUpdated *uint64) {
	for bene := range beneChan {
		bene := bene
		beneid := bene.Key()

		// check if completed.. skip if so
		// 1 == dups, 2 == hashes, 3 == both
		completed := false
		var beneStatus string
		if err := bene.Value(func(v []byte) error {
			beneStatus = string(v)
			if beneStatus == "2" || beneStatus == "3" {
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

		// look for missing mbi's
		conn, err := db.Acquire(context.Background())
		if err != nil {
			logger.Println(err)
			conn.Release()
			continue
		}
		defer conn.Release()
		txn, err := conn.Begin(context.Background())
		rows, err := txn.Query(context.Background(), missingMbiPattern, string(beneid))
		if err != nil {
			logger.Println("error querying missing mbi hashes for ", string(beneid))
			logger.Fatal(err)
		}
		defer rows.Close()

		// parse results
		type hashBatch struct {
			beneHistoryID string
			mbiHash       string
		}
		var hashQueue []hashBatch
		var hashCounter int
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
			batch := hashBatch{beneHistoryID: beneHistoryID, mbiHash: mbiHash}
			hashQueue = append(hashQueue, batch)
			hashCounter++
		}
		txn.Commit(context.Background())
		rows.Close()
		conn.Release()

		// update the record
		conn, err = db.Acquire(context.Background())
		if err != nil {
			logger.Println(err)
			conn.Release()
			continue
		}
		defer conn.Release()

		txn, err = conn.Begin(context.Background())
		if err != nil {
			logger.Fatal(err)
		}
		for _, hash := range hashQueue {
			_, err = txn.Exec(context.Background(), updateHashPattern, hash.mbiHash, beneid, hash.beneHistoryID)
			if err != nil {
				txn.Rollback(context.Background())
				conn.Release()
				logger.Printf("error executing query for bene: %v - bh history entry: %v\n", string(beneid), hash.beneHistoryID)
				logger.Fatal(err)
			}
		}
		txn.Commit(context.Background())
		conn.Release()

		// mark bene as done
		ok, _ := badgerWrite(queue, beneid, []byte("2"))
		if ok {
			atomic.AddUint64(hashesUpdated, uint64(hashCounter))
			hashDoneChan <- true
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
	processQueueFlag := flag.Bool("process-queue", false, "process the queue")
	flag.Parse()

	// exit if no flag was set
	if *processQueueFlag != true {
		fmt.Println("nothing to do.")
		flag.Usage()
		os.Exit(1)
	}

	// open postgres
	psqlInfo := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", cfg.RwDbUser, cfg.RwDbPassword, cfg.RwDbHost, cfg.RwDbPort, cfg.DbName)
	db, err := pgxpool.Connect(context.Background(), psqlInfo)
	if err != nil {
		logger.Fatal(err)
	}
	defer db.Close()

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
	fmt.Printf("mbi hashing will take around %v seconds per bene to process (around %v seconds per million)\n", hashCost.Seconds(), fmt.Sprintf("%s", hashPerMil))

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

	// get queue status
	qCount, doneCount, err := badgerStatus(queue)
	if err != nil {
		logger.Println("error getting queue status")
		logger.Fatal(err)
	}

	numBenesToProcess := (qCount - doneCount)
	p := message.NewPrinter(message.MatchLanguage("en")) // used to print numbers with comma's
	p.Printf("queue stats: %v bene's in queue - %v completed - %v remain.\n", qCount, doneCount, numBenesToProcess)

	// progress bar
	count := int64(numBenesToProcess)
	bar := pb.New64(count)
	hashDoneChan := make(chan bool)
	barStart := false
	bar.ShowPercent = true
	bar.ShowBar = true
	bar.ShowCounters = false
	bar.ShowTimeLeft = true
	go func() {
		for <-hashDoneChan {
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
		processQueue(db, queue, &cfg, logger, hashDoneChan)
	}
	bar.FinishPrint("complete.")

}
