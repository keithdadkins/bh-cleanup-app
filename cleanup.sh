#!/usr/bin/env bash

# source env vars
. .env

# build the queue
while true; do
  if ./bh-cleanup-app -build-queue 2>>log; then
    break
  else
    sleep 5
  fi
done

# process dups
while true; do
  if ./bh-cleanup-app -process-dups 2>>log; then
    break
  else
    sleep 5
  fi
done

# backfil hashes
while true; do
  if ./bh-cleanup-app -process-hashes 2>>log; then
    break
  else
    sleep 5
  fi
done

# run another dedup pass
while true; do
  if ./bh-cleanup-app -process-dups -force 2>>log; then
    break
  else
    sleep 5
  fi
done

# run a vacuum
./bh-cleanup-app -vacuum 2>>log

# display stats
./bh-cleanup-app -stats 2>>log

echo "FINISHED"
