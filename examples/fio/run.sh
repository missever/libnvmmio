#!/bin/bash
export PMEM_PATH=/mnt/pmem

for workload in "read" "randread" "write" "randwrite"
do
	if [ -e "$PMEM_PATH"/*"" ]; then
		rm "$PMEM_PATH"/*""
	fi

	numactl --cpunodebind=0 ./fio \
		--name=test \
		--ioengine=sync \
		--directory=$PMEM_PATH \
		--rw=$workload \
		--filesize=4g \
		--bs=4k \
		--thread --numjobs=1 \
		--runtime=60 --time_based

done
