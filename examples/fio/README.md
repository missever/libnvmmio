# fio
We cloned the 3.8 version of fio from [its github repository](https://github.com/axboe/fio/tree/ac694f66968fe7b18c820468abd8333f3df333fb) and modified it to use libnvmmio.
As shown in the [fio-libnvmmio.patch](fio-libnvmmio.patch) file, we only modified 8 lines.
After building fio, you can run fio using the [run.sh](run.sh) script.
