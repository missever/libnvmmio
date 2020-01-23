# Libnvmmio
We have designed and implemented *Libnvmmio* to maximize the IO performance of non-volatile main memory (NVMM) systems. 
The purpose of Libnvmmio is eliminating software overhead, providing low-latency, scalable file IO while ensuring data-atomicity.
As the name indicates, Libnvmmio is linked with applications as a library, providing an efficient IO path using the ```mmap``` interface. 
