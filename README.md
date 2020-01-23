# Libnvmmio
We have designed and implemented *Libnvmmio* to provide efficient file IO to maximize the performance of low-latency storage systems.
The purpose of Libnvmmio is eliminating software overhead, providing low-latency, scalable file IO while ensuring data-atomicity.
As the name indicates, Libnvmmio is linked with applications as a library, providing an efficient IO path using the ```mmap``` interface. 
