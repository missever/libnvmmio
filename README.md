# Libnvmmio
We have designed and implemented *Libnvmmio* to maximize the IO performance of non-volatile main memory (NVMM) systems. 
The purpose of Libnvmmio is eliminating software overhead, providing low-latency, scalable file IO while ensuring data-atomicity.
As the name indicates, Libnvmmio is linked with applications as a library, providing an efficient IO path using the ```mmap``` interface. 

You can use Libnvmmio with any filesystem that provides ```DAX-mmap```, such as Ext4-DAX, XFS-DAX, PMFS, and NOVA.
The ```DAX-mmap``` allows Libnvmmio to map the pages of an NVMM-backed file into its address space and then access it via ```load``` and ```store``` instructions.
Libnvmmio intercepts and replaces ```read```/```write``` system calls with ```load```/```store``` instructions. 
