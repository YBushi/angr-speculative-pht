# angr-speculative-pht
Symbolic execution based tool for detecting speculative execution vulnerabilities (Spectre-PHT) in binaries developed as part of my Bachelor's Thesis at Vrije Universiteit Amsterdam.
Disclaimer: Parts of this repository were build on work from other sources  
The angr folder was copied from the memsight Github repository (https://github.com/gleissen/memsightpp/tree/main)  
The container_setup folder and Dockerfile were copied and modified for this project from memsight Github repository (https://github.com/gleissen/memsightpp/tree/main)  
The test cases named spectre_test{Number} were created using an LLM. They were created for the sole purpose of development and debugging. Results obtained from these cases will not be presented in the thesis.
## Installation
### Docker
#### Apple Silicon Mac
#### Prerequisites
Enable: "Use Rosetta for x86/amd64 emulation"  
Enable: "Use the Apple Virtualization framework"  
Enable QEMU emulation: "docker run --rm --privileged tonistiigi/binfmt --install all"  
Build the container: "docker buildx build --platform linux/amd64 -t angr-spec --load ."  
<pre> Run the container: docker run -it --platform=linux/amd64 -v "$(pwd)":/workspace -w /workspace angr-spec</pre>
#### Windows with WSL2
Enable QEMU emulation: "docker run --rm --privileged tonistiigi/binfmt --install all"  
Build the container: "docker buildx build --platform linux/amd64 -t angr-spec --load ."  
<pre> docker run -it --platform=linux/amd64 -v "$(pwd)":/workspace -w /workspace angr-spec</pre>
## Compiling 
To compile a c-file from test_sources run command: gcc -fno-pie -no-pie -O0 -o ../test_binaries/output_binary your_file.c
