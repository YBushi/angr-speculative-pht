# angr-speculative-pht
Symbolic execution based tool for detecting speculative execution vulnerabilities (Spectre-PHT) in binaries developed as part of my Bachelor's Thesis at Vrije Universiteit Amsterdam.
## Installation
### Docker
#### Apple Silicon Mac
#### Prerequisites
Enable: "Use Rosetta for x86/amd64 emulation"  
Enable: "Use the Apple Virtualization framework"  
Enable QEMU emulation: "docker run --rm --privileged tonistiigi/binfmt --install all"  
Build the container: "docker buildx build --platform linux/amd64 -t angr-spec --load ."  
Run the container: "docker run -it \
  --platform=linux/amd64 \
  -v "$(pwd)":/workspace \
  -w /workspace \
  angr-spec"  
#### Windows with WSL2
Enable QEMU emulation: "docker run --rm --privileged tonistiigi/binfmt --install all"  
Build the container: "docker buildx build --platform linux/amd64 -t angr-spec --load ."  
Run the container: "docker run -it \
  --platform=linux/amd64 \
  -v "$(pwd)":/workspace \
  -w /workspace \
  angr-spec"  
## Compiling 
To compile a c-file from test_sources run command: gcc -fno-pie -no-pie -O0 -o ../test_binaries/output_binary your_file.c
