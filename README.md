# angr-speculative-pht
Symbolic execution based tool for detecting speculative execution vulnerabilities (Spectre-PHT) in binaries developed as part of my Bachelor's Thesis at Vrije Universiteit Amsterdam.
## Installation
### Docker
1. Clone the repository
2. Run the command: docker build -t angr-spec .
3. In the repository angr-speculative-pht run the command:  docker run -it \
--platform=linux/amd64 \
--mount type=bind,src="$(pwd)",target=/workspace \
-w /workspace \
angr-spec /bin/bash
