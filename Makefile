FINDCMD = find . -maxdepth 1 -type f -name "*.py"
SHELL = /bin/bash
TARGETS = env test

.ONESHELL:
.PHONY: all $(TARGETS)

all:
	$(error Targets are: $(TARGETS))

env:
	wget https://github.com/conda-forge/miniforge/releases/download/4.14.0-0/Mambaforge-4.14.0-0-Linux-x86_64.sh -O installer.sh
	bash installer.sh -bfp .conda
	rm -v installer.sh
	source .conda/etc/profile.d/conda.sh
	conda create -y -n macroscope python=3.10 black ijson isort mypy pylint pytest sqlite
	@echo "Run 'source activate-env' to activate environment"

test:
	set -e
	$(FINDCMD) -exec black {} +
	$(FINDCMD) -exec isort --profile black {} +
	$(FINDCMD) -exec pylint {} +
	$(FINDCMD) -exec mypy --ignore-missing-imports {} +
