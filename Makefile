SHELL = /bin/bash
export PATH := $(shell yarn global bin):$(PATH)

default: lint test

test:
	go test -race -v ./...

benchmark:
	go test -bench '.' -benchtime=2s -benchmem ./... | tee output.txt

lint:
	golangci-lint run --verbose
