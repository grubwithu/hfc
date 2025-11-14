.PHONY: build run

build:
	mkdir -p build
	go build -o build/hfc

# TEST_STATIC_FILE := $(shell ls ./test/fuzzerLogFile*.yaml | head -n 1)

# test: build
# 	./build/hfc -program=./test/main.out -staticdata=$(STATIC_FILE)
