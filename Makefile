.PHONY: build run v2 test-v2

GO ?= go

build:
	mkdir -p build
	$(GO) build -o build/hfc

v2:
	mkdir -p build/v2/bin
	$(GO) build -o build/v2/bin/orchestra-ossfuzz ./cmd/orchestra-ossfuzz
	$(GO) build -o build/v2/bin/orchestra-coordinator ./cmd/orchestra-coordinator

test-v2:
	$(GO) test ./internal/buildconfig ./internal/bitmap ./internal/contracts \
		./internal/artifact ./internal/ossfuzz ./internal/coordinator ./internal/frontier \
		./internal/programmodel ./internal/probe ./internal/worker \
		./cmd/orchestra-ossfuzz ./cmd/orchestra-coordinator

# TEST_STATIC_FILE := $(shell ls ./test/fuzzerLogFile*.yaml | head -n 1)

# test: build
# 	./build/hfc -program=./test/main.out -staticdata=$(STATIC_FILE)
