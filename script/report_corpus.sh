#!/bin/bash

CORPUS=$1
# make sure CORPUS is abs path
if [ ! -d "$CORPUS" ]; then
  echo "Error: $CORPUS is not a directory"
  exit 1
fi
CORPUS=$(realpath $CORPUS)


curl -X POST -H "Content-Type: application/json" \
  -d '{"fuzzer": "AFL", "identity": "master_1", "corpus": ["'$CORPUS'"]}' \
  http://localhost:8080/reportCorpus

