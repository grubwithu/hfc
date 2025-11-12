#!/bin/bash

TASK_ID=$1

curl -X GET -H "Content-Type: application/json" \
  http://localhost:8080/peekResult/$TASK_ID

