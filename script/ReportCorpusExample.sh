curl -X POST -H "Content-Type: application/json" \
  -d '{"fuzzer": "AFL", "identity": "master_1", "corpus": ["test/seeds/"]}' \
  http://localhost:8080/reportCorpus

