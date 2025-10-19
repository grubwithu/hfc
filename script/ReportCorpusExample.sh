curl -X POST -H "Content-Type: application/json" \
  -d '{"fuzzer": "AFL", "identity": "master_1", "corpus": ["corpus1", "corpus2"]}' \
  http://localhost:8080/reportCorpus

