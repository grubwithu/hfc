# API

## POST

### /reportCorpus

Request Body:
```json
{
    "fuzzer": "AFL",
    "identity": "master_1",
    "corpus": [
        "/path/to/corpus1",
        "/path/to/corpus2"
    ]
}
```

Response Body:
```json
{
  "success": true,
  "message": "Corpus report received successfully. Processing in background.",
  "data": {
    "task_id": "554f3a04-01d8-4292-b55f-4b8fd06d6bed"
  }
}
```


## GET
### /peekResult/:taskId

Response Body:
```json
{
  "success": true,
  "message": "Task status retrieved",
  "data": {
    "constraint_groups": [
      {
        "group_id": "1",
        "function": "main",
        "total_importance": 100.0
      }
    ]
  }
}
```
