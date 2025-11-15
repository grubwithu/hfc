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
### /peekResult

Response Body:
```json
{
  "success": true,
  "message": "Constraint groups retrieved",
  "data": {
    "constraint_groups": [
      {
        "group_id": "1ca34b37-d225-4944-b981-ab74157e8842",
        "function": "png_handle_sCAL",
        "importance": 0.483546069753371,
        "paths":[ ["LLVMFuzzerTestOneInput", "png_read_info"] ]
      }
    ]
  }
}
```
