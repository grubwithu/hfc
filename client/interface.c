#include "cJSON.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ATTRIBUTE_INTERFACE 
#define ATTRIBUTE_INTERFACE __attribute__((visibility("default")))
#endif

// 响应数据回调函数
struct MemoryStruct {
  char *memory;
  size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if (ptr == NULL) {
    // 内存分配失败
    printf("Not enough memory (realloc returned NULL)\n");
    return 0;
  }

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

// 构建JSON请求体 - 使用cJSON库
static char *buildJsonBody(const char *fuzzer, const char *identity, const char *corpus[], int corpusCount) {
  // 创建主JSON对象
  cJSON *root = cJSON_CreateObject();
  if (root == NULL) {
    return NULL;
  }

  // 添加fuzzer和identity字段
  cJSON_AddStringToObject(root, "fuzzer", fuzzer);
  cJSON_AddStringToObject(root, "identity", identity);

  // 创建corpus数组
  cJSON *corpusArray = cJSON_CreateArray();
  if (corpusArray == NULL) {
    cJSON_Delete(root);
    return NULL;
  }

  // 添加corpus数组到主对象
  cJSON_AddItemToObject(root, "corpus", corpusArray);

  // 向数组中添加corpus项
  for (int i = 0; i < corpusCount; i++) {
    cJSON_AddItemToArray(corpusArray, cJSON_CreateString(corpus[i]));
  }

  // 将JSON对象转换为字符串
  char *jsonString = cJSON_PrintUnformatted(root);

  // 释放JSON对象
  cJSON_Delete(root);

  return jsonString;
}

// 从响应中解析taskId
static char *parseTaskId(const char *response) {
  if (response == NULL) {
    return NULL;
  }

  // 解析JSON响应
  cJSON *root = cJSON_Parse(response);
  if (root == NULL) {
    printf("Error parsing response: %s\n", cJSON_GetErrorPtr());
    return NULL;
  }

  // 获取data字段
  cJSON *data = cJSON_GetObjectItem(root, "data");
  if (data == NULL || !cJSON_IsObject(data)) {
    cJSON_Delete(root);
    return NULL;
  }

  // 获取taskId字段
  cJSON *taskId = cJSON_GetObjectItem(data, "taskId");
  if (taskId == NULL || !cJSON_IsString(taskId)) {
    cJSON_Delete(root);
    return NULL;
  }

  // 复制taskId字符串
  char *result = strdup(taskId->valuestring);

  // 释放JSON对象
  cJSON_Delete(root);

  return result;
}

// 发送reportCorpus请求
static char *reportCorpus(const char *serverUrl, const char *fuzzer, const char *identity, const char *corpus[],
                          int corpusCount) {
  CURL *curl;
  CURLcode res;
  char *taskId = NULL;

  // 初始化CURL
  curl = curl_easy_init();
  if (curl) {
    // 构建完整的URL
    char *fullUrl = (char *)malloc(strlen(serverUrl) + strlen("/reportCorpus") + 1);
    if (fullUrl == NULL) {
      curl_easy_cleanup(curl);
      return NULL;
    }
    sprintf(fullUrl, "%s/reportCorpus", serverUrl);

    // 构建JSON请求体
    char *jsonBody = buildJsonBody(fuzzer, identity, corpus, corpusCount);
    if (jsonBody == NULL) {
      free(fullUrl);
      curl_easy_cleanup(curl);
      return NULL;
    }

    // 设置响应内存
    struct MemoryStruct chunk;
    chunk.memory = malloc(1); // 初始化为非NULL
    chunk.size = 0;           // 尚未存储任何数据

    // 设置CURL选项
    curl_easy_setopt(curl, CURLOPT_URL, fullUrl);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonBody);

    // 设置HTTP头
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // 设置响应回调
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    // 执行请求
    res = curl_easy_perform(curl);

    // 检查结果
    if (res == CURLE_OK) {
      // 输出响应
      printf("Response: %s\n", chunk.memory);

      // 解析响应中的taskId
      taskId = parseTaskId(chunk.memory);
    } else {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }

    // 清理资源
    free(fullUrl);
    free(jsonBody);
    free(chunk.memory);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }

  return taskId; // 返回taskId，失败则为NULL
}

// 查询任务结果
static void peekResult(const char *serverUrl, const char *taskId) {
  if (taskId == NULL) {
    return;
  }

  CURL *curl;
  CURLcode res;

  // 初始化CURL
  curl = curl_easy_init();
  if (curl) {
    // 构建完整的URL
    char *fullUrl = (char *)malloc(strlen(serverUrl) + strlen("/peekResult/") + strlen(taskId) + 1);
    if (fullUrl == NULL) {
      curl_easy_cleanup(curl);
      return;
    }
    sprintf(fullUrl, "%s/peekResult/%s", serverUrl, taskId);

    // 设置响应内存
    struct MemoryStruct chunk;
    chunk.memory = malloc(1); // 初始化为非NULL
    chunk.size = 0;           // 尚未存储任何数据

    // 设置CURL选项
    curl_easy_setopt(curl, CURLOPT_URL, fullUrl);

    // 设置响应回调
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    // 执行请求
    res = curl_easy_perform(curl);

    // 检查结果
    if (res == CURLE_OK) {
      // 输出响应
      printf("Task result: %s\n", chunk.memory);
    } else {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }

    // 清理资源
    free(fullUrl);
    free(chunk.memory);
    curl_easy_cleanup(curl);
  }
}

ATTRIBUTE_INTERFACE void _hfc_report_corpus_sync(const char* corpusPath, const char* fuzzer, const char* identity) {

  // Get server URL from env
  char* serverUrl = getenv("HFC_SERVER_URL");
  if (serverUrl == NULL) {
    serverUrl = "http://localhost:8080";
  }
  int len = strlen(serverUrl);
  if (serverUrl[len - 1] == '/') {
    serverUrl[len - 1] = '\0';
  }

  char *corpus[1] = {corpusPath};

  char *taskId = reportCorpus(serverUrl, fuzzer, identity, corpus, 1);
  if (taskId != NULL) {

    while (1) {
      sleep(0.5);
      peekResult(serverUrl, taskId);
    }

    free(taskId);
  }
}
