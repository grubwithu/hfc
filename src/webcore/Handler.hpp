#pragma once
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <unordered_map>
#include <functional>

using HTTPRequestHandler = Poco::Net::HTTPRequestHandler;
using HTTPServerRequest = Poco::Net::HTTPServerRequest;
using HTTPServerResponse = Poco::Net::HTTPServerResponse;
using HTTPRequestHandlerFactory = Poco::Net::HTTPRequestHandlerFactory;
using HTTPRequest = Poco::Net::HTTPRequest;
using HTTPResponse = Poco::Net::HTTPResponse;

template <typename K, typename V>
using map = std::unordered_map<K, V>;
using path = std::string;
using handler = std::function<void(HTTPServerRequest &request,
                                   HTTPServerResponse &response)>;

class RequestHandler : public HTTPRequestHandler {
public:
  void handleRequest(HTTPServerRequest &request,
                     HTTPServerResponse &response) override;
  RequestHandler();

private:
  map<path, handler> getHandlers;
  void handleGetRequest(HTTPServerRequest &request,
                        HTTPServerResponse &response);
  map<path, handler> postHandlers;
  void handlePostRequest(HTTPServerRequest &request,
                         HTTPServerResponse &response);
};

class RequestHandlerFactory : public HTTPRequestHandlerFactory {
public:
  HTTPRequestHandler *createRequestHandler(const HTTPServerRequest &) override;
};
