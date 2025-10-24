#include "Handler.hpp"
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>
#include <iostream>
#include <sstream>
#include <string>

namespace webcore {

static void ReportCorpus(HTTPServerRequest &request, HTTPServerResponse &response);

RequestHandler::RequestHandler() {
  postHandlers["/reportCorpus"] = ReportCorpus;
}

/*****===========================================================*****/

static std::string getBody(HTTPServerRequest &request) {
  auto &istr = request.stream();
  return std::string((std::istreambuf_iterator<char>(istr)), std::istreambuf_iterator<char>());
}

static void ReportCorpus(HTTPServerRequest &request, HTTPServerResponse &response) {
  auto body = getBody(request);

  try {
    Poco::JSON::Parser parser;
    Poco::Dynamic::Var result = parser.parse(body);
    Poco::JSON::Object::Ptr object = result.extract<Poco::JSON::Object::Ptr>();

    std::string fuzzer = object->getValue<std::string>("fuzzer");
    std::string identity = object->getValue<std::string>("identity");
    auto corpus = object->getArray("corpus");

    std::cout << "fuzzer: " << fuzzer << std::endl;
    std::cout << "identity: " << identity << std::endl;
    for (const auto &c : *corpus) {
      std::cout << "corpus: " << c.toString() << std::endl;
    }
  } catch (const Poco::Exception &e) {
    std::cerr << "JSON parsing error: " << e.displayText() << std::endl;
    response.setStatus(HTTPResponse::HTTP_BAD_REQUEST);
    response.setContentType("text/plain");

    std::ostream &ostr = response.send();
    ostr << "Bad request\n";
    return;
  }

  response.setStatus(HTTPResponse::HTTP_OK);
  response.setContentType("text/plain");

  std::ostream &ostr = response.send();
  ostr << "OK\n";
}

void RequestHandler::handleRequest(HTTPServerRequest &request, HTTPServerResponse &response) {
  auto &method = request.getMethod();
  if (method == HTTPRequest::HTTP_GET) {
    handleGetRequest(request, response);
  } else if (method == HTTPRequest::HTTP_POST) {
    handlePostRequest(request, response);
  } else {
    response.setStatus(HTTPResponse::HTTP_METHOD_NOT_ALLOWED);
    response.setContentType("text/plain");

    std::ostream &ostr = response.send();
    ostr << "Method not allowed\n";
  }
}

void RequestHandler::handlePostRequest(HTTPServerRequest &request, HTTPServerResponse &response) {
  if (postHandlers.find(request.getURI()) != postHandlers.end()) {
    postHandlers[request.getURI()](request, response);
  } else {
    response.setStatus(HTTPResponse::HTTP_NOT_FOUND);
    response.setContentType("text/plain");

    std::ostream &ostr = response.send();
    ostr << "Not found\n";
  }
}

void RequestHandler::handleGetRequest(HTTPServerRequest &request, HTTPServerResponse &response) {
  if (getHandlers.find(request.getURI()) != getHandlers.end()) {
    getHandlers[request.getURI()](request, response);
  } else {
    response.setStatus(HTTPResponse::HTTP_NOT_FOUND);
    response.setContentType("text/plain");

    std::ostream &ostr = response.send();
    ostr << "Not found\n";
  }
}

HTTPRequestHandler *RequestHandlerFactory::createRequestHandler(const HTTPServerRequest &) {
  return new RequestHandler;
}

} // namespace webcore
