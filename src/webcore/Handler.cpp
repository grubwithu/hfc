#include "Handler.hpp"
#include "pfuzzer/FuzzerDefs.h"
#include "pfuzzer/FuzzerPlatform.h"
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>
#include <iostream>
#include <cstdlib>
#include <sstream>
#include <string>

extern "C" {
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
}

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
      // TODO: Only directory supported currently.
      std::cout << "corpus: " << c.toString() << std::endl;
    }

    char tmpPath[] = "/tmp/hfcXXXXXXX";
    if (mkdtemp(tmpPath) == nullptr) {
      std::cerr << "mkdtemp failed" << std::endl;
      response.setStatus(HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
      response.setContentType("text/plain");

      std::ostream &ostr = response.send();
      ostr << "Internal server error\n";
      return;
    }

    int argc = corpus->size() + 1;
    char **argv = new char*[argc];
    argv[0] = tmpPath;
    for (size_t i = 0; i < corpus->size(); i++) {
      argv[i + 1] = const_cast<char*>(corpus->get(i).toString().c_str());
    }
    fuzzer::FuzzerDriver(&argc, &argv, LLVMFuzzerTestOneInput);
    delete[] argv;
    rmdir(tmpPath);
    
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
