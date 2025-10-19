#include "Server.hpp"
#include "Handler.hpp"
#include <iostream>

int Server::main(const std::vector<std::string> &args) {
  Poco::UInt16 port = 8080;
  Poco::Net::ServerSocket svs(port);

  Poco::Net::HTTPServerParams *params = new Poco::Net::HTTPServerParams;
  params->setMaxQueued(100);
  params->setMaxThreads(8);

  Poco::Net::HTTPServer server(new RequestHandlerFactory, svs, params);
  server.start();
  std::cout << "HTTP server started on port " << port << std::endl;

  waitForTerminationRequest();
  std::cout << "Shutting down..." << std::endl;
  server.stop();

  return Application::EXIT_OK;
}