#pragma once
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPServerParams.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Util/ServerApplication.h>

namespace webcore {

class Server : public Poco::Util::ServerApplication {
protected:
  int main(const std::vector<std::string> &args) override;
};

}
