#include "icfg/Icfg.hpp"
#include "webcore/Server.hpp"
#include "pfuzzer/FuzzerPlatform.h"
#include <iostream>
#include <string>

static std::string parseCommandLineArgs(int argc, char **argv);

ATTRIBUTE_INTERFACE int main(int argc, char **argv) {
  // Parse command line arguments
  std::string filePath = parseCommandLineArgs(argc, argv);

  // If file path is specified, display information
  if (!filePath.empty()) {
    std::cout << "Processing file: " << filePath << std::endl;
  } else {
    std::cout << "No file path specified, using default configuration" << std::endl;
    filePath = "default.dot";
  }

  // Initialize ICFG with the specified file path
  icfg::initProgramIcfg(filePath);

  webcore::Server app;
  return app.run(argc, argv);
}

// Simple command line argument parser
static std::string parseCommandLineArgs(int argc, char **argv) {
  std::string filePath;

  // Iterate through all arguments
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];

    // Check if it's -f parameter
    if (arg == "-f") {
      // Ensure there's a next argument
      if (i + 1 < argc) {
        filePath = argv[i + 1];
        i++; // Skip the next argument (file path)
      } else {
        std::cerr << "Error: -f parameter requires a file path" << std::endl;
        exit(1);
      }
    }
    // Check if it's help parameter
    else if (arg == "-h" || arg == "--help") {
      std::cout << "Usage: " << argv[0] << " [-f file_path]" << std::endl;
      std::cout << "Options:" << std::endl;
      std::cout << "  -f <file_path>    Specify file to process" << std::endl;
      std::cout << "  -h, --help       Show this help message" << std::endl;
      exit(0);
    }
    // Handle unknown parameters
    else if (arg[0] == '-') {
      std::cerr << "Error: Unknown parameter '" << arg << "'" << std::endl;
      std::cerr << "Use " << argv[0] << " -h for help" << std::endl;
      exit(1);
    }
  }

  return filePath;
}