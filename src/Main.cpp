#include "icfg/Icfg.hpp"
#include "pfuzzer/FuzzerDefs.h"
#include "pfuzzer/FuzzerPlatform.h"
#include "webcore/Server.hpp"
#include <iostream>
#include <string>

extern "C" {
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
}

struct StartOption {
  bool runPfuzzer = false;
  std::string filePath;
};

static StartOption parseCommandLineArgs(int argc, char **argv);
bool hfcRunning = true;

ATTRIBUTE_INTERFACE int main(int argc, char **argv) {
  // Parse command line arguments
  auto option = parseCommandLineArgs(argc, argv);
  
  if (option.runPfuzzer) {
    fuzzer::FuzzerDriver(&argc, &argv, LLVMFuzzerTestOneInput);
    hfcRunning = false;
    return 0;
  }

  // If file path is specified, display information
  auto& filePath = option.filePath;
  if (!filePath.empty()) {
    std::cout << "Processing file: " << filePath << std::endl;
  } else {
    std::cout << "No file path specified, using default configuration" << std::endl;
    filePath = "test/icfg_initial.dot";
  }

  // Initialize ICFG with the specified file path
  icfg::initProgramIcfg(filePath);

  webcore::Server app;
  return app.run(argc, argv);
}

// Simple command line argument parser
static StartOption parseCommandLineArgs(int argc, char **argv) {
  StartOption opt;
  // Iterate through all arguments
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];

    // Check if it's -f parameter
    if (arg == "-f") {
      // Ensure there's a next argument
      if (i + 1 < argc) {
        opt.filePath = argv[i + 1];
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
    // Check if it's pfuzzer
    else if (arg == "--run-pfuzzer") {
      opt.runPfuzzer = true;
    }
    // Handle unknown parameters
    else if (arg[0] == '-') {
      std::cerr << "Error: Unknown parameter '" << arg << "'" << std::endl;
      std::cerr << "Use " << argv[0] << " -h for help" << std::endl;
      exit(1);
    }
  }

  return opt;
}