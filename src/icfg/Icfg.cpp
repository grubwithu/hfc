#include "Icfg.hpp"
#include "lib/DotParser.h"
#include <cassert>
#include <iostream>
#include <regex>
#include <string>

namespace icfg {

DotGraph *programICFG = nullptr;

void initProgramIcfg(std::string &DotFilePath) {
  std::cout << "Loading ICFG from " << DotFilePath << std::endl;
  programICFG = DotParser::ParseFromFile(DotFilePath);

  // for (auto node : programICFG->GetNodes()) {
  //   if (node->GetAttributes().find("label") == node->GetAttributes().end()) {
  //     continue;
  //   } else {
  //     auto& attributes = node->GetAttributes();
  //     NodeLabel icfgNode(attributes.GetValue("label"));
  //   }
  // }
}


} // namespace icfg
