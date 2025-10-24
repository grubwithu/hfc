#pragma once

#include <cassert>
#include <iostream>
#include <regex>
#include <string>
#include <unordered_map>
#include <vector>

namespace icfg {

struct NodeLabel {
  std::string id;

  std::string func;

  size_t line;
  size_t column;
  std::string file;

  NodeLabel(const std::string &label) {
    assert(label[0] == '{');
    size_t pos = label.find_first_of(' ');
    id = label.substr(1, pos - 1);

    func = extract(label, R"(fun: ([a-zA-Z_][a-zA-Z0-9_\.]*))");

    auto line_str = extract(label, R"(\\\"ln\\\": (\d+))");
    line = line_str.empty() ? 0 : std::stoul(line_str);

    auto col_str = extract(label, R"(\\\"cl\\\": (\d+))");
    column = col_str.empty() ? 0 : std::stoul(col_str);
    
    file = extract(label, R"(\\\"fl\\\": \"(.*?)\"")");
    if (file.empty()) {
      file = extract(label, R"(\\\"file\\\": \\\"(.*?)\\\")");
    }
  }

  NodeLabel() { }

private:
  static std::string extract(const std::string &label, const std::string &regex) {
    std::regex funcRegex(regex);
    std::smatch match;
    if (std::regex_search(label, match, funcRegex)) {
      return match[1].str();
    }
    return "";
  }
};

class TAttributes : public std::unordered_map<std::string, std::string> {
public:
  bool HasValue(const std::string &_sKey, const std::string &_sValue) const {
    const auto it = find(_sKey);
    return it != end() && it->second == _sValue;
  }

  std::string GetValue(const std::string &_sKey) const {
    const auto it = find(_sKey);
    return it != end() ? it->second : "";
  }
};

class DotNode {
public:
  struct Successor {
    Successor(DotNode *_pNode = nullptr, const TAttributes &_Attributes = {}) : pNode(_pNode), Attributes(_Attributes) {
    }

    DotNode *pNode = nullptr;
    TAttributes Attributes; // Edge Attributes
  };

  DotNode(const std::string &_sName = {}, const std::vector<Successor> &_Successors = {},
          const TAttributes &_Attributes = {})
      : m_sName(_sName), m_Successors(_Successors), m_Attributes(_Attributes) {
  }

  DotNode(DotNode &&_Other)
      : m_sName(std::move(_Other.m_sName)), m_Attributes(std::move(_Other.m_Attributes)),
        m_Successors(std::move(_Other.m_Successors)) {
  }

  ~DotNode() {};

  DotNode *AddSuccessor(DotNode *_pNode, const TAttributes &_Attributes = {}) {
    m_Successors.emplace_back(_pNode, _Attributes);
    return this;
  }

  DotNode *AddAttributes(const TAttributes &_Attributes, const bool _bOverride = false) {
    for (const auto &[k, v] : _Attributes) {
      SetAttribute(k, v, _bOverride);
    }
    return this;
  }

  DotNode *SetAttribute(const std::string &_sKey, const std::string &_sValue, const bool _bOverride = false) {
    if (_bOverride || m_Attributes.count(_sKey) == 0u) {
      if (_sKey.compare("label") == 0) {
        label = NodeLabel(_sValue);
      }
      m_Attributes[_sKey] = _sValue;
    }
    return this;
  }

  const std::string &GetName() const {
    return m_sName;
  }
  const TAttributes &GetAttributes() const {
    return m_Attributes;
  }
  const std::vector<Successor> &GetSuccessors() const {
    return m_Successors;
  }

private:
  std::string m_sName;

  TAttributes m_Attributes; // Node Attributes
  std::vector<Successor> m_Successors;

  NodeLabel label;
};

} // namespace icfg
