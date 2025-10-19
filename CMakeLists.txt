cmake_minimum_required(VERSION 3.14)
project(hfc VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB WEBCORE_SRC_FILES "src/webcore/*.cpp")
file(GLOB WEBCORE_HEAD_FILES "src/webcore/*.hpp")

file(GLOB PFUZZER_SRC_FILES "src/pfuzzer/*.cpp")
file(GLOB PFUZZER_HEAD_FILES "src/pfuzzer/*.hpp")

add_executable(${PROJECT_NAME}
  src/Main.cpp
  ${WEBCORE_SRC_FILES}
  ${WEBCORE_HEAD_FILES}
  ${PFUZZER_SRC_FILES}
  ${PFUZZER_HEAD_FILES}
)

find_package(Poco REQUIRED Net Util Foundation XML JSON)
target_link_libraries(${PROJECT_NAME}
  PRIVATE
    Poco::Net
    Poco::Util
    Poco::Foundation
    Poco::XML
    Poco::JSON
)
