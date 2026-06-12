cmake_minimum_required(VERSION 4.1)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PROJECT_NAME peparser)
project(${PROJECT_NAME} LANGUAGES CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

set(CPP
    ${CMAKE_CURRENT_SOURCE_DIR}/src/dataDirectories.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/dosHeader.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ntHeader.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/peParser.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sectionHeaders.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utils.cpp)

set(H ${CMAKE_CURRENT_SOURCE_DIR}/include/peParser.h)

add_executable(${PROJECT_NAME} ${CPP} ${H})
target_include_directories(${PROJECT_NAME}
                           PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
