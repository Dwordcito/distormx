# CMake project to build distorm3 library with mingw cross compiled.
cmake_minimum_required(VERSION 3.0)

project(distorm3)

# set distorm3 include directory
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/distorm3/include)

# add subdirectory for tests
#add_subdirectory(tests)

# set distorm3 source directory
file(GLOB distorm_src
    "src/*.c"
    "distorm3/src/*.c"
)

add_library(distorm3 STATIC ${distorm_src})

add_executable(distorm3_example examples/main.cpp)
target_link_libraries(distorm3_example distorm3)
