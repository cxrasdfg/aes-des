cmake_minimum_required(VERSION 3.7)
project(aes_and_des)

set(CMAKE_CXX_STANDARD 14)
set(SOURCE_FILES  des_main.cpp src/des.hpp src/aes.hpp src/triple_des.hpp)
add_executable(aes_and_des ${SOURCE_FILES})