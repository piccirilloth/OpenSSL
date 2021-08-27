cmake_minimum_required(VERSION 3.20)
project(prime C)

find_package(OpenSSL REQUIRED)
set(CMAKE_C_STANDARD 11)

add_executable(prime main.c)
target_include_directories(prime PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(prime ${OPENSSL_LIBRARIES})
