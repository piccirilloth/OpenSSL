cmake_minimum_required(VERSION 3.20)
project(openSSL_CBC C)

set(CMAKE_C_STANDARD 11)
find_package(OpenSSL REQUIRED)

add_executable(openSSL_CBC main.c)

target_include_directories(openSSL_CBC PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(openSSL_CBC ${OPENSSL_LIBRARIES})
