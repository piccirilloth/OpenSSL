cmake_minimum_required(VERSION 3.20)
project(rsa C)

set(CMAKE_C_STANDARD 11)
find_package(OpenSSL REQUIRED)

add_executable(rsa main.c)

target_include_directories(rsa PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(rsa ${OPENSSL_LIBRARIES})
