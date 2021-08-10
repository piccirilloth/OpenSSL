cmake_minimum_required(VERSION 3.20)
project(hmac C)

find_package(OpenSSL REQUIRED)
set(CMAKE_C_STANDARD 11)

add_executable(hmac main.c)
target_include_directories(hmac PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(hmac ${OPENSSL_LIBRARIES})
