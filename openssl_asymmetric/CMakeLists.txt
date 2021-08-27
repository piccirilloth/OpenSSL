cmake_minimum_required(VERSION 3.20)
project(openssl_asymmetric C)

find_package(OpenSSL REQUIRED)
set(CMAKE_C_STANDARD 11)

add_executable(openssl_asymmetric main.c)
target_include_directories(openssl_asymmetric PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(openssl_asymmetric ${OPENSSL_LIBRARIES})