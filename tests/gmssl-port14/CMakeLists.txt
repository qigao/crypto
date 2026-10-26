cmake_minimum_required(VERSION 3.21)
project(CryptoGmSSLPort14ParserContract LANGUAGES C)
include(CTest)
add_executable(crypto_gmssl_port14_parser ccs_hrr_parser.c)
set_target_properties(crypto_gmssl_port14_parser PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
target_include_directories(crypto_gmssl_port14_parser PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/../../providers/gmssl/candidates/port14")
if(MSVC)
  target_compile_options(crypto_gmssl_port14_parser PRIVATE /W4 /WX)
else()
  target_compile_options(crypto_gmssl_port14_parser PRIVATE -Wall -Wextra -Werror)
endif()
add_test(NAME crypto.candidate.rfc8446_ccs_and_hrr_padding
         COMMAND crypto_gmssl_port14_parser)
