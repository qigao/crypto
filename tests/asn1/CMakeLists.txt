# Exact original BER/DER, owned value-tree and cryptographic-format
# conformance cases, migrated to the single static Salts::Crypto owner.
# No SaltsCore, TinyTest or secondary ASN.1 provider dependency.
foreach(_case IN ITEMS reader value crypto)
  add_executable(crypto_asn1_${_case}_test ${_case}.c)
  target_compile_features(crypto_asn1_${_case}_test PRIVATE c_std_11)
  set_target_properties(crypto_asn1_${_case}_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
  target_link_libraries(crypto_asn1_${_case}_test PRIVATE Salts::Crypto)
  add_test(NAME crypto.asn1.${_case}
    COMMAND crypto_asn1_${_case}_test)
  set_tests_properties(crypto.asn1.${_case} PROPERTIES TIMEOUT 120)
endforeach()

add_executable(crypto_asn1_header_cpp_test header_cpp.cpp)
target_compile_features(crypto_asn1_header_cpp_test PRIVATE cxx_std_17)
target_link_libraries(crypto_asn1_header_cpp_test PRIVATE Salts::Crypto)
add_test(NAME crypto.asn1.header_cpp17 COMMAND crypto_asn1_header_cpp_test)
set_tests_properties(crypto.asn1.header_cpp17 PROPERTIES TIMEOUT 120)
