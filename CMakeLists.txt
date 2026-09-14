cmake_minimum_required(VERSION 3.20)
project(kpqc LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(KPQC_TEST_ENTROPY "Build a test-only entropy injection interface" OFF)
if(KPQC_TEST_ENTROPY)
    set(KPQC_RANDOMBYTES_SOURCE native/csrc/randombytes_test.c)
else()
    set(KPQC_RANDOMBYTES_SOURCE native/csrc/randombytes.c)
endif()

set(PQC_FIPS202_SYMBOLS
    sha3_256 sha3_256_inc_absorb sha3_256_inc_ctx_clone
    sha3_256_inc_ctx_release sha3_256_inc_finalize sha3_256_inc_init
    sha3_384 sha3_384_inc_absorb sha3_384_inc_ctx_clone
    sha3_384_inc_ctx_release sha3_384_inc_finalize sha3_384_inc_init
    sha3_512 sha3_512_inc_absorb sha3_512_inc_ctx_clone
    sha3_512_inc_ctx_release sha3_512_inc_finalize sha3_512_inc_init
    shake128 shake128_absorb shake128_ctx_clone shake128_ctx_release
    shake128_inc_absorb shake128_inc_ctx_clone shake128_inc_ctx_release
    shake128_inc_finalize shake128_inc_init shake128_inc_squeeze
    shake128_squeezeblocks shake256 shake256_absorb shake256_ctx_clone
    shake256_ctx_release shake256_inc_absorb shake256_inc_ctx_clone
    shake256_inc_ctx_release shake256_inc_finalize shake256_inc_init
    shake256_inc_squeeze shake256_squeezeblocks)

set(COMPACT_FIPS202_SYMBOLS
    KeccakF_RoundConstants sha3_256 sha3_512 shake128 shake128_absorb
    shake128_absorb_once shake128_finalize shake128_init shake128_squeeze
    shake128_squeezeblocks shake256 shake256_absorb shake256_absorb_once
    shake256_finalize shake256_init shake256_squeeze shake256_squeezeblocks)

set(NTRUPLUS_SYMBOLS
    baseinv basemul basemul_add crypto_kem_dec crypto_kem_enc
    crypto_kem_keypair hash_f hash_g hash_h invntt ntt poly_baseinv
    poly_basemul poly_basemul_add poly_cbd1 poly_crepmod3 poly_frombytes
    poly_invntt poly_ntt poly_sotp_decode poly_sotp_encode poly_sub
    poly_tobytes poly_triple zetas)

set(HAETAE_SYMBOLS
    brv8 fix_round hammingWeight_8 polyfixfix_sub sample_gauss
    shake128_stream_init shake256_absorb_thrice shake256_absorb_twice
    shake256_stream_init start_cube start_times_threehalves)

set(SMAUGT_SYMBOLS flipabs shake256_absorb_twice_squeeze)

function(kpqc_rename_symbols target name)
    foreach(symbol IN LISTS ARGN)
        target_compile_definitions(${target} PRIVATE "${symbol}=kpqc_${name}_${symbol}")
    endforeach()
endfunction()

function(kpqc_object_library target name wrapper include_dir)
    add_library(${target} OBJECT
        ${wrapper}
        ${KPQC_RANDOMBYTES_SOURCE}
        ${ARGN})
    target_include_directories(${target} PRIVATE ${include_dir})
    target_compile_definitions(${target} PRIVATE
        "KPQC_PREFIX=kpqc_${name}_"
        "randombytes=kpqc_${name}_randombytes")
    if(MSVC)
        target_compile_options(${target} PRIVATE /O2 /W0)
    else()
        target_compile_options(${target} PRIVATE
            -O2 -fvisibility=hidden -fno-strict-aliasing -w)
    endif()
    set_property(GLOBAL APPEND PROPERTY KPQC_OBJECT_TARGETS ${target})
endfunction()

function(kpqc_add_aimer parameter)
    set(name "aimer${parameter}")
    set(root "${CMAKE_CURRENT_SOURCE_DIR}/vendor/AIMer")
    string(SUBSTRING "${parameter}" 0 3 field_size)
    kpqc_object_library(${name} ${name} native/csrc/signature.c ${root}
        ${root}/aim2.c
        ${root}/hash.c
        ${root}/sign.c
        ${root}/tree.c
        ${root}/field${field_size}.c
        ${root}/common/fips202.c)
    target_include_directories(${name} PRIVATE ${root}/common)
    target_compile_definitions(${name} PRIVATE PARAMS=${parameter} KPQC_AIMER=1)
    kpqc_rename_symbols(${name} ${name}
        crypto_sign_keypair_internal crypto_sign_signature_internal
        crypto_sign_verify_internal ${PQC_FIPS202_SYMBOLS})
endfunction()

function(kpqc_add_haetae name mode)
    set(root "${CMAKE_CURRENT_SOURCE_DIR}/vendor/HAETAE")
    set(sources)
    foreach(source decompose encoding fft fixpoint ntt packing poly polyfix
                   polymat polyvec reduce sampler sign fips202 symmetric-shake)
        list(APPEND sources "${root}/src/${source}.c")
    endforeach()
    kpqc_object_library(${name} ${name} native/csrc/signature.c
        ${root}/include ${sources})
    target_compile_definitions(${name} PRIVATE HAETAE_CONFIG_MODE=${mode})
    kpqc_rename_symbols(${name} ${name}
        ${COMPACT_FIPS202_SYMBOLS} ${HAETAE_SYMBOLS})
endfunction()

function(kpqc_add_ntruplus parameter)
    set(name "ntruplus${parameter}")
    set(root "${CMAKE_CURRENT_SOURCE_DIR}/vendor/NTRUplus/NTRU+${parameter}")
    kpqc_object_library(${name} ${name} native/csrc/kem.c ${root}
        ${root}/kem.c
        ${root}/ntt.c
        ${root}/poly.c
        ${root}/symmetric.c
        ${root}/fips202/fips202.c)
    kpqc_rename_symbols(${name} ${name}
        ${NTRUPLUS_SYMBOLS} ${PQC_FIPS202_SYMBOLS})
endfunction()

function(kpqc_add_smaugt name mode)
    set(root "${CMAKE_CURRENT_SOURCE_DIR}/vendor/SMAUG-T")
    set(sources)
    foreach(source cbd ciphertext dg hash hwt indcpa kem key pack packring
                   poly toomcook verify fips202)
        list(APPEND sources "${root}/src/${source}.c")
    endforeach()
    kpqc_object_library(${name} ${name} native/csrc/kem.c
        ${root}/include ${sources})
    target_compile_definitions(${name} PRIVATE SMAUGT_CONFIG_MODE=${mode})
    kpqc_rename_symbols(${name} ${name}
        ${COMPACT_FIPS202_SYMBOLS} ${SMAUGT_SYMBOLS})
endfunction()

foreach(parameter 128f 128s 192f 192s 256f 256s)
    kpqc_add_aimer(${parameter})
endforeach()

kpqc_add_haetae(haetae2 0)
kpqc_add_haetae(haetae3 1)
kpqc_add_haetae(haetae5 2)

foreach(parameter 768 864 1152)
    kpqc_add_ntruplus(${parameter})
endforeach()

kpqc_add_smaugt(smaugt128 0)
kpqc_add_smaugt(smaugt192 1)
kpqc_add_smaugt(smaugt256 2)
kpqc_add_smaugt(timer 3)

get_property(object_targets GLOBAL PROPERTY KPQC_OBJECT_TARGETS)
set(kpqc_objects)
foreach(target IN LISTS object_targets)
    list(APPEND kpqc_objects $<TARGET_OBJECTS:${target}>)
endforeach()

add_library(kpqc SHARED ${kpqc_objects})
if(KPQC_TEST_ENTROPY)
    set(kpqc_output_name kpqc_test)
else()
    set(kpqc_output_name kpqc_native)
endif()
set_target_properties(kpqc PROPERTIES
    OUTPUT_NAME ${kpqc_output_name}
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES)

if(WIN32)
    target_link_libraries(kpqc PRIVATE bcrypt)
elseif(UNIX AND NOT APPLE)
    target_link_libraries(kpqc PRIVATE m)
endif()

install(TARGETS kpqc
    RUNTIME DESTINATION native
    LIBRARY DESTINATION native)
