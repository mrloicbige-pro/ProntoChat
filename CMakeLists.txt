cmake_minimum_required(VERSION 3.20)

project(chat
    VERSION 0.1.0
    DESCRIPTION "Terminal P2P encrypted messenger"
    LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(CHAT_ENABLE_SANITIZERS "Build with AddressSanitizer and UBSan" OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB REQUIRED IMPORTED_TARGET glib-2.0)
pkg_check_modules(LIBNICE REQUIRED IMPORTED_TARGET nice)
pkg_check_modules(LIBSODIUM REQUIRED IMPORTED_TARGET libsodium)
pkg_check_modules(LIBWEBSOCKETS REQUIRED IMPORTED_TARGET libwebsockets)

add_library(chat_common
    common/identity.c
    common/log.c
    common/protocole.c)

target_include_directories(chat_common
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_options(chat_common
    PRIVATE
        -Wall -Wextra -Wpedantic)

target_link_libraries(chat_common
    PUBLIC
        PkgConfig::LIBSODIUM)

add_executable(chat
    client/main.c)

target_link_libraries(chat
    PRIVATE
        chat_common)

add_executable(chatd
    daemon/main.c)

target_link_libraries(chatd
    PRIVATE
        chat_common
        PkgConfig::GLIB
        PkgConfig::LIBNICE
        PkgConfig::LIBWEBSOCKETS)

add_executable(chat-server
    server/main.c
    server/users.c)

target_link_libraries(chat-server
    PRIVATE
        chat_common
        PkgConfig::LIBWEBSOCKETS)

foreach(target chat chatd chat-server)
    target_compile_options(${target}
        PRIVATE
            -Wall -Wextra -Wpedantic)
endforeach()

if(CHAT_ENABLE_SANITIZERS)
    foreach(target chat_common chat chatd chat-server)
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endforeach()
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(test_protocol
        tests/test_protocol.c)
    target_link_libraries(test_protocol PRIVATE chat_common)
    target_compile_options(test_protocol PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME protocol COMMAND test_protocol)

    add_executable(test_identity
        tests/test_identity.c)
    target_link_libraries(test_identity PRIVATE chat_common)
    target_compile_options(test_identity PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME identity COMMAND test_identity)
endif()
