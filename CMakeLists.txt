cmake_minimum_required(VERSION 3.20)

project(chat
    VERSION 0.1.1
    DESCRIPTION "Terminal P2P encrypted messenger"
    LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(CHAT_ENABLE_SANITIZERS "Build with AddressSanitizer and UBSan" OFF)
option(CHAT_ENABLE_NETWORK_TESTS "Enable local ICE and end-to-end network tests" OFF)
set(CHAT_DEFAULT_SERVER_URL "wss://pronto-chat.duckdns.org" CACHE STRING
    "Default ProntoChat control server URL")

if(CHAT_ENABLE_SANITIZERS)
    add_library(chat_sanitizers INTERFACE)
    target_compile_options(chat_sanitizers
        INTERFACE
            -fsanitize=address,undefined
            -fno-omit-frame-pointer)
    target_link_options(chat_sanitizers
        INTERFACE
            -fsanitize=address,undefined)
endif()

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
include(GNUInstallDirs)
pkg_check_modules(GLIB REQUIRED IMPORTED_TARGET glib-2.0)
pkg_check_modules(LIBNICE REQUIRED IMPORTED_TARGET nice)
pkg_check_modules(LIBSODIUM REQUIRED IMPORTED_TARGET libsodium)
pkg_check_modules(LIBWEBSOCKETS REQUIRED IMPORTED_TARGET libwebsockets)

add_library(chat_common
    common/contacts.c
    common/crypto.c
    common/identity.c
    common/ipc.c
    common/log.c
    common/protocole.c)

target_include_directories(chat_common
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_definitions(chat_common
    PUBLIC
        CHAT_DEFAULT_SERVER_URL="${CHAT_DEFAULT_SERVER_URL}")

target_compile_options(chat_common
    PRIVATE
        -Wall -Wextra -Wpedantic)

target_link_libraries(chat_common
    PUBLIC
        PkgConfig::LIBSODIUM)

if(CHAT_ENABLE_SANITIZERS)
    target_link_libraries(chat_common PUBLIC chat_sanitizers)
endif()

add_executable(chat
    client/main.c)

target_link_libraries(chat
    PRIVATE
        chat_common)

add_executable(chatd
    daemon/main.c
    daemon/ice.c)

target_link_libraries(chatd
    PRIVATE
        chat_common
        Threads::Threads
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

install(TARGETS chat chatd
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT client)

install(FILES packaging/systemd/chatd.service
    DESTINATION ${CMAKE_INSTALL_DATADIR}/chat/systemd
    COMPONENT client)

install(FILES packaging/launchd/chatd.plist
    DESTINATION ${CMAKE_INSTALL_DATADIR}/chat/launchd
    COMPONENT client)

install(TARGETS chat-server
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT server
    EXCLUDE_FROM_ALL)

install(FILES packaging/systemd/chat-server.service
    DESTINATION ${CMAKE_INSTALL_DATADIR}/prontochat/systemd
    COMPONENT server
    EXCLUDE_FROM_ALL)

install(PROGRAMS packaging/archive/install-client.sh
    DESTINATION .
    RENAME install.sh
    COMPONENT client
    EXCLUDE_FROM_ALL)

install(FILES packaging/archive/README-client.md
    DESTINATION .
    RENAME README.md
    COMPONENT client
    EXCLUDE_FROM_ALL)

install(PROGRAMS packaging/archive/install-server.sh
    DESTINATION .
    RENAME install.sh
    COMPONENT server
    EXCLUDE_FROM_ALL)

install(FILES packaging/archive/README-server.md
    DESTINATION .
    RENAME README.md
    COMPONENT server
    EXCLUDE_FROM_ALL)

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

    add_executable(test_contacts
        tests/test_contacts.c)
    target_link_libraries(test_contacts PRIVATE chat_common)
    target_compile_options(test_contacts PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME contacts COMMAND test_contacts)

    add_executable(test_crypto
        tests/test_crypto.c)
    target_link_libraries(test_crypto PRIVATE chat_common)
    target_compile_options(test_crypto PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME crypto COMMAND test_crypto)

    add_executable(test_server_users
        tests/test_server_users.c
        server/users.c)
    target_link_libraries(test_server_users PRIVATE chat_common)
    target_compile_options(test_server_users PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME server_users COMMAND test_server_users)

    add_executable(test_ipc
        tests/test_ipc.c)
    target_link_libraries(test_ipc PRIVATE chat_common)
    target_compile_options(test_ipc PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME ipc COMMAND test_ipc)

    add_executable(test_ice_loopback
        tests/test_ice_loopback.c
        daemon/ice.c)
    target_link_libraries(test_ice_loopback
        PRIVATE
            chat_common
            PkgConfig::LIBNICE)
    target_compile_options(test_ice_loopback PRIVATE -Wall -Wextra -Wpedantic)

    if(CHAT_ENABLE_NETWORK_TESTS)
        find_package(Python3 REQUIRED COMPONENTS Interpreter)

        add_test(NAME ice_loopback COMMAND test_ice_loopback)
        set_tests_properties(ice_loopback PROPERTIES
            LABELS "network"
            TIMEOUT 60)

        foreach(scenario direct offline identity_mismatch control_disconnect)
            set(e2e_args --build-dir ${CMAKE_BINARY_DIR})
            if(scenario STREQUAL "offline")
                list(APPEND e2e_args --expect-offline)
            elseif(scenario STREQUAL "identity_mismatch")
                list(APPEND e2e_args --expect-identity-mismatch)
            elseif(scenario STREQUAL "control_disconnect")
                list(APPEND e2e_args --disconnect-control)
            endif()

            add_test(NAME e2e_${scenario}
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/e2e_chat.py ${e2e_args})
            set_tests_properties(e2e_${scenario} PROPERTIES
                LABELS "network;e2e"
                RESOURCE_LOCK "chat_control_port"
                RUN_SERIAL TRUE
                TIMEOUT 180)
        endforeach()
    endif()
endif()

set(CPACK_GENERATOR "TGZ")
set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_ALL client server)
set(CPACK_PACKAGE_NAME "prontochat")
set(CPACK_PACKAGE_VENDOR "ProntoChat")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DIRECTORY "${CMAKE_BINARY_DIR}/dist")
set(CPACK_PACKAGE_FILE_NAME
    "prontochat-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY ON)
set(CPACK_COMPONENT_INCLUDE_TOPLEVEL_DIRECTORY ON)
include(CPack)

add_custom_target(archives
    COMMAND "${CMAKE_CPACK_COMMAND}" --config "${CMAKE_BINARY_DIR}/CPackConfig.cmake"
    DEPENDS chat chatd chat-server
    COMMENT "Building separate ProntoChat client and server archives"
    VERBATIM)
