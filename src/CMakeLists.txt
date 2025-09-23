# redir need linux/* stuff
if (LINUX)
    option(WITH_SS_REDIR "Build ss-redir" ON)
else ()
    option(WITH_SS_REDIR "Build ss-redir" OFF)
endif ()

set(SS_CRYPTO_SOURCE
        crypto.c
        aead.c
        stream.c
        base64.c
        )
set(SS_PLUGIN_SOURCE
        plugin.c
        )
set(SS_SHARED_SOURCES
        ppbloom.c
        utils.c
        jconf.c
        json.c
        netutils.c
        )

set(SS_REDIR_SOURCE
        ${SS_SHARED_SOURCES}
        udprelay.c
        probe.c
        cache.c
        redir.c
        ${SS_CRYPTO_SOURCE}
        ${SS_PLUGIN_SOURCE}
        )

if (WITH_STATIC)
find_library(LIBSODIUM libsodium.a)
find_library(LIBMBEDTLS libmbedtls.a)
find_library(LIBMBEDCRYPTO libmbedcrypto.a)
find_library(LIBEV libev.a)
find_library(LIBUDNS libcares.a)
find_library(LIBPCRE libpcre.a)

# Dependencies we need for static and shared
list(APPEND DEPS
        m
        bloom
        ${LIBEV}
        ${LIBUDNS}
        ${LIBPCRE}
        ${LIBSODIUM}
        ${LIBMBEDTLS}
        ${LIBMBEDCRYPTO}
        )
endif ()

find_library(LIBSODIUM_SHARED sodium)
find_library(LIBMBEDTLS_SHARED mbedtls)
find_library(LIBMBEDCRYPTO_SHARED mbedcrypto)
find_library(LIBEV_SHARED ev)
find_library(LIBUDNS_SHARED cares)
find_library(LIBPCRE_SHARED pcre)

if (WITH_EMBEDDED_SRC)
list(APPEND DEPS_SHARED
        m
        bloom-shared
        cork-shared
        ipset-shared
        ${LIBEV_SHARED}
        ${LIBUDNS_SHARED}
        ${LIBPCRE_SHARED}
        ${LIBSODIUM_SHARED}
        ${LIBMBEDTLS_SHARED}
        ${LIBMBEDCRYPTO_SHARED}
        )
else ()
find_library(LIBBLOOM_SHARED bloom)
find_library(LIBCORK_SHARED cork)
find_library(LIBCORKIPSET_SHARED corkipset)
list(APPEND DEPS_SHARED
        m
        ${LIBBLOOM_SHARED}
        ${LIBCORK_SHARED}
        ${LIBCORKIPSET_SHARED}
        ${LIBEV_SHARED}
        ${LIBUDNS_SHARED}
        ${LIBPCRE_SHARED}
        ${LIBSODIUM_SHARED}
        ${LIBMBEDTLS_SHARED}
        ${LIBMBEDCRYPTO_SHARED}
        )
endif ()

find_package (Threads)

if (WITH_STATIC)
# ------------------------------------------------------------------
# Static
if (WITH_SS_REDIR)
    add_executable(ss-redir ${SS_REDIR_SOURCE})
else ()
    add_executable(ss-redir EXCLUDE_FROM_ALL ${SS_REDIR_SOURCE})
endif ()

target_compile_definitions(ss-redir PUBLIC)
target_link_libraries(ss-redir cork ipset ${DEPS})
endif ()

# ------------------------------------------------------------------
# Shared
if (WITH_SS_REDIR)
    add_executable(ss-redir-shared ${SS_REDIR_SOURCE})
else ()
    add_executable(ss-redir-shared EXCLUDE_FROM_ALL ${SS_REDIR_SOURCE})
endif ()

target_compile_definitions(ss-redir-shared PUBLIC)
target_link_libraries(ss-redir-shared ${DEPS_SHARED})
set_target_properties(ss-redir-shared PROPERTIES OUTPUT_NAME ss-redir)

set_target_properties(ss-redir-shared
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${RUNTIME_SHARED_OUTPUT_DIRECTORY}
        )

# ------------------------------------------------------------------
# Misc
# Recommend to install shared by default
install(DIRECTORY ${RUNTIME_SHARED_OUTPUT_DIRECTORY}/
        USE_SOURCE_PERMISSIONS
        DESTINATION bin)


add_custom_target(distclean
        COMMAND ${CMAKE_COMMAND} -E echo WARNING: distclean target is not functional
        COMMAND ${CMAKE_COMMAND} -E echo Use 'git clean -fdx' instead
        VERBATIM
        )
