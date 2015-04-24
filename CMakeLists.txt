cmake_minimum_required(VERSION 2.8)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/CMakeModules")

project(func_redis)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -shared -fPIC -Wall -pedantic")

find_package(asterisk REQUIRED)

set(SOURCE_FILES func_redis.c)

add_library(func_redis SHARED ${SOURCE_FILES})

set_target_properties(func_redis PROPERTIES PREFIX "")

target_link_libraries (func_redis hiredis)

install (TARGETS func_redis DESTINATION ${ASTERISK_LIBRARY_DIR})

add_custom_target(samples COMMAND cp "${CMAKE_SOURCE_DIR}/samples/func_redis.conf.sample" /etc/asterisk/func_redis.conf )

add_custom_target(uninstall COMMAND rm -f "${ASTERISK_LIBRARY_DIR}/func_redis.so" && rm -f /etc/asterisk/func_redis.conf )