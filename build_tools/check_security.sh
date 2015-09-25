#!/usr/bin/env bash

CMAKE_SOURCE_DIR=$1


function banner(){
    echo -e "\e[0;32m-----------------------------------------------"
    echo -e "               $1"
    echo -e "-----------------------------------------------\e[0m"
}

function echo_error(){
echo -e "\e[31m$1\e[0m" >&2
}

banner "graudit"

if hash graudit 2>/dev/null
then
    graudit -d ${CMAKE_SOURCE_DIR}/build_tools/c.db ${CMAKE_SOURCE_DIR}/src/func_redis.c
else
    echo_error "graudit not found in the system path, install it or fix the path"
fi

banner "flawfinder"

if hash flawfinder 2>/dev/null
then
    flawfinder ${CMAKE_SOURCE_DIR}/src/func_redis.c
else
    echo_error "flawfinder not found in the system path, install it or fix the path"
fi

banner "cppcheck"

if hash cppcheck 2>/dev/null
then
    cppcheck --enable=all --std=c89 ${CMAKE_SOURCE_DIR}/src/func_redis.c
else
    echo_error "cppcheck not found in the system path, install it or fix the path"
fi

