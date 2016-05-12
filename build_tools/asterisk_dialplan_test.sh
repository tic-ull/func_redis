#!/usr/bin/env bash

CMAKE_SOURCE_DIR=$1

cp ${CMAKE_SOURCE_DIR}/build_tools/test_dialplan.conf /etc/asterisk/test_dialplan.conf

cat /etc/asterisk/extensions.conf | grep "test_dialplan.conf" > /dev/null
if [ $? != 0 ]
then
    echo "#include \"test_dialplan.conf\"" >> /etc/asterisk/extensions.conf
fi

cat /etc/asterisk/logger.conf | grep -v "^;" | grep "full" > /dev/null
if [ $? != 0 ]
then
    echo "full => notice,warning,error,debug,verbose,dtmf,fax" >> /etc/asterisk/logger.conf
    asterisk -rx "logger reload"
fi

asterisk -rx "dialplan reload"


function make_call {

    echo -e "
Channel: Local/2@test_func_redis
Callerid: 1000
Context: test_func_redis
Extension: 1
Priority: 1
" > /tmp/test_func_redis.callfile
mv /tmp/test_func_redis.callfile /var/spool/asterisk/outgoing/
}


(sleep 30 && make_call)&
(sleep 31 && make_call)&
(sleep 32 && make_call)&
(sleep 33 && make_call)&
(sleep 34 && make_call)&
(sleep 35 && make_call)&
(sleep 36 && make_call)&


#tail -f /var/log/asterisk/full | grep "ERROR|WARNING" --color

gdb -ex=r --args asterisk -cgdvvvvvvvvvvvvvv
#valgrind --suppressions=/usr/src/asterisk-13.9.0/contrib/valgrind.supp --log-fd=9 asterisk -cgdvvvvvvvvvvvvvvv 9> valgrind.tx
killall asterisk

exit 0