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

echo -e "
Channel: Local/2@test_func_redis
Callerid: 1000
Context: test_func_redis
Extension: 1
Priority: 1
" > /tmp/test_func_redis.callfile

(sleep 1 && mv /tmp/test_func_redis.callfile /var/spool/asterisk/outgoing/)&

tail -f /var/log/asterisk/full