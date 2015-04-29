#!/bin/bash

ASTVARDIR=`cat /etc/asterisk/asterisk.conf| grep astvarlibdir | cut -d ">" -f2`

DOC_FILE="$ASTVARDIR/documentation/thirdparty/func_redis-en_US.xml"

echo "Building Documentation"
echo "Creating $DOC_FILE"

echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" > $DOC_FILE
echo "<!DOCTYPE docs SYSTEM \"appdocsxml.dtd\">" >> $DOC_FILE
echo "<docs xmlns:xi=\"http://www.w3.org/2001/XInclude\">" >> $DOC_FILE

echo "Extracting Documentation from func_redis.c"
awk -f build_tools/get_documentation ./func_redis.c >> $DOC_FILE

echo "</docs>" >> $DOC_FILE
