# Locate asterisk includes and library
# This module defines
# ASTERISK_LIBRARY_DIR, the name of the asterisk modules library
# ASTERISK_INCLUDE_DIR, where to find asterisk includes
#

set( ASTERISK_FOUND "NO" )

find_path( ASTERISK_INCLUDE_DIR asterisk/version.h
  HINTS
  PATH_SUFFIXES include
  PATHS
  ~/Library/Frameworks
  /Library/Frameworks
  /usr/local/include
  /usr/include
  /sw/include
  /opt/local/include
  /opt/csw/include
  /opt/include
  /mingw
)

# message( "ASTERISK_INCLUDE_DIR is ${ASTERISK_INCLUDE_DIR}" )

find_path( ASTERISK_LIBRARY_DIR app_dial.so
  HINTS
  PATH_SUFFIXES modules
  PATHS
  /usr/lib/asterisk
  /usr/lib64/asterisk
  /usr/local/lib/asterisk
  /usr/local/lib64/asterisk
)

# message( "ASTERISK_LIBRARY_DIR is ${ASTERISK_LIBRARY_DIR}" )
if(ASTERISK_LIBRARY_DIR)
set( ASTERISK_FOUND "YES" )
endif(ASTERISK_LIBRARY_DIR)