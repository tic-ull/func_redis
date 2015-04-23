# func_redis

func_redis is a asterisk module to use Redis from the dialplan.
It uses hiredis as library for redis.

## Dependencies
- redis
     - [Ubuntu] apt-get install redis-server
     - [Archlinux] pacman -S redis

- hiredis
    - [Ubuntu] apt-get install libhiredis-dev
    - [Archlinux] pacman -S hiredis
    
- asterisk
    - [Ubuntu] apt-get install asterisk
    - [Archlinux] pacman -S asterisk

        
## Instalation
1. Install the dependencies
2. ```cmake .```
3. ```make```
4. ```make install```

## Uninstall 
- ```make unistall```

## Using func_redis

### Using func_redis from the Dialplan 


### Using func_redis from the CLI


## Contribute to the project


## AUTHORS

func_redis is written by Sergio Medina Toledo (lumasepa at gmail)
