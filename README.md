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
5. ```make samples```


## Uninstall 
- ```make unistall```

## Using func_redis

In order to use the func_redis you have to configure the settings for the module 
in the file redis.conf there is an example in samples/redis.conf.sample if you 
run make samples it will copy this file to /etc/asterisk

here an example of the file :

```
[general]
hostname=127.0.0.1
port=6379
dbname=asterisk
```


### Using func_redis from the Dialplan 


### Using func_redis from the CLI

You can use the next commands related to func_redis in the asterisk CLI 

1. ```redis show [key]```
    Shows all the key-value pairs in redis.
    
2. ```redis set <key> <value>```
    Set the value <value> to the key <key> in redis.
    
3. ```redis del <key>```
    Deletes the key-value pair in redis

## Contribute to the project


## AUTHORS

func_redis is written by Sergio Medina Toledo (lumasepa at gmail)
