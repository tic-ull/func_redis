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
    - [Ubuntu] apt-get install asterisk asterisk-dev
    - [Archlinux] pacman -S asterisk

        
## Instalation
1. Install the dependencies
2. ```cmake -DCMAKE_BUILD_TYPE=Release .```
3. ```make```
4. ```make install```
5. ```make samples```


## Uninstall 
- ```make unistall```

## Using func_redis

In order to use the func_redis you have to configure the settings for the module 
in the file func_redis.conf. There is an example in samples/func_redis.conf.sample, if you 
run make samples it will copy this file to /etc/asterisk

Here an example of the file :

```
[general]
; host where is the redis server 
hostname=127.0.0.1
; Port of the redis server
port=6379
; Database name in redis
dbname=asterisk
; Timeout on connect with the redis server
timeout=3
```


### Using func_redis from the Dialplan

#### Set a key-value pair
```same => n,Set(REDIS(test/count)=$[${COUNT} + 1])```

#### Get a value from a key
```same => n,Set(COUNT=${REDIS(test/count)})```

#### Delete a key-value pair
```same => n,NoOp(Deleting test/count ${REDIS_DELETE(test/count)}```

#### Check if a key exist in redis
```same => n,GotoIf(${REDIS_EXISTS(test/count)}?exist:no_exist)```


### Using func_redis from the CLI

You can use the next commands related to func_redis in the asterisk CLI 

1. ```redis show [pattern]```
    Shows all the key-value pairs in redis.
    [pattern] pattern to match keys
    Examples :
        - h?llo matches hello, hallo and hxllo
        - h*llo matches hllo and heeeello
        - h[ae]llo matches hello and hallo, but not hillo

    
2. ```redis set <key> <value>```
    Set the value <value> to the key <key> in redis.
    
3. ```redis del <key>```
    Deletes the key-value pair in redis

## Contribute and collaborate

Im open to contributions, if you make a pull-request I will merge it.
Also you can contact with me in my mail lumasepa at gmail and ask for
any doubt that you can have.

## AUTHORS

func_redis is written by Sergio Medina Toledo (lumasepa at gmail)