# func_redis

func_redis is a asterisk module to use Redis from the dialplan.
It uses hiredis as library for redis.
I have tested it in Asterisk 11.6 certified version.

## Motivation of the project

This project is motivated by the need to share information between different
asterisk in both active-active and active-passive scheme.

In the case of passive-active scheme if you use AstDB for storing data, 
when system switch over, the data in AstDB isn't in the passive node,
so some functionality is lost, using Redis instead of AstDB, the active
node and the passive one can access the data, even the possibility of 
making an passive active redis scheme in this case the active asterisk 
attack the active redis and the passive asterisk attacks the passive 
redis with this scheme you can have on the same machine redis and Asterisk.

In the case of both active-active scheme asterisk can share information easily by redis.

func_redis is not a drop in replacement of AstDB, internally asterisk uses AstDB,
for example to keep registry of the phones.

You can use an agi script or a system call to a script to use redis from the dialplan
but the performance is low compared to a asterisk module and the integration is worst.

## Dependencies
- gcc
    - [Ubuntu] apt-get install build-essential
    - [Archlinux] pacman -S gcc
    
- cmake
    - [Ubuntu] apt-get install cmake
    - [Archlinux] pacman -S cmake
    
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
6. ```make doc```


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
; Database number in redis
db=0
; Timeout on connect with the redis server
timeout=3
```


### Using func_redis from the Dialplan

#### Set a key-value pair
```same => n,Set(REDIS(test/count)=$[${COUNT} + 1])```

#### Get a value from a key
```same => n,Set(COUNT=${REDIS(test/count)})```

#### Delete a key-value pair
```same => n,NoOp(Deleting test/count ${REDIS_DELETE(test/count)})```

#### Check if a key exist in redis
```same => n,GotoIf(${REDIS_EXISTS(test/count)}?exist:no_exist)```

#### Publish a message in a redis channel
```same => n,Set(REDIS_PUBLISH(worker_channel)=do_stuff)```

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
    Deletes the key-value pair in redis.

## Contribute and collaborate

Im open to contributions, if you make a pull-request I will merge it.
Also you can contact with me in my mail lumasepa at gmail and ask for
any doubt that you can have.