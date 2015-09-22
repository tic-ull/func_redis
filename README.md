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
; host of the redis server
; if not defined, use default of 127.0.0.1
hostname=127.0.0.1

; port of the redis server
if not defined, use default of 6379
port=6379

; database index in redis
; if not defined, use default of 0
database=0

; password for redis server
; if not defined, authentication will not be used
;password=s3cr3tp@ssw0rd

; connection time out when connecting to the server
; if not defined, use a default of 5 seconds
timeout=3
```


### Using func_redis from the Dialplan

#### Set a key value
```same => n,Set(REDIS(test)=${TEST})```

#### Set a hash value
```same => n,Set(REDIS(test,field)=${TEST})```

#### Get the value from a key
```same => n,Set(TEST=${REDIS(test)})```

#### Get the value from a hash
```same => n,Set(TEST=${REDIS(test,field)})```

#### Delete a key
```same => n,NoOp(Deleting test key ${REDIS_DELETE(test)})```

#### Check if a key exists
```same => n,GotoIf(${REDIS_EXISTS(test)}?exists:doesnt_exist)```

#### Publish a message to a redis channel
```same => n,Set(REDIS_PUBLISH(channel)=test)```

### Using func_redis from the CLI

You can use these commands related to func_redis in the Asterisk CLI 

1. ```redis show [pattern]```
    Shows all the key values.
    [pattern] pattern to match keys
    Examples :
        - h?llo matches hello, hallo and hxllo
        - h*llo matches hllo and heeeello
        - h[ae]llo matches hello and hallo, but not hillo

2. ```redis hshow <hash>```
    Shows all the hash's values for a given hash.
    
3. ```redis set <key> <value>```
    Sets the key's <key> value to <value>.
   ```redis set <key> <hash> <value>```
    Sets the hash's <hash> value <value> for a given key <key>.
    
4. ```redis del <key>```
    Deletes the key-value pair in redis.


## Contribute and collaborate

Im open to contributions, if you make a pull-request I will merge it.
Also you can contact with me in my mail lumasepa at gmail and ask for
any doubt that you can have.

