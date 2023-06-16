# Cryptopals 

This are my solutions to the [Matasano Cryptopals challenges](https://cryptopals.com/).

The code is written in pure C.

## How to compile/run

You will need premake5 to compile those projects:

sudo apt install libtomcrypt-dev libcjson-dev


```sh
# Generate solution on Windows
$ vcpkg install libtomcrypt cjson
$ premake5 vs2022

# Generate makefile on Linux
$ sudo apt install libtomcrypt-dev libtommath-dev libcjson-dev
$ premake5 gmake
```


## What are these challenges?

Cryptopals is a collection of exercises that demonstrate attacks on real world ciphers and protocols. 
Exercises exploit both badly designed systems and subtle implementation bugs in theoretically rock solid crypto.


