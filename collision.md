# collision

## Description

collision - 3 pt

> Daddy told me about cool MD5 hash collision today. <br>
> I wanna do something like that too! <br> <br>
> ssh col@pwnable.kr -p2222 (pw:guest)

## Solution

### Background

#### Hash functions and collisions

A hash function is a function that maps data of arbitrary size to data of a fixed size. The values returned by a hash function are called hash values, hash codes, digests, or simply hashes. 

For example, the MD5 hash of the string "Hello, world!" is `ed076287532e86365e841e92bfc50d8c`. MD5 is a cryptographic hash function with a 128-bit hash value, and it is one of the most widely used hash functions in the world.

A hash collision is a pair of inputs that hash to the same value. Hash collisions are dangerous because they can be used to create fake data. For example, if a hash collision is found for a password hash, an attacker can use the collision to log in as the user with that password.

### Exploit

Connecting to the server, we are given the following files:

```
total 16
-r-sr-x--- 1 col_pwn col     7341 Jun 11  2014 col
-rw-r--r-- 1 root    root     555 Jun 12  2014 col.c
-r--r----- 1 col_pwn col_pwn   52 Jun 11  2014 flag
```

Let's take a look at the source code:

```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}

int main(int argc, char* argv[]){
	if(argc<2){
		printf("usage : %s [passcode]\n", argv[0]);
		return 0;
	}
	if(strlen(argv[1]) != 20){
		printf("passcode length should be 20 bytes\n");
		return 0;
	}

	if(hashcode == check_password( argv[1] )){
		system("/bin/cat flag");
		return 0;
	}
	else
		printf("wrong passcode.\n");
	return 0;
}
```

It looks like the program takes a 20 byte password as one of the command line arguments, and checks if the hash of the password is equal to `0x21DD09EC`.

The given hash function `check_password` is very simple. It devides the 20 byte password into 5 4-byte integers, and adds them together. The hash of the password is the sum of the 5 integers.

Our goal is to find a 20 byte password that hashes to `0x21DD09EC`. We can brute force this, but it will take a very long time. Since the hash function is very simple, we can just create a password that hashes to `0x21DD09EC` by hand.

We need to find 5 numbers that sum up to `0x21DD09EC` (which is `568134124` in decimal). Dividing `568134124` by 5 gives us `113626824.8`. Rounding up we get `113626825`.

And so, our 5 numbers are `113626825` (four times) and `113626824` (once). Converting these to hex gives us `0x06C5CEC9` and `0x06C5CEC8`. So, the bytes of our password are:

```
06 C5 CE C9 06 C5 CE C9 06 C5 CE C9 06 C5 CE C9 06 C5 CE C8
```

Here is a Python script that solves the challenge:

```py
from pwn import *

con = ssh('col', 'pwnable.kr', port=2222, password='guest')

p = con.process(['col', '\xC9\xCE\xC5\x06\xC9\xCE\xC5\x06\xC9\xCE\xC5\x06\xC9\xCE\xC5\x06\xC8\xCE\xC5\x06'])

print(p.recvall())
```

```
b'daddy! I just managed to create a hash collision :)\n'
```