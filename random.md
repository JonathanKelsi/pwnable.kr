# welcome

## Description

random - 1pt

> Daddy, teach me how to use random value in programming! <br> <br>
> ssh random@pwnable.kr -p2222 (pw:guest)


## Solution

### Background

#### Random Values in C

The C standard library provides a function called rand() that returns a pseudo-random integer in the range 0 to RAND_MAX.

RAND_MAX is a constant defined in stdlib.h. It is implementation-defined, but is guaranteed to be at least 32767.

The rand() function uses a linear congruential generator to produce a sequence of pseudo-random integers. The generator is seeded by the function srand().

Thus, if the generator is not seeded, the same sequence of pseudo-random numbers will be generated each time the program is run.

### Exploit


When connecting to the server, we first check who are we:

```bash 
$ id
uid=1012(random) gid=1012(random) groups=1012(random)
```

Then, we check the avialable files:

```bash
$ ls -l
total 20
-r--r----- 1 random_pwn root     49 Jun 30  2014 flag
-r-sr-x--- 1 random_pwn random 8538 Jun 30  2014 random
-rw-r--r-- 1 root       root    301 Jun 30  2014 random.c
```

Let's take a look at the source code:

```c
#include <stdio.h>

int main(){
	unsigned int random;
	random = rand();	// random value!

	unsigned int key=0;
	scanf("%d", &key);

	if( (key ^ random) == 0xdeadbeef ){
		printf("Good!\n");
		system("/bin/cat flag");
		return 0;
	}

	printf("Wrong, maybe you should try 2^32 cases.\n");
	return 0;
}
```

THe program generates a "random" number, and then asks us to enter a number. If the XOR of the two numbers is equal to `0xdeadbeef`, we get the flag.

Since the generator is not seeded, the same random number will be generated each time the program is run. We can check which one, by writing a program of our own:

```c
#include <stdio.h>

int main(){
    unsigned int random = rand();
    printf("%d\n", random);
    return 0;
}
```

Compiling and running it, yields that the random number is `1804289383`. So, we are looking for a key that satisfies the following equation:

```bash
(1804289383 ^ key) = 0xdeadbeef
```

To solve this equation, we can xor both sides with `1804289383`, and get:

```bash
key = 1804289383 ^ 0xdeadbeef
```

Since for every number `x`, `x ^ x = 0`, and `0 ^ x = x`. Calculating the XOR, the desired key is `3039230856`. Entering it to the server, we get the flag:

```bash
$ ./random
3039230856
Good!
Mommy, I thought libc random is unpredictable...
```