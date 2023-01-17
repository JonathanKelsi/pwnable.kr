# mistake

## Description

mistake - 1pt

>We all make mistakes, let's move on. <br>
>(don't take this too seriously, no fancy hacking skill is required at all) <br> <br>
>This task is based on real event <br>
>Thanks to dhmonkey <br> <br>
>hint : operator priority <br> <br>
>ssh mistake@pwnable.kr -p2222 (pw:guest)


## Solution

### Background

#### Operator Priority

Operator priority is the order in which operators are evaluated when an expression is evaluated. For example, in the expression 1 + 2 * 3, the multiplication operator has higher priority than the addition operator; therefore, the expression is evaluated as (1 + 2) * 3 = 9.

The following table lists the operators in order of decreasing priority. Operators at the top of the table have the highest priority; operators at the bottom have the lowest priority.

| Operator | Description |
|----------|-------------|
| () [] -> . | postfix |
| ++ -- ! ~ + - (type) * & sizeof | unary |
| * / % | multiplicative |
| + - | additive |
| << >> | shift |
| < <= > >= | relational |
| == != | equality |
| & | bitwise AND |
| ^ | bitwise XOR |
| \| | bitwise OR |
| && | logical AND |
| \|\| | logical OR |
| ?: | conditional |
| = += -= *= /= %= &= ^= <<= >>= | assignment |
| , | comma |


### Exploit

As always, we start by examining our permissions and the available files:

```bash
$ id
uid=1017(mistake) gid=1017(mistake) groups=1017(mistake)
```

```bash
$ ls -l
total 24
-r-------- 1 mistake_pwn root      51 Jul 29  2014 flag
-r-sr-x--- 1 mistake_pwn mistake 8934 Aug  1  2014 mistake
-rw-r--r-- 1 root        root     792 Aug  1  2014 mistake.c
-r-------- 1 mistake_pwn root      10 Jul 29  2014 password
```

Let's examine the source code:

```c
#include <stdio.h>
#include <fcntl.h>

#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
	int i;
	for(i=0; i<len; i++){
		s[i] ^= XORKEY;
	}
}

int main(int argc, char* argv[]){
	
	int fd;
	if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
		printf("can't open password %d\n", fd);
		return 0;
	}

	printf("do not bruteforce...\n");
	sleep(time(0)%20);

	char pw_buf[PW_LEN+1];
	int len;
	if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
		printf("read error\n");
		close(fd);
		return 0;		
	}

	char pw_buf2[PW_LEN+1];
	printf("input password : ");
	scanf("%10s", pw_buf2);

	// xor your input
	xor(pw_buf2, 10);

	if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
		printf("Password OK\n");
		system("/bin/cat flag\n");
	}
	else{
		printf("Wrong Password\n");
	}

	close(fd);
	return 0;
}
```

The program starts by opening the file "/home/mistake/passworod/", which is owned by root and has permissions 0400. It then sleeps for a random amount of time between 0 and 20 seconds.

Next, it appears to read the password from the file into a buffer, and then prompts the user for a password. The user's input is then XOR'd with the value 1, and then compared to the password read from the file. If the two values match, the program prints the flag.

Taking a closer look at the opening of the password file, we see that `fd` isn't assigned with the actual file descriptor of the password file, but the result of the comparison `open("/home/mistake/password",O_RDONLY,0400) < 0`, because of operator priority. 

This means that if the file is opened successfully, fd will be assigned the value `0`, which is the file descriptor for stdin. Thus, in order to pass the check, we need to enter two passwords: one that will be read when the program opens the file, and one that will be read when the program prompts the user for a password. Those two passwords must be the same, XOR'd with 1.

For example, we can take the passwords `@@@@@@@@@@` and `AAAAAAAAAA`:

```bash
$ ./mistake
do not bruteforce...
@@@@@@@@@@
input password : AAAAAAAAAA
Password OK
Mommy, the operator priority always confuses me :(
```