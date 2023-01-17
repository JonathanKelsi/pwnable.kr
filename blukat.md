# blukat

## Description

blukat - 3pt

> Sometimes, pwnable is strange... <br>
> hint: if this challenge is hard, you are a skilled player. <br> <br>
> ssh blukat@pwnable.kr -p2222 (pw: guest)

## Solution

### Background

#### Linux File Permissions

In Linux, every file and directory has a set of permissions associated with it. These permissions determine who can read, write, and execute the file or directory. The permissions are divided into three categories: user, group, and other. The user category contains the permissions for the file's owner. The group category contains the permissions for the file's group. The other category contains the permissions for everyone else.

The permissions are represented by three sets of three characters. The first set of three characters represents the permissions for the user category. The second set of three characters represents the permissions for the group category. The third set of three characters represents the permissions for the other category.

For example, the following permissions indicate that the file's owner can read, write, and execute the file. The file's group can read and execute the file. Everyone else can only read the file.

```
-rwxr-xr--
```

### Exploit


When connecting to the server, we first check who are we:

```bash 
$ id
uid=1104(blukat) gid=1104(blukat) groups=1104(blukat),1105(blukat_pwn)
```

Then, we check the avialable files:

```bash
$ ls -l
total 20
-r-xr-sr-x 1 root blukat_pwn 9144 Aug  8  2018 blukat
-rw-r--r-- 1 root root        645 Aug  8  2018 blukat.c
-rw-r----- 1 root blukat_pwn   33 Jan  6  2017 password
```

We can see that our user is part of the `blukat_pwn` group. So we can read the `password` file:

```bash
$ cat password
cat: password: Permission denied
```

Wait, what? We can't read the file?! Checking the permissions again, it doesn't make sense. Unless... **this** is the password!

Now the question stands: what is the *use* of this password? Let's take a look at the source code:

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
char flag[100];
char password[100];
char* key = "3\rG[S/%\x1c\x1d#0?\rIS\x0f\x1c\x1d\x18;,4\x1b\x00\x1bp;5\x0b\x1b\x08\x45+";
void calc_flag(char* s){
	int i;
	for(i=0; i<strlen(s); i++){
		flag[i] = s[i] ^ key[i];
	}
	printf("%s\n", flag);
}
int main(){
	FILE* fp = fopen("/home/blukat/password", "r");
	fgets(password, 100, fp);
	char buf[100];
	printf("guess the password!\n");
	fgets(buf, 128, stdin);
	if(!strcmp(password, buf)){
		printf("congrats! here is your flag: ");
		calc_flag(password);
	}
	else{
		printf("wrong guess!\n");
		exit(0);
	}
	return 0;
}
```

Huh, let's try to give this password to the program:

```bash
$ ./blukat
guess the password!
cat: password: Permission denied
congrats! here is your flag: Pl3as_DonT_Miss_youR_GrouP_Perm!!
```

Always check the permissions!