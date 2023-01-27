# input

## Description

> Mom? how can I pass my input to a computer program? <br> <br>
> ssh input2@pwnable.kr -p2222 (pw:guest)

## Solution

### Exploit

Let's examine the source code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char* argv[], char* envp[]){
	printf("Welcome to pwnable.kr\n");
	printf("Let's see if you know how to give input to program\n");
	printf("Just give me correct inputs then you will get the flag :)\n");

	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");	

	// stdio
	char buf[4];
	read(0, buf, 4);
	if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
	read(2, buf, 4);
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
	printf("Stage 2 clear!\n");
	
	// env
	if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
	printf("Stage 3 clear!\n");

	// file
	FILE* fp = fopen("\x0a", "r");
	if(!fp) return 0;
	if( fread(buf, 4, 1, fp)!=1 ) return 0;
	if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
	fclose(fp);
	printf("Stage 4 clear!\n");	

	// network
	int sd, cd;
	struct sockaddr_in saddr, caddr;
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1){
		printf("socket error, tell admin\n");
		return 0;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons( atoi(argv['C']) );
	if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		printf("bind error, use another port\n");
    		return 1;
	}
	listen(sd, 1);
	int c = sizeof(struct sockaddr_in);
	cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
	if(cd < 0){
		printf("accept error, tell admin\n");
		return 0;
	}
	if( recv(cd, buf, 4, 0) != 4 ) return 0;
	if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
	printf("Stage 5 clear!\n");

	// here's your flag
	system("/bin/cat flag");	
	return 0;
}
```

There are 5 different stages we need to pass in order to get the flag:

### argv  

in the argv stage, we need to give a bunch of arguments to the program. We can get past using:

```python
from pwn import *
import os, time

con = ssh('input2', 'pwnable.kr', port=2222, password='guest')

# argv + env
payload = ['A']*64 + ['\x00'] + ['\x20\x0a\x0d'] + ['A']*33
p = con.process(['/home/input2/input'] + payload)
```

First, we need to make sure we give 100 arguments to the program. The first argument is the program's name, and the rest are ours. Then, the program expects the 65th argument to be `\x00` and the 66th argument to be `\x20\x0a\x0d`.

### stdio

In the stdio stage, we need to send the following bytes to stdin and stderr: `\x00\x0a\x00\xff` and `\x00\x0a\x02\xff`. Passing the first one is easy, but the second one is a bit tricky. At first glance, it looks like we need to figure out how to write to stderr. But, since the program is running on a terminal, stderr is the same as stdout. So, we can just send the bytes to stdin, and the terminal will output them to stdout (which is the same as stderr).

```python
# stdio
p.send('\x00\x0a\x00\xff')
p.send('\x00\x0a\x02\xff')
```

### env

In the env stage, we need to set the environment variable `\xde\xad\xbe\xef` to `\xca\xfe\xba\xbe`. We can simply update the environment variables before we run the program:

```python
p = con.process(['/home/input2/input'] + payload, env={'\xde\xad\xbe\xef':'\xca\xfe\xba\xbe'})
```

### file

In the file stage, the program opens a file named `\x0a`, reads 4 bytes from it and compares them to `\x00\x00\x00\x00`. We can't just create a file named `\x0a` because we don't have sufficient permissions. So, we need to create the file in a different directory, and then run the program from that directory. We can do this by using the `cwd` argument in `process`.

Also, since we run the program from `/tmp/a`, we need to make sure that the program can find the flag. We can do this by creating a symlink to the flag in `/tmp/a`.

```python
# file
con[""" mkdir /tmp/a """]
con[""" python3 -c "with open('/tmp/a/\x0a','w') as f: f.write('\x00\x00\x00\x00')" """]
con[""" ln -s /home/input2/flag /tmp/a/ """]

...

p = con.process(['/home/input2/input'] + payload, env={'\xde\xad\xbe\xef':'\xca\xfe\xba\xbe'}, cwd = '/tmp/a')
```

### network

In the network stage, the program opens a socket on the port specified in the 67th argument. Then, it waits for a connection, and reads 4 bytes from the connection. If the bytes are `\xde\xad\xbe\xef`, the program prints the flag. We can use netcat to connect to the port and send the bytes:

```python
...

payload = ['A']*64 + ['\x00'] + ['\x20\x0a\x0d'] + ['5555'] + ['A']*32

...

# network
nc = con.process(['nc', 'localhost', '5555'])
nc.sendline('\xde\xad\xbe\xef')
```

### Putting it all together

```python
from pwn import *
import os, time

con = ssh('input2', 'pwnable.kr', port=2222, password='guest')

# file
con[""" mkdir /tmp/a """]
con[""" python3 -c "with open('/tmp/a/\x0a','w') as f: f.write('\x00\x00\x00\x00')" """]
con[""" ln -s /home/input2/flag /tmp/a/ """]

# argv + env
payload = ['A']*64 + ['\x00'] + ['\x20\x0a\x0d'] + ['5555'] + ['A']*32
p = con.process(['/home/input2/input'] + payload, env={'\xde\xad\xbe\xef':'\xca\xfe\xba\xbe'}, cwd = '/tmp/a')

# stdio
p.send('\x00\x0a\x00\xff')
p.send('\x00\x0a\x02\xff')

# network
nc = con.process(['nc', 'localhost', '5555'])
nc.sendline('\xde\xad\xbe\xef')

# result
p.interactive()
```

Running the script gives us the flag:

```
Mommy! I learned how to pass various input in Linux :)
```