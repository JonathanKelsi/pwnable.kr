# coin1

## Description

coin1 - 6 pt

> Mommy, I wanna play a game! <br>
> (if your network response time is too slow, try nc 0 9007 inside pwnable.kr server) <br> <br>
> Running at : nc pwnable.kr 9007 

## Solution

### Exploit

This challenge is a bit different from the previous ones. This time, we aren't given any source code nor any binary. We are only given a server to connect to using netcat:

```bash
$ nc pwnable.kr 9007

    ---------------------------------------------------
	-              Shall we play a game?              -
	---------------------------------------------------
	
	You have given some gold coins in your hand
	however, there is one counterfeit coin among them
	counterfeit coin looks exactly same as real coin
	however, its weight is different from real one
	real coin weighs 10, counterfeit coin weighes 9
	help me to find the counterfeit coin with a scale
	if you find 100 counterfeit coins, you will get reward :)
	FYI, you have 60 seconds.
	
	- How to play - 
	1. you get a number of coins (N) and number of chances (C)
	2. then you specify a set of index numbers of coins to be weighed
	3. you get the weight information
	4. 2~3 repeats C time, then you give the answer
	
	- Example -
	[Server] N=4 C=2 	# find counterfeit among 4 coins with 2 trial
	[Client] 0 1 		# weigh first and second coin
	[Server] 20			# scale result : 20
	[Client] 3			# weigh fourth coin
	[Server] 10			# scale result : 10
	[Client] 2 			# counterfeit coin is third!
	[Server] Correct!

	- Ready? starting in 3 sec... -
```

We are given a number of coins `N`, and one of them is known to be counterfeit. We are also given a number of chances `C` to find the counterfeit coin. In each chance, we can specify a set of coins to be weighed. The server will return the total weight of the specified coins.

Our goal is to find the counterfeit coin in `C` chances. If we do this 100 times, we will get a reward. Also, we have a 60 seconds time limit.

Connecting the server a few times, it seems that the number of chances is always too low to compare all the coins. Also, because of the time limit we need to find the fastest way possible. using as few chances as possible.

The solution - binary search. We can divide the coins into two groups, and sum the weights of the first group. If the sum is divisible by 10, then the counterfeit coin is in the second group. Otherwise, it is in the first group. We can repeat this process until we find the counterfeit coin.

```python
from pwn import *
import re

def bin_search(nc, N, C):
    low, high = 0, N

    for i in range(C):
        middle = (low + high) // 2
        
        nc.sendline(' '.join([str(_) for _ in range(low, middle)]).encode())
        w = int(nc.recvline().decode())

        if w % 10 == 0:
            low = middle
        
        else:
            high = middle + 1

    nc.sendline(str(low).encode())
    nc.recvline()

def exploit():
    nc = remote('pwnable.kr', 9007)
    nc.recvuntil(b'\t- Ready? starting in 3 sec... -\n\t\n')

    for i in range(100):
        match = re.search('N=([0-9]*) C=([0-9]*)', nc.recvline().decode())
        N, C = int(match.group(1)), int(match.group(2))
        bin_search(nc, N, C)
        
    nc.interactive()

exploit()
```

*Note*: It's possible that the network response time is too slow, and the server will disconnect us. In this case, we can connect to the server using `nc localhost 9007` inside the pwnable.kr server.

Running the script, we get the flag:

```bash
Congrats! get your flag
b1NaRy_S34rch1nG_1s_3asy_p3asy
```