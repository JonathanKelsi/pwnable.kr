# coin2

## Description

coin2 - 111 pt

> Shall we play a game? <br>
> (if your network response time is slow, try nc 0 9008 inside pwnable.kr server) <br> <br>
> Running at : nc pwnable.kr 9008

## Solution

### Exploit

This challenge is very similar to `coin1`. Once again, we are given a server to connect to using netcat, and our goal is, by using a scale, to find the counterfeit coin among a set of coins:

```bash
$ nc pwnable.kr 9008

    ---------------------------------------------------
    -              Shall we play a game?              -
    ---------------------------------------------------

    You have given some gold coins in your hand.
    however, there is one counterfeit coin among them
    counterfeit coin looks exactly same as real coin
    luckily, its weight is different from real one
    real coin weighs 10, counterfeit coin weighes 9
    help me to find the counterfeit coin with a scale.
    if you find 100 counterfeit coins, you will get reward :)
    FYI, you have 60 seconds.

    - How to play - 
    1. you get a number of coins (N) and number of chances (C) to use scale
    2. then you specify C set of index numbers of coins to be weighed
    3. you get the weight information of each C set
    4. you give the answer

    - Example -
    [Server] N=4 C=2        # find counterfeit among 4 coins with 2 trial
    [Client] 0 1-1 2        # weigh two set of coins (first and second), (second and third)
    [Server] 20-20          # scale result : 20 for first set, 20 for second set
    [Client] 3              # counterfeit coin is fourth!
    [Server] Correct!

    - Note - 
    dash(-) is used as a seperator for each set

    - Ready? starting in 3 sec ... -
```

The key difference between the two challenges is that this time, we need to specify all the sets we want to weight in one go. We can't specify a set, weight it, and then - based on the result - specify the next. This means no simple binary search.

Instead, we are going to use a non-adaptive binary search. For each set, we are going to pick every other block of 2^i coins:

| Group | Picked numbers |
|----------|-------------|
| 0 | 0, 2, 4, 6, 8, ... |
| 1 | 0, 1, 4, 5, 8, 9, ... |
| 2 | 0, 1, 2, 3, 8, 9, 10, 11, ... |
| ... | ... |

Using these sets, we can binary search on the result:

```python
from pwn import *
import re

def search(nc, N, C):
    # create the wanted sets
    sets = []

    for i in range(C):
        power, temp = pow(2, i), []
        
        for n in range(N):
            if (n % (power * 2)) <= power - 1:
                temp.append(n)
            
        sets.append(temp)
    
    # send the sets
    nc.sendline(('-'.join([' '.join([str(_) for _ in s]) for s in sets])).encode())
    
    # parse the response
    res = [int(_) for _ in nc.recvline().decode().split('-')]
    
    # find where the fake coin is
    contendors = [_ for _ in range(N)]
    
    for i in range(C):
        if res[i] % 10 == 0:
            contendors = list(set(contendors) - set(sets[i]))
        else:
            contendors = list(set(contendors) & set(sets[i]))
            
    # send the index of the fake coin to the server
    nc.sendline(str(contendors[0]).encode())
    
    # receive the response
    nc.recvline()


def exploit():
    nc = remote('pwnable.kr', 9008)
    nc.recvuntil(b'\t- Ready? starting in 3 sec ... -\n\t\n')

    for i in range(100):
        match = re.search('N=([0-9]*) C=([0-9]*)', nc.recvline().decode())
        N, C = int(match.group(1)), int(match.group(2))
        print('HERE')
        search(nc, N, C)
        
    nc.interactive()


exploit()
```

```bash
NoN_aDaptiv3_b1narY_S3arcHing_is_4ls0_3asY
```