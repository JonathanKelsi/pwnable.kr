# blackjack

## Description

blackjack - 1 pt 

>Hey! check out this C implementation of blackjack game! <br>
>I found it online <br>
>http://cboard.cprogramming.com/c-programming/114023-simple-blackjack-program.html <br> <br>
>I like to give my flags to millionares. <br>
>how much money you got? <br> <br> <br>
>Running at : nc pwnable.kr 9009

## Solution

### Exploit

In this challenge we are given a C program that implements a simple blackjack game, and are told that we need to be a millionaire to get the flag. 

The program is pretty simple, and the only interesting parts are the `bettin()` and `play()` functions:

```c
int betting() //Asks user amount to bet
{
 printf("\n\nEnter Bet: $");
 scanf("%d", &bet);
 
 if (bet > cash) //If player tries to bet more money than player has
 {
        printf("\nYou cannot bet more money than you have.");
        printf("\nEnter Bet: ");
        scanf("%d", &bet);
        return bet;
 }
 else return bet;
} // End Function
```

```c
 
void play() //Plays game
{
      
    ...

    betting(); //Prompts user to enter bet amount
        
    while(i<=21) //While loop used to keep asking user to hit or stay at most twenty-one times
                //  because there is a chance user can generate twenty-one consecutive 1's
    {

    ...
    
        if(p>21) //If player total is over 21, loss
        {
            printf("\nWoah Buddy, You Went WAY over.\n");
            loss = loss+1;
            cash = cash - bet;
            printf("\nYou have %d Wins and %d Losses. Awesome!\n", won, loss);
            dealer_total=0;
            askover();
        }

    ...

    } // End While Loop
} // End Function
```

It looks like we can bet as much money as we want - as long as it's less than the amount of money we have, and if we lose the game we lose the amount we bet.

Thus, we can bet a negative amount of money and lose the game. This will cause the `cash` variable to be *increased* by the positive value of the bet, and we will be able to get the flag. 

```bash
$ nc pwnable.kr 9009

...

Enter Bet: $-2147483147

...

Dealer Has the Better Hand. You Lose.

...

YaY_I_AM_A_MILLIONARE_LOL
```
