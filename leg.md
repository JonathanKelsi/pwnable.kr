# leg

## Description

leg - 2 pt

> Daddy told me I should study arm. <br>
> But I prefer to study my leg! <br> <br>
> Download : http://pwnable.kr/bin/leg.c <br>
> Download : http://pwnable.kr/bin/leg.asm <br> <br>
> ssh leg@pwnable.kr -p2222 (pw:guest)

## Solution

### Background

#### Arm Assembly

The ARM architecture is a 32-bit RISC architecture. It is a reduced instruction set computer (RISC) architecture, which means that it has a small number of simple instructions. The ARM architecture is used in many embedded systems, including mobile phones, tablets, and other devices.

#### ARM and THUMB modes    

Arm processors can operate in two modes: ARM and THUMB. The ARM mode is the default mode. The THUMB mode is a reduced instruction set that is used to save space in small programs. The THUMB mode is a 16-bit mode, while the ARM mode is a 32-bit mode. 



### Exploit

Here is the attached source code:

```c
#include <stdio.h>
#include <fcntl.h>
int key1(){
	asm("mov r3, pc\n");
}
int key2(){
	asm(
	"push	{r6}\n"
	"add	r6, pc, $1\n"
	"bx	r6\n"
	".code   16\n"
	"mov	r3, pc\n"
	"add	r3, $0x4\n"
	"push	{r3}\n"
	"pop	{pc}\n"
	".code	32\n"
	"pop	{r6}\n"
	);
}
int key3(){
	asm("mov r3, lr\n");
}
int main(){
	int key=0;
	printf("Daddy has very strong arm! : ");
	scanf("%d", &key);
	if( (key1()+key2()+key3()) == key ){
		printf("Congratz!\n");
		int fd = open("flag", O_RDONLY);
		char buf[100];
		int r = read(fd, buf, 100);
		write(0, buf, r);
	}
	else{
		printf("I have strong leg :P\n");
	}
	return 0;
}
```

The porgram calculates 3 keys, and compare their sum with the input. Let's disect each key, by looking at the disassembled code:

```arm
Dump of assembler code for function key1:
   0x00008cd4 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cd8 <+4>:	add	r11, sp, #0
   0x00008cdc <+8>:	mov	r3, pc
   0x00008ce0 <+12>:	mov	r0, r3
   0x00008ce4 <+16>:	sub	sp, r11, #0
   0x00008ce8 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008cec <+24>:	bx	lr

```

The return value is passed in `r3`, and it's value is the value of the program counter. By looking at the disassembly of the main function, we can see that progarm is in `ARM` mode here, and so the `pc` will point to the current instruction **+ 8 bytes**. Thus, `key()` will return  `0x00008cdc+8 = 0x8ce4`.

```arm
Dump of assembler code for function key3:
   0x00008d20 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008d24 <+4>:	add	r11, sp, #0
   0x00008d28 <+8>:	mov	r3, lr
   0x00008d2c <+12>:	mov	r0, r3
   0x00008d30 <+16>:	sub	sp, r11, #0
   0x00008d34 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d38 <+24>:	bx	lr
```

`key3()` retunrs the value of the link register, which is the return address of the function. Looking at the relevant part of the main:

```arm
...
0x00008d78 <+60>:	add	r4, r4, r3
0x00008d7c <+64>:	bl	0x8d20 <key3>
0x00008d80 <+68>:	mov	r3, r0
...
```

`key3()` will return `0x00008d80`.

```arm
Dump of assembler code for function key2:
   0x00008cf0 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cf4 <+4>:	add	r11, sp, #0
   0x00008cf8 <+8>:	push	{r6}		; (str r6, [sp, #-4]!)
   0x00008cfc <+12>:	add	r6, pc, #1
   0x00008d00 <+16>:	bx	r6
   0x00008d04 <+20>:	mov	r3, pc
   0x00008d06 <+22>:	adds	r3, #4
   0x00008d08 <+24>:	push	{r3}
   0x00008d0a <+26>:	pop	{pc}
   0x00008d0c <+28>:	pop	{r6}		; (ldr r6, [sp], #4)
   0x00008d10 <+32>:	mov	r0, r3
   0x00008d14 <+36>:	sub	sp, r11, #0
   0x00008d18 <+40>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d1c <+44>:	bx	lr
```

`key2()` is a bit more complicated. In this function, the program is in `THUMB` mode, and so the `pc` will point to the current instruction **+ 4 bytes**. The return value is passed in `r3`, and `r3`'s value is the value of the program counter pluse 4 (there is a `add r3, pc, #4` instruction). Thus, `key2()` will return `0x00008d04+4+4 = 0x8d0c`.

The program will calculate the sum of the 3 keys, and compare it with the input. Thus, the input should be `0x8ce4+0x8d0c+0x8d80 = 108400`:

```bash
$ ./leg
Daddy has very strong arm! : 108400
Congratz!
My daddy has a lot of ARMv5te muscle!
```