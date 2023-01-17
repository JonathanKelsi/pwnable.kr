# flag

## Description

flag - 7 pt

> Papa brought me a packed present! let's open it. <br> <br>
> Download : http://pwnable.kr/bin/flag <br> <br>
> This is reversing task. all you need is binary


## Solution

### Background

#### Executable Packers

An executable packer is a program that takes an executable file and compresses it, encrypts it, or otherwise modifies it in some way. The resulting file is called a packed executable. The purpose of a packer is to make the executable file smaller, harder to reverse engineer, or both. The most common type of packer is a compressor, which reduces the size of the executable file by removing redundant data. Other types of packers include encryptors, which make the executable file harder to reverse engineer by encrypting it, and binders, which combine multiple executable files into a single file.

When we run a packed file, it unpacks itself in memory and then executes the unpacked file. The unpacked file is usually deleted after it is executed, and is identical to the original file, but it may be slightly different.


### Exploit

In this challenge, we are given a elf file named ```flag```. Running ```file``` to check the file type, we get the following output:

```bash
$ file flag
flag: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header
```

As of now, it looks like a normal elf file. Running it gives us the following output:

```bash
$ ./flag
I will malloc() and strcpy the flag there. take it.
```

It appears that the program is going to malloc() and strcpy() the flag. Let's run it in gdb to see what's going on.

```bash
$ gdb ./flag
(gdb) disas main
No symbol table is loaded. Use the "file" command.
```

It looks the binary is stripped. Trying our luck with ```strings``` command, we get the following output:

```bash
$ strings flag
...
USQRH
PROT_EXEC|PROT_WRITE failed.
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.08 Copyright (C) 1996-2011 the UPX Team. All Rights Reserved. $
_j<X
Ph^)-
j2AZE)
...
```

It looks like the binary is **[packed](#executable-packers)** with UPX. Let's try to unpack it.

```bash
$ upx -d flag
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    883745 <-    335288   37.94%   linux/amd64   flag

Unpacked 1 file.
```

Now, we are able to run the binary in gdb. Right after the ```malloc```, the program loads the flag for strcpy. Then, we can extract the flag using gdb.

```
$rdx   : 0x00000000496628  →  "UPX...? sounds like a delivery service :)"
```
