ksmbd 条件竞争漏洞挖掘：思路与案例
====================

本文介绍从代码审计的角度分析、挖掘条件竞争、UAF 漏洞思路，并以 ksmbd 为实例介绍审计的过程和几个经典漏洞案例。

分析代码版本为：linux-6.5.5

相关漏洞在一年前已修复完毕.

掌握背景：Linux 内核条件竞争 UAF 常见场景
--------------------------

首先我们看一下 Linux 内核下 UAF 漏洞产生的几种常见情况，UAF 的核心原理是 内存被释放了，程序仍让能使用这块内存，导致该现象的常见场景：

- 指针在程序中被拷贝（比如存放到不同的对象中、放到链表中），其中一个指针释放后另一个指针没有被清理
- 程序中并发访问导致内存对象还在使用时被其他线程释放.

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-472d9aa178cee85d297dcbf60975cb5f38225ad1.png)

对于 Linux 内核/驱动而言，目前最常见的 UAF 是由于条件竞争导致的，即一个线程在使用某块内存时其他线程将其释放了。

那么 Linux 内核为什么会有条件竞争问题呢，其根本原因如下：

- Linux 以进程为调度主体，不同的进程可能会同时运行
- 不同的进程实体，通过系统调用进入内核后共用同一个内核里面的资源，比如物理内存、内核堆内存等

> 下图表示一个多核系统上两个进程同时在不同的 CPU 核运行，访问内核中的共享变量，实际上由于调度中断单核情况下也存在并发场景

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-ecedc385694e34e1683cc79ccafd67df660545e1.png)

并发执行+共享对象 是条件竞争的根因，因此驱动在开发设计时要考虑到并发场景，利用锁、引用计数等机制让资源在并发访问时不出问题.

常见的并发场景：

| 并发场景 | 解释 |
|---|---|
| 用户进程之间 | 多线程并发系统调用，比如IOCTL、MMAP、READ、WRITE 等 |
| 用户进程与内核线程之间 | 内核线程中访问的共享对象，可能被用户态进程修改、释放 |
| 内核线程之间 | 不同内核线程之间使用共享对象 |

以 IOCTL 为例用户态进程通过 SVC 指令进入内核，首先进入 ioctl 系统调用入口，然后在 `vfs_ioctl`​ 里面会调用 f\_op-&gt;unlocked\_ioctl 注册的函数指针，进入每个文件/驱动自己实现的回调中。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-bfb91390a4eef34783ec516b230b8cd348957134.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-2430168137443cfe2ecdd563cb23e77d8776e5ea.png)

由于多核可以并发 SVC 同时执行系统调用，且从系统调用入口到驱动回调中没有锁保护，所以在各个驱动接口中需要**自己实现锁保护并发资源访问**。

同理以 mmap 回调为例，SVC 进入内核后会进入 vm\_mmap\_pgoff 里面会获取当前进程 mm 对象的写锁，然后才通过 do\_mmap 执行驱动对应的 mmap 回调

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-bd6a1e40e7ba2004789c4eee7556369b23bd7b10.png)

分析系统调用 ---&gt; 驱动回调的调用路径之间锁的使用情况可知：

- 同一个进程的不同线程共享 mm 对象（即使 mm 指针一样）所以线程之间无法并发 mmap，但是 mmap 和其他回调比如 ioctl 是可以互相并发的.
- fork 出来的子进程或者通过 IPC 将 fd 共享给其他进程情况下，可以通过多进程并发同时进入驱动的 mmap 回调中.

**挖掘条件竞争漏洞，首先就需要通过分析内核代码，清楚了解目标函数执行上下文中是否已经有锁保护，有哪些锁保护，然后以并发执行的视角分析并发场景下的各个代码时序，判断是否存在 UAF。**

分析目标：梳理目标软件脉络
-------------

分析 ksmbd 的背景是去年偶然间看到一篇介绍通过 syzkaller fuzz ksmbd 协议的文章：[Tickling ksmbd: fuzzing SMB in the Linux kernel](https://pwning.tech/ksmbd-syzkaller/) ，其核心原理是新增一个伪系统调用 syz\_ksmbd\_send\_req 用来将 syzkaller 生成的数据喂给内核的协议中解析

```c
#define KSMBD_BUF_SIZE 16000
static long syz_ksmbd_send_req(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
    int sockfd;
    int packet_reqlen;
    int errno;
    struct sockaddr_in serv_addr;
    char packet_req[KSMBD_BUF_SIZE]; // max frame size

    debug("[*]{syz_ksmbd_send_req} entered ksmbd send...\n");
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    memset(&serv_addr, '\0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(445);
    errno = connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    // prepend kcov handle to packet
    packet_reqlen = a1 + 8 > KSMBD_BUF_SIZE ? KSMBD_BUF_SIZE - 8 : a1;
    *(unsigned long*)packet_req = procid + 1;
    memcpy(packet_req + 8, (char*)a0, packet_reqlen);

    if (write(sockfd, (char*)packet_req, packet_reqlen + 8) < 0)
        return -4;

    if (read(sockfd, (char*)a2, a3) < 0)
        return -5;

    if (close(sockfd) < 0)
        return -6;

    debug("[+]{syz_ksmbd_send_req} successfully returned\n");
    return 0;
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-186a7af7f4ae8a53ebbd2acee2c61ee238515196.png)

通过分析这篇文章可以得到一些信息：

- 定位 ksmbd 处理数据包的入口，即 ksmbd\_conn\_handler\_loop
- 还存在一些简单的内存越界漏洞，代表可能还会存在一些较复杂、或者隐藏较深的漏洞

 基于这些信息开始对 ksmbd 的源码进行分析，分析思路：

- 从入口出追踪客户端发送的网络数据流，梳理出请求处理过程中的数据流过程、校验逻辑.
- 分析数据解析过程，尝试挖掘内存越界、溢出等漏洞
- 分析请求处理时的一些上下文约束，比如是否可并发、是否有锁，对象生命周期管理，尝试挖掘条件竞争、UAF漏洞

从 ksmbd\_conn\_handler\_loop 往上追踪，这是在 ksmbd\_tcp\_new\_connection 创建的内核线程回调函数

```c
static int ksmbd_tcp_new_connection(struct socket *client_sk)
{
    t = alloc_transport(client_sk);
    csin = KSMBD_TCP_PEER_SOCKADDR(KSMBD_TRANS(t)->conn);
    KSMBD_TRANS(t)->handler = kthread_run(ksmbd_conn_handler_loop,
                          KSMBD_TRANS(t)->conn,
                          "ksmbd:%u",
                          ksmbd_tcp_get_port(csin));
```

 其调用路径：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-c6f3ec9332c0c88e18f88ace7699f96f39b0af8c.png)

因此可以知道每当有一个客户端连接 445 端口时，ksmbd\_kthread\_fn 就会通过 ksmbd\_tcp\_new\_connection 创建一个内核线程，然后 ksmbd\_conn\_handler\_loop 里面处理每个 socket 请求的业务.

在 ksmbd\_tcp\_new\_connection --&gt; alloc\_transport 会为每一个连接创建两个关键的对象（`ksmbd_transport`​ 和 `ksmbd_conn`​），用于管理 tcp 连接下的各种协议状态

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-7a7e8baeea186750b06a6e3bba753fdf30c55019.png)

两个对象互相保存对方的指针，方便从一个对象中拿到另一个对象进行操作，对象的大概作用：

- ksmbd\_transport：负责链路数据的收发，比如从网络连接中读取数据
- ksmbd\_conn：管理整个 smb 连接的状态，比如登录、文件操作，会话密钥等，**每个 TCP 连接对应一个 conn 对象**

其中 ksmbd\_conn 是非常核心的对象，在 SMB 请求处理的各个环节都能看到， ksmbd\_conn\_handler\_loop 的大概处理流程如下

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-e0aa71608b9322c0702f7dfc71b009812dac7c5d.png)

conn 下每收到一个请求都会新建一个 work，然后把 work 放到 ksmbd\_wq， workqueue 会动态分配到不同 worker 执行。这边在介绍一下内核的 workqueue 机制，workqueue 和 work 的关系如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-b87cc2ada19c4a6d5cb37b6df90c802458eefca2.png)

核心概念是：work 先注册到 workqueue ，然后具体由 worker 执行，在代码中每个 worker 对应一个 work\_thread 内核线程，**一个 workqueue 里面会存在多个 worker，这些 worker 之间并发执行**.

因此**同一时刻可能会有 handle\_ksmbd\_work 实例访问同一个 conn 对象，这样就有了 RACE 的可能**.

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-fb41f22d73f9c908bdd2b334b79809ea2c081151.png)

继续分析 handle\_ksmbd\_work 的大体逻辑：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-2e8fb58dbc698aae3b9905a1effb925a242545af.png)

handle\_ksmbd\_work 主要逻辑就是解析 work-&gt;request\_buf 中的网络报文数据，根据里面的请求类型、参数调用对应的请求处理函数进行处理（`conn->cmds`​），同时可以看到 cmds-&gt;proc 执行时上**下文是没有锁的**，因此如果 cmd 里面如果有访问到共享变量就需要**自行加锁避免并发**.

cmds 中可用的回调函数如下

```c
static struct smb_version_cmds smb2_0_server_cmds[NUMBER_OF_SMB2_COMMANDS] = {
    [SMB2_NEGOTIATE_HE] =   { .proc = smb2_negotiate_request, },
    [SMB2_SESSION_SETUP_HE] =   { .proc = smb2_sess_setup, },
    [SMB2_TREE_CONNECT_HE]  =   { .proc = smb2_tree_connect,},
    [SMB2_TREE_DISCONNECT_HE]  =    { .proc = smb2_tree_disconnect,},
    [SMB2_LOGOFF_HE]    =   { .proc = smb2_session_logoff,},
    [SMB2_CREATE_HE]    =   { .proc = smb2_open},
    [SMB2_QUERY_INFO_HE]    =   { .proc = smb2_query_info},
    [SMB2_QUERY_DIRECTORY_HE] = { .proc = smb2_query_dir},
    [SMB2_CLOSE_HE]     =   { .proc = smb2_close},
    [SMB2_ECHO_HE]      =   { .proc = smb2_echo},
    [SMB2_SET_INFO_HE]      =       { .proc = smb2_set_info},
    [SMB2_READ_HE]      =   { .proc = smb2_read},
    [SMB2_WRITE_HE]     =   { .proc = smb2_write},
    [SMB2_FLUSH_HE]     =   { .proc = smb2_flush},
    [SMB2_CANCEL_HE]    =   { .proc = smb2_cancel},
    [SMB2_LOCK_HE]      =   { .proc = smb2_lock},
    [SMB2_IOCTL_HE]     =   { .proc = smb2_ioctl},
    [SMB2_OPLOCK_BREAK_HE]  =   { .proc = smb2_oplock_break},
    [SMB2_CHANGE_NOTIFY_HE] =   { .proc = smb2_notify},
};
```

这些回调函数就会根据请求和 conn 对象实现 smb 协议的业务逻辑，之后就可以对这些回调函数进行审计，这里再次回顾一下这些回调函数执行的上下文状态：

- 回调函数会在不同的 worker 线程中被调用，存在并发性
- 同一个连接的不同请求可能并发处理，处理时会访问同一个 conn 对象

经过分析 ksmbd 中的共享变量、对象也主要是集中在 conn 对象中（类似于 file\_operation 回调的共享 filp 对象），因此在分析条件竞争漏洞时可重点关注对 conn 对象的访问、操作。

 ‍

实例分析：加深理解
---------

 本节以一些真实案例介绍条件竞争漏洞的挖掘、分析经验

### smb2\_open 条件竞争 UAF

smb2\_open 的命令字为 SMB2\_CREATE\_HE，其用途对标的是 Linux 用户态的 open 函数，用于打开远程 smb 服务器上的一个文件。

```c
    [SMB2_CREATE_HE]    =   { .proc = smb2_open},
```

函数的代码很长，大致逻辑是首先从数据包中提取出要打开的文件名和打开的模式，对文件名校验后通过内核 vfs 子系统的 API 打开共享目录下的文件。

对该函数进行审计的思路是：

- 常规数据解析类漏洞，比如堆栈溢出等
- 文件名校验逻辑是否有误，导致目录穿越
- 对象管理是否有误，导致 UAF

对数据解析和文件名校验、打开逻辑进行分析没有发现问题，分析其对象管理时，发现 smb2\_open 打开文件后会分配 struct ksmbd\_file 对象管理打开文件对应的 struct file 对象，ksmbd\_file 和 ksmbd\_cnn 的关系如下图所示：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-92cb0692bbe0144758eaa75332626fb1bbc8ad50.png)

- ksmbd\_conn 对象里面的 sessions 数组中保存了当前连接的会话对象（ksmbd\_session）
- ksmbd\_session 对象的 file\_table 保存了打开的所有文件对象（ksmbd\_file）
- ksmbd\_file 对象的 filp 指向了真正打开的 VFS 文件对象（struct file）

下面看一下 ksmbd\_file 对象的创建和初始化过程，相关代码如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-150ae68b59609777fa42407d7c48a77fed7f3816.png)

首先调用 ksmbd\_open\_fd 分配 fp，其中会调用 kmem\_cache\_zalloc 分配 ksmbd\_file 对象，然后通过 \_\_open\_id 将 fp 存放到 ksmbd\_session 的 file\_table 里面（work-&gt;sess-&gt;file\_table）, work-&gt;sess 是进入回调函数前从 conn 对象中获取的

```c
struct ksmbd_session *ksmbd_session_lookup(struct ksmbd_conn *conn,
                       unsigned long long id)
{
    struct ksmbd_session *sess;

    sess = xa_load(&conn->sessions, id);
    if (sess)
        sess->last_active = jiffies;
    return sess;
}

work->sess = ksmbd_session_lookup_all(conn, sess_id);
```

ksmbd\_open\_fd 返回后设置 fp 对象的其他字段，注意到此时 fp 已经被放入了 sess-&gt;file\_table ，此时其他线程也可以同时获取该对象，而且此时 **fp 的引用计数为 1**。

下面可以看一下 smb\_close 的实现，其核心逻辑位于 ksmbd\_close\_fd

```c
int ksmbd_close_fd(struct ksmbd_work *work, u64 id)
{
    struct ksmbd_file   *fp;
    struct ksmbd_file_table *ft;

    ft = &work->sess->file_table;
    read_lock(&ft->lock);
    fp = idr_find(ft->idr, id);
    if (fp) {
        set_close_state_blocked_works(fp);
        if (!atomic_dec_and_test(&fp->refcount))
            fp = NULL;
    }
    read_unlock(&ft->lock);
    __put_fd_final(work, fp);
    return 0;
}
```

当 fp-&gt;refcount 减一后为 0 时会进入 \_\_put\_fd\_final 释放 fp 的内存，因此可以在线程 A 执行 smb2\_open 时，其他线程通过 smb2\_close 释放 fp 就能导致 UAF。

RACE 场景下的时序关系如下图：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-63f0e76d63fcb37307c936939af4c0c7cfdf8ac7.png)

触发后的 kasan 日志如下

```c
[  224.236369] BUG: KASAN: slab-use-after-free in __open_id+0xfc/0x160 [ksmbd]
[  224.236457] Write of size 8 at addr ffff8881bf504788 by task kworker/6:1/90

[  224.236469] CPU: 6 PID: 90 Comm: kworker/6:1 Tainted: G           OE      6.5.4 #1
[  224.236478] Hardware name: VMware, Inc. VMware Virtual Platform/440BX Desktop Reference Platform, BIOS 6.00 07/22/2020
[  224.236485] Workqueue: ksmbd-io handle_ksmbd_work [ksmbd]
[  224.236572] Call Trace:
[  224.236577]  <TASK>
[  224.236583]  dump_stack_lvl+0x48/0x70
[  224.236595]  print_report+0xd2/0x660
[  224.236605]  ? __virt_addr_valid+0x103/0x180
[  224.236617]  ? kasan_complete_mode_report_info+0x8a/0x230
[  224.236639]  ? __open_id+0xfc/0x160 [ksmbd]
[  224.236721]  kasan_report+0xd0/0x120
[  224.236731]  ? __open_id+0xfc/0x160 [ksmbd]
[  224.236816]  __asan_store8+0x8e/0xe0
[  224.236825]  __open_id+0xfc/0x160 [ksmbd]
[  224.236908]  ksmbd_open_durable_fd+0x21/0x40 [ksmbd]
[  224.236991]  smb2_open+0x1276/0x3d00 [ksmbd]
[  224.237083]  ? __pfx_smb2_open+0x10/0x10 [ksmbd]
[  224.237167]  ? ksmbd_release_crypto_ctx+0xd1/0x100 [ksmbd]
[  224.237281]  ? ksmbd_crypt_message+0x48d/0xc70 [ksmbd]
[  224.237368]  ? __pfx_ksmbd_crypt_message+0x10/0x10 [ksmbd]
[  224.237463]  ? xas_descend+0x82/0x130
[  224.237473]  ? xas_descend+0x82/0x130
[  224.237481]  ? xas_start+0x8a/0x1d0
[  224.237490]  ? __rcu_read_unlock+0x51/0x80
[  224.237507]  ? ksmbd_smb2_check_message+0xa56/0xc90 [ksmbd]
[  224.237595]  handle_ksmbd_work+0x2a7/0x800 [ksmbd]
[  224.237684]  process_one_work+0x4d3/0x840
[  224.237700]  worker_thread+0x91/0x6e0
[  224.237715]  ? __pfx_worker_thread+0x10/0x10
[  224.237726]  kthread+0x188/0x1d0
[  224.237735]  ? __pfx_kthread+0x10/0x10
[  224.237744]  ret_from_fork+0x44/0x80
[  224.237754]  ? __pfx_kthread+0x10/0x10
[  224.237763]  ret_from_fork_asm+0x1b/0x30
[  224.237777]  </TASK>

[  224.237785] Allocated by task 90:
[  224.237790]  kasan_save_stack+0x38/0x70
[  224.237800]  kasan_set_track+0x25/0x40
[  224.237809]  kasan_save_alloc_info+0x1e/0x40
[  224.237818]  __kasan_slab_alloc+0x9d/0xa0
[  224.237824]  kmem_cache_alloc+0x17f/0x3c0
[  224.237833]  ksmbd_open_fd+0x2d/0x550 [ksmbd]
[  224.237916]  smb2_open+0x1200/0x3d00 [ksmbd]
[  224.237999]  handle_ksmbd_work+0x2a7/0x800 [ksmbd]
[  224.238082]  process_one_work+0x4d3/0x840
[  224.238091]  worker_thread+0x91/0x6e0
[  224.238100]  kthread+0x188/0x1d0
[  224.238106]  ret_from_fork+0x44/0x80
[  224.238114]  ret_from_fork_asm+0x1b/0x30

[  224.238124] Freed by task 774:
[  224.238128]  kasan_save_stack+0x38/0x70
[  224.238137]  kasan_set_track+0x25/0x40
[  224.238146]  kasan_save_free_info+0x2b/0x60
[  224.238155]  ____kasan_slab_free+0x180/0x1f0
[  224.238164]  __kasan_slab_free+0x12/0x30
[  224.238170]  slab_free_freelist_hook+0xd2/0x1a0
[  224.238178]  kmem_cache_free+0x1b2/0x360
[  224.238187]  __ksmbd_close_fd+0x34a/0x490 [ksmbd]
[  224.238280]  ksmbd_close_fd+0xb0/0x110 [ksmbd]
[  224.238362]  smb2_close+0x2fc/0x690 [ksmbd]
[  224.238445]  handle_ksmbd_work+0x2a7/0x800 [ksmbd]
[  224.238528]  process_one_work+0x4d3/0x840
[  224.238537]  worker_thread+0x91/0x6e0
[  224.238546]  kthread+0x188/0x1d0
[  224.238552]  ret_from_fork+0x44/0x80
[  224.238560]  ret_from_fork_asm+0x1b/0x30
```

### smb2\_close 条件竞争 UAF

发现 smb2\_open 的漏洞后，忽然想到如果并发 smb2\_close 会出现什么样的效果.再次回顾下 smb2\_close --&gt; ksmbd\_close\_fd 的代码

```c
int ksmbd_close_fd(struct ksmbd_work *work, u64 id)
{
    struct ksmbd_file   *fp;
    struct ksmbd_file_table *ft;

    ft = &work->sess->file_table;
    read_lock(&ft->lock);
    fp = idr_find(ft->idr, id);
    if (fp) {
        set_close_state_blocked_works(fp);
        if (!atomic_dec_and_test(&fp->refcount))
            fp = NULL;
    }
    read_unlock(&ft->lock);
    __put_fd_final(work, fp);
    return 0;
}
```

让我们以并发的思维人脑模拟执行一下上面的代码：

1. 假设两个线程 A B 并发进入 ksmbd\_close\_fd，且此时 id 对应 fp 的引用计数为 1
2. 由于持有的是 read\_lock 读锁，所以两个线程可以同时拿到 fp 并进入 atomic\_dec\_and\_test
3. 由于 atomic\_dec\_and\_test 的逻辑其中一个线程会进入 fp = NULL 分支，所以只有一个线程能正常释放 fp.

因此上述场景是无法产生 UAF 的，那假如线程 A 先进入 \_\_put\_fd\_final ，然后线程 B 执行到 atomic\_dec\_and\_test ，然后线程 A 在 \_\_put\_fd\_final 里面释放 fp 是否可行呢？

由于 \_\_put\_fd\_final 释放 fp 前会先获取 ft-&gt;lock 的写锁，将 fp 从 idr 中移除后才会去释放 fp，**因此无法构造上面的场景**，因为写锁的获取要等所有读锁释放后才能获取。

单纯并发 ksmbd\_close\_fd 不可行，那利用其他接口配合这个逻辑是否可以产生不一样的效果呢，经过思考和尝试，当其他线程在使用 fp 时，多个线程进入 close 就可以把 fp 提前释放。

以 smb2\_read 为例，函数首先通过 ksmbd\_lookup\_fd\_slow 获取 fp 并增加其引用计数，使用完成后会通过 ksmbd\_fd\_put 释放引用

```c
    fp = ksmbd_lookup_fd_slow(work, req->VolatileFileId, req->PersistentFileId);

    nbytes = ksmbd_vfs_read(work, fp, length, &offset);

    ksmbd_fd_put(work, fp);
```

并发导致 UAF 的场景如下：

1. 线程 A 持有 fp （比如通过 smb2\_read），此时 fp-&gt;refcount = 2
2. 5 个线程 B1 B2 .... B5，同时进入 ksmbd\_close\_fd 就会尝试最多减 5 次引用计数，导致 fp-&gt;refcount = 0，被释放
3. 线程 A 后面使用 fp 时就是被释放的 fp

触发漏洞后的 kasan 日志如下

```c
[  115.537085] BUG: KASAN: slab-use-after-free in smb2_read+0x241/0x850 [ksmbd]
[  115.537205] Read of size 4 at addr ffff8881ac7099cc by task kworker/6:2/76

[  115.537218] CPU: 6 PID: 76 Comm: kworker/6:2 Tainted: G           OE      6.5.4 #1
[  115.537227] Hardware name: VMware, Inc. VMware Virtual Platform/440BX Desktop Reference Platform, BIOS 6.00 07/22/2020
[  115.537235] Workqueue: ksmbd-io handle_ksmbd_work [ksmbd]
[  115.537321] Call Trace:
[  115.537327]  <TASK>
[  115.537333]  dump_stack_lvl+0x48/0x70
[  115.537349]  print_report+0xd2/0x660
[  115.537361]  ? __virt_addr_valid+0x103/0x180
[  115.537375]  ? kasan_complete_mode_report_info+0x8a/0x230
[  115.537387]  ? smb2_read+0x241/0x850 [ksmbd]
[  115.537472]  kasan_report+0xd0/0x120
[  115.537482]  ? smb2_read+0x241/0x850 [ksmbd]
[  115.537570]  __asan_load4+0x8e/0xd0
[  115.537579]  smb2_read+0x241/0x850 [ksmbd]
[  115.537680]  ? __pfx_smb2_read+0x10/0x10 [ksmbd]
[  115.537782]  handle_ksmbd_work+0x2a7/0x800 [ksmbd]
[  115.537870]  process_one_work+0x4d3/0x840
[  115.537889]  worker_thread+0x91/0x6e0
[  115.537904]  ? __pfx_worker_thread+0x10/0x10
[  115.537915]  kthread+0x188/0x1d0
[  115.537925]  ? __pfx_kthread+0x10/0x10
[  115.537934]  ret_from_fork+0x44/0x80
[  115.537946]  ? __pfx_kthread+0x10/0x10
[  115.537955]  ret_from_fork_asm+0x1b/0x30
[  115.537969]  </TASK>

[  115.537977] Allocated by task 76:
[  115.537983]  kasan_save_stack+0x38/0x70
[  115.537994]  kasan_set_track+0x25/0x40
[  115.538003]  kasan_save_alloc_info+0x1e/0x40
[  115.538012]  __kasan_slab_alloc+0x9d/0xa0
[  115.538019]  kmem_cache_alloc+0x17f/0x3c0
[  115.538028]  ksmbd_open_fd+0x2d/0x550 [ksmbd]
[  115.538110]  smb2_open+0x1200/0x3ca0 [ksmbd]
[  115.538193]  handle_ksmbd_work+0x2a7/0x800 [ksmbd]
[  115.538298]  process_one_work+0x4d3/0x840
[  115.538307]  worker_thread+0x91/0x6e0
[  115.538316]  kthread+0x188/0x1d0
[  115.538323]  ret_from_fork+0x44/0x80
[  115.538331]  ret_from_fork_asm+0x1b/0x30

[  115.538341] Freed by task 1114:
[  115.538346]  kasan_save_stack+0x38/0x70
[  115.538355]  kasan_set_track+0x25/0x40
[  115.538364]  kasan_save_free_info+0x2b/0x60
[  115.538373]  ____kasan_slab_free+0x180/0x1f0
[  115.538382]  __kasan_slab_free+0x12/0x30
[  115.538388]  slab_free_freelist_hook+0xd2/0x1a0
[  115.538396]  kmem_cache_free+0x1b2/0x360
[  115.538405]  __ksmbd_close_fd+0x34a/0x490 [ksmbd]
[  115.538487]  ksmbd_close_fd+0xb0/0x110 [ksmbd]
[  115.538569]  smb2_close+0x2fc/0x690 [ksmbd]
[  115.538652]  handle_ksmbd_work+0x2a7/0x800 [ksmbd]
[  115.538734]  process_one_work+0x4d3/0x840
[  115.538743]  worker_thread+0x91/0x6e0
[  115.538752]  kthread+0x188/0x1d0
[  115.538758]  ret_from_fork+0x44/0x80
[  115.538777]  ret_from_fork_asm+0x1b/0x30
```

### smb2\_write 条件竞争 UAF

有了上面的经验，我开始关注代码中对对象的使用：

1. 使用共享对象是是否持有引用计数
2. 能否并发释放

于是在浏览代码时发现 smb2\_write 上来就是使用了 work-&gt;tcon 对象

```c
int smb2_write(struct ksmbd_work *work)
{
    WORK_BUFFERS(work, req, rsp);
    if (test_share_config_flag(work->tcon->share_conf, KSMBD_SHARE_FLAG_PIPE)) {
        ksmbd_debug(SMB, "IPC pipe write request\n");
        return smb2_write_pipe(work);
    }
```

追踪一下赋值点

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-eb1beb297886ae73f375458b4d6f51ad0f6ceb59.png)

```c
int smb2_get_ksmbd_tcon(struct ksmbd_work *work)
{
    struct smb2_hdr *req_hdr = ksmbd_req_buf_next(work);
    unsigned int tree_id;
    work->tcon = ksmbd_tree_conn_lookup(work->sess, tree_id);
    return 1;
}
```

可以看到 work-&gt;tcon 没有持有 tcon 对象的引用计数，那么能够并发释放吗，其并发逻辑位于

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-4b445d77442ece53804072d1c8281f94c1146081.png)

smb2\_tree\_disconnect 为 \_\_handle\_ksmbd\_work 的 cmd 回调，其中也没有锁保护，因此可以并发释放 tcon.

因此在 smb2\_write 执行时，多线程发起 smb2\_tree\_disconnect 请求就能在 smb2\_write 使用 tcon 时将其释放，导致 UAF，Crash 的日志如下：

```c
[ 5521.190232] BUG: KASAN: slab-use-after-free in smb2_write+0x16e/0x840 [ksmbd]
[ 5521.190327] Read of size 8 at addr ffff8881c5ef6708 by task kworker/6:0/1913

[ 5521.190341] CPU: 6 PID: 1913 Comm: kworker/6:0 Tainted: G           OE      6.5.4 #1
[ 5521.190350] Hardware name: VMware, Inc. VMware Virtual Platform/440BX Desktop Reference Platform, BIOS 6.00 07/22/2020
[ 5521.190358] Workqueue: ksmbd-io handle_ksmbd_work [ksmbd]
[ 5521.190446] Call Trace:
[ 5521.190451]  <TASK>
[ 5521.190457]  dump_stack_lvl+0x48/0x70
[ 5521.190473]  print_report+0xd2/0x660
[ 5521.190485]  ? __virt_addr_valid+0x103/0x180
[ 5521.190499]  ? kasan_complete_mode_report_info+0x8a/0x230
[ 5521.190511]  ? smb2_write+0x16e/0x840 [ksmbd]
[ 5521.190596]  kasan_report+0xd0/0x120
[ 5521.190606]  ? smb2_write+0x16e/0x840 [ksmbd]
[ 5521.190694]  __asan_load8+0x8b/0xe0
[ 5521.190704]  smb2_write+0x16e/0x840 [ksmbd]
[ 5521.190790]  ? _raw_spin_lock+0x82/0xf0
[ 5521.190807]  ? __pfx_smb2_write+0x10/0x10 [ksmbd]
[ 5521.190894]  ? ksmbd_smb2_check_message+0xa56/0xc90 [ksmbd]
[ 5521.191001]  handle_ksmbd_work+0x2a7/0x800 [ksmbd]
[ 5521.191090]  process_one_work+0x4d3/0x840
[ 5521.191109]  worker_thread+0x91/0x6e0
[ 5521.191124]  ? __pfx_worker_thread+0x10/0x10
[ 5521.191135]  kthread+0x188/0x1d0
[ 5521.191145]  ? __pfx_kthread+0x10/0x10
[ 5521.191154]  ret_from_fork+0x44/0x80
[ 5521.191166]  ? __pfx_kthread+0x10/0x10
[ 5521.191175]  ret_from_fork_asm+0x1b/0x30
[ 5521.191189]  </TASK>

[ 5521.191197] Allocated by task 1913:
[ 5521.191203]  kasan_save_stack+0x38/0x70
[ 5521.191214]  kasan_set_track+0x25/0x40
[ 5521.191223]  kasan_save_alloc_info+0x1e/0x40
[ 5521.191231]  __kasan_kmalloc+0xc3/0xd0
[ 5521.191240]  kmalloc_trace+0x48/0xc0
[ 5521.191249]  ksmbd_tree_conn_connect+0x75/0x2c0 [ksmbd]
[ 5521.191335]  smb2_tree_connect+0x11d/0x4c0 [ksmbd]
[ 5521.191419]  handle_ksmbd_work+0x2a7/0x800 [ksmbd]
[ 5521.191502]  process_one_work+0x4d3/0x840
[ 5521.191511]  worker_thread+0x91/0x6e0
[ 5521.191520]  kthread+0x188/0x1d0
[ 5521.191526]  ret_from_fork+0x44/0x80
[ 5521.191534]  ret_from_fork_asm+0x1b/0x30

[ 5521.191544] Freed by task 1922:
[ 5521.191549]  kasan_save_stack+0x38/0x70
[ 5521.191558]  kasan_set_track+0x25/0x40
[ 5521.191567]  kasan_save_free_info+0x2b/0x60
[ 5521.191575]  ____kasan_slab_free+0x180/0x1f0
[ 5521.191585]  __kasan_slab_free+0x12/0x30
[ 5521.191591]  slab_free_freelist_hook+0xd2/0x1a0
[ 5521.191599]  __kmem_cache_free+0x1a2/0x2f0
[ 5521.191608]  kfree+0x78/0x120
[ 5521.191616]  ksmbd_tree_conn_disconnect+0x94/0xb0 [ksmbd]
[ 5521.191701]  smb2_tree_disconnect+0x183/0x1b0 [ksmbd]
[ 5521.191785]  handle_ksmbd_work+0x2a7/0x800 [ksmbd]
[ 5521.191868]  process_one_work+0x4d3/0x840
[ 5521.191877]  worker_thread+0x91/0x6e0
[ 5521.191886]  kthread+0x188/0x1d0
[ 5521.191892]  ret_from_fork+0x44/0x80
[ 5521.191913]  ret_from_fork_asm+0x1b/0x30
```

### smb2\_lock 条件竞争 UAF

下面看一个稍微复杂一点的例子，对于复杂代码我们依然采用一样的策略，关注对象使用、锁、引用计数, smb2\_lock 的关键代码如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-750be09b98dfddccb3c58463e74baa4245ee29e0.png)  
 ‍

这里涉及的对象为存放在 **conn-&gt;lock\_list** 中的 smb\_lock 对象，在 【1】 -- 【2】 之间其他线程，通过 SMB2\_LOCKFLAG\_UNLOCK 进入 【0】 释放 smb\_lock 就会导致 UAF.

产生漏洞的本质原因是 \[1\] 分支提前将 smb\_lock 对象放入了 work-&gt;**conn-&gt;lock\_list** 这样在其释放 llist\_lock 后，其他线程就能释放 smb\_lock，\[2\] 处使用的 smb\_lock 就是已经被释放的对象。

这也是一种常见的条件竞争常见，即提前将对象放入了共享资源池中，后续使用时一旦被并发释放就会导致 UAF.

panic 日志如下

```c
[  192.743133] BUG: KASAN: slab-use-after-free in smb2_lock+0x17a7/0x2010 [ksmbd]
[  192.743228] Write of size 8 at addr ffff88810a5ca028 by task kworker/6:2/76

[  192.743241] CPU: 6 PID: 76 Comm: kworker/6:2 Tainted: G           OE      6.5.4 #1
[  192.743250] Hardware name: VMware, Inc. VMware Virtual Platform/440BX Desktop Reference Platform, BIOS 6.00 07/22/2020
[  192.743258] Workqueue: ksmbd-io handle_ksmbd_work [ksmbd]
[  192.743345] Call Trace:
[  192.743350]  <TASK>
[  192.743357]  dump_stack_lvl+0x48/0x70
[  192.743372]  print_report+0xd2/0x660
[  192.743384]  ? __virt_addr_valid+0x103/0x180
[  192.743398]  ? kasan_complete_mode_report_info+0x8a/0x230
[  192.743422]  ? smb2_lock+0x17a7/0x2010 [ksmbd]
[  192.743507]  kasan_report+0xd0/0x120
[  192.743518]  ? smb2_lock+0x17a7/0x2010 [ksmbd]
[  192.743605]  __asan_store8+0x8e/0xe0
[  192.743615]  smb2_lock+0x17a7/0x2010 [ksmbd]
[  192.743700]  ? xas_descend+0x82/0x130
[  192.743710]  ? __rcu_read_unlock+0x51/0x80
[  192.743730]  ? __pfx_smb2_lock+0x10/0x10 [ksmbd]
[  192.743814]  ? ksmbd_smb2_check_message+0xa56/0xc90 [ksmbd]
[  192.743902]  handle_ksmbd_work+0x2a7/0x800 [ksmbd]
[  192.743990]  process_one_work+0x4d3/0x840
[  192.744009]  worker_thread+0x91/0x6e0
[  192.744024]  ? __pfx_worker_thread+0x10/0x10
[  192.744035]  kthread+0x188/0x1d0
[  192.744045]  ? __pfx_kthread+0x10/0x10
[  192.744054]  ret_from_fork+0x44/0x80
[  192.744066]  ? __pfx_kthread+0x10/0x10
[  192.744075]  ret_from_fork_asm+0x1b/0x30
[  192.744089]  </TASK>

[  192.744097] Allocated by task 76:
[  192.744103]  kasan_save_stack+0x38/0x70
[  192.744114]  kasan_set_track+0x25/0x40
[  192.744123]  kasan_save_alloc_info+0x1e/0x40
[  192.744132]  __kasan_kmalloc+0xc3/0xd0
[  192.744141]  kmalloc_trace+0x48/0xc0
[  192.744151]  smb2_lock+0x4c6/0x2010 [ksmbd]
[  192.744233]  handle_ksmbd_work+0x2a7/0x800 [ksmbd]
[  192.744316]  process_one_work+0x4d3/0x840
[  192.744325]  worker_thread+0x91/0x6e0
[  192.744334]  kthread+0x188/0x1d0
[  192.744340]  ret_from_fork+0x44/0x80
[  192.744349]  ret_from_fork_asm+0x1b/0x30

[  192.744358] Freed by task 83:
[  192.744363]  kasan_save_stack+0x38/0x70
[  192.744372]  kasan_set_track+0x25/0x40
[  192.744382]  kasan_save_free_info+0x2b/0x60
[  192.744390]  ____kasan_slab_free+0x180/0x1f0
[  192.744411]  __kasan_slab_free+0x12/0x30
[  192.744418]  slab_free_freelist_hook+0xd2/0x1a0
[  192.744426]  __kmem_cache_free+0x1a2/0x2f0
[  192.744436]  kfree+0x78/0x120
[  192.744443]  smb2_lock+0x1488/0x2010 [ksmbd]
[  192.744526]  handle_ksmbd_work+0x2a7/0x800 [ksmbd]
[  192.744608]  process_one_work+0x4d3/0x840
[  192.744617]  worker_thread+0x91/0x6e0
[  192.744626]  kthread+0x188/0x1d0
[  192.744632]  ret_from_fork+0x44/0x80
[  192.744641]  ret_from_fork_asm+0x1b/0x30

[  192.744650] Last potentially related work creation:
[  192.744655]  kasan_save_stack+0x38/0x70
[  192.744664]  __kasan_record_aux_stack+0xb3/0xd0
[  192.744673]  kasan_record_aux_stack_noalloc+0xb/0x20
[  192.744682]  kvfree_call_rcu+0x2d/0x4e0
[  192.744690]  kernfs_unlink_open_file+0x18b/0x1a0
[  192.744699]  kernfs_fop_release+0x6d/0x180
[  192.744707]  __fput+0x1e1/0x480
[  192.744716]  ____fput+0xe/0x20
[  192.744725]  task_work_run+0x109/0x190
[  192.744733]  exit_to_user_mode_prepare+0x16b/0x190
[  192.744743]  syscall_exit_to_user_mode+0x29/0x60
[  192.744755]  do_syscall_64+0x67/0x90
[  192.744764]  entry_SYSCALL_64_after_hwframe+0x6e/0xd8

[  192.744780] Second to last potentially related work creation:
[  192.744784]  kasan_save_stack+0x38/0x70
[  192.744794]  __kasan_record_aux_stack+0xb3/0xd0
[  192.744802]  kasan_record_aux_stack_noalloc+0xb/0x20
[  192.744811]  kvfree_call_rcu+0x2d/0x4e0
[  192.744819]  kernfs_unlink_open_file+0x18b/0x1a0
[  192.744827]  kernfs_fop_release+0x6d/0x180
[  192.744834]  __fput+0x1e1/0x480
[  192.744842]  ____fput+0xe/0x20
[  192.744851]  task_work_run+0x109/0x190
[  192.744858]  exit_to_user_mode_prepare+0x16b/0x190
[  192.744867]  syscall_exit_to_user_mode+0x29/0x60
[  192.744877]  do_syscall_64+0x67/0x90
[  192.744885]  entry_SYSCALL_64_after_hwframe+0x6e/0xd8
```

### smb20\_oplock\_break\_ack 条件竞争 UAF

这个漏洞的模式稍微有点区别，smb20\_oplock\_break\_ack 会在在释放 fp 和 opinfo 的引用后继续使用 opinfo

```plaintext
static void smb20_oplock_break_ack(struct ksmbd_work *work)
{
    fp = ksmbd_lookup_fd_slow(work, volatile_id, persistent_id);
    opinfo = opinfo_get(fp);

    // 【0】use fp and opinfo with refcount

    opinfo_put(opinfo);
    ksmbd_fd_put(work, fp);

    // 【1】use opinfo after drop refcount
    opinfo->op_state = OPLOCK_STATE_NONE;
    wake_up_interruptible_all(&opinfo->oplock_q);

    rsp->StructureSize = cpu_to_le16(24);
    rsp->OplockLevel = rsp_oplevel;
    rsp->Reserved = 0;
    rsp->Reserved2 = 0;
    rsp->VolatileFid = volatile_id;
    rsp->PersistentFid = persistent_id;
    inc_rfc1001_len(work->response_buf, 24);
    return;
}

```

【0】 中的代码是正确的，使用对象时应该要在持有引用计数的情况下使用，避免被其他线程 RACE 释放，但是 【1】 处时 opinfo 的引用计数已经释放，其他线程可以并发释放 opinfo，这样后续对 opinfo 的操作就会导致 UAF.

opinfo 会在 fp 被释放时进行释放，关键调用栈如下：

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-972bd30687d699a0eb5c4e7cdc7ea16a8206b0ea.png)

### smb2\_tree\_disconnect 条件竞争 UAF

这个漏洞和 smb2\_close 条件竞争 UAF 很像，看看关键代码如下：

```c
int smb2_tree_disconnect(struct ksmbd_work *work)
{
    struct smb2_tree_disconnect_rsp *rsp;
    struct smb2_tree_disconnect_req *req;
    struct ksmbd_session *sess = work->sess;
    struct ksmbd_tree_connect *tcon = work->tcon;

    WORK_BUFFERS(work, req, rsp);

    rsp->StructureSize = cpu_to_le16(4);
    inc_rfc1001_len(work->response_buf, 4);

    if (!tcon || test_and_set_bit(TREE_CONN_EXPIRE, &tcon->status)) {
        rsp->hdr.Status = STATUS_NETWORK_NAME_DELETED;
        smb2_set_err_rsp(work);
        return 0;
    }

    ksmbd_close_tree_conn_fds(work);
    ksmbd_tree_conn_disconnect(sess, tcon);
    work->tcon = NULL;
    return 0;
}
```

和 smb2\_close 的区别是这里没有读写锁的保护，而是利用 test\_and\_set\_bit 原子操作来避免 tcon 被多次释放，但其实 UAF 的位置也就是 test\_and\_set\_bit

race 场景如下：

1. 两个线程 A B 同时执行到 test\_and\_set\_bit 前
2. 线程 A 先执行将 tcon-&gt;status 设置为 TREE\_CONN\_EXPIRE
3. 并通过 ksmbd\_tree\_conn\_disconnect 释放 work-&gt;tcon
4. 线程 B 执行 test\_and\_set\_bit 时， tcon 已经被释放，导致 UAF

通过这两个例子可以看出，一个正确的 free 逻辑需要考虑的情况比较复杂，漏洞挖掘人员也应该重点关注。

 ‍

### ksmbd\_session\_lookup\_all 条件竞争 UAF

ksmbd\_session\_lookup\_all --&gt; ksmbd\_session\_lookup 中会在无锁情况访问 sess ，在 \[0\] \[1\] 之间其他线程释放 sess 就会 UAF

```c
struct ksmbd_session *ksmbd_session_lookup(struct ksmbd_conn *conn,
                       unsigned long long id)
{
    struct ksmbd_session *sess;

    sess = xa_load(&conn->sessions, id);

    // [0] race window begin

    // [1] race window end
    if (sess)
        sess->last_active = jiffies;
    return sess;
}
```

总结
--

本文介绍以 ksmbd 为例介绍如何从0开始分析一个目标，并发现其中可能的条件竞争攻击面，最后结合多个实际的漏洞案例对漏洞挖掘、分析进行讲解。