php无文件攻击(三) - php-fpm文件描述符泄露
============================

本文思路来源于imbeee师傅的文章(膜膜膜) <https://www.anquanke.com/post/id/163197>

一、写在前面
------

Linux进程使用文件描述符（FD）来管理打开的文件。

**php-fpm运行的php脚本里，使用system()等函数执行外部程序时，由于php-fpm没有使用FD\_CLOEXEC处理FD，导致fork出来的子进程会继承php-fpm进程的所有FD。**

举个栗子：

这是当前php-fpm work的所有FD：

[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-e6940149303d96c7c4648e62a640346f84968bf8.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-e6940149303d96c7c4648e62a640346f84968bf8.png)

```php
<?php  system("sleep 60");>
```

php-fpm在执行该文件时，会fork sleep 子进程。 sleep子进程会继承了父进程php-fpm的FD，其中包括一个关键FD：php-fpm监听的9000端口的socket ，这里是5号FD。（原文中一直在声明是0号FD，可能该值并不固定）

sleep进程号为1771，可见sleep进程继承了5号FD：

[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-fdffff367f27e9419e2503859ed8bea178abdb73.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-fdffff367f27e9419e2503859ed8bea178abdb73.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-d692850384d4c08e31556e760e24100c721d235e.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-d692850384d4c08e31556e760e24100c721d235e.png)

在子进程里有了继承来的socket FD，就可以直接使用accept函数直接从该socket接受一个连接。

测试下：

index.php

```php
<?php
// t2.php
system("/tmp/test");
```

/tmp/test.c

```php
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char *argv[])
{
     int sockfd, newsockfd, clilen;
     struct sockaddr_in cli_addr;
     clilen = sizeof(cli_addr);
     //直接使用5 fd作为socket句柄，原文中是fd号为0
     sockfd = 5;

     //这里accept会阻塞，接受连接后才会执行system()
     newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
     system("/bin/touch /tmp/lol");
     return 0;
}
```

编译后，访问index.php。发现被阻塞了。此时访问fpm的任意文件，test进程接收到socket连接，执行system()。

[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-2b46fc4f4e9380f8c1212a9f1bb80c69aa308889.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-2b46fc4f4e9380f8c1212a9f1bb80c69aa308889.png)

**还有一点，test进程在/proc/下面的文件所属用户是www（php-fpm的运行用户）而不是root（php-fpm的master进程所属用户为root），也就是说子进程继承的worker的运行权限。**

[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-cf158341442a35dcc288474573d84b4b8f3b0118.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-cf158341442a35dcc288474573d84b4b8f3b0118.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-66a3d1acbb84e0b8fd9bda411b7f8f19387a63f0.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-66a3d1acbb84e0b8fd9bda411b7f8f19387a63f0.png)

二、利用方式
------

**我们的终极目标是，在php中建立一个socket，通过该socket 操作 php-fpm的socket。**

测试一下，在php中建立一个socket：

```php
<?php
// t3.php
sleep(10);
$socket = socket_create( AF_INET, SOCK_STREAM, SOL_TCP );
sleep(10);
```

原本的worker只有 0 1 2 5四个FD。

php脚本新建socket后，多了一个3号FD（其实测试socket阻断那里就已经发现是3号FD了），也就是说我们通过一个子进程将5号FD复制到3号FD，即可实现通过该socket接管php-fpm的socket。

[![](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-3cc527764488cfc10af76f984d758b1e217ded70.png)](https://shs3.b.qianxin.com/attack_forum/2021/04/attach-3cc527764488cfc10af76f984d758b1e217ded70.png)

完成代码可见原文，这里不再赘述。下面分析下具体思路：

1. php脚本运行后先删除自身
2. php脚本创建一个socket，并获取FD号。
3. php脚本调用system()建立一个子进程，该子进程会继承worker运行权限。
4. 子进程attach到父进程(php-fpm worker)，向父进程中注入复制FD的shellcode（shellcode作用为调用dup2命令，将php-fpm socket的FD号，复制到php创建的socket的FD号（在我的测试中就是5号复制到3号）。
5. 子进程恢复worker进程状态后detach，退出。

整个过程完成后，php代码中的socket即可操作php-fpm的socket。

如想完成webshell功能，可以解析请求fast-cgi请求，如果包含指令，拦截并执行。

否则正常转发到9000端口让正常的worker处理即可。

三、总结
----

该方法虽然实现了对php-fpm的无文件攻击，但是个人觉得局限性较高，利用场景可能比较局限：

- 环境的限制：只能在linux、php版本(5.x&lt;5.6.35，7.0.x&lt;7.0.29，7.1.x&lt;7.1.16，7.2.x&lt;7.2.4)下利用。
- 攻击php-fpm work本身的限制：生产环境中php-fpm的worker进程众多，fast-cgi请求能被污染后的worker accept 接受到的概率很低。
- php-fpm socket FD号并不固定，个人觉得加个遍历比较好。

除此之外，子进程向worker进程注入shellcode的操作应该有更优雅的姿势，希望师傅们可以关注下。

相关代码完善后会同步至github。