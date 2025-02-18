Linux Rootkit查杀工具Chkrootkit分析
=============================

介绍
--

chkrootkit是一种用于在本地检查rootkit迹象的工具。文件最近一次更新 v 0.57 2023/01/13 。这个工具每个文件都可以单独运行，这里主要分析两个检查`LKM`特洛伊木马的文件，其他文件简单描述一下作用和用到的技术。[rootkit](http://www.chkrootkit.org/links/) . 其中包括：

- **chkrootkit**：检查系统的shell脚本 用于修改rootkit的二进制文件。
- **ifpromisc.c**：检查接口是否处于 混杂模式。
- **chklastlog.c**：检查上次日志删除。
- **chkwtmp.c**：检查wtmp删除。
- **check\_wtmpx.c**：检查wtmpx删除。 （仅限Solaris）
- **chkproc.c**：检查LKM特洛伊木马程序的迹象。
- **chkdirs.c**：检查LKM特洛伊木马程序的迹象。
- **strings.c**：快速和肮脏的字符串更换。
- **chkutmp.c**：检查utmp删除。

chkrootkit文件分析
--------------

此文件主要为base命令文件，把已知病毒的检测定义为一个函数。通过命令和系统文件、端口、进程等检查。

chkproc.c文件分析
-------------

这个文件主要通过多方面检测进程，从而定位异常进程。主要通过ps命令、`/proc/`目录下的进程文件、线程等来判断，具体如下：

#### 从ps命令查看进程：

先确定查看进程的ps命令，直接定义了一个命令列表，根据不同的系统选择不同的参数。

 static char \*ps\_cmds\[\] \\= {  
 "ps -edf",  
 "ps auxw",  
 "ps mauxw 2&gt;&amp;1 ",  
 "ps auxw -T|tr -s ' '|cut -d' ' -f2-",  
 };

执行命令列表中的其中一个命令

 ps = popen(pscmd, "r")

把执行结果，一行行读取，并把每一个进程的pid提取出来，如果pid有效，给这个pid好标记为1，存在的意思。

 while (readline(buf, MAX\_BUF, ps))  
 {  
 p \\= buf;  
 #if defined(\_\_sun)  
 while (isspace(\*p)) /\* Skip spaces \*/  
 p++;  
 #endif  
 while (!isspace(\*p)) /\* Skip User \*/  
 p++;  
 while (isspace(\*p)) /\* Skip spaces \*/  
 p++;  
 /\* printf("&gt;&gt;PS %s&lt;&lt;\\n", p); /\* -- DEBUG \*/  
 ret \\= atol(p);  
 if ( ret &lt; 0 || ret &gt; MAX\_PROCESSES )  
 {  
 fprintf (stderr, " OooPS, not expected %ld value\\n", ret);  
 exit (2);  
 }  
 psproc\[ret\] \\= 1;  
 }

#### 从`/proc/`目录查看进程

打开目录流，并读取目录。在 /proc 文件系统中，每个进程对应一个目录，目录名就是对应进程的 PID。

 DIR \*proc = opendir("/proc");  
 dir = readdir(proc));

一次读取一个目录或文件。由于Linux系统每个目录下都会有两个特殊的目录，当前目录（.）和父目录(..)，需要排除这两个目录。并且进程信息目录都是以进程ID命名，为纯数字。找到的进程放到`dirproc`集合中，标记为`1`，同样表示存在。

 while ((dir \\= readdir(proc)))  
 {  
 tmp\_d\_name \\= dir-&gt;d\_name;  
 if (!strcmp(tmp\_d\_name, ".") || !strcmp(tmp\_d\_name, ".."))  
 continue;  
 if(!isdigit(\*tmp\_d\_name))  
 continue;  
 /\* printf("%s\\n", tmp\_d\_name); /\* -- DEBUG \*/  
 dirproc\[atol(tmp\_d\_name)\] \\= 1;  
 }

#### 从线程查看进程

看线程之前，先看一个概念：

`NTPL（Native POSIX Thread Library）`是 Linux 系统下的一套实现 POSIX 线程标准的线程库。NTPL 提供了一组函数来管理线程，包括创建、销毁、同步、调度等操作。在 NTPL 线程模型中，每个线程都有一个唯一的线程 ID（TID）和一个线程控制块（Thread Control Block，TCB）。

目录下，都有一个名为 task 的子目录，其中包含了该进程的所有线程目录，每个线程目录的目录名就是该线程的 TID。为了将线程和进程区分开来，在新版 Linux 系统下，如果一个线程的 TID 是以一个点 "." 开头的数字，那么在 /proc 目录下会以这个数字命名一个文件，文件名为以一个点 "." 开头的数字，例如 ".12345"。

判断是否以`.`开头，如果是，那么就可能是一个单独的线程

 if (\*tmp\_d\_name \\== '.') {  
 tmp\_d\_name++;  
 maybeathread \\= 1;  
 }

同样，放入一个单独的集合，标记为`1`，表示存在。

 isathread\[atol(tmp\_d\_name)\] \\= 1;

#### 查找隐藏进程

从通过遍历的方式，打开`/proc`目录下的进程目录。如果能正常打开，说明这个进程存在。

 strcpy(buf, "/proc/");  
 snprintf(&amp;buf\[6\], 8, "%d", i);  
 if (!chdir(buf))

如果进程存在，如果`ps`和目录遍历`/proc`中有没有，线程集合也没有，这个进程可能被隐藏。

 if (!pdirproc\[i\] )  
 if (!psproc\[i\] )

如果都没有，进一步对进程目录下的`cwd`、`exe`、`file`等进程检查。分别获取并打印他们的符号链接目标文件路径。

其中，PID 的 cwd、exe、file 分别表示：

cwd：进程的当前工作目录（Current Working Directory） exe：进程可执行文件的路径（Executable） file：进程打开的文件描述符列表（File Descriptors）

 j \\= readlink ("./cwd", path, sizeof(path));  
 path\[(j &lt; sizeof(path)) ? j : sizeof(path) - 1\] \\= 0;  
 printf ("CWD %5d: %s\\n", i, path);

如果是FreeBSD 系统，在前边打开`/proc`目录下的进程目录没有成功情况下，还会通过`getpriority`进一步检测进程。`getpriority()`用于获取指定进程或进程组的优先级。获取失败，也会认为被隐藏了。

 errno \\= 0;  
 getpriority(PRIO\_PROCESS, i);  
 if (!errno)  
 {  
 retdir++;  
 if (verbose)  
 printf ("PID %5d(%s): not in getpriority readdir output\\n", i, buf);  
 }

最后，再检查一下`EnyeLKM` rootkit。LKM rootkit用于 2.6 内核的 Linux x86 的 LKM rootkit。它在 system\_call 和 sysenter\_entry 处理程序中插入盐，因此它不会修改 sys\_call\_table 或 IDT 内容。它隐藏文件、目录和进程。隐藏文件内部的块，提供远程 reverse\_shell 访问权限，本地 root 等。

 if (stat(ENYELKM, &amp;sb) &amp;&amp; kill (12345, 58) &gt;= 0)  
 {  
 printf("Enye LKM found\\n");  
 retdir+= errno;  
 }  
 ​

chkdirs.c文件分析
-------------

这个文件主要通过将父目录的链接数与找到的子目录数进行比较，从而发现隐藏文件目录。

先了解几个概念：

**硬链接**是在文件系统中创建指向同一文件的不同文件名的方式。在同一个文件系统中，多个文件名可以指向同一个文件的数据块，这些文件名就称为这个文件的硬链接。

#### 获取父目录连接数

通过`lstat()`获取当前目录的元数据（stat结构体），再通过元数据的`st_nlink`成员获取文件的硬链接数。获取目录的硬链接等于1，代表该目录除了其本身以外，没有任何其他目录或文件链接到它。

 if (lstat(".", &amp;statinfo)) {  
 fprintf(stderr, "lstat(%s): %s\\n", fullpath, strerror(errno));  
 goto abort;  
 }  
 linkcount \\= statinfo.st\_nlink;  
 if (linkcount \\== 1)  
 {  
 fprintf(stderr, "WARNIING: It seems you are using BTRFS, if this is true chkdirs can't help you to find hidden files/dirs\\n");  
 goto abort;  
 }

#### 获取子目录数

由于子目录的里边可能还有子目录，所以就需要一层层遍历获取所有子目录数量。先来看看获取一个目录的代码：

打开目录流，读取目录，获取文件目录的元数据，然后判断是否是目录。如果是目录，子目录计数加`1`。

 dirhandle \\= opendir(".");  
 finfo \\= readdir(dirhandle);  
 lstat(finfo-&gt;d\_name, &amp;statinfo);  
 S\_ISDIR(statinfo.st\_mode);

下边开始遍历，定义一个目录信息列表结构体，方便遍历。结构体包括：目录名、链接数、下一个结构体地址。

 struct dirinfolist {  
 char dil\_name\[NAME\_MAX+1\];  
 int dil\_lc;  
 struct dirinfolist \*dil\_next;  
 };

绑定结构体的上下关系

 dptr \\= dl;  
 if (!(dl \\= (struct dirinfolist \*)malloc(sizeof(struct dirinfolist)))) {  
 fprintf(stderr, "malloc() failed: %s\\n", strerror(errno));  
 norecurse \\= 1;  
 while (dptr) {  
 dl \\= dptr-&gt;dil\_next;  
 free((void \*)dptr);  
 dptr \\= dl;  
 }  
 continue;  
 }

把当前目录的相关信息指向结构体对象

 strncpy(dl-&gt;dil\_name, finfo-&gt;d\_name, sizeof(dl-&gt;dil\_name));  
 dl-&gt;dil\_lc = statinfo.st\_nlink;  
 dl-&gt;dil\_next = dptr;

开始遍历子目录

 while (dl) {  
 check\_dir(dl-&gt;dil\_name, fullpath, dl-&gt;dil\_lc, norecurse);  
 dptr \\= dl-&gt;dil\_next;  
 free((void \*)dl);  
 dl \\= dptr;  
 }

#### 对比

父目录链接数-子目录个数-2=差异

 diff \\= linkcount - numdirs - 2;

chklostlog.c文件分析
----------------

打开 lastlog 和 wtmp 文件并使用 while 循环读取 wtmp 文件。 对于 wtmp 文件中的每个条目，程序使用名为 read\_pwd 的函数在密码文件 (/etc/passwd) 中查找相应的用户，然后报告该用户的上次登录时间和会话信息。

chkwtmp.c文件分析
-------------

它读取类 Unix 系统上的 wtmp 或 utmp 文件并报告文件被截断的次数（时间戳为 0 的条目）。

wtmp 和 utmp 文件用于跟踪类 Unix 系统上的登录/注销事件和系统事件。 wtmp 包含所有用户登录和注销的日志，而 utmp 包含每个用户的当前登录状态。 当系统重新启动或文件轮换时，这些文件可能会被截断，这意味着某些条目可能会丢失。 该程序读取文件并报告文件被截断的次数和截断发生的时间。

chkutmp.c文件分析
-------------

它检索系统上当前活动的用户及其正在运行的进程。具体来说，程序首先通过执行 ps 命令获得进程信息。然后，它通过读取系统日志文件 utmp 来获得与 ps 命令中获得的进程相关联的终端信息。

程序使用两个结构体：struct ps\_line 用于存储来自 ps 命令的进程信息，而 struct utmp\_line 用于存储来自 utmp 文件的终端信息。

ifpromisc.c文件分析
---------------

用于确定是否有任何网络接口处于混杂模式。 它的工作原理是打开一个套接字，然后查询套接字以获取系统上所有网络接口的列表。 对于每个接口，它查询套接字以确定接口是否处于混杂模式。

该程序会扫描 /proc/net/packet 文件以确定是否有任何进程以混杂模式打开了原始套接字。 如果找到这样的套接字，程序将尝试确定哪个进程打开了套接字并报告进程名称。