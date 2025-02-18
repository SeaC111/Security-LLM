0x00 漏洞介绍
=========

双重抓取漏洞是一种特定类型的time-of-check to time-of-use (TOCTOU) bug，一般发生在共享内存接口中。当内核进程或其他特权进程(如设备驱动程序)多次访问一个不太受信任的变量，而在第二次访问时没有重新验证变量的任何检查时，就会发生这种情况。

这个术语最早是国外网络安全研究员在微软安全与防御博客MS08-061上的一篇文章中使用的。在2008年，这个bug类在那篇博客文章之前就已经为人所知。这个漏洞允许在当时的Windows版本中进行本地权限升级，原因是内核两次访问用户控制的内存池，而没有检查内存池大小的变化。这个漏洞不存在公开的漏洞利用方式，它可能在当时的研究员所掩盖，这是一个广为人知的带有系统特权的远程代码执行漏洞，两周后被披露。自从发现和描述了这个漏洞之后，在Linux内核、Windows内核以及各种设备驱动程序和虚拟化硬件中都发现了双重抓取漏洞的变形和二次应用。由于各种原因，双重抓取漏洞会导致安全方面的隐患。如果设备驱动程序、内核进程或其他高特权代码与用户控制的易受双重抓取漏洞影响的变量进行交互，则可能导致漏洞(如权限提升或缓冲区溢出)。这些漏洞十分不容易通过静态分析和代码审计识别出来。

双重抓取漏洞的实现或表现形式有很多方式，有的可能是无意间的代码逻辑缺陷，有的则可能是黑客的恶意应用。但它们都从共享变量或内存接口访问一个值，而这个值是由另一个进程访问的。第二次获变量值在没有再检查数据是否被其他程序更改的情况下可以修改其数据。也就是说，一个有较高权限的进程先访问了某一个变量，并且正在使用他，此时一个权限较低的进程在其之后访问了该变量，可以对这个变量进行修改。利用这个逻辑缺陷，我们可以修改那些被影响的敏感的变量，使自己的权限升级到较高权限，或者执行命令（RCE）。

还需要注意的是，尽管这些漏洞通常被称为“double fetch”，但是由其他类型的访问(比如共享变量或对象)导致发生这种漏洞，该情况也可能发生。

在保护不足的情况下访问共享内存可能会导致双重抓取漏洞。有时是由于无效程序员的假设，或在其他情况下。一个有高级权限的进程，比如内核，可能在没有进行适当检查的情况下使用由特权较低的用户控制的数据导致权限较低的用户所持有的权限被升级。

0x01 风险等级
=========

并不是所有的双重抓取漏洞都是可利用的。依据漏洞风险，我们参照互联网上的公开案例和博客，我们可以做出如下分类:

•无危害的双重抓取漏洞：一种无法被利用的情况。因为程序的保护机制，或者某些场景下，无法通过较低权限修改被共同使用的变量。

•有低级危害的双重抓取漏洞:一种可能导致内核、进程故障的情况，故障仅限于性能，不会造成危害较大的结果。不会非法提升权限，也不会远程执行命令等。

•有高级危害的双重抓取漏洞:一种可以被积极利用的情况，特权升级、任意读写、缓冲区溢出。

当在研究双重抓取漏洞的术语（装逼专用）时，主要从安全影响方面。虽然三个风险等级都属于双重抓取漏洞，但是我们要知道，只有可以利用的漏洞才有价值。但是无危害的双重抓取漏洞不代表对程序没有影响，可能会导致进程变慢、进程故障甚至是崩溃。双重抓取漏洞存在于底层代码中，比如内核和设备驱动程序，因为共享内存接口可以提供性能优于套接字等高级机制。设备驱动程序，就其本质而言，容易含有双重抓取漏洞是因为它们在与内存交互时使用了更高的权限，而内存可能会被修改。

0x02 漏洞触发原因
===========

双重抓取漏洞可能由烂烂的编程或意外的编译器优化引起。一个进程使用一个由低权限进程控制的变量，并在随后执行检查重用相同的变量而不执行进一步的检查。虽然在MS08-06之前就存在双重抓取漏洞，但通常使用更传统的方法来描述这术语，如缓冲区溢出。

```c

// Attacker controls lParam  
void win32k_entry_point(...) {

[...]

// lParam has already passed successfully the ProbeForRead

my_struct = (PMY_STRUCT)lParam;

if (my_struct ->lpData) {

cbCapture = sizeof(MY_STRUCT) + my\_struct->cbData;   // [1] first fetch

[...]

// my_struct ->lpData has already passed successfully the ProbeForRead

[...]

if ( my_allocation = UserAllocPoolWithQuota(cbCapture, TAG_SMS_CAPTURE)) != NULL) {  
RtlCopyMemory(my\_allocation, my_struct->lpData,

  my\_struct->cbData);    //[2] second fetch

}

}

[...]

}
```

Compiler-Introduced双重抓取漏洞

在这种情况下，这两次获取在源代码中是可见的，如果在被内核使用之前，审核人员将变量确定为源自用户空间，那么手动代码审查可以确定问题。在这个例子中，mystruct-&gt;cbData的第一次获取被用来确定my\_struct-&gt;lpData的大小，然后确定由my\_allocation引用的内存区域的大小，该区域将保存my\_struct-&gt;lpData的副本。第二次获取发生在RtlCopyMemory函数用于获取my\_struct的一个新副本，并将my\_struct-&gt;lpData的mystruct-&gt;cbData字节复制到my\_allocation中。如果攻击者在my\_struct引用的内存中插入了一个大于my\_struct原始值的有效负载，那么这个有效负载将溢出my\_allocation引用的内存。

通常，这些情况涉及两个或多个变量之间的不变量，其中一个或多个变量在不强制执行不变量的情况下被修改。一个可能影响安全性的特定情况的例子，比如前面描述的，是特权进程的代码读取用户控制的变量来确定内存分配的大小，随后执行变量的副本，而不重新检查大小是否仍然正确。检测和可能的修复将在本帖后面描述。下面的例子显示了来自CVE 2005-24906报告的Linux内核2.6.9的代码。虽然被描述为CVE中的缓冲区溢出，但它与MS08-061描述的漏洞相似，它检查了一次长度，但获取了两次，使用的是第一次获取的长度。在下面的代码中，传递给函数的用户控制参数在第一个while循环中被检查，在第二个while循环中被复制。数据长度的验证只发生在第一个循环中，而第二个循环复制数据时不验证长度。

0x03 实例
=======

双读取错误可能发生在编译器引入多个对变量的读取的情况下，尽管在源代码中只进行了一次读取。与前面讨论的MS08-061错误不同，这个bug源于被允许的编译器转换，导致对用户控制的内存进行第二次读取。因此，该漏洞在目标代码中可见，但在源代码中不可见。

请注意，这种类型在过去被称为“编译器诱发”。我们在这里使用“编译器引入”这个短语来强调这是一个有效的转换。这一区别将在第二篇更详细地讨论。以下代码改编自CVE-2015-8550 (XSA-155)，演示了由编译器引入。该代码很容易受到竞争条件的影响，在这种情况下，ps指针引用的整数可能被另一个线程修改，该线程在第一次和第二次读取变量之间进行修改。

```js

int cmsghdr\_from\_user\_compat\_to\_kern(struct msghdr \*kmsg, unsigned char \*stackbuf,  
int stackbuf\_size)

{

struct compat\_cmsghdr \_\_user \*ucmsg;  
struct cmsghdr \*kcmsg, \*kcmsg\_base;  
compat\_size\_t ucmlen;

\[...\]

kcmsg\_base = kcmsg = (struct cmsghdr \*)stackbuf;  
ucmsg = CMSG\_COMPAT\_FIRSTHDR(kmsg);

while(ucmsg != NULL) {

if(get\_user(ucmlen, &ucmsg->cmsg\_len))  
return -EFAULT;

if(CMSG\_COMPAT\_ALIGN(ucmlen) < CMSG\_COMPAT\_ALIGN(sizeof(struct compat\_cmsghdr)))  
return -EINVAL;

\[...\]

if((...)(((char \_\_user \*)ucmsg - (char \_\_user\*)... + ucmlen) > kmsg->msg\_controllen)  
return -EINVAL;

ucmsg = cmsg\_compat\_nxthdr(kmsg, ucmsg, ucmlen);

}

if(kcmlen == 0)  
return -EINVAL;

\[...\]

ucmsg = CMSG\_COMPAT\_FIRSTHDR(kmsg);

while(ucmsg != NULL) {

\_\_get\_user(ucmlen, &ucmsg->cmsg\_len);

tmp = ((ucmlen - CMSG\_COMPAT\_ALIGN(sizeof(\*ucmsg))) +  
CMSG\_ALIGN(sizeof(struct cmsghdr)));

kcmsg->cmsg\_len = tmp;

if(copy\_from\_user(CMSG\_DATA(kcmsg), CMSG\_COMPAT\_DATA(ucmsg),  
(ucmlen - CMSG\_COMPAT\_ALIGN(sizeof(\*ucmsg)))))

}
```

0x04 总结
=======

本篇文章主要讲述了双重抓取漏洞的基本原理里，该漏洞在国外已经被曝光很久，但在国内并没有太多人在研究。我希望通过写这篇文章，加强开发者对编程规范的重视。这个漏洞主要是因为程序逻辑自我矛盾，导致非法修改数据，进而提升权限或者执行命令。  
多个CVE与该漏洞有关，在此不再列举。  
下一篇文章，将会详细讲述双重抓取漏洞的技术问题以及如何预防。