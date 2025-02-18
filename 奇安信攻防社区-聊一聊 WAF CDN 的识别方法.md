在日常渗透中，经常会遇到目标网站存在 WAF 和 CDN 的情况，如果直接对其进行漏洞扫描的话，大概率发现不了安全问题，反而给目标留下很多漏洞测试的告警，即浪费时间又没有效果，在做漏洞扫描之前可以先进行 WAF 的识别，如果确认没有 WAF 的情况，在进行漏洞扫描，而存在 WAF 的目标，可以进行手工测试，尽量不要使用明显的攻击方式，找一些逻辑方面的问题，WAF 是无法进行识别的。

0x01 首先看看 CDN 是什么，如何识别？
=======================

> CDN 的全称是 Content Delivery Network，即内容分发网络。CDN 是构建在现有网络基础之上的智能虚拟网络，依靠部署在各地的边缘服务器，通过中心平台的负载均衡、内容分发、调度等功能模块，使用户就近获取所需内容，降低网络拥塞，提高用户访问响应速度和命中率。CDN 的关键技术主要有内容存储和分发技术。--**百度百科**

光看介绍不太明显，下图是 cloudflare 保护前后的架构：

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-8dd2e7751dbb17c2f61a52e28589cbcb3709c599.png)

再部署 CDN 之前，我们可以直接访问目标网站，没有任何阻碍，当然做任何事儿都是可以的，当目标部署了 CDN 之后，用户访问的所有流量都会经过 CDN 设备，然后 CDN 设备针对用户的访问，进行数据的返回，相当于有了一层反向代理，其实 WAF 的原理也是一样的，只不过核心功能不一样，CDN 的核心是针对网站进行加速，让全球用户访问该网站都是如丝般顺滑，而 WAF 的核心是让做坏事的人，无处遁形，及时制止。

如果要去识别 CDN 该怎么办呢？如果部署了 CDN，我们会在最开始访问时就接触到它，所以域名解析的 IP 地址就是 CDN 的 IP 而非目标的真实 IP，所以通过 IP 来判断是主要的方式，前提是你要有一份完整的 CDN 系统 IP 地址规则库，所幸有巨人整理好了，参考项目：

> <https://github.com/timwhitez/Frog-checkCDN>

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-cb1ed38618f8e24545c5aa295dcb73750954ebf8.png)

有了这个就可以很大概率上识别出网站是否存在 CDN 了，规则中还有一个关于 CNAME 的规则，这是什么原理？那得看看 CDN 是如何配置的，毕竟网站系统还是自己的不是 CDN 厂商的，所以不可能直接配置域名 DNS IP 到 CDN 处，需要一个中转，在不改变目标网站配置的情况下，让用户流量先过 CDN 然后再到目标网站，看一下腾讯云关于 CDN 的配置方式：

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-929aff67ea836a7bda547e5af99c41e1b962b6ab.png)

配置 CNAME 就能做到上面的需求，在不改变目标网站配置的情况下，直接通过修改域名的 CNAME 记录就可以达到部署 CDN 的效果，所以是可以通过获取域名 CNAME 记录，来判断网站是否使用了 CDN 的情况。以上就是 CDN 的识别方法。

0x02 其次，看看 WAF 是如何识别的？
======================

WAF 的配置跟 CDN 的配置差不多，如果类似 CDN 的配置，那么该 WAF 的部署方式属于串连部署，就是所有流量先经过 WAF 设备，然后再到后端服务器，这样对于攻击事件，可以做到实时拦截，有一个缺点就是，容易误伤用户，如果 WAF 设备出现故障，那么会影响一大片用户的访问，造成 p0 级故障，这是安全同事不想看到的。

那么还有啥方式呢？就是旁路部署的方式，原理就是将所有流量镜像到 WAF 设备，对于 WAF 设备来说，流量是实时的，但是对于目标系统来说只是将流量复制了一份而已，这种部署方式无法做到实时拦截，需要 WAF 审计出攻击事件之后，再给目标系统发送指令，来对攻击来源进行限制，比如封 IP，封账号之类的操作。如图：

![4.jpeg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-5396504c1c111f3b33e6c2752769cf0202431a78.jpeg)

那么如何识别呢？首先可以尝试识别 CDN 的那种方式，从 IP、CNAME 上去匹配相应规则，这种可以识别那些 WAF 串联在目标与用户之间的 WAF，而旁路 WAF 部署则需要进行 WAF 触发拦截之后，根据相应数据来进行规则判断，比如项目：

> <https://github.com/EnableSecurity/wafw00f>
> 
> <https://github.com/stamparm/identYwaf>

核心原理就是，有一个 WAF 指纹库，通过构造恶意 payload 来进行触发 WAF 拦截，然后再进行指纹比对，如果能比对上则说明存在 WAF，比如 sqlmap 检测 WAF 的 Payload：

```php
HEURISTIC_PAYLOAD = "1 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#"  # Reference: https://github.com/sqlmapproject/sqlmap/blob/master/lib/core/settings.py
```

当我们在一个没有 WAF 的网站做测试时，使用上面的 payload 是不会有任何变化的，如图：

> [https://edu.xazlsec.com/?1%20AND%201=1%20UNION%20ALL%20SELECT%201,NULL,%27%3Cscript%3Ealert(/%22XSS/%22)%3C/script%3E%27,table\_name%20FROM%20information\_schema.tables%20WHERE%202%3E1--/etc/passwd%27](https://edu.xazlsec.com/?1%20AND%201=1%20UNION%20ALL%20SELECT%201,NULL,%27%3Cscript%3Ealert(/%22XSS/%22)%3C/script%3E%27,table_name%20FROM%20information_schema.tables%20WHERE%202%3E1--/etc/passwd%27))#

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c92543383216f850afc327ac6c929bc5c3eddd1d.png)

当我们在一个有 WAF 的网站测试时，如图：

![6.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-8c26229af00cef351e69a00e0b40ff7bd56618e4.png)

出现了跟正常访问不一样的画面，这就证明该网站存在了 WAF，因为 WAF 厂商也要考虑用户体验问题，正常用户难免会触发 WAF 拦截，WAF 误伤问题很常见，所以拦截页面都还是比较友好的，而且很有辨识度，能够即使发现问题，经过投诉之后，及时解决，这对于识别 waf 来说也提供了便利。

0x03 总结
=======

以上就是关于 WAF 和 CDN 的识别方法，我基于上面的两个开源项目，将规则进行了整合，然后自己写了一个批量识别 waf 的脚本，加了多线程，效果还是不错的，有兴趣的可以加入星球获取脚本，你也可以自己去实现，不难。