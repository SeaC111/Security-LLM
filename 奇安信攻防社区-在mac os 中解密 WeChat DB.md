前提知识
====

先来了解一下有哪些DB 和 db对应的作用  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b84085c60faf7cf8033a71c058e165486a5af6bd.png)  
这里主要会使用到msg\_x.db, wccontact\_new2.db, group\_new.db

```go
    Msg_1|2|3|4.db …… 这些是把聊天信息分割后生成的文件
    wccontact_new2.db  微信上的联系人
    group_new.db 群聊信息，群聊昵称，微信id
    ftsmessage.db 这个数据库用密钥没有办法解开，有知道的小伙伴可以私信联系。
```

本次需要使用到的工具：lldb，DB Browser for SQLite, wechat

注意： 如果有小伙伴的mac book 一会儿运行了lldb之后出现error: attach failed: xxxxxxxxxxx 这个时候重启电脑 黑屏后 按住 command + R 进入恢复模式，然后输入账户密码，进入之后到上方点《实用工具》-〉点击〈终端〉之后输入 csrutil disable 然后 reboot 重启即可进行调试，csrutil 的开启是为了提供系统完整性保护 关闭了之后我们就能使用lldb 对wechat进行调试。

搞事部分
====

1. 运行微信的记得退出微信先。  
    我们首先打开微信，点开之后不要做任何操作  
    ![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f80b82e83352ed612e729b6c0c30c7c47e46a76c.png)

2.然后我们打开终端  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-88cf4eacff97452b4c54be88390daf87e6cfddae.png)

3.使用lldb工具对pid进行调试，使用pgrep 过滤出微信的pid  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-bf9584de031ca705a9143b4c9511c1b5f5f27770.png)

4.我们输入 breakpoint set –name sqlite3\_key | br set -n sqlite3\_key | br s -n sqlite3\_key  
br s -n 的意思就是在sqlite3\_key的地方下断点  
| 分割多种写法  
然后在continue 一下  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d765e1b40e81053edde925b16fe05fed218d5e63.png)

5.点击登陆，并在我们的手机上进行确认登陆  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-87b0cd5d670fb7280afc2610e725b92d70fddecf.png)

6.这个时候断点就生效了，程序会保持在刚才那个登陆确认的页面上，然后我们在lldb上就能够看到显示的汇编指令，可以看到最后一行是把rcx 寄存器中的值 赋值给了rsi  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-b4abb55b0a06090a8a0c5db2dc574ec6279d235d.png)

7.我们通过lldb 读取 rsi寄存器中的内容  
memory read –s 1 -f x -c 32 $rsi  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-309ac5b5fadb6bd4103debe9af5150f92bed900a.png)

8.我们把得到的结果复制到ultraedit(你们自己下一下)然后我们把前面的地址去掉，替换掉0x，还有空格，最后把四行变成一行  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c4085713864e550012b9aa6b0b0e22930484e1b1.png)  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9b3d7b508e193b6faaa89736b11dba3099c05aa3.png)  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-f515468368f8d634b01030c00cb848ca7b2dbd43.png)

9.最后变成一串长度为64的密钥，但是这样是没有办法解密的，因为我们一会儿要用row的方式解密，所以前面要加上0x  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-22e1db5e154b20822f22d63082203b74f63f724e.png)  
也就是变成这样  
`0xaac8b521a98740ecb***************************416b9fda1463abb023b3`

10.获取到密码之后然后我们把db Browser 安装好之后 打开  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-76d5aec5a38dd99da3a76f371cbf8ec07d306a63.png)

11.把db文件拖进db Browser我这里拖的是wccontact\_new2.db然后我们进行如下操作  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-adecbd5b2898c7c93fd34ec457ac588268f60927.png)

12.点击ok就能打开数据库了  
![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d5e8cd012942c6df26675e7434388fa55869b00a.png)

其余的数据库也是同样的操作，赶紧动手试试！！！