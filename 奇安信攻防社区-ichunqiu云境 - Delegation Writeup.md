0x1 Info
--------

![Pasted image 20221208163617.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-4de78340c6173954d728c661bdc9418d9f626ce6.png)  
靶场地址：<https://yunjing.ichunqiu.com/ranking/summary?id=BzMFNFpvUDU> 从web到内网再到域的靶场环境都全，且出题的思路很好，感兴趣的可以去玩玩

0x2 Recon
---------

1. Target external IP  
    ` 39.98.34.149 `
2. Nmap results

![Pasted image 20221208164115.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-fedf4f32375ee94b7bdc6e6bd74627671999a708.png)

3. 关注80端口的http服务，目录爆破（省略）找到 /admin

![b481ac2a048677f4f6ad2074a1a3407 1.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-1622a33562b97f195e63a045527c3ead84b8d727.png)

4. 使用弱口令登录进入后台，去到模板页面，编辑header.html，添加php一句话  
    \\ ```php
    用户名: admin, 密码：123456
    ```
    
    \\

![f71dd2cf6322f6235561582fe3698a6.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-9c40414a239dab6c7206874c999037fafaba31de.png)

5. 命令执行

![82a94d5ec8b215f3a9f2723e3be15fd.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c35d087129624acc2add3f5c71268cf225d281b3.png)

0x03 入口点：172.22.4.36
--------------------

1. 弹shell

![d3574e2db871fd6076c065e4fb03a9e.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-e4a4988f17016ec68d9d0b4e531cb4eb433cf2a6.png)  
快速过一下：

- 入口机器没特别的东西
- 没能提权到root权限（也不需要提权到root权限）
- stapbpf suid利用失败  
    \\  
    找到diff suid

![Pasted image 20221208123303.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-96fd274da4f038bd542529d3f266f8d3cf1880c8.png)

2. flag01  
    `diff --line-format=%L /dev/null /home/flag/flag01.txt`

![Pasted image 20221208165708.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-b6b593d76c3acc9579adc58a68b109a76fec1464.png)

3. flag01 里面有提示用户名  
    `WIN19\Adrian`
4. 挂代理扫 445

![Pasted image 20221208165856.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-0440ab5eda652ec6e887a6b4212f0b979ba9910a.png)  
\\  
获取到三个机器信息

```php
172.22.4.19 fileserver.xiaorang.lab
172.22.4.7 DC01.xiaorang.lab
172.22.4.45 win19.xiaorang.lab
```

5. 用 Flag01提示的用户名 + rockyou.txt 爆破，爆破出有效凭据 (提示密码过期)  
    \\  
    `win19\Adrian babygirl1`
6. xfreerdp 远程登录上 win19 然后改密码

![Pasted image 20221208171122.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-294de21de3a7c3b87d489c632967e3b39c0938a6.png)

![Pasted image 20221208171214.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-7d5ac40cbe5594359b8108670f27014be4983292.png)

0x04 Pwing WIN19 - 172.22.4.45
------------------------------

前言：当前机器除了机器账户外，完全没域凭据，需要提权到system获取机器账户

1. 桌面有提示

![Pasted image 20221208171414.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8e813d1d221248d18d6f438909660d5abc653d9d.png)

2. 关注这一栏，当前用户Adrian对该注册表有完全控制权限

![Pasted image 20221208171546.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-2f838217a409f0c7efef83e9d18d2379144df918.png)

![Pasted image 20221208171610.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-1f07123286a5984a5d69e54b4fdab3d4501d7a57.png)

3. 提权  
    msfvenom生成服务马，执行 sam.bat

![Pasted image 20221208144611.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-6748dcf57f55b6770cba952af3cfb4095977780d.png)  
\\  
sam.bat

![Pasted image 20221208143321.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-12c1e6f0e597fad724641b59aade27f50d315248.png)  
\\  
修改注册表并且启用服务，然后桌面就会获取到 sam，security，system

![Pasted image 20221208144646.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-b42ba57c45d6290d5f6a1a41443dd515dfc3edf2.png)

4. 获取 Administrator + 机器账户 凭据
    
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:ba21c629d9fd56aff10c3e826323e6ab:::  
    $MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:917234367460f3f2817aa4439f97e636  
    \\

![Pasted image 20221208173220.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-53a28dfba9a6220437be59b0e2e4cb8dd3395248.png)

5. flag02

![Pasted image 20221208174927.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-082e5b3706529f7bda31d5532023341ffacb89a9.png)

6. 使用机器账户收集域信息

![Pasted image 20221208172122.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-a20c7254061ec184b23aa1cf72bea8d055091a84.png)

0x05 DC takeover - 172.22.4.7
-----------------------------

1. 分析 Bloodhound，发现 WIN19 + DC01都是非约束委派

![Pasted image 20221208172337.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-77e92edb6e9856a92c7f8a0a2b877813a8812147.png)

2. 使用Administrator登录进入 WIN19，部署rubeus

![Pasted image 20221208172853.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-2265acf445d615184d7704b1d6289ede93181419.png)

3. 使用DFSCoerce强制触发回连到win19并且获取到DC01的TGT

![Pasted image 20221208173259.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-a60a3a4f311d40dbfcfc21ace8470415ee8ec426.png)

![Pasted image 20221208173314.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-dd229cc79fafee8e0d849553f4c25b02753dec59.png)

4. Base64的tgt 解码存为 DC01.kirbi

![Pasted image 20221208173720.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f38d68e0c7069003e43072f11c87df744525f2ce.png)

5. DCSync 获取域管凭据

![Pasted image 20221208174536.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-48652ab687d88b0ec24384d805dd2516bdd24702.png)

6. psexec - flag04

![Pasted image 20221208174813.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8163b956845247cd79097b3f7c074d870a8874e3.png)

0x06 Fileserver takeover - 172.22.4.19
--------------------------------------

1. psexec - flag03

![Pasted image 20221208174831.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-2542e4a22866555081b40928d9be00bb403a9c09.png)

0x07 Outro
----------

- 感谢Alphabug师傅的提示（0x03 - 0x04），大哥已经把入口点都打完了，我只是跟着进来而已
- 感谢九世师傅的合作
- Spoofing已经打完了，walkthrough也写完了，等1000奖励到手后新年释出，个人感觉Spoofing更好玩，出题的思路很妙