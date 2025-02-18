一、基本原理
------

#### 1.商品的一般购买流程：

选择商品和数量-选择支付方式及配送方式-生成订单编号-订单支付选择-完成支付  
（支付宝、微信、银行卡等等）

#### 2.常见的参数：

常见编号ID，购买价格，购买数量，支付方式，订单号，支付状态

#### 3.常见修改方法：

替换支付，重复支付，最小额支付，负数支付，优惠券支付等

二、检测与危害
-------

#### 演示案例（一）：

某商城系统商品支付购买数量、订单编号测试  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b9579200de949f2a6997f1233d743a263eeb3574.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-b9579200de949f2a6997f1233d743a263eeb3574.png)  
账号和密码登入成功之后生成一个产品  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-30a77700f2a6a612aa60d878664baf4b7d26e2e6.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-30a77700f2a6a612aa60d878664baf4b7d26e2e6.png)  
设置商品的交易配置与配送管理中的物流配送  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7201c8deb6ebdb3df0c004144d098b769925e918.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-7201c8deb6ebdb3df0c004144d098b769925e918.png)  
修改购买数量：点击商品出现立即购买和加入购物车，选择77件比较好辨认的数字  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d7c64b15ce0d5c72f61c2f1486fdd58e5312155b.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d7c64b15ce0d5c72f61c2f1486fdd58e5312155b.png)  
打开burpsite点击立即购买开始抓包，发现num=77猜测可能是购买的数量  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-dfa9e4be6a379829fccf7a6770c8df27ec5ac115.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-dfa9e4be6a379829fccf7a6770c8df27ec5ac115.png)  
再一次通过不同的数量（15）继续抓包证实num就是数量  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-df08880009adb47f65a87f83771335da308d9c95.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-df08880009adb47f65a87f83771335da308d9c95.png)  
尝试通过把num改成负数，成功可以0元支付  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0c56eb4ed16ba21b7ade146ba1919a3d42ae9780.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-0c56eb4ed16ba21b7ade146ba1919a3d42ae9780.png)  
修改订单的编号：点击商品立即购买之后，一直forward放掉，再点击提交订单，找到数据包里面含有订单编号  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6e3829f1d8df55262b6526b9cf6925fbcba1ce81.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-6e3829f1d8df55262b6526b9cf6925fbcba1ce81.png)  
将数据包发送到repeater进行保存一下，放出数据包，发下订单的编号  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-3ee1345ab6bf0fe94bbaf0767eb63b7a130327d2.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-3ee1345ab6bf0fe94bbaf0767eb63b7a130327d2.png)  
重新下一个订单  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f15a1a78439c1955d7eb2d1f27b1db2eda16a29a.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-f15a1a78439c1955d7eb2d1f27b1db2eda16a29a.png)  
用刚刚的订单编号替换新的订单编号并返回数据包，发现订单改变，相当于用一千的钱买了价值两千的商品  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-db8adec1cc7733d4838b74b10cc215e9919d4bc8.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-db8adec1cc7733d4838b74b10cc215e9919d4bc8.png)  
这个漏洞的产生的主要原因是由于没有验证订单编号的机制  
这里提一下修改支付接口：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-dbef86fbc40e311d5c555ddeb3c1917ff0f30156.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-dbef86fbc40e311d5c555ddeb3c1917ff0f30156.png)  
类似存在这种有多种支付方法的订单，可以将其支付接口为一个不存在的接口，如果没做好不存在接口相关处理，那么此时就会支付成功（这边的实验环境不能实现）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-252e37f250c5fe9a4fe6edbb583ed10bc16e1eff.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-252e37f250c5fe9a4fe6edbb583ed10bc16e1eff.png)

#### 演示案例二：

某系统商品订单数量、支付价格商品测试  
登入账号之后  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8e668fc5dc90a444e0c1f9526010ac506feadfd2.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-8e668fc5dc90a444e0c1f9526010ac506feadfd2.png)  
修改订单数量：回到首页随机点击一个产品  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-53cc1ab023c971ea233572543468069c46a8db7e.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-53cc1ab023c971ea233572543468069c46a8db7e.png)  
打开burpsite抓包，点击立即购买抓取数据包  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-891b59c9db925d1a03d5e5c75dba07966c5f5e8a.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-891b59c9db925d1a03d5e5c75dba07966c5f5e8a.png)  
分析数据包，发现“qty=1”猜测可能是数量故将qty的值改为2发送回去  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-acafda38eb5a456fc63d04c1fc4771e65b22e3f6.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-acafda38eb5a456fc63d04c1fc4771e65b22e3f6.png)  
发现成功修改商品的数量，猜测成功  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-84469df42875671eac8199eae9adcc98761decf5.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-84469df42875671eac8199eae9adcc98761decf5.png)  
修改订单价格：继续发现里面还有价格  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d45e1e2651a1b1bbbd369163348783a7425d1fb1.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-d45e1e2651a1b1bbbd369163348783a7425d1fb1.png)  
修改价格为1并返回数据包发现订单改变  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-73f245d06a80b0bb312028863067c9c330a65443.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-73f245d06a80b0bb312028863067c9c330a65443.png)  
选择大米手机cms和大米CMS手机开发专版两种不同的订单（价格不同一个为5400一个为6000），复制抓取出来的数据包进行比较，发现id和name不同已经pic（图片不同不用理会）  
[![](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1ff6b95c6d9260a62e0d13d4ec606a295d315ff8.png)](https://shs3.b.qianxin.com/attack_forum/2021/09/attach-1ff6b95c6d9260a62e0d13d4ec606a295d315ff8.png)  
尝试花5400买到大米CMS手机开发专版，抓包5000的大米手机cms立即购买的数据包，将id和name替换成6000的大米CMS手机开发专版发现花5400可以买的价值6000的大米CMS手机开发专版  
在实际应用中，有些数据是不能随便更改的所以大多只能通过数据包的对比明确的哪些数据是可以更改的那些数据是不能变化的支付漏洞还有很多，但是很多不好演示具体的内容可以参考：<https://www.secpulse.com/archives/67080.html>  
注：演示案例中使用软件的新版本大多已经修复

三、修复
----

1.进行交易时，做数据签名，对用户金额和订单签名。  
2.判断服务端的计算金额是否为正数。  
3.支付过程中加一个服务器生成的key，用户校验参数有没有被串改。  
4.金额，以及数量，单价，快递费等支付时需要输入的一些数值，尽量的进行安全过滤与判断  
5.提交订单时后台判断单价是否与数据库中相符  
6.服务端效验客户端提交的参数，严格控制用户从GET、POST、Cookies等的提交方式去篡改数值，再一个支付的加密算法，尽可能在程序代码里，服务器端里做过，而不是直接读客户端的值