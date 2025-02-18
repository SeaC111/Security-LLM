本次是在某cms存在注入漏洞后，再尝试寻找其他注入时的尝试与思考，并成功发现存在大量的其他注入漏洞，希望能对大家带来启发。

前台SQL注入挖掘
---------

### get注入点

/g/sub.php中第16-17行：  
可以看到第17行，当cpid中的参数值存在`,`时，会对对变量$cpid直接引用；并且$cpid取值来源于cookie中可控的参数，存在sql注入的风险。

![image.png](https://shs3.b.qianxin.com/butian_public/f780991f0748ec0600dc8e1e79f768b500b87fd6b78b5.jpg)

查找showcookiezs()函数的调用位置，发现在label.php中第71行fixed()存在调用。  
![image.png](https://shs3.b.qianxin.com/butian_public/f299697497b1f1668537fedef40d4dcb57c2f3f5002a8.jpg)  
/inc/label.php中第71行：  
其触发条件为变量$channel值等于`cookiezs`。  
![image.png](https://shs3.b.qianxin.com/butian_public/f3435976fd8af3149bc2b0ea98966e43f18314e33e776.jpg)  
通过继续跟进fixed()函数的调用位置，找到showlabel()函数。分析该函数的代码逻辑，发现触发sql注入需要$channel值取`cookiezs`的条件是满足$str中存在`{#showcookiezs:}`（这里第11行代码中$value传递的值就是$channel值）。  
![image.png](https://shs3.b.qianxin.com/butian_public/f528043e1a5ff564851804ea09d4785f6c0dc40538a8f.jpg)  
但是这个$str是什么呢？任意找个调用该函数的页面进行下断点测试，发现$str的内容实际上就是未经过处理渲染的网页html模板代码。  
![image.png](https://shs3.b.qianxin.com/butian_public/f924390ced640cfd6b8dda2241811d8b1856260ee3da9.jpg)  
![image.png](https://shs3.b.qianxin.com/butian_public/f867845780ac3c787ad8bb745ef02ad9fa9166975b7bb.jpg)  
因此触发该注入漏洞需要满足两个条件：

- 代码中调用了showlabel()函数处理页面中的标签，触发注入漏洞；
- 代码中引用的htm页面模板中存在关键字`{#showcookiezs:}`

我们可以通过全局搜索关键字的方式快速找到相关的模板文件，并根据模板文件的引用位置，锁定可以触发注入的路径。  
![image.png](https://shs3.b.qianxin.com/butian_public/f787607ddd0ca7df6eda3e15aa693171e710abff95a9c.jpg)  
这里以找到的模板zhaoshang\_search.htm为例，在search.php文件中即引用了该模板又调用showlabel()函数，所以访问路径/g/search.php进行测试  
![image.png](https://shs3.b.qianxin.com/butian_public/f74136788c8c5aa8d3d07a26a79d1bc16e38ea1f1e7e2.jpg)  
![image.png](https://shs3.b.qianxin.com/butian_public/f801776225ba5791082499f3955ea78cf8eaafaf42244.jpg)  
使用带`,`的数据作为测试数据。  
![image.png](https://shs3.b.qianxin.com/butian_public/f123751e27f2775290f92ddb715b06bc3660408df4050.jpg)  
对注入点位置下断点，可以看到测试数据成功带入sql语句中。  
![image.png](https://shs3.b.qianxin.com/butian_public/f386764ec276a706af7815fd3ee73fdf713c70766058c.jpg)  
根据语句的拼接方式，构造延时注入语句，并成功执行。  
![image.png](https://shs3.b.qianxin.com/butian_public/f1052329f0af85375bf63e138e6fadaa6c67a052fa7d8.jpg)  
此外，受到该注入点的利用条件启发，想到了在审计时找到的一个差点因为无危害而被忽略的鸡肋问题。貌似还能继续发挥一下作用。

### get前台伪登录

这个差点因为无危害而被忽略的鸡肋问题是在尝试对系统登录部分的代码进行审计时发现的。在显示页面的top部分时，会从用户cookie中获得`UserName`的参数值；并且当同时存在`UserName`和`PassWord`时，会将cookie中的`UserName`参数值在页首展示出来。  
/inc/top.php  
![image.png](https://shs3.b.qianxin.com/butian_public/f307910d2b69aabfa109e2897b5aba29d891c61e0ab1f.jpg)  
具体的测试过程如下：  
![image.png](https://shs3.b.qianxin.com/butian_public/f87852885b8b176a74050d0296c7e1e70f6a18da73c8f.jpg)  
通过控制cookie中`UserName`和`PassWord`参数值，在页面上成功伪造出登录了的假象。当然实际测试中，因为session并未完成登录流程，所以实际并无任何用户的操作权限，更无法通过此漏洞越权到管理员。  
![image.png](https://shs3.b.qianxin.com/butian_public/f198764e2f1f001e09d60eaf8d787df87c7a026b555b6.jpg)  
非常的鸡肋，可以算一个无危害的问题，原本并没有计划浪费时间记录该问题。但正巧找到的注入点是根据页面模板内容作为触发点，因此感觉可以组合使用扩大危害。  
这里联想到通过cookie中的参数控制页首显示任意的用户名，尝试将PassWord为任意值，UserName为`{#showcookiezs:3,60,60}`，使页面模板内容中存在可以触发注入的内容。  
通过文件内容关键字搜索的方式，找个一个同时调用存在注入的showlabel()函数函数并包含了/inc/top.phpd的文件/g/class.php  
![image.png](https://shs3.b.qianxin.com/butian_public/f68319646c829872929c2391a3a02a32c220cbb6d67ac.jpg)  
使UserName参数值为`test123`进行测试，未能触发延时语句。  
![image.png](https://shs3.b.qianxin.com/butian_public/f908682ca6f910c936bf263abf2d36022cf489c490c44.jpg)![image.png](https://shs3.b.qianxin.com/butian_public/f474986e0615e200b3ecd5716d439359caceca2a6ee96.jpg)

使UserName参数值为`{#showcookiezs:3,60,60}`进行测试，成功触发延时语句。这了最明显就是断点位置的用户名经过showlabel()函数处理后，在返回的数据包中已然发生变化。  
![image.png](https://shs3.b.qianxin.com/butian_public/f5509714fb8ef57addb9c8890601c2a26c198574ddca7.jpg)  
![image.png](https://shs3.b.qianxin.com/butian_public/f412382cf2016dca72ad2f2aadec406fc22d3db290c0b.jpg)

### get多枚前台注入漏洞

为了找到所有的受影响文件，需要先明确这种利用方式的条件：

- 代码中调用了showlabel()函数处理页面中的标签，触发注入漏洞；
- 代码中包含了/inc/top.php文件，可以控制页面中的信息；

利用查找功能，还是能找到不少的满足上述条件的文件，但浏览了一下文件内容搜索到的结果，可能存在漏洞的利用点非常多，一个一个抓包测试很浪费时间。  
![image.png](https://shs3.b.qianxin.com/butian_public/f416528a5ae367c517cfb1f35b7ba6ee3d0f5d62f4739.jpg)  
这里就偷个小懒，利用命令在网站根目录下提取到php文件的路径，并制作成字典。

> dir /s /b &gt;filename.txt

![image.png](https://shs3.b.qianxin.com/butian_public/f33606357f372909c9ad9aa66369fa7cc87ef204a2188.jpg)  
添加好可以获得管理员用户名和密码的注入语句后，对路径进行暴破一下。  
![image.png](https://shs3.b.qianxin.com/butian_public/f511895ac42f3635ea7e45305a7b4513c1c6bae52be83.jpg)  
成功获得大量存在回显注入的漏洞路径。  
![image.png](https://shs3.b.qianxin.com/butian_public/f783199088c1193222d4ccd6772fe2057832ab7a0c232.jpg)

修复建议
----

建议优先处理注入点，在引用参数值$cpid前，对它使用有效的过滤或is\_numeric()函数检查。