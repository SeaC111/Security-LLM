ATutor是一个开源基于Web的学习管理系统(LCMS)，2.2.4是目前的最新版本，我汇总了所有CVE进行复现，进行黑白盒测试，对国外站点PHP代码审计的学习有所帮助。

1. [CVE-2019-11446](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11446)
----------------------------------------------------------------------------------

任意文件上传

利用条件

l 获得一个有教师权限的用户（即可以创建和管理课程）

l 版本为2.2.4

利用教师用户新建一个课程

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9b180fd74617a22a0ba27ce5a7a48e05703cb919.png)

进入课程，找到文件管理界面

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-f7b8b0d146c67e49354c6abf49bcff3be2207132.png)

这里是上传点，存在任意文件上传漏洞，原因是后端采用后缀名黑名单过滤，过滤不严谨，可以修改后缀名为phP，或者phtml进行绕过

通过burpsuite进行抓包，发现上传点为mods/\_core/file\_manager/upload.php

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-644b42efdfd217fe45c6694abe41bafbe0a46ab2.png)  
因此，我们对mods/\_core/file\_manager/upload.php进行审计

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-a83202c1ff3b379af4eaf1f08b61d1d4133a7501.png)

这是一个常规的文件上传代码，重点看处理过滤的部分，代码中对上传的文件有两处过滤

1\. 一个是对文件名进行str\_replace函数过滤，处理掉了文件名中的特殊字符，这个无所谓

2\. 另一个对文件后缀名的变量$ext，进行in\_array函数黑名单判断，检测是否包含非法的后缀名，其中，$IllegalExtentions变量是后缀的黑名单

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-60b7ddad0c4d67f17c0a8ca88553bf0a6cb176ef.png)

我们全局搜索下$IllegalExtentions变量具体的值

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-0735cd01c84bf33d209c280df00acda54bd01198.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-63906711ed0bd765047f2699e05e2ad1fc4d66db.png)

我写了一个demo，来测试in\_array是否大小写敏感

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-d62957855b2df9906bd609560e6ad7aabbd20fe2.png)

经过测试，该黑名单只对小写进行过滤，因此可以大小写转换phP，进行绕过，同时黑名单过滤不严谨，用php其他可以被解析的后缀也可以绕过，以下是PHP其他的后缀名：.php3 .php4 .php5 .php7 .php8 .pht .phar .phpt .pgif .phtml .phtm

将webshell上传成功后，怎么知道文件的位置在哪里呢？

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-e33a7f0203e31a5a69afaafb1152f9a6b6a77ad8.png)

通过审计，可以知道，文件被move\_uploaded\_file函数上传到了  
$path.$\_FILES\['uploadedfile'\]\['name'\]，其中“.”是PHP中的拼接符号，前面的$path变量是目录的值，后面的$\_FILES\['uploadedfile'\]\['name'\]其实就是文件名的值

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8be613fb4f612ce9726c6cb53f0c12ab3b52beff.png)

我们跟进下，$path的值具体是什么

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-0b4faed867069832dc149599f5edf8c918ef2f2b.png)

由此可知，$path的值是由AT\_CONTENT\_DIR和$\_SESSION\['course\_id'\]以及$\_POST\['pathext'\]这三个值拼接成的，我们一个个来找

看了下我们post的请求，pathext是为空的

AT\_CONTENT\_DIR中，目录位置为atutor/content，前面的是它的WEB目录绝对路径

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9ebd298dd545cd1db558c1661bf2cce4a3c00e14.png)

course\_id的值在自定义函数add\_update\_course中

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-3637cb3843fe22aebbd5da8f5c54583bd0a17dbf.png)

因为add\_update\_course函数最后会返回course\_id的值，所以我们只用全局搜索哪个页面调用了该函数就行了

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-3130a509d31d5a49dbea560d3e8b8851c56dfd6c.png)

mods\_core\\courses\\users\\create\_course.php页面调用了该函数，并将函数返回的值，赋给了$errors变量，因为course\_id是一个大于0的整数，所以$errors的if判断肯定是为true的，即$errors!=False，最后将$errors（也就是course\_id的值）通过header响应头的Location字段（即重定向的URL）输出，所以这里我们需要通过burpsuite抓包，将其放入repeater模块中，查看响应包的Location字段

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-09519372307eb58e886c9491b8c02cb0e41979b8.png)

回到开头，我们利用教师用户新建一个课程

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8ad0d429c91ea82eab0b156da950dc3ec0cdd82a.png)

通过burpsuite抓包，发现返回了course\_id

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9f5143918b4a8d12e10457bae359f6194a035ab4.png)

大功告成，文件上传位置变量$path的值是由AT\_CONTENT\_DIR和$\_SESSION\['course\_id'\]以及$\_POST\['pathext'\]这三个值拼接成的，因为AT\_CONTENT\_DIR为atutor/content，$\_SESSION\['course\_id'\]为2，$\_POST\['pathext'\]为空，所以上传位置在  
<http://xx.com/atutor/content/2/xx.php>

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-44bf694f0fdab7a5213d208443fb00c4289bda86.png)

2. [CVE-2019-12169](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12169)
----------------------------------------------------------------------------------

任意文件上传

利用条件

l 获得管理员权限用户

l 版本为2.2.4

漏洞的位置在mods/\_core/languages/language\_import.php，访问要先登录管理员权限用户，其他普通用户打不开

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-a14063569862060b402425f8f79a334169a287a0.png)

这里又是一个上传点，通过burpsuite进行抓包，发现上传点依然是language\_import.php

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-f04ed143ee1aaf781c444f6dad4df64b85f929dd.png)

我们对mods/\_core/languages/language\_import.php进行审计

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-51a10feae74b968fc89bf4166090f642c9a2f937.png)

我们上传的文件会传到$languageManager这个类的import函数里面  
因为language\_import.php包含了vitals.inc.php文件，所以$languageManager变量在vitals.inc.php里，可以看到变量$languageManager就是类LanguageManager

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-23473c7f9b8bd0594f3298f7e9e3b3dc4b5900f8.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-e1ba5d476d19e709b1341f4da8df80fb53791225.png)

我们再跟进LanguageManager类的import函数

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9367dc32f7723c6dd4f01130932c11c2cc542a8c.png)

重点看$archive = new PclZip($filename); 其中PclZip是一个对压缩包进行处理的类，$filename是我们在函数中传进来的参数，所以说我们上传的文件必须是一个压缩包

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-60a3811334259c10becc661896bf8228511776ca.png)

可以看到，后面$archive-&gt;extract( PCLZIP\_OPT\_PATH, $import\_path)，即我们上传的文件被解压到了$import\_path变量（应该是一个目录的地址）

我们上下文找下$import\_path变量的值，发现其值是AT\_CONTENT\_DIR .和'import/'拼接起来的, AT\_CONTENT\_DIR中，目录位置为atutor/content，前面的是它的WEB目录绝对路径，所以$import\_path的值应该为atutor/content/import，即上传文件的目录

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-35386d00bdcd10d937a2709ac9eb1affc870bdd4.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-d747984ff708adf0151846fe3158cd17ba02bbac.png)

我们将poc.php文件，进行zip压缩后，将压缩包上传

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-503f2731a3b7d9f0df4bc65a2b79b1577a551423.png)

访问上文中我们总结出来的上传目录atutor/content/import  
即http://xx.com/atutor/content/import/poc.php

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-3d551b2c5c90b117cdfdec1432bb81476787f3cb.png)

3. [CVE-2021-43498](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43498)
----------------------------------------------------------------------------------

访问控制缺陷（导致可修改任意用户密码）

利用条件

l 版本为2.2.4

存在漏洞的地方在password\_reminder.php，但是要携带特定的参数才能触发漏洞

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9b073d7dbb67d00fd2b68f689ccdeed6d91156dc.png)

我们先审计下password\_reminder.php，进入到密码找回的判断逻辑  
密码找回是会发送个链接到你用户绑定的邮箱的，我们触发漏洞的参数，就是去猜测找回密码的链接的参数的值，所以必须要代码审计

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-50bac7a0d6417a9e7baf8db8d2c7ed4000af15ad.png)

首先要设置参数id、g、h，才能进入if判断里面，其中参数id就是用户的id值，参数g是密码找回发送链接到你邮箱的时间，参数h是sha1(参数id+参数g+用户的密码md5)，计算出sha1后，再取其从第五个数开始的后十五位

上面看不懂也没关系，我们一步步来，变量$current = intval(((time()/60)/60)/24);我用本地PHP环境跑了一下，得到变量$current当前的值为19524

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-7a11c953901f3e8b67985e2f5740fd4e029cc4d3.png)

$expiry\_date = $\_REQUEST\['g'\] + AT\_PASSWORD\_REMINDER\_EXPIRY;  
其中AT\_PASSWORD\_REMINDER\_EXPIRY是常量，值为2，$expiry\_date=19524+2，就是19526  
参数g的值则为19524

if ($current &gt; $expiry\_date)，就会exit退出，所以$expiry\_date要大于$current

$row = queryDB($sql, array(TABLE\_PREFIX, $\_REQUEST\['id'\]), TRUE); 为了确保用户是存在的，我们将参数id暂时设为1

if ($\_REQUEST\['h'\] !== $hash\_bit)，就会报错，所以参数h的值必须要等于变量$hash\_bit，其中上文提到，参数h是sha1(参数id+参数g+用户的密码md5怎么办？

先看一下数据库中用户1的password字段为8635fc开头

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-c4392d07bb2a6dad17b8b68de3c8f35feab75c9e.png)

还是老样子，我们在本地环境跑一下，看看参数id+参数g+用户的密码md5算出来是多少

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-9c0755ea79e2c41dbcdf5c440ad2883de965c381.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-76f5b24341eaab265e581830962366bd2181d8fc.png)  
最终算出来为28160，为什么？因为在PHP中，整数和字符串进行运算，字符串若前面为字母，则取值为0，若字符串前面为数字，以这里密码md5的8635fc为例，则取字母前面的数字为值，所以说1（参数id的值）+19524（参数g的值）+8635（用户密码md5）=28160

但是我们也说了，参数h是sha1(参数id+参数g+用户的密码md5)，计算出sha1后，再取其从第五个数开始的后十五位，所以得用脚本生成一个经过sha1和substr函数运算后的字典，再用burpsuite的intruder模块进行爆破（因为我们无法知道用户密码md5开头的值）

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-e50728469f67989e61ed2365eec3c17a7ae6ebae.png)

我这里是用PHP生成了一个字典，保存为h.txt

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-c4dcc54ad3c9399c36d6985b811c2ee7b57b1296.png)

上面的字典，是爆破我们参数h的值

但是我们依然没有重置用户密码，还需要参数form\_password\_hidden和 form\_change，所以还没有代码审计完

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-43b0152fc552a45187a25cdd63d49d596bffc162.png)

我们需要设置一个参数form\_change，进入if判断，值为空就可以  
我们的目的是进入if (!$msg-&gt;containsErrors())，里面可以执行update用户密码的SQL语句  
关于!$msg-&gt;containsErrors()，要求前面参数id,g,h的值设置正确，就不会报错，ok，如果以上都理解了，我们就可以执行攻击了  
参数form\_password\_hidden是重新设置的新密码，一般是md5，但是为了方便大家看懂，我这里的值直接设置为yyds，以显示我们攻击成功了，我们直接通过burpsuite的intrude模块进行爆破

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-31749ccf14529e1f8835294b45c65378afe5cca8.png)

我这里是成功了的，注意发包的时候，同个payload有时返回200有时候302，所以最好多尝试几次，响应的字段长度基本差不了多少，所以不是基于响应长度判断是否成功，我这里通过爆破成功修改了用户密码

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-bb1339deb62a9be9660e37e7549b73480afc1aec.png)

4. [CVE-2020-23341](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-23341)
----------------------------------------------------------------------------------

反射型XSS

利用条件

l 版本为2.2.4

漏洞存在的位置在themes\\default\\include\\header.tmpl.php

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-3f0eb3af2a585dcb11aa43fc11009a02bbdb7514.png)

注意前面的if判断，页面中必须要定义了AT\_INCLUDE\_PATH常量，否则就exit退出，但是这个header.tmpl.php是不包含此常量的，也就是说它需要被其他文件包含（通过.tmpl.php的命名我们就可以知道这是一个模板文件）

我们来全局搜索下，哪些文件是包含了header.tmpl.php的，发现header.inc.php文件是包含的，但是header.inc.php又没有定义AT\_INCLUDE\_PATH常量，所以我们需要套娃，找到包含header.inc.php的文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-8e778481d56089b9b19e8077ac1f11309dae3632.png)

继续搜索，哪些文件是包含了header.inc.php的，发现about.php包含，而且定义了AT\_INCLUDE\_PATH常量，所以我们从about.php页面入手

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-be385dbd0e7ea17c7c43042b3099fcf80fb500e4.png)

Ok，找到要执行攻击的页面了，但是漏洞在哪里呢？  
我们前文说过漏洞存在的位置在themes\\default\\include\\header.tmpl.php  
所以继续往下进行代码审计，一般反射型XSS肯定都是靠参数传递的啦，我们直接在该页面搜”$\_”关键字，找到$\_GET\[‘fb’\];

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-ade9c935e2fa353b8b8cdf4b25a00209840847ef.png)

发现printNoLookupFeedback函数会将我们传的参数显示出来，这里有戏，但是我们要跟进函数，看看会不会过滤尖括号

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-d581b46c0bf296a4265e58e0c17c30ea06fa6f84.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-54c280c2dc862d138a6f17357219ae7224bbe0f5.png)

这里又套娃了，刚刚的$msg-&gt;xx()是类中的一个函数，这里的$this-&gt;savant-&gt;xx()也是类中的函数，继续跟进吧

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-be72f690a259a1088c0e7ed1b6812d7fc00f7dba.png)  
通过全局搜索可以知道，函数属于Savant2这个类，它是先把类Savant2的实例化（new Savant2 ()）赋值给变量$ Savant，再将变量传参给类Message的实例化，即new Message($ Savant)，类Message再通过构造函数，将传进来的值，赋给$this-&gt; savant

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-3496f4a90f97bc1865d000a8d495059093f7bd37.png)

看完了，这个传参点是没有过滤的，我们直接通过about.php页面执行XSS payload吧

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-bbd21e8f94a498d2c6861f98748e0f99b14cec60.png)

5. [CVE-2019-7172](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7172)
--------------------------------------------------------------------------------

储存型XSS

利用条件

l 获得管理员权限的用户

l 版本为2.2.4

先登录管理员用户，再打开mods/\_core/users/admins/my\_edit.php页面，在real\_name位置提交XSS payload

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-6360e1717087caf31c2e45ddbbf93c54cd0a562f.png)

保存后，打开mods/\_core/users/admins/index.php页面，发现执行成功

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-94ecc40f4540bda0ebd3ab2ad0467c684cac905b.png)

漏洞出在mods/\_core/users/admins/my\_edit.php，我们对其进行审计

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-b5eaceb787372ef819a4ca3907d84f54659acc33.png)

$msg-&gt;containsErrors()默认是false，所以负负得正，为true，进入if里面  
其中，$addslashes会对我们提交的real\_name值进行过滤，我们先看看$addslashes被赋了哪个过滤函数

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-3ef0b47c2c2d4c8720ac1554bb3d8d8ff10d4554.png)

$addslashes其实就是mysql\_real\_escape\_string函数

![image.png](https://shs3.b.qianxin.com/attack_forum/2023/06/attach-7f3b707a70440ccc3fdfff805bb9b777b9ffa86f.png)

过滤的无非是斜杠、单引号、双引号、回车这些，和尖括号无关，所以对XSS攻击是没有过滤的，除非你是通过标签的属性，即闭合双引号来XSS

6. [CVE-2019-16114](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16114)
----------------------------------------------------------------------------------

变量覆盖

我的理解是，因为在安装WEB的时候，跳过了步骤5，即数据库配置这一块，导致安装的页面依然可以访问，二次安装，篡改数据库的配置，不过这个确实没想到，算是拓展下思路