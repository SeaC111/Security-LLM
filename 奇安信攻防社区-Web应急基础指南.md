1 总述
====

web应急实际上是基于webshell和各类web漏洞如sql注入、RCE的应急响应。从抽象定义角度来说它独立于OS也就是windows或linux之外，但在实际操作中又常常与操作系统无法分开。

本篇中只涉及web部分，对于攻击队后续的维权手段（如CS马）等不做涉猎。

本文中不会出现安全设备日志分析相关知识（因为1厂商设备太多2笔者工作中接触不到多少安全设备3很多情况下客户那里是没有设备的），我们将从最原始的web日志，根据下面的应急响应四步骤开始分析。

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723001427695-711e9d52-995c-43e2-9c25-2435957481a8.png)

2 信息搜集
======

基于web应急的信息搜集，如果抛开安全设备不谈肯定就是web日志了。通常用户的请求从客户端发出经过一系列设备最终到达web应用本身，这些设备中能够留下日志的有：web服务器（如apache、nginx）和应用服务器（如jboss、tomcat、uWSGI、IIS）。少数web应用自身也会留下记录，如thinkphp的日志或其他自定义的日志功能。

下图是一个经过抽象简化后的请求路径图，其中反向代理和应用服务器不一定存在。

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723019415287-260a8052-15bf-4962-9a52-be25721029fb.png)

那么按照我们上文所述，则第一目标是：确定web服务器、应用服务器和web应用是否存在及其位置，然后找到它们的日志。

2.1 确定网站使用服务器类型
---------------

最好的状况是开发坐在你对面，有什么对面会直接说。而如果没有这么便利的条件，服务器上运行了啥就得你自己来找。

### 2.1.1 访问网站

我们可以先对网站进行一个基础的浏览，以确定它使用的服务器/应用语言。比如：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723023325419-09e1aac8-89f7-44b0-b0d4-bf1eafd9e64a.png)

这个请求就能看出使用了.NET。

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723023361264-38e543b7-c61a-4c92-8628-8f9a11f1ba03.png)

而这个响应说明服务器是Nginx。

### 2.1.2 查看进程

在windows中我们可以使用tasklist+findstr来查找常用服务器进程。

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723023029479-39c63c73-026c-444e-861f-e90d0525f9a3.png)

在linux中我们通常使用ps -aux+grep。

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723024556733-742aa3d4-7ad9-4bfa-bd78-5fd75603a625.png)

- apache
- httpd
- apache2
- nginx
- nginx
- tomcat
- java/javaw
- IIS
- inetinfo

2.2 常见日志位置
----------

以下是windows和linux中一些服务器常见路径/配置文件路径（配置文件里会有日志路径）/日志文件路径。

### 2.2.1 Linux下

- Apache
- /usr/local/apache/logs/
- /var/log/apache2/
- httpd.conf
- access.log
- error.log
- Nginx
- /etc/nginx/logs/
- /var/log/nginx/
- nginx.conf
- access.log
- error.log
- Tomcat
- $CATALINA\_HOME
- catalina.out
- localhost.yyyy-mm-dd.log

### 2.2.2 Windows下

- IIS
- %SystemRoot%\\System32\\LogFiles\\
- Apache
- 安装路径非固定
- httpd.conf
- access.log
- error.log
- Nginx
- 安装路径非固定
- nginx.conf
- access.log
- error.log
- Tomcat
- %CATALINA\_HOME%
- catalina.out
- localhost.yyyy-mm-dd.log

在更多情况下，我们会直接对日志文件位置进行搜索。linux使用find命令，windows可以使用everything进行搜索。

2.3 Web应用中的日志
-------------

对于web应用本身，如果其使用了框架或自带日志功能，也会有日志文件。这种日志的路径不定，需要通过搜索web所属框架来寻找，或者通过查看应用的数据库来查询。

有些框架自带log功能，如大名鼎鼎的thinkphp，大多数小CMS也会自带一个简单的日志系统，一般存放在数据库中。有些系统后台也会自带登陆审核日志审计等功能。

所以我们查找web应用日志的最好方式是：

1. 在根目录下搜索log文件
2. 登陆网站数据库，查询是否有log表

这是大米CMS的日志位置，作为基于thinkphp的CMS它也保留了日志功能：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723086977987-3dae4a8c-32bf-4734-a765-4985ddd2e2ba.png)

这是yzmCMS的日志位置，php的CMS一般都会有一张admin\_log表。

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723087080068-362af8b1-8217-4c3e-971f-6ceeaa91cfc5.png)

2.4 Docker中的日志
--------------

Docker的web日志通过登陆Docker查看。

docker ps -a 列出所有容器

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1685497939519-541b8030-0fce-4345-b139-9da67456c5b7.png)

docker exec -it &lt;id&gt; /bin/bash 为此容器起一个shell

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1685498149044-a31006b0-663e-44d5-b850-ccb02710597d.png)

docker cp &lt;id&gt;:/etc/passwd /tmp/ 拷贝容器文件到本地

![](https://cdn.nlark.com/yuque/0/2023/png/32358243/1685498601927-065b8da5-6b31-4fe7-bb3f-d483989bc1dd.png)

3 分析研判
======

先问问各位读者：在获取到足够的日志后，我们如何展开分析？日志中能获取到的信息有哪些？

在能够获取到事件发生时间（通过询问客户）时，我们可以从事件发生前后开始寻找。如果不知道具体的事件发生时间，则需要将日志导入分析工具。

3.1 常见日志格式
----------

1. 确定事件发生的时间
2. 通过工具或手动分析，找到存在异常的请求包和可能的后门
3. 结合源代码对上述异常进行分析

由于web日志的生成方式比较多样，这里主要介绍一下针对大多数服务器日志的研判方法，我们以apache日志为例。

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723098928786-b70c0136-08bc-409c-8e75-957e9895b80d.png)

可以看到，这些Apache日志的格式为：

访问IP - - \[访问时间（服务器时间）\] "请求方式 请求路由 HTTP协议版本" 响应码 -

而error.log这类的报错日志格式会有些许变化，但它需要具体情况具体分析。

3.2 使用工具对日志进行分析
---------------

如果在windows下分析，那么日志分析工具最为方便：因为它能够图形化展示日志详情。

这里使用360星图对日志进行审计。

打开星图的根目录/conf/config.ini，替换其中日志文件路径为我们需要分析的路径：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723105254606-c9694e11-4ba2-45d7-987f-aae06b7c1c28.png)

启动星图，待完毕后即可从result文件夹中获取报告：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723104944687-95ef4f3a-5d91-4cde-87f0-3919e74b0cdc.png)

同时还能获取到可疑攻击的统计，如下：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723105949362-48799286-b5bf-4da0-b608-717aefa14bce.png)

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723105986278-c576f001-7dc5-44ab-a689-5325ebaddcff.png)

3.3 使用命令对日志进行简单统计
-----------------

这是linux下常用的日志统计方式。一般我们会使用wc命令以统计行数，awk、cut命令进行文本处理，sort进行排序，使用uniq、cat、tail等命令读取文件，然后将它们组合进行审计。

以下是一些常用的审计命令组合，我会依次解释它们的作用：

1. `cut -d - -f 1 [file] | sort | uniq -c | sort -rn | head 20` 统计访问次数最多的IP

cut -d - -f 1使用-分割字符串，然后选取第一个分段

uniq -c 取唯一值，然后统计这些唯一值出现的次数

sort -rn 排序，按照数值逆向排序（-r为逆向reverse -n为数字number）

head 20 取头部20个

2. `awk '{print $1}' [file] | sort | uniq | wc -l`统计访问IP数量

awk '{print $1}' 取第一个子串（IP）

sort 排序

uniq 取唯一值

wc -l 统计行数

3. `grep "/index.php" [file] | wc -l` 统计页面index.php被访问次数
4. `awk '{++S[$1]} END {for (a in S) print a,S[a]}' [file]` 对于每一个IP，打印出它们访问的页面数量

有点抽象，可以理解为先用S存储每个$1出现的次数，然后对于每一个S中的值，打印出值和出现的次数

5. `grep ^[ip] [file] | awk '{print $1,$7}'` 查找IP访问的页面

这个就简单了，查找IP出现的行数然后使用AWK过滤出IP，页面。

6. `awk '{print $4,$1}' [file] | grep [time_11/Jun/2020:14] | awk '{print $2}' |sort |uniq |wc- l` 判断对于某时间（可精确到小时），有多少IP访问了页面

3.4 黑页与黑链的研判
------------

黑页一般指的是入侵者对网站首页的改写。研判黑页与黑链，最先要解决的问题是：确定入侵者如何改写网站首页。

而入侵者使用的手段也是五花八门：如仅改写TITLE；如判断用户UA，在PC端不改写首页；如判断用户IP，在境外则展示被改写首页；如使用js脚本定时跳转首页，如仅改写META。

还有一些黑链通过修改服务器的拦截规则进行劫持，如匹配特定url转发到黑页：

```php
location /abc/ {
    proxy_pass http://www.baidu.com:80/;
}
```

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1724656747868-b836ad76-4cf9-4950-85e1-14d5a5f2a3d0.png)

一个简单的黑页判断通常仅会通过访问网站首页并抓包完成。在完成访问首页操作并确认黑页已跳转之后返回查看过程包，特别注意访问中加载的可疑外部js和跳转顺序等。

### 3.4.1 例1 META篡改

下图中的暗链仅篡改了META数据并实体编码篡改内容，使研判者难以使用肉眼判断网站是否被篡改：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723709095988-74b0b441-81fe-402b-a5b4-b18321498e73.png)

将其解码可发现网站META数据已被篡改为黑产导航：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723709309027-7a89ca1c-2fae-4520-86e7-9c8c7133962d.png)

3.5 特殊情况
--------

### 3.5.1 反向代理

有些情况下，服务器内部会做反向代理，也就是客户的访问会经过一个或多个反向代理服务器然后被转发到真正的服务器上。此时，对于真正的服务器而言访问它的是上一个反向代理服务器，则日志中记录的IP也会是上一个反向代理服务器的IP（也就是说，都是同一个IP）。

在此情形下，如果服务器开启了combined日志，我们可以通过筛选User-Agent头来简单区分访问者的身份。User-Agent头是由浏览器生成的标识，里面包含了浏览器版本、操作系统版本等信息：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723710950319-beea2072-7be4-4e51-9c27-1a274a3d5dde.png)

4 排查修复
======

排查修复这个名词由两个短语组成，排查与修复。

排查指的自然是排查攻击者留下的后门和系统本身存在的隐患——特别是导致此次应急事件中攻击者攻击成功的隐患；而修复则是指恢复遭到破坏网站的正常服务，并修补漏洞。

4.1 排查
------

对于web应急而言排查主要针对于webshell。

### 4.1.1 如何判断后门？

我们一般从创建时间、文件内容、访问日志三个方面来判断一个文件是否是后门。通俗来说，也就是：

创建时间：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723175408045-1c2e7995-5aa0-42dd-98af-763f7518d32d.png)

linux下使用这条命令来查找带时间的文件：

```php
find / -name *.php -newermt "2023-03-01" -printf '%T+ %p\n' | sort -r
```

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723184332343-cd508750-8eef-4179-87a5-facc13fd3205.png)

文件内容：

主要是通过D盾等工具进行查杀。

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723175427792-192d3145-7425-41ff-b3a0-94937add116f.png)

找到疑似后门，可以通过访问日志来反推攻击时间：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723175438963-8dd65e15-2db8-445f-8124-14e0e8940e32.png)

### 4.1.2 内存马排查

我们以php和Java为例。内存马总而言之指的是“仅存在于内存中的木马”，换而言之它是不落地的（php属于部分落地，后门在地上定时复活后门的马在内存里），所以我们无法通过普通的方式找到并删除内存马。

排查php内存马，需要通过被反复落地的文件反推内存马逻辑；排查Java内存马则部分可以通过读取注册组件名和字节码。

4.2 修复
------

在删除webshell之后我们需要对漏洞进行修补。在不熟悉业务和漏洞无修补包的情况下，当确认了入侵者使用的漏洞后，我们还要尝试为漏洞寻求一个修补方案。这通常通过代码审计做到。

这要求最基本的代码功底，但知道POC路径的情况下进行审计比一般审计会快也容易许多。

修复漏洞的方式根据具体漏洞类型的变化而变化。

4.3 PHP内存马的排查与修复
----------------

鉴于php的语言特性，基于php的内存马通常会是一个死循环php文件，在攻击者访问此死循环文件后它将在指定目录下一直生成webshell文件。

一个基础的php内存马如图所示：

```php
<?php
  set_time_limit(0); #取消超时
  ignore_user_abort(1); #忽略用户操作
  unlink(__FILE__); #删除自身
  $c = ''; #这是webshell的内容
  while (true) {
    if(!file_exists("back.php")){
        file_put_contents("back.php", $c); 
        #死循环，判断文件webshell是否存在，不存在则生成
    }
    usleep(1000000); #等待一秒
  }
?>
```

访问木马，源文件将被删除，同时webshell文件将一直存在（如果被删除则内存马会再次生成此文件）。也就是“删不掉的webshell”。

排查php内存马的步骤与常规排查步骤相同，但它的修复方式则不同。

由于原内存马文件已删除，我们无法获取到内存马源代码，只能尝试推断它的行为并进行处置，如：

1. 使用空白文件对原生成文件进行占位
2. 定时扫描生成文件并删除
3. **重启服务（理论上非必要不操作，虽然每每山穷水尽至此）**

4.4 Java内存马的排查与修复
-----------------

与php不同，java内存马可做到无文件落地。**我们虽然能够通过日志找到可疑的木马路径，却无法通过删除文件的方式对内存马进行修复。**

### 4.4.1 agent内存马排查与修复

实际上，对于agent内存马的修复就像绕过杀软给WinAPI挂的钩子一样，如果非要选我选择重启。

### 4.4.2 组件内存马排查与修复

组件（servlet、filter、listener）内存马的原理就是在java运行时动态注册新的组件。由于会产生新类，它的排查更为容易些。

我们可以使用arthas对java中的类进行枚举，然后寻找可疑类反编译进行排查。

在排查到可疑类后，可以使用agent工具对排查到的可疑组件进行卸载。

4.5 例2：Filter内存马简单排查
--------------------

jps.exe是java自带的一个工具，一般在jdk目录下。先使用jps.exe列出所有Java进程的PID：

`.\\jps.exe`

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723794190580-795950ed-78d7-4b10-aebd-92ec4ea79c98.png)

然后使用arthas连接到被检测对象所属的java进程：

`java.exe -jar .\\arthas-boot.jar \[pid\]`

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723794320582-afaa0307-8667-4629-96f1-bbf1a8d42f66.png)

使用sc命令查询当前所有Filter：

`sc \*.Filter`

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723794494684-f8c25dcb-c33e-4254-81a0-b346e3ce5cf7.png)

前面三个是arthas自己的，第四个和第六个是自带的，第五个类可疑。

使用jad反编译可疑类对应的源代码：

` jad --source-only org.apache.coyote.ser.std.ByteBufferSerializer`

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723794558412-b1260ebc-9da0-4436-9cf0-c856a5395fee.png)

将源代码拖入IDE中查看，可以看到一开头就是Classloader（**在JAVA内存马研判中最要注意的就是匿名或子类实现的classloader，换句话说，就是“来路不正”的classloader**）：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723794643824-e156490f-41f7-42ec-9c15-644843504493.png)

经过研判后，确定这是内存马。

4.6 例3：简单Windows应急
------------------

由于是笔者自己搭建的环境，没有溯源环节。

### 3.4.1 简单日志审计

先找到日志查看行数，一共三百多行不是很多，可以肉眼看也可以工具跑。

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723170547355-6238ce81-0de6-44cd-b714-9d4146ddf92d.png)

然后访问网站判断web类型，这个很明显是CMS建站系统，所以可以现在百度里搜索一下历史漏洞（这个示例是笔者自己用之前审计到的漏洞打的，在这里）：

<https://forum.butian.net/share/2506>

根据文章里的提示 后台存在文件上传漏洞。我们根据POC对比日志查看是否有相同的请求包。

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723170722536-fa8d2073-8f2d-4e4f-b85f-347efa19369c.png)

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723170617297-92c73190-af66-4941-9cf7-b31af8b6b156.png)

确实是有，说明此次漏洞很有可能是文件上传。但是这个包是POST的没有body，无法判断上传webshell的文件名。

### 4.3.2 查找后门

此时我们可以继续查看日志试图寻找webshell，但最好的方式还是使用webshell查杀工具对网站根目录进行查杀。

这里我们使用D盾，在已知web位置时可以自定义目录进行扫描。这里也是很快就扫描到几个可疑文件，其中一个是已知后门：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723171782763-4be7423d-ce7b-48b7-9325-76a6887f6fe0.png)

自然要先看已知后门，在日志中搜索这个文件：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723171885783-4976c330-d9e5-4d55-b27c-43d3e2c9486f.png)

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723171896998-f29f0c95-ea2e-49a5-995a-de0261e5d3b5.png)

这里可以看到，访问中带上rebeyond，提示这可能是冰蝎的webshell，查看文件内容：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723171957275-96f54b0f-1bf4-472b-b7c9-dc86c3d63fbb.png)

确定是冰蝎了，对其进行删除。

### 4.3.3 漏洞修补

这里就根据我原文里的代码审计截图直接查找存在漏洞的函数：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723189846908-449fbc3a-830d-4d97-9123-39792c3df4ce.png)

这个函数的原代码如下：

```php
public function upload(){
        $this->CheckAction('template'); //权限验证

        $file     = $_FILES['file'];
        $folderpath = $this->temp_path . $this->current_dir;

        $valid_image_extensions = array('gif', 'jpg', 'peg', 'bmp', 'tml', 'htm', 'php', 'css', 'txt', 'asp', 'swf', 'flv', 'jsp', 'js', 'xml', 'tpl', 'png', 'mp3');

        if($file['size'] == 0)  {
            $errors = '请选择要上传的文件!';
        }else if(!in_array(getFileExt($file['name']), $valid_image_extensions)){
            $errors = '不允许的文件类型!';
        } elseif (!is_uploaded_file($file['tmp_name']) || !($file['tmp_name'] != 'none' && $file['tmp_name'] && $file['name'])){
            $errors ='上传文件无效!';
        }elseif (file_exists($folderpath . $file['name'])){
            $errors = '目标文件夹内存在同名的文件, 请先删除原文件再上传!';
        }else{
            @chmod($folderpath, 0777);

            if((function_exists('move_uploaded_file') AND @move_uploaded_file($file['tmp_name'], $folderpath . $file['name'])) OR @rename($file['tmp_name'], $folderpath . $file['name'])){
                @chmod($folderpath . $file['name'], 0777);
            }else{
                $errors = '文件夹 "' . BASEURL . 'public/templates/' . $this->current_dir . '" 不可写!';
            }
        }

        if(isset($errors)){
            Error($errors, '上传模板文件错误');
        }else{
            Success('template?'. Iif($this->current_dir, 'dir=' . $this->current_dir . '&') . 'uploaded=' . $file['name']);
        }
    }
```

粗略查看后我们能发现以下几个问题：

1. 上传允许后缀中直接包含了PHP
2. 文件名未重命名且直接与路径进行拼接

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723191589050-f3c9b1bc-4e11-4d8a-bbf9-a92a4b90a4d3.png)

短短两行全是雷点，哈哈

我们还能发现其他点，如：

1. 这个接口需要鉴权（这说明攻击者登录到后台了，这里也许存在其他漏洞或弱口令）
2. 这是一个上传模版点，在保证功能正常的情况下修补方式与一般上传点要有所变化

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723191680430-2164be41-0fee-4b1e-b7da-fa75ac86a0c8.png)

最好先登录后台看看功能点长啥样，再随机应变，进行修补。

这里从数据库找到管理员密码登录后台（这里顺便看到密码是弱口令，结合日志可以判断出只是使用了弱口令进行入侵），找到功能点：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723192026924-6fec70ee-fe47-4e28-9a0a-15a041a87b83.png)

可以看到这里默认是允许php上传的，但这个功能不太合理。

采取的修补方式应该是：对文件名进行校验，确定只包含\[a-zA-Z0-9\_\\-\]并且.只出现过一次。因为功能是“上传模版”，对文件名直接粗暴得进行重命名不太恰当。

那么判断条件也就是这个正则：

```php
/[a-zA-Z0-9-_]*\.?[a-zA-Z0-9-_]*$/
```

也就是在函数开始时添加这一段：

```php
if(preg_match("/[a-zA-Z0-9-_]*\.?[a-zA-Z0-9-_]*$/", $file['name']) 
    or preg_match("/[a-zA-Z0-9-_]*\.?[a-zA-Z0-9-_]*$/", $file['tmp_name'])){
    Error('你的格式有误！');
}
```

然后对弱口令进行修补。这里需要通知客户。全局搜索database等关键字，查询数据库连接配置：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723193724426-9801145c-cb64-4514-9fee-5b2f70514ee8.png)

根据配置连接上数据库，找到用户表：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723193462556-b3281a34-e2e8-40bb-a148-f6a8bc58a6d7.png)

这里也是一眼就能看出来是MD5，密码太简单了就随便改一个强口令（记得告诉客户）。MD5生成随便在网上找个在线生成或者本地用工具就行：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723194070845-47189d07-aa23-4119-80f7-94fb69f1c458.png)

如果是linux呢，那就使用mysql登陆，然后用语句修改。

```php
mysql -h localhost:3306 -u root -p 
```

比如：

```php
UPDATE hongcms.hong_user SET password="6c10cac8a7ceb242e31e349d1bba9cd8" WHERE username="admin";
```

这里由于是高贵的PHP，不需要重启服务器就能完成修补（也就是所谓的hot fix，这个词用来描述它也许不够准确但是够形象）。如果是其它需要重启的服务器，需要先与客户协商一致，再进行重启。

5 攻击溯源
======

基于web的攻击溯源主要还是通过IP来进行的。此时如果攻击者的IP上未进行域名绑定或未运行服务，则溯源难度会变得很大。

比如这里星图报告上的IP：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723797676568-03208499-5faa-4886-823d-a04b65581da8.png)

使用微步进行情报搜索，可以看到它是一个移动基站，那就是类似家庭住宅IP：

![](https://cdn.nlark.com/yuque/0/2024/png/32358243/1723797662625-c5258bb6-599d-4a05-90f8-5bd933a8bff7.png)

而如果查询出的结果为服务器IP，则可以通过多种方式进行溯源，如：

- 对此服务器上运行的web和其他服务进行探测，获取网站关键字
- 对IP绑定域名进行探测，进而查询WHOIS