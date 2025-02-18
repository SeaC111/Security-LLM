0x01 前言
=======

某1day漏洞，从拿代码到审计getshell，全历程。后来review发现影响很多站点。

0x02 黑盒测试任意文件下载
===============

前台看到有相关附件下载，如下：

![-w870](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d96e8ec4d2d81e78e71d6314d1dfa1911eeea613.jpg)

点击下载功能，发现URL长这样：

```php
/xxxx/downloadFiles?downloadInfo={files:['uploadfiles/bd/doc/xxxxxx.pdf']}
```

直觉告诉我这里存在任意文件下载，于是进行测试。

```php
/xxxxx/downloadFiles?downloadInfo={files:[%27/WEB-INF/web.xml%27]}
```

![-w374](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3fffe453ef207f5a67a10f40714375cd54494cf7.jpg)

果然可以，然后分析`web.xml`文件，然后看具体代码位置。

偶然看到该接口可以批量下载，如下：

![-w692](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2877c289f75f8b96568c872700f13fc404c0497e.jpg)

那先下载`DownloadFilesServlet`进行分析，看一下具体怎么批量下载。

![-w1304](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4b232ea5f984e1e642a2dd3e1cef516216a4ec65.jpg)

结果却找不到该类，然后看了下还有其他批量下载的接口，比如：

![-w680](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-912c25c00f48b31b69082a0c82498f4930e15136.jpg)

尝试下载，发现：

![-w805](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dec4d982f80a3c423d3ac10dc12cc834db37d777.jpg)

开整，分析。

0x03 代码审计
=========

3.1 任意文件下载
----------

因为没有拿到`DownloadFilesServlet` 代码，所以只能分析替代品`WcDownloadFilesServlet.class` 代码了，，看看其怎么批量下载，然后拿到完整代码进行分析。

（1）首先从前端传入`downloadInfo`，然后处理成json，如果json为空，提示下载失败。

![-w1100](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-890e583dc9ac2fc16946ce4c35434b52fdb6cfce.jpg)

（2）84-86行代码中，把json解析好以后，传入了`downLoadFiles`函数。

![-w552](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e800790a3cb48d7e5c2ec937c7f66f8b94c6287e.jpg)

（3）跟进`downLoadFiles`函数的实现如下：

![-w950](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d01b945ee52778dcc06fbf9932edc482ec1cb79b.jpg)

跟进下`getAllFiles`方法，看一下其获取的所有文件的方法。

![-w757](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-80ade2e940564e6f42ade42ff4ee5bcccb854e96.jpg)

概括一下：

- 如果输入的内容中有?、\*一类的字符，会认为你是通过正则类型匹配下载文件，然后解析正则，下载你想要的文件
- 如果文件名不存在正则，那么就会拼接目录，递归解析目录，然后把所有目录中的文件的绝对路径都解析出来，形成一个数组`fVector`

然后回到`downLoadFiles`中，如果返回的`files.size()`为`1`，则调用`downSimple`,即只下载单一代码。否则进行压缩后下载。

![-w679](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f09b7b84e21994eefc25201d290ab54169eab736.jpg)

（4）跟进`downZipFile`看一下其实现

![-w1182](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c0c555b01dd5de73153215cf5657fb50d6a47e49.jpg)

![-w1251](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fa5dfcc755504a3d9e73c979e272cad8aa385c72.jpg)

到此已经看到了下载压缩文件的全流程了。那么要利用，则只需要传递参数：`/xxx/wcdownloadFiles?downloadInfo={files:['/WEB-INF/']}` ,即可打包下载`WEB-INF`目录了。压缩web根目录会超时，无法完成下载，所以只能退而求其次，下载`WEB-INF`目录，但该有的代码还是可以看到的。

全部代码：

![-w970](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4dc444840f599e9c8e4d14b9fe59cc1fc93f27cb.jpg)

（5）上面没提到单一文件下载的`downSimple`，给大家看一下，没啥技术含量。

![-w1040](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8402823f4a4485a0f7187d6c23c2b197c8f64374.jpg)

3.2 任意文件上传-
-----------

有了完整的代码以后，导入idea，进行分析，侧重能拿权限的接口。

![-w942](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-906c5b7898059d963eceb3fcd4621b5390a3c605.jpg)

找到对应代码进行分析如下：

（1）获取Web根目录，然后拼接路径

![-w1275](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5f108ea7e12a48d9d9e9a229fb795c2d7811a1c2.jpg)

此时目录为`[Web Real Path]/uploadfiles/[savePath用户传入]`

（2）解析上传请求

![-w843](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ec9a3493ed3a997407b3af6cd29eaeefa9790e9b.jpg)

（3）文件保存

![-w1121](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c3a460876bbe4064783a276c1d8e28ac86f47212.jpg)

![-w618](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d19980cc64e37a39be4d313660246477a7de020b.jpg)

最后返回给前端。

任意文件上传分析完成，然后进行测试，却....

![-w1320](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6b1ec1b959a7b64fa2f766cbf3c6c664cffc9c77.jpg)

至少应该是显示上传失败才对啊。到这，这个洞派暂时派不上用场，但在内网却起到了很大作用。

内网见到同样的CMS时，直接抄起poc就打，然后就成了。这台机器在我们后来的横向中起到了很关键的作用，因为密码是通用密码且能读到明文。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5f1f8ffc0a5122a9ed91cf27c5ac75fd95735eda.png)

后来测试，该漏洞在互联网上也是影响很多资产。

3.3 任意文件上传2-webUploadServlet
----------------------------

找这个接口，主要是我在前台用过，且真实可以上传文件，但不返回文件名，而且上传什么上去都是`.png`，所以进行分析。

最开始没找他的代码的原因是因为`class`目录没这个类。

![-w668](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e78e7c76bb2830cf793700fa7d3350739b0b8804.jpg)

就很离谱，然后问了某大佬，说可能在依赖的jar包里面，于是在lib目录下找到了名称为项目名的jar包。果然找到了对应的代码，如下：

在解析POST请求时，定义不同的action用于处理不同内容。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-704ff0185bd6456f96a81d971c1c88a50ae4477b.png)

首先先看下`uploadFile`的实现：

（1）处理上传请求，具体如下：

![-w1066](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d62558a6b1896fa069f7d2facca5bd354e277f58.jpg)

（2）拼接路径，完成上传，具体逻辑如下：

![-w929](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-45e7f42864fafb25b92dd76fa09ca5cae3a461be.jpg)

其实这里面有个坑点，判断`chunks`不为空，则取`chunk`作为最终文件名，这怕是少写了个字母，最开始我没注意这点，走了很多弯路。

（3）漏洞利用-1，只需要构造数据包，满足以上逻辑要求即可。

![-w1289](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a96851a913d94a9f2cc0d973c59eeeddfc7cc449.jpg)

然后shell地址为：`/uploadfiles/attach/chunk/test/tst.jsp`,测试：

![-w1348](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1b70824e6277bbc28915fe1ec48000b7619ec203.jpg)

3.4 任意文件上传2+文件移动接口
------------------

上面提到说当时踩了`chunks`和`chunk`这个坑，当时是上传以后，死活也访问不到上传后的文件。

然后发现有个`action`分支为：`checkChunk`，涉及文件操作，它是这样实现的：

![-w987](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7e09df1f43cff62488855ce68f36da7e24869ca4.jpg)

把用户传入的`fileUuid`拼接进了路径，和我们上面看到上传里面的`(String)var10.get(var10.get("id"))`的值对应上，到`var6`这里就是同一个目录，然后接着 http请求、`fileUuid`的值和`chunks`的值被传入了`mergeFile`函数，跟进一下看看实现。

![-w1116](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fe0abe3716389c084dd927d79d8bc59793e463c4.jpg)

![-w693](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1573dace0efb2e04a351d0505f081d32901ff82a.jpg)

所以，无论我们的`storePath`写什么内容，最后保存的文件名都可控，所以，这必然存在漏洞。

利用方法：

![-w1257](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-14d6b670e25703dae816236a69d0cd7758922cdb.jpg)

此时因为没`chunks`，所以传的文件访问不到。

![-w1305](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ed41b7f04eb4b0d0e282ef4bef00d214d9823f82.jpg)

![-w1327](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b620392ea86fa58b54dedc97b4ba17e357b6adb7.jpg)

是这么存的，所以需要用到另一个接口进行移动文件，测试如下：

![-w1361](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-94772582b3920c8a404d1b5dc7b5ccf7dd82126b.jpg)

然后访问shell：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-afbd1dd616b0ffebd03eaf21f1398313e08f9fd0.png)