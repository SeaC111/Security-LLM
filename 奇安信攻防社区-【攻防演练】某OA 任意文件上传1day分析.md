0x01 OfficeServer接口
===================

接口对应的class为`OfficeServer.class`,将其反编译，看到代码如下：

![图 8](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-e2be025e14be4d7bee83623a8834e24bfbfe65af.jpg)

（1）首先判断请求方法为POST

（2）然后将`this.MsgObj.sendType`设置为JSON格式

（3）调用`this.MsgObj.Load`解析参数，跟进该方法

![图 10](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-deb70605dc2f0fddbd791a72b963d8a930eb0c80.jpg)

该方法有两种解析参数的方法，根据函数名可以得知，一种是处理表单数据，另一种是处理文件上传数据，这里我们先看处理表单数据的，因为还没涉及到文件。

![图 11](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-dd1678d9cc85af31d52482c8b2a681dc3d061695.jpg)

从上传的表单中，将数据转化为json格式，并赋值给`saveFormParam`属性。

（4）获取上传表单的数据，并根据数据执行对应功能

![图 13](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-a4aec26dec460b8e77ff0f83dc60dbe94c6887bd.jpg)

（5）当`mOption`为`INSERTIMAGE`时，存在漏洞，我们直接到该循环中，如下：

当传入的参数`isInsertImageNew`为1时，进入到插入图片的功能，具体实现如下：

![图 14](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-4615a3a825c65ced3c92cefd52e8e6b9942e6028.jpg)

（6）根据传入的`imagefileid4pic`,从数据库查询文件名，如果文件名中存在`.`则以原后缀名作为后缀，否则以`.jpg`作为后缀。

![图 15](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-065d3e463af11323770fa36deb8bf8f5786b29c7.jpg)

（7）获取文件内容并且保存

![图 16](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-1d250b1ce67c42ff1fdc2b13e66ccab21e272e55.jpg)

`ImageFileManager.getInputStreamById`方法会根据传入的`imagefileid4pic`从数据库中获取其真实路径，然后读取文件流，返回`inputStream`对象，如下：

![图 18](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-63c5960c89f357d63bd70a6bf4befdd76f352403.jpg)

`isZip`在ecology默认安装的时候为1，如果用户修改设置，不进行压缩时，会直接打开文件，获取文件流。

然后跟进`OdocFileUtil.getFileFromByte`,如下：

![图 19](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-6bedeab1843590f5dcece7b45c6841001ff7867b.jpg)

其中`var1`为`GCONST.getRootPath()`，也就是网站根目录。`var2`为（6）中计算的文件名。

到这也就实现，任意的文件写入了，但是现在我们需要一个接口，可以将文件上传到服务器，并且写入`ecology..iamgefile`这个表中。

0x02 uploaderOperate接口任意文件上传
============================

接口位置：workrelate/plan/util/uploaderOperate.jsp

![图 1](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-2c50976c6d1cb515af1dddf1b96cdf57c3273d98.jpg)

当传入的secId不为0的时候，调用dev.uploadDocToImg方法，接着往上看一下dev是哪个对象。

![图 2](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-e3eddbe07d2468e80c42026b233805286ef0a1b6.jpg)

找到对应的方法，如下：

![图 4](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-00f36f08eb57c83235e372342993d877a8ed445d.jpg)

直接跳过这一对创建对象，赋值，if条件判断等内容，因为都没有return exit等操作，直接找到下面的关键点（代码位于：`classbean/weaver/docs/docs/DocExtUtil.class`），如下：

![图 6](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-7263a8154b8c7c7d22542f9ee5c4868e68be18a6.jpg)

流程如下：

- 1.创建了RecordSet类，是用来操作数据库的，后面要用到

```java
RecordSet var19 = new RecordSet();
```

- 2.获取了当前数据库中存放的文档id的下一位值

```java
int var20 = var12.getNextDocId(var19);
```

- 3.调用上传函数

```java
String var21 = var1.uploadFiles(var3); //var3为Filedata
```

此处传入的值`var3`为`Filedata`

接着跟进到`classbean/weaver/file/FileUpload.class` 当中，找到`uploadFiles`的实现，如下：

![图 8](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-f63f41519c682d84d3b558eb17652539526fbfbd.jpg)

然后会调用

![图 9](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-aa8e1d30e27dda8c65726978f0248983e76ab5b7.jpg)

该方法中验证`this.mpdata`是否为空，这里不需要担心，在实例化对象的时候，会给赋值，只需要满足带有上传附件即可，如下：

![图 12](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-12024c1ed4435378f584aa61de7f3370d2229c9c.jpg)

跟进`getAttachment`方法，可以看到：

![图 4](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-8c1df8c604a8d8ab8c3a913c579acd41e40acd42.jpg)

其返回了一个`MultipartRequest`对象，然后在实例化该对象时，会将文件压缩写入到`filesystem`目录下，如下：

![图 5](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-0fa237bb41bbc4197146a3500407c70878cd9ca8.jpg)

`FilePart.writeTo`的核心代码：

![图 7](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-cc843b02358d623908e329f83989f1a0fb9e7665.jpg)

到这里我们大概清楚，当文件上传时，会将临时文件以zip的形式保存在`D:/WEAVER/ecology/filesystem/`

接着回到`uploadFiles(String[] var1, String var2)`,继续跟进逻辑：

- 先遍历上传文件数组，清除文件名中xss相关payload
- 判断上传文件数组是否为空
- 判断this.getParameter("name") 是否不为空
- 保存文件

```java
int var3 = var1.length; // 因为上一个函数将文件名处理为数组，传入该函数
String[] var4 = new String[var3];
this.filenames = new String[var3];

for(int var5 = 0; var5 < var3; ++var5) { // 遍历var1数组，也就是附件名 ['Filedata']
    this.filenames[var5] = SecurityMethodUtil.textXssClean(this.mpdata.getOriginalFileName(var1[var5])); // xss清除
    if (this.filenames[var5] == null || "".equals(this.filenames[var5])) { // 判断请求中是否未传入文件
        return var4;
    }
    // var2来源于：this.getParameter("name") 函数，只要不传入name参数，var2即为False
    // 所以!StringUtils.isBlank(var2)为False，整个if条件为False
    if (!StringUtils.isBlank(var2) && !var2.equals(this.filenames[var5]) && (var2.equals(this.filenames[var5]) || "file".equals(this.filenames[var5]))) {
        this.filenames[var5] = var2;
        var4[var5] = this.saveFile(var1[var5], var2, this.mpdata);
    } else {
        // 到这里，调用saveFile保存文件 
        var4[var5] = this.saveFile(var1[var5], this.mpdata);
    }
}
```

跟进到`saveFile`当中，看一下逻辑实现：

1、获取文件保存路径：

```java
String var4 = var2.getFilePath(var1); //var4 = D:/WEAVER/ecology/filesystem/
```

2、获取文件名

```java
String var5 = var2.getFileName(var1); //临时文件名
// 原始文件名
String var6 = SecurityMethodUtil.textXssClean(var2.getOriginalFileName(var1));
String var7 = var2.getContentType(var1);
long var8 = var2.getFileSize(var1);
String var10 = Util.null2String(this.getParameter("imagefilename"));
String var11 = Util.null2String(var6);
String var12 = var11.contains(".") ? var11.substring(var11.indexOf(".")) : "";
// imagefilename不为空，且后缀与原始文件名一致时，优先取imagefilename作为文件名
if (!var10.isEmpty() && ("".equals(var12) || var10.endsWith(var12))) {
    var6 = var10;
}
```

3、进行大小判断和是否允许此类后缀上传的判断

![图 14](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-70070123389c33a75e1f4e5295b6dff59a267177.jpg)

![图 15](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-10a9bb9b23aa463de68e1710257bd454c0043e98.jpg)

默认配置，任意文件都可以上传。所以，会直接进入下一个else：

首先判断，上传内容是否需要压缩，代码如下：

![图 1](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-bc321538530c57259a9f383c45ab4e4e69c08109.jpg)

如果我们不传入`needCompressionPic`则会直接进入下面，其中`this.needzip`和`this.needzipencrypt`存放于数据库`SystemSet`中，两者默认均为1

然后继续跟进，代码如下：

![图 2](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-eae0d445d902b23e1e98583ea759fad6aa8be2c1.jpg)

其逻辑如下：

1.生成插入imagefile表的数据库语句

2.创建OSS对象生成对应的aescode和Tokenkey

3.更新数据库，将文件名等信息写入`imagefile`数据库

![图 3](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-56f06881e818ecbfce6fb0889e3bda0e217cf2a5.jpg)

4.上传文件到OSS

到这里，我们就完成了文件的上传，而且`imageFilename`为`.jsp`格式，然后将`imagefileid`传给`OfficeServer`接口即可解压文件，getshell。

0x03 漏洞利用
=========

pocsuite -u <http://127.0.0.1:8082/> -r ~/exp/poc/ecology/ecology\_upload\_rce\_nday.py

![图 20](https://shs3.b.qianxin.com/attack_forum/2022/07/attach-147628a4d964c0586f02b7c9e4bbe60d006251dd.jpg)