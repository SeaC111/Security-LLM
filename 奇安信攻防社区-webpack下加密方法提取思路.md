webpack下加密方法提取思路
================

0x01 js中常规提取思路
--------------

### 1.1 找到加密方法位置

常见方法有：

- 搜索加解密关键字，如**encypt**,**encode**等
- 搜索被加密接口或者参数名，如**login**,**password**等
- XHR监听，搜索调用堆栈

这里通过搜索**encypt**找到了加密方法位置

![](https://shs3.b.qianxin.com/butian_public/f67115356eebafe4dfa1896b5203872c0768457c3ced5.jpg)

### 1.2 提取加密方法和有关调用函数

我们将加密函数提取到本地后，还需要跟进补齐所有函数定义，比如i，n，s sm2.doEncrypt等方法提取打包下来

![](https://shs3.b.qianxin.com/butian_public/f9515010c016d3f43daf7583c898a240aebda1173eb4f.jpg)  
![](https://shs3.b.qianxin.com/butian_public/f812538de5493d08f353a1c7d92205aee64c565f42f25.jpg)

### 1.3.1 递进式补齐所有依赖

补齐调用函数后直接执行发现在在sm2.doEncypt()中出现u对象缺少定义，我们在该处调试进入，发现所需依赖越来越多。  
webpack的代码，非常的繁多，一个webpack可能就是几万行代码。在逆向中对于webpack的加解密网站，一般是不建议去扣代码。

### 1.3.2 自实现加密方法

当前面方法难以实现时，我们可以试试阅读加密方法的加密逻辑，自己用脚本模拟实现其加密处理逻辑。  
以上面方法为例：  
首先该方法传入三个参数，分别是**待加密字符串t，SM2公钥，SM4密钥**  
![](https://shs3.b.qianxin.com/butian_public/f675289ca7c8f21bf0492660f56a9de0ecf4745250ff7.jpg)  
回到上一层，找到该方法的调用，可以看到SM4的密钥是由newGuid方法生成的  
![](https://shs3.b.qianxin.com/butian_public/f82098698499e34af7626a73b9b2d3bc0430da9f9f448.jpg)  
而newGuid方法其实是随机生成32位hex字符串

![](https://shs3.b.qianxin.com/butian_public/f980695073c0c2ae141a56fd6b6993bec69847c10bfe3.jpg)

> tips: 对于这种随机生成密钥，可以通过bp修改返回值为固定值，如将return i.join("")改成return "xxxx"，固定其值

具体分析一下加密方法过程，其处理逻辑是：首先用国密2来加密随机生成的国密4的密钥，再用国密4加密待加密的明文字符串，两个加密后的结果再加上其长度进行组合拼接后转base64，作为最终结果

![](https://shs3.b.qianxin.com/butian_public/f546057e42261e54c56c536aa8bc2d119064b5bebb4aa.jpg)

其中的i 方法：hex字符串转数组；n 方法：返回8位字符串 t参数前面用0填充；s：方法取数组t元素的ascii码值（此处是8位长度字符串的ascii码，作用是后续数组转base64获取到数字字符）  
![](https://shs3.b.qianxin.com/butian_public/f193071c24c797b800b0a902f84e738165420b9756b71.jpg)

我们输出加密结果也证实了我们上面的分析，我们分析完整个加密逻辑就可以自实现其加密算法，或在本例中i，n，s方法本不缺少依赖，我们只需将缺少的国密2和国密4加密算法用第三方库应用代替，成功平提原加密逻辑。  
![](https://shs3.b.qianxin.com/butian_public/f159776515e8606e5bd31857641b375a03b4ef58a4480.jpg)

我们发现其实上面着两种方案都比较复杂，那么在webpack模式下有没有更好的方式提取还原算法呢，答案是有的。首先我们来了解一下webpack

0x02 webpack基础知识
----------------

webpack是 JavaScript 应用程序的模块打包器,可以把开发中的所有资源（图片、js文件、css文件等）都看成模块，通过loader（加载器）和plugins（插件）对资源进行处理，打包成符合生产环境部署的前端资源。所有的资源都是通过JavaScript渲染出来的。  
![](https://shs3.b.qianxin.com/butian_public/f5615977ecf79395606c0921287a10893991c0e6d7be9.jpg)

2.1 基本结构
--------

形如

```php
!function(形参){加载器;}([模块1, 模块2…]) 
```

定义一个自执行函数，里面实现一个加载器方法，函数传入的模块数组，数组中的每个元素都是函数，数组从0下标开始计算

![](https://shs3.b.qianxin.com/butian_public/f56778654b80b8961dd79ad9c774d5f5f0e97d4288037.jpg)  
或是：

```php
!function(形参){加载器;}({'模块名1':模块1, '模块名2':模块2…}) 
```

传入一个字典，元素都为函数对象，通过字符串调用对应模块  
![](https://shs3.b.qianxin.com/butian_public/f9380706b44a556c7b945b27918e083e6ed330861c2a3.jpg)

当模块比较多，就会将模块打包成JS文件  
形如：

```php
(window.webpackJsonp = window.webpackJsonp || []).push([[模块ID], {函数对象}, [n, e, t]]);
```

定义一个全局变量 window\["webpackJsonp"\] = \[\]，它的作用是存储需要动态导入的模块，然后重写 window\["webpackJsonp"\] 数组的 push() 方法，window\["webpackJsonp"\].push() 其实执行的是 webpackJsonpCallback();  
window\["webpackJsonp"\].push()接收三个参数,第一个参数是模块的ID,第二个参数是 一个数组或者对象,里面定义大量的函数,第三个参数是要调用的函数(可选)，一般是入口js会传入这个参数来指定首先加载的模块。  
![](https://shs3.b.qianxin.com/butian_public/f171862e9d1479c337b5e3b5f2c61fe272d77efad2d5d.jpg)

2.2 加载器基础知识
-----------

介绍完webpack基本结构，我们来看看加载器做了什么工作  
![](https://shs3.b.qianxin.com/butian_public/f998475be2367dcd9a2676ec2e9f71f6e1d15a735a5f9.jpg)  
加载器处理逻辑：

1. 判断模块是否有缓存，  
    如果有则返回缓存模块的 export 对象，即 module.exports。
2. 新建一个模块 module，并放入缓存。
3. 执行文件路径对应的模块函数。
4. 将这个新建的模块标识为已加载。
5. 执行完模块后，返回该模块的 exports 对象。

**加载器其实就相当于是python中的import**

### 2.3 webpack识别方法

1、多模块打包webapackJsonp特征

```php
(window.webpackJsonp = window.webpackJsonp || []).push([[0], []]);
```

2、加载器实现特征

```php
!function(){
    function xx(n){
        return x[n].call(**.exports, ***, ***.exports, xx)
    }
}();

```

3、页面有`app.版本号.js`，`chunk-libs.版本号.js`等js文件就能大概猜到是使用了 webpack 打包

0x03 Webpack提取加密方法思路
--------------------

Webpack提取加密方法通用思路主要是：

1. 定位加密方法
2. 找到模块引用，提取加载器方法
3. 提取加密实现模块和引用模块文件
4. 调用加密模块，执行输出

### 3.1 定位加密方法

通过搜索接口名和加密字段找到加密方法  
![](https://shs3.b.qianxin.com/butian_public/f5614933df5a39c5c3d974b3d50430e338441f24a92a4.jpg)

### 3.2 提取加载器方法

我们向上看到形如n(字符串)的调用，这种形式一般来说就是利用加载器进行模块引用，我们断点进入  
![](https://shs3.b.qianxin.com/butian_public/f798873e90ec4a093cfb79413dd94c90f8fc589628027.jpg)  
断点跟进，发现其在index中,看到加载器特征

```php
return c[n].call(u.exports,u,u.exports,d),u.l=!0,u.exports;
```

![](https://shs3.b.qianxin.com/butian_public/f688911a102a035cbb6292f2eedb1bae1083b6e5a73d8.jpg)

我们把script标签中的js代码全部提取出来,d函数即是加载器函数  
![](https://shs3.b.qianxin.com/butian_public/f3612210aabbc61be4f32fcbe95652365e487344e18e2.jpg)  
直接执行提示缺少window对象，这是因为window表示浏览器打开的窗口，在客户端JavaScript中window对象是全局的对象，所有 JavaScript 全局对象、函数以及变量均自动成为 window 对象的成员。但在nodejs中直接调用window是不存在的，而代替的是globa;  
于是定义全局变量var window = global;解决报错问题

![](https://shs3.b.qianxin.com/butian_public/f406329d18648aa3f6a6e8e25a94d4ec6896385238e7d.jpg)

### 3.3 提取加密实现模块

提取到加载器方法后，我们还需要找的加密算法实现模块，这里有个技巧，我们前面知道加载器会传入所以模块的数组，我们断点进入提取加载器方法后，控制台可以直接输出模块数组

![](https://shs3.b.qianxin.com/butian_public/f987130e83891abfc10b7472887b995f700dd0b892179.jpg)

前面我们知道加密方法来自“MuMZ”模块，我们利用模块数组直接在控制台打印进入“MuMZ”模块  
![](https://shs3.b.qianxin.com/butian_public/f763992b65adfca28ebe1c2408fc7341e29f6da25c915.jpg)  
复制提取加密模块到本地，直接调用发现缺少了"xbrz"模块的定义

![](https://shs3.b.qianxin.com/butian_public/f943339da2296a3c474ded30661ff13c5a81136a723ce.jpg)  
为了方便，可以把"xbrz"模块所在文件整个复制到本地，利用require进行引用  
![](https://shs3.b.qianxin.com/butian_public/f257212aaf2f1530fc90b09b76cd0303a90e157b6733c.jpg)

### 3.4 调用加密模块执行输出

补齐所有代码后，因为!function是立即执行的函数，为了灵活调用和返回值，定义变量导出加载器方法，调用加密模块，返回加密函数结果

![](https://shs3.b.qianxin.com/butian_public/f547702aa21364affecfb925b9c55b304426c3005e2ad.jpg)

0x04 总结
-------

对比三种提取思路，利用webpack的结构特性进行脚本构造其过程较其他两者更简单，只需要复制加载器和加密模块代码，引用其他文件就可调用加密方法。