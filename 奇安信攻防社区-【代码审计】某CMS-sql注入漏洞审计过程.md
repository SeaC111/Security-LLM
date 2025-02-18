说在前面
====

本次审计纯属分享审计过程和审计思路，请勿用于非法用途！

审计过程
----

拿到源码，我们可以本地搭建，进入后台看看有什么可能存在漏洞功能块。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-bd796a5d7d0f6d130670e5d140982215ee64c16f.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-bd796a5d7d0f6d130670e5d140982215ee64c16f.png)  
我们可以看到里面有一些功能，里面有一个sql的写入框，有问题看看有没有过滤，我们随便输入东西看一看  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d8b979f5a6298939b4788f1fa7f1441e5a09b471.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d8b979f5a6298939b4788f1fa7f1441e5a09b471.png)  
看来存在过滤  
但是我们有源码不怕，通过报错信息里有一个非法操作，放到工具里面搜搜看  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a774febc8644e02c83c1e6e99e5da75330eea9b7.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a774febc8644e02c83c1e6e99e5da75330eea9b7.png)  
发现里面1到17个都有感叹号，而报错里面没有，说明这个程序运行是在最后一个里面，发现后面两个都是在同一个php文件里面，我们先看第一个  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-83f1ee772a8a9805598557253529894e211e1513.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-83f1ee772a8a9805598557253529894e211e1513.png)  
后来发现最后面两个搜索结果都是同一个地方，可能是搜索结果出现问题了

回到正题，通过这个搜索我们还不能判断是否程序运行在这里，我们再看看里面的参数有title，limits，orders，isall，sqls等等，他们都是通过frparam函数将这些参数里面的具体内容传递给$data这个数组里面，既然是参数可以肯定在抓包的时候会出现，我们就抓个包试试  
在前面那个功能块里面点击保存，并抓包  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8cb04a0be60373b052d204171afccb47c32250a6.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8cb04a0be60373b052d204171afccb47c32250a6.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-79d80456314fc42c3089365d0e51a9af42afda58.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-79d80456314fc42c3089365d0e51a9af42afda58.png)  
我们可以看到里面的参数和我们源码里面看到的参数一样且sql的输入框框是sqls这个参数，基本可以肯定是这里了

接下来就是代码审计了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6fee6e798d7b2d2e03496147771e0eac3f8ae64b.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-6fee6e798d7b2d2e03496147771e0eac3f8ae64b.png)  
我们可以看到他做了一个if判断，通过frparam函数的运行结果是否等于1，我们看看frparam函数，这个函数一看就是自定义的，对于自定义的函数肯定有function frparam这个函数声明，我们去搜一搜。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a64b4cc45587c8b635e43bbc8a17171db1b81f70.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a64b4cc45587c8b635e43bbc8a17171db1b81f70.png)  
找到了，点进去看看  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-42216bb84ae17fe3281284998268cd0f3a7472e5.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-42216bb84ae17fe3281284998268cd0f3a7472e5.png)  
可以看到它是获取URl的参数值，通过前面调用这个函数，他已经go和1传过来了，所以这里的$str和$int为go和1。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d9ac2a846ec7fbd961f8289f272e113790269a92.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-d9ac2a846ec7fbd961f8289f272e113790269a92.png)  
这里$data = $this-&gt;\_data;意思是把前端的所有数据传过来，这时候再判断$str是否为空，再通过这个array\_key\_exists函数判断$str是否在不在$data里面，显然都不满足，所以跳过，后面他在$method变量判断，显然是为空的，因为我们没有赋值给他就默认了，然后把 $data\[$str\]赋值给$value了，最后再return format\_param($value,$int,$default);看一看format\_param函数。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b7636a80848b9f335c143e0f9d770b0070cca92a.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-b7636a80848b9f335c143e0f9d770b0070cca92a.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-cb0932815d1a103a28424ace1ffaa485a2ff186d.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-cb0932815d1a103a28424ace1ffaa485a2ff186d.png)  
这里他参数过滤，格式化了，通过前面传来的int=1，我们直接跳到case 1：，里面他通过SafeFilter函数进行了过滤，我们定位看看  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9c8cbf288e06116821a15d66b1045b2ef36509ce.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9c8cbf288e06116821a15d66b1045b2ef36509ce.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8942e9f580309b9fb8f719f28be193920356a9d7.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8942e9f580309b9fb8f719f28be193920356a9d7.png)  
可以看到他里面过滤了xss攻击了，简单看了一下，是过滤xss的，顺便看下这个框框有没有xss漏洞，通过 $arr = preg\_replace($ra,'',$arr)这个函数判断$arr有没有在$ra里面，有就替换成空了，看到$ra里面就过滤了一些基本的js语句，可能会有，然后再接着看下去，就回到前面了。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9466b07bda73a74a60eda854917d7f57fd0bf0d8.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9466b07bda73a74a60eda854917d7f57fd0bf0d8.png)  
可以看到他又把传来的$值给html实体了。。。没戏。

不慌，我们接着看下去。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3785f28a58dc79d3d737139a9cf410596f70c241.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3785f28a58dc79d3d737139a9cf410596f70c241.png)  
可以看到他判断php版本了，大于等于7.4就会通过addslashes函数在每个双引号"前添加反斜杠，然后再return $value,如果没有大于等于，就会判断是否开启魔术方法了，没有就会和上面一样，通过addslashes函数在每个双引号"前添加反斜杠，然后再return $value，说到这我只能说这代码写的真严谨。。。

好了，这里看完了，回到前面。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9f44c117378376242f3a8daf193bd9948f9e1a63.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-9f44c117378376242f3a8daf193bd9948f9e1a63.png)  
这里return的值就是层层过滤后的$value的值了，这里运行结束，然后我们再返回去看前面。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-92d940ed4d3024c6c46c113ba9bd0d78b5f38967.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-92d940ed4d3024c6c46c113ba9bd0d78b5f38967.png)  
好了，一个frparam函数终于看完了，后面好多个都是通过这个frparam层层筛选的和前面一样，就不多说，我们再往下看。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-04cc2a17c7e5f11cc4b2abeda38a4fceaadcda28.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-04cc2a17c7e5f11cc4b2abeda38a4fceaadcda28.png)  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8564cf0b3edcaf25b11b361c9eceda532f26d414.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-8564cf0b3edcaf25b11b361c9eceda532f26d414.png)  
（太长了，截两张）这里他对这个sqls参数进行了stripos函数判断，这个stripos函数是查找我们指定的字符在字符串中第一次出现的位置，如果有就会输出位置也就是不等于false，也就是为真了，代码里他通过多次或逻辑，只要有一个为真就会执行if里面的”非法操作“这个代码，所以我们只要绕过这些判断，也就是全为假，可以看到他对update，delete，insert，drop，truncate进行了对比，我们只要不适用这些函数就OK了。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-baff28badbd4ad2b805327917cbf20ece937791b.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-baff28badbd4ad2b805327917cbf20ece937791b.png)  
看到我箭头画的就是执行顺序了，他直接就带入执行了，说明存在漏洞。

漏洞验证
----

我们只要的插入sql语句的时候不要有上面的敏感字符就可以了，payload我相信大家都会写，我就不废话了，就直接放sqlmap跑了。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5449cda88f6e5d33621925de20443280dc7372ad.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-5449cda88f6e5d33621925de20443280dc7372ad.png)