0x00 前言
=======

这次 DLL 的分析主要是参照 VMware Security 博客 学习 emotet 家族的 C2 配置提取，所以只有一个 DLL 样本，没有对应的宏文档和窃密程序。

由于 C2 配置在解密后的子 DLL 中，所以我首先分析的是内层的子 DLL，这一篇文章都是子 DLL 转储出来后的分析过程。分析完子 DLL 后我想看下母 DLL 是怎么与子 DLL 关联的，所以又把母 DLL 的行为分析了，但是由于篇幅的原因和手法的不太一样，所以我把母 DLL 的分析放在另一篇了。

建议先看这篇子 DLL 的分析过程，因为这是我先分析的，样本的发展阶段也在这里提及~

0x01 内层 DLL 分析
==============

样本 IOC
------

| HASH | 值 |
|---|---|
| MD5 | 4e22717b48f2f75fcfd47531c780b218 |
| SHA1 | 60b637e95b1f2d14faaa71085b7e26321bfeeb6d |
| SHA256 | 7f94107c9becbcc6ca42070fca7e1e63f29cdd85cbbd8953bbca32a1b4f91219 |

总体行为预览
------

### 动态获取函数手法

在 Emotet C2 Configuration Extraction and Analysis 文章中我得知该样本每个动态获取的 API 函数都通过包装器包装起来供外层核心代码调用，所以我们分析时需要进入每个包装器中识别出动态获取的函数。更高级的是在 get\_dll\_and\_funbase 上下断点，因为所有 API 函数都通过此函数动态获取，这样我们就可以提取出所有 API 包装器并命名它们。

举例文章中分析的 ExitProcess 包装器：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b5109d6c70edc623570368529cb5be010a319af4.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-bffe970e2e21df2ecf1a94e57ebd886a93217789.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0531eb7e98a23cc155213fe26e62c1c0adc7dcf7.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c6b418fba8a0dd1e739610c0090fd63226dd99df.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e912f5caeb3cd50b58af62d3f19fc7831b8d6ccb.png)

在下面的分析中，所有标注了 API 函数别名的，都是基于手动进入包装器内提取动态获取的函数后再回到包装器外标注出来。

### 字符串解密手法

举例，在我定义的包装器 data\_decrypt\_to\_string 中，申请空间，解密字符：

（这一部分待解密的字符串都在 .text 段中，在 IDA 的 string window 窗口中看不到）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0fa70b470cfe74a29d3bd058429f53a3388ecd06.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2e76954ac2f3c1d428e6a38d35561da2fb888e9a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-70f310b6ea79cff288fb3a824082a93c7a09d4d6.png)

### 混淆手法

通过控制流平坦化和大数混淆使相同代码编译得到的二进制特征各不相同，即干扰杀软特征匹配检查，也让逆向跟踪分析增大困难，特别是静态分析。

控制流平坦化：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c8e9ea7b64524fe04640e7e90294e21f2d9437f1.png)

大数混淆：

执行多次数学运算，运算结果有的传入函数中，但是从不使用。有的作为控制流跳转的一部分，不断混淆代码流。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-27201313d8b7a23db9fd20d17108779cc36db4bc.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-371e303f621e42317afd6b7aece7245d757a81ef.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-162db9ca77e6364e4450382c78b4b4f957f3c696.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b9bdcaa29ca2d893fb2ed72a14155f2c7150c17a.png)

### 所属阶段

该转储出来的内部 DLL 属于内层恶意代码，从火绒实验室的 [层层对抗安全软件 火绒对Emotet僵尸网络深度分析](https://bbs.pediy.com/thread-267282.htm) 中我们可以对比出此次分析的内层恶意代码属于Emotet内层恶意代码中内层PE混淆的第三阶段。

3.控制流平坦化和大数运算混淆

在原有API动态获取和加密字符串的基础上，病毒使用控制流平坦化和大数运算进行混淆。这使得相同的代码编译得到的二进制特征各不相同，从而增大安全软件的检出难度，阻碍分析人员对病毒功能逻辑的分析。

控制流平坦化使逻辑难以分析

大数运算混淆改变二进制特征

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-315e08e1183822f8584a43c789e6e47a284477b6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b5fd0784a4c3b0bb8cb0acb8557dff09a82bc1ca.png)

C2 配置提取与解密
----------

VMware Security 博客 中的重点就在这个 emotet 家族的 C2 配置提取，但是过程并没有很明晰，只是直接放上 截图说这就是 C2 的解密函数，现在我从头到尾分析过一遍后发现还是有迹可循的，比如 F8 单步执行时会有明显的 ECK1、ECS1 字样，在后面调用大量加密解密和网络通信 API 中也会发现有对密钥和 IP 的导入，凭借这些迹象足够我们定位到这个 C2 配置解密函数了。

### 迹象定位

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9a1b1753d74ef39148daecfd9a742684a284ac14.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2b50f7913d3a1bc05bef47ee0fb411f3286be7e2.png)

### 解密流程分析

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-29eb2d93e18a4fa11abf06776fe867e11d6f6158.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2e489542b68e1040ee733dbc887ecf0a0300b88d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-cf2e3d1b781860554ae2ac75e38b1e33a26b4f83.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6ac2bca50d8b69cc197f6128cd1c50fe9513a402.png)

### 加密数据格式及手动解密

根据 VMware Security 博客 的研究可以知道公钥在加密中的数据格式，第一个 Dword 是解密的 key，第二个 Dword 是公钥的长度，剩下的就是加密的数据了，在上面解密流程分析的伪代码中也可以分析得出来这点。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1d134dd2f1c5e4d032f2786389d1efff842777ff.png)

手动解密中可以通过将加密数据区的第一个 DWORD 与第二个 DWORD 进行异或来获得加密数据的长度。从第 3 个 Dword 开始，在长度范围内，用第一个 DWORD 对每个块进行 XOR，即可得到解密后的公钥。

以上面 ECK1 为例解密：  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a6326638caaec7e661bba803acc3040d1e1e8008.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d3b8c672aa168df3e75f9c91c8d021d17dabe83b.png)

### 提取公钥

通过以下方法得到如下公钥：

ECK1（base64 编码）：RUNLMSAAAADzozW1Di4r9DVWzQpMKT588RDdy7BPILP6AiDOTLYMHkSWvrQO5slbmr1OvZ2Pz+AQWzRMggQmAtO6rPH7nyx2

ECS1（base64 编码）：RUNTMSAAAABAX3S2xNjcDD0fBno33Ln5t71eii+mofIPoXkNFOX1MeiwCh48iz97kB0mJjGGZXwardnDXKxI8GCHGNl0PFj5

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-757146afd13a46ddd642f93e490624a4a7b053dd.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-aa7d2c293c4f6aa3d30b4dcfc086245b056129f7.png)

### 同理解密 IP 配置

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-31f88708788d6be8c0356c532ed4d8bfe04073d3.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-16b404831d430f4c68207ac1d35b2f6c587261b3.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b9dbb944dcaed725752708b34bfac0bdaf9c164c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0b3b3e0d0ea763d4d777ad175b7aca72a6ec1336.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-93a371b31b00adb3dbf775fd7654726415a60c03.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e5a66b3902f2dbb9d1bd731e83bffa84a6916f99.png)

行为分析
----

### DLL 调试及入口设置

我们通过微软的 rundll32.exe 来调试子 DLL，按照母 DLL 样本给出的命令行参数设置同样的即可，这里我们跟进的是 DllRegisterServer 的导出函数。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-45e4055dc18577595bc26efb509dd419214329f7.png)

"C:\\Windows\\SysWOW64\\rundll32.exe" C:\\Users\*\*\*\\AppData\\Local\\Kfsdwbgbdwjo\\tlcdjloq.dfv,DllRegisterServer

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-316d8106a3c28e9632acc7ed05f111ce523fcdb6.png)

### 先执行的入口点，检查命令行参数

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2aa73355499fcf5e20f7bd0be854968a31951397.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5fd14bc1eb1782e199e3ae0345079ba5f47be3f8.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9bd4a4412ba2c1ddcb176c1f0bb78130a024276d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dd60dfa9b97e34c67163ff06a90116bf6d92ff76.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-041318ee7a7d0c14b10d0324d01ae073ec626c22.png)

### 生成随机数：（用途不详）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-895a8f14db7bfb29e3e993ec2f3bcd7e039fea62.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a650a5e3ce5995d3da397c62d1975bd42b663200.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-49e1703d23c9a72a46ad22db4403006e58ee9011.png)

### 获取路径信息，尝试连接服务控制管理器：（猜测是想将自身作为服务来开机自启动）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5d9a2616a37e5c13c3294e7f58e52552166631a0.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-85f907b95611b482752c500e17f9e49d30c897a1.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a74f4439ce7127223b113a97f6b663d2f7198c2a.png)

### 获取命令行参数：（应该是冗余操作）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d2d827adaf742af2c3349ca9dc34ec43bd3adf75.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e48c67eb1d8170c799b4c47b814dd43cf8c7f1a2.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-53c8708c2e2d8b8af5263fb7102c97bdfcc16baa.png)

### 获取当前文件信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-012fe15473c8f62e8d844ffd9a7592c58ed7def9.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6e322b8af40e50c96ae3c184baa6501202c730f6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-35f52cdc57cc7bfc920153b4024ab85706d856df.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ebfcf63a35e4bab11c52420086d14498eab5c973.png)

### 获取计算机相关信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-258f9b9e4061a7e97cc8ae33d29648af08c914b6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b60d2434ccbf485547287ecc2abeb7d7fb5b9318.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7a2c0e4e90bdaeef5a9167e2e5da90aa239aed0c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-461c39caeedc4494c417190a6e98714fb46c9ac1.png)

### 使用事件对象来通知等待线程发生事件

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-fdf20787c254ff70927c0eab9b6613a4a845c0c0.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-bc1f057df441482450eed546a3dc503a0d48d29d.png)

#### 线程函数

创建一个线程，线程的作用是检查当前目录下文件改动的情况。  
![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0d25c985950b1b0e7275b315f18f5f418d13fb3a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-7cf321077455ddbaa72cec8bc1ac07680d9c35cc.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c45e783ecdd39e9f3d563ea9c523b57c9c1ea49f.png)

### 解密公钥和 IP 等 C2 配置

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0311eeb86fd225fe00424e71026a77bf6c9d4fd2.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5900b099ee8c313f15462157a83b127fc68d122b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3e4ece352207869eace365fb4ffe2e96b149cf9c.png)

### 导入ECK1公钥

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f0d7e8d1f5b27c7239e5bb56cb81e79c90fb6b73.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a474363f492f44db9208857031b28fea9fab1bf1.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-55739b88d1582a508aa80579411a45f401d24a1c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1d6600171db823c0cb627afe266037f3c8442d88.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-44fbbcb29054b7b3e394328b1981669b9c2331f2.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6a37961ece431e9f0c0ff49267f133e3a8918bf6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-98d1ed4afdc947dd6ede8bb6532905839acd17ff.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8bf98dbf31d62d0971b83a21587ae6ea0fa8bdef.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2e1201ba18765929f0180019f83a204ffc13f210.png)

### 动态生成 AES 密钥：（猜测是用 ECK1 公钥加密动态生成的 AES 加密密钥再来加密信息）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d7ba6116bcf751845c250180d07e7786eb20d116.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-031babf1be6a2026cc4b08dc016653b2539fe800.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-05dc355df2aa75dc32c15c0dd089bb1f1fd55cfd.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3f4d8c9d1339d212f5283d4e953ac1c86b96b37b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6198e9f6cefbccbb784466e897c78c451e3b57e0.png)

### 导入ECS1公钥

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a9817f232a2466665688b26ba4b5f3452b1b8181.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b65e11b0ea56bb9e6bd1843548f2173d99e4006a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-db862c0d7d38d6c28694affefa57192ee2ce40d1.png)

### 检索文件目录来确认当前目录中只有一个文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-48653fd1e34aa1c94f4550ff6ad07a558c2b0987.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f11c3c1db056a815db44911b7a402e183e9feefa.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f5a370fcc0ee6cb1947f253d1042ea593ef92d06.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-75f2e5ff571a3279e8cfdb7fd6a3088b20003e51.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9981d32ea2769dc29165914aac4b836beec51a6d.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-51665fae7203f54cf5076644b0e1f3e07c857af8.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-35425d6359e077edb35e5e805664a7c39aad9c16.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-a8c59a3f143632281dd0e2bb98a12fd139a8deab.png)

### 收集当前系统相关信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-af6f133bf4fc58dcf26e1da409e9fe994ae8f4d9.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c22a3c578d9e8ee23a4b7a8d636802530817b436.png)

### 检索关联的远程桌面服务会话

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-df843448504181cdc271e3ae5992d199618c1656.png)

### 对相关系统信息进行加密

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c843faf29593eebb74bbabc5a471b5bd4562eb01.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1ce67df7dfd64d9b25818f0d695944e7d0cb7c3b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8603ad11d91d54cf62580a0237302b5f1dfa838c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6af51b6b3fcd74fcd797c1506dfd27eb9e533b79.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-21605d17fcd7ef1c45ccb6b20f85dfc40c059e92.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ddf286a2873f75bbbe61df808e825ca6794ec008.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-38250b2ad0cf8541ef17cbf314871c3783e364cd.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-18f83dc3ff43c7b9bcd6831d8dfcda407c6f932c.png)

### BASE64 格式化输出加密信息

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c134421720e4e21ec2cd4027edd78833ccb2fe08.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-4a1546d189d8dabad0aed0d63e6352a1a9a2c374.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2cf886036d90fcd4f1327cd23d78eef4262bc31b.png)

### 网络通信操作，利用COOKIE发送加密数据，读取远程文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3da2803d287f8ef090314a363cb90370ff821fbc.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b11166441848569c0e7282f143165daf48d8b4ab.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e6107229130e591783abecc6d07258dddca05528.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-55175feb998c0c211b3673da8fef4aa033548ab6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e14f4cf9c428caefa8373450e5b0eba53c9c63a2.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9420e6f37eb911b79f6e491aa1a17305ba6e1cf3.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c741afae5c5e4ce2f497b2e2cc6e657b2871da1c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-f7b3593c966169bd290869d3e299e826937d1f79.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ed25bda7f5a6e8c889ca8ac43b803881e3a2166a.png)

### 解密读取的远程文件数据

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9a215f95f1ef4e971bf4b4230c81add202558f6b.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8fa04a56fc75ed67f893230bb6e78ba567e28aa7.png)

### 对文件流进行 HASH 加密后验证签名

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-905d3fc419d4917315750e8bd4b5d46b5b12cd79.png)

### 注册表操作：（空操作）

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-67ccdec66358506e13829b046860c1b5f13eabbd.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1cf804b45c258264c72ee50567934344a4c82552.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8f35b1942ab52419517c44e0d4a8c38815d45f0d.png)

### 创建临时文件并复制当前文件过去来躲避查杀

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c6b99b68c88e76c96520e55cf323baed8de7d0c1.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8f1c6a0e099d24624f27ffdd7927fc4da8d94cc6.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-66c951c7374b3c687cb20aea0c77730f58bfd1ff.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-3cd88609f3af3f2bdb68f67934e429bc00cb5022.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-b11ce2bf75fe70d10def5984656cd816d1866971.png)

### 退出程序

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2f3a1bfa12a161a3e17879ae08c7b08c9be007c4.png)

行为总结
----

首先子 DLL 先获取当前程序命令行参数，然后截取出对应参数来看是否在运行导出函数 DllRegisterServer 。然后获取就尝试连接并打开本地服务控制管理器同时获取自身路径信息，猜测是想将自身作为服务来开机自启动。

紧接着检索程序自身所在问价的创建，访问，写入时间等信息，并对比系统时间来查看文件状态是否正常或已被他人操作。（检查是否改动的操作是在开启的线程中进行的）

然后就是获取本地计算机名、磁盘序列号、系统版本信息、关联的远程桌面服务会话来加密传输，其中加密的方式应该是使用解密出的 ECK1 公钥加密动态生成 AES 密钥后再对上面信息进行加密，并对加密后信息以 base64 格式附在 cookie 中发送给解密出的 C2 服务器列表。

再然后就是在发送完相关信息后从 C2 服务器处读取远程文件并进行 HASH 验证，猜测是进行另一种恶意操作，但是这里并没有跟踪到。

最后就是在系统开机自启动的 RUN 目录下进行操作，由于程序最后尝试在系统临时目录下根据系统时间创建唯一的临时文件名并复制自身过去，可以猜测程序想写入的是复制成功后的临时文件路径到 RUN 目录中来维持权限和延长存活时间。

0x02 函数链顺序划分
============

获取程序命令行参数切割导出函数并匹配验证：（对比不上就退出程序）

GetCommandLineA----&gt;L"DllRegisterServer"----&gt;lstrcmpiw\_data（----&gt;SHGetFolderPathA）

申请内存空间：processheap----&gt;RtlAllocateHeap

生成随机数："RNG"----&gt;BCryptOpenAlgorithmProvider----&gt;BCryptGenRandom----&gt;BCryptCloseAlgorithmProvider

连接控制管理器：OpenSCManagerW

获取计算机信息：SHGetFolderPathA、GetModuleFileName

获取时间信息：GetTickCount

获取当前程序命令行参数：GetCommandLineW----&gt;CommandLineToArgvW----&gt;LocalFree

打开文件获取信息：GetModuleFileName----&gt;CreateFileW----&gt;GetFileInformationByHandleEx----&gt;GetSystemTimeAsFileTime----&gt;closehandle

获取计算机系统信息并格式化输出：GetComputerNameA----&gt;GetWindowsDirectoryW----&gt;GetVolumeInformationW----&gt;sprintfW

使用事件对象创建线程（可参考：CreateEvent函数用法）：CreateEventW----&gt;CreateThread

线程函数：GetModuleFileName----&gt;PathFindFileNameW----&gt;CreateFileW----&gt;ReadDirectoryChangesW----&gt;

循环格式化输出解密 IP 配置：循环----&gt;snwprintf

使用 Windows 的 API 导入 ECK1 密钥附加生成的私钥创建协议值：

“ECDH\_P256”+L"Microsoft Primitive Provider"----&gt;BCryptOpenAlgorithmProvider（256位素数椭圆曲线 Diffie-Hellman 密钥交换算法）----&gt;BCryptGenerateKeyPair----&gt;BCryptFinalizeKeyPair(啥变化也没，可能就是标志用的)----&gt;L"ECCPUBLICBLOB"----&gt;BCryptExportKey----&gt;memcpy----&gt;BCryptImportKeyPair----&gt;BCryptDeriveKey----&gt;BCryptDestroySecret----&gt;BCryptCloseAlgorithmProvider

使用 Windows 的 API 进行 AES 加密：

“AES”+L"Microsoft Primitive Provider"----&gt;BCryptOpenAlgorithmProvider（基于高级加密标准 (AES) 密码的消息认证码 (CMAC) 对称加密算法。）L"ObjectLength"----&gt;BCryptGetProperty----&gt;BCryptImportKey----&gt;BCryptCloseAlgorithmProvider

使用 Windows 的 API 导入解密的 ECS1 密钥：

L"ECDSA\_P256"+L"Microsoft Primitive Provider"----&gt;BCryptOpenAlgorithmProvider----&gt;L"ECCPUBLICBLOB"----&gt;BCryptImportKeyPair----&gt;BCryptCloseAlgorithmProvider

单个线程等待函数：WaitForSingleObject

检索文件目录并用通配符比较文件名，确保当前目录文件夹中只有一个文件："%s%s"----&gt;sprintfw----&gt;PathFindFileNameW----&gt;L"%s\\*"----&gt;L"C:\\Users\\xxx\\AppData\\Local\\Kfsdwbgbdwjo\\\\*"----&gt;FindFirstFileW----&gt;FindNextFileW（2次）----&gt;PathFindFileNameW----&gt;lstrcmpiw----&gt;FindClose

收集当前系统相关信息：RtlGetVersion----&gt;GetNativeSystemInfo

检索与指定进程关联的远程桌面服务会话：ProcessIdToSessionId----&gt;GetCurrentProcessId

加密信息：L“SHA256”+L"Microsoft Primitive Provider"----&gt;BCryptOpenAlgorithmProvider----&gt;L"ObjectLength"----&gt;BCryptGetProperty----&gt;BCryptGetProperty----&gt;BCryptCreateHash----&gt;BCryptHashData----&gt;BCryptDestroyHash----&gt;BCryptCloseAlgorithmProvider----&gt;BCryptEncrypt（这个句柄不知道是谁的，加密了两次）

BASE64 格式化输出：CryptBinaryToStringW

BASE64加密数据合并到cookie中传输：L"Cookie: %s=%s\\r\\n"----&gt;sprintfW

网络通信操作：InternetOpenW----&gt;InternetConnectW----&gt;HttpOpenRequestW----&gt;InternetSetOptionW（选项要16进制转10进制）----&gt;InternetQueryOptionW----&gt;InternetQueryOptionW----&gt;HttpSendRequestW----&gt;HttpQueryInfoW----&gt;InternetReadFile----&gt;InternetCloseHandle（3次）

又加密读取的文件数据流：L“SHA256”+L"Microsoft Primitive Provider"----&gt;BCryptOpenAlgorithmProvider----&gt;L"ObjectLength"----&gt;BCryptGetProperty----&gt;BCryptCreateHash----&gt;BCryptHashData----&gt;BCryptFinishHash----&gt;BCryptDestroyHash----&gt;BCryptCloseAlgorithmProvider----&gt;BCryptVerifySignature

注册表操作：0x800001（HKEY\_CURRENT\_USER）+ L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"----&gt;RegCreateKeyExW----&gt;RegDeleteValueW----&gt;RegCloseKey

复制文件到临时文件：GetTempPathW----&gt;GetTempFileNameW----&gt;L"C:\\Users\\xxx\\AppData\\Local\\Kfsdwbgbdwjo\\tlcdjloq.dfv" + L"C:\\Users\\xxx\\AppData\\Local\\Temp\\9000.tmp"----&gt;SHFILEOPSTRUCTA（移动文件）----&gt;PathFindFileNameW----&gt;RemoveDirectoryA