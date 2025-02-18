环境搭建
----

链接:<https://pan.baidu.com/s/10V-1Foq6MJp82JDF3NHKxg> 提取码:9496

数据库：sqlserver 2016 <https://cloud.tencent.com/developer/article/1644863>

操作系统：Windows2016

某友系列很多，本次选择了是一套很老的系统了

### 用友源码安装

下载百度云下载的压缩包，解压压缩包，运行setup.bat文件

![image-20240516213314292](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-b9ff21fd3f3511037aeeb1542c0ddb8fa858092e.png)

![image-20240516213337274](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-c8a5fe1e6e3600a4e2dd1c65eab8802edb198c85.png)

选择模块然后点击安装，建议选择全模块安装，这样功能多，漏洞也多

![image-20240516213402743](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-c570980e1ab72241b155240be8a4c18431851c08.png)

等待安装完成

![image-20240516213431139](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-69550d82d5cd94175b2a0e83519784509ea9be34.png)

安装完成后目录（一般默认安装在C:\\），运行startServer.bat 启动服务

![image-20240516213528031](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-d63d1a38431336e432afd30433d6ff975eef50be.png)

![image-20240516213608016](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-5ccc430691854f7c234038475d0785c2abbcb6ce.png)

这样本地环境就搭建后了，方便复现漏洞

#### debug调试配置

用友本身是有调试功能的，我们配置一下，在审计代码的断点调试

配置文件路径：`C:\yonyou\home\bin\sysConfig.bat`

![image-20240516214848514](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-8e7e549ae914dffae30b5241bbfd12d491b0b54b.png)

将下面的配置填入到虚拟机参数中，一般添加在最前面就可以了

-agentlib:jdwp=transport=dt\_socket,server=y,suspend=n,address=5005

这样在运行服务时监听5005端口

![image-20240516215511117](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-0a1670e8d552effea1010ae038de6abfe79eeb81.png)

IDEA配置

![image-20240516214819885](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-e08ddd9685286d315e278129542adcecd2f145c0.png)

在jar中class文件下断点

![image-20240516220046757](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-fdc4b8e0e0287e71482e56675095d6f3ee0ffff1.png)

![image-20240516220105442](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-5c26c0be75acb1023b2afa6a857cf32fc52b6dc6.png)

![image-20240516220935169](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-f07f862977dd12bc9e1cfe6474ab97395e8d5e61.png)

### cfr批量反编译jar

用友安装后的源码都是jar的，将jar都反编译出来，这样可以很好的审计代码

工具地址：<https://github.com/leibnitz27/cfr/releases/tag/0.152>

```php
@echo off  
color 17  
​  
if "%1" == "" (  
   for /f "delims=" %%i in ('dir /s /b /a-d /o-s \*.jar') do (  
       echo 正在反编译 %%~ni...  
       title 正在反编译 %%i...  
       java -jar cfr-0.152.jar "%%i" --caseinsensitivefs true  --outputdir "%%~di%%~pi%%~ni"  
       echo ----%%i已经翻反编译---  
   )  
   goto :end  
) else (  
   title 正在反编译 %1...  
   java -jar cfr-0.152.jar %1 --caseinsensitivefs true  --outputdir "%~d1%~p1%~n1"  
   echo 反编译完成.  
   goto :end  
)  
​  
echo 反编译完成.  
@pause>nul  
​  
:end  
pause  
exit
```

![image-20240516221033074](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-742ccb0054d7915e727b688c5a45e28293772305.png)

将1.bat和cfr.jar放在一个目录，运行就批量反编译

![image-20240516221132903](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-cc56f23e105b1fd04daf6c6662484e9d86ed4ee2.png)

等待反编译完成，代码太多需要时间有点长

代码审计
----

开始分析代码前，可以去用友官网查看历史漏洞

![image-20240516221424319](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-a7dea8d07fbb0ec1327e880afc8e7be13dbd47e5.png)

通过这些历史漏洞，可以捡漏。

- 因为一个接口存在漏洞，其他代码中也可能有漏洞
- 避免重复挖掘，不然提交CNVD会重复，白费功夫

主要讲我提交的两个sql注入`workflowService，PaWfm2`，这个系统sql注入还是很多的，只要用心都可以挖到漏洞

### workflowService sql注入漏洞

漏洞代码路径：`C:\yonyou\home\modules\webimp\lib\pubwebimp_cpwfmLevel-1\nc\uap\wfm\action\WorkflowService.java`

![image-20240516222116969](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-8fa7aa623a056fb24b277f5f82d7422fd414ffb9.png)

在`WorkflowService`类中，将`proDefPk`参数传入`getWfmXmlByPk`方法

跟进getWfmXmlByPk方法

![image-20240516222146091](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-968d346356fbe733fb47d7d1eaeae08441e4768d.png)

看到使用到了 `getProDefVOByProDefPk`带入pk参数

![image-20240516222205142](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-e513415dd4d7dbadeb2c084c6454d56fd8d988d7.png)

`getProDefVOByProDefPk` 是 接口类`IWfmProDefQry`定义的方法

在`WfmProDefQry`类实现`getProDefVOByProDefPk`方法

![image-20240516222222456](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-ad45419e0455c08580be24bbc5cf46941c19757e.png)

```java
public WfmProdefVO getProDefVOByProDefPk(String proDefPk) throws WfmServiceException {  
        PtBaseDAO dao = new PtBaseDAO();  
        SuperVO[] superVos = null;  
        try {  
            superVos = dao.queryByCondition(WfmProdefVO.class, "pk_prodef='" + proDefPk + "'");  
        }  
        catch (DAOException e) {  
            WfmLogger.error((String)e.getMessage(), (Throwable)e);  
            throw new LfwRuntimeException(e.getMessage());  
        }  
        if (superVos == null || superVos.length == 0) {  
            return null;  
        }  
        return (WfmProdefVO)superVos[0];  
}
```

`getProDefVOByProDefPk`该方法 直接将`proDefPk`参数 传入`dao.queryByCondition`查询

#### `PtBaseDAO`类中 queryByCondition 方法下断点

开启断点调试查看proDefP值传入数据库，`dao.queryByCondition` 连接数据库查询

`D:\CodeQL\databases\nc\home\modules\webbd\lib\pubwebbd_pubLevel-1.jar!\nc\uap\cpb\persist\dao\PtBaseDAO.class`

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-627d8229b623a62b4a3ae71002a96dc1cd7344ee.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-3b3c99fddfbd7d6f1a1193c104cfceb2580abfb7.png)

`strWhere = (isnull(dr,0)=0) and pk_prodef='11';waitfor delay '0:0:4'--'`  
可以看到 sql语句 查询pk\_prodef字段是使用`'`闭合了sql，导致注入漏洞

![image-20240516222313463](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-c2ea0030ad74d65970676258558b56d5ff5aadbf.png)

注：提交sql注入给CNVD 需要跑出数据库名称等，不然会被打回。

### PaWfm2 sql注入漏洞

PaWfm2 漏洞产生的原理和 workflowService都是使用了 `getProDefVOByProDefPk`导致sql注入漏洞

![image-20240516222539420](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-548a5fec2ef2442631417f5589b9c34b9987ad02.png)

在代码的54行中，使用了`getProDefVOByProDefPk`方法来查询，该方法实现类为`WfmProdefVO`

`WfmProdefVO proDefVo = WfmServiceFacility.getProDefQry().getProDefVOByProDefPk(proDefPk);`

跟踪`WfmProdefVO`类实现的`getProDefVOByProDefPk`方法

![image-20240516222720074](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-879e362683b7387697d22a0eb2cae59d6324b5d9.png)

`getProDefVOByProDefPk`方法 代码

```java
    public WfmProdefVO getProDefVOByProDefPk(String proDefPk) throws WfmServiceException {  
        PtBaseDAO dao = new PtBaseDAO();  
        SuperVO[] superVos = null;  
        try {  
            superVos = dao.queryByCondition(WfmProdefVO.class, "pk_prodef='" + proDefPk + "'");  
        }  
        catch (DAOException e) {  
            WfmLogger.error((String)e.getMessage(), (Throwable)e);  
            throw new LfwRuntimeException(e.getMessage());  
        }  
        if (superVos == null || superVos.length == 0) {  
            return null;  
        }  
        return (WfmProdefVO)superVos[0];  
}
```

`getProDefVOByProDefPk`该方法 直接将`proDefPk`参数 拼接到sql查询语句中，所以造成了sql注入漏洞

跟workflowService一样都使用了`getProDefVOByProDefPk`该方法

直接 queryByCondition 方法下断点

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-3b3c99fddfbd7d6f1a1193c104cfceb2580abfb7.png)

pk\_prodef字段是使用`'`闭合了sql，导致注入漏洞  
`strWhere = (isnull(dr,0)=0) and pk_prodef='11';waitfor delay '0:0:4'--'`

![image-20240516222848172](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-01a16b4904d97d9ad99dfa74684180aa212a34c1.png)

提交了三个漏洞，重复了一个，两个高危

![image-20240516222942430](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-eab5c14b517f0c9933b9011e39e025116c7e01b4.png)

![image-20240522190609516](https://shs3.b.qianxin.com/attack_forum/2024/05/attach-d9faa3a9bcd3461f34c5bac1f0d47e7887526b91.png)

总结
--

- 漏洞挖掘过程本身没有多少技术含量，但是总归收获了高危漏洞证书。