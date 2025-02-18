- - - - - -

title: 记一次针对bc的数据盗取
-------------------

0x00 锁定目标
=========

话不多说，开干 。

[![undefined](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-38cb7e68137b2eabf028ff9163a16f09e51b2d56.png "undefined")](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-38cb7e68137b2eabf028ff9163a16f09e51b2d56.png "undefined")

根据指纹信息在批量资产中寻找网站源码

[![undefined](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3315349d5479a8198a0a9c7daef842f001c47859.png "undefined")](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-3315349d5479a8198a0a9c7daef842f001c47859.png "undefined")

0x01 代码审计
=========

针对bc我们的目标是数据，所以优先寻找sql注入。

打开源码发现有360safe保护，那么没法绕过了嘛？

[![undefined](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ecd9dbc0d0194f54077f61c366bc7ba3eb25a1b9.png "undefined")](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ecd9dbc0d0194f54077f61c366bc7ba3eb25a1b9.png "undefined")

阅读下保护规则，在webscan\_cache文件第16行发现了绕过方式，即admin /dede/下为白名单不在拦截范围内。那么思路有了就在admin下找寻注入点。

[![undefined](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fbc4371c32a695a33c8a0c62ba7b75f1eef35aff.png "undefined")](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-fbc4371c32a695a33c8a0c62ba7b75f1eef35aff.png "undefined")

但是我们是没有账号的 那么就需要在admin下寻找前台注入

find ./ -name "\*.php" |xargs grep -L "login\_check.php"|xargs grep -Enl "REQUEST\[|GET\[|POST\["

过滤完在一处前台php页面的第6行找到一处

[![](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4b543fd5842c914d629f8c509e4220ddb0406cf7.png)](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-4b543fd5842c914d629f8c509e4220ddb0406cf7.png)

[![undefined](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e0ded12e4dc9af5a09acdd45f411314d272cb7a9.png "undefined")](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-e0ded12e4dc9af5a09acdd45f411314d272cb7a9.png "undefined")

0x02 另辟蹊径
=========

盲布尔遇到数据量大速度就显得略慢，需要我们找能好的注入点，我们已经有了一处前台注入，后台账号的话就用前台注入注出来。那么就扩大范围前后台都可以寻找。

账密

[![undefined](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ae46516d1b0e8f30a07963b5a586bf5e6b7e74ea.png "undefined")](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-ae46516d1b0e8f30a07963b5a586bf5e6b7e74ea.png "undefined")

登入

[![undefined](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f0cebcbf1534137977b7568357097a585c1460f8.png "undefined")](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-f0cebcbf1534137977b7568357097a585c1460f8.png "undefined")

找的过程略过一堆延时布尔

最后在这个文件找到了后台union注入

[![undefined](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a3146e9309b92bf5fb0bb73fe8344f6f8595e7d9.png "undefined")](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-a3146e9309b92bf5fb0bb73fe8344f6f8595e7d9.png "undefined")

[![undefined](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-78e9c90ace81b6a84afdf4afae690bd36f7b431a.png "undefined")](https://shs3.b.qianxin.com/attack_forum/2021/07/attach-78e9c90ace81b6a84afdf4afae690bd36f7b431a.png "undefined")