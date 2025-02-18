拿到两个文件，`secret.raw`和 `yuijm0-=pkl;`

分析
==

用 volatility 扫描`secret.raw`：`volatility -f secret.raw imageinfo`，得到：  
&gt; Suggested Profile(s) : Win10x64\_14393, Win10x64\_10586, Win10x64, Win2016x64\_14393

是一个内存镜像文件，同时获得内存的操作系统类型及版本。

使用 AXIOM 分析内存镜像文件，镜像配置文件直接选择 `Win10x64_14393`

AXIOM 分析完毕后，先好好地翻一翻，看看都有啥。  
使用痕迹 --&gt; 操作系统 --&gt; Windows 时间线活动，能找到不少 VeraCrypt 的运行痕迹：

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-0c3196c0e518f3635ce941e0b22d12785a7570da.png)

使用痕迹 --&gt; web 相关，对日期做降序排序之后，能看到不少文件记录，  
值得注意的有：几个虚拟磁盘文件，很可疑的flag.txt.txt，BitLocker 恢复密钥，decrypt.png，secret.zip  
![4.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-a3f3a22d8083b352b259ee6fe0c6624e05ec433d.png)

使用痕迹 --&gt; 加密，能看到5个 BitLocker 恢复密钥文件，其中四个恢复密钥内容相对完整，且包含有三个不同的恢复密钥，如下：  
`109703-115929-085558-382888-715638-661716-466774-220858`  
`172612-531773-032945-133364-584639-681373-481602-511291`  
`109703-115929-085558-382888-715638-661716-466774-233200`

结合 VeraCrypt 的运行痕迹，猜测`yuijm0-=pkl;`应该是一个磁盘文件，大概需要使用 VeraCrypt 进行挂载，  
web 相关中得到的几个可疑文件，应该与挂载之后的步骤有关联，  
几个 BitLocker 恢复密钥，应该是需要我们使用恢复密钥，解开后面得到的某个文件。

解题
==

结合所给的提示：**键盘密码**，发现该文件的文件名很有特点，连起来得到两个字母：  
![3.jpg](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-08731cc75864a3c904a23f729586a935c24ac1d1.jpg)

可以看出，应该是 TZ，推测是挂载需使用的密码。  
成功将磁盘文件挂载到本地后，得到一个虚拟磁盘文件：`encrypt.vhd`

打开 DiskGenius，磁盘 --&gt; 打开虚拟磁盘文件，选择上一步得到的文件，  
可以看到是使用 BitLocker 加密的：  
![5.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-e9a73afddf25a21e0afad1e5d6e1230177049b37.png)

依次尝试之前获得的三个恢复密钥，可以成功解开，获得 `decrypt.png`和`secret.zip`：  
![6.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-606f72f920ecad80cecdf065ba1b5cc3a097b916.png)

其中，`secret.zip`被加密，结合文件名推测`decrypt,png`应该包含密码。  
`decrypt,png`如下：  
![decrypt.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-39e801f16eef21fc401da6713bf7f345567b17d7.png)  
文字提示：致敬 babydisk，可以联想到初赛的那道题，查看 wp 后获得关键词**螺旋**。

几番尝试后得到密码为：从右上角开始，按顺时针旋转的顺序列出偏旁：`⼃⼇⼋⼏⼎⼍⼌⼈⼄⼀⼁⼂⼆⼊⼉⼅`  
直接复制维基的 Unicode，使用7z解才能成功  
（注意字符的问题，手打出来的偏旁，可能因为输入法的原因，有可能会解不出来）

解得 flag.txt 内容如下：  
![8.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c113d92ac91c3ed572bd2bc83b80b535000b99c1.png)

编写脚本解密：

```python
import base64

def decrypt(lines):
    base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"     
    bintext = ""
    for line in lines:
        if line.find("==") &gt; 0:
            tmp = bin(base64char.find(line[-3]) &amp; 15)[2:]
            bintext = bintext+"0"*(4-len(tmp))+tmp
        elif line.find("=") &gt; 0:
            tmp = bin(base64char.find(line[-2]) &amp; 3)[2:]
            bintext = bintext+"0"*(2-len(tmp))+tmp
    text = ""
    if(len(bintext) % 8 != 0):
        print("error")
        for i in range(0, len(bintext), 8):
            if(i+8 &gt; len(bintext)):
                text = text+"-"+bintext[i:]
                return text
            else:
                text = text+chr(int(bintext[i:i+8], 2))
    else:
        for i in range(0, len(bintext), 8):
            text = text+chr(int(bintext[i:i+8], 2))
        return text

if __name__ == "__main__":
    path = "flag.txt"
    file = open(path, "r")
    line = file.read().splitlines()
    print(decrypt(line))
```

最后得到 flag为：`MemoRy_S1cr1t`