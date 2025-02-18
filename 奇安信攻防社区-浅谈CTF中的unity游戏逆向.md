0x00前言
======

**前几天做re题目的时候发现一道肥肠有意思的题目 \[BJDCTF2020\]BJD hamburger competition**。题目给出了一个unity游戏让我们进行逆向。近期的各种比赛中，re整的花活是越来越多了，unity游戏逆向的地位也是水涨船高，所以我们有必要学习一下unity游戏逆向。

0x01 准备工具
=========

**逆向最简单的Unity3D类安卓游戏建议使用安装好 JAVA 环境的Windows系统（涉及到dll文件的修改，所以Windows平台更加适合）。并且下载好专用于.net逆向反编译的dnspy**

安卓apk逆向三件套
----------

**一般 APK 逆向，常使用到 apktool、dex2jar、jd-gui**。在逆向 Unity3D 安卓游戏时，仅仅只需要使用到 **apktool**

> **Apktool: 用于解压/重新打包安卓APK。**  
> **dex2jar: 将解压出来的dex文件变成jar，方便使用jd-gui查看**  
> **jd-gui: 查看dex文件逻辑**

dll文件逆向三件套
----------

**一般的 Unity3D 安卓游戏的主逻辑都在dll文件中，所以我们还需要 dll文件逆向/重新打包 的工具。**

> **ILSpy: 用于查看dll程序逻辑**
> 
> **ILDASM： 用于反编译dll文件，生成il文件(存放了dll反编译后的指令)和res文件(反编译后的资源文件)，可以安装Windows SDK或者从网上下载。**
> 
> **ilasm: .net4.0自带了，位置在 C:\\Windows\\Microsofr.NET\\Framework\\v4.0.30319\\ilasm.exe**

0x02 Unity开发的前世今生
=================

**Unity3D这款游戏引擎想必大家都不陌生，独立游戏制作者们很多人都在用它，甚至一些大公司也用在很商业的游戏制作上。**

**Unity3D最大的一个特点是一次制作，多平台部署**，而 这一核心功能是靠`Mono`实现的。可以说一直以来Mono是Unity3D核心中的核心，是Unity3D跨平台的根本。这种形式一直持续到2014年年中，Unity3D官方博客上发了一篇“[The future of scripting in unity](https://link.zhihu.com/?target=http%3A//blogs.unity3d.com/cn/2014/05/20/the-future-of-scripting-in-unity/)”的文章，引出了`IL2CPP`的概念，这种相比Mono来说安全性更强的方式。

Mono与IL
-------

> **Mono:一个由 Xamarin公司主持的自由开放源代码项目，目标是创建一系列符合ECMA标准（Ecma- 334和Ecma-335）的.NET工具包括C#编译器和通用语言架构。与微软的.NET Framework（共通语言运行平台）不同Mono项目不仅可以运行于Windows系统上，还可以运行于 Linux，FreeBSD，Unix，OS X和Solaris，甚至一些游戏平台。Mono使得C#这门语言有了很好的跨平台能力。**
> 
> **IL:全称是 Intermediate Language。翻译过来就是中间语言。它是一种属于 通用语言架构和.NET框架的低阶（lowest-level）的人类可读的编程语言。简单来说，IL类似于一个面向对象的汇编语言。**

0x03 unity游戏逆向基本思路
==================

**unity主要可以看成两类，dll游戏和libil2cpp游戏，dll游戏比较简单,其核心代码都在** `game/assets/bin/data/Managed/Assembly-CSarp.dll`这个 dll 文件中，并且由于c#类似Js的语言特性，几乎就是可以明文随便篡改。为了提高安全性，用来转换dll to so 的libil2cpp应运而生，但实际上逆向的时候使用ida分析libil2cpp的时候也差不多，有点汇编基础不难看懂，题型要么是结合frida去动态断点一些位置，要么是使用dwarf去动态调试一些位置。

**一般dll类型的unity游戏逆向，唯一核心就是逆向/修改某个 dll 文件就可以了。而一般IL2CPP的Unity3D游戏的逆向，大多只需要根据global-metadata.dat和libil2cpp.so来进行就可以了。目标异常明确，这也是 Unity3D 和 其它安卓逆向不同的地方。**

0x04 unity游戏dll类型逆向实战
=====================

**可能是我才疏学浅，或者是unity游戏逆向需要说的真的不多，实践出真知，我们还是从题目中总结规律吧。**

\[BJDCTF2020\]BJD hamburger competition
---------------------------------------

**出题人太有才了，做一次笑一次。**

**出题人非常贴心的把应用程序给我们解压缩了。我们直接在manage文件夹下找到Assembly-CSharp文件。使用dnspy反编译。在**`{}`栏目下寻找关键代码，最终找到`ButtonSpawnFruit`处的关键代码

```php
public void Spawn()
{

else if (name == "汉堡顶" && Init.spawnCount == 5)
{
Init.secret ^= 127;
string str = Init.secret.ToString();
if (ButtonSpawnFruit.Sha1(str) == "DD01903921EA24941C26A48F2CEC24E0BB0E8CC7")
{
this.result = "BJDCTF{" + ButtonSpawnFruit.Md5(str) + "}";
Debug.Log(this.result);
}
}
Init.spawnCount++;
Debug.Log(Init.secret);
Debug.Log(Init.spawnCount);
}
}
```

**可以看到，给出的字符串DD01903921EA24941C26A48F2CEC24E0BB0E8CC7是flag进行sha1加密后的值。使用解密工具对sha1加密字符串进行解密。**

![](https://i.bmp.ovh/imgs/2022/02/cd6dd19e3d57211a.png)

**跟进一下md5函数。得出将sha1解密的结果md5加密后取大写前20位即为flag**

```php
public static string Md5(string str)
{
byte[] bytes = Encoding.UTF8.GetBytes(str);
byte[] array = MD5.Create().ComputeHash(bytes);
StringBuilder stringBuilder = new StringBuilder();
foreach (byte b in array)
{
stringBuilder.Append(b.ToString("X2"));
}
return stringBuilder.ToString().Substring(0, 20);
}
```

\[2019红帽杯\]Snake
----------------

**不得不说，小游戏做的还是蛮精致的，可惜我们现在没有闲工夫去欣赏游戏了。还是将data文件夹中的**`Assembly-CSharp`文件放入dnspy进行反编译。

[![HuAPZn.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-2ed827b51d4aca285a72f1167975bcafbfa2c439.png)](https://imgtu.com/i/HuAPZn)

**发现表面上的代码一切都很正常，搜字符串也没有和flag有关的，慢慢看各个类，发现可疑的类Interface。看函数名有点像Unity系统的一些东西，但实际上不是，对C#和C++混合编程熟悉的人会发现实际上这是一个外部导入的.dll，由C++编写，按Unity的规则，dll被存放在附件游戏目录的**`Snake\Snake_Data\Plugins\Interface.dll`

**\[**![HuAwdI.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-6324c96b6fcf6ade3989bff68f112d70fc2a5890.png)

**下面看看这个可疑的类做了什么，发现导入了外部interface动态链接库，且GameObject主函数就在这个库中。接着分析GameObject函数是如何被使用的，使用dnspy自带的分析器可以看出GameObject函数向Move函数中传入了一个坐标参数**

[![HuArJf.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c8db301a7a2907ef920a1c38f0ebfb8f71612109.png)](https://imgtu.com/i/HuArJf)

**这个函数传入的应该是蛇头在Unity中的绝对坐标(x,y)，来确认蛇的位置。接下来找到Plugins文件夹下的Interface，是个用c++写的64位动态链接库。使用ida载入。shift-f12查看字符串，发现 “You win ！ flag is”可以语句，交叉定位发现在gameobject函数中**

**\[**![HuAULd.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-97ff9cf57f97b884055150fde06088527de6294c.png)

[![HuAcQg.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d824f28d17bb69c87dc8a831283c07677aea28be.png)](https://imgtu.com/i/HuAcQg)

**\[**![HuA6SS.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-266907894d0dd435ef2210c3bf46629fe2f51194.png)

**反编译GameObject函数，这个函数的逻辑看似很复杂，但是我们注意到这个函数只有一个参数a1（x坐标）传入，传入的a1范围如果在0到99之间就能输出flag。既然是个C++写的动态链接库，不妨写个程序导入这个动态链接库爆破一下。**

```php
#include<iostream>
#include<Windows.h>
#include"defs.h"//ida自带的头文件
typedef signed __int64(*Dllfunc)(int);//函数指针
using namespace std;
int main()
{
Dllfunc GameObject;//GameObject是dll中想要调用的函数名称
HINSTANCE hdll = NULL;
hdll = LoadLibrary(TEXT("Interface.dll"));//用LoadLibrary加载dll
if (hdll == NULL)
{
cout << "加载失败\n";
}
else
{
GameObject = (Dllfunc)GetProcAddress(hdll, "GameObject");//到dll中定位函数
if (GameObject == NULL)
{
cout << "加载函数失败\n";
}
else
{
for (int i = 0; i <= 99; i++)
{
signed __int64 res = GameObject(i);
}
}
}
FreeLibrary(hdll);//释放dll
return 0;
}

```

**小技巧：利用python内置的ctypes模块导入dll**

**python ctypes模块：**

> **模块ctypes是Python内建的用于调用动态链接库函数的功能模块，一定程度上可以用于Python与其他语言的混合编程。由于编写动态链接库，使用C/C++是最常见的方式，故ctypes最常用于Python与C/C++混合编程之中。**

**使用python版的poc 轻松又便捷**

```php
import ctypes
dll = ctypes.cdll.LoadLibrary("文件路径\\Interface.dll")#导入库
for i in range(100):
    dll.GameObject(i)#调用库函数
    print(i)
```

**爆破需要花费一定的时间，让我们耐心的等待~就可以得到flag了**

[![HuESfK.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-1f6da86b345dd8a39b58709fa2a7ddb982a18322.png)](https://imgtu.com/i/HuESfK)

### \[RoarCTF2019\] TankGame

**不多说，用dnspy反编译data文件夹中的**`Assembly-CSharp`文件

[![HlVOzt.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-d02501dc83eaab80cd835091b953357085882df9.png)](https://imgtu.com/i/HlVOzt)

**使用分析器分析一下可疑的**`FlagText` 发现其在`WinGame`中被调用，跟进`WinGame`函数

```php
public static void WinGame()
 {
     if (!MapManager.winGame && (MapManager.nDestroyNum == 4 || MapManager.nDestroyNum == 5))
     {
         string text = "clearlove9";
         for (int i = 0; i < 21; i++)
         {
             for (int j = 0; j < 17; j++)
             {
                 text += MapManager.MapState[i, j].ToString();
             }
         }
         string a = MapManager.Sha1(text);
         if (a == "3F649F708AAFA7A0A94138DC3022F6EA611E8D01")
         {
             FlagText._instance.gameObject.SetActive(true);
             FlagText.str = "RoarCTF{wm-" + MapManager.Md5(text) + "}";
             MapManager.winGame = true;
         }
     }
 }
```

**拿flag逻辑很简单，如果被摧毁的方块数为4或5且此时游戏没有结束，那么遍历21x17的某数组尽数加入某字符串。判断sha1(“clearlove9”+mapstate)是否为指定值，如果是则flag为"RoarCTF{wm-" + MapManager.Md5(text) + "}"，这个md5是“clearlove9”+mapdata的md5的前十个字符。**

**MapState为游戏当前的地图数据，观察游戏初始时的地图数据（21x17）和我们游戏地图相比对得出：**

```php
8 空的
1 砖头
4 水
5 草
2 钢铁
0 家（炸了之后就是9）
```

[![Hl2z8O.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-0b367cd18a9a12cec0ead1f376895a707baf9844.png)](https://imgtu.com/i/Hl2z8O)

[![HlRnxg.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-a988a468f5237bfbed6f1c6890f152fd06e511cc.png)](https://imgtu.com/i/HlRnxg)

**其中只有砖头和家可以打碎，打碎后砖头变成空（1）家打碎了就gg了。接下来写脚本遍历所有情况即可(python2环境下运行，python3 hashlib的要求不同，该脚本会报错)。**

```php
import hashlib
data = [
    [8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8],
    [8, 8, 4, 5, 8, 1, 1, 1, 1, 1, 1, 8, 8, 8, 8, 4, 8],
    [8, 2, 8, 1, 8, 8, 5, 1, 8, 8, 8, 1, 8, 1, 8, 4, 8],
    [8, 5, 8, 2, 8, 8, 8, 8, 1, 8, 8, 4, 8, 1, 1, 5, 8],
    [8, 8, 8, 8, 2, 4, 8, 1, 1, 8, 8, 1, 8, 5, 1, 5, 8],
    [8, 8, 8, 8, 5, 8, 8, 1, 5, 1, 8, 8, 8, 1, 8, 8, 8],
    [8, 8, 8, 1, 8, 8, 8, 8, 8, 8, 8, 8, 1, 8, 1, 5, 8],
    [8, 1, 8, 8, 1, 8, 8, 1, 1, 4, 8, 8, 8, 8, 8, 1, 8],
    [8, 4, 1, 8, 8, 5, 1, 8, 8, 8, 8, 8, 4, 2, 8, 8, 8],
    [1, 1, 8, 5, 8, 2, 8, 5, 1, 4, 8, 8, 8, 1, 5, 1, 8],
    [9, 1, 4, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8],
    [1, 1, 8, 1, 8, 8, 2, 1, 8, 8, 5, 2, 1, 8, 8, 8, 8],
    [8, 8, 8, 8, 4, 8, 8, 2, 1, 1, 8, 2, 1, 8, 1, 8, 8],
    [8, 1, 1, 8, 8, 4, 4, 1, 8, 4, 2, 4, 8, 4, 8, 8, 8],
    [8, 4, 8, 8, 1, 2, 8, 8, 8, 8, 1, 8, 8, 1, 8, 1, 8],
    [8, 1, 1, 5, 8, 8, 8, 8, 8, 8, 8, 8, 1, 8, 8, 8, 8],
    [8, 8, 1, 1, 5, 2, 8, 8, 8, 8, 8, 8, 8, 8, 2, 8, 8],
    [8, 8, 4, 8, 1, 8, 2, 8, 1, 5, 8, 8, 4, 8, 8, 8, 8],
    [8, 8, 2, 8, 1, 8, 8, 1, 8, 8, 1, 8, 2, 2, 5, 8, 8],
    [8, 2, 1, 8, 8, 8, 8, 2, 8, 4, 5, 8, 1, 1, 2, 5, 8],
    [8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8]
]
text = ''
for i in range(21):
    for j in range(17):
        text += str(data[i][j])
text = list(text)
def work(data,index,num):
    if num == 3:
        temp=''.join(data)
        if hashlib.sha1('clearlove9'+temp).hexdigest() == '3f649f708aafa7a0a94138dc3022f6ea611e8d01':
            key=hashlib.md5('clearlove9'+temp).hexdigest().upper()[:10]
            flag="RoarCTF{wm-"+key+"}"
            print(flag)
        return
    if index == 21*17:
        return
    if data[index] =='1':
        temp=list(data)
        temp[index]='8'
        work(temp,index+1,num+1)
    work(data,index+1,num)

if __name__ == "__main__":
    work(text,0,0)
```

0x05 unity游戏IL2CPP类型逆向实战
========================

**IL2CPP类型相对来说，题目难度有一个质的提升。对unity的理解程度需要更深。IL2CPP的Unity3D游戏的逆向，只需要根据global-metadata.dat和libil2cpp.so来进行就可以了。**

\[MRCTF2021\] EzGame
--------------------

**游戏类似于超级玛丽，真的是挺好玩的**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-5fa2dd1d280d5b120d95d2d07488b36e81020979.png)

**在esc面板上发现了getflag按钮，提示我们得到flag要满足下述条件**

```php
回家（通关）
找到外星人
吃到饼干
吃到所有星星
隐藏条件：不能死太多次
```

**我们可以先尝试通过ce修改满足所有条件。修改死亡次数为0 星星数为105**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-ee82d1175e49fbeb3844c84ff216846f8a877069.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-02e6fa1c5e14b1e5732fccc18852392b15aefa6f.png)

**饼干路上就可以看到，外星人则在出生点的地底下，可以通过出生点左边墙壁的缝隙出去到达 通关这个就得看你的操作了。帮不了你。满足所以条件后我们尝试getflag md还不给我们flag，果然这个题目没那么简单。所以单纯使用CE是做不出这个题目的。**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-f170f739b042a77926ea73d60340e28cbf384dcf.png)

**暴力破解不出来，我们只好改变思路了。学习官方题解给我们提供了解题思路：U3d的程序逻辑都是放在**`GameAssembly.dll`里的。可以发现该游戏使用的il2cpp是有工具来反编译`GameAssembly.dll`的，虽然将源码编译成了C++，但是可以IDA，然后还有个`IL2CPPDumper`工具，能够dump出该DLL里的所有类以及类里的方法和成员。接下来使用dnspy反编译我们dump出的dll。

**可以发现在getflag类中有许多和flag相关的东西。死亡次数，吃了多少星星，是否拿到饼干，是否找到外星人，这些都是符合游戏逻辑可以识别的。还有一些加密算法。这是我们突然发现一个需要注意的方法，**`EatTokenUpdateKey`。我们每次吃到星星之后都会执行EatTokenUpdateKey方法，这就是CE直接修改数目无法得到flag的原因。

```php
[Token(Token ="0x600007F")]

[Address(RVA="0x784360",Offset ="0x784360",VA ="0x7FFA27754360")]

public static void EatTokenUpdateKey()

{

}
```

**然后之前我们在cheatengine中观察游戏内存时，发现每一次星星数改变时，有八字节数据会发生变动。那我们就可以合理的推测这8字节数据的变动是由于**`EatTokenUpdateKey`方法。接下来我们就有了一个思路，逆向计算生成八字节key的算法。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-c5ce96e9d76c0444b82b6b72bfde90a7d020ccdb.png)

```php
#include <stdio.h>

unsigned char init[] = {0x4E, 0x51, 0x14, 0xA1, 0xFA, 0xEE, 0xDB, 0xEA};

int fun()
{
        __int64 v2, v3, v4;
        char v5;
        unsigned __int64 v6;
        __int64 result;
        int v0 = 8, i;

        do{
                v2 = 0;
            v3 = 0;
            v4 = 1;

                do
                {
                        v5 = v3++ & 0x3f;
                        v6 = v4 & (*((__int64 *)init));
                        v4 = (v4 << 1) | (v4 >> 63);
                        v2 ^= v6 >> v5; 

                }while(v3 < 64);

                result = v2 | 2* (*((__int64 *)init));
                (*((__int64 *)init)) = result;

                --v0;
        }while(v0);
} 

int main(void)
{
        int i, j;

        for(i = 3; i <= 105; i += 2)
        {
                fun();

                for(j = 0; j < 8; j++)
                {
                        printf("%x ", init[j]);
                } 

                putchar(10);
        }
}
```

**上面的算法中有一个未知量v0,也就是要运行的次数。经过暴力测试在v0 == 8时，得到正确的结果。修改内存即可getflag。**

**附：官方wp中采取了利用 IL2CPP的API进行dll注入的破解手段，可是我太菜了看不懂。暂且使用如上的一种方法，准备学习学习dll相关知识再回头研究**

\[Nu1LCTF2018\] baby unity3d
----------------------------

**本题的程序使用了Riru框架，在Android环境下对相关释放函数Hook并dump出解密后的metadata.具体的原理和使用**可以前往项目[**Riru-Il2CppDumper**](https://github.com/Perfare/Riru-Il2CppDumper)查看。dump metadata 和静态分析的过程这里省略掉。我们直接来看关键函数

```php
bool __fastcall sub_D15EC(int a1, int a2, int a3)
{
  _BOOL4 result; // r0
  bool v4; // zf
  int v5; // r12
  _DWORD *v6; // r2
  _DWORD *v7; // lr
  bool v8; // zf
  int v9; // r1
  int v10; // r3
  bool v11; // zf

  result = 1;
  if ( a2 != a3 )
  {
    v4 = a2 == 0;
    result = 0;
    if ( a2 )
      v4 = a3 == 0;
    if ( !v4 )
    {
      v5 = *(_DWORD *)(a2 + 8);
      if ( v5 == *(_DWORD *)(a3 + 8) )
      {
        v6 = (_DWORD *)(a3 + 12);
        v7 = (_DWORD *)(a2 + 12);
        if ( v5 <= 7 )
        {
LABEL_16:
          if ( v5 >= 4 )
          {
            if ( *v7 != *v6 || v7[1] != v6[1] )
              return result;
            v5 -= 4;
            v6 += 2;
            v7 += 2;
          }
          if ( v5 >= 2 )
          {
            if ( *v7 != *v6 )
              return result;
            v5 -= 2;
            ++v6;
            ++v7;
          }
          result = 1;
          if ( v5 )
            result = *(unsigned __int16 *)v7 == *(unsigned __int16 *)v6;
        }
        else
        {
          while ( 1 )
          {
            v8 = *v7 == *v6;
            if ( *v7 == *v6 )
              v8 = v7[1] == v6[1];
            if ( !v8 )
              break;
            v9 = v6[2];
            v10 = v7[2];
            v11 = v10 == v9;
            if ( v10 == v9 )
              v11 = v7[3] == v6[3];
            if ( !v11 )
              break;
            v5 -= 8;
            v6 += 4;
            v7 += 4;
            if ( v5 < 8 )
              goto LABEL_16;
          }
        }
      }
    }
  }
  return result;
}
```

**关键代码**

```php
 if ( a2 != a3 )
  {
    v4 = a2 == 0;
    result = 0;
```

**a2**是之前经AES加密后的密文，**a3**是**dword\_69B7F0**，那么只要**a2**==**a3**，CheckFlag就会返回1.

**尝试使用 Frida对传入参数dword\_69B7F0** 进行 Hook。关于frida hook技术接下来我们单开一章讲

frida native hook 技术（ frida hook so层函数）
---------------------------------------

### 什么是hook：

> **hook，中文译作”钩子“，”挂钩“，看起来好像和钓鱼有点关系，其实它更像一张网。想象这样一个场景：我们在河流上筑坝，只留一个狭窄的通道让水流通过，在这个通道上设一张网，对流经的水进行过滤，那么，想从这里游过去的鱼虾自然就被网住了。在计算机中，当程序执行时，指令流也像水流一样，只要在适当的位置下网，就可以对程序的运行流程进行监控，拦截。Hook的关键就是通过一定的手段埋下”钩子“，钩住我们关心的重要流程，然后根据需要对执行过程进行干预。**

### frida

**frida是一个轻便好用的工具，支持对java层和so层进行hook。**

### frida环境搭建

**frida的环境搭建分为两部分，在windows安装客户端、在手机中安装服务端**

**windows客户端环境搭建**

```php
 pip install frida
 pip install frida-tools
```

**安装完之后发现启动frida报错，百度搜索解决方案发现我们要在**<https://pypi.org/project/frida/#files>手动下载合适版本的egg文件并拷贝到python安装目录。例如：`C:\Program Files\Python37\Lib\site-packages`

**查看连接到的设备**

```php
frida -ls -devices
```

**手机服务端环境搭建**

**首先到github上下载frida-server，网址为**<https://github.com/frida/frida/releases>，从网址可以看到，frida提供了各种系统平台的server。

**查询手机对应的cpu(adb安装不再赘述)可以看到我们开的模拟器是x86架构的cpu**

```php
adb shell getprop ro.product.cpu.abi
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/02/attach-bcc1e7d51d863cc25462b5fef9dd0502ba85ad16.png)

**解压后，使用adb将frida-server放到手机目录/data/local/，然后修改属性为可执行**

```php
#查看设备连接状态
adb devices -l

#把服务端推送到手机的指定目录（记得先解压再推送）
adb  push  C:\Users\1003441\Downloads\frida-server-12.6.12-android-arm64  /data/loacl

#进入手机终端，修改文件权限并运行
adb shelll

cd /data/local
chmod 777 frida-server-12.4.0-android-arm
./frida-server-12.4.0-android-arm &
```

### frida hook 原理 与题解

**有导出：函数名可以在导出表找到 通过导出表的数据结构 用函数名称进行函数的定位**  
**无导出：函数名在导出表找不到。 这里需要根据函数特征 比如字符串等 手动搜索关键字符串定位函数地址。**

**本题是有导出的frida hook 在本机运行命令**

```php
 frida -U -l 2.js com.nu1l.crack
```

**笔者水平有限，在网上扒到了大佬的脚本** `2.js`原文链接：<https://www.52pojie.cn/thread-1348438-1-1.html>

```php
Java.perform(function(){
    var soAdrr = Module.findBaseAddress("libil2cpp.so");
    send("[soAdrr] "+ soAdrr);
    var ptrCheckFlag = soAdrr.add(0x518a24);
    send("[ptrCheckFlag] " + ptrCheckFlag);
    Interceptor.attach(ptrCheckFlag,{
        onEnter: function(args){
            console.log(("enter ptrCheckFlag args[0]->" + args[0]));
            console.log("enter ptrCheckFlag args[1]->\n" +hexdump(args[1], {
                offset: 12,
                length: args[0].toInt32() * 2 + 12
            }));
        },
        onLeave: function(args){
            console.log(args.toInt32());
            args.replace(1);
            console.log(args);
        }
    })
    var ptrAESEncrypt = soAdrr.add(0x518b54);
    send("[ptrAESEncrypt] " + ptrAESEncrypt);
    Interceptor.attach(ptrAESEncrypt,{
        onEnter: function(args){
            console.log(("enter ptrAESEncrypt args[0]-> " + args[0]));
            console.log(("enter ptrAESEncrypt args[1] text->\n" + hexdump(args[1])));
            console.log(("enter ptrAESEncrypt args[2]-> password\n" + hexdump(args[2],{
                offset: 12,
                length: 12 + 16 * 2
            })));
            console.log(("enter ptrAESEncrypt args[3]-> iv\n" + hexdump(args[3],{
                offset: 12,
                length: 12 + 16 * 2
            })));
        },
        onLeave: function(args){
            //send("leave->"+args);
            console.log("enter ptrAESEncrypt retvalue->\n" + hexdump(args));
        }
    })
    var ptrD15EC = soAdrr.add(0x0D15EC);
    send("[ptrD15EC] " + ptrD15EC);
    Interceptor.attach(ptrD15EC,{
        onEnter: function(args){
            console.log(("enter ptrD15EC args[0]-> " + (args[0])));
            console.log(("enter ptrD15EC args[1] ->\n" + hexdump(args[1])));
            console.log(("enter ptrD15EC args[2]-> \n" + hexdump(args[2])));
        },
        onLeave: function(args){

            console.log("enter ptrD15EC retvalue-> " + args);
        }
    })

})
```

**通过firda hookHook得到AES加密的key为 91c775fa0f6a1cba ，iv为 58f3a445939aeb79 flag的密文为 w0ZyUZAHhn16/MRWie63lK+PuVpZObu/NpQ/E/ucplc=**。

**利用解密工具即可得到flag**

0x06后记
======

**通过做题可以感受到 unity游戏逆向在ctf中的难度分布那是相当不均匀，分析手段花样繁多（常规加解密手段、dll爆破、frida......）。有些题目由于作者水平有限只能部分复现......不禁感叹一声路漫漫而修远兮,还是得好好学习，充实自己。**

0x07 参考链接
=========

[https://blog.csdn.net/liuxiaohuai\_/article/details/111595325](https://blog.csdn.net/liuxiaohuai_/article/details/111595325)

[https://blog.csdn.net/weixin\_44058342/article/details/87940908](https://blog.csdn.net/weixin_44058342/article/details/87940908)

<https://www.bilibili.com/video/BV1nv411M7XV>

[https://blog.csdn.net/qq\_38867330/article/details/103210597?spm=1001.2101.3001.6650.6`&amp;&`utm\_medium=distribute.pc\_relevant.none-task-blog-2%7Edefault%7EOPENSEARCH%7ERate-6.pc\_relevant\_default`&amp;&`depth\_1-utm\_source=distribute.pc\_relevant.none-task-blog-2%7Edefault%7EOPENSEARCH%7ERate-6.pc\_relevant\_default`&amp;&`utm\_relevant\_index=9](https://blog.csdn.net/qq_38867330/article/details/103210597?spm=1001.2101.3001.6650.6&utm_medium=distribute.pc_relevant.none-task-blog-2~default~OPENSEARCH~Rate-6.pc_relevant_default&depth_1-utm_source=distribute.pc_relevant.none-task-blog-2~default~OPENSEARCH~Rate-6.pc_relevant_default&utm_relevant_index=9)

[https://blog.csdn.net/The\_Time\_Runner/article/details/107050990](https://blog.csdn.net/The_Time_Runner/article/details/107050990)

<https://www.cnblogs.com/decode1234/p/10270911.html>

[https://blog.csdn.net/chqj\_163/article/details/83385494](https://blog.csdn.net/chqj_163/article/details/83385494)

<https://www.anquanke.com/post/id/237793#h2-1>

<https://www.52pojie.cn/thread-1417678-1-1.html>

<https://www.anquanke.com/post/id/237793#h3-2>

<https://www.cnblogs.com/shlyd/p/14219188.html>

<https://www.233tw.com/unity/32619>

<https://www.cnblogs.com/shlyd/p/14219188.html>

<https://zhuanlan.zhihu.com/p/267330536>