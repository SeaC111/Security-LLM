前言
==

​ 前几天参加了一个比赛，上面有一道题目与Poly Network 事件攻击手法类似，写一篇文章来总结一下。简单说一下攻击的点在于函数签名值的爆破，错误的设置合约owner。

代码分析
====

合约的代码文件在[Github](https://github.com/zpano/BlockChain-Security/tree/main/solidity%E5%90%88%E7%BA%A6%E8%B5%9B%E9%A2%98%EF%BC%88%E5%85%A8%E9%83%A8%EF%BC%89/%E8%B5%9B%E9%A2%983)上，可以自行下载。下面分析漏洞点

```solidity
 //DVT3.sol
        function changeOwner(address newOwner) public onlyOwner returns(bool) {
        require(newOwner != address(0));
        emit OwnerExchanged(owner, newOwner);
        owner = newOwner;
        return true;
    }

    function payforflag() public onlyOwner {
        emit SendFlag(msg.sender);
    }

}
```

在这段代码中，我们想要实现触发SendFlag事件必须要有owner权限，而changeOwner函数权限也掌握在owner中，我们无法突破。但是让我们来看另一段代码

```solidity
//Airdrop.sol
function TransferOrAirDrop(address to, bool isTransfer, bytes calldata _method, uint256 amount) external {
        if (isTransfer) {
            bytes memory returnData;
            bool success;
            (success, returnData) = token.call(abi.encodePacked(bytes4(keccak256(abi.encodePacked(_method, "(address,address,uint256)"))),abi.encode(msg.sender,to,amount)));

            require(success, "executeProposal failed");
        } else {
            bytes memory returnData;
            bool isFristAirDropFlag;
            bool success;
            if(AirDropCount[msg.sender] == 0) {
                isFristAirDropFlag = true;
            } else if (AirDropCount[msg.sender] > 2) {
                return;
            }
            (success, returnData) = token.call(abi.encodePacked(bytes4(keccak256(abi.encodePacked(_method, "(bool,address)"))), abi.encode(isFristAirDropFlag, msg.sender)));
            require(success, "executeProposal failed");
            AirDropCount[msg.sender]++;
        } 
    }
}
```

在TransferOrAirDrop函数中，使用了call调用，但是未做调用函数名的限制，且\_method参数可控，就可以通过爆破函数签名的方式调用token合约上的任意函数。在此处我们依旧可以注意到  
[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4553cdc992b47b555b0e30ed999e5842d56c05ca.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-4553cdc992b47b555b0e30ed999e5842d56c05ca.png)  
对于DVT3合约上的owner被设置为了Airdrop的地址，也就是说我们可以调用前面提到的changeOwner函数变成合约的owner，进而实现触发SendFlag事件。

Poc分析
=====

```python
import sha3
from Crypto.Util.number import *
p=sha3.keccak_256()
p.update(b'changeOwner(address)')
print(p.hexdigest()[:8])
#a6f9dae1
```

再分析下面的两个call调用

```solidity
(success, returnData) = token.call(abi.encodePacked(bytes4(keccak256(abi.encodePacked(_method, "(address,address,uint256)"))),abi.encode(msg.sender,to,amount)));
(success, returnData) = token.call(abi.encodePacked(bytes4(keccak256(abi.encodePacked(_method, "(bool,address)"))), abi.encode(isFristAirDropFlag, msg.sender)));
```

对于第一个调用我们需要爆破出满足`_method(address,address,uint256)`函数签名为0xa6f9dae1的\_method，往后传入的第一个参数为msg.sender，恰好等于下面的代码

```php
token.call(abi.encodePacked(bytes4(keccak256(abi.encodePacked("changeOwner(address)"))),abi.encode(msg.sender)));
```

对于第二个调用我们需要爆破出满足`_method((bool,address)`函数签名为0xa6f9dae1的\_method，往后传入的第一个参数为isFristAirDropFlag，恰好等于下面的代码

```php
token.call(abi.encodePacked(bytes4(keccak256(abi.encodePacked("changeOwner(address)"))),abi.encode(0x0/0x1)));
```

上述参数传递使用了Solidity语言的参数传递优化自动对齐的性质。

但是对于第二个调用不能是我们变成DVT3合约的owner，不太符合我们的调用。所以我们选择第一个调用。

攻击过程
====

使用 github.com/ethereum/go-ethereum/crypto 的库编写一个Go语言的多线程爆脚本 大致经过十五分钟可以出结果

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a18a2b7c9b1720e1f2b3f9e79a6adeab647707cc.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-a18a2b7c9b1720e1f2b3f9e79a6adeab647707cc.png)

可以看到两者的签名相同

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-568d22f9d1bed6f992cbab00f5d156d372fc514e.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-568d22f9d1bed6f992cbab00f5d156d372fc514e.png)

转化出攻击参数

进行攻击

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3ca14be6826f7dd69c5c603d4df472637584de3d.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-3ca14be6826f7dd69c5c603d4df472637584de3d.png)

成功实现攻击

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1ad0c3b123e03bc55909542d30d355405844b4ab.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-1ad0c3b123e03bc55909542d30d355405844b4ab.png)

最后实现触发SendFlag事件

[![](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-2535e3b1634d741b7136febb4a491ae0722836f6.png)](https://shs3.b.qianxin.com/attack_forum/2021/10/attach-2535e3b1634d741b7136febb4a491ae0722836f6.png)

与Poly Network 事件的联系
===================

在[Poly Network官方开源的源码中](https://github.com/polynetwork/eth-contracts/blob/master/contracts/core/cross_chain_manager/logic/EthCrossChainManager_new_template.sol#L185)的\_executeCrossChainTx函数中，我们可以容易的看到这一行

```solidity
(success, returnData) = _toContract.call(abi.encodePacked(bytes4(keccak256(abi.encodePacked(_method, "(bytes,bytes,uint64)"))), abi.encode(_args, _fromContractAddr, _fromChainId)));
```

就可以在\_toContract对应的合约上调用任意的函数，同时\_toContract对应的合约上没有进行合理的鉴权，攻击者通过爆破\_method从而调用 putCurEpochConPubKeyBytes 函数去替换 \_toContract合约上的Keeper 的Public Key Bytes。

```solidity
    function putCurEpochConPubKeyBytes(bytes memory curEpochPkBytes) public whenNotPaused onlyOwner returns (bool) {
        ConKeepersPkBytes = curEpochPkBytes;
        return true;
    }
```

在用替换后的Keeper的Public Key Bytes对应的私钥进行签名即可通过所有检查执行调用 LockProxy 合约将其管理的资产转出。

可以从[函数签名库](https://www.4byte.directory/signatures/?bytes4_signature=0x41973cd9)中找到

总结
==

本次攻击利用的三个点

- 权限控制错误
- call调用参数可控
- 函数签名值的爆破

本次漏洞的发生在本质上还是对于call调用的错误限制，并且和其他的漏洞组合使用导致了Poly Network 6.1亿美金的被盗事件。在智能合约的开发实践中还是需要注意严格控制call调用，不可使其参数可控。同时对于一些关键函数的权限控制在审计时应作为重点审计。将这些函数的使用权掌握在可控的地方，不可被恶意利用。