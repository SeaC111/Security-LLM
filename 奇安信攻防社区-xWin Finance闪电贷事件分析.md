0x00 前言
=======

北京时间2021年6月25日，币安智能链（BSC）上DeFi项目xWin Finance受到闪电贷攻击。

xWin Finance 代币 XWIN 24 小时跌幅达近 90%。攻击者利用了 xWin Finance 的“奖励机制”，不断添加移除流动性，进而获取奖励，价值超过30万美元。在正常情况下，由于用户的添加量不大，因此获取的收益可能会很小，甚至不足以支付手续费；但在巨量资金面前，奖励就会变得异常高了。

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-ee96c40b61a202f31e013d3d4876e3e3f8ef2d82.png)

在攻击发生后，xWIN团队立刻决定终止其推荐系统和奖励系统，并进行xWIN 代币的销毁。

0x01 前提知识
=========

闪电贷
---

闪电贷是 DeFi（去中心化金融，Decentralized Finance） 生态的一个新名词，一类特殊的贷款。在普通贷款中，一般都要有一定的信用分数或者抵押，以此降低被借款人的风险。在闪电贷之前，DeFi一直都是超额抵押借贷，要借先押，借方可以通过抵押币的行为，来借一定比例的其他币种。抵押方也可以将自己的币抵押（存入）进交易池，供给其他人借币，来获取一定的利息收益。而闪电贷允许借款人无需抵押资产即可实现借贷，从而极大提高资金利用率。

在闪电贷中，所有操作都在一笔交易（一个区块）中完成，由合约代码强制执行，它允许借款人无需抵押资产即可实现借贷（但需支付额外较少费用）。因为代码保证在一定时间内（以太坊大约是13秒）偿还借款，如果资金没有返还，那么交易会被还原，即撤消之前执行的所有操作，从而确保协议和资金的安全。当然，使用闪电贷也并不是零成本的，每个协议规定了成功使用闪电贷的用户在归还资金时需要支付一定的手续费，即使是最终闪电贷失败回滚，那么调用和部署智能合约也需要付出一定的费用。

但也正因为闪电贷大大减少了对资金的需求，因此有不少人试图攻击DeFi项目，空手套白狼。目前，大多是通过“哄抬套利”、“操纵预言机”、“重入攻击”和“技术漏洞”四种方式来攻击。

让我们来看一份闪电贷源码的flashLoan函数部分。

```solidity
 function flashLoan(address _receiver, address _reserve, uint256 _amount, bytes memory _params)

    public

    nonReentrant

    onlyActiveReserve(_reserve)

    onlyAmountGreaterThanZero(_amount)

 {

    //check that the reserve has enough available liquidity

    //we avoid using the getAvailableLiquidity() function in LendingPoolCore to save gas

    uint256 availableLiquidityBefore = _reserve == EthAddressLib.ethAddress()

      ? address(core).balance

     : IERC20(_reserve).balanceOf(address(core));

    require(

      availableLiquidityBefore >= _amount,

      "There is not enough liquidity available to borrow"

   );

   (uint256 totalFeeBips, uint256 protocolFeeBips) = parametersProvider

     .getFlashLoanFeesInBips();

    //calculate amount fee

    uint256 amountFee = _amount.mul(totalFeeBips).div(10000);

    //protocol fee is the part of the amountFee reserved for the protocol - the rest goes to depositors

    uint256 protocolFee = amountFee.mul(protocolFeeBips).div(10000);

    require(

      amountFee > 0 && protocolFee > 0,

      "The requested amount is too small for a flashLoan."

   );

    //get the FlashLoanReceiver instance

    IFlashLoanReceiver receiver = IFlashLoanReceiver(_receiver);

    address payable userPayable = address(uint160(_receiver));

    //transfer funds to the receiver

    core.transferToUser(_reserve, userPayable, _amount);

    //execute action of the receiver

    receiver.executeOperation(_reserve, _amount, amountFee, _params);

    //check that the actual balance of the core contract includes the returned amount

    uint256 availableLiquidityAfter = _reserve == EthAddressLib.ethAddress()

      ? address(core).balance

     : IERC20(_reserve).balanceOf(address(core));

    require(

      availableLiquidityAfter == availableLiquidityBefore.add(amountFee),

      "The actual balance of the protocol is inconsistent"

   );

    core.updateStateOnFlashLoan(

      _reserve,

      availableLiquidityBefore,

      amountFee.sub(protocolFee),

      protocolFee

   );

    //solium-disable-next-line

    emit FlashLoan(_receiver, _reserve, _amount, amountFee, protocolFee, block.timestamp);

 }
```

此函数依次进行了如下操作：

1. 检查目前池中余额
    
    ```solidity
    uint256 availableLiquidityBefore = _reserve == EthAddressLib.ethAddress()
    
         ? address(core).balance
    
        : IERC20(_reserve).balanceOf(address(core));
    ```
2. 验证借出方地址 \_reserve 的余额是否小于借贷金额 \_amount , 如果是就回滚初始状态,不是继续后续操作
    
    ```solidity
    require(
    
         availableLiquidityBefore >= _amount,
    
         "There is not enough liquidity available to borrow"
    
      );
    ```
3. 验证gas费和协议费是否大于0，是则继续后续操作，否则回滚初始状态
    
    ```solidity
    require(
    
         amountFee > 0 && protocolFee > 0,
    
         "The requested amount is too small for a flashLoan."
    
      );
    ```
4. 将借贷地址\_receiver定义为可接受转账地址
    
    ```solidity
    address payable userPayable = address(uint160(_receiver));
    ```
5. 从 \_reserve 借出方地址向 \_receiver 借贷地址转账借贷金额 \_amount 值
    
    ```solidity
    core.transferToUser(_reserve, userPayable, _amount);
    ```
6. 还款，他需要四个参数，分别是借出方地址 \_reserve ，借贷金额 \_amount ，手续费 amountFee 和额外的参数 \_params
    
    ```solidity
    receiver.executeOperation(_reserve, _amount, amountFee, _params);
    ```
7. 再次检查目前池中余额
    
    ```solidity
    uint256 availableLiquidityAfter = _reserve == EthAddressLib.ethAddress()
    
         ? address(core).balance
    
        : IERC20(_reserve).balanceOf(address(core));
    ```
8. 根据转账前后池中余额，确保借款人已经还款并支付了手续费
    
    ```solidity
    require(
    
         availableLiquidityAfter == availableLiquidityBefore.add(amountFee),
    
         "The actual balance of the protocol is inconsistent"
    
      );
    ```
9. 更新闪电贷状态
    
    ```solidity
    core.updateStateOnFlashLoan(
    
         _reserve,
    
         availableLiquidityBefore,
    
         amountFee.sub(protocolFee),
    
         protocolFee
    
      );
    ```
10. 完成闪电贷，并打上时间戳
    
    ```solidity
    emit FlashLoan(_receiver, _reserve, _amount, amountFee, protocolFee, block.timestamp);
    ```

如何对闪电贷进行调用呢，来看一个函数

```solidity
function flashloan(address _asset) public {

  bytes memory data = "";

  uint amount = 1 ether;

  ILendingPool lendingPool = ILendingPool(addressesProvider.getLendingPool());

  lendingPool.flashLoan(address(this), _asset, amount, data);

}
```

在这个函数中，用户需要传入一个闪电贷借款币种地址 \_asset ，并且 通过 Aave 提供的 ILendingPoolV1 初始化 LendingPool 接口，这样我们就可以调用 flashLoan 函数。调用 flashLoan 函数时，需要传递四个参数，分别是用户接受贷款地址address(this)，借款币种地址 \_asset ，借款金额amount，以及附带信息data。

xWin奖励机制
--------

在遭受攻击之前，xWIN 协议中有四种获得 xWIN 代币奖励的方式：

1. xWIN 推荐系统，其中 1 个 BNB 存入任何交易、指数或收益保险库中，推荐用户的每一个条目将有权获得 0.20 XWIN
2. xWIN 奖励系统，用户在任何交易、指数或收益金库中存入 1 个 BNB 将有权获得 0.10 XWIN 的每单次入场
3. xWIN 金库所有者/经理奖励系统，其中用户每次输入 1 BNB 至 0.05 xWIN 代币
4. xWIN vault 代币种植和抵押

流动性挖矿
-----

流动池简单的讲就是将两种不同的Token，以一定的比例组合在一起，这就被称为流动池。

流动性挖矿即LP挖矿，也常叫二池，主要是通过提供代币资产，从而获得收益。提供流动性需要将两种代币质押到LP池子，如果两个代币的价格发生波动，根据恒定乘积公式 X\*Y=K，质押的代币数量会发生变化。

用户将根据提供流动性的占比，获得REEF/BNB交易对交易手续费，这个过程也被称为“流动性挖矿”，提供的流动性可以随时取回。

0x02事件分析
========

> xWinFarm合约地址：0x8f52e0c41164169818c1fb04b263fdc7c1e56088
> 
> xWinDeFi合约地址：0x1bf7fe7568211ecff68b6bc7ccad31ecd8fe8092
> 
> 攻击者两次攻击
> 
> - 0xba0fa8c150b2408eec9bbbbfe63f9ca63e99f3ff53ac46ee08d691883ac05c1d
> - 0xda1016b24b8982ea27671e3502691c0ca17231e1dbc0dfd00df41f0646217643

1. 攻击者首先从0xc78248D676DeBB4597e88071D3d889eCA70E5469上借了76000个BNB的闪电贷，相当于 1100 万美元。

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-de2f12db86f51c4e3e42ccf0e30800ab0762ee80.png)

2. 攻击者订阅了旧的PCPL-XWIN 金库（允许用户通过订阅金库轻松参与 PCS LP 农场），将闪电贷借出的所有BNB分成1:1两笔，一半在PancakeSwap上兑换XWIN，另一半用于和置换出的XWIN一起在PancakeSwap中添加流动性，进行流动性挖矿并获得 LP 代币。

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-983ba5ab3cb1d0e9706889d44d14a656e640a754.png)

3. 由于提供了流动性，PCLP-XWIN 金库将铸造 PCLP-XWIN 代币给对应的用户，作为金库所有权的证明。同时，xWIN 协议会将授权的推荐 xWIN 代币奖励记录到推荐地址。

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-6e8c1165d38019a68338f66bef2f4f71bea9f0f9.png)

4. 攻击者通过调用xWIN协议中的redeem函数，使所有的LP代币转换回 BNB 和 XWIN，此时系统会将所有 XWIN 转换回 BNB 并发回给用户。
5. 通过上述操作，xWIN 协议为推荐地址标记了 76,000 x 0.20 = 15,200 xWIN 的奖励。
6. 攻击者重复1、2、3、4步骤多达20次，获得共计303998枚xWIN奖励。
7. 攻击者通过PancakeSwap V2，将xWIN交换为903个BNB。

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-43af89e539d06e32da39eb725e01d5e8e41a74cd.png)

4. 黑客以相同的逻辑进行了第二次攻击，获得了104个BNB。加上第一次攻击，攻击者共计获取了1007枚BNB，总价值超过30万美元。

0x03 源码分析
=========

1. 前往\[攻击者交易log信息\]\[[https://bscscan.com/tx/0xba0fa8c150b2408eec9bbbbfe63f9ca63e99f3ff53ac46ee08d691883ac05c1d#eventlog\]，可获取攻击者更新奖励调用的事件\_Subscribe](https://bscscan.com/tx/0xba0fa8c150b2408eec9bbbbfe63f9ca63e99f3ff53ac46ee08d691883ac05c1d#eventlog%5D%EF%BC%8C%E5%8F%AF%E8%8E%B7%E5%8F%96%E6%94%BB%E5%87%BB%E8%80%85%E6%9B%B4%E6%96%B0%E5%A5%96%E5%8A%B1%E8%B0%83%E7%94%A8%E7%9A%84%E4%BA%8B%E4%BB%B6_Subscribe)。

![6.png](https://shs3.b.qianxin.com/attack_forum/2022/03/attach-2c7f3149ddfa7fd8e0fa3acbb57080c59894929d.png)

2. 前往\[xWinDeFi合约\]\[[https://bscscan.com/address/0x1bf7fe7568211ecff68b6bc7ccad31ecd8fe8092#code\]，查看关于Subscribe函数的相关信息。可以看到，在if判断语句中，只要rewardRemaining&gt;0即可调用storeRewardQty方法和updateReferralReward方法（即更新推荐人奖励信息），并没有对奖励上限做出过多限制](https://bscscan.com/address/0x1bf7fe7568211ecff68b6bc7ccad31ecd8fe8092#code%5D%EF%BC%8C%E6%9F%A5%E7%9C%8B%E5%85%B3%E4%BA%8ESubscribe%E5%87%BD%E6%95%B0%E7%9A%84%E7%9B%B8%E5%85%B3%E4%BF%A1%E6%81%AF%E3%80%82%E5%8F%AF%E4%BB%A5%E7%9C%8B%E5%88%B0%EF%BC%8C%E5%9C%A8if%E5%88%A4%E6%96%AD%E8%AF%AD%E5%8F%A5%E4%B8%AD%EF%BC%8C%E5%8F%AA%E8%A6%81rewardRemaining)。

```solidity
/// @dev perform subscription based on ratio setup and put into lending if available 
    function Subscribe(xWinLib.TradeParams memory _tradeParams) public nonReentrant onlyNonEmergency payable {

        require(isxwinFund[_tradeParams.xFundAddress] == true, "not xwin fund");
        xWinLib.xWinReferral memory _xWinReferral = xWinReferral[msg.sender];
        require(msg.sender != _tradeParams.referral, "referal cannot be own address");

        if(_xWinReferral.referral != address(0)){
            require(_xWinReferral.referral == _tradeParams.referral, "already had referral");
        }
        xWinFund _xWinFund = xWinFund(_tradeParams.xFundAddress);
        TransferHelper.safeTransferBNB(_tradeParams.xFundAddress, _tradeParams.amount);
        uint256 mintQty = _xWinFund.Subscribe(_tradeParams, msg.sender);

        if(rewardRemaining > 0){
            _storeRewardQty(msg.sender, _tradeParams.amount, mintQty);
            _updateReferralReward(_tradeParams, _xWinFund.getWhoIsManager());
        }
        emit _Subscribe(msg.sender, _tradeParams.xFundAddress, _tradeParams.amount, mintQty);
    }
```

3. 查看updateReferralReward函数的细节，可以看到，推荐奖励是通过`_tradeParams.amount.mul(referralperunit).div(1e18)`来计算的。

```solidity
function _updateReferralReward(xWinLib.TradeParams memory _tradeParams, address _managerAddress) internal {

        xWinLib.xWinReferral storage _xWinReferral = xWinReferral[msg.sender];
        if(_xWinReferral.referral == address(0)){
            _xWinReferral.referral = _tradeParams.referral; //store referal address
        }
        xWinLib.xWinReward storage _xwinReward =  xWinRewards[_xWinReferral.referral];

        if(_xwinReward.accBasetoken > 0){
            uint256 entitleAmt = _tradeParams.amount.mul(referralperunit).div(1e18);  //0.10
            _xwinReward.previousRealizedQty = _xwinReward.previousRealizedQty.add(entitleAmt);
        } 

        xWinLib.xWinReward storage _xwinRewardManager =  xWinRewards[_managerAddress];
        if(_xwinRewardManager.blockstart == 0){
            _xwinRewardManager.blockstart = block.number;
        }
        uint256 entitleAmtManager = _tradeParams.amount.mul(managerRewardperunit).div(1e18); //manager get 0.05
        _xwinRewardManager.previousRealizedQty = _xwinRewardManager.previousRealizedQty.add(entitleAmtManager);
    }
```

0x04 安全建议
=========

此次xWin Finance被攻击事件手法并不复杂，只是利用了xWin Finance的“奖励机制”，不断添加移除流动性，进而获取奖励。这也敲响警钟，在审计代码的同时，也要注意自身的推广奖励机制是否存在漏洞，特别是对代币兑换及获取奖励的铸币代码块，应寻找专业人士进行多次审核演算，避免出现限制不全面导致大量铸币的问题。