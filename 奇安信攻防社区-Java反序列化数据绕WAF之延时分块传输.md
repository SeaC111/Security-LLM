0x01 背景
-------

`chunked-coding-converter`在0.2.1以及之前版本是不支持对二进制数据进行分块的。这个问题实验室的`darkr4y`师傅今年3月份的时候就已经反馈了多次，由于懒癌在身一直没有更新。直到我自己遇到一个站点，[反序列化带大量脏数据](https://gv7.me/articles/2021/java-deserialize-data-bypass-waf-by-adding-a-lot-of-dirty-data/)没有绕成功，于是又想起了分块传输。花了一点时间让插件支持了二进制数据，然而这样依然被拦截了！  
[![直接分块传输被WAF拦截](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-573d38050162a7d3caf9d7783274ba775ee5f57f.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-573d38050162a7d3caf9d7783274ba775ee5f57f.png)

这也在意料之中，分块传输被公开已经有两年之久，很多WAF已经支持检测。那有没有办法让这个姿势重振往日雄风呢？

0x02 延时分块
---------

通过测试，发现WAF一般是如下应对分块传输的。

1. 发现数据包是分块传输，启动分块传输线程进行接收
2. 分块传输线程不断接收客户端传来的分块，直到接收到`0\r\n\r\n`
3. 将所有分块合并，并检测合并之后的内容。

当时和`darkr4y`师傅交流时，我们曾做过一个设想，**在上一块传输完成后，sleep一段时间，再发送下一块。** 目的是在2阶段延长WAF分块传输线程的等待时间，消耗WAF性能。这时有没有可能WAF为自身性能和为业务让步考虑，而放弃等待所有分块发送完呢？ 。这次正好遇到适合的环境来验证一下想法。  
[![延时分块绕WAF流程](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e37bbefaf96f968da59ae0ec3fb4d1ed7ea1a660.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-e37bbefaf96f968da59ae0ec3fb4d1ed7ea1a660.png)  
当然了，我们块与块之间发送的间隔时间必须要小于后端中间件的`post timeout`,Tomcat默认是20s,weblogic是30s。

0x03 编码实现
---------

为了加大WAF的识别难度，我们可以考虑以下3点。

1. 延时时间随机化
2. 分块长度随机化
3. 垃圾注释内容与长度随机化\[可选\]

首先我们需要对原始request header进行处理。需要把`Content-Length`删除，分块传输不需要发送body长度，然后加上`Transfer-Encoding: chunked`头。

```java
headers.remove("Content-Length");
headers.put("Transfer-Encoding","chunked");
```

其实调用`HttpURLConnection.setChunkedStreamingMode(int chunkedLen)`就可以实现分块发包。不过这个接口只能设置固定分块长度，而且无法直接控制分块时间间隔。于是我打算用socket来模拟发送http/https分块传输包，这样要灵活的多。以下是实现的简化代码。

```java
// 1.连接目标服务器
Socket socket = socket.connect(new InetSocketAddress(host, port));
OutputStream osw = socket.getOutputStream();

// 2.发送request header
osw.write(reqHeader);
osw.flush();

// 3.随机分块和随机延时发送request body
ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(reqBody);
byte[] buffer = new byte[Util.getRandom(minChunkedLen,maxChunkedLen)];
while (byteArrayInputStream.read(buffer) != -1){
        // 3.1发送分块长度
        final String chunkedLen = Util.decimalToHex(buffer.length) + "\r\n";
        osw.write(chunkedLen.getBytes());
        chunkeInfoEntity.setChunkedLen(buffer.length);
        osw.flush();

        // 3.2发送分块内容
        byte[] chunked = Transfer.joinByteArray(buffer, "\r\n".getBytes());
        osw.write(chunked);
        osw.flush();

        // 3.3延时
        int sleeptime = Util.getRandom(minSleepTime,maxSleepTime);
        Thread.sleep(sleeptime);

        buffer = new byte[Util.getRandom(minChunkedLen,maxChunkedLen)]; // 获取新的buffer长度
}

// 4.发送完毕
osw.write("0\r\n\r\n".getBytes());
osw.flush();
byte[] result = readFullHttpResponse(socket.getInputStream());
```

为了方便日后使用，我给[chunked-coding-converter](https://github.com/c0ny1/chunked-coding-converter)插件添加了`sleep chunked sender`，并添加很多细节功能，比如预估分块数量范围和延时范围，显示每一块发送的内容，长度，延时时间以及发送状态等等。

这里我直接使用最新版本，将被拦截的数据分成`218块`，共延时`1分46秒`发送，最终成功绕过WAF。  
[![延时分块传输成功绕过WAF](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-01470b9749dc5862dbe876793d2a93d1cff7c143.png)](https://shs3.b.qianxin.com/attack_forum/2021/08/attach-01470b9749dc5862dbe876793d2a93d1cff7c143.png)

0x04 一些零碎
---------

最后列一点边边角角的东西，当餐后”甜点“，需要请自取。

1. 只有HTTP/1.1支持分块传输
2. POST包都支持分块，不局限仅仅于反序列化和上传包
3. Transfer-Encoding: chunked大小写不敏感