0x01漏洞分析
--------

\\app\\shop\\controller\\Upload.php  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-54344c3fb3894138f8a460d88449a5865306e1ee.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-54344c3fb3894138f8a460d88449a5865306e1ee.png)  
\\app\\shop\\controller\\common.php  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-ae794b7ce010a1c03eb1e6baab5b4dd34dda7442.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-ae794b7ce010a1c03eb1e6baab5b4dd34dda7442.png)  
可以看到由于没有清除参数或过滤所以导致任意文件删除

0x02漏洞复现
--------

为了测试，在跟目录下创建a.txt  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-eed62ecb89b9b0cbf9d397ba9af3d4b387a7f580.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-eed62ecb89b9b0cbf9d397ba9af3d4b387a7f580.png)

POC：  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3bd49fa470616a8e0673f5c6bf04828ad1c20163.png)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3bd49fa470616a8e0673f5c6bf04828ad1c20163.png)  
返回true即删除成功。