在一次测试过程中，发现一个文件上传的入口，如图：

![1.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-0bfb1b39a2b6ffa5f509d314f26597e81cf9e3a4.png)

测试时，使用 burp 提交数据包时，将文件名处添加 XSS 的 Payload：`("><img src=x onerror=alert(document.domain>.png)`:

![2.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-abf4188b6d193ca23f0f939ab1456e9971eb892b.png)

然后，发现 xss 漏洞触发执行，算是一个 self-xss，危害有限：

![3.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-090a8459a0b2f3901e15b0e83f0e21b6f696349b.png)

关闭弹窗后，发现一些错误信息：

![4.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-45f1ff5adf07fff5bc1bd18416b705689623af12.png)

![5.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-e66a066ce2da7187ea217ccf22250231236e6c68.png)

感觉文件是文件名在插入数据库时报的错，所以尝试将 xss 的 payload 修改为 SQL 注入的：

1、`--sleep(15).png`

![6.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-69fb4dd12a598e48a1b1bd6ca80da41e2dca2eb9.png)

2、`--sleep(6*3).png`

![7.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-9257221eede4a562f86ec619e1cc31675029257e.png)

3、`--sleep(25).png`

![8.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-2d126b2c180887fbd812a118d6f7fab85299e04e.png)

4、 `--sleep(5*7).png`

![9.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-4528b674c381c8f6156e083f0fe5eefefab94189.png)

从测试上来看，大概猜测了下后端代码的实现方式，如下：

```php
<?php
$target_dir = “uploads/”;       #存放文件的目录
$target_file = $target_dir . basename($_FILES[“fileToUpload”][“name”]); #上传之后的文件路径
$uploadOk = 1;
$imageFileType = strtolower(pathinfo($target_file,PATHINFO_EXTENSION)); #文件名扩展小写
// 检查图片的格式是否是真实图片
if(isset($_POST[“submit”])) {
$check = getimagesize($_FILES[“fileToUpload”][“tmp_name”]);
if($check !== false) {
echo “File is an image - “ . $check[“mime”] . “.”;
$uploadOk = 1;
} else {
echo “File is not an image.”;
$uploadOk = 0;
}
}
?>
```

以上代码没有检测文件名是否有效，从而导致，任意构造文件名，进入后续文件写入、数据入库的环节，导致漏洞产生，应该增加如下代码来检测文件名是否有效：

```php
$filename = ‘../../test.jpg’;
if (preg_match(‘/^[\/\w\-. ]+$/’, $filename))
echo ‘VALID FILENAME’;
else
echo ‘INVALID FILENAME’;
```

至此这个测试的过程就分享到这里。虽不是什么特别高大上的测试过程，也算一个不错的漏洞案例，任何用户可控的参数都是不可信的，都是可能存在漏洞的，细节决定成败。