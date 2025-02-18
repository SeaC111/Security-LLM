Java生态中基本只有Jackson和Fastjson组件，但是两者相关的版本均存在相应的漏洞（反序列化、DDOS），那么如何有效识别目标使用了哪种对应的组件就很有必要了。

 理想状态下**如果站点有原始报错回显，可以用不闭合花括号的方式进行报错回显**，报错中往往中会有Fastjson/Jackson的关键字：

 Jackson：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-6c4a903c47da8867fe08ff161f9d0045c2fabb48.png)

 Fastjson：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-f3c1cb3916f167f1dad9968168f19a738cc85c0c.png)

 但是实际上并不可能那么的理想，所以需要一些其他的trick来进行区分。下面探讨下两个解析器之间有什么区别。

0x01 Fastjson&amp;Jackson中的Feature
==================================

 FastJson和Jackson在序列化和反序列化的过程中提供了很多特性（Feature），例如Fastjson的Feature.DisableFieldSmartMatch（1.2.30引入）。如果没有选择该Feature,那么在反序列的过程中，FastJson会自动把下划线命名的Json字符串转化到驼峰式命名的Java对象字段中。

 简单看下两个解析器是如何加载Feature的。

1.1 Fastjson
------------

 以**1.2.24版本**为例，查看常用的解析方法，在对json文本进行解析时，一般会使用JSON.parse(text)，默认配置如下：

```java
public static Object parse(String text) {
    return parse(text, DEFAULT_PARSER_FEATURE);
}
```

 DEFAULT\_PARSER\_FEATURE是一个缺省默认的feature配置:

```java
public static int DEFAULT_PARSER_FEATURE;
static {
    int features = 0;
    features |= Feature.AutoCloseSource.getMask();
    features |= Feature.InternFieldNames.getMask();
    features |= Feature.UseBigDecimal.getMask();
    features |= Feature.AllowUnQuotedFieldNames.getMask();
    features |= Feature.AllowSingleQuotes.getMask();
    features |= Feature.AllowArbitraryCommas.getMask();
    features |= Feature.SortFeidFastMatch.getMask();
    features |= Feature.IgnoreNotMatch.getMask();
    DEFAULT_PARSER_FEATURE = features;
}
```

 可以通过Feature类的isEnabled方法来判断相关的Feature是否开启：

```java
package com.alibaba.fastjson.parser;

public enum Feature
{
  AutoCloseSource,  AllowComment,  AllowUnQuotedFieldNames,  AllowSingleQuotes,  InternFieldNames,  AllowISO8601DateFormat,  AllowArbitraryCommas,  UseBigDecimal,  IgnoreNotMatch,  SortFeidFastMatch,  DisableASM,  DisableCircularReferenceDetect,  InitStringFieldAsEmpty,  SupportArrayToBean,  OrderedField,  DisableSpecialKeyDetect,  UseObjectArray,  SupportNonPublicField;

  public final int mask;

  private Feature()
  {
    this.mask = (1 << ordinal());
  }

  public final int getMask()
  {
    return this.mask;
  }

  public static boolean isEnabled(int features, Feature feature)
  {
    return (features & feature.mask) != 0;
  }
  ......
}
```

1.2 Jackson
-----------

 Jackson主要是在com.fasterxml.jackson.core.JsonFactory对Feature进行管理。在类加载时会先把相关Feature的默认值进行采集：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-b24aab12aa241eeac9b201f4e064dfd83ef312d1.png)

 每个Feature都会有自己的默认值，例如下图中的USE\_BIG\_DECIMAL\_FOR\_FLOATS主要是将浮点数反序列化为BIG\_DECIMAL，默认是False：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-660719312b71e3aeb78759d45034f41a78bc0bde.png)

 同样的，springboot在org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration进行装配时，如果没有其他配置，会把这些默认的Feature配置进行装载：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-2d9760c724236a2a6dd47d451bc444632315a8a0.png)

 既然两者都在在序列化和反序列化的过程中提供了很多特性（Feature），而两者之间的Feature肯定是有区别的，可以利用这一点看看能不能找到一些思路用户两者的区分。

0x02 黑盒区分Fastjson和Jackson
=========================

2.1 通过默认Feature配置区分
-------------------

 根据前面的思路，可以根据两者默认的Feature配置或者设计上的区别来进行区分。下面列举一些可用的trick。

### 2.1.1 Jackson的JsonParser.Feature(2.10后替换为JsonReadFeature)

 JsonReadFeature的配置也是一样的：

```java
public enum JsonReadFeature implements FormatFeature {
  ALLOW_JAVA_COMMENTS(false, JsonParser.Feature.ALLOW_COMMENTS),
  ALLOW_YAML_COMMENTS(false, JsonParser.Feature.ALLOW_YAML_COMMENTS),
  ALLOW_SINGLE_QUOTES(false, JsonParser.Feature.ALLOW_SINGLE_QUOTES),
  ALLOW_UNQUOTED_FIELD_NAMES(false, JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES),
  ALLOW_UNESCAPED_CONTROL_CHARS(false, JsonParser.Feature.ALLOW_UNQUOTED_CONTROL_CHARS),
  ALLOW_BACKSLASH_ESCAPING_ANY_CHARACTER(false, JsonParser.Feature.ALLOW_BACKSLASH_ESCAPING_ANY_CHARACTER),
  ALLOW_LEADING_ZEROS_FOR_NUMBERS(false, JsonParser.Feature.ALLOW_NUMERIC_LEADING_ZEROS),
  ALLOW_LEADING_DECIMAL_POINT_FOR_NUMBERS(false, JsonParser.Feature.ALLOW_LEADING_DECIMAL_POINT_FOR_NUMBERS),
  ALLOW_NON_NUMERIC_NUMBERS(false, JsonParser.Feature.ALLOW_NON_NUMERIC_NUMBERS),
  ALLOW_MISSING_VALUES(false, JsonParser.Feature.ALLOW_MISSING_VALUES),
  ALLOW_TRAILING_COMMA(false, JsonParser.Feature.ALLOW_TRAILING_COMMA);
  ......
  }
```

 这里以JsonParser.Feature为例进行举例:

- 解析value遇到以"0"为开头的数字

 Jackson的objectMapper默认情况下是不能解析以"0"为开头的数字的，但是fastjson是可以的：

```Java
/**
Feature that determines whether parser will allow JSON integral numbers to start with additional (ignorable) zeroes (like: 000001). If enabled, no exception is thrown, and extra nulls are silently ignored (and not included in textual representation exposed via getText).
Since JSON specification does not allow leading zeroes, this is a non-standard feature, and as such disabled by default.
**/
ALLOW_NUMERIC_LEADING_ZEROS(false),
```

 Fastjson会把01解析成1:

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c14ee208503f76f1813c8d0cdff8cfa3918add3c.png)

 Jackson在解析01时会抛出异常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-90de133a041d2d6d2f18ec452c1864b4935ecd69.png)

- 解析value为NaN  
     Jackson的ObjectMapper解析器默认不能识别 "Not-a-Number" (NaN)，不会认为其为浮点类型或者int类型的数字：

```Java
/**
Feature that allows parser to recognize set of "Not-a-Number" (NaN) tokens as legal floating number values (similar to how many other data formats and programming language source code allows it). Specific subset contains values that XML Schema  (see section 3.2.4.1, Lexical Representation) allows (tokens are quoted contents, not including quotes):
"INF" (for positive infinity), as well as alias of "Infinity"
"-INF" (for negative infinity), alias "-Infinity"
"NaN" (for other not-a-numbers, like result of division by zero)
Since JSON specification does not allow use of such values, this is a non-standard feature, and as such disabled by default.
**/
ALLOW_NON_NUMERIC_NUMBERS(false)
```

 Fastjson 1.2.70会把NaN解析成0:

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-03a6e62eaf8b54c8d08b22ab2e91417620ad9aaa.png)

 Fastjson 1.2.37会抛出异常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-b4d5acf5aeeb496c9c565ad0ee52dacca5e04b12.png)

 Jackson会抛出异常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-90f986a4258940e57f3a0299f996f65595703f6f.png)

- 注释符

 当json字符串里存在注释符时，默认情况下Jackson的ObjectMapper解析器不能解析（Fastjson的AllowComment默认是开启的，所以支持注释符的解析）：

```Java
/**
 * Feature that determines whether parser will allow use
 * of Java/C++ style comments (both '/'+'*' and
 * '//' varieties) within parsed content or not.
 *<p>
 * Since JSON specification does not mention comments as legal
 * construct,
 * this is a non-standard feature; however, in the wild
 * this is extensively used. As such, feature is
 * <b>disabled by default</b> for parsers and must be
 * explicitly enabled.
 */
ALLOW_COMMENTS(false)
```

 Fastjson支持注释符：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-0c45862aaab3c70050d3d28b028e3bea0796926a.png)

 Jackson默认情况下会报错：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-210529e54b4398645910f0cbc85dd0b882182619.png)

- json字段使用单引号包裹

 Fastjson的Feature.AllowSingleQuote 是默认开启的，支持使用单引号包裹字段名，但是jackson受到JsonParser.Feature.ALLOW\_SINGLE\_QUOTES的影响，默认是不支持的：

```Java
/**
Feature that determines whether parser will allow use of single quotes (apostrophe, character '\'') for quoting Strings (names and String values). If so, this is in addition to other acceptable markers. but not by JSON specification).
Since JSON specification requires use of double quotes for field names, this is a non-standard feature, and as such disabled by default.
**/
ALLOW_SINGLE_QUOTES(false)
```

 Fastjson正常解析：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-4bb1b2bb42483b59d42af0bfd8ac443b7a7629a0.png)

 Jackson解析抛出异常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-900cf9d69b042ff55ac28e3793df7730d35cc199.png)

- json属性没有使用双引号包裹

 fastjson的AllowUnQuotedFieldNames默认开启，允许json字段名不被引号包裹，但是jackson的ALLOW\_UNQUOTED\_FIELD\_NAMES默认不开启，无法解析：

```Java
/**
 * Feature that determines whether parser will allow use
 * of unquoted field names (which is allowed by Javascript,
 * but not by JSON specification).
 *<p>
 * Since JSON specification requires use of double quotes for
 * field names,
 * this is a non-standard feature, and as such disabled by default.
 */
ALLOW_UNQUOTED_FIELD_NAMES(false)
```

- 解析JSON数组中“缺失”的值

 如果数组中两个逗号之间缺失了值，形如这样`[value1, , value3]`。对于fastjson来说可以解析，jackson受到`ALLOW_MISSING_VALUES`的影响会抛出异常：

```Java
/**
Feature allows the support for "missing" values in a JSON array: missing value meaning sequence of two commas, without value in-between but only optional white space. Enabling this feature will expose "missing" values as JsonToken.VALUE_NULL tokens, which typically become Java nulls in arrays and java.util.Collection in data-binding.
For example, enabling this feature will represent a JSON array ["value1",,"value3",] as ["value1", null, "value3", null]
Since the JSON specification does not allow missing values this is a non-compliant JSON feature and is disabled by default.
**/
ALLOW_MISSING_VALUES(false)
```

 Fastjson正常解析，会把缺失的值忽略掉：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-5bed1917b015c9a554f2322ed144d6f696c53982.png)

 Jackson会抛出异常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-b3fc109affe55030386450dda53da96c5e72bb17.png)

### 2.1.2 Jackson的MapperFeature

- 大小写敏感

 假设Bean的结构如下：

```Java
public class User {
    private int id;
    private String userName;
    private String sex;
    private String[] nickNames;

    //对应的getter和setter方法
}
```

 在代码里里属性id是小写的，在fastjson和jackson解析时会有区别。

 FastJson在反序列化的时候，是对大小写不敏感的:

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-7e9c00ede27171a666ebaf81446d1ef1f6decf70.png)

 在Jackson中，`MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES`默认设置为FALSE，在反序列化时是大小写敏感的，可以看到下面的例子中Id因为大小写敏感的问题并未赋值：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-e719bbe86c17e8b4892350adb135930d042e0569.png)

### 2.1.3 Fastjson的Feature

- 忽略json中包含的连续的多个逗号

 Fastjson中Feature.AllowArbitraryCommas是默认开启的，允许在json字符串中写入多个连续的逗号。

 Fastjson正常解析：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-5249c1bc09ee93ef63b8ccd058c7d0cac493ace4.png)

 Jackson会抛出异常，类似的的Feature是ALLOW\_TRAILING\_COMMA（是否允许json尾部有逗号，默认是False)：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-ab2ee0e4116f8fd4aa7c1f265c0e00178a766b23.png)

2.2 结合fastjson智能匹配区分
--------------------

 除了通过默认Feature的差异以外，FastJSON存在智能匹配的特性，即使JavaBean中的字段和JSON中的key并不完全匹配，在一定程度上还是可以正常解析的。通过这些特性也可以简单的进行区分。

- 字段名包含`-`和`_`

 主要是在JavaBeanDeserializer.smartMatch方法进行实现。通过这一特点可以在一定程度上做区分。

 在**1.2.36版本及后续版本**，部分具体代码如下，具体处理方法在TypeUtils.fnv1a\_64\_lower：

```Java
public FieldDeserializer smartMatch(String key, int[] setFlags)
  {
    if (key == null) {
      return null;
    }
    FieldDeserializer fieldDeserializer = getFieldDeserializer(key, setFlags);
    if (fieldDeserializer == null)
    {
      long smartKeyHash = TypeUtils.fnv1a_64_lower(key);
      if (this.smartMatchHashArray == null)
      {
        long[] hashArray = new long[this.sortedFieldDeserializers.length];
        for (int i = 0; i < this.sortedFieldDeserializers.length; i++) {
          hashArray[i] = TypeUtils.fnv1a_64_lower(this.sortedFieldDeserializers[i].fieldInfo.name);
        }
        Arrays.sort(hashArray);
        this.smartMatchHashArray = hashArray;
      }
```

 查看TypeUtils.fnv1a\_64\_lower的具体实现,这里忽略字母大小写和-和\_：

```java
 public static long fnv1a_64_lower(String key)
  {
    long hashCode = -3750763034362895579L;
    for (int i = 0; i < key.length(); i++)
    {
      char ch = key.charAt(i);
      if ((ch != '_') && (ch != '-'))
      {
        if ((ch >= 'A') && (ch <= 'Z')) {
          ch = (char)(ch + ' ');
        }
        hashCode ^= ch;
        hashCode *= 1099511628211L;
      }
    }
    return hashCode;
  }
```

 也就是说fastjson1.2.36版本及后续版本支持同时使用\_和-对字段名进行处理：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-4b816fe96c761a9414cc6bbd06ea05f74132f639.png)

 但是jackson默认是没有这一特性的，例如下面的例子，并没有识别到经过`-`和`_`处理后的userName：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-985bd876ea286c493999563a74048f7db30c7a5c.png)

- 使用is开头的key字段

 Fastjson在做智能匹配时，如果key以is开头,则忽略is开头,相关代码如下:

```Java
int pos = Arrays.binarySearch(this.smartMatchHashArray, smartKeyHash);
if ((pos < 0) && (key.startsWith("is")))
{
    smartKeyHash = TypeUtils.fnv1a_64_lower(key.substring(2));
    pos = Arrays.binarySearch(this.smartMatchHashArray, smartKeyHash);
}
```

 同样的Jackson是不具备该特点的。

0x03 一些疑惑?
==========

 根据上面的思路可以发掘出很多别的思路，但是实际在环境测试时却与之前的想法有差异，这里对遇到的其中一个点进行分析。

3.1 关于Jackson的属性对齐特性
--------------------

 很容易发现Jackson反序列化多余的属性会抛出异常，其实是受到`DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES`的影响(默认设置为true):

```Java
/**
Feature that determines whether encountering of unknown properties (ones that do not map to a property, and there is no "any setter" or handler that can handle it) should result in a failure (by throwing a JsonMappingException) or not. This setting only takes effect after all other handling methods for unknown properties have been tried, and property remains unhandled.
Feature is enabled by default (meaning that a JsonMappingException will be thrown if an unknown property is encountered).
**/
FAIL_ON_UNKNOWN_PROPERTIES(true)
```

 所以相比fastjson，jackson会比较严格，因为强制key与javabean属性对齐，只能少不能多key，所以在解析时会报错。服务器的响应包中多少会异常回显（或者是通用报错页面）。看一个具体的例子：

 例如JavaBean中有如下属性：

```Java
public class User {
    private int id;
    private String userName;
    private String sex;

    //对应属性的getter和setter方法
}
```

 使用ObjectMapper对对应的Json字符串进行解析，因为没有passwd属性，在解析时会抛出异常：

```Java
public static void main(String[] args) throws IOException {
    String jsonStr="{\"id\":1,\"sex\":\"male\",\"userName\":\"admin\",\"passwd\":\"123456\"}";
    ObjectMapper mapper = new ObjectMapper();
    User user = mapper.readValue(jsonStr,User.class);
    System.out.println(user);
}
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-be3126b13051b06287724f7e2d902bda90fc0be7.png)

 **根据上面的猜想，理论上应该是可以通过这个属性对齐特性来简单区分使用的是Jackson还是fastjson解析器的**。

 进一步在springboot环境下进行测试（Springboot默认使用的是Jackson）：

 同样是刚刚的JavaBean，可以看到增加了新的无关属性passwd后，并未抛出异常：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-fc6cc3a51125b35e6247dbedd488d9b214182025.png)

 这是为什么呢？

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-96ab46834bbc4ff7b9a588cd0e8a14a86dc39616.png)

 其实**在Spring/Spring Boot环境下**，**`DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES`默认是关闭的**。这里简单说下原因：

 以springboot为例，如果在编码时没提供自定义的配置，会遵循springboot的默认配置，主要是在`org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration`类进行配置，这里通过`Jackson2ObjectMapperBuilder`来创建ObjectMapper：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-65a56c135d31c292c43502d756e56fae3e84ff9b.png)

 如果没有额外的配置的话，会使用默认的Jackson2ObjectMapperBuilder，查看具体build()的实现：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-1c39c494e4e4c02483d37b0ffca6031a277ca64b.png)

 在configure方法里进行了相关的配置，这里通过调用customizeDefaultFeatures()配置了一些feature：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-26609b6d8c8a766f258cd9ecc7fd152566852f89.png)

 继续查看customizeDefaultFeatures方法的具体实现，可以看到这里**将`DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES`设置成了false，Jackson的属性对齐特性不生效了，也就应证了前面增加了新的无关属性后，依旧正常解析的现象了**：

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/06/attach-c7d418cb6f4e08fc52e51d284fffd46cfc3504a2.png)

 所以想要在Spring/Sping Boot环境下区分使用的是哪个解析器，需要另辟蹊径。

0x04 其他
=======

 除此以外，虽然说大多数都是使用的Jackson/Fastjson，但是不排除还有使用gson等其他解析库的。一些Feature同样的会有影响，例如标准JSON里面是不能包含换行符的（必须以\\n表示），但是Fastjson和gson都是支持的，这里也会引入一些干扰项。总的来说，通过上述的一些技巧在一定程度上还是能进行区分的。