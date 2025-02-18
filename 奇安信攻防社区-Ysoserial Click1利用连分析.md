`click1 gadget`构造思路是基于`Commons-Collections2`的Sink点`（com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl）`和source点`（java.util.PriorityQueue）`。`Commons-Collections2`使用`TransformingComparator`方法作为`PriorityQueue`类中的`comparator`属性值。再`Click1 gadget`中，作者使用`org.apache.click.control.Column$ColumnComparator`类作为替代。在`Commons-Collections2`分析中，可知`java.util.PriorityQueue`反序列化可以调用`org.apache.click.control.Column$ColumnComparator#compare`方法。

```php
public int compare(Object row1, Object row2) {
    this.ascendingSort = this.column.getTable().isSortedAscending() ? 1 : -1;
    Object value1 = this.column.getProperty(row1);
    Object value2 = this.column.getProperty(row2);
    if (value1 instanceof Comparable && value2 instanceof Comparable) {
        return !(value1 instanceof String) && !(value2 instanceof String) ? ((Comparable)value1).compareTo(value2) * this.ascendingSort : this.stringCompare(value1, value2) * this.ascendingSort;
    } else if (value1 != null && value2 != null) {
        return value1.toString().compareToIgnoreCase(value2.toString()) * this.ascendingSort;
    } else if (value1 != null && value2 == null) {
        return 1 * this.ascendingSort;
    } else {
        return value1 == null && value2 != null ? -1 * this.ascendingSort : 0;
    }
}
```

其中`compare`方法传入的参数，即是构造好的恶意`TemplatesImpl`对象。  
[![](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d6600e49f8c5bc966e28a102926e2cb640018459.png)](https://shs3.b.qianxin.com/attack_forum/2021/11/attach-d6600e49f8c5bc966e28a102926e2cb640018459.png)  
调用`this.column.getProperty(row1)`方法

```php
public Object getProperty(Object row) {
    return this.getProperty(this.getName(), row);
}
```

调用`this.getName()`方法获取`Column#name`属性值，并调用`this.getProperty(name , row)`方法。

```php
public Object getProperty(String name, Object row) {
    if (row instanceof Map) {
        Map map = (Map)row;
        Object object = map.get(name);
        if (object != null) {
            return object;
        } else {
            String upperCaseName = name.toUpperCase();
            object = map.get(upperCaseName);
            if (object != null) {
                return object;
            } else {
                String lowerCaseName = name.toLowerCase();
                object = map.get(lowerCaseName);
                return object != null ? object : null;
            }
        }
    } else {
        if (this.methodCache == null) {
            this.methodCache = new HashMap();
        }

        return PropertyUtils.getValue(row, name, this.methodCache);
    }
}
```

由于传入的`TemplatesImpl`对象不是`Map`的子类，直接跳过if判断，在为`methodCache`属性初始化`HashMap`类型对象后，调用`PropertyUtils.getValue(row, name, this.methodCache)`方法。

```php
public static Object getValue(Object source, String name, Map cache) {
    String basePart = name;
    String remainingPart = null;
    if (source instanceof Map) {
        return ((Map)source).get(name);
    } else {
        int baseIndex = name.indexOf(".");
        if (baseIndex != -1) {
            basePart = name.substring(0, baseIndex);
            remainingPart = name.substring(baseIndex + 1);
        }

        Object value = getObjectPropertyValue(source, basePart, cache);
        return remainingPart != null && value != null ? getValue(value, remainingPart, cache) : value;
    }
}
```

首先将传入的name参数值赋给`basePart`变量。并在调用`getObjectPropertyValue`方法时，作为参数传入。

```php
private static Object getObjectPropertyValue(Object source, String name, Map cache) {
    PropertyUtils.CacheKey methodNameKey = new PropertyUtils.CacheKey(source, name);
    Method method = null;

    try {
        method = (Method)cache.get(methodNameKey);
        if (method == null) {
            method = source.getClass().getMethod(ClickUtils.toGetterName(name));
            cache.put(methodNameKey, method);
        }

        return method.invoke(source);
    } catch (NoSuchMethodException var13) {
        try {
            method = source.getClass().getMethod(ClickUtils.toIsGetterName(name));
            cache.put(methodNameKey, method);
            return method.invoke(source);
        } catch (NoSuchMethodException var11) {
            String msg;
            try {
                method = source.getClass().getMethod(name);
                cache.put(methodNameKey, method);
                return method.invoke(source);
            } catch (NoSuchMethodException var9) {
                msg = "No matching getter method found for property '" + name + "' on class " + source.getClass().getName();
                throw new RuntimeException(msg);
            } catch (Exception var10) {
                msg = "Error getting property '" + name + "' from " + source.getClass();
                throw new RuntimeException(msg, var10);
            }
        } catch (Exception var12) {
            String msg = "Error getting property '" + name + "' from " + source.getClass();
            throw new RuntimeException(msg, var12);
        }
    } catch (Exception var14) {
        String msg = "Error getting property '" + name + "' from " + source.getClass();
        throw new RuntimeException(msg, var14);
    }
}
```

由于`cache`是初始化的`HashMap`对象，所以从`catch`中获取不到任何缓存方法，因此会调用`source.getClass().getMethod(ClickUtils.toGetterName(name))`方法。

```php
public static String toGetterName(String property) {
    HtmlStringBuffer buffer = new HtmlStringBuffer(property.length() + 3);
    buffer.append("get");
    buffer.append(Character.toUpperCase(property.charAt(0)));
    buffer.append(property.substring(1));
    return buffer.toString();
}
```

此方法是为传入的`property`属性头部添加"get"三个字符，并返回，因此回到`getObjectPropertyValue`方法，调用`method.invoke(source)`方法时，method参数值对应的是"get" + 传入的name变量。在上述的分析中，name变量值是由`Column#name`属性值决定的。因此控制`Column#name`属性值，可以调用任意类中以"get"为首的无参方法。  
对于`Column#name`属性的控制也比较简单，通过调用`Column`构造方法即可。

```php
public Column(String name) {
    if (name == null) {
        throw new IllegalArgumentException("Null name parameter");
    } else {
        this.name = name;
    }
}
```

根据`Commons-Collections2`中，最终触发RCE，还需要调用`TemplatesImpl#newTransformer`方法。而恰巧在`TemplatesImpl#getOutputProperties`方法中会调用到`newTransformer`方法，从而触发自定义恶意类的初始化。

```php
public synchronized Properties getOutputProperties() {
    try {
        return newTransformer().getOutputProperties();
    }
    catch (TransformerConfigurationException e) {
        return null;
    }
}
```

至此，利用链构造完成。