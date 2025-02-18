2024qwb
=======

mips
----

作者用qemu模拟器加载mips\_bin文件并手动实现了hook

我们只解mips\_bin文件的话会解出一个假的flag

ida,alt+t直接搜索 23000，定位到关键函数的位置

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-4852408b19910733f09fe1579c52d82ab6f179d8.png)

交叉引用的话，可以发现程序对flag头与flag的长度进行了检查

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-51e11534d0c8aa48438c674620f25d33f0f913c3.png)  
之后程序对字符串进行了一个魔改的rc4加密，同时进行了一个异或操作

给出解密脚本:

```php
#include <stdio.h>
#include <malloc.h>
#include "h_IDA.h"

unsigned char N_str[] = {0xDE, 0xAD, 0xBE, 0xEF};
unsigned char map1[256] ;
unsigned char map2[256] ;
void swap(unsigned char *inp, int x, int y) {
  unsigned char ch = inp[x];
  inp[x] = inp[y];
  inp[y] = ch;
}

void init(){
    for (int i = 0; i < 256; i++) {
            unsigned char v3 = ((((unsigned char)(i << 7) | (i >> 1)) << 6) ^ 0xC0 |((unsigned char)((i << 7) | (i >> 1)) >> 2) ^ 0x3B) ^0xBE;
            unsigned char out =(((unsigned char)(((16 * (((32 * v3) | (v3 >> 3)) ^ 0xAD)) | ((unsigned char)(((32 * v3) | (v3 >> 3)) ^ 0xAD) >>4)) ^ 0xDE) >>5) | (8 * (((16 * (((32 * v3) | (v3 >> 3)) ^ 0xAD)) |((unsigned char)(((32 * v3) | (v3 >> 3)) ^ 0xAD) >> 4)) ^ 0xDE)));
            map1[out] = i;
            map2[i] = out;
    }
//    for(int i=0;i<256;i++){
//      printf("0x%x ",map1[i]);
//  }
//  puts("");
//    for(int i=0;i<256;i++){
//      printf("0x%x ",map2[i]);
//  }
//  puts("");
}

unsigned char *__fastcall en_rc4(unsigned __int8 *inp)
{
  int x_1; // edx
  unsigned __int8 v3; // [rsp+15h] [rbp-17Bh]
  int i; // [rsp+18h] [rbp-178h]
  int y; // [rsp+1Ch] [rbp-174h]
  unsigned int i_1; // [rsp+20h] [rbp-170h]
  int x; // [rsp+24h] [rbp-16Ch]
  int v8; // [rsp+28h] [rbp-168h]
  int j; // [rsp+2Ch] [rbp-164h]
  int a; // [rsp+30h] [rbp-160h]
  int j_1; // [rsp+34h] [rbp-15Ch]
  int aa; // [rsp+3Ch] [rbp-154h]
  char *key; // [rsp+40h] [rbp-150h]
  unsigned __int8 *output; // [rsp+48h] [rbp-148h]
  unsigned __int8 m[256]; // [rsp+80h] [rbp-110h] BYREF
  __int16 v16; // [rsp+180h] [rbp-10h]
  unsigned __int64 v17; // [rsp+188h] [rbp-8h]

  memset(m, 0, sizeof(m));
  v16 = 0;
  for ( i = 0; i <= 255; ++i )
    m[i] = i;
  y = 0;
  i_1 = 0;
  key = "6105t3";
  do
  {
    a = m[i_1];
    j_1 = (unsigned __int8)(key++)[(int)(2 * (i_1 / 6 - (((0xAAAAAAAB * (unsigned __int64)i_1) >> 32) & 0xFFFFFFFC)))];
    y += a + j_1;
    x_1 = i_1++;
    m[x_1] = m[(unsigned __int8)y];
    m[(unsigned __int8)y] = a;
  }
  while ( i_1 != 256 );

  x = 0;
  v8 = 0;
  output = (unsigned __int8 *)malloc(256LL);
  for ( j = 0; j != 22; ++j )
  {
    aa = m[(unsigned __int8)++x];
    v8 += aa;
    m[(unsigned __int8)x] = m[(unsigned __int8)v8];
    m[(unsigned __int8)v8] = aa;

    output[j] = m[(unsigned char)(m[x] + m[v8])] ^ N_str[j & 3] ^ map2[inp[j + 5]];

  }
  return output;
}

unsigned char *__fastcall de_rc4(unsigned __int8 *inp)
{
  int x_1; // edx
  unsigned __int8 v3; // [rsp+15h] [rbp-17Bh]
  int i; // [rsp+18h] [rbp-178h]
  int y; // [rsp+1Ch] [rbp-174h]
  unsigned int i_1; // [rsp+20h] [rbp-170h]
  unsigned char x; // [rsp+24h] [rbp-16Ch]
  unsigned char v8; // [rsp+28h] [rbp-168h]
  int j; // [rsp+2Ch] [rbp-164h]
  int a; // [rsp+30h] [rbp-160h]
  int j_1; // [rsp+34h] [rbp-15Ch]
  int aa; // [rsp+3Ch] [rbp-154h]
  char *key; // [rsp+40h] [rbp-150h]
  unsigned __int8 *output; // [rsp+48h] [rbp-148h]
  unsigned __int8 m[256]; // [rsp+80h] [rbp-110h] BYREF
  __int16 v16; // [rsp+180h] [rbp-10h]
  unsigned __int64 v17; // [rsp+188h] [rbp-8h]

  memset(m, 0, sizeof(m));
  v16 = 0;
  for ( i = 0; i <= 255; ++i )
    m[i] = i;
  y = 0;
  i_1 = 0;
  key = "6105t3";
  do
  {
    a = m[i_1];
    j_1 = (unsigned __int8)(key++)[(int)(2 * (i_1 / 6 - (((0xAAAAAAAB * (unsigned __int64)i_1) >> 32) & 0xFFFFFFFC)))];
    y += a + j_1;
    x_1 = i_1++;
    m[x_1] = m[(unsigned __int8)y];
    m[(unsigned __int8)y] = a;
  }
  while ( i_1 != 256 );
    for(int i=0;i<256;i++){
    printf("0x%x ",m[i]);
  }
  puts("");

  x = 0;
  v8 = 0;
  output = (unsigned __int8 *)malloc(256LL);
  for ( j = 0; j != 22; ++j )
  {
    aa = m[(unsigned __int8)++x];
    v8 += aa;

    m[(unsigned __int8)x] = m[(unsigned __int8)v8];
    m[(unsigned __int8)v8] = aa;

    output[j] = map1[ m[(unsigned char)(m[x] + m[v8])] ^ N_str[j & 3]  ^ inp[j]];   
//  printf("0x%x - 0x%x - 0x%x", m[(unsigned char)(m[x] + m[v8])], N_str[j & 3],inp[j]);

  }
  puts("");
  return output;
}

int main(){
    init();
    unsigned char cip[] = {0x000000C4, 0x000000EE, 0x0000003C, 0x000000BB, 0x000000E7, 0x000000FD, 0x00000067, 0x0000001D, 0x000000F8, 0x00000097, 0x00000068, 0x0000009D, 0x0000000B, 0x0000007F, 0x000000C7, 0x00000080, 0x000000DF, 0x000000F9, 0x0000004B, 0x000000A0, 0x00000046, 0x00000091};
      swap(cip, 12, 16);
      swap(cip, 7, 11);
  for (int i = 0; i < 22; i++) {
    cip[i] ^= 0xa;
  }
    unsigned char *m = de_rc4(cip);

    printf("flag{");
    for (int i = 0; i < 22; i++) {
      printf("%c", (unsigned char)m[i]);
    }

    return 0;
}

// flag{QeMu_r3v3rs3in9_h@ck6}
```

其中 异或的值有反调试，调试或者attach状态下都拿不到，我们可以尝试爆破、patch、epbftrace等方法拿到

patch的话，就像这样:

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-af886b9c0544e7efb2a360dc2b8af819f4266a5a.png)

patch出一个write系统调用

bpbftrace命令如下：

```php
sudo bpftrace -e '
watchpoint:0x0007FFFF76FF942:8:x 
{ 
    $addr = 0x0007FFFF7FF4324;
    printf("before rc4 watch n_STR and input \n");
    @i = 0;
    printf("n_STR: ");
    unroll (4) {
        printf("%02x,", *(uint8*)($addr + @i));
        @i++;
    }
    printf("\n");

}
' -p pid
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-fb06b8655136931832f0787dbc31497acfa35bdb.png)

remem
-----

先修elf文件，之后调试程序，注意到程序每次都会mmap，并且把shellcode放入mmap内存中执行，之后销毁，在固定基址后，mmap申请的位置是固定的，我们可以获取到每个mmap的shellcode片段，整理下来如下:

0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 61626364h  
0x7F722B88300C: mul rax  
0x7F722B88300F: leaveq  
0x7F722B883011: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 250BB52207267F10h  
0x7F722B88300F: mov rbx, 3  
0x7F722B883016: mul rbx  
0x7F722B883019: leaveq  
0x7F722B88301B: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 61626364h  
0x7F722B88300C: mov rbx, 65666768h  
0x7F722B883013: mul rbx  
0x7F722B883016: leaveq  
0x7F722B883018: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 2692C5C033CD9CA0h  
0x7F722B88300F: mov rbx, 6  
0x7F722B883016: mul rbx  
0x7F722B883019: leaveq  
0x7F722B88301B: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 65666768h  
0x7F722B88300C: mov rbx, 52h ; 'R'  
0x7F722B883013: mul rbx  
0x7F722B883016: leaveq  
0x7F722B883018: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 65666768h  
0x7F722B88300C: mov rbx, 6  
0x7F722B883013: mul rbx  
0x7F722B883016: leaveq  
0x7F722B883018: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 61626364h  
0x7F722B88300C: mul rax  
0x7F722B88300F: leaveq  
0x7F722B883011: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 250BB52207267F10h  
0x7F722B88300F: mov rbx, 2  
0x7F722B883016: mul rbx  
0x7F722B883019: leaveq  
0x7F722B88301B: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 65666768h  
0x7F722B88300C: mov rbx, 0Dh  
0x7F722B883013: mul rbx  
0x7F722B883016: leaveq  
0x7F722B883018: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 61626364h  
0x7F722B88300C: mov rbx, 11h  
0x7F722B883013: mul rbx  
0x7F722B883016: leaveq  
0x7F722B883018: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 61626364h  
0x7F722B88300C: mov rbx, 696A6B6Ch  
0x7F722B883013: mul rbx  
0x7F722B883016: leaveq  
0x7F722B883018: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 2819D65E6074BA30h  
0x7F722B88300F: mov rbx, 5  
0x7F722B883016: mul rbx  
0x7F722B883019: leaveq  
0x7F722B88301B: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 696A6B6Ch  
0x7F722B88300C: mul rax  
0x7F722B88300F: leaveq  
0x7F722B883011: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 2B68785BBA837590h  
0x7F722B88300F: mov rbx, 5  
0x7F722B883016: mul rbx  
0x7F722B883019: leaveq  
0x7F722B88301B: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 696A6B6Ch  
0x7F722B88300C: mov rbx, 58h ; 'X'  
0x7F722B883013: mul rbx  
0x7F722B883016: leaveq  
0x7F722B883018: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 6D6E6F70h  
0x7F722B88300C: mov rbx, 696A6B6Ch  
0x7F722B883013: mul rbx  
0x7F722B883016: leaveq  
0x7F722B883018: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 2D0FC95A678AD340h  
0x7F722B88300F: mov rbx, 4  
0x7F722B883016: mul rbx  
0x7F722B883019: leaveq  
0x7F722B88301B: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 696A6B6Ch  
0x7F722B88300C: mul rax  
0x7F722B88300F: leaveq  
0x7F722B883011: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 2B68785BBA837590h  
0x7F722B88300F: mov rbx, 5  
0x7F722B883016: mul rbx  
0x7F722B883019: leaveq  
0x7F722B88301B: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 6D6E6F70h  
0x7F722B88300C: mov rbx, 0E8h  
0x7F722B883013: mul rbx  
0x7F722B883016: leaveq  
0x7F722B883018: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 6D6E6F70h  
0x7F722B88300C: mul rax  
0x7F722B88300F: leaveq  
0x7F722B883011: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 2EC73A8954C25100h  
0x7F722B88300F: mov rbx, 23h ; '#'  
0x7F722B883016: mul rbx  
0x7F722B883019: leaveq  
0x7F722B88301B: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 71727374h  
0x7F722B88300C: mov rbx, 8  
0x7F722B883013: mul rbx  
0x7F722B883016: leaveq  
0x7F722B883018: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 71727374h  
0x7F722B88300C: mul rax  
0x7F722B88300F: leaveq  
0x7F722B883011: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 32463D176F616C90h  
0x7F722B88300F: mov rbx, 10h  
0x7F722B883016: mul rbx  
0x7F722B883019: leaveq  
0x7F722B88301B: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 38B939BA0h  
0x7F722B88300F: mov rbx, 2463D176F616C900h  
0x7F722B883019: add rax, rbx  
0x7F722B88301C: leaveq  
0x7F722B88301E: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 2463D17A81AA64A0h  
0x7F722B88300F: mov rbx, 653D00C696911300h  
0x7F722B883019: sub rax, rbx  
0x7F722B88301C: leaveq  
0x7F722B88301E: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 0BF26D0B3EB1951A0h  
0x7F722B88300F: mov rbx, 5E2F4391h  
0x7F722B883016: xor rdx, rdx  
0x7F722B883019: div rbx  
0x7F722B88301C: mov rax, rdx  
0x7F722B88301F: leaveq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 0D90A59CAA4914BD0h  
0x7F722B88300F: mov rbx, 632C14FD80h  
0x7F722B883019: add rax, rbx  
0x7F722B88301C: leaveq  
0x7F722B88301E: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 0D90A5A2DD0A64950h  
0x7F722B88300F: mov rbx, 0B43F25699E2B4D00h  
0x7F722B883019: sub rax, rbx  
0x7F722B88301C: leaveq  
0x7F722B88301E: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 24CB34C4327AFC50h  
0x7F722B88300F: mov rbx, 5E2F4391h  
0x7F722B883016: xor rdx, rdx  
0x7F722B883019: div rbx  
0x7F722B88301C: mov rax, rdx  
0x7F722B88301F: leaveq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 0D90A59CAA4914BD0h  
0x7F722B88300F: mov rbx, 243C94ED20h  
0x7F722B883019: add rax, rbx  
0x7F722B88301C: leaveq  
0x7F722B88301E: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 0D90A59EEE12638F0h  
0x7F722B88300F: mov rbx, 0C8812FD7E247A2F0h  
0x7F722B883019: sub rax, rbx  
0x7F722B88301C: leaveq  
0x7F722B88301E: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 10892A16FEDE9600h  
0x7F722B88300F: mov rbx, 5E2F4391h  
0x7F722B883016: xor rdx, rdx  
0x7F722B883019: div rbx  
0x7F722B88301C: mov rax, rdx  
0x7F722B88301F: leaveq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 526334048h  
0x7F722B88300F: mov rbx, 6778899A4h  
0x7F722B883019: add rax, rbx  
0x7F722B88301C: leaveq  
0x7F722B88301E: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 4A176A440E4CFE20h  
0x7F722B88300F: mov rbx, 0B9DBBD9ECh  
0x7F722B883019: add rax, rbx  
0x7F722B88301C: leaveq  
0x7F722B88301E: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 4A176A4FAC08D80Ch  
0x7F722B88300F: mov rbx, 5E2F4391h  
0x7F722B883016: xor rdx, rdx  
0x7F722B883019: div rbx  
0x7F722B88301C: mov rax, rdx  
0x7F722B88301F: leaveq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 207ACD1F50h  
0x7F722B88300F: mov rbx, 260666C70h  
0x7F722B883019: add rax, rbx  
0x7F722B88301C: leaveq  
0x7F722B88301E: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 0E770A28136D1ABC0h  
0x7F722B88300F: mov rbx, 22DB338BC0h  
0x7F722B883019: add rax, rbx  
0x7F722B88301C: leaveq  
0x7F722B88301E: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 0E770A2A412053780h  
0x7F722B88300F: mov rbx, 6F231F6615737D30h  
0x7F722B883019: sub rax, rbx  
0x7F722B88301C: leaveq  
0x7F722B88301E: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 784D833DFC91BA50h  
0x7F722B88300F: mov rbx, 5E2F4391h  
0x7F722B883016: xor rdx, rdx  
0x7F722B883019: div rbx  
0x7F722B88301C: mov rax, rdx  
0x7F722B88301F: leaveq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 286A77D6h  
0x7F722B88300C: mov rbx, 42DB9F06h  
0x7F722B883013: xor rax, rbx  
0x7F722B883016: leaveq  
0x7F722B883018: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 5E867B43h  
0x7F722B88300C: mov rbx, 35368926h  
0x7F722B883013: xor rax, rbx  
0x7F722B883016: leaveq  
0x7F722B883018: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 3AB4599Bh  
0x7F722B88300C: mov rbx, 509A3978h  
0x7F722B883013: xor rax, rbx  
0x7F722B883016: leaveq  
0x7F722B883018: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 43D5705Dh  
0x7F722B88300C: mov rbx, 1EBFA92Fh  
0x7F722B883013: xor rax, rbx  
0x7F722B883016: leaveq  
0x7F722B883018: retnq  
​  
0x7F722B883000: push rbp  
0x7F722B883002: mov rbp, rsp  
0x7F722B883005: mov rax, 464560F0h  
0x7F722B88300C: mov rbx, 555CC98Ch  
0x7F722B883013: xor rax, rbx  
0x7F722B883016: leaveq  
0x7F722B883018: retnq  
​

之后编写vm解析器:

```php
from capstone import *

opcode=[0x0F2,0x0,0x0F2,0x3,0x0F7,0x0F2,0x3,0x0F2,0x3,0x0F7,0x0F2,
3,0x0F7,0x0F2,0x3,0x0F7,0x0F2,0x0,0x0F2,0x3,0x0F7,0x0F2,
3,0x0F7,0x0F2,0x3,0x0F7,0x0F2,0x3,0x0F2,0x3,0x0F7,0x0F2,
0,0x0F2,0x3,0x0F7,0x0F2,0x3,0x0F7,0x0F2,0x3,0x0F2,0x3,0x0F7,
0x0F2,0x0,0x0F2,0x3,0x0F7,0x0F2,0x3,0x0F7,0x0F2,0x0,0x0F2,
3,0x0F7,0x0F2,0x3,0x0F7,0x0F2,0x0,0x0F2,0x3,0x0F7,0x0F0,
0,0x3,0x0F1,0x0,0x3,0x0F6,0x3,0x0F0,0x0,0x3,0x0F1,0x0,0x3,0x0F6,
3,0x0F0,0x0,0x3,0x0F1,0x0,0x3,0x0F6,0x3,0x0F0,0x0,0x3,0x0F0,
0,0x3,0x0F6,0x3,0x0F0,0x0,0x3,0x0F0,0x0,0x3,0x0F1,0x0,0x3,0x0F6,
3,0x0F7,0x0F3,0x0,0x3,0x0F3,0x0,0x3,0x0F3,0x0,0x3,0x0F3,0x0,
3,0x0F3,0x0,0x3,0x0F8]

arr=[0]*11
arr[0] = 0x61626364
arr[1] = 0x65666768
arr[2] = 0x69707172
arr[3] = 0x73747576
arr[4] = 0x7778797A
arr[5] = 0x5E2F4391
arr[6] = 0x42DB9F06
arr[7] = 0x35368926
arr[8] = 0x509A3978
arr[9] = 0x1EBFA92F
arr[10] = 0x555CC98C

v16=[0]*18
v16[0] = arr[0]
v16[1] = arr[0]
v16[2] = arr[1]
v16[3] = arr[1]
v16[4] = arr[0]
v16[5] = arr[1]
v16[6] = arr[0]
v16[7] = arr[0]
v16[8] = arr[2]
v16[9] = arr[2]
v16[10] = arr[3]
v16[11] = arr[2]
v16[12] = arr[3]
v16[13] = arr[3]
v16[14] = arr[4]
v16[15] = arr[4]
v16[16] = 0
v16[17] = 0
v15=[0]*6
ptr=[0]*9

v13 = 1
v14 = arr[0]
v10 = 0
v11 = 0
rip=0

while True:
    if opcode[rip] == 0xF0:
        v10-=1
        # v0 = v16[v10 + 18]
        print(f'{rip} v0 = v16[{v10+18}]')
        v10-=1
        # v1 = func0(v16[v10 + 18], v0)
        print(f'{rip} v1=func0(v16[{v10+18},v0])')
        # v16[v10 + 18] = v1
        print(f'{rip} v16[{v10+18}] = v1')
        v10+=1
        rip += 3
        # print('F0',end=' ')
#         
    elif opcode[rip] == 0xF1:
        v10-=1
#         v2 = v16[v10 + 18]
        print(f'{rip} v2 = v16[{v10+18}]')
        v10-=1
#         v3 = func1(v16[v10 + 18], v2)
        print(f'{rip} v3=func1(v16[{v10+18},v2])')
#         v16[v10 + 18] = v3
        print(f'{rip} v16[{v10+18}] = v3')
        v10+=1
        rip += 3
        # print('F1',end=' ')
#         
    if opcode[rip] == 0xF2:
        # v14=func2(v14)  
        print(f'{rip} v14=func2(v14)')                  
        rip += 2
        # print('F2',end=' ')
    elif opcode[rip] == 0xF3:
        v11-=1
#         v14 = func3(v14 ^ v15[v11])
        print(f'{rip} v14=func3(v14^v15[{v11}])')
        rip += 3
        # print('F3',end=' ')
#         
    elif opcode[rip] == 0xF5:
        v10-=1
#         v4 = v16[v10 + 18]
        print(f'{rip} v4 = v16[{v10+18}]')
        v10-=1
#         v14 = func4(v16[v10 + 18], v4)
        print(f'{rip} v14=func5(v16[{v10+18},v4])')
        rip += 3
        # print('F5',end=' ')
#         
    elif opcode[rip] == 0xF6:
        v10-=1
        print(f'{rip} v5=func5(v16[{v10+18},{hex(arr[5])}])')
        print(f'{rip} v15[{v11}] = v5')
#         v5 = func5(v16[v10 + 18], arr[5]%0xffffffff)
#         v15[v11] = v5
        rip += 2
        v11+=1
        # print('F6',end=' ')
#         
    elif opcode[rip] == 0xF7:
        v6 = v10
        v10+=1
        # v16[v6 + 18] = v14
        print(f"{rip} v16[{v6+18}] = v14")
        v7 = v13
        v13+=1
        # v14 = v16[v7]
        print(f"{rip} v14 = v16[{v7}]")
        rip+=1
    elif opcode[rip] == 0xF8:
        print('F8',end=' ')
        break
#         if v14!=0:
#             print('fail!')

# F2 F2 F7 F2 F2 F7 F2 F7 F2 F7 F2 F2 F7 F2 F7 F2 F7 F2 F2 F7 F2 F2 F7 F2 F7 F2 F2 F7 F2 F2 F7 F2 F7 F2 F2 F7 F2 F7 F2 F2 F7 F0 F1 F6 F0 F1 F6 F0 F1 F6 F0 F0 F6 F0 F0 F1 F6 F7 F3 F3 F3 F3 F3 F8
```

得到:

```php
0 v14=func2(v14)                // v14 = part1 * part1
2 v14=func2(v14)                // v14 = v14 * 3
4 v16[18] = v14                        // v16[18] = v14                    ==> 0x6f231f6615737d30
4 v14 = v16[1]                        // v14 = part1
5 v14=func2(v14)                // v14 = part1 * part2
7 v14=func2(v14)                // v14 = v14 * 6
9 v16[19] = v14                        // v16[19] = v14
9 v14 = v16[2]                        // v14 = part2
10 v14=func2(v14)                // v14 = part2 * 0x52
12 v16[20] = v14                // v16[20] = v14
12 v14 = v16[3]                        // v14 = part2
13 v14=func2(v14)                // v14 = part2*6
15 v16[21] = v14                // v16[21] = v14
15 v14 = v16[4]                        // v14 = v16[4]
16 v14=func2(v14)                // v14 = part1 * part1
18 v14=func2(v14)                // v14 = v14 * 2
20 v16[22] = v14                // v16[22] = v14
20 v14 = v16[5]                        // v14 = v16[5]
21 v14=func2(v14)                // v14 = part2 * 0xd
23 v16[23] = v14                // v16[23] = v14
23 v14 = v16[6]                        // v14 = v16[6]        
24 v14=func2(v14)                // v14 = part1 * 0x11
26 v16[24] = v14                // v16[24] = v14
26 v14 = v16[7]                        // v14 = v16[7]
27 v14=func2(v14)                // v14 = part1 * part3 
29 v14=func2(v14)                // v14 = v14 * 5
31 v16[25] = v14                // v16[25] = v14
31 v14 = v16[8]                        // v14 = v16[8]
32 v14=func2(v14)                // v14 = part3 * part3
34 v14=func2(v14)                // v14 = v14 * 5
36 v16[26] = v14                // v16[26] = v14
36 v14 = v16[9]                        // v14 = v16[9]        
37 v14=func2(v14)                // v14 = part3 * 0x58
39 v16[27] = v14                // v16[27] = v14
39 v14 = v16[10]                // v14 = v16[10]
40 v14=func2(v14)                // v14 = part3 * part4
42 v14=func2(v14)                // v14 *= 4;
44 v16[28] = v14                // v16[28] = v14
44 v14 = v16[11]                // v14 = v16[11]
45 v14=func2(v14)                // v14 = part3 * part3
47 v14=func2(v14)                // v14 *= 5
49 v16[29] = v14                // v16[29] = v14
49 v14 = v16[12]                // v14 = v16[12]
50 v14=func2(v14)                // v14 = part4 * 0xE8
52 v16[30] = v14                // v16[30] = v14        
52 v14 = v16[13]                // v14 = v16[13]
53 v14=func2(v14)                // v14 = part4 * part4
55 v14=func2(v14)                // v14 = v14 * 0x23
57 v16[31] = v14                //  v16[31] = v14
57 v14 = v16[14]                // v14 = v16[14]
58 v14=func2(v14)                // v14 = part5 * 8
60 v16[32] = v14                // v16[32] = v14
60 v14 = v16[15]                // v14 = v16[15]
61 v14=func2(v14)                // v14 = part5*part5
63 v14=func2(v14)                // v14 = v14 * 0x10
65 v16[33] = v14                // v16[33] = v14
65 v14 = v16[16]                // v14 = v16[16]
66 v0 = v16[33]                        // v0 = v16[33]        
66 v1=func0(v16[32,v0])        // v1 = v16[32] + v16[33]
66 v16[32] = v1                        // v16[32] = v1        
69 v2 = v16[32]                        // v2 = v16[32]
69 v3=func1(v16[31,v2])                                // v3=v16[32] - v16[31]        
69 v16[31] = v3                                                // v16[31] = v3
72 v5=func5(v16[31,0x5e2f4391])                // v5 = v16[31] % 0x5e2f4391
72 v15[0] = v5                                                // v15[0] = v5
74 v0 = v16[30]                                                // v0 = v16[30]
74 v1=func0(v16[29,v0])                                // v1 = v16[29]  +v16[30]
74 v16[29] = v1                                                // v16[29] = v1
77 v2 = v16[29]                                                // v2 = v16[29]        
77 v3=func1(v16[28,v2])                                // v3 =v16[29]        -v16[28] 
77 v16[28] = v3                                                // v16[28] = v3                        
80 v5=func5(v16[28,0x5e2f4391])                // v5 = v3 % 0x5e2f4391
80 v15[1] = v5                                                // v15[1] = v5                
82 v0 = v16[27]                                                // v0 = v16[27]
82 v1=func0(v16[26,v0])                                // v1 = v16[26] + v16[27]
82 v16[26] = v1                                                // v16[26] = v1                
85 v2 = v16[26]                                                // v2 = v16[26]        
85 v3=func1(v16[25,v2])                                // v3 = v16[26] - v16[25]
85 v16[25] = v3                                                // v16[25] = v3
88 v5=func5(v16[25,0x5e2f4391])                        // v5 =v16[25] %  0x5e2f4391
88 v15[2] = v5                                                        // v15[2] = v5
90 v0 = v16[24]                                                        // v0 = v16[24]
90 v1=func0(v16[23,v0])                                        // v1 = v16[23] + v16[24]
90 v16[23] = v1                                                        // v16[23] = v1        
93 v0 = v16[23]                                                        // v0 = v16[23]        
93 v1=func0(v16[22,v0])                                        // v1 = v16[22] + v16[23]
93 v16[22] = v1                                                        // v16[22] = v1
96 v5=func5(v16[22,0x5e2f4391])                        // v5 = v16[22] % 0x5e2f4391
96 v15[3] = v5                                                        // v15[3] = v5        
98 v0 = v16[21]                                                        // v0 = v16[21]
98 v1=func0(v16[20,v0])                                        // v1 = v16[21] + v16[20]
98 v16[20] = v1                                                        // v16[20] = v1        
101 v0 = v16[20]                                                // v0 = v16[20]                
101 v1=func0(v16[19,v0])                                // v1 = v16[19] + v16[20]
101 v16[19] = v1                                                // v16[19] = v1        
104 v2 = v16[19]                                                // v2 = v16[19]        
104 v3=func1(v16[18,v2])                                // v3 = v16[19] - v16[18]
104 v16[18] = v3                                                // v16[18] = v3                
107 v5=func5(v16[18,0x5e2f4391])                // v5 = v16[18] % 0x5e2f4391
107 v15[4] = v5                                                        // v15[4] = v5                
109 v16[18] = v14                                                // v16[18] = v14
109 v14 = v16[17]                                                // v14 = v16[17]        
110 v14=func3(v14^v15[4])                                // v14 = v16[17] ^ v15[4] ^ 0x42DB9F06
113 v14=func3(v14^v15[3])                                // v14 = v14 ^ v15[3] ^ 0x35368926
116 v14=func3(v14^v15[2])                                // v14 = v14 ^ v15[2] ^ 0x509A3978
119 v14=func3(v14^v15[1])                                // v14 = v14 ^ v15[1] ^ 0x1EBFA92F
122 v14=func3(v14^v15[0])                                // v14 = v14 ^ v15[0] ^ 0x555CC98C
```

分析写出c语言代码:

```php
#include <stdio.h>
unsigned char inp[100] = {0};
unsigned long long int part1,part2,part3,part4,part5;
unsigned long long int v14;
unsigned long long int v16[100];
unsigned long long int v0,v1,v2,v3,v4,v5,v6;
unsigned long long int v15[10];
int main(){                  
        // 0x61626364 0x65666768 0x696A6B6C 0x6D6E6F70 0x71727374
//        scanf("%s",inp);                            
        scanf("%x",&part1);
        scanf("%x",&part2);
        scanf("%x",&part3);
        scanf("%x",&part4);
        scanf("%x",&part5);
//        printf("0x%x\n",part1);
//        printf("0x%x\n",part2);
//        printf("0x%x\n",part3);
//        printf("0x%x\n",part4);
//        printf("0x%x\n",part5);
//        part1 = inp
        v14 = part1 * part1;                                 ;
        v14 = v14 * 3;                                       ;
        v16[18] = v14;                                       ;
        v14 = part1;                                         ;
        v14 = part1 * part2;                                 ;
        v14 = v14 * 6;                                       ;
        v16[19] = v14;                                       ;
        v14 = part2;                                         ;
        v14 = part2 * 0x52;                                  ;
        v16[20] = v14;                                       ;
        v14 = part2                                          ;
        v14 = part2*6                                        ;
        v16[21] = v14                                        ;
        v14 = v16[4]                                         ;
        v14 = part1 * part1                                  ;
        v14 = v14 * 2                                        ;
        v16[22] = v14                                        ;
        v14 = v16[5]                                         ;
        v14 = part2 * 0xd                                    ;
        v16[23] = v14                                        ;
        v14 = v16[6]                                             ;
        v14 = part1 * 0x11                                   ;
        v16[24] = v14                                        ;
        v14 = v16[7]                                         ;
        v14 = part1 * part3                                  ;
        v14 = v14 * 5                                        ;
        v16[25] = v14                                        ;
        v14 = v16[8]                                         ;
        v14 = part3 * part3                                  ;
        v14 = v14 * 5                                        ;
        v16[26] = v14                                        ;
        v14 = v16[9]                                             ;
        v14 = part3 * 0x58                                   ;
        v16[27] = v14                                        ;
        v14 = v16[10]                                        ;
        v14 = part3 * part4                                  ;
        v14 *= 4;                                            ;
        v16[28] = v14                                        ;
        v14 = v16[11]                                        ;
        v14 = part3 * part3                                  ;
        v14 *= 5                                             ;
        v16[29] = v14                                        ;
        v14 = v16[12]                                        ;
        v14 = part4 * 0xE8                                   ;
        v16[30] = v14                                             ;
        v14 = v16[13]                                        ;
        v14 = part4 * part4                                  ;
        v14 = v14 * 0x23                                     ;
         v16[31] = v14                                       ;
        v14 = v16[14]                                        ;
        v14 = part5 * 8                                      ;
        v16[32] = v14                                        ;
        v14 = v16[15]                                        ;
        v14 = part5*part5                                    ;
        v14 = v14 * 0x10                                     ;
        v16[33] = v14                                        ;
        v14 = v16[16]                                        ;
        v0 = v16[33]                                             ;
        v1 = v16[32] + v16[33]                               ;
        v16[32] = v1                                             ;
        v2 = v16[32]                                         ;
        v3=v16[32] - v16[31]                                     ;
        v16[31] = v3                                         ;
        v5 = v16[31] % 0x5e2f4391                            ;
        v15[0] = v5                                          ;
        v0 = v16[30]                                         ;
        v1 = v16[29]  +v16[30]                               ;
        v16[29] = v1                                         ;
        v2 = v16[29]                                             ;
        v3 =v16[29]        -v16[28]                                 ;
        v16[28] = v3                                                     ;
        v5 = v3 % 0x5e2f4391                                 ;
        v15[1] = v5                                                     ;
        v0 = v16[27]                                         ;
        v1 = v16[26] + v16[27]                               ;
        v16[26] = v1                                                 ;
        v2 = v16[26]                                             ;
        v3 = v16[26] - v16[25]                               ;
        v16[25] = v3                                         ;
        v5 =v16[25] %  0x5e2f4391                            ;
        v15[2] = v5                                          ;
        v0 = v16[24]                                         ;
        v1 = v16[23] + v16[24]                               ;
        v16[23] = v1                                             ;
        v0 = v16[23]                                             ;
        v1 = v16[22] + v16[23]                               ;
        v16[22] = v1                                         ;
        v5 = v16[22] % 0x5e2f4391                            ;
        v15[3] = v5                                                 ;
        v0 = v16[21]                                         ;
        v1 = v16[21] + v16[20]                               ;
        v16[20] = v1                                             ;
        v0 = v16[20]                                                 ;
        v1 = v16[19] + v16[20]                               ;
        v16[19] = v1                                             ;
        v2 = v16[19]                                             ;
        v3 = v16[19] - v16[18]                               ;
        v16[18] = v3                                                 ;
        v5 = v16[18] % 0x5e2f4391                            ;
        v15[4] = v5                                                     ;
        v16[18] = v14                                        ;
        v14 = v16[17]                                             ;
        v14 = v16[17] ^ v15[4] ^ 0x42DB9F06                  ;
        v14 = v14 ^ v15[3] ^ 0x35368926                      ;
        v14 = v14 ^ v15[2] ^ 0x509A3978                      ;
        v14 = v14 ^ v15[1] ^ 0x1EBFA92F                      ;
        v14 = v14 ^ v15[0] ^ 0x555CC98C                      ;

//        printf("0x%x\n",v14);
        printf("0x%x\n",v15[0]);
        printf("0x%x\n",v15[1]);
        printf("0x%x\n",v15[2]);
        printf("0x%x\n",v15[3]);
        printf("0x%x\n",v15[4]);
        if(v15[0] != 0x555CC98C && v15[1] != 0x1EBFA92F && v15[2] != 0x509A3978 && v15[3] != 0x35368926 && v15[4] != 0x42DB9F06){
                printf("error\n");

        }else{
                printf("success\n");
        }

//        for(int i=0;i<34;i++){
//                printf("%d : 0x%llx\n",i,v16[i]);
//        }
//        puts("");
//        printf("v14 : 0x%x",v14);

}

```

gcc编译并开O3优化;

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-1e327c479d999b24667e81993b17a1ea4903b3e7.png)

整理出来，实际是一个求同余式问题:

```php

( (16 * part5 * part5 + 8 * part5) - 35 * part4 * part4)           % 1580155793 == 1432144268;               
((( 5 * part3 * part3) + 232 * part4) - 4 * part3 * part4)        % 1580155793 == 515877167;                
( (88 * part3 +  (5 * part3 * part3) ) - 5 * part1 * part3)         % 1580155793 == 1352284536;             
 ( 2 * part1 * part1 + ( 13 * part2 + 17 * part1))                   % 1580155793 == 892766502;             
( (0x58 * part2 + 6 * part2 * part1) - 3 * part1 * part1)                 % 1580155793 == 1121689350;     
```

其中第四个与第五个等式只含part1与part2变量，并且第四个等式的part2可以用part1来表示:

```php
part2 = (892766502 - 2 * part1 * part1  - 17 * part1) * 13^(-1) (mod 1580155793)  // 这里的13^(-1) 是13关于1580155793的逆元
```

那么我们直接尝试爆破:

```php
爆破part1,2:
for part1 in range(0x20202020,0x80808080):
    part2 = ((0x35368926 - 2 * part1 * part1  - 17 * part1) * 0x39f5b36d)% 0x5e2f4391
    if ((0x58 * part2 + 6 * part2 * part1) - 3 * part1 * part1) % 0x5e2f4391 == 0x42DB9F06:
        print(hex(part1),hex(part2));
得到:
part1 = 0x33636662
part2 = 0x336f1d5 + 0x5e2f4391

爆破 part3:
part1 = 0x33636662
for part3 in range(0x20202020,0x80808080):
    if ( (88 * part3 +  (5 * part3 * part3) ) - 5 * part1 * part3)         % 1580155793 == 1352284536:
        print(hex(part3))

爆破part4:

for part4 in range(0x20202020,0x80808080):
    if ((( 5 * part3 * part3) + 232 * part4) - 4 * part3 * part4) % 1580155793 == 515877167 :
        print(hex(part4))

```

```php
for part1 in range(0x20202020,0x80808080):
    part2 = ((0x35368926 - 2 * part1 * part1  - 17 * part1) * 0x39f5b36d)% 0x5e2f4391
    if ((0x58 * part2 + 6 * part2 * part1) - 3 * part1 * part1) % 0x5e2f4391 == 0x42DB9F06:
        print(hex(part1),hex(part2));
        break

part1 = 0x33636662
part2 = 0x336f1d5 + 0x5e2f4391

part1 = 0x33636662
for part3 in range(0x30303030,0x80808080):
    if ( (88 * part3 +  (5 * part3 * part3) ) - 5 * part1 * part3)  % 1580155793 == 1352284536:
        print(hex(part3))
        break

part3 = 0x39613138

for part4 in range(0x20202020,0x80808080):
    if ((( 5 * part3 * part3) + 232 * part4) - 4 * part3 * part4) % 1580155793 == 515877167 :
        print(hex(part4))
        break

part4 = 0x33383261
for part5 in range(0x20202020,0x80808080):
    if ( (16 * part5 * part5 + 8 * part5) - 35 * part4 * part4)         % 1580155793 == 1432144268:
        print(hex(part5))

from struct import pack
flag = pack(">I",0x33636662) +  pack(">I",0x336f1d5 + 0x5e2f4391) +pack(">I",0x39613138) + pack(">I",0x33383261) + pack(">I",0x6132337d)

```

最后得到flag:

flag{3cfbaf5f9a18382aa23}

ez\_vm
------

这道题被队友开局直接秒了，tql，下面说说我的思路

这里存在系统调用，我们对照着这张表可以恢复一些符号.

<https://j00ru.vexillium.org/syscalls/nt/64/>

之后手动定义结构体:

```php
struct context{
    _QWORD res_opcode;
    _QWORD new_rsp;

    _QWORD rax;
    _QWORD rcx;
    _QWORD rdx;
    _QWORD rbx;
    _QWORD rsp;
    _QWORD rbp;
    _QWORD rsi;
    _QWORD rdi;
    _QWORD r8;
    _QWORD r9;
    _QWORD r10;
    _QWORD r11;
    _QWORD r12;
    _QWORD r13;
    _QWORD r14;
    _QWORD r15; //  mov     [rax+88h], r15
    _QWORD empty1   ;
    _QWORD empty2   ;
    _QWORD empty3   ;
    _QWORD empty4   ;
    _QWORD empty5   ;
    _QWORD empty6   ;
    _QWORD empty7   ;
    _QWORD empty8   ;
    _QWORD empty9   ;
    _QWORD empty10  ;
    _QWORD empty11  ;
    _QWORD empty12  ;
    _QWORD empty13  ;
    _QWORD empty14  ;
    _QWORD empty15  ;
    _QWORD empty16  ;
    _QWORD empty17  ;
    _QWORD empty18  ;
    _QWORD empty19  ;
    _QWORD empty20  ;
    _QWORD empty21  ;
    _QWORD empty22  ;
    _QWORD empty23  ;
    _QWORD empty24  ;
    _QWORD empty25  ;
    _QWORD empty26  ;
    _QWORD empty27  ;
    _QWORD empty28  ;
    _QWORD empty29  ;
    _QWORD empty30  ;
    _QWORD empty31  ;
    _QWORD empty32  ;
    _QWORD empty33  ;
    _QWORD empty34  ;
    _QWORD empty35  ;
    _QWORD empty36  ;
    _QWORD empty37  ;
    _QWORD empty38  ;
    _QWORD empty39  ;
    _QWORD empty40  ;
    _QWORD empty41  ;
    _QWORD empty42  ;
    _QWORD empty43  ;
    _QWORD empty44  ;
    _QWORD empty45  ;
    _QWORD empty46  ;
    _QWORD empty47  ;
    _QWORD empty48  ;
    _QWORD  cntBaseAddr ;               // +0x210
    _QWORD  stackBaseAddr ;         // size: 0x8000
    _QWORD  what3 ;                 // 0i64
    _QWORD  what4 ;                 // 0x1000i64
    _QWORD  base_addr2_rwx ;        // size: 0x1000
    _QWORD  what6 ;                 // 0i64
    _QWORD  what7 ;

}
```

就像这样

下面我们可以开始分析这个vm题目了

我们对输入下内存访问断点，不断的跟踪输入流的流向，并手动打log

跟踪的过程中，发现了存储输入的地址，其中的数据发生了这样的变化:

11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff  
\\===&gt;  
11 66 bc ef 55 aa ff 44 99 ef 33 88 de 22 77

类似于AES的行移位

之后继续打log:

x = inp\[0\] &lt;&lt; 2;  
add x , 0x0000000140013000  
add x, 0  
x1 = x\[0\]

\\==&gt;

x = inp\[0\] &lt;&lt; 2;  
x1 = 0x0000000140013000\[x+0\]; ==&gt; 0x000000009662140C  
y\[0\] = x1

x = inp\[1\] &lt;&lt; 2;  
x1 = 0x0000000140013400\[x+0\] ==&gt;0x000000006E600A75  
y\[1\] = x1;

\\====&gt; 000000000014FCA0

x = inp\[3\] &lt;&lt; 2;  
x1 = 0x0000000140013800\[x+0\] =&gt; 140013AEC\[0\] ==&gt; 0x00000000103DCFB3  
y\[2\] = x\[1\];

4、3701215Bh  
y\[3\]=x\[1\];

x = y\[0\]; //0x000000009662140C  
x /= 2; // 0x000000004B310A06  
x /= 2; // 0x0000000025988503  
x /= 2; // 0x0000000012CC4281  
x /= 2; // 0x0000000009662140  
x /=2 ; //0x0000000004B310A0  
x /= 2; //0x0000000002598850;  
x /=2; // 0x00000000012CC428  
x /=2; // 0x0000000000966214  
x /= 2; // 0x00000000004B310A  
x /= 2; //0x0000000000259885  
x /= 2; // 0x000000000012CC42  
x /=2; // 0x0000000000096621  
x /=2 ; //0x000000000004B310  
x /=2 ; //0x0000000000025988  
x /=2 ; //0x0000000000012CC4  
x /=2 ; //0x0000000000009662  
x /=2 ; //0x0000000000004B31  
x /=2 ; //0x0000000000002598  
x /=2 ; //0x00000000000012CC  
x /=2 ; //0x0000000000000966  
x /=2 ; //0x00000000000004B3  
x /=2 ; //0x0000000000000259  
x /=2 ; //0x000000000000012C  
x /=2 ; //0x0000000000000096

x /=2 ; //0x000000000000004B  
x /=2 ; //0x0000000000000025  
x /=2 ; //0x0000000000000012  
x /=2 ; //0x0000000000000009  
x = 0xf &amp; x

x &lt;&lt;= 4;  
x1 = &amp;0x000000014005F000\[x\] , 14005F090h =====&gt; 0000000000907CC0  
x1 = x1\[0\]

x = y\[1\]  
x = 0xf &amp; x  
x = x &lt;&lt; 0  
...

随着log的不断增加，我们可以发现这个算法用了很多关于表，并且可以发现AES白盒的特征。其实这个vm就是实现的aes白盒，明白这个之后，我们用常规的差分故障分析即可求出flag(上文有讲)

snake
-----

贪吃蛇脚本:

注意 `输入的序列最少`！！！ 这是重点！

```php
import hashlib
import copy
lpAddress = [0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0x38, 0x4C, 0xB0, 0x38, 0x6D, 0xEE, 0x3F, 0xC4, 0xB4, 0xB4, 0x09, 0x6A, 0xF0, 0x38, 0x2C, 0x79, 0xF6, 0x34, 0xE9, 0x89, 0x38, 0xAC, 0x7F, 0x35, 0xD4, 0xB4, 0xB4, 0x38, 0x6D, 0x77, 0xF6, 0xB6, 0x38, 0x6D, 0x78, 0xF6, 0xB6, 0x2B, 0x18, 0xB4, 0xB4, 0xB4, 0x3B, 0x81, 0x81, 0x81, 0x81, 0xEF, 0x4E, 0x38, 0x4C, 0x7D, 0xF6, 0x33, 0xD4, 0xB4, 0xB4, 0xB0, 0xE8, 0xF4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB0, 0xE8, 0xF6, 0x2B, 0x27, 0xA3, 0x1D, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xB4, 0xB0, 0xF8, 0x04, 0x38, 0x89, 0xE3, 0xC3, 0xCA, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xC4, 0xB0, 0xF8, 0x04, 0x38, 0xB3, 0x67, 0xE3, 0x16, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xD4, 0xB0, 0xF8, 0x04, 0x38, 0xB6, 0xD3, 0xB6, 0xA9, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xE4, 0xB0, 0xF8, 0x04, 0x38, 0x89, 0xD8, 0xC7, 0x33, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xB4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xB4, 0x38, 0x4C, 0xED, 0xB5, 0xD4, 0xB4, 0xB4, 0x4C, 0xF4, 0xD4, 0x2C, 0xF8, 0x85, 0x37, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xC4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xC4, 0x38, 0x4C, 0xED, 0xB5, 0xD4, 0xB4, 0xB4, 0x4C, 0xF4, 0xD4, 0x2C, 0xF8, 0x85, 0x37, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xD4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xD4, 0x38, 0x4C, 0xED, 0xB5, 0xD4, 0xB4, 0xB4, 0x4C, 0xF4, 0xD4, 0x2C, 0xF8, 0x85, 0x37, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xE4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xE4, 0x38, 0x4C, 0xED, 0xB5, 0xD4, 0xB4, 0xB4, 0x4C, 0xF4, 0xD4, 0x2C, 0xF8, 0x85, 0x37, 0xB0, 0xEC, 0xFE, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0x6F, 0x14, 0x4C, 0xEC, 0xFE, 0xB4, 0xB4, 0xB4, 0x2F, 0xC0, 0x2C, 0xEC, 0xFE, 0xB4, 0xB4, 0xB4, 0xCC, 0x6C, 0xFE, 0xB4, 0xB4, 0xB4, 0xB6, 0x24, 0xCC, 0x72, 0xB4, 0xB4, 0xB4, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xB4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xC4, 0x4C, 0x79, 0x85, 0x37, 0xD0, 0xD2, 0xF4, 0x5B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xE1, 0xC4, 0x4C, 0xF9, 0x05, 0x37, 0xD0, 0x62, 0x04, 0xE3, 0x60, 0x5B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xE1, 0xC4, 0xE4, 0x79, 0x05, 0x37, 0x4C, 0xE9, 0xF4, 0xCC, 0xE2, 0xE4, 0x4C, 0xE1, 0x4C, 0xF9, 0xED, 0x38, 0xF8, 0x4C, 0xE8, 0xF4, 0xF8, 0xE4, 0xE0, 0xA8, 0x4C, 0xC1, 0xE3, 0x60, 0xE4, 0x79, 0x04, 0x37, 0x4C, 0xD0, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xB4, 0x2C, 0xF8, 0x85, 0x37, 0x4C, 0xE8, 0xF6, 0x4C, 0x69, 0xF4, 0xE4, 0x40, 0x4C, 0xD0, 0x2C, 0xE8, 0xF4, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xC4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xB4, 0x4C, 0x79, 0x85, 0x37, 0xD0, 0xD2, 0xF4, 0x5B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xE1, 0xB4, 0x4C, 0xF9, 0x05, 0x37, 0xD0, 0x62, 0x04, 0xE3, 0x60, 0x5B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xE1, 0xB4, 0xE4, 0x79, 0x05, 0x37, 0x4C, 0xE9, 0xF4, 0xD0, 0x62, 0x64, 0xCC, 0xE2, 0xE4, 0x4C, 0xE1, 0x4C, 0xF9, 0xED, 0x38, 0xF8, 0x4C, 0xE8, 0xF4, 0xF8, 0xE4, 0xE0, 0xA8, 0x4C, 0xC1, 0xE3, 0x60, 0xE4, 0x79, 0x04, 0x37, 0x4C, 0xD0, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xC4, 0x2C, 0xF8, 0x85, 0x37, 0x52, 0x54, 0x2F, 0x2F, 0x2F, 0xB0, 0xEC, 0x00, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0x6F, 0x14, 0x4C, 0xEC, 0x00, 0xB4, 0xB4, 0xB4, 0x2F, 0xC0, 0x2C, 0xEC, 0x00, 0xB4, 0xB4, 0xB4, 0xCC, 0x6C, 0x00, 0xB4, 0xB4, 0xB4, 0xB6, 0x24, 0xCC, 0x72, 0xB4, 0xB4, 0xB4, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xD4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xE4, 0x4C, 0x79, 0x85, 0x37, 0xD0, 0xD2, 0xF4, 0x5B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xE1, 0xE4, 0x4C, 0xF9, 0x05, 0x37, 0xD0, 0x62, 0x04, 0xE3, 0x60, 0x5B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xE1, 0xE4, 0xE4, 0x79, 0x05, 0x37, 0x4C, 0xE9, 0xF4, 0xCC, 0xE2, 0xE4, 0x4C, 0xE1, 0x4C, 0xF9, 0xED, 0x38, 0xF8, 0x4C, 0xE8, 0xF4, 0xF8, 0xE4, 0xE0, 0xA8, 0x4C, 0xC1, 0xE3, 0x60, 0xE4, 0x79, 0x04, 0x37, 0x4C, 0xD0, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xD4, 0x2C, 0xF8, 0x85, 0x37, 0x4C, 0xE8, 0xF6, 0x4C, 0x69, 0xF4, 0xE4, 0x40, 0x4C, 0xD0, 0x2C, 0xE8, 0xF4, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xE4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xD4, 0x4C, 0x79, 0x85, 0x37, 0xD0, 0xD2, 0xF4, 0x5B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xE1, 0xD4, 0x4C, 0xF9, 0x05, 0x37, 0xD0, 0x62, 0x04, 0xE3, 0x60, 0x5B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xE1, 0xD4, 0xE4, 0x79, 0x05, 0x37, 0x4C, 0xE9, 0xF4, 0xD0, 0x62, 0x64, 0xCC, 0xE2, 0xE4, 0x4C, 0xE1, 0x4C, 0xF9, 0xED, 0x38, 0xF8, 0x4C, 0xE8, 0xF4, 0xF8, 0xE4, 0xE0, 0xA8, 0x4C, 0xC1, 0xE3, 0x60, 0xE4, 0x79, 0x04, 0x37, 0x4C, 0xD0, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xE4, 0x2C, 0xF8, 0x85, 0x37, 0x52, 0x54, 0x2F, 0x2F, 0x2F, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xB4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xD4, 0x4C, 0x79, 0x85, 0x37, 0x4C, 0xF8, 0x04, 0x37, 0xE3, 0xD0, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xB4, 0x2C, 0xF8, 0x85, 0x37, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xC4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xE4, 0x4C, 0x79, 0x85, 0x37, 0x4C, 0xF8, 0x04, 0x37, 0xE3, 0xD0, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xC4, 0x2C, 0xF8, 0x85, 0x37, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xE4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xB4, 0x4C, 0x79, 0x85, 0x37, 0x4C, 0xF8, 0x04, 0x37, 0xE3, 0xD0, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xE4, 0x2C, 0xF8, 0x85, 0x37, 0x3B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0xC0, 0xC4, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xD4, 0x4C, 0x79, 0x85, 0x37, 0x4C, 0xF8, 0x04, 0x37, 0xE3, 0xD0, 0x2B, 0xF4, 0xB4, 0xB4, 0xB4, 0x38, 0x4A, 0x50, 0xD4, 0x2C, 0xF8, 0x85, 0x37, 0xA0, 0xEC, 0x42, 0xB4, 0xB4, 0xB4, 0x3D, 0xA0, 0xEC, 0x52, 0xB4, 0xB4, 0xB4, 0xBE, 0xA0, 0xEC, 0x62, 0xB4, 0xB4, 0xB4, 0x51, 0xA0, 0xEC, 0x6F, 0xB4, 0xB4, 0xB4, 0x3D, 0xA0, 0xEC, 0x7F, 0xB4, 0xB4, 0xB4, 0x5B, 0xA0, 0xEC, 0x12, 0xB4, 0xB4, 0xB4, 0x8D, 0xA0, 0xEC, 0x22, 0xB4, 0xB4, 0xB4, 0x65, 0xA0, 0xEC, 0x32, 0xB4, 0xB4, 0xB4, 0xA7, 0xA0, 0xEC, 0xBF, 0xB4, 0xB4, 0xB4, 0x4D, 0xA0, 0xEC, 0xCF, 0xB4, 0xB4, 0xB4, 0xAC, 0xA0, 0xEC, 0xDF, 0xB4, 0xB4, 0xB4, 0xF8, 0xA0, 0xEC, 0xEF, 0xB4, 0xB4, 0xB4, 0x06, 0xA0, 0xEC, 0xFF, 0xB4, 0xB4, 0xB4, 0xE9, 0xA0, 0xEC, 0x8F, 0xB4, 0xB4, 0xB4, 0x3B, 0xA0, 0xEC, 0x9F, 0xB4, 0xB4, 0xB4, 0xA3, 0xA0, 0xEC, 0xAF, 0xB4, 0xB4, 0xB4, 0x31, 0xB0, 0xEC, 0xF5, 0xC4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0xB4, 0x6F, 0x14, 0x4C, 0xEC, 0xF5, 0xC4, 0xB4, 0xB4, 0x2F, 0xC0, 0x2C, 0xEC, 0xF5, 0xC4, 0xB4, 0xB4, 0xCC, 0x6C, 0xF5, 0xC4, 0xB4, 0xB4, 0xB5, 0x68, 0xE6, 0x38, 0xCA, 0xEC, 0xF5, 0xC4, 0xB4, 0xB4, 0x24, 0x1B, 0xF8, 0x04, 0x37, 0x38, 0xCA, 0x6D, 0xF5, 0xC4, 0xB4, 0xB4, 0x24, 0x1B, 0x7D, 0x85, 0x42, 0xB4, 0xB4, 0xB4, 0x63, 0xD0, 0xF7, 0xF4, 0xD3, 0xC0, 0x6F, 0xF4, 0x6F, 0x00, 0xBB, 0xC4, 0x38, 0x4C, 0x3F, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD]

def left(inp=None):                 # 向左,low-1
    if inp==None:
        global lpAddress
        v7 = lpAddress[:]
        for i in range(1152):
            lpAddress[i] = v7[(i + 6) % 1152];
    else:
        for lpaddr in inp:
            v7 = lpaddr[:]
            for i in range(1152):
                lpaddr[i] = v7[(i + 6) % 1152];

def right(inp=None):                  # 向右,low+1
    if inp == None:
        global lpAddress
        for i in range(1152):
            lpAddress[i] += 30
            lpAddress[i] &= 0xff
    else:
        for lpaddr in inp:
            for i in range(1152):
                lpaddr[i] += 30
                lpaddr[i] &= 0xff

def reright(inp=None):                  # 向右,low+1
    if inp == None:
        global lpAddress
        for i in range(1152):
            lpAddress[i] -= 30
            lpAddress[i] &= 0xff
    else:
        for lpaddr in inp:
            for i in range(1152):
                lpaddr[i] -= 30
                lpaddr[i] &= 0xff

def up(inp=None):                  # 向上，high-1
    if inp ==None:
        global lpAddress
        for i in range(1152):
            lpAddress[i] -= 0x66;
            lpAddress[i] &= 0xff
    else:
        for lpaddr in inp:
            for i in range(1152):
                lpaddr[i] -= 0x66;
                lpaddr[i] &= 0xff

def down(inp=None):                # 向下,high+1
    if inp == None:
        global lpAddress
        for i in range(1152):
            lpAddress[i] = ((lpAddress[i] >> 5) | (lpAddress[i] << 3)) & 0xff
    else:
        for lpaddr in inp:
            for i in range(1152):
                lpaddr[i] = ((lpaddr[i] >> 5) | (lpaddr[i] << 3)) & 0xff

low_now = low_begin = 0xa
high_now = high_begin = 0xa
low_list = [0x11,0xc,0x3,0xf,0xd,0x4,0xc,0xe,0x3,0x13,0xa,0x0,0x10,0x0,0xd,0x11,0xf,0x10,0x3,0xd,0x12,0xa,0x9,0xc,0x6,0x3,0x3,0x10,0x0,0x7,0x10,0xd,0x4,0xa,0x4,0x0,0x6,0x10,0x10,0x5,0x0,0x1,0xa,0x2,0xa,0x6,0x12,0x13,0xa,0x12,0x6,0x11,0xc,0xa,0xe,0x2,0x2,0x12,0x5,0x8,0x1,0xa,0xf,0x12,0xb,0x1,0x10,0x6,0xf,0x1,0xb,0x5,0x0,0xd,0x11,0xe,0xa,0xa,0x2,0xf,0x8,0x6,0x4,0x12,0x8,0x10,0xf,0x9,0x2,0xa,0x6,0xa,0x11,0x6,0x8,0x8,0x10,0x12,0x10,0xd,0x3,0x13,0x6,0xa,0x0,0xe,0x10,0xe,0x6,0x2,0x12,0x3,0x11,0x4,0x5,0x8,0x10,0x13,0x10,0x1,0x9,0xc,0x12,0x6,0x9,0xf,0x9,0x8,0x9,0xc,0x13,0x6,0xe,0x13,0x8,0x1,0xa,0xc,0x5,0x4,0xd,0x8,0x0,0x2,0x2,0xe,0x12,0xb,0x7,0x3,0x7,0x12,0x10,0xb,0x9,0x2,0x3,0x1,0xa,0x5,0x11,0xf,0x1,0x3,0x5,0x10,0xd,0x1,0x0,0x4,0x2,0x13,0x10,0xb,0x2,0x1,0xd,0xe,0xe,0x3,0x5,0x5,0x12,0xd,0x1,0xb,0xc,0x4,0x1,0x11,0x9,0x2,0x9,0x13,0xb,0x2,0x7,0x12,0x11,0xe,0xe,0x0,0x7,0x8,0x11,0x7,0xf,0x9,0x0,0xf,0x9,0x9,0xa,0x13,0x0,0x5,0xa,0x0,0x2,0x7,0x7,0x12,0x10,0x2,0x3,0x11,0x3,0xb,0x10,0xd,0x1,0xd,0xe,0x6,0xe,0x1,0x6,0x11,0x10,0xf,0xf,0x5,0x3,0x0,0x3,0xb,0x11,0x2,0x6,0x13,0xf,0x13,0xb,0xc,0xe,0x2,0x1,0x8,0xf,0xc,0x10,0x12,0x8,0x10,0x6,0xe,0x1,0x4,0x6,0x10,0x3,0x12,0x8,0x5,0x5,0x10,0x13,0x4,0x12,0x10,0x9,0x3,0x7,0x5,0x13,0x10,0x3,0xc,0x7,0x8,0x3,0x13,0x13,0xb,0x6,0x1,0x11,0xe,0x7,0x1]
high_list = [0x0,0xa,0xb,0x9,0x12,0xa,0xa,0x10,0x7,0xe,0xb,0xf,0xb,0x10,0x3,0xc,0x3,0xe,0x13,0x11,0x9,0x11,0x8,0x4,0x3,0xb,0x6,0x5,0x1,0x4,0xa,0x7,0x13,0x8,0xd,0xc,0xf,0x7,0x6,0x10,0x9,0xc,0xc,0x9,0x8,0xf,0xd,0xa,0x0,0xb,0x4,0xc,0x13,0x9,0x4,0x10,0x3,0xf,0xe,0x4,0xf,0xd,0x4,0x1,0x9,0x13,0x10,0xe,0x1,0xd,0xd,0x4,0xd,0x12,0x7,0x4,0xc,0x6,0x12,0x9,0x7,0x4,0x7,0x3,0x12,0x1,0xe,0x10,0x4,0x3,0xd,0x3,0xb,0x2,0x13,0x10,0x9,0x6,0xa,0x11,0x2,0x13,0x12,0x5,0x10,0x10,0x4,0x7,0x9,0x11,0x10,0xf,0xc,0xd,0x4,0xe,0x9,0x11,0xe,0x1,0x0,0xf,0x1,0x2,0x12,0x7,0xd,0x7,0x8,0x6,0x12,0x8,0x1,0x12,0xa,0x5,0x1,0x3,0x10,0xb,0x1,0x1,0x9,0xa,0xc,0x3,0x7,0x11,0x1,0xd,0xd,0xa,0x2,0xb,0x8,0x9,0x6,0x5,0x5,0x12,0x10,0x1,0x1,0x8,0x13,0x8,0x13,0xe,0x8,0xd,0x6,0x2,0x3,0xc,0x11,0x9,0xe,0xd,0xc,0xd,0x3,0x2,0x6,0xb,0xe,0x4,0x11,0x1,0x2,0xb,0x4,0x11,0x3,0x11,0x11,0xc,0x12,0x13,0x3,0x8,0x11,0x4,0x12,0x2,0x7,0xc,0xa,0x0,0xe,0x13,0x8,0x1,0x8,0xb,0x9,0x8,0xd,0x9,0xc,0xd,0xb,0xd,0x4,0x8,0x10,0x9,0x0,0xc,0x0,0xa,0xe,0x1,0x9,0x13,0x8,0x2,0x11,0x10,0x12,0xc,0x8,0x11,0xe,0xd,0x3,0x10,0xa,0x6,0x6,0x13,0x12,0x5,0x6,0x7,0x7,0x10,0x10,0xa,0x9,0xc,0x0,0xe,0x12,0x3,0xf,0x13,0x5,0xa,0x12,0x1,0xc,0x4,0x10,0xf,0x12,0x1,0x8,0xa,0x6,0x10,0x9,0x10,0x2,0xe,0xc,0xa,0x10,0x8,0xd,0x6,0x9,0x10,0x13,0xd,0x5,0x9,0xf,0xe,0x8,0xf]
md5_cip = "9c06c08f882d7981e91d663364ce5e2e"

def pan_md5(inp=None):
    global md5_cip
    if inp==None:
        global lpAddress
        md5 = hashlib.md5()
        md5.update(bytes(lpAddress))
        encrypted_string = md5.hexdigest()
        return encrypted_string == md5_cip
    else:
        for lpaddr in inp:
            md5 = hashlib.md5()
            md5.update(bytes(lpaddr))
            encrypted_string = md5.hexdigest()
            if encrypted_string == md5_cip:
                return 1
        return 0

shellcode_list = []
shellcode_list.append(copy.deepcopy(lpAddress) )
last_dir = ["","right"]     # 给定初始方向

for i in range(300):

    dy = high_list[i] - high_now
    dx = low_list[i] - low_now
    print(f"before <=> ({last_dir[0]},{last_dir[1]})")
    print(f"({low_now},{high_now}) ==> ({low_list[i]},{high_list[i]})  === ({dx},{dy}) ")
    if dx == 0 and dy == 0:
        continue
    elif dx == 0 or dy == 0:
        if dx == 0:
            if dy > 0:      # down
                if last_dir[1] == "down":
                    pass
                elif last_dir[1] == "up":
                    assert 0        # 情况比较复杂，先不考虑
                elif last_dir[1] == "left":
                    down(shellcode_list)
                    last_dir[1] = "down"
                elif last_dir[1] == "right":
                    down(shellcode_list)
                    last_dir[1] = "down"
            else:
                if last_dir[1] == "down":
                    assert 0        # 情况比较复杂，先不考虑
                elif last_dir[1] == "up":
                    up(shellcode_list)
                    last_dir[1] = "up"
                elif last_dir[1] == "left":
                    up(shellcode_list)
                    last_dir[1] = "up"

                elif last_dir[1] == "right":
                    up(shellcode_list)
                    last_dir[1] = "up" 

        elif dy == 0:
            if dx > 0:
                if last_dir[1] == "right":
                    pass
                elif last_dir[1] == "left":
                    assert 0    # 情况比较复杂，先不考虑
                elif last_dir[1] == "up":
                    right(shellcode_list)
                    last_dir[1] = "right"
                elif last_dir[1] == "down":
                    right(shellcode_list)
                    last_dir[1] = "right"
            else:
                if last_dir[1] == "right":
                    assert 0       #          情况比较复杂，先不考虑
                elif last_dir[1] == "left":
                    pass
                elif last_dir[1] == "up":
                    left(shellcode_list)
                    last_dir[1] = "left"
                elif last_dir[1] == "down":
                    left(shellcode_list)
                    last_dir[1] = "left"  
        high_now = high_list[i] 
        low_now = low_list[i]   

    elif dx > 0 and dy > 0:          # 向右 + 向下
        print(f"round: {i} | high_now: {high_now} | low_now: {low_now}")
        print(f"          | high_list[i]:{high_list[i]} | low_list[i]: {low_list[i]}")

        if "right" == last_dir[1]:  # 上右，下右，左下，右下
            down(shellcode_list)
            last_dir = ["right","down"]
        elif "down" == last_dir[1]:
            right(shellcode_list)
            last_dir = ["down","right"]
        else:      
            if last_dir[1] == "left":       
                down(shellcode_list)
                right(shellcode_list)
                last_dir = ["down","right"]

            elif last_dir[1] == "up":       
                right(shellcode_list)
                down(shellcode_list)
                last_dir = ["right","down"]

        high_now = high_list[i] 
        low_now = low_list[i]

    elif dx > 0 and dy < 0:              # 向右 + 向上
        if "right" == last_dir[1]:
            up(shellcode_list)
            last_dir = ["right","up"]
        elif "up" == last_dir[1]:
            right(shellcode_list)
            last_dir = ["up","right"]

        else:       # 之前是左下/下左方向,那我们只能按照右上/上右的顺序来到达终点
            if last_dir[1] == "left":
                last_dir = ["up","right"]
            elif last_dir[1] == "down":
                last_dir = ["right","up"]

            right(shellcode_list)
            up(shellcode_list)

        high_now = high_list[i] 
        low_now = low_list[i]

    elif dx < 0 and dy > 0:         # 向左 + 向下
        if "left" == last_dir[1]:
            down(shellcode_list)
            last_dir = ["left","down"]
        elif "down" == last_dir[1]:
            left(shellcode_list)
            last_dir = ["down","left"]

        else:      
            if last_dir[1] == "right":
                last_dir = ["down","left"]

            elif last_dir[1] == "up":
                last_dir = ["left","down"]

            left(shellcode_list)
            down(shellcode_list)
        high_now = high_list[i] 
        low_now = low_list[i]

    elif dx < 0 and dy < 0:         # 向左 + 向上
        if "left" == last_dir[1]:
            up(shellcode_list)
            last_dir = ["left","up"]
        elif "up" == last_dir[1]:
            left(shellcode_list)
            last_dir = ["up","left"]

        else:      
            if last_dir[1] == "right":
                last_dir = ["up","left"]

            elif last_dir[1] == "down":
                last_dir = ["left","up"]

            left(shellcode_list)
            up(shellcode_list)
        high_now = high_list[i]
        low_now = low_list[i]

    if pan_md5(shellcode_list):
        fp = open("./xcode.bin","wb")
        fp.write(bytes(shellcode_list[0]))
        fp.close()
        assert 0
```

之后把得到的 xcode.bin文件patch到snake的程序上就能看到加密逻辑:

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-70ee0551b4f5af5b43d5df6ce787e25c8a7ab5d7.png)  
一个小改的tea加密

exp:

```php
#include <cstdio>
#include <cstdint>

int main()
{
    unsigned char answer[17] = { 0 };
    answer[0] = 0x98;
    answer[1] = 0xA0;
    answer[2] = 0xD9;
    answer[3] = 0x98;
    answer[4] = 0xBA;
    answer[5] = 0x97;
    answer[6] = 0x1B;
    answer[7] = 0x71;
    answer[8] = 0x9B;
    answer[9] = 0x81;
    answer[10] = 0x44;
    answer[11] = 0x2F;
    answer[12] = 0x55;
    answer[13] = 0xB8;
    answer[14] = 0x37;
    answer[15] = 0xDF;

    unsigned char k[] = "W31c0m3. 2 QWBs8";

    uint32_t* v = (uint32_t*)answer;
    uint32_t* key = (uint32_t*)k;

    v[2] ^= v[1];
    v[3] ^= v[0];
    v[1] ^= v[3];
    v[0] ^= v[2];

    constexpr uint32_t delta = 0x9E3779B9;
    uint32_t sum = 0;
    for (int i = 0; i < 64; ++i)
        sum += delta;

    for (int k = 0; k < 32; ++k)
    {
        v[3] -= (key[(sum >> 11) & 3] + sum) ^ (v[2] + ((v[2] >> 5) ^ (16 * v[2])));
        sum -= delta;
        v[2] -= (key[sum & 3] + sum) ^ (v[3] + ((v[3] >> 5) ^ (16 * v[3])));
    }

    for (int j = 0; j < 32; ++j)
    {
        v[1] -= (key[(sum >> 11) & 3] + sum) ^ (v[0] + ((v[0] >> 5) ^ (16 * v[0])));
        sum -= delta;
        v[0] -= (key[sum & 3] + sum) ^ (v[1] + ((v[1] >> 5) ^ (16 * v[1])));
    }

    printf("%s\n", answer);
    return 0;
}
```

flag{G0@d\_Snake}

mapp
----

推箱子小游戏，注意是要求的是箱子的移动次数

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-d2abd87d18358e7ce36d011fba0f532e4c0ef071.png)

在github上找到了一个开源项目(地址忘了)

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-f8a92d9082949c67f3ce50966e3785ede41c589c.png)

我们改一下配置文件，换成题目给的推箱子地图，即可实现自动推箱子

最后得到的箱子最小移动次数是：2、12、13、9、 21、13、25、31、3

flag求md5 再加上qwb!即可

solve2-apk
----------

### 题目思路

jadx反编译不出来关键函数，字符串也搜不成功，拥抱jeb了。

安装app后，输入错误的字符串会存在一个 failure回显，jeb直接搜字符串就能定位关键函数。

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-025e6cb3e41661619e50f5e15255168a68e90d8e.png)

这个函数混淆严重，直接copy到IJ里调试。

手动插桩一下:

cmp length  
arr\_v = new int\[\]{0x5E5440B0, 2057046228, 0x4A1ED228, 0x233FE7C, 0x96461450, -2002358035, 0xF79BFC89, 0x20C3D75F};  
arr\_v1 = new int\[8\];  
arr\_v1\[0\] |= (arr\_b\[0\] &amp; 0xFF) &lt;&lt; 24  
++v3  
arr\_v1\[0\] |= (arr\_b\[1\] &amp; 0xFF) &lt;&lt; 16  
++v3  
arr\_v1\[0\] |= (arr\_b\[2\] &amp; 0xFF) &lt;&lt; 8  
++v3  
arr\_v1\[0\] |= (arr\_b\[3\] &amp; 0xFF) &lt;&lt; 0  
++v3  
arr\_v1\[1\] |= (arr\_b\[4\] &amp; 0xFF) &lt;&lt; 24  
++v3  
arr\_v1\[1\] |= (arr\_b\[5\] &amp; 0xFF) &lt;&lt; 16  
++v3  
arr\_v1\[1\] |= (arr\_b\[6\] &amp; 0xFF) &lt;&lt; 8  
++v3  
arr\_v1\[1\] |= (arr\_b\[7\] &amp; 0xFF) &lt;&lt; 0  
++v3  
arr\_v1\[2\] |= (arr\_b\[8\] &amp; 0xFF) &lt;&lt; 24  
++v3  
arr\_v1\[2\] |= (arr\_b\[9\] &amp; 0xFF) &lt;&lt; 16  
++v3  
arr\_v1\[2\] |= (arr\_b\[10\] &amp; 0xFF) &lt;&lt; 8  
++v3  
arr\_v1\[2\] |= (arr\_b\[11\] &amp; 0xFF) &lt;&lt; 0  
++v3  
arr\_v1\[3\] |= (arr\_b\[12\] &amp; 0xFF) &lt;&lt; 24  
++v3  
arr\_v1\[3\] |= (arr\_b\[13\] &amp; 0xFF) &lt;&lt; 16  
++v3  
arr\_v1\[3\] |= (arr\_b\[14\] &amp; 0xFF) &lt;&lt; 8  
++v3  
arr\_v1\[3\] |= (arr\_b\[15\] &amp; 0xFF) &lt;&lt; 0  
++v3  
arr\_v1\[4\] |= (arr\_b\[16\] &amp; 0xFF) &lt;&lt; 24  
++v3  
arr\_v1\[4\] |= (arr\_b\[17\] &amp; 0xFF) &lt;&lt; 16  
++v3  
arr\_v1\[4\] |= (arr\_b\[18\] &amp; 0xFF) &lt;&lt; 8  
++v3  
arr\_v1\[4\] |= (arr\_b\[19\] &amp; 0xFF) &lt;&lt; 0  
++v3  
arr\_v1\[5\] |= (arr\_b\[20\] &amp; 0xFF) &lt;&lt; 24  
++v3  
arr\_v1\[5\] |= (arr\_b\[21\] &amp; 0xFF) &lt;&lt; 16  
++v3  
arr\_v1\[5\] |= (arr\_b\[22\] &amp; 0xFF) &lt;&lt; 8  
++v3  
arr\_v1\[5\] |= (arr\_b\[23\] &amp; 0xFF) &lt;&lt; 0  
++v3  
arr\_v1\[6\] |= (arr\_b\[24\] &amp; 0xFF) &lt;&lt; 24  
++v3  
arr\_v1\[6\] |= (arr\_b\[25\] &amp; 0xFF) &lt;&lt; 16  
++v3  
arr\_v1\[6\] |= (arr\_b\[26\] &amp; 0xFF) &lt;&lt; 8  
++v3  
arr\_v1\[6\] |= (arr\_b\[27\] &amp; 0xFF) &lt;&lt; 0  
++v3  
arr\_v1\[7\] |= (arr\_b\[28\] &amp; 0xFF) &lt;&lt; 24  
++v3  
arr\_v1\[7\] |= (arr\_b\[29\] &amp; 0xFF) &lt;&lt; 16  
++v3  
arr\_v1\[7\] |= (arr\_b\[30\] &amp; 0xFF) &lt;&lt; 8  
++v3  
arr\_v1\[7\] |= (arr\_b\[31\] &amp; 0xFF) &lt;&lt; 0  
++v3  
v3 = 0  
cmp v3 &gt;= 8?  
v4 = arr\_v1\[0\];  
v5 = arr\_v1\[1\];  
v2 = 0  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
arr\_v1\[0\] = v4;  
arr\_v1\[1\] = v5;  
v3 += 2  
cmp v3 &gt;= 8?  
v4 = arr\_v1\[2\];  
v5 = arr\_v1\[3\];  
v2 = 0  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
arr\_v1\[2\] = v4;  
arr\_v1\[3\] = v5;  
v3 += 2  
cmp v3 &gt;= 8?  
v4 = arr\_v1\[4\];  
v5 = arr\_v1\[5\];  
v2 = 0  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
arr\_v1\[4\] = v4;  
arr\_v1\[5\] = v5;  
v3 += 2  
cmp v3 &gt;= 8?  
v4 = arr\_v1\[6\];  
v5 = arr\_v1\[7\];  
v2 = 0  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
v2 -= 0x61c88647  
v4 = (v5 &lt;&lt; 4 ^ v5) + (v2 ^ v5 &gt;&gt;&gt; 5) + v4;  
v5 = (v4 &lt;&lt; 4 ^ v4) + (v4 &gt;&gt;&gt; 5 ^ v2) + v5;  
arr\_v1\[6\] = v4;  
arr\_v1\[7\] = v5;  
v3 += 2  
cmp v3 &gt;= 8?  
v3 = 0

很显然是魔改的tea算法，写出解密脚本:

```php
#tea
from ctypes import *

def encrypt(v, k):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    delta = 0x61c88647 
    k0, k1, k2, k3 = k[0], k[1], k[2], k[3]

    total = c_uint32(0)
    for i in range(32):
        total.value -= delta 
        v0.value += (v1.value<<4  ^ v1.value) + (total.value ^ v1.value  >> 5)  
        v1.value += (v0.value<<4  ^ v0.value) + (v0.value >> 5 ^ total.value)
    return v0.value, v1.value 

def decrypt(v, k):
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    delta = 0x61c88647
    k0, k1, k2, k3 = k[0], k[1], k[2], k[3]

    total = c_uint32((-delta) * 32)
    for i in range(32):                       
        v1.value -= (v0.value<<4 ^ v0.value) + (v0.value >> 5 ^ total.value) 
        v0.value -= (v1.value<<4 ^ v1.value) + (total.value ^ v1.value >> 5)  
        total.value += delta

    return v0.value, v1.value   

def detea(inp:bytes,key:bytes):
    from struct import pack,unpack
    k = unpack("<4I",key)
    inp_len = len(inp) // 4
    # print(inp_len)
    value = unpack(f"<{inp_len}I",inp)
    res = b""
    for i in range(0,inp_len,2):
        v = [value[i],value[i+1]]
        # x = encrypt(v,k)
        x = decrypt(v,k)
        res += pack("<2I",*x)
    return res

def entea(inp:bytes,key:bytes):
    from struct import pack,unpack
    k = unpack("<4I",key)
    inp_len = len(inp) // 4
    # print(inp_len)
    value = unpack(f"<{inp_len}I",inp)
    res = b""
    for i in range(0,inp_len,2):
        v = [value[i],value[i+1]]
        x = encrypt(v,k)
        # x = decrypt(v,k)
        res += pack("<2I",*x)
    return res

from struct import pack
cip = [0x5e5440b0,0x7a9c08d4,0x4a1ed228,0x233fe7c,0x96461450,0x88a670ed,0xf79bfc89,0x20c3d75f]
inp = b""
for i in cip:
    inp += pack("<I",i)
key = b"\x00"*16
ret = detea(inp,key)
list_ret = list((ret[0:4])[::-1] + (ret[4:8])[::-1] + (ret[8:12])[::-1] + (ret[12:16])[::-1] + (ret[16:20])[::-1] + (ret[20:24])[::-1] + (ret[24:28])[::-1] + (ret[28:32])[::-1])
print(list_ret)

# inp = b"flag{00112233445566778899aabbcc}"
# inp = (inp[0:4])[::-1] + (inp[4:8])[::-1] + (inp[8:12])[::-1] + (inp[12:16])[::-1] + (inp[16:20])[::-1] + (inp[20:24])[::-1] + (inp[24:28])[::-1] + (inp[28:32])[::-1]
# key = b"\x00"*16
# ret = entea(inp,key)
# print(ret.hex())
```

然鹅得到的不可见字符:

\[17, 195, 233, 4, 248, 101, 84, 71, 227, 90, 246, 152, 90, 226, 43, 85, 217, 59, 232, 190, 102, 70, 79, 110, 211, 86, 122, 226, 100, 224, 42, 201\]

题目还有第二层，在通过第一层的tea加密与校验后，题目会检查输入的后32字节，就在这个 successWithString函数中

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-2cd056615f2373e3b4f64e292b4b4032b3f16ed3.png)  
同样copy代码到IJ中进行调试、手动源码插桩，得到:

0x67616c66 ^= iArr23\[0\](0x4a3f345a); ==&gt; 0x2d5e583c  
0x3130307b ^= iArr23\[1\];(0xf7aedde9) ==&gt; 0xc69eed92 |------1  
0x33323231 ^= iArr23\[2\]; ==&gt; 0xdb8bd63e// 0xe8b9e40f  
0x35343433 ^= iArr23\[3\](0xd8794bcf); ==&gt; 0xed4d7ffc  
0x19fd7394 = b(0x2d5e583c, 0, iArr20);3  
0x22897166 = b(0xc69eed92, 3, iArr20);6  
0xdb8bd63e ^= (0x19fd7394 + 0x22897166) + iArr23\[0x8\]; ==&gt; 0x86f2e9ff // 0x20f25ac7 ===3  
0xc37974ff = (0x86f2e9ff &gt;&gt;&gt; 1) | (0x86f2e9ff &lt;&lt; 31);  
0xda9afff9 = (0xed4d7ffc &lt;&lt; 1) | (0xed4d7ffc &gt;&gt;&gt; 31);2  
0xda9afff9 ^= ((0x22897166 \* 2) + 0x19fd7394) + iArr23\[0x9\](0x16250e5e); ==&gt; 0xafaf9b47 ===4  
0x497ab833 = b(0xc37974ff, 0, iArr20);4  
0x30ff9538 = b(0xafaf9b47, 3, iArr20);  
0x2d5e583c ^= (0x497ab833 + 0x30ff9538) + iArr23\[0xa\]; ==&gt; 0xf101f355//0x61e55dfe ===2  
0xf880f9aa = (0xf101f355 &gt;&gt;&gt; 1) | (0xf101f355 &lt;&lt; 31);  
0x8d3ddb25 = (0xc69eed92 &lt;&lt; 1) | (0xc69eed92 &gt;&gt;&gt; 31); ||||  
0x2df2cbac = (((0x30ff9538 \* 2) + 0x497ab833) + iArr23\[0xb\]) ^ 0x8d3ddb25; // 0xf5552de6 |3  
0x6787df4b = b(0xf880f9aa, 0, iArr20);3  
0x9d41b5e = b(0x2df2cbac, 3, iArr20);6  
0xc37974ff ^= (0x6787df4b + 0x9d41b5e) + iArr23\[0xc\]; ==&gt; 0x6dbae9d9 // 0x3d67a27d ===3  
0xb6dd74ec = (0x6dbae9d9 &gt;&gt;&gt; 1) | (0x6dbae9d9 &lt;&lt; 31);  
0x5f5f368f = (0xafaf9b47 &lt;&lt; 1) | (0xafaf9b47 &gt;&gt;&gt; 31);2  
0x5f5f368f ^= ((0x9d41b5e \* 2) + 0x6787df4b) + iArr23\[0xd\](0x21ecb038); ==&gt; 0xc243f0b0 ===4  
0x1fb2c954 = b(0xb6dd74ec, 0, iArr20);4  
0x43ccd623 = b(0xc243f0b0, 3, iArr20);  
0xf880f9aa ^= (0x1fb2c954 + 0x43ccd623) + iArr23\[0xe\]; ==&gt; 0x3a6c9122//0x5f6cc911 ===2  
0x1d364891 = (0x3a6c9122 &gt;&gt;&gt; 1) | (0x3a6c9122 &lt;&lt; 31);  
0x5be59758 = (0x2df2cbac &lt;&lt; 1) | (0x2df2cbac &gt;&gt;&gt; 31); ||||  
0x8695a30c = (((0x43ccd623 \* 2) + 0x1fb2c954) + iArr23\[0xf\]) ^ 0x5be59758; // 0x3623beba |3  
0xcff94abd = b(0x1d364891, 0, iArr20);3  
0x540f5a39 = b(0x8695a30c, 3, iArr20);6  
0xb6dd74ec ^= (0xcff94abd + 0x540f5a39) + iArr23\[0x10\]; ==&gt; 0xc8e585f // 0x964a87bd ===3  
0x86472c2f = (0xc8e585f &gt;&gt;&gt; 1) | (0xc8e585f &lt;&lt; 31);  
0x8487e161 = (0xc243f0b0 &lt;&lt; 1) | (0xc243f0b0 &gt;&gt;&gt; 31);2  
0x8487e161 ^= ((0x540f5a39 \* 2) + 0xcff94abd) + iArr23\[0x11\](0xee57fd73); ==&gt; 0xe2e81dc3 ===4  
0x1a08621b = b(0x86472c2f, 0, iArr20);4  
0x6b0391f8 = b(0xe2e81dc3, 3, iArr20);  
0x1d364891 ^= (0x1a08621b + 0x6b0391f8) + iArr23\[0x12\]; ==&gt; 0xc35f07bc//0x595d5b1a ===2  
0x61af83de = (0xc35f07bc &gt;&gt;&gt; 1) | (0xc35f07bc &lt;&lt; 31);  
0xd2b4619 = (0x8695a30c &lt;&lt; 1) | (0x8695a30c &gt;&gt;&gt; 31); ||||  
0x2ff94fce = (((0x6b0391f8 \* 2) + 0x1a08621b) + iArr23\[0x13\]) ^ 0xd2b4619; // 0x32c283cc |3  
0x4661dd00 = b(0x61af83de, 0, iArr20);3  
0x8bf89c61 = b(0x2ff94fce, 3, iArr20);6  
0x86472c2f ^= (0x4661dd00 + 0x8bf89c61) + iArr23\[0x14\]; ==&gt; 0x23e490f5 // 0xd3494379 ===3  
0x91f2487a = (0x23e490f5 &gt;&gt;&gt; 1) | (0x23e490f5 &lt;&lt; 31);  
0xc5d03b87 = (0xe2e81dc3 &lt;&lt; 1) | (0xe2e81dc3 &gt;&gt;&gt; 31);2  
0xc5d03b87 ^= ((0x8bf89c61 \* 2) + 0x4661dd00) + iArr23\[0x15\](0xbccb79b0); ==&gt; 0xdeceb4f5 ===4  
0x31b07561 = b(0x91f2487a, 0, iArr20);4  
0x6790ca96 = b(0xdeceb4f5, 3, iArr20);  
0x61af83de ^= (0x31b07561 + 0x6790ca96) + iArr23\[0x16\]; ==&gt; 0x8fe6a61c//0x5507e5cb ===2  
0x47f3530e = (0x8fe6a61c &gt;&gt;&gt; 1) | (0x8fe6a61c &lt;&lt; 31);  
0x5ff29f9c = (0x2ff94fce &lt;&lt; 1) | (0x2ff94fce &gt;&gt;&gt; 31); ||||  
0xeff622f4 = (((0x6790ca96 \* 2) + 0x31b07561) + iArr23\[0x17\]) ^ 0x5ff29f9c; // 0xaf32b2db |3  
0x474d7304 = b(0x47f3530e, 0, iArr20);3  
0x5fd432f1 = b(0xeff622f4, 3, iArr20);6  
0x91f2487a ^= (0x474d7304 + 0x5fd432f1) + iArr23\[0x18\]; ==&gt; 0x33364523 // 0xfba26764 ===3  
0x999b2291 = (0x33364523 &gt;&gt;&gt; 1) | (0x33364523 &lt;&lt; 31);  
0xbd9d69eb = (0xdeceb4f5 &lt;&lt; 1) | (0xdeceb4f5 &gt;&gt;&gt; 31);2  
0xbd9d69eb ^= ((0x5fd432f1 \* 2) + 0x474d7304) + iArr23\[0x19\](0x54e5392f); ==&gt; 0xe6467bfe ===4  
0x177c0f76 = b(0x999b2291, 0, iArr20);4  
0x3b4fa32b = b(0xe6467bfe, 3, iArr20);  
0x47f3530e ^= (0x177c0f76 + 0x3b4fa32b) + iArr23\[0x1a\]; ==&gt; 0x739a5452//0xe19d54bb ===2  
0x39cd2a29 = (0x739a5452 &gt;&gt;&gt; 1) | (0x739a5452 &lt;&lt; 31);  
0xdfec45e9 = (0xeff622f4 &lt;&lt; 1) | (0xeff622f4 &gt;&gt;&gt; 31); ||||  
0xd48e563b = (((0x3b4fa32b \* 2) + 0x177c0f76) + iArr23\[0x1b\]) ^ 0xdfec45e9; // 0x7d46be06 |3  
0x5c8a91bd = b(0x39cd2a29, 0, iArr20);3  
0xea722412 = b(0xd48e563b, 3, iArr20);6  
0x999b2291 ^= (0x5c8a91bd + 0xea722412) + iArr23\[0x1c\]; ==&gt; 0x852ab142 // 0xd5b4de04 ===3  
0x429558a1 = (0x852ab142 &gt;&gt;&gt; 1) | (0x852ab142 &lt;&lt; 31);  
0xcc8cf7fd = (0xe6467bfe &lt;&lt; 1) | (0xe6467bfe &gt;&gt;&gt; 31);2  
0xcc8cf7fd ^= ((0xea722412 \* 2) + 0x5c8a91bd) + iArr23\[0x1d\](0x2589f418); ==&gt; 0x9a743a04 ===4  
0xc975685 = b(0x429558a1, 0, iArr20);4  
0x7a975dc0 = b(0x9a743a04, 3, iArr20);  
0x39cd2a29 ^= (0xc975685 + 0x7a975dc0) + iArr23\[0x1e\]; ==&gt; 0xff9357b8//0x3f2fc94c ===2  
0x7fc9abdc = (0xff9357b8 &gt;&gt;&gt; 1) | (0xff9357b8 &lt;&lt; 31);  
0xa91cac77 = (0xd48e563b &lt;&lt; 1) | (0xd48e563b &gt;&gt;&gt; 31); ||||  
0x18f4c030 = (((0x7a975dc0 \* 2) + 0xc975685) + iArr23\[0x1f\]) ^ 0xa91cac77; // 0xb0225a42 |3  
0x89d6ba0f = b(0x7fc9abdc, 0, iArr20);3  
0xc674cb34 = b(0x18f4c030, 3, iArr20);6  
0x429558a1 ^= (0x89d6ba0f + 0xc674cb34) + iArr23\[0x20\]; ==&gt; 0x5c9f732e // 0xcdbea64c ===3  
0x2e4fb997 = (0x5c9f732e &gt;&gt;&gt; 1) | (0x5c9f732e &lt;&lt; 31);  
0x34e87409 = (0x9a743a04 &lt;&lt; 1) | (0x9a743a04 &gt;&gt;&gt; 31);2  
0x34e87409 ^= ((0xc674cb34 \* 2) + 0x89d6ba0f) + iArr23\[0x21\](0xcc7ded88); ==&gt; 0xd7d649f6 ===4  
0x6b5a3141 = b(0x2e4fb997, 0, iArr20);4  
0x3bf01654 = b(0xd7d649f6, 3, iArr20);  
0x7fc9abdc ^= (0x6b5a3141 + 0x3bf01654) + iArr23\[0x22\]; ==&gt; 0x2d657a15//0xab628a34 ===2  
0x96b2bd0a = (0x2d657a15 &gt;&gt;&gt; 1) | (0x2d657a15 &lt;&lt; 31);  
0x31e98060 = (0x18f4c030 &lt;&lt; 1) | (0x18f4c030 &gt;&gt;&gt; 31); ||||  
0xb7b0d8b8 = (((0x3bf01654 \* 2) + 0x6b5a3141) + iArr23\[0x23\]) ^ 0x31e98060; // 0xa31efaef |3  
0x64ec4e34 = b(0x96b2bd0a, 0, iArr20);3  
0x82e4ece7 = b(0xb7b0d8b8, 3, iArr20);6  
0x2e4fb997 ^= (0x64ec4e34 + 0x82e4ece7) + iArr23\[0x24\]; ==&gt; 0xd7bc1e35 // 0x12226c87 ===3  
0xebde0f1a = (0xd7bc1e35 &gt;&gt;&gt; 1) | (0xd7bc1e35 &lt;&lt; 31);  
0xafac93ed = (0xd7d649f6 &lt;&lt; 1) | (0xd7d649f6 &gt;&gt;&gt; 31);2  
0xafac93ed ^= ((0x82e4ece7 \* 2) + 0x64ec4e34) + iArr23\[0x25\](0x5a7315c8); ==&gt; 0x6a85ae27 ===4  
0xfeb287a4 = b(0xebde0f1a, 0, iArr20);4  
0x36fe6679 = b(0x6a85ae27, 3, iArr20);  
0x96b2bd0a ^= (0xfeb287a4 + 0x36fe6679) + iArr23\[0x26\]; ==&gt; 0x4163ca4c//0xa2208929 ===2  
0x20b1e526 = (0x4163ca4c &gt;&gt;&gt; 1) | (0x4163ca4c &lt;&lt; 31);  
0x6f61b171 = (0xb7b0d8b8 &lt;&lt; 1) | (0xb7b0d8b8 &gt;&gt;&gt; 31); ||||  
0x812f8133 = (((0x36fe6679 \* 2) + 0xfeb287a4) + iArr23\[0x27\]) ^ 0x6f61b171; // 0x819edbac |3  
0xebde0f1a ^= iArr23\[4\](0xe1429065) ==&gt; 0xa9c9f7f // 0xe1429065  
0x6a85ae27 ^= iArr23\[5\](0xb67e9807); ==&gt; 0xdcfb3620  
0x20b1e526 ^= iArr23\[6\](0x704d77b4); ==&gt; 0x50fc9292  
0x812f8133 ^= iArr23\[7\](0xedd067b7); ==&gt; 0x6cffe684  
cmp en\_inp, final\_cip  
dump en\_inp:  
0x7f,0x9f,0x9c,0xa,0x20,0x36,0xfb,0xdc,0x92,0x92,0xfc,0x50,0x84,0xe6,0xff,0x6c,  
dump final cip:  
0x9f,0x2e,0x80,0xd3,0x38,0x22,0x16,0xdf,0xec,0x96,0xfc,0x8f,0x1a,0x22,0x88,0x73,

整理出加密函数为:

```php
void enc() {
    unsigned int N1 = inp1 ^ iArr23[0];
    unsigned int N2 = inp2 ^ iArr23[1];
    unsigned int N3 = inp3 ^ iArr23[2];
    unsigned int N4 = inp4 ^ iArr23[3];
    unsigned int x1 = 0;
    unsigned int x2 = 0;
    for (int i = 0; i < 8; i += 1) {
        x1 = b(N1, 0, iArr20);
        x2 = b(N2, 3, iArr20);
        N3 ^= (x1 + x2) + iArr23[8 + i * 4 + 0];
        N3 = Rror(N3, 1);
        N4 = Lror(N4, 1);
        N4 ^= ((x2 * 2) + x1) + iArr23[8 + i * 4 + 1];

        x1 = b(N3, 0, iArr20);
        x2 = b(N4, 3, iArr20);
        N1 ^= (x1 + x2) + iArr23[8 + i * 4 + 2];
        N1 = Rror(N1, 1);
        N2 = Lror(N2, 1);
        N2 ^= (((x2 * 2) + x1) + iArr23[8 + i * 4 + 3]);

    }
    N3 ^= iArr23[4];
    N4 ^= iArr23[5];
    N1 ^= iArr23[6];
    N2 ^= iArr23[7];
}
```

### exp

事实上这只是前16字节的加密，还有后16字节的加密，加密算法并不一样，不过后16字节的加密就一个 xor

给出后32字节的exp:

```php
#include <stdio.h>

unsigned int inp1 = 0x67616c66;
unsigned int inp2 = 0x3130307b;
unsigned int inp3 = 0x33323231;
unsigned int inp4 = 0x35343433;

unsigned int iArr23[40] = { 0x4a3f345a,0xf7aedde9,0xe8b9e40f,0xd8794bcf,0xe1429065,0xb67e9807,0x704d77b4,0xedd067b7,0x20f25ac7,0x16250e5e,0x61e55dfe,0xf5552de6,0x3d67a27d,0x21ecb038,0x5f6cc911,0x3623beba,0x964a87bd,0xee57fd73,0x595d5b1a,0x32c283cc,0xd3494379,0xbccb79b0,0x5507e5cb,0xaf32b2db,0xfba26764,0x54e5392f,0xe19d54bb,0x7d46be06,0xd5b4de04,0x2589f418,0x3f2fc94c,0xb0225a42,0xcdbea64c,0xcc7ded88,0xab628a34,0xa31efaef,0x12226c87,0x5a7315c8,0xa2208929,0x819edbac };
unsigned int iArr20[1024] = { 0x9797f5c4,0x6929a9a9,0xd8d888a0,0x33d17c7c,0xc3c399b4,0x4fb22121,0xa3a35c97,0x6ec1f6f6,0x6e6ecf2b,0x77840b0b,0x1a1ae09d,0xef3af9f9,0x94948f36,0xa7608787,0x6d6db5d9,0x3bdb7272,0xb5b53d79,0xaa346161,0x3131272c,0x6526a0a0,0xeaead57e,0xf321ecec,0xededd07a,0x5d108a8a,0x2c2cc2b5,0x9a084545,0x161661ee,0x485a7e7e,0x404086e5,0x2576d0d0,0xe8e85e05,0xd5ba6464,0x73732ab2,0x2e918686,0xcccc6235,0xa5d63030,0x5c5c92f5,0xccff9999,0xdbdbf252,0x78665a5a,0x9999ffcc,0x396dc5c5,0xababa212,0x82165757,0x3e3edcad,0xaf6a8989,0xbcbc3275,0x62ceffff,0xf9f93aef,0xb499c3c3,0xcfcf18c7,0xae316666,0x9f9f0b41,0xd309d4d4,0x18186be6,0xe5864040,0x5a5a6678,0xbe75656,0x88889b26,0xa23e6f6f,0x3939d9a9,0xa088d8d8,0x7070504,0x27c06767,0x6767c027,0x1c1b1515,0x70705040,0x95ea1414,0x2828bd43,0xe730f7f7,0x9090f0c0,0xa9d93939,0xcaca96b8,0xc8fa9e9e,0x272746c2,0x73810c0c,0xf8f8cb66,0xb896caca,0x494989e9,0xe8d2a6a6,0xb1b1428f,0x951e1e1,0xbebeb90e,0xeb3ffefe,0xe7e7a584,0x8e195e5e,0x53536974,0x5efdd2d2,0xfefe3feb,0x181e1212,0x8585ebdc,0x85fe0808,0x42420d9e,0xecd7a1a1,0x6969ca2f,0x9cbbf5f5,0x4e4e8ced,0x154af4f4,0xb4b4ccf0,0xd54e6e6,0xacaca716,0x72dae3e3,0x9c9c71b3,0x52f2dbdb,0x77775544,0xb1c72b2b,0x12121e18,0xd6573c3c,0xc7c7e642,0x229e8f8f,0xf3f34f11,0xb3719c9c,0xe5e52eff,0xf8c6baba,0x98980e45,0xdceb8585,0x525298fd,0x4c5f7979,0xf7f730e7,0xe0d8a8a8,0xa6a6d2e8,0xc4f59797,0xc9c9ec4a,0xba207d7d,0xa0a75fe,0xed8c4e4e,0x7575de3f,0xd9b56d6d,0x111164ea,0x53a93434,0x5d5d637c,0x59158d8d,0x101f189,0x8df40606,0x7c7cd133,0x6f9a1919,0x808065a3,0xdb03dada,0x29294cca,0xca4c2929,0x6b6b4154,0x3fde7575,0x2222c8bd,0x834db8b8,0x7f7fabc1,0xd4e18b8b,0x32325dde,0xff2ee5e5,0xdada03db,0x86135050,0x1414ea95,0x584e6262,0xbfbf4887,0x7d38b2b2,0x7b7bd437,0xb09cc4c4,0x7e7e5a48,0x2d7cdede,0x9b9b74b7,0xfe25151,0xfbfbb194,0x60784848,0x4a4af31b,0x303c2424,0x3a3aa35b,0x44557777,0xdfdf8da4,0xd2523b3b,0x1c1c1410,0x47b82f2f,0x2b2bc7b1,0x89f10101,0x2f2fb847,0x5af8d5d5,0x8d8d1559,0xb9cd2525,0x4b4b0292,0x6c774141,0xd2d2fd5e,0xee611616,0xdede7c2d,0x13f94444,0x9e9efac8,0x5ba33a3a,0xa2a2ad1e,0x2b6b7b7,0xb2b2387d,0xf1975b5b,0x89896aaf,0xa3658080,0x5e5e198e,0x7532bcbc,0x6f6f3ea2,0xbb7b9292,0x202043c6,0xc1ab7f7f,0x9a9a853e,0x9de01a1a,0xa1a1d7ec,0xeb9bebe,0xd0d07625,0x328a9393,0xf0f035e3,0xcf12c1c1,0xd3d30cd7,0xc718cfcf,0xf4f44a15,0x49019191,0x5b5b97f1,0x8b47b6b6,0x15151b1c,0xf4c9b3b3,0xaeae2c6d,0x2173d7d7,0x1313ef91,0x54416b6b,0x4343fc17,0xc0f09090,0x3434a953,0xbf7e9595,0x6363bfd1,0x94b1fbfb,0xe4e4df76,0x14111b1b,0xcecee94e,0x16a7acac,0x57571682,0x8f42b1b1,0xfafa401d,0x7ed5eaea,0x7676a4cd,0xe335f0f0,0xe6e6540d,0x9f56adad,0x8a8a105d,0x242d3f3f,0x606f48d,0xe66b1818,0x666631ae,0xb22a7373,0xeeeeaa88,0xf0ccb4b4,0x6464bad5,0x450e9898,0xafafdde4,0x1eada2a2,0x4141776c,0xd8ee8282,0x8b8be1d4,0x1bf34a4a,0x3b3b52d2,0x2fca6969,0x84841a55,0x9e0d4242,0x4545089a,0xcda47676,0xaaaa539b,0x3d68c2c2,0x6a6ab0dd,0x99e51d1d,0x8282eed8,0xea641111,0x4f4f7d64,0xfd985252,0xf1f1c46a,0xf724ebeb,0x7d7d20ba,0x56f7dcdc,0xd6d682a8,0x6d2caeae,0x8e8e6fab,0xbc93cdcd,0x4d4df61f,0x8748bfbf,0xa8a8d8e0,0x975ca3a3,0x74742fb6,0x1aa8a5a5,0x7272db3b,0xde5d3232,0x10109563,0x2c273131,0xb7b7b602,0xbe257a7a,0xd9d97929,0x4bb72626,0x93938a32,0xc31dc8c8,0xbabac6f8,0x9b53aaaa,0x46467268,0xe4ddafaf,0x68683ba6,0x9359a4a4,0xb3b3c9f4,0xfcc3bdbd,0x8181942a,0x511f8383,0x1e1e9f6b,0x3e859a9a,0xcbcb6731,0x57ac3333,0xa4a45993,0x551a8484,0x3f3f2d24,0x6123a7a7,0x9090f0c,0x63951010,0xe0e0a08,0x10141c1c,0xe9e9af8c,0x67901717,0xc6c617cb,0x6b9f1e1e,0x19199a6f,0x37d47b7b,0xd0d70fa,0xc9a17171,0x17179067,0x7b8b0202,0x83831f51,0x7e85f5f,0xefef5b01,0x50446c6c,0x3c3c57d6,0xb62f7474,0xa7a72361,0x1d40fafa,0xe0e0a080,0x46e3c0c0,0xc2c2683d,0xd70cd3d3,0xb9b9bc0a,0x4aecc9c9,0x2d2d333c,0xf27a0303,0x79795f4c,0x368f9494,0xdcdcf756,0x40507070,0xa9a92969,0xc5ae7878,0x92927bbb,0x1945fdfd,0x353558da,0x20283838,0xa0a02665,0x38362a2a,0x5058e7f,0xddb06a6a,0xfcfcb490,0x0,0xbdbdc3fc,0x55ee8e8,0x1f1f6ee2,0x76dfe4e4,0x8f8f9e22,0x410b9f9f,0x9d9d803a,0xe26e1f1f,0xd5d5f85a,0x88aaeeee,0xdddd06df,0xa1d33737,0x91910149,0x81fb0f0f,0x59591c8a,0x66cbf8f8,0x54546c70,0x3a809d9d,0x8c8ce4d0,0x4050707,0x6060c523,0xcb17c6c6,0x2028b7b,0x793db5b5,0x48487860,0x98bef2f2,0x2626b74b,0xc2462727,0xd7d77321,0x42e6c7c7,0xf6f6c16e,0x1ff64d4d,0x50501386,0x92024b4b,0x1b1b1114,0x7c635d5d,0xd1d187ac,0xdf06dddd,0x23233934,0x8a1c5959,0x9696044d,0x6ac4f1f1,0x808fe85,0x2bcf6e6e,0xecec21f3,0x5c4b6565,0xc1c112cf,0xa882d6d6,0x95957ebf,0xfa700d0d,0x3030d6a5,0xe1834747,0x7878aec5,0xf5925c5c,0x5f5fe807,0x269b8888,0x2121b24f,0xda583535,0x1d1de599,0x2979d9d9,0xe2e22bfb,0xd1bf6363,0x2525cdb9,0x3167cbcb,0x3333ac57,0xf67f0404,0x474783e1,0x80a0e0e,0x5151e20f,0x17fc4343,0x6c6c4450,0x43bd2828,0x7171a1c9,0xb7749b9b,0x3737d3a1,0x74695353,0xc5c56d39,0x114ff3f3,0xc0c0e346,0x706c5454,0xa5a5a81a,0x80a0e0e0,0x0,0x2a948181,0x4c4c0796,0x84a5e7e7,0xcdcd93bc,0xfe750a0a,0x878760a7,0x15befef,0x36362228,0x7f8e0505,0x55559df9,0x3c332d2d,0x616134aa,0xf99d5555,0xb0b8477,0x68724646,0x2e2e49ce,0xc6432020,0x5656e70b,0xbdc82222,0x2a2a3638,0x7ad0eded,0x8686912e,0xab6f8e8e,0x65654b5c,0xac87d1d1,0x7a7a25be,0x4d049696,0xf0ffb81,0xe9894949,0xf5f5bb9c,0x34392323,0xe1e15109,0xa63b6868,0x4444f913,0x3ed5858,0x3037af2,0x5fa63d3d,0x38382820,0x90b4fcfc,0xc4c49cb0,0xfb2be2e2,0xb6b6478b,0x6b3b0b0,0xfdfd4519,0x96074c4c,0xd4d409d3,0x23c56060,0x24243c30,0x3562cccc,0xbbbb3771,0x91ef1313,0xc0c8173,0xaddc3e3e,0xb0b0b306,0x28223636,0xf2f2be98,0x12a2abab,0xadad569f,0xd0e48c8c,0x5858ed03,0xce492e2e,0x62624e58,0x7137bbbb,0x3d3da65f,0x8cafe9e9,0xebeb24f7,0x647d4f4f,0xffffce62,0xc0f0909,0xe3e3da72,0xabcb9b9,0xb8b84d83,0x4ee9cece,0x4047ff6,0xa48ddfdf,0xc8c81dc3,0xb5c22c2c,0x5d7c5d63,0xee82d8ee,0x9cb39c71,0xb6b702b6,0x29ca294c,0x8347e183,0xbe0ebeb9,0x5f794c5f,0x74b6742f,0x1914901,0xf59cf5bb,0x56ad9f56,0xfc90fcb4,0xe3c046e3,0x35da3558,0xea1495ea,0x89af896a,0x6c54706c,0xab12aba2,0xdb723bdb,0xdddfdd06,0x9b88269b,0xed7aedd0,0xbf63d1bf,0x5cf55c92,0x8f94368f,0xd8a0d888,0xceff62ce,0x16ee1661,0xcbf866cb,0x5f075fe8,0xa171c9a1,0x1fe21f6e,0xdae372da,0x4d1f4df6,0x8459a08,0x3cd63c57,0x95106395,0x39a939d9,0xada21ead,0x20c62043,0xde753fde,0xb770b84,0x1dc8c31d,0xd4d3d409,0xf090c0f,0x9845980e,0x492ece49,0xad9fad56,0xf64d1ff6,0x32de325d,0x573cd657,0xf866f8cb,0xd17c33d1,0x88508fe,0xe7560be7,0x149514ea,0xcf6e2bcf,0x9d3a9d80,0xed5803ed,0x66ae6631,0x91862e91,0x3a5b3aa3,0xa5e784a5,0x3f243f2d,0xab7fc1ab,0xa6e8a6d2,0xb3b006b3,0xd6a8d682,0x7e95bf7e,0xae6dae2c,0xca692fca,0xcb31cb67,0x79d92979,0xf810ffb,0xc56023c5,0xd55ad5f8,0x859a3e85,0xdadbda03,0x6f8eab6f,0x6b546b41,0x975bf197,0x8d598d15,0xe85f07e8,0x441344f9,0x32bc7532,0x17671790,0x7b92bb7b,0xbc75bc32,0xba64d5ba,0xbf87bf48,0xff99ccff,0x602360c5,0xe6c742e6,0xc730c81,0x2d3f242d,0x57825716,0x1a84551a,0xa8e0a8d8,0x750afe75,0x6c506c44,0x3af9ef3a,0x196f199a,0x42b18f42,0xf66ef6c1,0x700dfa70,0x9f419f0b,0xc72bb1c7,0xb006b0b3,0x6580a365,0x78c578ae,0xf94413f9,0x10631095,0xfa9ec8fa,0xe2fbe22b,0x72466872,0x49e94989,0xb06addb0,0xe372e3da,0x12c1cf12,0xd1acd187,0x4627c246,0x90c090f0,0x3ffeeb3f,0xd929d979,0xfdd25efd,0x2ece2e49,0xb9f410b,0x73b2732a,0xbef298be,0x76cd76a4,0x158d5915,0x812a8194,0x749bb774,0x214f21b2,0x96cab896,0x9436948f,0xc6baf8c6,0x655c654b,0x13508613,0xcab8ca96,0x9e8f229e,0x459a4508,0x77416c77,0xa397a35c,0xb82f47b8,0x580358ed,0x24ebf724,0x794c795f,0xa63d5fa6,0xaa9baa53,0x6116ee61,0x22bd22c8,0x1f83511f,0xbdfcbdc3,0xd630a5d6,0xb883b84d,0x87d1ac87,0x2d3c2d33,0x23a76123,0x7e487e5a,0x2be2fb2b,0xcdbccd93,0x6dc5396d,0xcfc7cf18,0x55774455,0xa493a459,0xc1f66ec1,0x63d163bf,0xbbf59cbb,0xbaf8bac6,0x59a49359,0x1c101c14,0x332d3c33,0x1d991de5,0xf10189f1,0x70407050,0x6dddf06,0xc6cbc617,0x62cc3562,0x431743fc,0x16578216,0x47e14783,0x4964d04,0x1218121e,0xaaee88aa,0x8455841a,0xc22cb5c2,0x2cb52cc2,0x4b655c4b,0x2bb12bc7,0xa8a51aa8,0xb27db238,0xd337a1d3,0x5e8e5e19,0xb7264bb7,0x264b26b7,0x8e057f8e,0x87a78760,0xa2ab12a2,0xde2dde7c,0xb9be0eb9,0xb702b7b6,0x3b68a63b,0x71c971a1,0xe9ce4ee9,0xe5ffe52e,0x840b7784,0x4f644f7d,0x51e10951,0xc94ac9ec,0x9cc4b09c,0xc046c0e3,0x37bb7137,0x1a9d1ae0,0xa0e080a,0xa1eca1d7,0x54e60d54,0xf7e7f730,0xa7ac16a7,0xd721d773,0xa33a5ba3,0x57f058e,0xf8d55af8,0xfd19fd45,0x5835da58,0x52fd5298,0x48bf8748,0xe98ce9af,0x719cb371,0x4a1b4af3,0x39233439,0x6add6ab0,0x4af4154a,0x2a382a36,0x8c4eed8c,0xe476e4df,0x27312c27,0x77447755,0xd5ea7ed5,0x6dd96db5,0x5ee8055e,0x50865013,0x29a96929,0x68a6683b,0x8a93328a,0x7b377bd4,0x30f7e730,0x40e54086,0x207dba20,0x92bb927b,0xe2510fe2,0x38203828,0xc3bdfcc3,0x964d9604,0xf090c0f0,0x27b028b,0x94812a94,0x753f75de,0xb2214fb2,0xebf7eb24,0xfe0885fe,0x723b72db,0x108a5d10,0x90c090f,0x68c23d68,0x692f69ca,0x3e6fa23e,0xea7eead5,0x2ee5ff2e,0x8cd08ce4,0x53aa9b53,0x8826889b,0x8640e586,0xc1cfc112,0x47b68b47,0x9a3e9a85,0xe01a9de0,0x8bd48be1,0x3dadb03,0xef01ef5b,0x1b151c1b,0xa761a723,0xa93453a9,0xe805e85e,0x67cb3167,0x3bd23b52,0x22362822,0x68d06f4,0x635d7c63,0xf415f44a,0xa476cda4,0x30a530d6,0xe48cd0e4,0x7dba7d20,0x4ff3114f,0x151c151b,0xddafe4dd,0xfb94fbb1,0x4320c643,0xdfa0d70,0x8b027b8b,0x7fc17fab,0x5bef015b,0xb4f0b4cc,0x665a7866,0xe60de654,0xccb4f0cc,0xd25ed2fd,0x7f04f67f,0x7abe7a25,0xd47b37d4,0x8eab8e6f,0xef1391ef,0x61aa6134,0x195e8e19,0xc4b0c49c,0xdfe476df,0xb68bb647,0x5070405,0x36283622,0xd8a8e0d8,0x510f51e2,0xd2a6e8d2,0x560b56e7,0x2cae6d2c,0x5bf15b97,0x4db8834d,0x18e6186b,0xe98450e,0xff62ffce,0x9d4d309,0x11ea1164,0xcd3d70c,0xb579b53d,0x7a03f27a,0x5a785a66,0x6b18e66b,0xb18fb142,0xd0ed7ad0,0x335733ac,0xeb85dceb,0x4b924b02,0xc822bdc8,0x8a5d8a10,0x3db5793d,0x6258624e,0xb56dd9b5,0x4eed4e8c,0x9a196f9a,0x598a591c,0x35f0e335,0xc23dc268,0x6e1fe26e,0x46684672,0xd429e0d,0xc742c7e6,0x9852fd98,0x9bb79b74,0xfc4317fc,0x37a137d3,0x3461aa34,0x80a38065,0xfb0f81fb,0xd3d7d30c,0x9f1e6b9f,0xdfa4df8d,0xe51d99e5,0x2f472fb8,0x6a89af6a,0xfeebfe3f,0xf2db52f2,0x9332938a,0x50704050,0xfa1dfa40,0xd7a1ecd7,0xe080e0a0,0xbcb90abc,0x672767c0,0x446c5044,0x53745369,0x925cf592,0xbb71bb37,0x5d32de5d,0xb90ab9bc,0x74c9607,0xcc35cc62,0xc06727c0,0x25b925cd,0xcd25b9cd,0x862e8691,0x4e62584e,0x5470546c,0x3166ae31,0x416c4177,0xdc3eaddc,0xc3b4c399,0x362a3836,0x85dc85eb,0xc9b3f4c9,0xecf3ec21,0x257abe25,0xe784e7a5,0x1c598a1c,0xf311f34f,0x8949e989,0x312c3127,0xc4f16ac4,0xafe0a75,0xf34a1bf3,0x1e6b1e9f,0xf4068df4,0xdb52dbf2,0x17c6cb17,0x3d5f3da6,0x28382028,0x7c337cd1,0x24b9202,0x99cc99ff,0x90176790,0x2430243c,0x8ddfa48d,0x55f9559d,0x6087a760,0x4f6047f,0xbd2843bd,0xa065a026,0xafe98caf,0xf9eff93a,0x73d72173,0x48604878,0xd939a9d9,0x8f228f9e,0x809d3a80,0xd025d076,0x141c1014,0x345334a9,0x416b5441,0x1b141b11,0x82d6a882,0x91499101,0xa0e080a0,0x27c22746,0x78486078,0xf16af1c4,0xac3357ac,0xb3f4b3c9,0x76d02576,0x9ec89efa,0xb4fc90b4,0x8351831f,0x5a7e485a,0xe080e0a,0xf7dc56f7,0x64d564ba,0x88d8a088,0xdc56dcf7,0xae78c5ae,0x97c497f5,0x7cde2d7c,0x6e2b6ecf,0x810c7381,0xf298f2be,0x38b27d38,0x4c964c07,0x2a73b22a,0xe109e151,0x3c24303c,0xf0e3f035,0xe18bd4e1,0xc8c3c81d,0x45fd1945,0x23342339,0xb1fb94b1,0x82d882ee,0x7d4f647d,0x3f2037a,0x523bd252,0xa51aa5a8,0x21ecf321,0x18901f1,0x26a06526,0x7040705,0xf597c4f5,0xee88eeaa,0x9d55f99d,0xa21ea2ad,0x69537469,0xce4ecee9,0x93cdbc93,0xa969a929,0xecc94aec,0x429e420d,0x5ca3975c,0x139113ef,0x4c29ca4c,0x95bf957e,0x40fa1d40,0x0,0x1e12181e,0x3ead3edc,0x18cfc718,0xac16aca7,0x6411ea64,0xafe4afdd,0x2f74b62f,0x284328bd,0x99c3b499,0xc539c56d,0x111b1411,0x6fa26f3e,0x0 };

unsigned int Rror(unsigned int m, int cnt) {
    return (m >> cnt) | (m << (32 - cnt));
}

unsigned int Lror(unsigned int m, int cnt) {
    return (m << cnt) | (m >> (32 - cnt));
}

unsigned char get_byte1(unsigned int v) {
    return v >> 8 & 0xFF;
}

unsigned char get_byte2(unsigned int v) {
    return v >> 16 & 0xFF;
}

unsigned char get_high_byte(unsigned int v) {
    return v >> 24 & 0xFF;
}

unsigned char get_byte_by_mode(unsigned int v, int mode) {
    switch (mode % 4) {
    case 0: {
        return v & 0xFF;
    }
    case 1: {
        return get_byte1(v);
    }
    case 2: {
        return get_byte2(v);
    }
    case 3: {
        return get_high_byte(v);
    }
    default: {
        return 0;
    }
    }
}

unsigned int b(unsigned int v, int mode_0_3, unsigned int arr_v[]) {
    unsigned v2 = arr_v[get_byte_by_mode(v, mode_0_3) * 2] ^ arr_v[get_byte_by_mode(v, mode_0_3 + 1) * 2 + 1] ^ arr_v[get_byte_by_mode(v, mode_0_3 + 2) * 2 + 0x200];
    return arr_v[get_byte_by_mode(v, mode_0_3 + 3) * 2 + 0x201] ^ v2;
}

void enc() {
    unsigned int N1 = inp1 ^ iArr23[0];
    unsigned int N2 = inp2 ^ iArr23[1];
    unsigned int N3 = inp3 ^ iArr23[2];
    unsigned int N4 = inp4 ^ iArr23[3];
    unsigned int x1 = 0;
    unsigned int x2 = 0;
    for (int i = 0; i < 8; i += 1) {
        x1 = b(N1, 0, iArr20);
        x2 = b(N2, 3, iArr20);
        N3 ^= (x1 + x2) + iArr23[8 + i * 4 + 0];
        N3 = Rror(N3, 1);
        N4 = Lror(N4, 1);
        N4 ^= ((x2 * 2) + x1) + iArr23[8 + i * 4 + 1];

        x1 = b(N3, 0, iArr20);
        x2 = b(N4, 3, iArr20);
        N1 ^= (x1 + x2) + iArr23[8 + i * 4 + 2];
        N1 = Rror(N1, 1);
        N2 = Lror(N2, 1);
        N2 ^= (((x2 * 2) + x1) + iArr23[8 + i * 4 + 3]);

    }
    N3 ^= iArr23[4];
    N4 ^= iArr23[5];
    N1 ^= iArr23[6];
    N2 ^= iArr23[7];

    printf("0x%x --- 0x%x --- 0x%x --- 0x%x\n", N3, N4, N1, N2);
}

void hexdump(unsigned int inp) {
    printf("%c", inp & 0xff);
    printf("%c", (inp >> 8) & 0xff);
    printf("%c", (inp >> 16) & 0xff);
    printf("%c", (inp >> 24) & 0xff);

}
bool test_dec() {
    unsigned int N3 = 0xa9c9f7f;
    unsigned int N4 = 0xdcfb3620;
    unsigned int N1 = 0x50fc9292;
    unsigned int N2 = 0x6cffe684;
    unsigned int x1 = 0;
    unsigned int x2 = 0;

    N3 ^= iArr23[4];
    N4 ^= iArr23[5];
    N1 ^= iArr23[6];
    N2 ^= iArr23[7];

    for (int i = 7; i >= 0; i--) {
        x1 = b(N3, 0, iArr20);
        x2 = b(N4, 3, iArr20);
        N1 = Lror(N1, 1);
        N1 ^= (x1 + x2) + iArr23[8 + i * 4 + 2];
        N2 ^= (((x2 * 2) + x1) + iArr23[8 + i * 4 + 3]);
        N2 = Rror(N2, 1);

        x1 = b(N1, 0, iArr20);
        x2 = b(N2, 3, iArr20);
        N3 = Lror(N3, 1);
        N3 ^= (x1 + x2) + iArr23[8 + i * 4 + 0];
        N4 ^= ((x2 * 2) + x1) + iArr23[8 + i * 4 + 1];
        N4 = Rror(N4, 1);
    }
    unsigned int inp1 = N1 ^ iArr23[0];
    unsigned int inp2 = N2 ^ iArr23[1];
    unsigned int inp3 = N3 ^ iArr23[2];
    unsigned int inp4 = N4 ^ iArr23[3];

    if (inp1 != 0x67616c66 || inp2 != 0x3130307b || inp3 != 0x33323231 || inp4 != 0x35343433) {
        return 0;
    }

    //hexdump(inp1);
    //hexdump(inp2);
    //hexdump(inp3);
    //hexdump(inp4);
    return 1;
}
void dec1() {

    if (!test_dec()) {
        printf("error dec algorithm!!!\n");
        getchar();
        return;
    }

    unsigned int N3 = 0xd3802e9f;
    unsigned int N4 = 0xdf162238;
    unsigned int N1 = 0x8ffc96ec;
    unsigned int N2 = 0x7388221a;
    unsigned int x1 = 0;
    unsigned int x2 = 0;
    N3 ^= iArr23[4];
    N4 ^= iArr23[5];
    N1 ^= iArr23[6];
    N2 ^= iArr23[7];

    for (int i = 7; i >= 0; i--) {
        x1 = b(N3, 0, iArr20);
        x2 = b(N4, 3, iArr20);
        N1 = Lror(N1, 1);
        N1 ^= (x1 + x2) + iArr23[8 + i * 4 + 2];
        N2 ^= (((x2 * 2) + x1) + iArr23[8 + i * 4 + 3]);
        N2 = Rror(N2, 1);

        x1 = b(N1, 0, iArr20);
        x2 = b(N2, 3, iArr20);
        N3 = Lror(N3, 1);
        N3 ^= (x1 + x2) + iArr23[8 + i * 4 + 0];
        N4 ^= ((x2 * 2) + x1) + iArr23[8 + i * 4 + 1];
        N4 = Rror(N4, 1);
    }
    unsigned int inp1 = N1 ^ iArr23[0];
    unsigned int inp2 = N2 ^ iArr23[1];
    unsigned int inp3 = N3 ^ iArr23[2];
    unsigned int inp4 = N4 ^ iArr23[3];

    hexdump(inp1);
    hexdump(inp2);
    hexdump(inp3);
    hexdump(inp4);
    //printf("\n");
}
void dec2() {
    unsigned char cip[] = { 0xa9,0xd9,0x76,0xbd ,0x77,0xbb,0x56,0x9a     ,0x31,0xb3,0xde,0xa8 ,0x65,0x8e,0x1a,0x32 };
    unsigned char key[] = { 0xe9 ,0x9c,0x40,0xf9,0x47,0xe2,0x19,0xcc,0x6,0xdb,0x97,0xc6,0xe,0xdd,0x2a,0x4f };
    for (int i = 0; i < 16; i++) {
        printf("%c", cip[i] ^ key[i]);
    }
    puts("");
}
int main() {
    //enc();

    dec1();
    dec2();
    return 0;

}
```

得到flag:

flag{iT3N0t7H@tH@E6D0YOV7hInkS0}

### 校验一下flag

```php
var flag = String("flag{00112233445566778899aabbcc}flag{iT3N0t7H@tH@E6D0YOV7hInkS0}");
Java.perform(function(){
    var targetClass = Java.use("H0.a");

    var ret = targetClass.successWithString(flag);
    console.log(ret);
});

```

这里我用frida主动调用来校验flag是否正确:

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/11/attach-1bca95ee1cb57c7ce374307bb141e4944522fc85.png)

事实证明是正确的

### 附件

附手动源码插桩的java文件:

./main.java:

```php
import java.util.Arrays;
import java.lang.Thread;

public class Main {
    public static void main(String[] args) throws InterruptedException {
        op_input();
        System.out.println("finish~");

    }
    static boolean z;
    public static void op_input() throws InterruptedException {
        String s = "flag{00112233445566778899aabbcc}flag{00112233445566778899aabbcc}";
//      String s = "flag{00112233445566778899aabbcc}xxxx{xxxxxxxxxxxxxxxxxxxxxxxxxx}";
//        String s = "flag{00112233445566778899aabbcc}flag{iT3N0t7H@tH@E6D0YOV7hInkS0}";

        byte[] arr_b = new byte[0];
        int[] arr_v = new int[0];
        int[] arr_v1 = new int[0];
        int v1 = 0;
        int v2 = 0;
        int v3 = 0;
        int v4 = 0;
        int v5 = 0;
        int v6 = 0;
        long v7 = 0x5BE935D0EDBFE83CL;
        int v8 = 24;
        System.out.printf("v2 = 0\n");
        while(Long.compare(v7, 0L) != 0) {
            long v9 = 0x404C98D80D628D27L;
            if(Long.compare(v7, 0x404C98D80D628D27L) == 0) {
                arr_v1[v1] = 0;
                v7 = 0x767AEC22C91BE2BFL;
            }

            long v10 = 8904566903685903062L;
            if(Long.compare(v7, 8904566903685903062L) == 0) {
                v7 = 0x29CB0C5AA5BA5210L;
            }

            long v11 = 0x7F6F5B8E28C072CFL;
            if(Long.compare(v7, 0x7F6F5B8E28C072CFL) == 0) {
                v2 -= 1640531527;
                System.out.printf("v2 -= 0x61c88647\n");
                v7 = 0x1E7D57CBFEE24485L;
            }

            long v12 = 0x123CFD69BDE0364DL;
            if(Long.compare(v7, 0x123CFD69BDE0364DL) == 0) {
                ++v3;
                System.out.printf("++v3\n");
                v7 = 0x3C57CEFFB4FFAFF4L;
            }

            long v13 = 2705319197673083720L;
            if(Long.compare(v7, 2705319197673083720L) == 0) {
                v7 = v8 == 0 ? 0x250D59D18CBA666DL : 0x7032C3F4B5EFAB31L;
            }

            long v14 = 0x41593FC8BF139758L;
            if(Long.compare(v7, 0x41593FC8BF139758L) == 0) {
                v7 = 0x69E4449C056151ACL;
                v8 = 24;
            }

            if(Long.compare(v7, 0x1F45282B0E978C91L) == 0) {
                v7 = 0x380BE8BE1044EE6DL;
            }

            long v15 = 0x2CEBD4941DD371AAL;
            if(Long.compare(v7, 0x29CB0C5AA5BA5210L) == 0) {
                v3 = 0;
                System.out.printf("v3 = 0\n");
                v7 = 0x2CEBD4941DD371AAL;
            }

            if(Long.compare(v7, 0x5260B3C741DB1316L) == 0) {
                v7 = 0x39E2DF14B65FB5B7L;
            }

            if(v7 == 0x380BE8BE1044EE6DL) {
                arr_v1[v1] |= (arr_b[v3] & 0xFF) << v8;
                System.out.printf("arr_v1[%d] |=  (arr_b[%d] & 0xFF) << %d\n",v1,v3,v8);
            }
            else {
                v13 = v7;
            }

            if(Long.compare(v13, 0x2CEBD4941DD371AAL) == 0) {
                v13 = v3 >= 8 ? 0x2A7EB92B8AF86758L : 2503205216640455778L;
                System.out.printf("cmp v3 >= 8?\n");
            }

            long v16 = 0x55CB210B059B852DL;
            long v17 = 0x5335127A3A0A4907L;
            if(Long.compare(v13, 0x55CB210B059B852DL) == 0) {
                v8 += -8;
                v13 = 0x5335127A3A0A4907L;
            }

            long v18 = 2368350050472760653L;
            if(Long.compare(v13, 2368350050472760653L) == 0) {
                v13 = 0x5A88D049059402F6L;
            }

            long v19 = 0x26D3DBBBECB952A4L;
            if(v13 == 0x26D3DBBBECB952A4L) {
                z = false;
                System.out.println("errror");
                break;
            }

            if(v13 != 0x7032C3F4B5EFAB31L) {
                v16 = v13;
            }

            if(v16 == 0x5335127A3A0A4907L) {
                ++v3;
                System.out.printf("++v3\n");
                v16 = 0x767AEC22C91BE2BFL;
            }

            if(v16 == 0x69E4449C056151ACL) {
                ++v1;
            }
            else {
                v17 = v16;
            }

            long v20 = 0x169A506C8792840DL;
            if(v17 == 0x169A506C8792840DL) {
                v3 += 2;
                System.out.printf("v3 += 2\n");
            }
            else {
                v15 = v17;
            }

            long v21 = 8829928630187910250L;
            if(v15 != 8829928630187910250L) {
                v11 = v15;
            }

            if(Long.compare(v11, 0x1E7D57CBFEE24485L) == 0) {
                v4 = (v5 << 4 ^ v5) + (v2 ^ v5 >>> 5) + v4;
                System.out.printf("v4 = (v5 << 4 ^ v5) + (v2 ^ v5 >>> 5) + v4;\n");
                v11 = 0x50E57F91E168FAC9L;
            }

            long v22 = 8153458827322010710L;
            long v23 = 0x2654EF16F510CF25L;
            if(Long.compare(v11, 8153458827322010710L) == 0) {
                v2 = 0;
                System.out.printf("v2 = 0\n");
                v11 = 0x2654EF16F510CF25L;
            }

            long v24 = 0x2981462384F2153CL;
            if(Long.compare(v11, 0x2981462384F2153CL) == 0) {
                arr_v = new int[]{0x5E5440B0, 2057046228, 0x4A1ED228, 0x233FE7C, 0x96461450, -2002358035, 0xF79BFC89, 0x20C3D75F};
                System.out.printf("arr_v = new int[]{0x5E5440B0, 2057046228, 0x4A1ED228, 0x233FE7C, 0x96461450, -2002358035, 0xF79BFC89, 0x20C3D75F};\n");
                v11 = 0x62E816E54253B307L;
            }

            if(Long.compare(v11, 0x33C51F874ED9F174L) == 0) {
                v6 = 0x20;
                v11 = 0x4D784B3DF54B096FL;
            }

            if(v11 != 0x767AEC22C91BE2BFL) {
                v10 = v11;
            }
            else if(v3 < 0x20) {
                v10 = 0x1F45282B0E978C91L;
            }

            if(v10 == 0x2A7EB92B8AF86758L) {
                v3 = 0;
                System.out.printf("v3 = 0\n");
                v10 = 0x3C57CEFFB4FFAFF4L;
            }

            if(Long.compare(v10, 0x2654EF16F510CF25L) != 0) {
                v21 = v10;
            }
            else if(v6 > 0) {
                --v6;
            }
            else {
                --v6;
                v21 = 0x1E65F68B123E6E17L;
            }

            if(Long.compare(v21, 0x5BE935D0EDBFE83CL) == 0) {
                v21 = s.length() >= 0x20 ? 0x1E47617FF0CE8BE3L : 0x7C99975CB23FC36BL;
                System.out.printf("cmp length\n");
            }

            if(v21 == 0x1E47617FF0CE8BE3L) {
                arr_b = Arrays.copyOf(s.getBytes(), 0x20);
                arr_b = new byte[]{17, (byte)195, (byte)233, 4, (byte)248, 101, 84, 71, (byte)227, 90, (byte)246, (byte)152, 90, (byte)226, 43, 85, (byte)217, 59, (byte)232, (byte)190, 102, 70, 79, 110, (byte)211, 86, 122, (byte)226, 100, (byte)224, 42, (byte)201};
            }
            else {
                v24 = v21;
            }

            if(Long.compare(v24, 0x1E65F68B123E6E17L) == 0) {
                arr_v1[v3] = v4;
                System.out.printf("arr_v1[%d] = v4;\n",v3);
                v24 = 0x6F35E9E1070E87BEL;
            }

            if(Long.compare(v24, 0x3C57CEFFB4FFAFF4L) != 0) {
                v18 = v24;
            }
            else if(v3 >= 8) {
                v18 = 0x752D25A60BA93D48L;
            }

            if(v18 == 0x752D25A60BA93D48L) {
                z = H0.a.successWithString(s);
                System.out.println("call successWithString...");
//                Thread.sleep(5000);
                break;

            }

            if(v18 != 0x250D59D18CBA666DL) {
                v14 = v18;
            }

            if(v14 == 0x62E816E54253B307L) {
                arr_v1 = new int[8];
                System.out.printf("arr_v1 = new int[8];\n");
            }
            else {
                v9 = v14;
            }

            if(v9 != 0x5A88D049059402F6L) {
                v12 = v9;
            }
            else if(arr_v1[v3] != arr_v[v3]) {
                v12 = 0x5260B3C741DB1316L;
                System.out.printf("arr_v1[%d] != arr_v[%d]\n",v3,v3);

            }

            if(v12 != 0x7C99975CB23FC36BL) {
                v19 = v12;
            }

            if(v19 == 2503205216640455778L) {
                v19 = 0x33C51F874ED9F174L;
            }

            if(v19 == 0x6F35E9E1070E87BEL) {
                arr_v1[v3 + 1] = v5;
                System.out.printf("arr_v1[%d] = v5;\n",v3+1);
            }
            else {
                v20 = v19;
            }

            v7 = 0x491A503216BAC9F4L;
            if(v20 == 0x491A503216BAC9F4L) {
                v5 = arr_v1[v3 + 1];
                System.out.printf("v5 = arr_v1[%d];\n",v3 + 1);
            }
            else {
                v22 = v20;
            }

            if(v22 == 0x50E57F91E168FAC9L) {
                v5 = (v4 << 4 ^ v4) + (v4 >>> 5 ^ v2) + v5;
                System.out.printf("v5 = (v4 << 4 ^ v4) + (v4 >>> 5 ^ v2) + v5;\n");
            }
            else {
                v23 = v22;
            }

            if(v23 != 0x39E2DF14B65FB5B7L) {
                if(v23 == 0x4D784B3DF54B096FL) {
                    v4 = arr_v1[v3];
                    System.out.printf("v4 = arr_v1[%d];\n",v3);
                    continue;
                }

                v7 = v23;
                continue;
            }

            z = false;
            System.out.println("errorrrr");
            break;
        }
        System.out.printf("dump N_cip:\n");
        for(int i=0;i<8;i++){
            System.out.printf("0x%x,",arr_v[i]);
        }
        System.out.printf("\n");
        System.out.printf("dump inp_Cip:\n");
        for(int i=0;i<8;i++){
            System.out.printf("0x%x,",arr_v1[i]);
        }
        System.out.printf("\n");

        if (z == true){
            System.out.println("success");
            Thread.sleep(5000);
        }

    }
}
```

./H0/a.java:

```php
package H0;

import java.lang.reflect.Array;
import java.util.Arrays;

/* loaded from: classes.dex */
public abstract class a {

    /* renamed from: a */
    public static final byte[][] f318a = {new byte[]{-87, 103, -77, -24, 4, -3, -93, 118, -102, -110, Byte.MIN_VALUE, 120, -28, -35, -47, 56, 13, -58, 53, -104, 24, -9, -20, 108, 67, 117, 55, 38, -6, 19, -108, 72, -14, -48, -117, 48, -124, 84, -33, 35, 25, 91, 61, 89, -13, -82, -94, -126, 99, 1, -125, 46, -39, 81, -101, 124, -90, -21, -91, -66, 22, 12, -29, 97, -64, -116, 58, -11, 115, 44, 37, 11, -69, 78, -119, 107, 83, 106, -76, -15, -31, -26, -67, 69, -30, -12, -74, 102, -52, -107, 3, 86, -44, 28, 30, -41, -5, -61, -114, -75, -23, -49, -65, -70, -22, 119, 57, -81, 51, -55, 98, 113, -127, 121, 9, -83, 36, -51, -7, -40, -27, -59, -71, 77, 68, 8, -122, -25, -95, 29, -86, -19, 6, 112, -78, -46, 65, 123, -96, 17, 49, -62, 39, -112, 32, -10, 96, -1, -106, 92, -79, -85, -98, -100, 82, 27, 95, -109, 10, -17, -111, -123, 73, -18, 45, 79, -113, 59, 71, -121, 109, 70, -42, 62, 105, 100, 42, -50, -53, 47, -4, -105, 5, 122, -84, Byte.MAX_VALUE, -43, 26, 75, 14, -89, 90, 40, 20, 63, 41, -120, 60, 76, 2, -72, -38, -80, 23, 85, 31, -118, 125, 87, -57, -115, 116, -73, -60, -97, 114, 126, 21, 34, 18, 88, 7, -103, 52, 110, 80, -34, 104, 101, -68, -37, -8, -56, -88, 43, 64, -36, -2, 50, -92, -54, 16, 33, -16, -45, 93, 15, 0, 111, -99, 54, 66, 74, 94, -63, -32}, new byte[]{117, -13, -58, -12, -37, 123, -5, -56, 74, -45, -26, 107, 69, 125, -24, 75, -42, 50, -40, -3, 55, 113, -15, -31, 48, 15, -8, 27, -121, -6, 6, 63, 94, -70, -82, 91, -118, 0, -68, -99, 109, -63, -79, 14, Byte.MIN_VALUE, 93, -46, -43, -96, -124, 7, 20, -75, -112, 44, -93, -78, 115, 76, 84, -110, 116, 54, 81, 56, -80, -67, 90, -4, 96, 98, -106, 108, 66, -9, 16, 124, 40, 39, -116, 19, -107, -100, -57, 36, 70, 59, 112, -54, -29, -123, -53, 17, -48, -109, -72, -90, -125, 32, -1, -97, 119, -61, -52, 3, 111, 8, -65, 64, -25, 43, -30, 121, 12, -86, -126, 65, 58, -22, -71, -28, -102, -92, -105, 126, -38, 122, 23, 102, -108, -95, 29, 61, -16, -34, -77, 11, 114, -89, 28, -17, -47, 83, 62, -113, 51, 38, 95, -20, 118, 42, 73, -127, -120, -18, 33, -60, 26, -21, -39, -59, 57, -103, -51, -83, 49, -117, 1, 24, 35, -35, 31, 78, 45, -7, 72, 79, -14, 101, -114, 120, 92, 88, 25, -115, -27, -104, 87, 103, Byte.MAX_VALUE, 5, 100, -81, 99, -74, -2, -11, -73, 60, -91, -50, -23, 104, 68, -32, 77, 67, 105, 41, 46, -84, 21, 89, -88, 10, -98, 110, 71, -33, 52, 53, 106, -49, -36, 34, -55, -64, -101, -119, -44, -19, -85, 18, -94, 13, 82, -69, 2, 47, -87, -41, 97, 30, -76, 80, 4, -10, -62, 22, 37, -122, 86, 85, 9, -66, -111}};

    /* renamed from: b */
    public static final int[][] f319b = (int[][]) Array.newInstance((Class<?>) Integer.TYPE, 4, 256);

    static {
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        int i10;
        for (int i11 = 0; i11 < 256; i11++) {
            byte[][] bArr = f318a;
            byte b2 = bArr[0][i11];
            int i12 = b2 & 255;
            int i13 = i12 >> 2;
            int i14 = b2 & 2;
            int i15 = 180;
            if (i14 != 0) {
                i2 = 180;
            } else {
                i2 = 0;
            }
            int i16 = i2 ^ i13;
            int i17 = b2 & 1;
            if (i17 != 0) {
                i3 = 90;
            } else {
                i3 = 0;
            }
            int i18 = ((i16 ^ i3) ^ i12) & 255;
            int i19 = i12 >> 1;
            if (i17 != 0) {
                i4 = 180;
            } else {
                i4 = 0;
            }
            int i20 = (i19 ^ i4) ^ i12;
            if (i14 != 0) {
                i5 = 180;
            } else {
                i5 = 0;
            }
            int i21 = i13 ^ i5;
            if (i17 != 0) {
                i6 = 90;
            } else {
                i6 = 0;
            }
            int i22 = ((i6 ^ i21) ^ i20) & 255;
            int i23 = bArr[1][i11];
            int i24 = i23 & 255;
            int[] iArr = {i12, i24};
            int i25 = i24 >> 2;
            int i26 = i23 & 2;
            if (i26 != 0) {
                i7 = 180;
            } else {
                i7 = 0;
            }
            int i27 = i7 ^ i25;
            int i28 = i23 & 1;
            if (i28 != 0) {
                i8 = 90;
            } else {
                i8 = 0;
            }
            int[] iArr2 = {i18, ((i27 ^ i8) ^ i24) & 255};
            int i29 = i24 >> 1;
            if (i28 != 0) {
                i9 = 180;
            } else {
                i9 = 0;
            }
            int i30 = i24 ^ (i29 ^ i9);
            if (i26 == 0) {
                i15 = 0;
            }
            int i31 = i25 ^ i15;
            if (i28 != 0) {
                i10 = 90;
            } else {
                i10 = 0;
            }
            int[] iArr3 = {i22, ((i10 ^ i31) ^ i30) & 255};
            int[][] iArr4 = f319b;
            int[] iArr5 = iArr4[0];
            int i32 = iArr[1] | (iArr2[1] << 8);
            int i33 = iArr3[1];
            iArr5[i11] = i32 | (i33 << 16) | (i33 << 24);
            int[] iArr6 = iArr4[1];
            int i34 = iArr3[0];
            iArr6[i11] = i34 | (i34 << 8) | (iArr2[0] << 16) | (iArr[0] << 24);
            int[] iArr7 = iArr4[2];
            int i35 = iArr2[1];
            int i36 = iArr3[1];
            iArr7[i11] = i35 | (i36 << 8) | (iArr[1] << 16) | (i36 << 24);
            int[] iArr8 = iArr4[3];
            int i37 = iArr2[0];
            iArr8[i11] = (iArr3[0] << 16) | (iArr[0] << 8) | i37 | (i37 << 24);
        }
    }

//    public static final int a(int i2, int i3, int[] input)
    public static int cnt=0;
    public static final int a(int i2, int i3, int[] iArr) {

        System.out.printf("0x%08x --- 0x%08x\n",iArr[0],iArr[1]);
        int i4;
        int i5;
        int i6 = i3 & 255;
        int g2 = g(i3);
        int h2 = h(i3);
        int i7 = i(i3);
        int i8 = iArr[0];
        int i9 = iArr[1];
        int i10 = iArr[2];
        int i11 = iArr[3];
        int i12 = i2 & 3;
        int[][] iArr2 = f319b;
        byte[][] bArr = f318a;
        cnt += 1;
        if (cnt==40){
            System.out.printf("here\n");
        }
        System.out.printf("cnt: %d === i3: 0x%x\n",cnt,i3);

        if (i12 != 0) {
            if (i12 != 1) {
                if (i12 != 2) {
                    if (i12 != 3) {
                        return 0;
                    }
                }
                int[] iArr3 = iArr2[0];
                byte[] bArr2 = bArr[0];
                i5 = (iArr3[(bArr2[(bArr2[i6] & 255) ^ (i9 & 255)] & 255) ^ (i8 & 255)] ^ iArr2[1][(bArr2[(bArr[1][g2] & 255) ^ g(i9)] & 255) ^ g(i8)]) ^ iArr2[2][(bArr[1][(bArr[0][h2] & 255) ^ h(i9)] & 255) ^ h(i8)];
                int[] iArr4 = iArr2[3];
                byte[] bArr3 = bArr[1];
                i4 = iArr4[(bArr3[(bArr3[i7] & 255) ^ i(i9)] & 255) ^ i(i8)];
                return i5 ^ i4;
            }
            int[] iArr5 = iArr2[0];
            byte[] bArr4 = bArr[0];
            i5 = (iArr5[(bArr4[i6] & 255) ^ (i8 & 255)] ^ iArr2[1][(bArr4[g2] & 255) ^ g(i8)]) ^ iArr2[2][(bArr[1][h2] & 255) ^ h(i8)];
            i4 = iArr2[3][(bArr[1][i7] & 255) ^ i(i8)];
            return i5 ^ i4;
        }
        i6 = (i11 & 255) ^ (bArr[1][i6] & 255);
        g2 = g(i11) ^ (bArr[0][g2] & 255);
        h2 = h(i11) ^ (bArr[0][h2] & 255);
        i7 = i(i11) ^ (bArr[1][i7] & 255);
        byte[] bArr5 = bArr[1];
        i6 = (i10 & 255) ^ (bArr5[i6] & 255);
        g2 = (bArr5[g2] & 255) ^ g(i10);
        h2 = (bArr[0][h2] & 255) ^ h(i10);
        i7 = i(i10) ^ (bArr[0][i7] & 255);
        int[] iArr32 = iArr2[0];
        byte[] bArr22 = bArr[0];
        i5 = (iArr32[(bArr22[(bArr22[i6] & 255) ^ (i9 & 255)] & 255) ^ (i8 & 255)] ^ iArr2[1][(bArr22[(bArr[1][g2] & 255) ^ g(i9)] & 255) ^ g(i8)]) ^ iArr2[2][(bArr[1][(bArr[0][h2] & 255) ^ h(i9)] & 255) ^ h(i8)];
        int[] iArr42 = iArr2[3];
        byte[] bArr32 = bArr[1];
        i4 = iArr42[(bArr32[(bArr32[i7] & 255) ^ i(i9)] & 255) ^ i(i8)];
        return i5 ^ i4;
    }

    public static int cnt2 = 0;
    public static final int b(int i2, int i3, int[] iArr) {
        cnt2 += 1;
//        System.out.printf("%d\n",cnt2);
        if(cnt2 == 32){
            System.out.printf("hereeeee\n");
            System.out.printf("dump iArr20...\n");
            for(int i=0;i<1024;i++){
                System.out.printf("0x%x,",iArr[i]);
            }
            System.out.printf("\n");

        }

        return iArr[(e(i2, i3 + 3) * 2) + 513] ^ ((iArr[e(i2, i3) * 2] ^ iArr[(e(i2, i3 + 1) * 2) + 1]) ^ iArr[(e(i2, i3 + 2) * 2) + 512]);
    }

    public static final int c(int i2, int i3) {
        for (int i4 = 0; i4 < 4; i4++) {
            i3 = d(i3);
        }
        int i5 = i2 ^ i3;
        for (int i6 = 0; i6 < 4; i6++) {
            i5 = d(i5);
        }
        return i5;
    }

    public static final int d(int i2) {
        int i3;
        int i4 = i2 >>> 24;
        int i5 = i4 & 255;
        int i6 = i5 << 1;
        int i7 = 0;
        if ((i4 & 128) != 0) {
            i3 = 333;
        } else {
            i3 = 0;
        }
        int i8 = (i6 ^ i3) & 255;
        int i9 = i5 >>> 1;
        if ((i4 & 1) != 0) {
            i7 = 166;
        }
        int i10 = (i9 ^ i7) ^ i8;
        return ((((i2 << 8) ^ (i10 << 24)) ^ (i8 << 16)) ^ (i10 << 8)) ^ i5;
    }

    public static final int e(int i2, int i3) {
        int i4 = i3 % 4;
        if (i4 == 0) {
            return i2 & 255;
        }
        if (i4 == 1) {
            return g(i2);
        }
        if (i4 == 2) {
            return h(i2);
        }
        if (i4 != 3) {
            return 0;
        }
        return i(i2);
    }

    public static final int f(int i2) {
        return i2 & 255;
    }

    public static final int g(int i2) {
        return (i2 >>> 8) & 255;
    }

    public static final int h(int i2) {
        return (i2 >>> 16) & 255;
    }

    public static final int i(int i2) {
        return (i2 >>> 24) & 255;
    }

    public static boolean successWithString(String input) {
        byte[] bArr;
        int i2;
        int[] iArr;
        int i3;
        int i4;
        int i5;
        byte[] input_part4;
        int i6;
        int i7;
        int i8;
        byte[] bArr2;
        int[] iArr2;
        int i9;
        int[] iArr3;
        int[] iArr4;
        int[] iArr5;
        byte[] bArr3;
        byte[] input__part4;
        byte[] bArr4;
        int i10;
        int[] iArr6;
        int[] iArr7;
        int[] iArr8;
        int i11;
        int i12;
        int i13;
        boolean z2;
        int i14;
        int i15;
        int[] iArr9;
        int i16;
        int[] iArr10;
        int i17;
        int i18;
        int[] iArr11;
        int i19;
        byte[] bArr5;
        int i20;
        char c2;
        int[] iArr12;
        int i21;
        char c3;
        int i22;
        int i23;
        int i24;
        byte[][] bArr6;
        int i25;
        int[] iArr13;
        int i26;
        int i27;
        int i28;
        int i29;
        int i30;
        int[] iArr14;
        byte[] input_partt4;
        int i31;
        int[] iArr15;
        int i32;
        byte[] bArr7;
        int i33;
        int i34;
        int[] iArr16;
        int[] iArr17;
        char c4;
        int[] iArr18;
        long j2;
        int[] iArr19 = null;
        int[] iArr20 = null;
        int[] iArr21 = null;
        byte[] bArr8 = null;
        int[] iArr22 = null;
        byte[] bArr9 = null;
        byte[] bArr10 = null;
        byte[] bArr11 = null;
        byte[] input_part3 = null;
        int[] iArr23 = null;
        long j3 = 4731072527315935075L;
        int i35 = 0;
        int i36 = 0;
        int i37 = 0;
        int i38 = 0;
        int i39 = 0;
        int i40 = 0;
        int i41 = 0;
        int i42 = 0;
        int i43 = 0;
        int i44 = 0;
        int i45 = 0;
        int i46 = 0;
        int i47 = 0;
        int i48 = 0;
        int i49 = 0;
        int i50 = 0;
        int i51 = 0;
        int i52 = 0;
        int i53 = 0;
        int i54 = 0;
        int i55 = 0;
        int i56 = 0;
        byte b2 = 0;
        int i57 = 0;
        int i58 = 0;
        int i59 = 0;
        int i60 = 0;
        int i61 = 0;
        int i62 = 0;
        int i63 = 0;
        byte[] final_cip = null;
        while (j3 != 0) {
            if (j3 == 1344274946653272861L) {
                bArr = bArr10;
                j3 = 1791603831984298670L;
                input_part3 = Arrays.copyOfRange(input.getBytes(), 32, 48);
            } else {
                bArr = bArr10;
            }
            if (j3 == 2624883423877033675L) {
                i41 = a(i38, 0x1010101 + i39, iArr19);
                j3 = 6791763692716894148L;
            }
            long j4 = j3;
            if (j3 == 1235382496194677124L) {
                j4 = i35 < 16 ? 1265064075323142964L : 1258015405620320613L;
            }
            if (j4 == 9217510483877698234L) {
                final_cip[14] = 26;
                j4 = 1206168581136677569L;
            }
            if (j4 == 2018356045126754964L) {
                final_cip[3] = -67;
                j4 = 3996485562340421897L;
            }
            if (j4 == 7439146434853463828L) {
                final_cip[10] = -34;
                j4 = 4125034680230680057L;
            }
            if (j4 == 7166648683214755429L) {
                j4 = 3232348833396235159L;
                i35 = 0;
            }
            if (j4 == 6456065269618269061L) {
                final_cip[12] = 101;
                j4 = 9128083677415659622L;
            }
            if (j4 == 2940914719786750343L) {
                final_cip = new byte[16];
                j4 = 1298355068347161880L;
            }
            if (j4 == 6556735160628504425L) {
                j4 = 8518748339665995304L;
                i40 = 0;
            }
            if (j4 == 8545670441877195089L) {
                int i64 = i40 + 3;
                i2 = i39;
                int i65 = ((input_part3[i40 + 1] & 255) << 8) | (input_part3[i40] & 255) | ((input_part3[i40 + 2] & 255) << 16);
                i40 += 4;
                i45 = i65 | ((input_part3[i64] & 255) << 24);
                j4 = 2685803154186139471L;
            } else {
                i2 = i39;
            }
            if (j4 == 2774930016233698765L) {
                j4 = 1917218271936056345L;
            }
            if (j4 == 3771045416936191600L) {
                final_cip[0] = -87;
                j4 = 3561976962102531662L;
            }
            if (j4 == 4721983077526601781L) {
                j4 = i35 < 16 ? 5449112193696891016L : 7828254552561955106L;
            }
            if (j4 == 3066500687241056891L) {
                j4 = 4002981753480083424L;
                i44 = 0;
            }
            if (j4 == 1949128521960768022L) {
                final_cip = new byte[16];
                j4 = 4582825124030923023L;
            }
            if (j4 == 3963581958469081827L) {
                final_cip[4] = 56;
                j4 = 7755442445806274292L;
            }
            if (j4 == 6235468836233699857L) {
                int i66 = i40 + 3;
                int i67 = ((input_part3[i40 + 1] & 255) << 8) | (input_part3[i40] & 255) | ((input_part3[i40 + 2] & 255) << 16);
                i40 += 4;
                i42 = i67 | ((input_part3[i66] & 255) << 24);
                System.out.printf("i42 = i67 | ((input_part3[i66] & 255) << 24);\n");
                j4 = 1960953289592796381L;
            }
            if (j4 == 2093361175579585723L) {
                j4 = 7491020394721445997L;
            }
            if (j4 == 4503359345410430401L) {
                i41 = (i41 << 8) | (i41 >>> 24);
                j4 = 6400104566594303800L;
            }
            if (j4 == 4729681422063648060L) {
                int i68 = i40 + 3;
                int i69 = ((input_part3[i40 + 1] & 255) << 8) | (input_part3[i40] & 255) | ((input_part3[i40 + 2] & 255) << 16);
                i40 += 4;
                i42 = i69 | ((input_part3[i68] & 255) << 24);
                System.out.printf("i42 = 0x%x\n",i42);
                j4 = 2619183670644040407L;
            }
            if (j4 == 1931444552567951803L) {
                final_cip[12] = 26;
                j4 = 4406359568694291741L;
            }
            if (j4 == 4550460380187288280L) {
                final_cip[6] = 86;
                j4 = 7259606742125695098L;
            }
            if (j4 == 1557189065681442799L) {
                int i70 = i40 + 3;
                int i71 = ((input_part3[i40 + 1] & 255) << 8) | (input_part3[i40] & 255) | ((input_part3[i40 + 2] & 255) << 16);
                i40 += 4;
                i59 = i71 | ((input_part3[i70] & 255) << 24);

                System.out.printf("i59 = i71 | ((input_part3[i70] & 255) << 24);\n");
                j4 = 4529813231791050890L;
            }
            if (j4 == 5724730743879706941L) {
                final_cip[14] = 26;
                j4 = 1745476098101140696L;
            }
            if (j4 == 3664515501258973547L) {
                int rev = i42;
                i42 = (i42 << 1) | (i42 >>> 31);
                System.out.printf("0x%x = (0x%x << 1) | (0x%x >>> 31);2\n",i42,rev,rev);
                j4 = 3798078227232544657L;
            }
            int i72 = i42;
            if (j4 == 3269202292537843991L) {
                final_cip[5] = -69;
                j4 = 7100981003187767618L;
            }
            if (j4 == 3027876831777635167L) {
                j4 = 3638715073757882335L;
            }
            if (j4 == 2381872149833716276L) {
                i48 = b(i72, 3, iArr20);
                System.out.printf("0x%x = b(0x%x, 3, iArr20);\n",i48,i72);
                j4 = 4687532178299999822L;
            }
            if (j4 == 3454830691820322386L) {
                i43 += 2;
                j4 = 5747130514941805881L;
            }
            int i73 = i43;
            if (j4 == 1693417113814409015L) {
                final_cip = new byte[16];
                j4 = 3293997730919338008L;
            }
            if (j4 == 7434671091395572559L) {
                int i74 = i44 + 3;
                iArr = iArr19;
                int i75 = ((bArr8[i44 + 2] & 255) << 16) | ((bArr8[i44 + 1] & 255) << 8) | (bArr8[i44] & 255);
                i44 += 4;
                iArr21[i35] = i75 | ((bArr8[i74] & 255) << 24);
                j4 = 2244588298960877871L;
            } else {
                iArr = iArr19;
            }
            int i76 = i44;
            if (j4 == 3749337558494560640L) {
                i35++;
                j4 = 4721983077526601781L;
            }
            if (j4 == 8576495708234852385L) {
                j4 = 2643541622786400324L;
                i35 = 0;
            }
            if (j4 == 7938615863272599159L) {
                i57 = i38 - 1;
                j4 = 6150867844939017811L;
            }
            if (j4 == 8885026426954417173L) {
                i51 = iArr22[1];
                j4 = 3776736958491573516L;
            }
            if (j4 == 1516524683227842992L) {
                bArr8[i35] = (byte) i35;
                j4 = 1704106780884375804L;
            }
            if (j4 == 1923774560246569152L) {
                int rev = i45;
                i45 = (i45 << 1) | (i45 >>> 31);
                System.out.printf("0x%x = (0x%x << 1) | (0x%x >>> 31); |||| \n",i45 ,rev,rev);

                j4 = 8865616538709174935L;
            }
            if (j4 == 1976739577957879234L) {
                j4 = 6846653198359909058L;
                i35 = 0;
            }
            if (j4 == 7187511718077947057L) {
                j4 = i35 < 16 ? 2995178518753654243L : 7237318116944859580L;
            }
            if (j4 == 5750672483363983940L) {
                j4 = 1499582615124426815L;
                iArr23 = new int[i36];
            }
            if (j4 == 1448425356520503711L) {
                i38 = i37 / 8;
                j4 = 6813145705137374739L;
            }
            if (j4 == 1959318858079064627L) {
                final_cip[6] = 22;
                j4 = 6847264319992049185L;
            }
            if (j4 == 8138934693726466556L) {
                final_cip = new byte[16];
                j4 = 6316099258019509927L;
            }
            if (j4 == 2670312744982717376L) {
                i46 = (i46 >>> 1) | (i46 << 31);
                j4 = 6742529599724506157L;
            }
            if (j4 == 2207722750320310621L) {
                j4 = 2647830346389990788L;
                i35 = 0;
            }
            if (j4 == 8710549355152942959L) {
                final_cip[3] = -67;
                j4 = 6840550518655151485L;
            }
            if (j4 == 6062811699616037457L) {
                j4 = (i35 >= 4 || i76 >= i37) ? 5634423947985751522L : 7105550752828252141L;
            }
            if (j4 == 8450049976084005921L) {
                int rev = i45;
                i45 ^= iArr23[1];
                System.out.printf("0x%x ^= iArr23[1];(0x%x) ==> 0x%x  |------1\n",rev,iArr23[1],i45);
                j4 = 8139682663513707735L;
            }
            if (j4 == 7965698667281418869L) {
                i48 = b(i72, 3, iArr20);
                System.out.printf("0x%x = b(0x%x, 3, iArr20);\n",i48,i72);
                j4 = 2915651820630837601L;
            }
            if (j4 == 8712522692857598416L) {
                j4 = i35 < 256 ? 6258186781956124801L : 5432899031047016039L;
            }
            if (j4 == 1406293758239810889L) {
                j4 = 6960008337303110994L;
            }
            if (j4 == 4390863030597796170L) {
                int i77 = iArr22[3];
                j4 = 6121095475008891355L;
            }
            if (j4 == 1330376841649282870L) {
                i51 = iArr22[1];
                j4 = 6248631473184684104L;
            }
            if (j4 == 5329812806323573738L) {
                j4 = 4141065487333702108L;
            }
            if (j4 == 4878474884038157657L) {
                return false;
            }
            if (j4 == 3132205735905595925L) {
                i45 ^= ((i48 * 2) + i47) + iArr23[i49];

                i49++;
                j4 = 5507786416351883958L;
            }
            if (j4 == 2540221427897138037L) {
                final_cip[5] = 34;
                j4 = 9187919677985842561L;
            }
            if (j4 == 5935421846599899027L) {
                final_cip[12] = 26;
                j4 = 3629825694819376798L;
            }
            if (j4 == 8693574105114856330L) {
                i45 ^= iArr23[1];
                j4 = 1607272796917644293L;
            }
            int i78 = i45;
            if (j4 == 6858362739340846367L) {
                final_cip[7] = -102;
                j4 = 2328180056253180144L;
            }
            if (j4 == 7837308487840170804L) {
                i48 = b(i78, 3, iArr20);
                System.out.printf("i48 = b(i78, 3, iArr20);\n");
                j4 = 5106069083976822048L;
            }
            if (j4 == 4433736888020758873L) {
                i3 = 16;
                j4 = i73 < 16 ? 8658034048742640241L : 5223925646383245751L;
            } else {
                i3 = 16;
            }
            if (j4 == 1210447254521047538L) {
                j4 = i35 < i3 ? 3027876831777635167L : 8861860503648848567L;
            }
            if (j4 == 6742543001969080469L) {
                i4 = i76;
                i5 = i35;
                input_part4 = Arrays.copyOfRange(input.getBytes(), 48, 64);
                j4 = 3309839572505684939L;
            } else {
                i4 = i76;
                i5 = i35;
                input_part4 = bArr;
            }
            if (j4 == 9205148841603072616L) {
                j4 = 7155080874485808131L;
            }
            if (j4 == 7442085785176969176L) {
                j4 = 7857940782209243597L;
                i4 = 0;
            }
            if (j4 == 1565736080187942985L) {
                j4 = 5021944871100814321L;
                i5 = 0;
            }
            if (j4 == 1221161945297932730L) {
                j4 = bArr9[i5] != final_cip[i5] ? 3809429621901428327L : 8606637167793465408L;
                System.out.printf("cmp en_inp, final_cip\n");
                System.out.printf("dump en_inp:\n");
                for(int i=0;i<16;i++){
                    System.out.printf("0x%x,",bArr9[i]);
                }
                System.out.printf("\n");
                System.out.printf("dump final cip:\n");
                for(int i=0;i<16;i++){
                    System.out.printf("0x%x,",final_cip[i]);
                }
                System.out.printf("\n");

                System.out.printf("dump iArr23\n");
                for(int i=0;i<40;i++){
                    System.out.printf("0x%x,",iArr23[i]);
                }
                System.out.printf("\n");
            }
            if (j4 == 6156216816975470944L) {
                j4 = 5158554594830700929L;
                i6 = 0;
            } else {
                i6 = i5;
            }
            if (j4 == 3889131894744472679L) {
                int i79 = i40 + 3;
                i7 = i36;
                int i80 = ((input_part3[i40 + 2] & 255) << 16) | ((input_part3[i40 + 1] & 255) << 8) | (input_part3[i40] & 255);
                i40 += 4;
                i78 = ((input_part3[i79] & 255) << 24) | i80;
                j4 = 7445081137528894062L;
            } else {
                i7 = i36;
            }
            if (j4 == 5081598064245946139L) {
                final_cip[4] = 56;
                j4 = 9025636051433876555L;
            }
            if (j4 == 4582825124030923023L) {
                final_cip[0] = -87;
                j4 = 2168699168102359386L;
            }
            byte[][] bArr12 = f318a;
            int[][] iArr24 = f319b;
            if (j4 == 4844213572013444662L) {
                i8 = i37;
                iArr20[(i6 * 2) + 1] = iArr24[1][(bArr12[0][(bArr12[1][i50] & 255) ^ g(i51)] & 255) ^ g(i52)];
                j4 = 1189820553702033682L;
            } else {
                i8 = i37;
            }
            if (j4 == 2479939902309983355L) {
                j4 = i6 < 256 ? 4414711808604472165L : 3816401808965634220L;
            }
            if (j4 == 6539778732394021364L) {
                i6++;
                j4 = 3288829365377197701L;
            }
            if (j4 == 4406359568694291741L) {
                final_cip[13] = 34;
                j4 = 3717774128157910605L;
            }
            if (j4 == 8467294207452721452L) {
                j4 = i6 < 16 ? 5577077923868017099L : 5035786145376624859L;
            }
            if (j4 == 1446293772852257370L) {
                j4 = 4019322378267872035L;
            }
            if (j4 == 5780988963199426860L) {
                j4 = 7029503371282280059L;
            }
            if (j4 == 3853058995086597827L) {
                j4 = 2827565969431776290L;
                i6 = 0;
            }
            if (j4 == 7650200577204707019L) {
                bArr9[i6] = (byte) (input_part4[i6] ^ bArr11[i53]);
                j4 = 8049116761699692167L;
            }
            if (j4 == 7828254552561955106L) {
                return true;
            }
            if (j4 == 1542568896301610920L) {
                return false;
            }
            if (j4 == 5674382685779100318L) {
                return true;
            }
            if (j4 == 3799650815120663631L) {
                int rev = i46;
                i46 = (i46 >>> 1) | (i46 << 31);
                System.out.printf("0x%x = (0x%x >>> 1) | (0x%x << 31);\n",i46,rev,rev);
                j4 = 3664515501258973547L;
            }
            if (j4 == 5785321344550860296L) {
                j4 = 2380097332528943626L;
                i6 = 0;
                i2 = 0;
            }
            if (j4 == 3635089787362081630L) {
                i78 = (i78 >>> 31) | (i78 << 1);

                j4 = 7606829752949254081L;
            }
            if (j4 == 6870659348541134994L) {
                int rev = i72;
                i72 ^= iArr23[5];
                System.out.printf("0x%x ^= iArr23[5](0x%x); ==> 0x%x\n",rev,iArr23[5],i72);
                j4 = 7957423564036594724L;
            }
            if (j4 == 3651248876173446844L) {
                j4 = i6 < bArr8.length ? 3261491808297697902L : 6154526864824538477L;
            }
            if (j4 == 8429256749154793372L) {
                i6++;
                j4 = 7559115683265846437L;
            }
            if (j4 == 6684206521967284343L) {
                final_cip[7] = -102;
                j4 = 6629490099819822416L;
            }
            if (j4 == 4489495459518801626L) {
                i6++;
                j4 = 6065652472169461293L;
            }
            if (j4 == 4913171088445306692L) {
                j4 = 7102882857441765884L;
                i55 = ((bArr11[i54] & 255) + i55) & 255;
            }
            if (j4 == 2971360862616034517L) {
                i46 ^= iArr23[2];
                j4 = 7679858687335731309L;
            }
            if (j4 == 5632710845036330174L) {
                final_cip[15] = 115;
                j4 = 2999075064852109317L;
            }
            if (j4 == 8712993034539386972L) {
                i41 = (i41 << 8) | (i41 >>> 24);
                j4 = 2385330523779930222L;
            }
            if (j4 == 4069681874230164976L) {
                bArr11[i56] = b2;
                j4 = 8995230908817835821L;
            }
            if (j4 == 1383509948187139942L) {
                iArr22[i57] = c(iArr21[i6], iArr[i6]);
                j4 = 2165639815662633400L;
            }
            if (j4 == 3641357321518337437L) {
                j4 = i6 < 16 ? 4367072516203707509L : 9155753144681893636L;
            }
            if (j4 == 7338973850236663134L) {
                i46 ^= iArr23[4];
                j4 = 5687179084370450098L;
            }
            if (j4 == 8147838551163462352L) {
                j4 = i6 < bArr8.length ? 1515150366864584833L : 7268096038668322638L;
            }
            if (j4 == 2267521650283250943L) {
                j4 = 1543835537816689303L;
            }
            if (j4 == 6066511524528422362L) {
                final_cip[13] = 34;
                j4 = 7916273223981762345L;
            }
            if (j4 == 7627928995385457046L) {
                bArr11[i56] = b2;
                j4 = 8642648116757711055L;
            }
            if (j4 == 8858813628494679889L) {
                iArr20 = new int[1024];
                j4 = 5002450969468452359L;
            }
            if (j4 == 7830774370852576407L) {
                int i81 = i4 + 3;
                bArr2 = input_part4;
                int i82 = ((bArr8[i4 + 2] & 255) << 16) | ((bArr8[i4 + 1] & 255) << 8) | (bArr8[i4] & 255);
                i4 += 4;
                iArr[i6] = i82 | ((bArr8[i81] & 255) << 24);
                j4 = 4253974366483718512L;
            } else {
                bArr2 = input_part4;
            }
            if (j4 == 2006261316763383880L) {
                i6++;
                j4 = 4268434749325211515L;
            }
            if (j4 == 4981578060776525784L) {
                int i83 = iArr22[2];
                j4 = 2354860184047444979L;
            }
            if (j4 == 5665212773913217619L) {
                bArr11[i6] = (byte) i6;
                j4 = 7936308356012564598L;
            }
            if (j4 == 1925267828353292404L) {
                i52 = iArr22[0];
                j4 = 3141556051555878191L;
            }
            if (j4 == 7477109834176307884L) {
                final_cip[1] = -39;
                j4 = 6536862633203215031L;
            }
            if (j4 == 5733075732827349729L) {
                final_cip[11] = -88;
                j4 = 6456065269618269061L;
            }
            if (j4 == 2979491677337701483L) {
                final_cip[0] = -87;
                j4 = 1186625407244930214L;
            }
            if (j4 == 8806141432899778163L) {
                j4 = 3658748673678459194L;
                iArr2 = new int[4];
            } else {
                iArr2 = iArr;
            }
            if (j4 == 5158554594830700929L) {
                j4 = i6 < 256 ? 5680233300170691155L : 5985635937414591521L;
            }
            if (j4 == 3857582825715051590L) {
                final_cip[9] = -106;
                j4 = 5712797840902770362L;
            }
            if (j4 == 3239610692754448539L) {
                i57--;
                j4 = 6062811699616037457L;
            }
            if (j4 == 2228412114913783121L) {
                i9 = 40;
                j4 = 7048362897848211972L;
            } else {
                i9 = i7;
            }
            if (j4 == 2464113797535833870L) {
                j4 = 1874544657470527590L;
            }
            if (j4 == 8899342501041115189L) {
                bArr9 = new byte[16];
                j4 = 6856100014110617486L;
            }
            if (j4 == 4502191866101741942L) {
                final_cip[3] = -45;
                j4 = 6003035240079781244L;
            }
            if (j4 == 6239062422289160234L) {
                i46 ^= (i47 + i48) + iArr23[i49];
                i49++;
                j4 = 2558574102511333837L;
            }
            if (j4 == 3944034548958798065L) {
                iArr3 = iArr21;
                j4 = 1715651793431489116L;
                i53 = ((bArr11[i54] & 255) + (bArr11[i55] & 255)) & 255;
            } else {
                iArr3 = iArr21;
            }
            if (j4 == 8601808016329414299L) {
                return false;
            }
            if (j4 == 1576871852716234009L) {
                i46 ^= (i47 + i48) + iArr23[i49];
                j4 = 7122579587187539743L;
                i49++;
            }
            if (j4 == 7134777286922640409L) {
                i6++;
                j4 = 7742223888133137430L;
            }
            if (j4 == 3408812674582655891L) {
                j4 = 4546317725273286940L;
                iArr4 = new int[4];
            } else {
                iArr4 = iArr3;
            }
            if (j4 == 6291717555241868931L) {
                iArr5 = iArr22;
                bArr3 = bArr9;
                input__part4 = Arrays.copyOfRange(input.getBytes(), 48, 64);
                j4 = 1477878882031581069L;
            } else {
                iArr5 = iArr22;
                bArr3 = bArr9;
                input__part4 = bArr2;
            }
            if (j4 == 5830459252270867373L) {
                j4 = 1307281791046846137L;
                i40 = 0;
            }
            if (j4 == 2272798444665954523L) {
                j4 = i6 < 16 ? 7922265040538291434L : 1949128521960768022L;
            }
            if (j4 == 5030664747537294245L) {
                final_cip[11] = -113;
                j4 = 3645268212325467906L;
            }
            if (j4 == 2243047018611698496L) {
                bArr4 = input__part4;
                iArr20[(i6 * 2) + 512] = iArr24[2][(bArr12[1][(bArr12[0][i58] & 255) ^ h(i51)] & 255) ^ h(i52)];
                j4 = 2012634943331272739L;
            } else {
                bArr4 = input__part4;
            }
            if (j4 == 1230993959279055670L) {
                j4 = i73 < 16 ? 1671474751395228828L : 6230299255924766997L;
            }
            if (j4 == 8614510693619874143L) {
                int rev = i59;
                i59 ^= (i47 + i48) + iArr23[i49];
                System.out.printf("0x%x ^= (0x%x + 0x%x) + iArr23[0x%x](0x%x); ==> 0x%x ===1\n",rev,i47,i48,i49,iArr23[i49],i59);
                j4 = 2101580866933054237L;
                i49++;
            }
            int i84 = i59;
            if (j4 == 2642256598463014223L) {
                final_cip[12] = 26;
                j4 = 5546371364110668020L;
            }
            if (j4 == 8571264530881593712L) {
                final_cip[13] = -114;
                j4 = 2136818370012310171L;
            }
            if (j4 == 1776589645593272517L) {
                final_cip[8] = -20;
                j4 = 1536915158700845943L;
            }
            if (j4 == 3216270323582324779L) {
                final_cip[6] = 86;
                j4 = 8354771225526520440L;
            }
            if (j4 == 5128669412318362325L) {
                j4 = 8858626231332964772L;
            }
            if (j4 == 6203948773157381693L) {
                int i85 = i4 + 3;
                i10 = i73;
                int i86 = ((bArr8[i4 + 1] & 255) << 8) | (bArr8[i4] & 255) | ((bArr8[i4 + 2] & 255) << 16);
                i4 += 4;
                iArr2[i6] = i86 | ((bArr8[i85] & 255) << 24);
                j4 = 6140926885576835727L;
            } else {
                i10 = i73;
            }
            if (j4 == 2143903162775120184L) {
                i6++;
                j4 = 6965451223574289359L;
            }
            if (j4 == 3524251343514742352L) {
                i72 = (i72 << 1) | (i72 >>> 31);
                j4 = 3232129143333112632L;
            }
            if (j4 == 2765340047003677131L) {
                i47 = b(i84, 0, iArr20);
                System.out.printf("0x%x = b(0x%x, 0, iArr20);\n",i47,i84);
                j4 = 8320362214494129059L;
            }
            if (j4 == 8113068425133703218L) {
                i2 += 33686018;
                j4 = 1615637139671222434L;
            }
            if (j4 == 1922411276633870490L) {
                iArr6 = new int[4];
                j4 = 2983171159703272091L;
            } else {
                iArr6 = iArr5;
            }
            if (j4 == 4249658298115383554L) {
                iArr7 = iArr6;
                iArr20[(i6 * 2) + 512] = iArr24[2][(bArr12[1][(bArr12[0][i58] & 255) ^ h(i51)] & 255) ^ h(i52)];
                j4 = 7796303291830281045L;
            } else {
                iArr7 = iArr6;
            }
            if (j4 == 8256907239556468412L) {
                final_cip[9] = -77;
                j4 = 3498352284358828315L;
            }
            if (j4 == 6505983967259753973L) {
                bArr11[i55] = b2;
                j4 = 5439844282370393304L;
            }
            if (j4 == 9171905176519800148L) {
                j4 = input.length() < 64 ? 4195029094423679636L : 3757062276099973803L;
            }
            if (j4 == 8045731683183909714L) {
                j4 = 7885522936240168470L;
                i55 = 0;
            }
            if (j4 == 9058600938452428912L) {
                int rev = i84;
                i84 = (i84 << 31) | (i84 >>> 1);
                System.out.printf("i84 = (i84 << 31) | (i84 >>> 1);\n",i84,rev,rev);
                j4 = 5744181537574184685L;
            }
            if (j4 == 9069075618791280805L) {
                final_cip[5] = 34;
                j4 = 1843429843798473511L;
            }
            if (j4 == 3689168917021238793L) {
                iArr20[(i6 * 2) + 512] = iArr24[2][(bArr12[1][(bArr12[0][i58] & 255) ^ h(i51)] & 255) ^ h(i52)];
                j4 = 3564308124560413862L;
            }
            if (j4 == 5301379100569539273L) {
                j4 = 6399356390896869309L;
                i55 = 0;
            }
            if (j4 == 3918062052349580671L) {
                j4 = 2466964143165741837L;
                i56 = 0;
            }
            if (j4 == 4967406293272637771L) {
                int rev1 = i46;
                int rev2 = iArr23[4];
                i46 ^= iArr23[4];
//                System.out.printf("i46: 0x%x\n",i46);
                System.out.printf("0x%x ^= iArr23[4](0x%x) ==> 0x%x // 0x%x\n",rev1,iArr23[4],i46,rev2);
                j4 = 6870659348541134994L;
            }
            int i87 = i46;
            if (j4 == 4655572712013400706L) {
                j4 = 4597609935169428732L;
            }
            if (j4 == 3166750012504996540L) {
                int rev = i78;
                i78 ^= iArr23[7];
                System.out.printf("0x%x ^= iArr23[7](0x%x); ==> 0x%x\n",rev,iArr23[7],i78);
                j4 = 6017806319896199361L;
            }
            if (j4 == 3759730075617569039L) {
                j4 = 5454795868479267733L;
                iArr8 = new int[4];
            } else {
                iArr8 = iArr7;
            }
            if (j4 == 6069099502938214271L) {
                j4 = 7738313729691083676L;
                i6 = 0;
                i2 = 0;
            }
            if (j4 == 8733995111375603342L) {
                return false;
            }
            if (j4 == 8474438945361269523L) {
                i48 = b(i78, 3, iArr20);
                System.out.printf("i48 = b(i78, 3, iArr20);1\n");
                j4 = 6628989894226553698L;
            }
            if (j4 == 6882462805502957432L) {
                final_cip[1] = -39;
                j4 = 6379026488496223403L;
            }
            if (j4 == 8451739037481316613L) {
                i6++;
                j4 = 2460950143244437765L;
            }
            if (j4 == 1506771280779625252L) {
                j4 = i6 < i9 / 2 ? 3691596519119015595L : 7571741907448362931L;
            }
            if (j4 == 1700983361891594708L) {
                j4 = 6236359899965482168L;
                i6 = 0;
                i11 = 0;
            } else {
                i11 = i2;
            }
            if (j4 == 6791763692716894148L) {
                i41 = (i41 << 8) | (i41 >>> 24);
                j4 = 6641130065549689505L;
            }
            if (j4 == 5143211481986516166L) {
                i12 = i78;
                i13 = i11;
                iArr8[i57] = c(iArr4[i6], iArr2[i6]);
                j4 = 7891276519961275113L;
            } else {
                i12 = i78;
                i13 = i11;
            }
            if (j4 == 6742635737946316261L) {
                i60 += i41;
                j4 = 3392984551034355170L;
            }
            if (j4 == 7423862695494096725L) {
                final_cip[14] = -120;
                j4 = 5025360563600307522L;
            }
            if (j4 == 1298355068347161880L) {
                z2 = false;
                final_cip[0] = -97;
                j4 = 4192332344726786256L;
            } else {
                z2 = false;
            }
            if (j4 == 1872248020497693162L) {
                return z2;
            }
            if (j4 == 7113837318717080147L) {
                i14 = bArr8.length;
                j4 = 3460300782170937607L;
            } else {
                i14 = i8;
            }
            if (j4 == 8689932493166301704L) {
                i6++;
                j4 = 2559141778370937007L;
            }
            if (j4 == 2712255506212294232L) {
                b2 = bArr11[i6];
                j4 = 2637559127033415801L;
            }
            if (j4 == 7895119885594720875L) {
                final_cip[2] = Byte.MIN_VALUE;
                j4 = 4797263790202639931L;
            }
            if (j4 == 4723608467462860668L) {
                i47 = b(i87, 0, iArr20);
                j4 = 4494853218025089243L;
            }
            if (j4 == 2417995832646284659L) {
                j4 = 4227288482303383078L;
            }
            if (j4 == 4646339510735050251L) {
                i60 += i41;
                j4 = 1818157425461567934L;
            }
            if (j4 == 4369458919546020466L) {
                i15 = i14;
                iArr20[(i6 * 2) + 1] = iArr24[1][(bArr12[0][(bArr12[1][i50] & 255) ^ g(i51)] & 255) ^ g(i52)];
                j4 = 2243047018611698496L;
            } else {
                i15 = i14;
            }
            if (j4 == 3169104890646436008L) {
                j4 = i6 < 256 ? 3490326607433591043L : 6156216816975470944L;
            }
            if (j4 == 8328790806156357318L) {
                final_cip[12] = 101;
                j4 = 1687871497192565496L;
            }
            if (j4 == 4876709113984680946L) {
                bArr11[i6] = (byte) i6;
                j4 = 2757157254562105502L;
            }
            if (j4 == 4967752726726655102L) {
                i87 ^= iArr23[4];
                j4 = 1881227562238638542L;
            }
            if (j4 == 6629490099819822416L) {
                final_cip[8] = 49;
                j4 = 8256907239556468412L;
            }
            if (j4 == 4253974366483718512L) {
                iArr8[i57] = c(iArr4[i6], iArr2[i6]);
                j4 = 3348113858426447674L;
            }
            if (j4 == 5328979100626095900L) {
                j4 = 6583809806457227315L;
                i49 = 8;
            }
            if (j4 == 9139492487154675731L) {
                i48 = b(i72, 3, iArr20);
                System.out.printf("0x%x = b(0x%x, 3, iArr20);2\n",i48,i72);
                j4 = 3676839726527528229L;
            }
            if (j4 == 3232348833396235159L) {
                j4 = i6 < 256 ? 2774930016233698765L : 5830459252270867373L;
            }
            if (j4 == 8790842551072430122L) {
                j4 = 5809570720048932031L;
                i53 = ((bArr11[i54] & 255) + (bArr11[i55] & 255)) & 255;
            }
            if (j4 == 3195178661704652520L) {
                b2 = bArr11[i6];
                j4 = 6597678744472727573L;
            }
            if (j4 == 7225103017975505690L) {
                bArr11[i54] = bArr11[i55];
                j4 = 1341808814515513048L;
            }
            if (j4 == 2119690742806089054L) {
                j4 = 7697030109774584633L;
                i54 = (i54 + 1) & 255;
            }
            if (j4 == 1404052937569931777L) {
                j4 = 3553147099752082898L;
            }
            if (j4 == 9037117679071136801L) {
                int i88 = i40 + 3;
                iArr9 = iArr4;
                int i89 = ((input_part3[i40 + 2] & 255) << 16) | ((input_part3[i40 + 1] & 255) << 8) | (input_part3[i40] & 255);
                i40 += 4;
                i16 = ((input_part3[i88] & 255) << 24) | i89;
                System.out.printf("i16 = ((input_part3[i88] & 255) << 24) | i89;\n");
                j4 = 2683712846824466970L;
            } else {
                iArr9 = iArr4;
                i16 = i12;
            }
            if (j4 == 5249992174669506009L) {
                i47 = b(i84, 0, iArr20);

                System.out.printf("0x%x = b(0x%x, 0, iArr20);3\n",i47,i84);
                j4 = 1757468250215542428L;
            }
            if (j4 == 8113126029116536782L) {
                final_cip[5] = 34;
                j4 = 7215458347621232043L;
            }
            if (j4 == 5346212181092580745L) {
                i87 ^= iArr23[2];
                j4 = 3552493032350408280L;
            }
            if (j4 == 8226334980212259602L) {
                j4 = 5613764015967390693L;
            }
            if (j4 == 8867156692366178090L) {
                i6++;
                j4 = 3645427461145798578L;
            }
            if (j4 == 3603503257907849991L) {
                j4 = i6 < i9 / 2 ? 3563910683601917326L : 4132824574133018925L;
            }
            if (j4 == 3498352284358828315L) {
                final_cip[10] = -34;
                j4 = 5733075732827349729L;
            }
            if (j4 == 4915374719664229127L) {
                j4 = 7851583652737565876L;
            }
            if (j4 == 7370392102556209775L) {
                final_cip[14] = 26;
                j4 = 2968432505771842589L;
            }
            if (j4 == 7922265040538291434L) {
                j4 = 3256821261585855975L;
            }
            if (j4 == 6797381422692238257L) {
                i6++;
                j4 = 8484923127125558638L;
            }
            if (j4 == 8822634336683979982L) {
                final_cip[11] = -88;
                j4 = 2283802967392970500L;
            }
            if (j4 == 2799049228121383361L) {
                bArr8[i6] = (byte) i6;
                j4 = 4616176720591788319L;
            }
            if (j4 == 7303333862302918217L) {
                i6++;
                j4 = 2771646971449226877L;
            }
            if (j4 == 1157556858167321294L) {
                i60 += i41;
                j4 = 6761671813385298993L;
            }
            if (j4 == 8533640950399556720L) {
                j4 = 7816334058516889118L;
                i53 = ((bArr11[i54] & 255) + (bArr11[i55] & 255)) & 255;
            }
            if (j4 == 2240421224603994624L) {
                i16 ^= iArr23[7];
                System.out.printf("i16 ^= iArr23[7];\n");
                j4 = 4851634851769503870L;
            }
            if (j4 == 7430299891549265788L) {
                i47 = b(i87, 0, iArr20);
                j4 = 6998551651859783261L;
            }
            if (j4 == 3108054655050818576L) {
                j4 = 2849892291077788860L;
                i55 = ((bArr11[i54] & 255) + i55) & 255;
            }
            if (j4 == 5889839625189711156L) {
                i6++;
                j4 = 7592770177733069920L;
            }
            if (j4 == 8513954143616756791L) {
                iArr20 = new int[1024];
                j4 = 4199913159470633820L;
            }
            if (j4 == 6385765029630073007L) {
                final_cip[8] = -20;
                j4 = 2741486890114654248L;
            }
            if (j4 == 3805451690314712856L) {
                j4 = 5235021199741258527L;
                iArr10 = new int[4];
            } else {
                iArr10 = iArr9;
            }
            if (j4 == 5407125151982145331L) {
                iArr23[(i6 * 2) + 1] = (i60 << 9) | (i60 >>> 23);
                j4 = 2006261316763383880L;
            }
            byte[] bArr13 = bArr8;
            if (j4 == 6017806319896199361L) {
                j4 = 2940914719786750343L;
                bArr3 = new byte[]{(byte) i87, (byte) (i87 >>> 8), (byte) (i87 >>> 16), (byte) (i87 >>> 24), (byte) i72, (byte) (i72 >>> 8), (byte) (i72 >>> 16), (byte) (i72 >>> 24), (byte) i84, (byte) (i84 >>> 8), (byte) (i84 >>> 16), (byte) (i84 >>> 24), (byte) i16, (byte) (i16 >>> 8), (byte) (i16 >>> 16), (byte) (i16 >>> 24)};
            }
            if (j4 == 6353868812675907408L) {
                i17 = i13;
                i60 = a(i38, i17, iArr10);
                j4 = 7193859361834778956L;
            } else {
                i17 = i13;
            }
            if (j4 == 5680233300170691155L) {
                j4 = 7720877091476958305L;
            }
            if (j4 == 6246276100940706152L) {
                final_cip[4] = 119;
                j4 = 3269202292537843991L;
            }
            if (j4 == 7608592725865706243L) {
                i6++;
                j4 = 6621328629503001747L;
            }
            if (j4 == 6317465591117429424L) {
                int rev = i84;
                i84 ^= iArr23[6];
                System.out.printf("0x%x ^= iArr23[6];// 0x%x \n",rev,iArr23[6]);
                j4 = 8990284059334595524L;
            }
            if (j4 == 2137603072377791592L) {
                i18 = i72;
                j4 = bArr3[i6] != final_cip[i6] ? 3696715939049432759L : 4319018985115126267L;
            } else {
                i18 = i72;
            }
            if (j4 == 2776803616288623434L) {
                i60 = a(i38, i17, iArr10);
                j4 = 2624883423877033675L;
            }
            if (j4 == 4390732763753961871L) {
                int i90 = i40 + 3;
                iArr11 = iArr2;
                int i91 = ((input_part3[i40 + 2] & 255) << 16) | ((input_part3[i40 + 1] & 255) << 8) | (input_part3[i40] & 255);
                i40 += 4;
                i19 = ((input_part3[i90] & 255) << 24) | i91;
                System.out.printf("i19 = ((input_part3[i90] & 255) << 24) | i91;");
                j4 = 8271636431825400542L;
            } else {
                iArr11 = iArr2;
                i19 = i18;
            }
            if (j4 == 2168699168102359386L) {
                final_cip[1] = -39;
                j4 = 7377732012589796128L;
            }
            if (j4 == 6922153080934778037L) {
                iArr23[i6 * 2] = i60;
                j4 = 7063269725703171761L;
            }
            if (j4 == 8139682663513707735L) {
                int rev1 = i87;
                int rev2 = iArr23[2];
                i87 ^= iArr23[2];
                System.out.printf("0x%x ^= iArr23[2]; ==> 0x%x// 0x%x\n",rev1,i87,rev2);
                j4 = 1818264258760743319L;
            }
            if (j4 == 6258872612775795445L) {
                bArr5 = new byte[16];
                j4 = 6728389485969756476L;
            } else {
                bArr5 = bArr13;
            }
            if (j4 == 3885594324910219477L) {
                i19 ^= iArr23[5];
                System.out.printf("i19 ^= iArr23[5];\n");
                j4 = 5107504885568133637L;
            }
            if (j4 == 3593043533289075260L) {
                j4 = 3635178025052271786L;
                i56 = 0;
            }
            if (j4 == 2435557629452229653L) {
                j4 = 5509768734639095146L;
            }
            if (j4 == 4766834611894299394L) {
                final_cip[9] = -106;
                j4 = 1515725586281083405L;
            }
            if (j4 == 2763205489416023289L) {
                final_cip[10] = -34;
                j4 = 1376792466778633276L;
            }
            if (j4 == 6583809806457227315L) {
                j4 = 2100408234106893388L;
                i10 = 0;
            }
            if (j4 == 6816337433391007991L) {
                final_cip[8] = -20;
                j4 = 8844440844274236713L;
            }
            if (j4 == 2330796828706545701L) {
                j4 = 6265501985217721867L;
                i54 = 0;
            }
            if (j4 == 1206664505993188401L) {
                j4 = 4416966639446818591L;
                i10 = 0;
            }
            if (j4 == 7152594270267019474L) {
                j4 = 8601808016329414299L;
            }
            if (j4 == 3193075933208574218L) {
                j4 = 5311422641086316628L;
                i6 = 0;
            }
            if (j4 == 2134414655671570111L) {
                final_cip[15] = 50;
                j4 = 8077015324826886926L;
            }
            if (j4 == 7615576072437806969L) {
                i6++;
                j4 = 3169104890646436008L;
            }
            if (j4 == 7342767995630740962L) {
                j4 = 5594187482349100765L;
                i49 = 8;
            }
            if (j4 == 2012634943331272739L) {
                int[] iArr25 = iArr24[3];
                byte[] bArr14 = bArr12[1];
                i20 = i87;
                iArr20[(i6 * 2) + 513] = iArr25[(bArr14[(bArr14[i61] & 255) ^ i(i51)] & 255) ^ i(i52)];
                j4 = 8016446346432534725L;
            } else {
                i20 = i87;
            }
            if (j4 == 3124355357281158283L) {
                j4 = bArr3[i6] != final_cip[i6] ? 8401000026215651795L : 3749337558494560640L;

                System.out.printf("cmp en_inp222, final_cip222\n");
                System.out.printf("dump en_inp222:\n");
                for(int i=0;i<16;i++){
                    System.out.printf("0x%x,",bArr3[i]);
                }
                System.out.printf("\n");
                System.out.printf("dump final_cip222:\n");

                for(int i=0;i<16;i++){
                    System.out.printf("0x%x,",final_cip[i]);
                }
                System.out.printf("\n");

//                System.out.printf("dump iArr23\n");
//                for(int i=0;i<40;i++){
//                    System.out.printf("0x%x,",iArr23[i]);
//                }
//                System.out.printf("\n");

            }
            if (j4 == 7738313729691083676L) {
                j4 = i6 < i9 / 2 ? 4202436593687076484L : 7628593932436149125L;
            }
            if (j4 == 3638715073757882335L) {

                if(i6 ==15){
                    System.out.printf("hhh\n");
                }
                j4 = bArr3[i6] != final_cip[i6] ? 4765566201281400311L : 7708592395920482331L;
                System.out.printf("cmp en_inp, final_cip\n");
                System.out.printf("dump en_inp:\n");
                for(int i=0;i<16;i++){
                    System.out.printf("0x%x,",bArr3[i]);
                }
                System.out.printf("\n");
                System.out.printf("dump final cip:\n");

                for(int i=0;i<16;i++){
                    System.out.printf("0x%x,",final_cip[i]);
                }
                System.out.printf("\n");

                System.out.printf("dump iArr23\n");
                for(int i=0;i<40;i++){
                    System.out.printf("0x%x,",iArr23[i]);
                }
                System.out.printf("\n");
            }
            if (j4 == 7084261336607768407L) {
                j4 = 1372428978400526091L;
                i54 = 0;
            }
            if (j4 == 2469602840783646837L) {
                j4 = 2610219915628716936L;
            }
            if (j4 == 2886594228447074028L) {
                j4 = bArr3[i6] != final_cip[i6] ? 7812355649959096589L : 9206504687413913692L;
            }
            if (j4 == 7235245031966433308L) {
                j4 = i6 < 256 ? 3879487290150562409L : 2908355311707016655L;
            }
            if (j4 == 6783335171051007387L) {
                iArr23[(i6 * 2) + 1] = (i60 << 9) | (i60 >>> 23);

                j4 = 3698409039146345710L;
            }
            if (j4 == 8494914655617116318L) {
                j4 = 3308045856010871254L;
            }
            if (j4 == 7391897490478601836L) {
                j4 = i6 < 16 ? 1947295455057318086L : 1784429727674430321L;
            }
            if (j4 == 9128083677415659622L) {
                final_cip[13] = -114;
                j4 = 9217510483877698234L;
            }
            if (j4 == 1729443654799488062L) {
                i57--;
                j4 = 8797484323472943077L;
            }
            if (j4 == 5592042121434727091L) {
                final_cip[5] = -69;
                j4 = 1323827752692402101L;
            }
            if (j4 == 1818264258760743319L) {
                c2 = 3;
                int rev = i19;
                i19 ^= iArr23[3];
//                System.out.printf("i19 ^= iArr23[3];1\n");
                System.out.printf("0x%x ^= iArr23[3](0x%x); ==> 0x%x\n",rev,iArr23[3],i19);
                j4 = 5328979100626095900L;
            } else {
                c2 = 3;
            }
            if (j4 == 6418068088604690665L) {
                i19 ^= iArr23[c2];
                System.out.printf("i19 ^= iArr23[c2];\n");
                j4 = 1503792404112071770L;
            }
            if (j4 == 4594646578689629539L) {
                j4 = 3365615621264263466L;
                bArr3 = new byte[16];
            }
            if (j4 == 9195216308108861773L) {
                final_cip[8] = 49;
                j4 = 3200337655383209956L;
            }
            if (j4 == 1577535481649201043L) {
                j4 = 3478198951987437965L;
                i6 = 0;
            }
            if (j4 == 3759219415620181525L) {
                i57 = i38 - 1;
                j4 = 6062811699616037457L;
            }
            if (j4 == 3256821261585855975L) {
                j4 = 3779293355388292368L;
                i54 = (i54 + 1) & 255;
            }
            if (j4 == 6329663680677574624L) {
                final_cip[15] = 50;
                j4 = 4912547151723290384L;
            }
            if (j4 == 6187038164260617255L) {
                j4 = 1311781772751449630L;
                i6 = 0;
            }
            if (j4 == 2685803154186139471L) {
                int i92 = i40 + 3;
                iArr12 = iArr10;
                int i93 = ((input_part3[i40 + 1] & 255) << 8) | (input_part3[i40] & 255) | ((input_part3[i40 + 2] & 255) << 16);
                i40 += 4;
                i21 = i93 | ((input_part3[i92] & 255) << 24);
                j4 = 4729681422063648060L;
            } else {
                iArr12 = iArr10;
                i21 = i20;
            }
            if (j4 == 3504079853553908765L) {
                i6++;
                j4 = 8954707163893861550L;
            }
            if (j4 == 6600686903247428085L) {
                c3 = 3;
                int i94 = iArr8[3];
                j4 = 8816681305993860676L;
            } else {
                c3 = 3;
            }
            if (j4 == 7573029167043807009L) {
                int i95 = iArr8[c3];
                j4 = 8002130431631985630L;
            }
            if (j4 == 5388008578103207358L) {
                j4 = 3805431862040669091L;
                i51 = iArr8[1];
            }
            if (j4 == 1868667817538176147L) {
                int i96 = i40 + 3;
                int i97 = ((input_part3[i40 + 1] & 255) << 8) | (input_part3[i40] & 255) | ((input_part3[i40 + 2] & 255) << 16);
                i40 += 4;
                i21 = i97 | ((input_part3[i96] & 255) << 24);
                j4 = 2889001075928355608L;
            }
            if (j4 == 7677570233584385171L) {
                int rev = i84;
                i84 = (i84 >>> 1) | (i84 << 31);
                System.out.printf("0x%x = (0x%x >>> 1) | (0x%x << 31);\n",i84,rev,rev);
                j4 = 1923774560246569152L;
            }
            if (j4 == 7215264321897972490L) {
                j4 = 7299484503295174969L;
                i10 = 0;
            }
            if (j4 == 7269244363048797189L) {
                j4 = 8344335594272363090L;
            }
            if (j4 == 5153625468444186480L) {
                int rev = i84;
                i84 = (i84 >>> 1) | (i84 << 31);
                System.out.printf("0x%x = (0x%x >>> 1) | (0x%x << 31);\n",i84,rev,rev);
                j4 = 1160266727076026994L;
            }
            if (j4 == 8405907736709769083L) {
                j4 = bArr3[i6] != final_cip[i6] ? 4727667340962820071L : 8074621974338335444L;
            }
            if (j4 == 7720877091476958305L) {
                j4 = 2712255506212294232L;
                i56 = ((bArr5[i62] & 255) + (bArr11[i6] & 255) + i56) & 255;
            }
            if (j4 == 5859366234801575937L) {
                bArr3[i6] = (byte) (bArr4[i6] ^ bArr11[i53]);
                j4 = 4375059743535676664L;
            }
            if (j4 == 8642648116757711055L) {
                i62 = (i62 + 1) % 16;
                j4 = 3176206153682062025L;
            }
            if (j4 == 7927706331794218369L) {
                final_cip[10] = -4;
                j4 = 4044116278763382115L;
            }
            if (j4 == 7620824939062689078L) {
                i19 ^= iArr23[3];
                System.out.printf("i19 ^= iArr23[3];2\n");
                j4 = 9203235650833687810L;
            }
            if (j4 == 3176206153682062025L) {
                i6++;
                j4 = 5158554594830700929L;
            }
            if (j4 == 3785530020709649507L) {
                bArr11[i6] = (byte) i6;
                j4 = 7615576072437806969L;
            }
            if (j4 == 6830438277265895922L) {
                final_cip[15] = 115;
                j4 = 5737565298662478736L;
            }
            if (j4 == 4730643406790254771L) {
                j4 = 4975363132170806438L;
                i62 = 0;
            }
            if (j4 == 4687532178299999822L) {
                int rev = i84;
                i84 ^= (i47 + i48) + iArr23[i49];
                System.out.printf("0x%x ^= (0x%x + 0x%x) + iArr23[0x%x]; ==> 0x%x//0x%x  ===2\n",rev,i47,i48,i49,i84,iArr23[i49]);
                j4 = 7677570233584385171L;
                i49++;
            }
            if (j4 == 3511893548020497197L) {
                int rev = i84;
                i84 ^= iArr23[6];
                System.out.printf("0x%x ^= iArr23[6]; ==> 0x%x // 0x%x\n",rev,i84,iArr23[6]);
                j4 = 7197100520713411792L;
            }
            if (j4 == 3490326607433591043L) {
                j4 = 3785530020709649507L;
            }
            if (j4 == 8964480036317405863L) {
                i60 += i41;
                j4 = 6411465233834267853L;
            }
            if (j4 == 7053198258759358084L) {
                j4 = 9072050633124824651L;
                i6 = 0;
            }
            if (j4 == 4919743909045453378L) {
                final_cip[3] = -45;
                j4 = 7612433227526352592L;
            }
            if (j4 == 3918700728063325793L) {
                int rev1 = i21;
                i21 ^= (i47 + i48) + iArr23[i49];
//                System.out.printf("i21: 0x%x\n",i21);
                System.out.printf("0x%x ^= (0x%x + 0x%x) + iArr23[0x%x]; ==> 0x%x // 0x%x ===3 \n",rev1,i47,i48,i49,i21,iArr23[i49]);
                j4 = 3799650815120663631L;
                i49++;
            }
            if (j4 == 3244817401922083652L) {
                j4 = 3508095575112387696L;
                i40 = 0;
            }
            if (j4 == 1791103446893765993L) {
                int[] iArr26 = iArr24[3];
                byte[] bArr15 = bArr12[1];
                iArr20[(i6 * 2) + 513] = iArr26[(bArr15[(bArr15[i61] & 255) ^ i(i51)] & 255) ^ i(i52)];
                j4 = 5028010433435687981L;
            }
            if (j4 == 2754848930084988709L) {
                final_cip[0] = -97;
                j4 = 4098100907245666696L;
            }
            if (j4 == 5634423947985751522L) {
                j4 = 6069099502938214271L;
                iArr23 = new int[i9];
            }
            if (j4 == 7907227585526812034L) {
                j4 = 8327337783489553350L;
                i56 = ((bArr5[i62] & 255) + (bArr11[i6] & 255) + i56) & 255;
            }
            if (j4 == 3150114737913458226L) {
                i10 += 2;
                j4 = 2100408234106893388L;
            }
            int i98 = i10;
            if (j4 == 8057179424399068224L) {
                bArr11[i54] = bArr11[i55];
                j4 = 8706528655033256702L;
            }
            if (j4 == 4013039085825403792L) {
                final_cip[7] = -33;
                j4 = 6385765029630073007L;
            }
            if (j4 == 4268434749325211515L) {
                i22 = 33686018 + i17;
                j4 = 7738313729691083676L;
            } else {
                i22 = i17;
            }
            if (j4 == 9090300621190835968L) {
                j4 = 9002596763800113747L;
                i50 = i6;
                i58 = i50;
                i61 = i58;
                i63 = i61;
            }
            if (j4 == 6742327015997388752L) {
                i16 ^= ((i48 * 2) + i47) + iArr23[i49];
                System.out.printf("i16 ^= ((i48 * 2) + i47) + iArr23[i49];\n");
                j4 = 7233187872281632736L;
                i49++;
            }
            if (j4 == 4335696836688972368L) {
                i23 = bArr5.length;
                j4 = 4477685489247392220L;
            } else {
                i23 = i15;
            }
            if (j4 == 5982238460718101231L) {
                bArr11[i6] = bArr11[i56];
                j4 = 7734105193329641264L;
            }
            if (j4 == 7079524315661024246L) {
                i24 = i98;
                j4 = i6 < 16 ? 4839378301785589868L : 4531779885876544223L;
            } else {
                i24 = i98;
            }
            if (j4 == 3798078227232544657L) {
                int rev = i19;
                i19 ^= ((i48 * 2) + i47) + iArr23[i49];

                System.out.printf("0x%x ^= ((0x%x * 2) + 0x%x) + iArr23[0x%x](0x%x); ==> 0x%x  ===4 \n",rev,i48,i47,i49,iArr23[i49],i19);

                i49++;
                j4 = 4170216661130793823L;
            }
            if (j4 == 1875129475667370410L) {
                int[] iArr27 = iArr24[3];
                byte[] bArr16 = bArr12[1];
                bArr6 = bArr12;
                iArr20[(i6 * 2) + 513] = iArr27[(bArr16[(bArr16[i61] & 255) ^ i(i51)] & 255) ^ i(i52)];
                j4 = 9181295485946627806L;
            } else {
                bArr6 = bArr12;
            }
            if (j4 == 7780188459499837486L) {
                i57 = i38 - 1;
                j4 = 3286379070729456885L;
            }
            if (j4 == 5426809489659825220L) {
                int i99 = i4 + 3;
                i25 = i16;
                System.out.printf("i25 = i16;\n");
                int i100 = ((bArr5[i4 + 1] & 255) << 8) | (bArr5[i4] & 255) | ((bArr5[i4 + 2] & 255) << 16);
                i4 += 4;
                iArr12[i6] = i100 | ((bArr5[i99] & 255) << 24);
                j4 = 7830774370852576407L;
            } else {
                i25 = i16;
            }
            if (j4 == 8738922874029281563L) {
                i6++;
                j4 = 1909122035249646259L;
            }
            if (j4 == 6665095630221528608L) {
                bArr5 = new byte[16];
                j4 = 7621196338214628961L;
            }
            if (j4 == 6179510455852880218L) {
                final_cip[12] = 101;
                j4 = 8310787871818619634L;
            }
            if (j4 == 3569809687587833405L) {
                i52 = iArr8[0];
                j4 = 8603388170022135396L;
            }
            if (j4 == 1167911205115368985L) {
                int i101 = i4 + 3;
                int i102 = ((bArr5[i4 + 1] & 255) << 8) | (bArr5[i4] & 255) | ((bArr5[i4 + 2] & 255) << 16);
                i4 += 4;
                iArr11[i6] = i102 | ((bArr5[i101] & 255) << 24);
                j4 = 6994571557561233697L;
            }
            int i103 = i4;
            if (j4 == 8623714993202893823L) {
                final_cip[11] = -88;
                j4 = 2189736568610615783L;
            }
            if (j4 == 4577416787505181944L) {
                final_cip[2] = 118;
                j4 = 5378952491855986803L;
            }
            if (j4 == 8789625248543143702L) {
                final_cip[2] = 118;
                j4 = 7991109021174387007L;
            }
            if (j4 == 1485094653842035027L) {
                j4 = (i6 >= 4 || i103 >= i23) ? 8504695950589395449L : 8461713412992271361L;
            }
            if (j4 == 4170216661130793823L) {
                i47 = b(i21, 0, iArr20);
                System.out.printf("0x%x = b(0x%x, 0, iArr20);4\n",i47,i21);
//                System.out.printf("i47: 0x%x\n",i47);
                j4 = 2381872149833716276L;
            }
            if (j4 == 8666010438815626922L) {
                b2 = bArr11[i54];
                j4 = 8057179424399068224L;
            }
            if (j4 == 7041655693530341265L) {
                i19 ^= ((i48 * 2) + i47) + iArr23[i49];
                System.out.printf("i19 ^= ((i48 * 2) + i47) + iArr23[i49]; ===5\n");
                j4 = 3169561277751192603L;
                i49++;
            }
            if (j4 == 4609849330570144880L) {
                final_cip[9] = -77;
                j4 = 2289044719646071181L;
            }
            if (j4 == 5449112193696891016L) {
                j4 = 3124355357281158283L;
            }
            if (j4 == 8662712234784089029L) {
                i23 = bArr5.length;
                j4 = 8878582214211818374L;
            }
            if (j4 == 6115233329846619454L) {
                j4 = 5395204442363878272L;
            }
            if (j4 == 4483906068230756548L) {
                j4 = 6676485492170781350L;
            }
            if (j4 == 1956686733200189415L) {
                final_cip = new byte[16];
                j4 = 7006355891692714059L;
            }
            if (j4 == 8053000807881165967L) {
                int rev =i84;
                i84 ^= (i47 + i48) + iArr23[i49];

                System.out.printf("0x%x ^= (0x%x + 0x%x) + iArr23[0x%x]; ==> 0x%x//0x%x ===6 \n",rev,i47,i48,i49,i84,iArr23[i49]);
                j4 = 5495851403009851521L;
                i49++;
            }
            if (j4 == 7143194817459945248L) {
                j4 = 3373811553476160062L;
            }
            if (j4 == 1749537745733462777L) {
                j4 = (i6 >= 4 || i103 >= i23) ? 6551390027023926275L : 4570635662716578048L;
            }
            if (j4 == 2188405883759779224L) {
                j4 = 3918062052349580671L;
                i62 = 0;
            }
            if (j4 == 7235937894701642304L) {
                int rev = i21;
                i21 = (i21 << 31) | (i21 >>> 1);
                System.out.printf("0x%x = (0x%x  << 31) | (0x%x  >>> 1);\n",i21,rev,rev);
                j4 = 7301888031531657853L;
            }
            if (j4 == 2995796423546491127L) {
                j4 = 9170084184750692299L;
            }
            if (j4 == 8002130431631985630L) {
                iArr20 = new int[1024];
                j4 = 7166648683214755429L;
            }
            if (j4 == 2860092959791447983L) {
                j4 = 7348308086934515854L;
                i56 = ((bArr5[i62] & 255) + (bArr11[i6] & 255) + i56) & 255;
            }
            if (j4 == 7591776709387561072L) {
                iArr13 = new int[4];
                j4 = 4062230737866491849L;
            } else {
                iArr13 = iArr11;
            }
            if (j4 == 3688747761534332265L) {
                int rev = i84;
                i84 ^= iArr23[0];

                System.out.printf("0x%x ^= iArr23[0]; ==> 0x%x // 0x%x\n",rev,i84,iArr23[0]);
                j4 = 2443751596759295723L;
            }
            if (j4 == 6453676624431139898L) {
                i6++;
                j4 = 1913249944150004525L;
            }
            if (j4 == 5235021199741258527L) {
                iArr13 = new int[4];
                j4 = 8117727425067800668L;
            }
            if (j4 == 7708592395920482331L) {
                i6++;
                j4 = 1210447254521047538L;
            }
            if (j4 == 4538286560804077206L) {
                i47 = b(i84, 0, iArr20);
                System.out.printf("0x%x = b(0x%x, 0, iArr20);5\n",i47,i84);
                j4 = 5165812183614621889L;
            }
            if (j4 == 7068862727388703850L) {
                j4 = 3933803068447152709L;
            }
            if (j4 == 7957723699443428076L) {
                i26 = i84;
                int i104 = i103 + 3;
                i27 = i21;
                int i105 = (bArr5[i103] & 255) | ((bArr5[i103 + 1] & 255) << 8) | ((bArr5[i103 + 2] & 255) << 16);
                i103 += 4;
                iArr12[i6] = i105 | ((bArr5[i104] & 255) << 24);
                j4 = 6933247193213399925L;
            } else {
                i26 = i84;
                i27 = i21;
            }
            if (j4 == 5595710579549419349L) {
                i6++;
                j4 = 1620820052340096368L;
            }
            if (j4 == 8097574055691912384L) {
                int i106 = i40 + 3;
                int i107 = ((input_part3[i40 + 1] & 255) << 8) | (input_part3[i40] & 255) | ((input_part3[i40 + 2] & 255) << 16);
                i40 += 4;
                i28 = i107 | ((input_part3[i106] & 255) << 24);
                System.out.printf("i28 = i107 | ((input_part3[i106] & 255) << 24);\n");
                j4 = 4298963903025309444L;
            } else {
                i28 = i26;
            }
            if (j4 == 2617081080307970335L) {
                j4 = 4473724296154421454L;
                i54 = (i54 + 1) & 255;
            }
            if (j4 == 8528493068304898123L) {
                final_cip[8] = 49;
                j4 = 3725381910638361431L;
            }
            if (j4 == 5710521428222058283L) {
                j4 = 6282419177198653002L;
                i6 = 0;
            }
            if (j4 == 5509705484215944470L) {
                i41 = a(i38, 0x1010101 + i22, iArr13);
                j4 = 9155937893447827252L;
            }
            if (j4 == 8141640372958328067L) {
                b2 = bArr11[i6];
                j4 = 3883979507512821622L;
            }
            if (j4 == 5014224365646153772L) {
                final_cip[14] = -120;
                j4 = 6781964674139290256L;
            }
            if (j4 == 2741486890114654248L) {
                final_cip[9] = -106;
                j4 = 7927706331794218369L;
            }
            if (j4 == 5351528138698026150L) {
                iArr23[i6 * 2] = i60;
                j4 = 8223258137555177735L;
            }
            if (j4 == 1307281791046846137L) {
                int i108 = i40 + 3;
                int i109 = ((input_part3[i40 + 1] & 255) << 8) | (input_part3[i40] & 255) | ((input_part3[i40 + 2] & 255) << 16);
                i40 += 4;
                i28 = i109 | ((input_part3[i108] & 255) << 24);
                System.out.printf("i28 = 0x%x\n",i28);
                j4 = 8545670441877195089L;
            }
            if (j4 == 3315634246002652401L) {
                j4 = 7391422008886710088L;
                i6 = 0;
            }
            if (j4 == 8726141804031885222L) {
                j4 = 6206967618882655077L;
                iArr23 = new int[i9];
            }
            if (j4 == 6265501985217721867L) {
                j4 = 7228169035332109883L;
                i55 = 0;
            }
            if (j4 == 6042232201362629815L) {
                return false;
            }
            if (j4 == 4915474783797972804L) {
                j4 = 4721983077526601781L;
                i6 = 0;
            }
            if (j4 == 1644016907092934503L) {
                final_cip[11] = -113;
                j4 = 2009277883651077966L;
            }
            if (j4 == 3242248119027284566L) {
                final_cip[2] = Byte.MIN_VALUE;
                j4 = 4919743909045453378L;
            }
            if (j4 == 8401000026215651795L) {
                j4 = 6042232201362629815L;
            }
            int i110 = i25;
            if (j4 == 1757468250215542428L) {
                i48 = b(i110, 3, iArr20);
//                System.out.printf("i48 = b(i110, 3, iArr20);\n");
                System.out.printf("0x%x = b(0x%x, 3, iArr20);6\n",i48,i110);
                j4 = 3918700728063325793L;
            }
            if (j4 == 3805431862040669091L) {
                int i111 = iArr8[2];
                j4 = 7573029167043807009L;
            }
            if (j4 == 1562483755754170452L) {
                b2 = bArr11[i54];
                j4 = 1281267670811563792L;
            }
            if (j4 == 4775749037024366417L) {
                bArr11 = new byte[256];
                j4 = 6667018595382172981L;
            }
            if (j4 == 7215458347621232043L) {
                final_cip[6] = 22;
                j4 = 4013039085825403792L;
            }
            if (j4 == 8851840692175027013L) {
                j4 = 3971401812264761653L;
            }
            if (j4 == 6496457465553891320L) {
                final_cip[3] = -45;
                j4 = 9067166631630121596L;
            }
            if (j4 == 4899867139846737305L) {
                j4 = 3291362829469222813L;
                i6 = 0;
            }
            if (j4 == 4949400257663735525L) {
                return true;
            }
            if (j4 == 6624026845403021411L) {
                i9 = 40;
                j4 = 1384619611072712114L;
            }
            if (j4 == 3717774128157910605L) {
                final_cip[14] = -120;
                j4 = 5632710845036330174L;
            }
            if (j4 == 4703006722331764068L) {
                final_cip[1] = 46;
                j4 = 5925562685676025045L;
            }
            if (j4 == 8906950120270949104L) {
                i110 = (i110 >>> 31) | (i110 << 1);
                System.out.printf("i110 = (i110 >>> 31) | (i110 << 1);1\n");
                j4 = 4054239504286538232L;
            }
            if (j4 == 2968358151039079624L) {
                j4 = 8694332280188348797L;
                i62 = 0;
            }
            if (j4 == 4731072527315935075L) {
                i29 = i103;
                j4 = input.length() < 64 ? 7152594270267019474L : 7207634175374518959L;
            } else {
                i29 = i103;
            }
            if (j4 == 5837388147636045013L) {
                final_cip[13] = 34;
                j4 = 4209003260697362161L;
            }
            if (j4 == 3348113858426447674L) {
                i6++;
                j4 = 3239610692754448539L;
            }
            if (j4 == 8499802369700230427L) {
                i62 = (i62 + 1) % 16;
                j4 = 6852692350973101702L;
            }
            if (j4 == 1355827378937596861L) {
                int i112 = iArr8[2];
                j4 = 3159131613398236155L;
            }
            if (j4 == 3765463719702917373L) {
                final_cip[3] = -67;
                j4 = 6246276100940706152L;
            }
            if (j4 == 7439466117788503430L) {
                final_cip[10] = -4;
                j4 = 4184352008924436096L;
            }
            if (j4 == 7328217541416181185L) {
                i62 = (i62 + 1) % 16;
                j4 = 7494950256479009720L;
            }
            if (j4 == 4931416120428297318L) {
                j4 = 3272108066239338657L;
                i41 = a(i38, 0x1010101 + i22, iArr13);
            }
            if (j4 == 1853586948992287921L) {
                i110 ^= iArr23[7];
                System.out.printf("i110 ^= iArr23[7];1\n");
                j4 = 3369304386314801955L;
            }
            int i113 = i24;
            if (j4 == 2100408234106893388L) {
                j4 = i113 < 16 ? 6044249269185916930L : 4967406293272637771L;
            }
            if (j4 == 6202119020092438945L) {
                bArr11 = new byte[256];
                j4 = 6207585730399429197L;
            }
            if (j4 == 1239202435642479562L) {
                j4 = 6282588756826602766L;
                i6 = 0;
            }
            if (j4 == 2921277261483052884L) {
                j4 = 3805451690314712856L;
                i9 = 40;
            }
            if (j4 == 4571385285247507939L) {
                iArr23[(i6 * 2) + 1] = (i60 << 9) | (i60 >>> 23);
                j4 = 1234569916309842559L;
            }
            if (j4 == 3460300782170937607L) {
                i38 = i23 / 8;
                j4 = 2921277261483052884L;
            }
            if (j4 == 3124726175048856375L) {
                i110 ^= iArr23[1];
                System.out.printf("i110 ^= iArr23[1];2\n");
                j4 = 8088807405999475448L;
            }
            if (j4 == 7309113347123373839L) {
                j4 = 2272798444665954523L;
                i6 = 0;
            }
            if (j4 == 3997704319387063135L) {
                j4 = 8997468243049584150L;
            }
            if (j4 == 8861860503648848567L) {
                i30 = i9;
                iArr14 = iArr8;
                input_partt4 = Arrays.copyOfRange(input.getBytes(), 48, 64);
                j4 = 2330796828706545701L;
            } else {
                i30 = i9;
                iArr14 = iArr8;
                input_partt4 = bArr4;
            }
            if (j4 == 4410622224915986892L) {
                final_cip[1] = 46;
                j4 = 6711257227006116877L;
            }
            if (j4 == 7194106817561645911L) {
                final_cip[13] = -114;
                j4 = 5512350061105350170L;
            }
            if (j4 == 6612240120868137916L) {
                bArr11[i56] = b2;
                j4 = 5693093104358912780L;
            }
            if (j4 == 2982641033187796690L) {
                iArr20[(i6 * 2) + 1] = iArr24[1][(bArr6[0][(bArr6[1][i50] & 255) ^ g(i51)] & 255) ^ g(i52)];
                j4 = 3486271154687386954L;
            }
            if (j4 == 3031198949573775541L) {
                i6++;
                j4 = 9203595848917361081L;
            }
            if (j4 == 5055689685515914335L) {
                j4 = i6 < 256 ? 1247075058077372606L : 6091441190737178001L;
            }
            if (j4 == 8682936313381034341L) {
                i31 = i6;
                input_part3 = Arrays.copyOfRange(input.getBytes(), 32, 48);
                j4 = 5026574997973149922L;
            } else {
                i31 = i6;
            }
            if (j4 == 4765566201281400311L) {
                j4 = 4878474884038157657L;
            }
            if (j4 == 3434639405684086363L) {
                final_cip[7] = -33;
                j4 = 2197600650028069726L;
            }
            if (j4 == 8117727425067800668L) {
                iArr15 = new int[4];
                j4 = 7442085785176969176L;
            } else {
                iArr15 = iArr14;
            }
            if (j4 == 7857940782209243597L) {
                j4 = 3759219415620181525L;
                i31 = 0;
            }
            if (j4 == 2003868226519400571L) {
                j4 = 4691140216346611221L;
            }
            if (j4 == 2466964143165741837L) {
                j4 = 3169104890646436008L;
                i31 = 0;
            }
            if (j4 == 8308487276324327784L) {
                bArr11[i31] = bArr11[i56];
                j4 = 2555970059350819025L;
            }
            if (j4 == 4202436593687076484L) {
                j4 = 2776803616288623434L;
            }
            if (j4 == 6996128371779785436L) {
                j4 = 8730538436400569799L;
                i29 = 0;
            }
            if (j4 == 8935933772175304137L) {
                int rev = i28;
                i28 ^= iArr23[0];
                System.out.printf("0x%x ^= iArr23[0](0x%x);  ==> 0x%x \n",rev, iArr23[0],i28);
                j4 = 7219960127837973449L;
            }
            if (j4 == 1715651793431489116L) {
                bArr3[i31] = (byte) (input_partt4[i31] ^ bArr11[i53]);

                System.out.printf("==> 0x%x =  (input_partt4[0x%x] ^ bArr11[0x%x](0x%x));\n",bArr3[i31],i31,i53,bArr11[i53]);
                j4 = 1688352577061095122L;
            }
            if (j4 == 4192332344726786256L) {
                final_cip[1] = 46;
                j4 = 3242248119027284566L;
            }
            if (j4 == 6097367080807002346L) {
                j4 = input.length() < 64 ? 4134022033126525745L : 9084636122582124317L;
            }
            if (j4 == 1645136258490241993L) {
                j4 = 4956183964370101238L;
                i31 = 0;
            }
            if (j4 == 8865616538709174935L) {
                i32 = (((i48 * 2) + i47) + iArr23[i49]) ^ i110;

                System.out.printf("0x%x = (((0x%x * 2) + 0x%x) + iArr23[0x%x]) ^ 0x%x; // 0x%x |3\n",i32,i48,i47,i49,i110,iArr23[i49]);
                j4 = 3150114737913458226L;
                i49++;
            } else {
                i32 = i110;
            }
            if (j4 == 5163304606225864297L) {
                final_cip[4] = 119;
                j4 = 5175101841935525119L;
            }
            if (j4 == 9026190483180684217L) {
                int i114 = i40 + 3;
                bArr7 = input_partt4;
                int i115 = ((input_part3[i40 + 2] & 255) << 16) | ((input_part3[i40 + 1] & 255) << 8) | (input_part3[i40] & 255);
                i40 += 4;
                i33 = i115 | ((input_part3[i114] & 255) << 24);
                j4 = 7022880009955170057L;
            } else {
                bArr7 = input_partt4;
                i33 = i27;
            }
            if (j4 == 2300035979815882265L) {
                i60 += i41;
                j4 = 5407125151982145331L;
            }
            if (j4 == 7076999511290385819L) {
                final_cip[10] = -4;
                j4 = 5005580943279474124L;
            }
            if (j4 == 7957423564036594724L) {
                int rev = i28;
                i28 ^= iArr23[6];
//                System.out.printf("i28 ^= iArr23[6];\n");
                System.out.printf("0x%x ^= iArr23[6](0x%x); ==> 0x%x \n",rev,iArr23[6],i28);
                j4 = 3166750012504996540L;
            }
            if (j4 == 2082226578850038631L) {
                j4 = 8587595791621758818L;
                i34 = 0;
            } else {
                i34 = i31;
            }
            if (j4 == 7377732012589796128L) {
                final_cip[2] = 118;
                j4 = 3765463719702917373L;
            }
            if (j4 == 8706528655033256702L) {
                bArr11[i55] = b2;
                j4 = 3944034548958798065L;
            }
            if (j4 == 7207634175374518959L) {
                bArr5 = new byte[16];
                j4 = 8619643661940722843L;
            }
            if (j4 == 5958651804061655044L) {
                iArr16 = iArr12;
                i60 = a(i38, i22, iArr16);
                j4 = 4120500615914686322L;
            } else {
                iArr16 = iArr12;
            }
            if (j4 == 5373825686582120237L) {
                int[] iArr28 = iArr24[0];
                byte[] bArr17 = bArr6[0];
                iArr17 = iArr16;
                iArr20[i34 * 2] = iArr28[(bArr17[(bArr17[i63] & 255) ^ f(i51)] & 255) ^ f(i52)];
                j4 = 5188016447122403309L;
            } else {
                iArr17 = iArr16;
            }
            if (j4 == 8657852808421337216L) {
                final_cip[0] = -97;
                j4 = 7303977094428283562L;
            }
            if (j4 == 2559141778370937007L) {
                j4 = i34 < bArr5.length ? 8226334980212259602L : 1807466501694616499L;
            }
            if (j4 == 7612433227526352592L) {
                final_cip[4] = 56;
                j4 = 8113126029116536782L;
            }
            if (j4 == 6641130065549689505L) {
                i60 += i41;
                j4 = 4904370970975869766L;
            }
            if (j4 == 6249148651518141632L) {
                c4 = 6;
                final_cip[6] = 22;
                j4 = 8443672320267095196L;
            } else {
                c4 = 6;
            }
            if (j4 == 7100981003187767618L) {
                final_cip[c4] = 86;
                j4 = 6684206521967284343L;
            }
            int i116 = i38;
            if (j4 == 5985635937414591521L) {
                j4 = 7309113347123373839L;
                bArr3 = new byte[16];
            }
            if (j4 == 4904370970975869766L) {
                iArr23[i34 * 2] = i60;
                j4 = 2300035979815882265L;
            }
            if (j4 == 8095882760764902094L) {
                int[] iArr29 = iArr24[0];
                byte[] bArr18 = bArr6[0];
                iArr20[i34 * 2] = iArr29[(bArr18[(bArr18[i63] & 255) ^ f(i51)] & 255) ^ f(i52)];
                j4 = 1614246019380523334L;
            }
            if (j4 == 8485630121070762057L) {
                j4 = i34 < 256 ? 1578923656121161355L : 2196269207190278500L;
            }
            if (j4 == 1807466501694616499L) {
                iArr18 = iArr13;
                j4 = 7113837318717080147L;
                input_part3 = Arrays.copyOfRange(input.getBytes(), 32, 48);
            } else {
                iArr18 = iArr13;
            }
            if (j4 == 4136628260743276174L) {
                j4 = 7015557725723415691L;
                i50 = i34;
                i58 = i50;
                i61 = i58;
                i63 = i61;
            }
            if (j4 == 7628593932436149125L) {
                j4 = 5388008578103207358L;
                i52 = iArr15[0];
            }
            if (j4 == 1688352577061095122L) {
                i34++;
                j4 = 2272798444665954523L;
            }
            if (j4 == 9156114371027586341L) {
                return false;
            }
            if (j4 == 8003113504676674850L) {
                final_cip[7] = -33;
                j4 = 4020479843606037028L;
            }
            if (j4 == 5538777342439939651L) {
                bArr11[i54] = bArr11[i55];
                j4 = 5136352466433219964L;
            }
            if (j4 == 6062303455322103900L) {
                j4 = 3727400916568393083L;
                i56 = 0;
            }
            if (j4 == 2112374256663903657L) {
                final_cip[5] = -69;
                j4 = 6479748932467918819L;
            }
            if (j4 == 7105550752828252141L) {
                j4 = 5426809489659825220L;
            }
            if (j4 == 3779293355388292368L) {
                j4 = 8666010438815626922L;
                i55 = ((bArr11[i54] & 255) + i55) & 255;
            }
            if (j4 == 4044116278763382115L) {
                final_cip[11] = -113;
                j4 = 1931444552567951803L;
            }
            if (j4 == 2228853410470432732L) {
                j4 = 5808169080060243476L;
                bArr3 = new byte[]{(byte) i33, (byte) (i33 >>> 8), (byte) (i33 >>> 16), (byte) (i33 >>> 24), (byte) i19, (byte) (i19 >>> 8), (byte) (i19 >>> 16), (byte) (i19 >>> 24), (byte) i28, (byte) (i28 >>> 8), (byte) (i28 >>> 16), (byte) (i28 >>> 24), (byte) i32, (byte) (i32 >>> 8), (byte) (i32 >>> 16), (byte) (i32 >>> 24)};
                System.out.printf("bArr3 = new byte[]{(byte) i33, (byte) (i33 >>> 8), (byte) (i33 >>> 16), (byte) (i33 >>> 24), (byte)\n");
            }
            if (j4 == 9179206018690720602L) {
                int rev = i19;
                i19 ^= iArr23[5];
                System.out.printf("0x%x ^= iArr23[5](0x%x); ==> 0x%x\n",rev,iArr23[5],i19);
                j4 = 3612472421307200740L;
            }
            if (j4 == 6016756214847724921L) {
                int rev = i19;
                i19 = (i19 >>> 31) | (i19 << 1);
                System.out.printf("0x%x = (0x%x >>> 31) | (0x%x << 1);1 \n",i19,rev,rev);

                j4 = 5461752164917072913L;
            }
            if (j4 == 4803956414827796846L) {
                int[] iArr30 = iArr24[0];
                byte[] bArr19 = bArr6[0];
                iArr20[i34 * 2] = iArr30[(bArr19[(bArr19[i63] & 255) ^ f(i51)] & 255) ^ f(i52)];
                j4 = 4369458919546020466L;
            }
            if (j4 == 6962662929294394300L) {
                return false;
            }
            if (j4 == 8016446346432534725L) {
                i34++;
                j4 = 3232348833396235159L;
            }
            if (j4 == 6087563668281968390L) {
                j4 = 7310006369231674608L;
                i49 = 8;
            }
            if (j4 == 1787685171167549243L) {
                i22 += 33686018;
                j4 = 7412843220635102870L;
            }
            i39 = i22;
            if (j4 == 2699912527891922057L) {
                j4 = 1392904840951541524L;
                i34 = 0;
            }
            if (j4 == 4755329529059895386L) {
                j4 = 7781468632794343149L;
                iArr21 = new int[4];
            } else {
                iArr21 = iArr17;
            }
            if (j4 == 8062189661182021718L) {
                bArr11[i55] = b2;
                j4 = 4392895671140748120L;
            }
            if (j4 == 8209964894033195569L) {
                i113 += 2;
                j4 = 2325655040068091391L;
            }
            if (j4 == 2329622646202800515L) {
                j4 = 6933244932276356793L;
                bArr3 = new byte[]{(byte) i33, (byte) (i33 >>> 8), (byte) (i33 >>> 16), (byte) (i33 >>> 24), (byte) i19, (byte) (i19 >>> 8), (byte) (i19 >>> 16), (byte) (i19 >>> 24), (byte) i28, (byte) (i28 >>> 8), (byte) (i28 >>> 16), (byte) (i28 >>> 24), (byte) i32, (byte) (i32 >>> 8), (byte) (i32 >>> 16), (byte) (i32 >>> 24)};
                System.out.printf("bArr3 = new byte[]{(byte) i33, (byte) (i33 >>> 8), (by\n");
            }
            if (j4 == 4896714650032568544L) {
                int rev = i19;
                i19 ^= ((i48 * 2) + i47) + iArr23[i49];
                System.out.printf("0x%x ^= ((0x%x * 2) + 0x%x) + iArr23[0x%x](0x%x); ==> 0x%x ===7\n",rev,i48,i47,i49,iArr23[i49],i19);
                j4 = 8940878725577409718L;
                i49++;
            }
            if (j4 == 6833218581303746055L) {
                return false;
            }
            if (j4 == 2637559127033415801L) {
                bArr11[i34] = bArr11[i56];
                j4 = 7627928995385457046L;
            }
            if (j4 == 4261074493174756469L) {
                j4 = i34 < 256 ? 3408743489810642039L : 8375352851180859940L;
            }
            if (j4 == 8969184396941120013L) {
                j4 = 7541922949363534567L;
                i38 = i23 / 8;
            } else {
                i38 = i116;
            }
            if (j4 == 1917218271936056345L) {
                j4 = 4803956414827796846L;
                i50 = i34;
                i58 = i50;
                i61 = i58;
                i63 = i61;
            }
            if (j4 == 3958656691010217951L) {
                i57--;
                j4 = 8093763168178308163L;
            }
            if (j4 == 8966069347392902833L) {
                j4 = 1697106464609179154L;
                b2 = bArr11[i54];
            }
            if (j4 == 5288938734069839879L) {
                j4 = 3194583820407555776L;
                i54 = 0;
            }
            if (j4 == 6044249269185916930L) {
                j4 = 5249992174669506009L;
            }
            if (j4 == 1206168581136677569L) {
                final_cip[15] = 50;
                j4 = 4915474783797972804L;
            }
            if (j4 == 1225816651125339139L) {
                final_cip[15] = 115;
                j4 = 6949424180928127742L;
            }
            if (j4 == 7228169035332109883L) {
                bArr11 = new byte[256];
                j4 = 2188405883759779224L;
            }
            if (j4 == 9201993842457705897L) {
                i34++;
                j4 = 7273042193299891196L;
            }
            if (j4 == 7492257630851803835L) {
                j4 = 8650561979795023195L;
            }
            if (j4 == 7107095938156443067L) {
                final_cip = new byte[16];
                j4 = 3906426331893585755L;
            }
            if (j4 == 2619183670644040407L) {
                int rev = i28;
                i28 ^= iArr23[0];

                System.out.printf("0x%x ^= iArr23[0](0x%x);  ==> 0x%x \n",rev, iArr23[0],i28);
                j4 = 8450049976084005921L;
            }
            i59 = i28;
            if (j4 == 2510646431895229276L) {
                final_cip[7] = -102;
                j4 = 5437327595751534596L;
            }
            if (j4 == 2999075064852109317L) {
                j4 = 1210447254521047538L;
                i34 = 0;
            }
            if (j4 == 8619643661940722843L) {
                j4 = 2559141778370937007L;
                i34 = 0;
            }
            if (j4 == 8401256578222293697L) {
                final_cip[2] = Byte.MIN_VALUE;
                j4 = 1899084405611363136L;
            }
            if (j4 == 3480570335270326812L) {
                i34++;
                j4 = 8373337668999560823L;
            }
            if (j4 == 7341970985672155477L) {
                final_cip[9] = -77;
                j4 = 7101323025934545574L;
            }
            if (j4 == 6604647837791727209L) {
                final_cip[4] = 119;
                j2 = 5029569272935880611L;
            } else {
                j2 = j4;
            }
            if (j2 == 5613764015967390693L) {
                bArr5[i34] = (byte) i34;
                j2 = 8689932493166301704L;
            }
            i45 = i32;
            iArr22 = iArr15;
            i35 = i34;
            i36 = i30;
            i44 = i29;
            bArr9 = bArr3;
            i46 = i33;
            iArr19 = iArr18;
            int i117 = i113;
            i37 = i23;
            bArr8 = bArr5;
            j3 = j2;
            i43 = i117;
            i42 = i19;
            bArr10 = bArr7;
        }
        return false;
    }
}
```