概述
==

我们知道目前用到比较多的Fuzz工具为AFL以及其衍生产品，比如`winafl`等。这类工具一般针对小程序，如果需要测试一些大型软件则需要做额外的适配工作，往往需要分析目标处理数据的函数，然后构造目标函数的参数，把Fuzz生成的数据传给软件去处理，这个过程复杂度与程序相关。

如果不想适配则需要对可执行程序完全插桩，比如qemu, dynamorio等，这样会对程序的性能有比较大的损耗，而且也有一定的平台限制。

`trapfuzzer` 是一款基于断点来获取程序覆盖率的fuzz工具。其优点在于对程序性能影响相对较小，可以单模块插桩，对平台的要求比较低（能支持软件断点即可）。缺点也很明显对覆盖率的记录相对AFL而言粒度较粗。

**代码地址**

```php
https://github.com/hac425xxx/trapfuzzer/
```

基本原理
====

为了尽可能减少Fuzz中的开销，目前采取的方案是首先使用 IDA 把目标模块的所有基本块的第一条指令替换为断点指令并把原始指令的位置、大小和内容保存到文件中。在Fuzz时只要命中断点指令则表示程序执行到了一个新的基本块，然后我们需要记录下执行到的基本块并将原始的指令恢复回去，以便让程序继续往下运行。通过这种方式可以获取到程序执行过程中的覆盖率。

这里又会涉及到一个选择，命中断点后是否需要把原始文件中的内容也恢复，如果恢复的话好处就是可以大幅提升Fuzz测试的速度，因为这样在整个Fuzz中每个断点指令只会命中一次，缺点就是只能记录每次测试新发现的基本块。在`trapfuzzer` 里面提供了相应的选项可以配置。

tracer模块
========

tracer模块用于获取进程执行过程中的覆盖率。

设置断点
----

首先使用IDA打开需要统计覆盖率的模块，然后使用 ida 脚本将模块中的所有基本块导出到文件中

```php
from idautils import *
from idaapi import *
import os
from struct import pack, unpack

filename = idaapi.get_root_filename().lower()
base = idaapi.get_imagebase()
allBlocks = {}
BBcount = 0
Fcount = 0
break_instr_size = 1  # size of break instr

file = open("bb.txt", 'wb')

data = pack("<I", len(filename)+1)
data += filename
data += "\x00"
file.write(data)
for segment_ea in Segments():
    segment = idaapi.getseg(segment_ea)
    if segment.perm & idaapi.SEGPERM_EXEC == 0:
        continue

    for location in Functions(SegStart(segment.startEA), SegEnd(segment.startEA)):
        Fcount += 1
        blocks = idaapi.FlowChart(idaapi.get_func(location))
        for block in blocks:
            BBcount += 1
            if block.startEA not in allBlocks:
                if GetMnem(block.startEA) == "":
                    print "Skipping %08X because this is not code" % (block.startEA)
                    print "    " + GetDisasm(block.startEA)
                    break

                voff = block.startEA - base
                foff = idaapi.get_fileregion_offset(block.startEA)
                instr = idaapi.get_bytes(block.startEA, break_instr_size)

                data = pack("<III", voff, foff, break_instr_size)
                data += instr
                file.write(data)
                allBlocks[block.startEA] = True
file.close()
print "Discovered %d basic blocks in %d functions" % (BBcount, Fcount)
```

导出文件的格式如下

```php
|4字节的模块名长度|模块名|4字节 基本块首地址相对模块基地址的偏移|4字节 基本块在文件中的偏移||4字节 保存指令的长度|保存的指令内容|.......
```

然后使用 setbp.py 把文件中的每个基本块开始的指令替换为断点指令.

```php
import os
import shutil
import getopt
import sys
from struct import pack, unpack

target = "./vuln"
bb_file = "./bb.txt"
print "Modifying %s based of BB-s in %s" % (target, bb_file)
shutil.copyfile(target, target + "_original")
f = open(bb_file, "rb")
fa = open(target, "r+b")

fname_sz = unpack("<I", f.read(4))[0]
fname = f.read(fname_sz)

print "fname: {}".format(fname)

while True:
    data = f.read(12)
    if len(data) < 12:
        break

    voff, foff, instr_sz = unpack("<III", data)
    instr = f.read(instr_sz)
    fa.seek(foff)
    fa.write("\xcc" * instr_sz)

f.close()
fa.close()
print "DONE"
```

脚本的流程很简单，就是读取之前从IDA里面导出的基本块信息，然后将基本块的第一条指令替换为断点指令(x86下为 `\xcc`)

代码覆盖率
-----

本节介绍两种使用上一步处理过的二进制来获取模块覆盖率的方式。主要思路都一样，就是当进程执行时执行到新基本块时会产生断点事件（每个基本块的第一条指令已经被替换为了断点指令），然后由我们的工具处理断点事件，将断点指令替换为原始指令，然后让进程继续往下执行，这样我们就可以获取到进程的覆盖率了。

下面分别介绍使用 `python-ptrace` 和 `gdb`的 `python`插件实现的方案

### python-ptrace

这个库封装了一些 ptrace的接口，使得我们可以在python中直接调用 ptrace 接口。下面分析具体实现

主要逻辑位于 trace 函数

```php
    def trace(self):
        module_name = self.coverage_module_name
        info = self.bbinfo[module_name]
        process = self.create_and_attach_process(self.target_args)
        bb_trace = []
        while True:
            process.cont()
            try:
                signal = process.waitSignals()
            except ProcessExit:
                break

            if signal.signum == SIGTRAP:
                ip = process.getInstrPointer()
                trap_addr = ip - 1

                offset = trap_addr - info['image_base']
                obyte = info[offset]['origin_byte']

                if offset in exit_basci_block:
                    process.terminate()
                    break

                process.writeBytes(trap_addr, obyte)
                process.setInstrPointer(trap_addr)
                bb_trace.append(offset)
```

代码逻辑如下

1. 首先使用 create\_and\_attach\_process 创建目标进程
2. 然后进入循环，使用process.cont()让进程继续执行，并使用 process.waitSignals() 等待进程触发信号，比如SIGABORT, SIGTRAP.
3. 如果进程触发了SIGTRAP信号，则去判断是否是执行到了新的基本块，如果是则记录此时的地址，然后将断点指令替换为该位置的原始指令，然后让进程继续往下执行。

### gdb的python插件

主要代码位于 gdbtracer.py，主要函数还是 trace

```php
    def trace(self, need_patch_to_file=False, verbose=False, exit_basci_block=[], timeout=2.0):

        try_count = 0
        while try_count < 3:
            if self.exec_with_gdb(timeout):
                break

        data = ""
        status = ""
        with open("{}/gdb.trace".format(self.workspace), "r") as fp:
            status = fp.readline().strip()
            data = fp.read()
```

直接进入 exec\_with\_gdb 函数

```php
def exec_with_gdb(self, timeout=30):
    command = "/usr/bin/gdb -q -x {}/cmd.gdb  --args {}".format(self.workspace, self.cmdline)

    self.is_timeout = False
    self.p = subprocess.Popen(command, shell=True, cwd=self.workspace, stdin=subprocess.PIPE,stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    ret = True
    output = ""
    if self.debug:
        log_file = open("debug.log", "w")

    timer = Timer(timeout, self.timeout_handler)
    try:
        timer.start()
        space_count = 0
        while True:
            l = self.p.stdout.readline()
            if "received signal SIGTRAP" in l:
                space_count = 0
                self.p.stdin.write("c\n")
            elif "[trapfuzzer] save_bb_trace" in l:
                break

    finally:
        timer.cancel()
```

代码流程如下

首先使用 subprocess 让gdb来加载执行被测程序。

1. gdb加载时会去执行 cmd.gdb 里面的指令。
2. 然后设置一个定时器，确保在超时时间到达时可以结束进程，避免出现死循环。
3. 然后不断获取进程的输出，如果出现`received signal SIGTRAP` 表示进程命中一个断点，我们需要发送 `c` 命令让进程继续往下执行，而恢复原始指令的处理则在`gdb`插件中进行。
4. 如果输出为 `[trapfuzzer] save_bb_trace` 表示进程结束，此时可以进行其他的处理。

下面再看看 cmd.gdb 的内容

```php
set confirm off
set pagination off
set auto-solib-add off
set disable-randomization on
source trap.py
```

设置了一些gdb的配置，用于提升速度，然后加载 `trap.py` 到gdb.

下面继续分析gdb插件的主要代码

```php
gdb.events.exited.connect(exit_handler)
gdb.events.stop.connect(stop_handler)
gdb.events.new_objfile.connect(new_objfile_handler)
```

插件会注册一些事件用于在进程出现某些行为时进行一定的处理，主要看 `stop_handler`，这个表示进程停止时会执行的回调函数，比如触发断点，收到信号等都会触发该事件。

下面主要看处理断点的部分

```php
def stop_handler(event):
    .....................
    .....................
    elif isinstance(event, gdb.StopEvent):

        pc = get_register("$pc") - 1
        offset = pc - COV_MODULE_INFO['image_base']

        tracer_sock.sendall(struct.pack("<I", offset))
        raw_byte = tracer_sock.recv(1)

        write_memory(pc, raw_byte, 1)
        set_register("pc", pc)

        BB_LIST.append(offset)
    .....................
    .....................
```

首先判断停止的事件是 `StopEvent`，一般表示是进程触发了断点，然后获取此时的地址，然后将地址通过socket发送给 `gdbtracer.py` 里面实现的服务端，用于获取这个位置的真实指令，然后把断点指令替换为真实指令，最后把地址保存起来，用于在进程退出时保存，这样即可获取到模块的覆盖率。

数据变异模块
======

目前实现了三种数据变异模块

RadamsaMutator
--------------

就是调用radamsa命令行工具来生成变异数据

```php
import subprocess

class RadamsaMutator:
    __mutator_name__ = "RadamsaMutator"

    def __init__(self):
        pass

    def mutate(self, input, output):
        command = "./radamsa {} -o {}".format(input, output)
        p = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait()
```

VanapaganMutator
----------------

这个变异器来自

```php
https://github.com/FoxHex0ne/Vanapagan
```

主要由 FileBitFlipping 和 FileByteValues 组成：

- FileBitFlipping ： 对文件中的某些字节进行比特翻转
- FileByteValues ： 用一些特殊字节替换特定的字节。

HonggfuzzMutater
----------------

这个变异器将 honggfuzz中的变异器用 python 重写了。

Fuzz调度模块
========

该模块时整个 fuzzer 的核心模块，控制了整个fuzz的流程，用例的保存和打分，以及用例集精简等功能。

加载测试用例
------

load\_testcase 用于加载指定目录的所有文件为初始测试用例

```php
    def load_testcase(self, dir_path):
        self.exec_stage = "loading-testcase"
        self.total_exec_count = 0
        count = 0
        start = time.time()

        file_list = self.get_filelist_by_filesize(dir_path)

        for full_path in file_list:

            if self.fuzzer_status == "stop":
                self.logger.log("stop from load_testcase\n")
                exit(0)

            shutil.copyfile(full_path, self.input_path_read_by_target)
            self.current_file = full_path
            ret = self.exec_testcase(self.patch_to_binary)
            self.total_exec_count += 1
            if ret.status == ExecStatus.NORMAL:
                if self.has_new_path(ret.trace):
                    self.last_new_path_found = self.logger.get_current_time()
                    self.save_testcase(ret.trace)
                    count += 1
            elif ret.status == ExecStatus.DOS:
                self.last_dos_found = self.logger.get_current_time()
                self.save_dos(ret.trace)
            else:
                self.last_crash_found = self.logger.get_current_time()
                self.save_crash(ret.trace, ret.crash_info)

            delta = time.time() - start
            self.total_exec_time += int(delta)
            self.avg_run_time = round(float(delta) / self.total_exec_count, 1)
            self.exec_speed = round(float(self.total_exec_count) / delta, 1)
```

加载的策略为只保存产生了新路径的用例，加载完成之后会计算每个样本的平均执行时间，用于后续判断DOS.

用例集精简
-----

`minimize` 用于对指定目录中的所有用例进行精简

```php
    def minimize(self, dir_path):
        # first load testcase from dir and generate trace for all file.
        count = 0
        for fname in os.listdir(dir_path):
            full_path = os.path.join(dir_path, fname)
            if os.path.isfile(full_path):

                shutil.copyfile(full_path, self.input_path_read_by_target)
                ret = self.exec_testcase(need_patch_to_file=self.patch_to_binary)

                if ret.status == ExecStatus.NORMAL:
                    self.save_testcase(ret.trace)
                    count += 1
                    self.total_bb_executed = self.total_bb_executed | set(
                        ret.trace)
                elif ret.status == ExecStatus.DOS:
                    self.save_dos(ret.trace)
                else:
                    self.save_crash(ret.trace, ret.crash_info)

        self.logger.log("[trapfuzzer] Before minimize, count: {}".format(count))

        if len(self.total_bb_executed) == 0:
            shutil.rmtree(self.output)
            print("[trapfuzzer] No good testcase found!")
            return

        min_case_list = []
        total_trace_in_min_case_list = set()

        # find the max trace case
        while True:
            max_case = self.find_max_trace_case()
            total_trace_in_min_case_list = total_trace_in_min_case_list | set(
                max_case.get_trace())
            min_case_list.append(max_case)

            self.remove_dup_case(max_case)
            self.testcase_list.remove(max_case)

        print("[trapfuzzer] After minimize, count: {}".format(len(min_case_list)))

        os.mkdir("{}/mini".format(self.output))
        for i in range(len(min_case_list)):
            c = min_case_list[i]
            src = "{}/trapfuzz-testcase-{}.bin".format(self.output, c.idx)
            dst = "{}/mini/trapfuzz-testcase-{}.bin".format(self.output, i)
            shutil.copyfile(src, dst)
            with open("{}/mini/trapfuzz-testcase-{}.trace".format(self.output, i), "wb") as fp:
                d = ""
                for bb in c.get_trace():
                    d += '0x{:X},'.format(bb)
                d = d[:-1]
                d += "\n"
                fp.write(d)
```

主要流程如下

1. 首先获取目标进程处理每个用例的覆盖率，即执行过的基本块。
2. 选择用例中执行基本块个数最多的用例，加入到最终的用例集中同时剔除掉多余的用例，即覆盖率已经被最终用例集包含的用例。
3. 继续第二步，直到没有新用例为止。

Fuzz主流程
-------

主流程位于 fuzz 函数中

```php
    def fuzz(self):
        if not self.resume_fuzzing and self.config.has_key("testcase"):
            if os.path.exists(self.config['testcase']):
                self.load_testcase(self.config['testcase'])
            else:
                self.logger.log("warning {} not exists!".format(self.config['testcase']))

        if len(self.testcase_list) == 0:
            self.logger.log("No testcase found, exit fuzzer!")
            return

        run_time = time.time()
        self.total_exec_count = 1
        self.exec_stage = "fuzz"

        self.cur_mutator = random.choice(self.mutator_list)

        while True:
            for seed in self.testcase_list:
                seed_path = "{}/trapfuzz-testcase-{}.bin".format(
                    self.output, seed.idx)
                for i in range(seed.exec_count):  # per case fuzz count
                    if self.fuzzer_status == "stop":
                        self.server_sock.close()
                        self.tracer.quit()
                        self.logger.log("exit fuzzer")
                        return

                    self.cur_mutator.mutate(seed_path, self.input_path_read_by_target)
                    self.current_file = seed_path
                    ret = self.exec_testcase(self.patch_to_binary)
                    if ret.status == ExecStatus.NORMAL:
                        if self.has_new_path(ret.trace):
                            self.last_new_path_found = self.logger.get_current_time()
                            self.save_testcase(ret.trace)
                            seed.found_path()
                    elif ret.status == ExecStatus.DOS:
                        seed.found_dos()
                        self.last_dos_found = self.logger.get_current_time()
                        self.save_dos(ret.trace)
                        self.logger.log("found a dos, seed index: {}".format(seed.idx))
                        break
                    else:
                        self.last_crash_found = self.logger.get_current_time()
                        self.save_crash(ret.trace, ret.crash_info)
                        self.logger.log("found a crash, seed index: {}".format(seed.idx))
```

函数流程如下

1. 首先判断是否需要恢复之前的执行，如果是则加载之前的测试数据。
2. 然后开始遍历样本队列，让并使用 `tracer` 模块去加载用例，并获取执行过程的覆盖率，以及异常情况。
3. 如果发现新路径则把产生新路径的样本加入到全局样本队列 `self.testcase_list`，否则如果是异常情况则按照不同的情况进行处理，比如 `crash`，dos有相应的处理。

样本打分策略
------

Testcase类表示每个用例，其中包含了一些信息用于对用例进行打分，打分的体现是这个用例在一轮测试中会被使用的测试，初始都是 50 次。

```php
class Testcase:
    def __init__(self, idx, bb_executed):
        self.idx = idx
        self.trace = bb_executed
        self.base_exec_count = 50
        self.exec_count = self.base_exec_count
        self.path_found = 0  # new path found by this case
        self.dos_count = 0

        self.inc_ratio = 0.1
        self.dec_ratio = 0.1

    def get_trace(self):
        return self.trace

    def found_dos(self):
        self.exec_count = int(self.exec_count * self.dec_ratio)
        self.dos_count += 1

    def found_path(self):
        self.path_found += 1
        self.exec_count = int(self.base_exec_count + self.base_exec_count * self.path_found * self.inc_ratio)

    def __str__(self):
        data = "idx: {}, dos found: {}, path found: {}, bb count: {}, exec count: {}".format(
            self.idx, self.dos_count, self.path_found, len(self.trace), self.exec_count)
        return data
```

目前实现的策略很简单，具体策略如下：

1. 如果用例发现DOS，则会将用例执行测试减10%，目的是为例提升测试速度，避免频繁出现DOS。
2. 如果用例发现新路径，则会将用例执行测试加10%.

使用示例
====

下面是一个有漏洞的程序

```php
int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Syntax: %s <input file>\n", argv[0]);
        exit(1);
    }
    int len = 0;
    char *data = read_to_buf(argv[1], &len);
    switch (data[0])
    {
    case 'A':
        handleData0(data, len);
        if (data[1] == 'K')
        {
            handleData5(data + 2, len - 2);
        }
        break;
    case 'B':
        handleData1(data, len);
        break;
    case 'C':
        handleData2(data, len);
        if (data[1] == 'G')
        {
            handleData3(data + 2, len - 2);
        }
        break;
    case 'D':
        handleData3(data, len);
        break;
    case 'E':
        handleData4(data, len);
        break;
    default:
        return;
    }
    return 0;
}
```

程序接收一个命令行参数，然后会读取文件内容进行处理。

1. 首先把编译好的程序使用 IDA 分析，然后使用 dump\_bb.py 把基本块信息导出到 bb.txt 文件。
2. 然后使用 setbp.py 通过 bb.txt 把二进制的每个基本块的第一条指令替换为断点指令。
3. 最后配置 config.json，执行 trap\_fuzzer.py，fuzz就会从config.json读取配置进行测试。

配置文件示例如下

```php
{
    "tracer": "gdb",
    "mutator": "radamsa-mutator",
    "args": ["/home/hac425/code/example/test", "/home/hac425/code/in/1"],
    "basic_block_file_path": ["/home/hac425/code/example/test-bb.txt"],
    "coverage_module_name": ["test"],
    "file_read_by_target": "/home/hac425/code/in/1",
    "manage_port": "8821",
    "exit_basci_block_list": "0xCF3",
    "output": "/home/hac425/code/output/",
    "testcase": "/home/hac425/code/testcase/",
    "patch_to_binary": true,
    "resume_execution": false
}
```

配置项说明

```php
tracer: 指定使用获取覆盖率的方式，可选项：gdb,python-ptrace, gdb-run. gdb-run 下节介绍实现
mutator：指定需要使用的数据变异器，可选项：Vanapagan-mutator, radamsa-mutator, honggfuzz-mutator
args: 被测进程执行的命令，fuzzer会根据这个执行目标进程

basic_block_file_path: IDA生成的基本块文件的路径，一个列表，每一项代表一个模块
coverage_module_name: 收集覆盖率的模块名，一个列表，需要和basic_block_file_path中的对应

file_read_by_target: 目标进程读取文件的全路径，fuzz过程中会将测试数据写到这个文件中
manage_port: 管理端口，fuzz执行过程用户可以nc到这个端口查看测试的信息
exit_basci_block_list: 退出基本块列表，多个的话用,分割，当进程执行到给定的基本块地址时退出进程
output: fuzzer输出目录，用于保存测试过程的信息
testcase: 初始用例读取目录
patch_to_binary: 是否需要在每次测试后把新执行到的基本块的原始指令在二进制文件中恢复，这样每个断点就只会被执行一次，可以提升速度，建议在测试大型软件时开启
resume_execution: 是否需要恢复之前的测试，如果为true，fuzzer会从output加载之前的测试信息。
```

总结
==

目前市面上有很多好用的Fuzz工具，其中最具代表性的就是AFL，不过这个工具的问题是想要测试起来需要花很多的时间去分析程序的数据处理函数，函数的入参，并需要构造入参才能进行测试。而那些开箱即用的工具比如peach等，都是一些黑盒测试工具，在测试过程中没法记录新产生路径的用例，测试效率不是太好，trapfuzzer则是一种权衡，在记录新产生路径的用例的同时不需要用户对目标程序有太多的了解（仅仅需要知道需要插桩的模块），而且对程序的性能损耗也较小。