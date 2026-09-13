---
name: qiling-run-linux-elf-windows
description: 在 Windows 上用 Qiling + ubuntu-base rootfs 运行 Linux x86-64 ELF（无 WSL 环境），含路径映射与常见坑的完整工作流。
agent_created: true
version: 1.1.0
---

# 用 Qiling 在 Windows 上运行 Linux ELF

适用场景：拿到一个 Linux x86-64 ELF（CTF 逆向题的 replay/模拟器程序、恶意样本、
或任何需要在 Windows 上沙箱运行的 Linux 程序），本机是 Windows、
WSL 被禁用、无 Docker，但 Python 环境里装有 `qiling` + `unicorn`。
下文以 `<binary>` 指代目标程序名。

## 步骤

### 1. 准备 rootfs（Ubuntu base，~30MB）

```bash
curl -sL -o ubuntu-base.tar.gz https://cdimage.ubuntu.com/ubuntu-base/releases/22.04/release/ubuntu-base-22.04.5-base-amd64.tar.gz
mkdir rootfs && tar -xzf ubuntu-base.tar.gz -C rootfs   # Git Bash 下 symlink 条目报错可忽略
```

补齐动态链接所需（tar 解不开的 symlink 要手工补）：

```bash
L=rootfs/usr/lib/x86_64-linux-gnu
mkdir -p rootfs/lib64 rootfs/lib/x86_64-linux-gnu
cp $L/ld-linux-x86-64.so.2 rootfs/lib64/     # ELF interp 是 /lib64/ld-linux-x86-64.so.2
for f in libc.so.6 libdl.so.2 libm.so.6 libpthread.so.0 libresolv.so.2 librt.so.1; do cp $L/$f rootfs/lib/x86_64-linux-gnu/; done
# dlopen 的库（如 libcrypto.so.3）也一并 cp 到 rootfs/lib/x86_64-linux-gnu/
```

### 2. 放置程序与数据文件

把 ELF 和它要读的数据文件放进 `rootfs/` 下的某个目录，如 `rootfs/root/`。
**重要**：程序若用 `dirname(argv[0]) + "/" + name` 拼路径，guest 内必须是
绝对 POSIX 路径（如 `/root/<binary>`），否则 Qiling 的相对路径 openat 会返回 EPERM。

### 3. 运行脚本（含两个必需的 workaround）

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

BIN = "/root/<binary>"          # guest 视角绝对路径（按实际程序名/位置改）
MAIN = 0x401236                 # ELF 的 main 地址（用 objdump/IDA 查）

def on_main(ql):
    """把 guest 栈上的 argv[0] 改写为 guest 绝对路径"""
    argv, sp = ql.arch.regs.read("rsi"), ql.arch.regs.read("rsp")
    addr = sp - 0x200
    ql.mem.write(addr, BIN.encode() + b"\x00")
    ql.mem.write(argv, addr.to_bytes(8, "little"))

ql = Qiling([f"rootfs{BIN}", "<arg>"],              # argv[0] 必须是 host 真实存在路径
            rootfs=r"C:\path\to\rootfs", verbose=QL_VERBOSE.OFF)
ql.hook_address(on_main, MAIN)                      # main 入口 hook
ql.os.set_syscall("futex", lambda ql, *a: 0)        # OpenSSL/glibc 初始化 futex 桩
ql.run()
```

> x86-64 下 `main` 的 argv 位于 `rsi`（argc 在 `rdi`）；如目标架构不同需相应调整寄存器。

## 踩坑记录

- `Qiling(argv, rootfs, verbose=QL_VERBOSE.X)`：**不收** `stdout/stderr` 关键字；
  `verbose` 必须传 `QL_VERBOSE` 枚举（1.4.6），传 int 会 KeyError。
- argv[0] 必须通过宿主 `os.path.isfile` 检查（用 host 相对/绝对路径），
  但 guest 内拿到的 argv[0] 就是原字符串 → 必须在 main 入口 hook 改写。
- guest 内相对路径 openat 会失败（EPERM），一律用 `/` 开头的 guest 绝对路径。
- OpenSSL 常触发 futex；单线程模式下 Qiling 的 futex 处理会抛
  `NoneType.cur_thread`，用 `ql.os.set_syscall("futex", stub)` 返回 0 即可。
- 加 hook 断点定位：`ql.hook_address(cb, addr)` 打印 milestone + rax，比盲读
  反汇编快得多；错误分支汇聚点（如统一报错函数）可从 `[rsp]` 读返回地址定位调用方。
- rootfs 可以被 Qiling 映射到的最简结构：`lib64/ld-linux` + `lib/x86_64-linux-gnu/`
  下所需 .so，无需完整发行版目录树。
