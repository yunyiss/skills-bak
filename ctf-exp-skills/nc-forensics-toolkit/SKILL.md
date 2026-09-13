---
name: nc-forensics-toolkit
description: 通过 nc 式裸 TCP 终端做 CTF 取证/远程命令自动化的完整工具链：单命令执行器、会话级重试、base64 文件回传、纯 Python pcap（SLL2）切流与解密分析。触发词：nc 容器取证、远程终端自动化、pcap 切流、TCP stream carve、dpkg -V 反取证、CTF forensics。
agent_created: true
---

# nc-forensics-toolkit

针对"连接 nc 容器（被入侵服务器克隆盘）做取证"类 CTF 的完整工作流与脚本。所有脚本位于 `scripts/`，使用前改文件头的 `HOST`/`PORT`。

## 工作流

1. **连通性**：`python onecmd.py "<cmd>"` —— 每次新开连接执行单条命令（prompt 正则 `user@prod-01:...$`，按实际目标改）。
2. **稳定会话（推荐）**：`python rsess.py "<cmd>"` —— 会话级重试 + 标记提取，比 onecmd 可靠。原理见下"终端自动化要点"。
3. **pcap 概览**：`pca.py <f.pcap>` 打印每文件 top 会话（支持 Ethernet 与 **SLL2/linktype 276**）。
4. **按攻击者 IP 聚合全部会话**：`convscan.py`（遍历 /var/log/pcap/*.pcap，按 4 元组汇总包数/字节数/时间窗，输出 /tmp/conv.txt）。先跑这个确定哪些流值得切。
5. **切流**：`carveall.py`（正确剥离 TCP 头 options；对每条流保存 raw + XOR 0x55/0x99/0xCC 三个版本并搜 `\x7fELF`/shebang）；`bigprobe.py` 单流深度探针；`sessdump.py` 小会话 HTTP 响应全文 dump。
6. **文件回传**：远端 `split -b 70000` + 逐块 `base64 -w0`，本地解码拼接 + md5 校验（参考 getfile.py 的 run_cmd 结构，或直接用 rsess 循环）。
7. **主机侧反取证检查**：`dpkg -V`（找"包仍安装但文件被删"）；`/var/log/apt/history.log`、`/var/log/dpkg.log` 时间线；`/etc/init.d/`、`/etc/systemd/system/`、`/usr/local/bin/` 异常文件；cron；`~/.bashrc` 别名后门。
8. **初始入侵向量定位**：`attconv.py`（按攻击者 IP 聚合 4 元组 + 时间窗 + 前 200B 样本）→ 找"恶意下载/回连发生**同一秒**的那个入站会话"就是入口；`rcedump.py` 按 (sport,dport) 白名单做 seq 排序重组（处理 GAP/retransmit），可打印流到 /tmp 文本。

## 终端自动化要点（踩坑实录）

- **`alias ls="echo -n #"`** 类反取证别名：alias 展开后 `#` 处于词首 → 注释掉**整行剩余命令**。永远用 `/bin/ls`。
- **bracketed paste**（`\x1b[?2004h`）：等该转义出现再发命令；执行输出从最后一个 `\x1b[?2004l` 之后开始。
- **标记防回显自匹配**：命令回显里不能含标记字面量。用变量拼接：
  `A=SH;B=START;echo $A$B; <cmd>; echo $A"END"`，然后从 `\x1b[?2004l` 之后找 `SHSTART`/`SHEND`。
- **stderr 不回显**：命令报错看不到，用 `echo RC=$?` 或 `2>&1` 显式带出。
- **容器随时会重启**：/tmp 物证会被清空，脚本先 b64 上传（`echo <b64> | base64 -d > /tmp/x.py`，b64 无引号可安全内嵌）；重连后按 workflow 第 4 步重建。
- 长任务用 `setsid bash -c '...' &` + done 标志文件（`touch /tmp/xx.done`）轮询。

## 解密经验

- 常见两层：传输层单字节 XOR（如 0x55）+ 载荷层 XOR（如 0x99，从 stager 反汇编 `xor byte ptr [rax], 0x99` 直接读出）。先 XOR 再搜 `\x7fELF`。
- **先验证明文压缩再上加密脑洞**：大流量上传开头若为 `1f 8b 08`（gzip）→ `gunzip -c`；`H4sIA...` 的 base64 也是 gzip。很多"高熵外传流"只是压缩。
- Go RAT 特征识别：`strings` 找 `EncryptSalt`、`json:"salt"`、garble 乱码符号、`{{.DisplayName}}` openrc/systemd 模板、memfd+fexecve、进程伪装名。
- **VShell RAT 内嵌配置解密**（scanconfig2.py）：配置是 **AES-CBC-PKCS7**，16 字节密钥**紧邻密文前**，布局尝试 IV=0 / IV=key / key+IV 相邻；全文件逐字节滑动，验证 = 解 256~2048B 后 PKCS7 合法且含 `"salt"`/`"server"`/`"vkey"` 子串。配置 JSON 形如 `{"server":"IP:port","type":"tcp","vkey":"...","salt":"...",...}`。⚠️ salt 不一定以明文出现在任何文件里——dropper 里的随机文件名参数常被误认为 salt。
- **VShell 流量帧解密与 salt 终验**（verifysalt.py）：帧 = `[4B LE len][12B nonce][GCM ct][16B tag]`，**AES-256-GCM key = `md5(salt).hexdigest()` 的 ASCII 字节**（32 字符 hex 当 key）。解出 salt 后必须用真实帧做 `decrypt_and_verify` 标签验证才算铁证；明文可见版本握手（如 `4.9.3`）、`conf`/`sucs`/`main` 控制帧。
- **Next.js Flight/Server Actions RCE 提取**：入口特征 = `POST /login`（或任意路由）+ `Next-Action` 头 + multipart 表单（name="0" UTF-16LE JSON，React Server Components `"$B1337"` 前缀技术，`process.mainModule.require('child_process').execSync`）。命令藏在该 part 的 **UTF-16LE** 文本里，JSON value 内还有一层 base64（`echo <b64> | base64 -d | sh`）——要解两层。
- **"第一个恶意文件名"陷阱**：`wget URL -O <name>` 的 `-O` 会同时覆盖 URL 基名和服务器 `Content-Disposition: filename=`，两者都是烟雾弹；必须找到**实际执行的下载命令**（RCE payload / history / 日志）确认落盘名。恶意样本常伪装成无害名（如 `.ssh`）且执行后自删除。
- bcrypt 验证：`pip install bcrypt` 后 `bcrypt.checkpw(候选密码, hash)`——README/初始化脚本里的演示密码常与库中 hash 一致。

## 环境

- Windows 无 nc：用 Python socket 客户端（scripts 内置）；或 `"C:/Program Files (x86)/Nmap/ncat"`。
- venv：`C:/Users/wbai/.workbuddy/binaries/python/envs/default/Scripts/python.exe`，已装 pycryptodome、bcrypt、capstone。
