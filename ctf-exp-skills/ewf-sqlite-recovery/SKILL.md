---
name: ewf-sqlite-recovery
description: 从 E01/EWF 取证镜像中恢复被删除的 SQLite 数据（Windows 无 libewf 环境）。触发词：E01、取证镜像、EnCase、audit.db 恢复、SQLite 删除记录恢复、WAL 重放、数据雕刻。
user_invocable: true
agent_created: true
---

# EWF(E01) 取证镜像 + SQLite 删除数据恢复（Windows 纯 Python 方案）

适用于：Windows 环境、无 ewfmount/libewf、pytsk3 wheel 不支持 E01 的场景。
完整流程案例见参考：CTF "committed"（审计 DB 恢复）。

## 流程总览

1. **环境准备**：`pip install pytsk3`（wheel 可装但不带 libewf，E01 会被当 raw 读）。
2. **纯 Python EWF 读取器**：用 `scripts/ewf_reader.py`（含 `EWFReader` + `TSKImg` 桥接 pytsk3），可寻址读取，无需落地 raw。
3. **文件系统勘察**：ext4/NTFS 遍历 → 找目标 SQLite 文件；检查 `$OrphanFiles`、freelist、freeblock。
4. **全盘雕刻**：对全镜像扫描 `SQLite format 3\x00` 和 WAL 魔数 `377f0682 / 377f0683`（`scripts/scan_wal.py`），未分配空间常有旧版 DB 快照和 WAL 副本。
5. **WAL 重放**：解析 WAL 帧（24B 帧头 + 页数据），**dbsize≠0 的帧是 commit 帧**；"最后成功提交的状态" = 底版 DB + 最多到最后一个 commit 帧的帧重放。commit 之后的帧属于中断事务，必须丢弃。
6. **校验**：`scripts/verify_wal.py` 按 SQLite WAL 规范逐帧验证累计校验和（magic 低位=0 → 小端字序）。
7. **对比分析**：对"已提交态"和"全帧重放态"分别 `pragma integrity_check` + 手工 b-tree 遍历（参考 CTF 解题记录）找被删记录。

## EWF/E01 格式要点（实测易错）

- 文件头 13 字节后是 76B section 描述符链：`16B名 + 8B next + 8B size + 40B pad + 4B CRC32(前72字节 adler32)`。
- `volume` 段：`@4=chunk数, @8=每chunk扇区数, @12=扇区大小, @16=总扇区数(u32)`。
  **@16 是扇区数不是字节数**！media_size = total_sectors × sector_size。
- `table` 段：`@0 u64=条目数, @8 u64=base_offset(相对段起始)`, **条目从 @24 开始**（不是 @16）；条目 u32：bit31=压缩标志，低 31 位为相对 base 的偏移。
- `sectors` 段每个 chunk（扇区数×512 字节）后跟 **4 字节 CRC32**，相邻条目间隔是 chunk_size+4。
- 压缩 chunk 用 `zlib.decompressobj().decompress(blob, chunk_size)`；最后一块按 media_size 截断。
- 多分段（E01/E02/E03）按 section 链各自独立解析后顺序拼接 chunk。

## pytsk3 注意事项（当前版本 20260715）

- 自定义镜像：`class Img(pytsk3.Img_Info)` 重写 `get_size()` / `read(offset, size)`，构造 `pytsk3.Img_Info(url='', type=pytsk3.TSK_IMG_TYPE_EXTERNAL)`。
- `File` 对象**没有 `read()`/`read_buffer()`**，只有 `read_random(offset, size)`。
- 目录枚举：`fs.open_dir(inode=N)`；若失败可用 `fs.open_meta(N).as_directory()`。
- 无分区表时直接 `FS_Info(img, 0)`；ftype 8192=ext4。

## SQLite WAL 恢复要点

- WAL 头 32B：`magic(4) version(4) pagesize(4) ckpt(4) salt1(4) salt2(4) cksum1(4) cksum2(4)`。
- 帧头 24B：`pgno dbsize salt1 salt2 cksum1 cksum2`（大端）；**dbsize≠0 → commit 帧**。
- 帧有效性 = salt 与 WAL 头一致 + 累计校验和通过（校验覆盖帧头前 8 字节 + 页数据；字序由 magic 决定：0x377f0682=小端，0x377f0683=大端）。
- 帧内偏移：WAL 文件中页数据在 `帧起始+24`；若在磁盘 4K 页内看到 "SQLite format 3" 位于 `+0x38`，多半是 WAL 首帧的 page1（WAL 头在 -32，帧头在 -24）。
- 重放：按页号覆盖，commit 帧后按 dbsize 截断；**未提交帧重放出的库 integrity_check 必然异常，且正是"被删除/未落盘数据"的观察窗口**（用手工 b-tree 遍历对比差异）。
