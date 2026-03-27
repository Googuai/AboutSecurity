---
name: ctf-flag-hunting
description: "CTF 挑战中的 Flag 搜索策略。当已获取命令执行/文件读取/数据库访问权限但不知道 flag 在哪里时使用。覆盖文件系统、数据库、环境变量、源码、内存等所有 flag 可能的存储位置。按成功率排序的搜索优先级"
metadata:
  tags: "ctf,flag,搜索,hunting,文件系统,数据库,环境变量,rce,getflag"
  category: "ctf"
---

# CTF Flag 搜索策略

## ⛔ 深入参考（必读）

- ⛔**必读** 需要各权限场景（RCE/LFI/SQLi/管理后台）的完整搜索路径和命令 → `read_skill(id="ctf-flag-hunting", path="references/flag-search-paths.md")`

---

## 按权限类型选择搜索策略

```
你有什么权限？
├─ 命令执行（RCE）→ 文件路径 > find搜索 > 环境变量 > 数据库
├─ 文件读取（LFI）→ /flag.txt > config > /proc/self/environ > LFI转RCE
├─ 数据库访问（SQLi）→ SHOW TABLES > flag/secret表 > LOAD_FILE
└─ Web 管理后台 → 翻页面 > 系统信息 > 用户notes > 文件管理
详细搜索路径 → `read_skill(id="ctf-flag-hunting", path="references/flag-search-paths.md")`
```

## RCE 快速搜索（最常用）

```bash
# 1. 常见路径（先试这些）
cat /flag && cat /flag.txt && cat /root/flag.txt

# 2. 文件系统搜索
find / -name "flag*" 2>/dev/null

# 3. 环境变量
env | grep -i flag

# 4. 数据库配置 → 连接查询
cat /var/www/html/config.php && cat /var/www/html/.env
```

## Flag 格式识别

- `FLAG{hex_string}` — 最常见
- `flag{string}`, `CTF{string}`
- 纯字符串（题目会说明）

## 注意事项
- **假 flag 陷阱**：`FLAG{test}`, `FLAG{this_is_not_the_flag}` 是迷惑项
- **Flag 位置暗示**：题目描述有时暗示 flag 在哪
- **拿到 flag 后立即验证**：参考 `ctf-flag-verification` 技能

## 进程信息
- `/proc/self/cmdline` 可能包含启动命令和参数中传递的 flag
