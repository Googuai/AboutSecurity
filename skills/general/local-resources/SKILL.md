---
name: local-resources
description: 字典库(Dic)、Payload库、POC库的结构和使用方法。使用 ffuf/dirsearch/hydra 等外部工具前必读。
metadata:
  category: general
  tags: [dictionary, wordlist, payload, poc, ffuf, dirsearch, hydra, resource]
  difficulty: basic
---

# 本地资源库导航

⚠️ **核心规则：禁止猜测路径** — 所有字典/payload 文件通过工具获取路径，不要硬编码 `/usr/share/wordlists/` 等系统路径。

## 📁 字典库 (Dic/) — 目录爆破 / 密码爆破 / 参数 Fuzz

### 工具链
```
dict_list()                         → 查看所有分类
dict_list(category="Web")           → 查看 Web 字典子分类
dict_resolve(path="Web/Directory/Fuzz_common.txt")  → 获取绝对路径给 ffuf -w
```

### 常用字典速查表

| 场景 | dict_resolve 路径 | 行数 |
|------|-------------------|------|
| 通用目录爆破 | `Web/Directory/Fuzz_common.txt` | ~5k |
| PHP 文件发现 | `Web/Directory/php/Fuzz_php.txt` | ~48k |
| PHP Top100 | `Web/Directory/php/Top100_php.txt` | ~100 |
| CTF URI Fuzz | `Web/CTF/Fuzz_uri.txt` | ~220 |
| CTF 参数 Fuzz | `Web/CTF/Fuzz_param.txt` | ~44 |
| CTF SQL Fuzz | `Web/CTF/Fuzz_sql.txt` | ~94 |
| 后台路径 | `Web/Directory/Fuzz_admin_dir.txt` | — |
| API 路径 | `Web/Directory/Fuzz_api.txt` | — |
| 备份文件 | `Web/File_Backup/` | — |
| 密码 Top100 | `Auth/password/top100.txt` | — |
| DNS 子域名 | `Web/dns/` | — |

### 决策树：该用哪个字典？

```
目标是 Web 应用？
├── CTF/靶场 → Web/CTF/Fuzz_uri.txt（小而精）
├── PHP 站 → Web/Directory/php/Fuzz_php.txt（全面）
├── 通用站 → Web/Directory/Fuzz_common.txt
├── 找后台 → Web/Directory/Fuzz_admin_dir.txt
├── 找 API → Web/Directory/Fuzz_api.txt
└── 找备份 → Web/File_Backup/

目标是认证服务？
├── 密码爆破 → Auth/password/top100.txt
├── 用户名枚举 → Auth/username/
└── 特定服务 → Port/{mysql,ssh,rdp,...}/
```

## 📁 Payload 库 — 漏洞验证 payload

### 工具链
```
payload_list()                            → 查看所有分类
payload_get(category="SQL-Inj", filename="xxx.txt")  → 获取 payload 内容
```

### 可用分类
SQL-Inj | XSS | LFI | SSRF | XXE | RCE | 403 绕过 | upload | CORS | HPP | SSI

## ⚠️ 使用外部工具的正确流程

```
❌ 错误：shell_execute("ffuf -u http://target/FUZZ -w /usr/share/wordlists/common.txt")
                                                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                        猜测路径，大概率不存在

✅ 正确：
1. dict_resolve(path="Web/Directory/Fuzz_common.txt")  → 获取绝对路径
2. shell_execute("ffuf -u http://target/FUZZ -w /实际/绝对/路径/Fuzz_common.txt")
```

## 💡 高效使用提示

1. **brute_dir 内置工具已封装字典** — 如果只是简单目录爆破，直接用 brute_dir(target, dictType="php")
2. **dict_resolve 用于 ffuf/dirsearch** — 需要自定义参数（如 -e .bak -mc 200）时用 dict_resolve + shell_execute
3. **CTF 场景优先用小字典** — Web/CTF/ 下的字典精简且针对性强，避免大字典浪费时间
