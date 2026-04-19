# AboutSecurity

渗透测试知识库，以 AI Agent 可执行的格式沉淀安全方法论。

## 核心模块

**Skills/** — 170+ 个技能方法论，覆盖侦察到后渗透全链路

- `cloud/` — 云环境（Docker逃逸、K8s攻击链、AWS IAM、阿里云、腾讯云、Serverless）
- `ctf/` — CTF竞赛（Web解题、逆向、PWN、密码学、取证、AI/ML）
- `dfir/` — 取证对抗（内存取证与反取证、磁盘取证与反取证、日志逃逸）🆕
- `evasion/` — 免杀对抗（C2框架、Shellcode生成、安全研究）
- `exploit/` — 漏洞利用（73 skills，按子分类组织）
  - `web-method/` — Web 通用方法论（注入、XSS、SSRF、SSTI、文件上传、反序列化、WAF绕过…）
  - `product-vuln/` — 特定产品漏洞（Nacos、Jenkins、Grafana、GitLab、中间件…）
  - `advanced/` — 高级利用（HTTP走私、竞态条件、供应链攻击、OT/ICS、加密攻击）
  - `auth/` — 认证授权（JWT、OAuth/SSO、IDOR、CORS、CSRF、Cookie分析）
- `general/` — 综合（报告生成、供应链审计、移动后端API）
- `lateral/` — 横向移动（AD域攻击、NTLM中继、数据库横向、Kerberoasting、ACL滥用）
- `malware/` — 恶意软件（样本分析方法论、C2 Beacon配置提取、沙箱逃逸实现）🆕
- `postexploit/` — 后渗透（Linux/Windows提权、持久化、凭据窃取）
- `recon/` — 侦察（子域名枚举、被动信息收集、JS API提取）
- `threat-intel/` — 威胁情报（IOC对抗、APT模拟、威胁猎杀规避）🆕
- `tool/` — 工具使用（fscan、nuclei、sqlmap、msfconsole、ffuf、hashcat）

**Dict/** — 字典库

- `Auth/` — 用户名/密码
- `Network/` — IP段排除、DNS服务器
- `Port/` — 按端口分类的爆破字典
- `Web/` — Web目录、API参数、fuzz字典

**Payload/** — 攻击载荷

- `SQL-Inj/`、`XSS/`、`SSRF/`、`XXE/`、`LFI/`、`RCE/`、`upload/`、`CORS/`、`HPP/`、`Format/`、`SSI/`、`email/`

**Tools/** — 外部工具声明式配置（程序化编排框架使用）

- `scan/`、`fuzz/`、`osint/`、`poc/`、`brute/`、`postexploit/`
- 详见 [Tools/README.md](./Tools/README.md)

> **Tools/ vs skills/tool/ 的区别**：`Tools/` 下的 YAML 是面向**程序化工具编排框架**的结构化接口定义（参数类型、命令模板、输出解析器），适合自动化引擎调用；`skills/tool/` 下的 SKILL.md 是面向 **LLM Agent** 的自然语言方法论（何时用、怎么选参数、结果怎么判断）。如果你只使用 Claude Code 等 LLM Agent，关注 `skills/tool/` 即可。

## 项目 skills 介绍

[skills/README.md](./skills/README.md) 详细介绍了项目的 skills 分类架构、格式规范、Benchmark 测试流程。

### sync-skills.sh 脚本

```bash
# 软链接模式（本地开发）
./sync-skills.sh

# 复制模式（远程部署）
./sync-skills.sh --copy

# 指定额外 skill 源（私有仓库）
./sync-skills.sh --extra-source /path/to/private-skills
```

脚本逻辑：
1. `find` 所有包含 `SKILL.md` 的目录
2. 按目录名（skill-name）去重，先到先得（主源优先）
3. 排除配置的分类（如 `ai-security|evasion`）
4. 创建软链接或复制到 `.claude/skills/<skill-name>/`

## 贡献

提交前阅读 [CONTRIBUTING.md](./CONTRIBUTING.md)，包括 Skill 格式规范、references 编写要求、benchmark 测试流程。

## 参考

- https://github.com/anthropics/skills/blob/main/skills/skill-creator/SKILL.md
- https://github.com/ljagiello/ctf-skills
- https://github.com/JDArmy/Evasion-SubAgents
- https://github.com/teamssix/twiki
- https://github.com/yaklang/hack-skills
- https://github.com/mukul975/Anthropic-Cybersecurity-Skills
- https://github.com/Pa55w0rd/secknowledge-skill
