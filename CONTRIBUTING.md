# AboutSecurity 资源贡献规范

本文档定义了 `Tools/` 和 `Skills/` 目录下 YAML 文件的编写规范，供社区贡献者和 AI 参考。

---

## 目录结构

```
AboutSecurity/
├── Tools/                    # 外部工具声明式配置
│   ├── scan/                 # 资产探测类
│   ├── osint/                # 情报搜索类
│   ├── poc/                  # 漏洞扫描类
│   ├── brute/                # 爆破/Fuzz 类
│   ├── postexploit/          # 后渗透类
│   └── util/                 # 辅助工具类
├── Skills/                   # AI Agent 技能剧本
│   ├── recon/                # 侦察类
│   ├── exploit/              # 漏洞利用类
│   ├── postexploit/          # 后渗透类
│   ├── lateral/              # 内网渗透类
│   ├── cloud/                # 云环境类
│   └── general/              # 综合类
└── manifest.yaml
```

---

# 一、Tools 外部工具编写规范

## 1.1 概述

每个 YAML 文件声明一个外部命令行工具。Kitsune AI Agent 读取这些定义后，可自动调用对应工具并解析输出。

**核心原则**：定义好输入（parameters），Kitsune 才能正确调用；定义好输出（output + findings_mapping），Kitsune 才能正确入库。

## 1.2 文件命名

```
{工具名}.yaml
```

示例：`nmap-scan.yaml`、`subfinder.yaml`、`nuclei-custom.yaml`

## 1.3 完整字段说明

```yaml
# ============================================================
# 基本信息（必填）
# ============================================================
id: ext_工具名                  # 工具唯一标识，必须以 ext_ 开头
name: 工具显示名称               # 中文名，给用户看的
description: "工具功能描述"       # AI 用这段文字决定是否调用此工具，写清楚能做什么
homepage: "https://github.com/xxx/xxx"  # 工具官网或 GitHub 地址，方便用户了解和安装
category: scan                  # 分类，见下方枚举
binary: nmap                    # 可执行文件名（从 PATH 查找）
binary_path: ""                 # 可选：绝对路径，如 /usr/local/bin/nmap
version_cmd: "nmap --version"   # 可选：版本检测命令

# ============================================================
# 参数定义（必填，至少一个）
# ============================================================
# AI Agent 看到这些参数，并根据 description 决定传什么值
parameters:
  - name: target                # 参数名，Go 模板变量名
    type: string                # 类型：string / integer / boolean
    description: "扫描目标"      # AI 读这段来理解参数用途
    required: true              # 是否必填
  - name: ports
    type: string
    description: "端口范围"
    default: "1-10000"          # 可选：默认值，AI 不传时自动填入
    enum: ["syn", "tcp"]        # 可选：枚举约束，AI 只能从中选择

# ============================================================
# 命令模板（必填）
# ============================================================
# 使用 Go text/template 语法，每行一组参数
# 可用变量：所有 parameters 的 name + {{.OutputFile}} + {{.WorkDir}}
command_template: |
  -sS
  -p {{.ports}}
  -oG {{.OutputFile}}
  --open
  {{.target}}

# 实际执行的命令 = binary + command_template 渲染结果
# 例如: nmap -sS -p 1-10000 -oG /tmp/xxx/output.txt --open 192.168.1.0/24

# ============================================================
# 输出解析（必填）
# ============================================================
output:
  mode: file                    # stdout / file / json_file
  file_pattern: "{{.OutputFile}}" # mode=file 时的文件路径模板
  parser: line                  # 解析器类型，见 1.4 节

  # 解析器配置（按 parser 类型选其一）
  line:                         # parser: line 时
    skip_prefix: "#"            # 跳过以此开头的行
    skip_empty: true            # 跳过空行
    split: " "                  # 分隔符
    fields:                     # 按分隔后的索引映射字段名
      - name: host
        index: 0
      - name: port
        index: 1

# ============================================================
# 结果映射（必填）
# ============================================================
# 将解析出的每条记录映射为 Kitsune Finding 入库
findings_mapping:
  type: info                    # Finding 类型
  severity: info                # 严重程度：info / low / medium / high / critical
  target_field: host            # 哪个解析字段作为 Finding.Target
  detail_template: "{{.host}}:{{.port}} open"  # 详情模板

# ============================================================
# 约束条件（可选）
# ============================================================
constraints:
  timeout: 300s                 # 超时时间（Go duration 格式）
  requires_root: false          # 是否需要 root 权限
  max_concurrent: 2             # 最大并发数
  proxy_flag: "--proxy"         # 代理参数名（Kitsune 自动注入代理地址）
```

## 1.4 四种输出解析器

### line — 按行分割（最常用）

适用于每行一条结果、字段用固定分隔符隔开的输出。

```yaml
output:
  parser: line
  line:
    skip_prefix: "#"          # 跳过注释行
    skip_empty: true
    split: ","                # 分隔符：空格、逗号、制表符等
    fields:
      - { name: ip, index: 0 }
      - { name: port, index: 1 }
      - { name: service, index: 2 }
```

若不配置 `line` 子项，则每行整体作为一个 `target` 字段。

### json — JSON 输出

适用于工具输出 JSON 格式（如 httpx -json、nuclei -json）。

```yaml
output:
  parser: json
  json:
    results_path: "results"   # JSON 数组路径（点分隔），如 "data.hosts"
    fields:
      - { name: host, path: "host" }
      - { name: port, path: "port" }
      - { name: url, path: "url" }
```

### regex — 正则提取

适用于非结构化输出，需要用正则捕获关键信息。

```yaml
output:
  parser: regex
  regex:
    pattern: 'Found open port (\d+)/tcp on (\S+)'
    groups: [port, host]      # 按捕获组顺序命名
```

### grepable — nmap -oG 专用

```yaml
output:
  parser: grepable
  grepable:
    host_regex: 'Host:\s+(\S+)'
    port_regex: '(\d+)/open'
```

## 1.5 category 枚举

| 值 | 说明 | 示例工具 |
|---|---|---|
| `scan` | 资产探测 | nmap, masscan, rustscan |
| `osint` | 情报搜索 | subfinder, amass, theHarvester |
| `poc` | 漏洞扫描 | nuclei, xray |
| `brute` | 爆破/Fuzz | dirsearch, ffuf, hydra |
| `postexploit` | 后渗透 | linpeas, winpeas |
| `util` | 辅助工具 | curl, jq, whatweb |

## 1.6 command_template 模板语法

使用 Go `text/template`，支持条件判断：

```yaml
command_template: |
  {{if eq .scan_type "syn"}}-sS{{else if eq .scan_type "udp"}}-sU{{else}}-sT{{end}}
  -p {{.ports}}
  {{if .wordlist}}-w {{.wordlist}}{{end}}
  -o {{.OutputFile}}
  {{.target}}
```

**内置变量**（无需在 parameters 中定义）：
- `{{.OutputFile}}` — Kitsune 自动创建的临时输出文件路径
- `{{.WorkDir}}` — Kitsune 自动创建的临时工作目录

## 1.7 完整示例

<details>
<summary>subfinder — 子域名发现</summary>

```yaml
id: ext_subfinder
name: Subfinder 子域名发现
description: "使用 subfinder 被动发现子域名，速度快、覆盖广，适合大规模侦察"
homepage: "https://github.com/projectdiscovery/subfinder"
category: scan
binary: subfinder
version_cmd: "subfinder -version"

parameters:
  - name: target
    type: string
    description: "目标域名"
    required: true

command_template: |
  -d {{.target}}
  -silent
  -o {{.OutputFile}}

output:
  mode: file
  file_pattern: "{{.OutputFile}}"
  parser: line

findings_mapping:
  type: info
  severity: info
  target_field: target
  detail_template: "subdomain: {{.target}}"

constraints:
  timeout: 120s
```
</details>

<details>
<summary>nuclei — 漏洞扫描（JSON 输出）</summary>

```yaml
id: ext_nuclei
name: Nuclei 漏洞扫描
description: "使用 nuclei 进行基于模板的漏洞扫描，支持数千个 CVE 和暴露检测模板"
homepage: "https://github.com/projectdiscovery/nuclei"
category: poc
binary: nuclei
version_cmd: "nuclei -version"

parameters:
  - name: target
    type: string
    description: "扫描目标 URL"
    required: true
  - name: severity
    type: string
    description: "严重等级过滤"
    default: "low,medium,high,critical"
    enum: ["info", "low", "medium", "high", "critical", "low,medium,high,critical"]
  - name: tags
    type: string
    description: "模板标签过滤（如 cve,exposed）"

command_template: |
  -u {{.target}}
  -severity {{.severity}}
  {{if .tags}}-tags {{.tags}}{{end}}
  -jsonl
  -o {{.OutputFile}}
  -silent

output:
  mode: file
  file_pattern: "{{.OutputFile}}"
  parser: json
  json:
    fields:
      - { name: host, path: "host" }
      - { name: template_id, path: "template-id" }
      - { name: severity, path: "info.severity" }
      - { name: name, path: "info.name" }
      - { name: matched_at, path: "matched-at" }

findings_mapping:
  type: vulnerability
  severity: medium
  target_field: host
  detail_template: "[{{.severity}}] {{.name}} ({{.template_id}}) at {{.matched_at}}"

constraints:
  timeout: 600s
  max_concurrent: 1
```
</details>

<details>
<summary>ffuf — Web Fuzz</summary>

```yaml
id: ext_ffuf
name: ffuf Web Fuzz
description: "使用 ffuf 进行高速 Web 路径和参数 Fuzz"
homepage: "https://github.com/ffuf/ffuf"
category: brute
binary: ffuf
version_cmd: "ffuf -V"

parameters:
  - name: target
    type: string
    description: "目标 URL，用 FUZZ 标记注入点，如 http://example.com/FUZZ"
    required: true
  - name: wordlist
    type: string
    description: "字典文件路径"
    required: true
  - name: filter_code
    type: string
    description: "过滤 HTTP 状态码"
    default: "404"

command_template: |
  -u {{.target}}
  -w {{.wordlist}}
  -fc {{.filter_code}}
  -o {{.OutputFile}}
  -of json
  -s

output:
  mode: file
  file_pattern: "{{.OutputFile}}"
  parser: json
  json:
    results_path: "results"
    fields:
      - { name: url, path: "url" }
      - { name: status, path: "status" }
      - { name: length, path: "length" }
      - { name: words, path: "words" }

findings_mapping:
  type: info
  severity: info
  target_field: url
  detail_template: "{{.url}} [{{.status}}] length={{.length}}"

constraints:
  timeout: 300s
  max_concurrent: 2
```
</details>

## 1.8 检查清单

提交 Tool YAML 前，请确认：

- [ ] `id` 以 `ext_` 开头，全局唯一
- [ ] `description` 清楚说明工具能做什么（AI 据此决定是否调用）
- [ ] `homepage` 填写工具的 GitHub 地址或官网，方便用户了解和安装
- [ ] 至少有一个 `required: true` 的 `target` 参数
- [ ] `command_template` 渲染后是合法的命令行
- [ ] `output.parser` 与工具实际输出格式匹配
- [ ] `findings_mapping.detail_template` 引用的字段在解析器中存在
- [ ] `binary` 是工具的实际可执行文件名
- [ ] 在本机安装该工具后实际测试通过

---

# 二、Skills 技能剧本编写规范

## 2.1 概述

每个 YAML 文件定义一个 AI Agent 技能（Playbook）。技能是一段预设的 AI 提示词模板，指导 Agent 按步骤执行渗透任务。

## 2.2 文件命名

```
{技能名}.yaml
```

示例：`recon-full.yaml`、`sql-injection-test.yaml`

## 2.3 完整字段说明

```yaml
# ============================================================
# 基本信息（必填）
# ============================================================
id: my-skill-name              # 技能唯一标识（英文短横线命名）
name: 技能显示名称               # 中文名
description: 技能功能描述        # 一句话说明这个技能做什么
category: 侦察                  # 分类，见下方枚举
tags: [recon, subdomain]        # 标签数组，用于搜索和筛选
difficulty: medium              # easy / medium / hard
icon: "🔍"                     # 可选：显示图标
step_count: 5                   # 可选：预估执行步骤数

# ============================================================
# 用户变量（必填，至少一个）
# ============================================================
# 用户在使用技能前需要填写的参数
variables:
  - name: target                # 变量名，在 prompt 中用 {{target}} 引用
    label: 目标域名              # 显示标签
    placeholder: example.com    # 输入框占位提示
    required: true
  - name: scope
    label: 扫描范围
    placeholder: "仅主域名 / 包含子域名"
    required: false

# ============================================================
# 提示词模板（必填）
# ============================================================
# AI Agent 收到此 prompt 后按指示执行
# 用 {{变量名}} 引用 variables 中的变量
prompt: |
  请对目标 {{target}} 执行以下任务：
  1. 步骤一描述
  2. 步骤二描述
  ...
```

## 2.4 category 枚举

| 值 | 说明 |
|---|---|
| `侦察` | 资产发现、信息收集、OSINT |
| `漏洞利用` | Web 漏洞、POC 验证、Fuzz |
| `后渗透` | 提权、持久化、凭据收集 |
| `内网渗透` | AD 攻击、横向移动、跳板 |
| `云环境` | 云资产审计、IAM、元数据 |
| `综合` | 全链路、红队评估、报告生成 |

## 2.5 prompt 编写要点

### 必须引用 Kitsune 内置工具名

Agent 按工具名调用，所以 prompt 中要写明确的工具名。可用的内置工具：

**资产探测**：`scan_dns`（子域名）、`scan_port`（端口）、`scan_urlive`（URL存活）、`scan_finger`（指纹）、`scan_crawl`（爬虫）、`scan_app`（应用识别）

**情报搜索**：`osint_fofa`、`osint_quake`、`osint_hunter`

**漏洞检测**：`poc_web`（Web POC）、`poc_category`（分类 POC）、`poc_default_login`（默认口令）

**爆破攻击**：`brute_dir`（目录爆破）、`brute_basic`（基础爆破）、`brute_host`（主机爆破）

**后渗透**：`privesc_check_linux`、`privesc_check_windows`、`privesc_suggest`

**横向移动**：`lateral_list_methods`、`lateral_generate_command`

**辅助**：`memory_save`、`memory_recall`、`query_assets`、`query_vulnerabilities`、`save_credential`

> 外部工具（Tools/ 中定义的 ext_xxx）也可在 prompt 中引用。

### 结构化步骤

每步写清楚：用什么工具 → 对什么目标 → 期望什么结果。

```yaml
prompt: |
  请对 {{target}} 执行渗透测试：
  1. 使用 scan_dns 枚举子域名
  2. 对发现的子域名使用 scan_port 扫描开放端口
  3. 使用 scan_urlive 检测存活 URL
  4. 对存活 URL 使用 poc_web 进行漏洞扫描
  5. 将所有发现使用 memory_save 保存到记忆库
  最终输出完整的渗透测试报告。
```

### 结果处理指示

告诉 Agent 如何处理每步结果：

```yaml
prompt: |
  ...
  每步完成后总结发现数量和关键信息。
  如果某步发现 0 条结果，分析可能原因并尝试替代方案。
  如发现漏洞，请标注风险等级（高/中/低）并给出修复建议。
```

## 2.6 完整示例

<details>
<summary>API 安全测试</summary>

```yaml
id: api-security-test
name: API 安全测试
description: 对 REST API 进行全面安全测试，包括认证绕过、注入、信息泄露
category: 漏洞利用
tags: [api, web, injection, auth]
difficulty: hard
icon: "🔌"
step_count: 5
variables:
  - name: target
    label: API 基础 URL
    placeholder: https://api.example.com
    required: true
  - name: auth_token
    label: 认证 Token（可选）
    placeholder: Bearer xxx
    required: false
prompt: |
  请对 API 目标 {{target}} 进行安全测试：
  1. 使用 scan_finger 识别 API 框架和版本
  2. 使用 scan_crawl 发现 API 端点
  3. 使用 brute_dir 爆破常见 API 路径（/api/v1, /swagger, /graphql 等）
  4. 使用 poc_web 检测已知 API 漏洞
  5. 对发现的端点检查：
     - 未授权访问（去掉认证头重放）
     - 信息泄露（debug 端点、错误信息）
     - 注入风险
  {{auth_token}}
  每步完成后记录发现，最终生成 API 安全评估报告。
```
</details>

<details>
<summary>供应链安全审计</summary>

```yaml
id: supply-chain-scan
name: 供应链安全审计
description: 检查目标站点的前端依赖库和第三方资源是否存在已知漏洞
category: 综合
tags: [supply-chain, web, dependency]
difficulty: medium
icon: "📦"
step_count: 3
variables:
  - name: target
    label: 目标网站
    placeholder: https://example.com
    required: true
prompt: |
  请对 {{target}} 进行供应链安全审计：
  1. 使用 scan_finger 识别前端框架和第三方库版本
  2. 使用 scan_crawl 抓取页面，提取所有外部 JS/CSS 资源链接
  3. 分析发现的第三方库：
     - 是否有已知 CVE
     - 版本是否过旧
     - 是否从不可信 CDN 加载
  生成供应链安全审计报告，按风险等级排序。
```
</details>

## 2.7 检查清单

提交 Skill YAML 前，请确认：

- [ ] `id` 全局唯一，英文短横线命名
- [ ] `description` 一句话说明技能功能
- [ ] `category` 是规范的枚举值
- [ ] `variables` 至少有一个 `required: true` 参数
- [ ] `prompt` 中每步引用了正确的工具名
- [ ] `prompt` 中所有 `{{变量名}}` 在 `variables` 中有定义
- [ ] `tags` 包含相关关键词便于搜索
- [ ] `difficulty` 与实际复杂度匹配

---

# 三、提交流程

1. Fork 本仓库
2. 在对应目录创建 YAML 文件
3. 按上述规范检查清单自查
4. 提交 PR，标题格式：`[Tool] 添加 xxx` 或 `[Skill] 添加 xxx`

---

# 四、常见问题

**Q: 工具输出没有固定格式怎么办？**
A: 使用 `parser: regex` 用正则提取关键信息，或使用 `mode: stdout` + `parser: line` 逐行处理。

**Q: 工具需要 root 权限怎么标注？**
A: 在 `constraints.requires_root: true` 标注，同时在 `description` 中说明。

**Q: 一个工具有多种使用场景，写几个 YAML？**
A: 建议拆成多个，如 `nmap-scan.yaml`（端口扫描）、`nmap-vuln.yaml`（漏洞脚本扫描），各有不同的 parameters 和 command_template。

**Q: Skill 的 prompt 可以引用外部工具吗？**
A: 可以。直接写 `ext_xxx` 工具名，Agent 会自动调用。
