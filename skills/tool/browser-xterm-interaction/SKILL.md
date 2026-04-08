---
name: browser-xterm-interaction
description: "Playwright Browser MCP 与 xterm.js 终端交互方法论。当需要通过浏览器操作网页内嵌终端、CTF 靶场伪终端、Cloud Shell、在线 IDE 中的终端时使用。覆盖终端内容读取（5 种方法）、命令执行、输出捕获、screenshot 降级策略。只要目标页面中有任何形式的 Web 终端（xterm.js/hterm/jQuery Terminal），就应使用此技能"
metadata:
  tags: "browser,playwright,xterm,web-terminal,xtermjs,浏览器终端"
  category: "tool"
---

# Playwright Browser MCP × Web 终端交互

Web 终端（xterm.js、hterm 等）在浏览器中渲染终端界面，但其输出通常用 canvas 或自定义 DOM 渲染，标准的 `browser_snapshot()` 只能看到 accessibility tree 中的最后一行 prompt。这是与 Web 终端交互时最大的痛点——需要用特定的 JS 方法才能可靠地读取终端输出。

## 核心原则

1. **一次定型** — 找到有效的读取方法后坚持用它，不要每次都换方法，因为来回切换会浪费大量 turn
2. **3 次法则** — 一种方法最多试 3 次就切换下一种，避免在死路上消耗 turn
3. **screenshot 兜底** — JS 方法全部失败时，截图+视觉分析是 100% 可靠的最终手段
4. **marker 包裹** — 用 `echo "===START==="; cmd; echo "===END==="` 包裹命令输出，方便精确提取

---

## Phase 1: 识别终端类型

先用一次 `browser_snapshot()` 或 `browser_evaluate` 探测终端类型：

```javascript
// 探测终端类型
() => {
  const xterm = document.querySelector('.xterm');
  const jquery_term = window.jQuery && window.jQuery.fn.terminal;
  const hterm = document.querySelector('[id*="hterm"]');
  return {
    xterm: !!xterm,
    jquery_terminal: !!jquery_term,
    hterm: !!hterm,
    terminal_classes: xterm ? xterm.className : 'not found'
  };
}
```

---

## Phase 2: 命令执行（输入）

### 方法 A: 通过 textbox ref 输入（推荐）

```
browser_type(ref='<terminal_input_ref>', text='your command', submit=True)
```

### 方法 B: 通过 keyboard 直接输入

```
browser_click(element='terminal area', ref='<terminal_ref>')
browser_press_key(key='your command text')  // 逐字符
browser_press_key(key='Enter')
```

### 方法 C: 通过 evaluate 写入

```javascript
() => {
  const textarea = document.querySelector('.xterm-helper-textarea');
  if (textarea) {
    textarea.focus();
    // 通过 InputEvent 模拟输入
  }
}
```

**⚠️ 重要**：执行命令后，必须等待足够时间让输出完成：
- 快速命令（echo, cat）: `browser_wait_for(time=2)`
- 中速命令（nslookup, curl）: `browser_wait_for(time=5)`
- 慢速命令（扫描、编译）: `browser_wait_for(time=15-30)`

---

## Phase 3: 输出读取（核心难点）

### ⭐ 方法 1: xterm-rows innerText（最可靠）

```javascript
() => {
  const rows = document.querySelectorAll('.xterm-rows > div');
  let lines = [];
  for (let row of rows) {
    const text = row.innerText || row.textContent || '';
    if (text.trim()) lines.push(text);
  }
  return lines.join('\n');
}
```

### 方法 2: xterm-screen innerText

```javascript
() => {
  const screen = document.querySelector('.xterm-screen');
  return screen ? screen.innerText : 'not found';
}
```

### 方法 3: 通过 Terminal API（如果暴露）

```javascript
() => {
  // 尝试通过 xterm.js Terminal 实例的 buffer 读取
  const term = document.querySelector('.xterm');
  if (term && term._core) {
    const buffer = term._core.buffer.active;
    let lines = [];
    for (let i = 0; i < buffer.length; i++) {
      const line = buffer.getLine(i);
      if (line) lines.push(line.translateToString(true));
    }
    return lines.join('\n');
  }
  return 'Terminal API not accessible';
}
```

### 方法 4: Marker 包裹法（精确提取命令输出）

执行命令时用 marker 包裹，便于精确提取：

```bash
echo "===START==="; your_command_here; echo "===END==="
```

然后在 JS 中提取 `===START===` 和 `===END===` 之间的内容。

### 方法 5: 重定向到文件 + cat

```bash
your_command > /tmp/out.txt 2>&1; cat /tmp/out.txt
```

适用于输出很长或滚动导致内容丢失的情况。

---

## Phase 4: 降级策略（JS 方法失败时）

### ⭐ Screenshot + 视觉分析（最终兜底）

当 JS 方法都无法可靠读取终端输出时：

```
browser_take_screenshot(type='png', filename='term_output.png')
Read(file_path='<output_dir>/term_output.png')
```

然后通过图片内容视觉分析终端输出。

**⚠️ 禁止使用 `fullPage=True`** — 全页截图体积极大（>1MB），会导致 SDK JSON buffer 溢出崩溃。只用默认的 viewport 截图。

**优点**：100% 可靠，不依赖 DOM 结构
**缺点**：消耗更多 tokens、只能看到可视区域

**技巧**：
- 在截图前先滚动终端到底部
- 长输出分多次截图
- 用 `fullPage=True` 尝试全页截图
- 配合 marker 法定位关键输出区域

---

## 常见问题与解决

### Q: `browser_snapshot()` 只返回最后一行 prompt

xterm.js 用 canvas 或 DOM renderer 渲染，snapshot 只能看到 accessibility tree。
**解决**: 用 `browser_evaluate` + Phase 3 的 JS 方法。

### Q: `browser_evaluate` 返回空字符串

可能终端用了 canvas renderer，DOM 中没有文本节点。
**解决**: 用 screenshot 兜底。

### Q: 终端输出太长被截断

xterm.js 有 scrollback buffer 限制（默认 1000 行）。
**解决**: 用重定向到文件法，或分段查看。

### Q: 命令执行后看不到输出变化

可能等待时间不够，或终端没有刷新。
**解决**: 增加 `browser_wait_for` 时间，或按 Enter 触发刷新。

---

## 决策流程图

```
开始
 ↓
识别终端类型 (Phase 1)
 ↓
执行命令 (Phase 2, 方法 A 优先)
 ↓
等待输出 (browser_wait_for)
 ↓
尝试 JS 读取 (Phase 3, 方法 1)
 ├── 成功 → 锁定此方法，后续复用
 ├── 失败 → 尝试方法 2
 │    ├── 成功 → 锁定
 │    ├── 失败 → 尝试方法 3
 │    │    ├── 成功 → 锁定
 │    │    └── 失败 → Screenshot 兜底 (Phase 4)
 └── 3 次后仍不稳定 → Screenshot 兜底
```

**⚠️ 禁止**: 在 JS 读取方法之间反复来回切换超过 3 次。确定一种方法后坚持使用。
