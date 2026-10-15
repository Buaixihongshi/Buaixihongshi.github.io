---
layout: post
title: "Nanobot 拆解：最简单的 Agent"
date: 2026-04-15 00:00 +0800
categories:
- AI
tags:
- Agent
- LLM
- Python
- OpenAI
---

核心：**Agent = LLM + 工具 + 循环**

# 一、nanoAgent 全局架构

nanoAgent 的 `agent-essence.py` 只有 100 行，但五脏俱全。整体结构可以拆成四个部分：

<div class="agent-architecture-diagram" style="margin: 2em 0; overflow-x: auto; text-align: center;">
<svg viewBox="0 0 740 270" width="100%" height="auto" style="max-width: 740px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: block; margin: 0 auto;" xmlns="http://www.w3.org/2000/svg">
  <!-- 外层卡片容器 -->
  <rect x="10" y="10" width="720" height="250" rx="8" fill="#181b21" stroke="rgba(231, 226, 216, 0.14)" stroke-width="1.2"/>
  
  <!-- 顶部标题栏 -->
  <text x="32" y="34" fill="#e7e2d8" font-size="13" font-weight="600">nanoAgent 架构分层体系 (agent-essence.py)</text>
  <rect x="585" y="21" width="125" height="18" rx="4" fill="rgba(201, 162, 39, 0.12)" stroke="#c9a227" stroke-width="0.8"/>
  <text x="647" y="33" fill="#c9a227" font-size="10.5" font-weight="600" text-anchor="middle">100 行最小可用实现</text>

  <!-- 1. LLM 客户端初始化 -->
  <g transform="translate(30, 48)">
    <rect x="0" y="0" width="680" height="44" rx="6" fill="#1e232d" stroke="rgba(148, 163, 184, 0.25)" stroke-width="1"/>
    <rect x="12" y="10" width="64" height="24" rx="4" fill="rgba(148, 163, 184, 0.15)"/>
    <text x="44" y="26" fill="#cbd5e1" font-size="11" font-weight="700" text-anchor="middle">Layer 1</text>
    <text x="90" y="21" fill="#f1f5f9" font-size="13" font-weight="600">1. LLM 客户端初始化</text>
    <text x="90" y="36" fill="#94a3b8" font-size="10.5">OpenAI SDK 实例构建，配置 API Key 与 Base URL，建立与 LLM 的通信通道</text>
    <text x="660" y="27" fill="#64748b" font-size="11" text-anchor="end">OpenAI Client</text>
  </g>

  <!-- 2. 工具定义 (Tool Schema) -->
  <g transform="translate(30, 99)">
    <rect x="0" y="0" width="680" height="44" rx="6" fill="#152433" stroke="rgba(56, 189, 248, 0.3)" stroke-width="1"/>
    <rect x="12" y="10" width="64" height="24" rx="4" fill="rgba(56, 189, 248, 0.15)"/>
    <text x="44" y="26" fill="#38bdf8" font-size="11" font-weight="700" text-anchor="middle">Layer 2</text>
    <text x="90" y="21" fill="#e0f2fe" font-size="13" font-weight="600">2. 工具定义 (Tool Schema)</text>
    <text x="90" y="36" fill="#7dd3fc" font-size="10.5">JSON Schema 格式声明工具名、功能描述与必填入参（execute_bash, read_file, write_file）</text>
    <text x="660" y="27" fill="#0284c7" font-size="11" text-anchor="end">Function Calling</text>
  </g>

  <!-- 3. 工具实现 (Tool Functions) -->
  <g transform="translate(30, 150)">
    <rect x="0" y="0" width="680" height="44" rx="6" fill="#241a31" stroke="rgba(192, 132, 252, 0.3)" stroke-width="1"/>
    <rect x="12" y="10" width="64" height="24" rx="4" fill="rgba(192, 132, 252, 0.15)"/>
    <text x="44" y="26" fill="#c084fc" font-size="11" font-weight="700" text-anchor="middle">Layer 3</text>
    <text x="90" y="21" fill="#f3e8ff" font-size="13" font-weight="600">3. 工具实现与路由 (Tool Functions)</text>
    <text x="90" y="36" fill="#d8b4fe" font-size="10.5">系统底层交互逻辑（subprocess.run、文件读写）及 available_functions 调度字典</text>
    <text x="660" y="27" fill="#9333ea" font-size="11" text-anchor="end">Action Dispatch</text>
  </g>

  <!-- 4. Agent 核心循环 (Core Loop) -->
  <g transform="translate(30, 201)">
    <rect x="0" y="0" width="680" height="44" rx="6" fill="#282216" stroke="rgba(201, 162, 39, 0.4)" stroke-width="1"/>
    <rect x="12" y="10" width="64" height="24" rx="4" fill="rgba(201, 162, 39, 0.15)"/>
    <text x="44" y="26" fill="#fbbf24" font-size="11" font-weight="700" text-anchor="middle">Layer 4</text>
    <text x="90" y="21" fill="#fef3c7" font-size="13" font-weight="600">4. Agent 核心循环 (Core Loop)</text>
    <text x="90" y="36" fill="#fde68a" font-size="10.5">闭环中枢：发送对话历史 -> 解析 tool_calls -> 执行工具并追加至 messages 短期记忆</text>
    <text x="660" y="27" fill="#d97706" font-size="11" text-anchor="end">ReAct Loop</text>
  </g>
</svg>
</div>

# 二、源码拆解

## 2.1 初始化

这里用的是 OpenAI 的 Python SDK：

```python
import os
import json
import subprocess
import sys
from openai import OpenAI

client = OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY"),
    base_url=os.environ.get("OPENAI_BASE_URL")
)
```

## 2.2 工具定义

```python
tools = [
    {
        "type": "function",
        "function": {
            "name": "execute_bash",
            "description": "Execute a bash command on the system",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The bash command to execute"
                    }
                },
                "required": ["command"]
            }
        }
    },
    # ... read_file, write_file 类似
]
```

这是 OpenAI Function Calling 的标准格式：

- `tools[]`：工具列表
- 每个工具 type 固定是 `"function"`
- `function` 里包含：
  - `name`：工具名（模型会按这个名选择）
  - `description`：给模型看的说明
  - `parameters`：JSON Schema 格式的属性字典。它像一本百科全书，定义了所有模型"可以"使用的参数名称、类型（string/number 等）以及对该参数的详细描述。
  - `required`：里面存放了 `properties` 中那些**绝对不能缺席**的参数键名（Key）

> [!TIP]
> **`required` 和 `properties` 之间的关系该如何理解？**
>
> 你可以把这个过程想象成"填表"：
> - `properties` 决定了表格里有哪些格子可以填（比如：姓名、电话、住址）。
> - `required` 决定了哪些格子不填就不能提交（比如：姓名和电话必填，住址选填）。
>
> **为什么不把 `required` 直接写在 `properties` 内部？**
>
> 这是很多人困惑的地方。原因有二：
> 1. **解耦设计**：JSON Schema 的标准设计就是将"结构定义"与"验证规则"分开。
> 2. **条件依赖**：在高级用法中，可以实现"如果 A 填了，则 B 必填"的动态逻辑。如果写死在属性内部，就无法实现这种交叉验证。
>
> **总结**：`properties` 告诉 AI **"有什么"**；`required` 告诉 AI **"必须给什么"**。

nanoAgent 定义了三个工具：

| **工具名** | **能力** | **危险等级** |
| --- | --- | --- |
| `execute_bash` | 执行任意 shell 命令 | ⚠️ 极高——理论上可以做任何事 |
| `read_file` | 读取文件内容 | 中——可能读到敏感信息 |
| `write_file` | 写入文件 | 高——可以覆盖任何文件 |

## 2.3 工具实现：把 LLM 的"意图"变成"行动"

```python
def execute_bash(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout + result.stderr
    except Exception as e:
        return f"Error: {str(e)}"

def read_file(path):
    try:
        with open(path, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error: {str(e)}"

def write_file(path, content):
    try:
        with open(path, 'w') as f:
            f.write(content)
        return f"Successfully wrote to {path}"
    except Exception as e:
        return f"Error: {str(e)}"
```

这三个函数就是工具的"真身"。几个值得注意的细节：

- **错误处理**：每个函数都用 try-except 包裹，确保即使执行出错也能把错误信息返回给 LLM，而不是让整个程序崩溃。这很重要——LLM 看到错误后可以自行修正策略。
- **`timeout=30`**：bash 命令有 30 秒超时限制，防止死循环或长时间阻塞。
- **`shell=True`**：意味着可以执行管道、重定向等复杂 shell 语法，能力很强，但安全风险也很大。

接下来是一个路由表，把工具名映射到实际函数：

```python
available_functions = {
    "execute_bash": execute_bash,
    "read_file": read_file,
    "write_file": write_file
}
```

这个字典是**工具调度的核心**——当 LLM 说"我要调用 execute_bash"时，代码通过这个字典找到对应的 Python 函数并执行。

## 2.4 Agent 核心循环

```python
def run_agent(user_message, max_iterations=5):
    messages = [
        {
            "role": "system",
            "content": (
                "You are a helpful assistant that can interact with the system. "
                "Be concise."
            )
        },
        {"role": "user", "content": user_message}
    ]

    for _ in range(max_iterations):
        # Step 1: 把完整对话历史 + 工具列表发给 LLM
        response = client.chat.completions.create(
            model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
            messages=messages,
            tools=tools
        )

        message = response.choices[0].message
        messages.append(message)

        # Step 2: 如果 LLM 没有调用工具 → 任务完成，返回文本回答
        if not message.tool_calls:
            return message.content

        # Step 3: 如果 LLM 要调用工具 → 逐个执行，把结果追加到对话历史
        for tool_call in message.tool_calls:
            function_name = tool_call.function.name
            function_args = json.loads(tool_call.function.arguments)
            print(f"[Tool] {function_name}({function_args})")
            function_response = available_functions[function_name](**function_args)
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": function_response
            })

    return "Max iterations reached"
```

# 三、Agent 循环的运行时序（核心重点）

整个 Agent 运转的时序与状态流转如下图所示：

<div class="agent-runtime-diagram" style="margin: 2em 0; overflow-x: auto; text-align: center;">
<svg viewBox="0 0 760 330" width="100%" height="auto" style="max-width: 760px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: block; margin: 0 auto;" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <marker id="arrow-gray" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <polygon points="0 1, 8 4, 0 7" fill="#a39e93"/>
    </marker>
    <marker id="arrow-gold" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <polygon points="0 1, 8 4, 0 7" fill="#c9a227"/>
    </marker>
    <marker id="arrow-cyan" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <polygon points="0 1, 8 4, 0 7" fill="#38bdf8"/>
    </marker>
    <marker id="arrow-green" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <polygon points="0 1, 8 4, 0 7" fill="#4ade80"/>
    </marker>
  </defs>

  <!-- 用户输入节点 -->
  <rect x="15" y="45" width="130" height="58" rx="6" fill="#1e2229" stroke="#7a756c" stroke-width="1.2"/>
  <text x="80" y="70" fill="#e7e2d8" font-size="13" font-weight="600" text-anchor="middle">用户任务输入</text>
  <text x="80" y="88" fill="#a39e93" font-size="11" text-anchor="middle">"统计并写入..."</text>

  <!-- 输入箭头 -->
  <line x1="145" y1="74" x2="185" y2="74" stroke="#a39e93" stroke-width="1.5" marker-end="url(#arrow-gray)"/>

  <!-- Agent Loop 循环容器 -->
  <rect x="195" y="15" width="550" height="295" rx="8" fill="rgba(201, 162, 39, 0.03)" stroke="#c9a227" stroke-width="1.2" stroke-dasharray="4 4"/>
  <rect x="210" y="6" width="180" height="20" rx="4" fill="#24221a" stroke="#c9a227" stroke-width="0.8"/>
  <text x="300" y="20" fill="#c9a227" font-size="11" font-weight="600" text-anchor="middle">Agent Loop 核心循环</text>

  <!-- 节点 1：组装上下文 -->
  <rect x="215" y="45" width="145" height="58" rx="6" fill="#222730" stroke="rgba(231,226,216,0.2)" stroke-width="1.2"/>
  <text x="287" y="70" fill="#e7e2d8" font-size="13" font-weight="600" text-anchor="middle">① 组装上下文</text>
  <text x="287" y="88" fill="#a39e93" font-size="11" text-anchor="middle">messages + tools</text>

  <!-- 箭头 1 -> 2 -->
  <line x1="360" y1="74" x2="385" y2="74" stroke="#a39e93" stroke-width="1.5" marker-end="url(#arrow-gray)"/>

  <!-- 节点 2：LLM 决策 -->
  <rect x="395" y="45" width="135" height="58" rx="6" fill="#222730" stroke="rgba(231,226,216,0.2)" stroke-width="1.2"/>
  <text x="462" y="70" fill="#e7e2d8" font-size="13" font-weight="600" text-anchor="middle">② LLM 思考决策</text>
  <text x="462" y="88" fill="#a39e93" font-size="11" text-anchor="middle">大模型生成响应</text>

  <!-- 箭头 2 -> 3 -->
  <line x1="530" y1="74" x2="555" y2="74" stroke="#c9a227" stroke-width="1.5" marker-end="url(#arrow-gold)"/>

  <!-- 节点 3：决策分支 -->
  <rect x="565" y="45" width="160" height="58" rx="6" fill="#2d2716" stroke="#c9a227" stroke-width="1.4"/>
  <text x="645" y="70" fill="#fef08a" font-size="13" font-weight="600" text-anchor="middle">③ 检查响应类型</text>
  <text x="645" y="88" fill="#d4b14e" font-size="11" text-anchor="middle">有 tool_calls 吗？</text>

  <!-- 分支 No -> 任务完成退出 -->
  <line x1="645" y1="103" x2="645" y2="175" stroke="#4ade80" stroke-width="1.5" marker-end="url(#arrow-green)"/>
  <rect x="653" y="128" width="80" height="18" rx="3" fill="#14261b"/>
  <text x="693" y="141" fill="#4ade80" font-size="11" font-weight="600" text-anchor="middle">No（纯文本）</text>

  <!-- 节点 4：任务完成 -->
  <rect x="565" y="180" width="160" height="65" rx="6" fill="#14261b" stroke="#4ade80" stroke-width="1.5"/>
  <text x="645" y="206" fill="#4ade80" font-size="13" font-weight="600" text-anchor="middle">✔ 任务达成</text>
  <text x="645" y="224" fill="#d1fae5" font-size="11" text-anchor="middle">返回纯文本回答</text>
  <text x="645" y="238" fill="#6ee7b7" font-size="10" text-anchor="middle">退出 Agent 循环</text>

  <!-- 分支 Yes -> 执行工具 -->
  <path d="M 605 103 L 605 130 L 462 130 L 462 175" fill="none" stroke="#38bdf8" stroke-width="1.5" marker-end="url(#arrow-cyan)"/>
  <rect x="480" y="120" width="95" height="18" rx="3" fill="#112536"/>
  <text x="527" y="133" fill="#38bdf8" font-size="11" font-weight="600" text-anchor="middle">Yes（调用工具）</text>

  <!-- 节点 5：执行工具 -->
  <rect x="390" y="180" width="145" height="65" rx="6" fill="#162330" stroke="#38bdf8" stroke-width="1.2"/>
  <text x="462" y="206" fill="#e0f2fe" font-size="13" font-weight="600" text-anchor="middle">④ 执行工具函数</text>
  <text x="462" y="224" fill="#93c5fd" font-size="11" text-anchor="middle">bash / read / write</text>
  <text x="462" y="238" fill="#60a5fa" font-size="10" text-anchor="middle">捕获执行结果与异常</text>

  <!-- 箭头 5 -> 6 -->
  <line x1="390" y1="212" x2="365" y2="212" stroke="#38bdf8" stroke-width="1.5" marker-end="url(#arrow-cyan)"/>

  <!-- 节点 6：追加结果到 messages -->
  <rect x="215" y="180" width="145" height="65" rx="6" fill="#222730" stroke="#38bdf8" stroke-width="1.2"/>
  <text x="287" y="206" fill="#e0f2fe" font-size="13" font-weight="600" text-anchor="middle">⑤ 结果追加记忆</text>
  <text x="287" y="224" fill="#93c5fd" font-size="11" text-anchor="middle">包装为 role: "tool"</text>
  <text x="287" y="238" fill="#60a5fa" font-size="10" text-anchor="middle">存入 messages 数组</text>

  <!-- 回环回路：6 -> 1 -->
  <line x1="287" y1="180" x2="287" y2="110" stroke="#38bdf8" stroke-width="1.5" stroke-dasharray="3 3" marker-end="url(#arrow-cyan)"/>
  <rect x="220" y="136" width="134" height="18" rx="3" fill="#18232e"/>
  <text x="287" y="149" fill="#7dd3fc" font-size="10.5" font-weight="600" text-anchor="middle">带着完整历史进入下一轮</text>
</svg>
</div>

以一个具体任务为例：

```bash
python 01-essence/agent-essence.py \
  "统计当前目录下有多少个 Python 文件，并把结果写入 count.txt"
```

Agent 在运行时的 3 轮循环流转如下：

## 第 1 轮循环

**1. 发送给 LLM 的 messages：**
初始状态仅包含系统提示与用户任务：

```plaintext
[system] You are a helpful assistant that can interact with the system. Be concise.
[user]   统计当前目录下有多少个 Python 文件，并把结果写入 count.txt
```

**2. LLM 返回：**
模型判断需要先通过 shell 命令统计文件数量，返回 `tool_calls`：

```json
{
  "tool_calls": [{
    "function": {
      "name": "execute_bash",
      "arguments": "{\"command\": \"find . -name '*.py' | wc -l\"}"
    }
  }]
}
```

**3. 代码执行：**
代码调用 `execute_bash("find . -name '*.py' | wc -l")`，得到结果 `"42\n"`。

**4. 追加到 messages：**
将执行结果包装为 `role: "tool"` 写入短期记忆：

```plaintext
[tool] 42
```

---

## 第 2 轮循环

**1. 发送给 LLM 的 messages：**
包含了第 1 轮积累的完整轨迹（system + user + assistant tool_call + tool 结果）：

```plaintext
[system]    You are a helpful assistant...
[user]      统计当前目录下有多少个 Python 文件，并把结果写入 count.txt
[assistant] tool_calls: execute_bash(command="find . -name '*.py' | wc -l")
[tool]      42
```

**2. LLM 返回：**
模型看到统计结果是 42，决定下一步将结果写入 `count.txt`：

```json
{
  "tool_calls": [{
    "function": {
      "name": "write_file",
      "arguments": "{\"path\": \"count.txt\", \"content\": \"Python files: 42\"}"
    }
  }]
}
```

**3. 代码执行：**
代码调用 `write_file("count.txt", "Python files: 42")`，得到结果 `"Successfully wrote to count.txt"`。

**4. 追加到 messages：**
将写入成功的反馈继续追加到对话历史中：

```plaintext
[tool] Successfully wrote to count.txt
```

---

## 第 3 轮循环

**1. 发送给 LLM 的 messages：**
此时上下文已包含完整的“思考 - 行动 - 观察”全过程：

```plaintext
[system]    You are a helpful assistant...
[user]      统计当前目录下有多少个 Python 文件，并把结果写入 count.txt
[assistant] tool_calls: execute_bash(...)
[tool]      42
[assistant] tool_calls: write_file(...)
[tool]      Successfully wrote to count.txt
```

**2. LLM 返回：**
模型看到文件已成功写入，确认用户的两项要求（统计 + 写入）均已完成，不再生成 `tool_calls`，直接返回纯文本回答：

```plaintext
"已统计完成，当前目录下共有 42 个 Python 文件，结果已写入 count.txt。"
```

**3. 终止判断：**
代码检测到 `not message.tool_calls` 为 `True` → 退出 Agent 循环，将最终回答输出给用户。任务圆满结束！

# 四、Agent 循环里的关键设计

## 4.1 为什么需要 `max_iterations`？

```python
for _ in range(max_iterations):  # 默认 5 次
```

这是一个**安全阀**。如果 LLM 陷入死循环（比如反复执行同一个失败的命令），`max_iterations` 确保程序最终会停下来。在生产级 Agent 中，这个值通常更大（比如 Claude Code 可以连续执行数十步），同时会配合更复杂的终止策略。

## 4.2 `messages` 列表为什么如此重要？

`messages` 是 Agent 的**短期记忆**。每一轮循环，它都会累积 LLM 的回复（包括它想调用什么工具）以及工具的执行结果。

当这个列表在下一轮发送给 LLM 时，LLM 能看到完整的"行动-观察"历史，从而做出更合理的下一步决策。这就是 Agent 和简单对话的本质区别——**Agent 维护了一条包含行动轨迹的上下文链**。

但请注意，这里的 `messages` 只在单次运行中存在。程序退出后，一切归零。Agent 下次运行时完全不记得上次做过什么。

## 4.3 LLM 是怎么"决定"调用工具的？

这是最容易产生误解的地方。LLM 并没有真的在"执行代码"或"调用函数"。实际发生的是：

1. 我们在 API 请求中传入了 `tools` 参数（工具说明书）
2. LLM 经过训练，学会了在适当的时候输出一种特殊的结构化格式（tool_calls）
3. 这个格式本质上就是一段 JSON，描述"我想调用哪个函数、传什么参数"
4. **我们的代码**解析这段 JSON，执行真正的函数，再把结果喂回给 LLM

所以整个过程可以理解为一种**协作协议**：

- **LLM 的职责**：思考、决策、生成工具调用指令
- **代码的职责**：解析指令、执行工具、返回结果

LLM 是"大脑"，代码是"手脚"。

## 4.4 `tool_call_id` 的作用

```python
messages.append({
    "role": "tool",
    "tool_call_id": tool_call.id,
    "content": function_response
})
```

`tool_call_id` 是 OpenAI API 的要求，用于将工具返回结果与对应的调用请求关联起来。当 LLM 在一次回复中同时调用多个工具时（并行调用），这个 ID 确保每个结果能正确匹配到对应的调用。
