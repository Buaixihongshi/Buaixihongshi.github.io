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

```
┌─────────────────────────────────────────┐
│           1. LLM 客户端初始化             │
├─────────────────────────────────────────┤
│           2. 工具定义（Tool Schema）      │
├─────────────────────────────────────────┤
│           3. 工具实现（Tool Functions）   │
├─────────────────────────────────────────┤
│           4. Agent 循环（Core Loop）     │
└─────────────────────────────────────────┘
```

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
                    "command": {"type": "string", "description": "The bash command to execute"}
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

> [!TIP] **`required` 和 `properties` 之间的关系该如何理解？**
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
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
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
        {"role": "system", "content": "You are a helpful assistant that can interact with the system. Be concise."},
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

用一张图来表示：

```
用户任务
  │
  ▼
┌──────────────────────────────────────────────────┐
│                  Agent Loop                      │
│                                                  │
│  ┌─────────┐    ┌──────────┐    ┌──────────────┐ │
│  │ 发送给  │───▶│ LLM 决策  │───▶│ 有tool_call? │ │
│  │ LLM     │    │          │    └──────┬───────┘ │
│  └─────────┘    └──────────┘           │         │
│       ▲                          Yes   │   No    │
│       │                          ┌─────┴─────┐   │
│       │                          ▼           ▼   │
│  ┌────┴────────┐          ┌──────────┐  返回文本  │
│  │ 结果追加到   │◀─────────│ 执行工具  │  ──────▶│
│  │ messages    │          └──────────┘   结束    │
│  └─────────────┘                                 │
└──────────────────────────────────────────────────┘
```

以一个具体例子来说明。假设用户运行：

```python
python 01-essence/agent-essence.py "统计当前目录下有多少个 Python 文件，并把结果写入 count.txt"
```

Agent 的执行过程如下：

## 第 1 轮循环

**发送给 LLM 的 messages：**

```
[system] You are a helpful assistant...
[user]   统计当前目录下有多少个 Python 文件，并把结果写入 count.txt
```

**LLM 返回：** 不是普通文本，而是一个 tool_call：

```json
{
  "tool_calls": [{
    "function": {"name": "execute_bash", "arguments": "{\"command\": \"find . -name '*.py' | wc -l\"}"}
  }]
}
```

**代码执行：** 调用 `execute_bash("find . -name '*.py' | wc -l")`，得到结果 `"42\n"`

**追加到 messages：**

```
[tool] 42
```

## 第 2 轮循环

**发送给 LLM 的 messages：** 现在包含了完整历史（system + user + assistant 的 tool_call + tool 结果）

**LLM 看到**结果是 42，决定写入文件：

```json
{
  "tool_calls": [{
    "function": {"name": "write_file", "arguments": "{\"path\": \"count.txt\", \"content\": \"Python files: 42\"}"}
  }]
}
```

**代码执行：** 调用 `write_file("count.txt", "Python files: 42")`

## 第 3 轮循环

**LLM 看到**文件写入成功，判断任务已完成，返回纯文本：

```
"已统计完成，当前目录下共有 42 个 Python 文件，结果已写入 count.txt。"
```

`not message.tool_calls` **为 True** → 退出循环，返回结果。

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
