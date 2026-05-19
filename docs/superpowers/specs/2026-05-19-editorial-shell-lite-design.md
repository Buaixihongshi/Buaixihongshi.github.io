# Editorial Shell Lite 融合设计

日期：2026-05-19

## 背景

当前博客已经形成“个人归档画廊”方向：米白背景、黑色细线、编号文章索引、克制的等宽字体。新的参考站点是 `https://atum.li/cn/`，它的主要气质来自 shell 语法、命令行提示符、`ls tags`、`==> meta <==` 这类终端化表达。

我们尝试过更完整的 Editorial Shell demo，但结果偏杂乱。确认后的方向是轻量融合：只吸收 atum 的“命令行签名”语感，不把整站改成终端模拟器。

## 已确认方向

- 保留当前米白归档画廊作为主视觉系统。
- 首页只增强现有两行命令行索引。
- 不改顶部导航为 `[0:posts*]` 形式。
- 不在文章列表中加入 `==> meta <==`。
- 不把标签页、TOC、文章页都改成 shell 输出风格。

## 具体设计

首页当前命令行索引：

```text
$ tail -f latest.log
writing, learning, wandering_
```

调整为：

```text
afk@archive % tail -f latest.log
writing, learning, wandering_
```

这是一处轻量作者签名，用来保留 atum 的 shell 气质。它不改变页面结构，也不增加额外信息密度。

## 视觉原则

- 仍使用米白背景、黑色线条和编号索引。
- `afk@archive %` 使用现有等宽字体与灰色次级文本。
- 第二行 `writing, learning, wandering_` 继续使用当前强调色。
- 不新增终端面板、深色背景块或多处命令行装饰。

## 技术范围

预期只需要修改 `_layouts/home.html`：

- 将首页第一行命令文本从 `$ tail -f latest.log` 改为 `afk@archive % tail -f latest.log`。

无需修改：

- `_includes/site-header.html`
- `_includes/post-index.html`
- `_layouts/post.html`
- `assets/css/personal-archive.scss`
- `assets/js/personal-archive.js`

## 验收

1. 首页 hero 中出现 `afk@archive % tail -f latest.log`。
2. 文章列表、顶部导航、标签页、文章页目录保持现状。
3. 移动端不出现横向溢出。
4. Jekyll 构建或 GitHub Actions 构建通过。
