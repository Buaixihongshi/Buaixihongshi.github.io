# 离别歌式夜读博客改版设计

日期：2026-08-11

## 背景

当前博客已完成一轮「奶油纸归档画廊」改版（自定义 Jekyll layout + SCSS，覆盖 Chirpy 可见结构）。用户希望参考 [离别歌](https://www.leavesongs.com/) 重新调整气质：结构上更像文人黑客博客（自述开场 + 朴素文章列表），视觉上采用深色夜读 + 暖金强调，并去掉编号索引、终端行与入口卡片。

技术栈不变：Jekyll 4、本地 `_layouts` / `_includes` / SCSS、GitHub Pages Actions、现有 Markdown 内容与 permalink。

## 已确认方向

| 项 | 决定 |
|----|------|
| 参考深度 | 结构 + 视觉都向离别歌靠拢 |
| 首页自述 | 复用 `/about/` 正文作为摘要；About 页保留完整版 |
| 文章分栏 | 本次不分 Security/Life 栏目；仅「最新文章」列表 |
| 视觉收敛 | 大幅收敛：去掉编号、终端行、Archive/Tags/About 三卡片 |
| 改版范围 | 全站统一（首页、文章、归档、标签、分类、About） |
| 配色 | **夜读暖金**（非白底、非奶油纸） |

## 目标

1. 首页先读到作者自述，再进入文章列表，气质贴近离别歌。
2. 全站统一为深色夜读阅读风，低装饰、少边框、无卡片堆叠。
3. 保留现有文章、分类、标签、permalink（`/posts/:title/`）与部署流程。
4. 移动端单栏可读，代码块可横向滚动且不撑破页面。

## 非目标

- 不迁移框架，不重写文章正文。
- 不新增站内搜索、评论、赞助/广告区、栏目分栏。
- 不保留奶油归档视觉、编号列表、终端风格文案、首页入口卡片。
- 不复制离别歌的品牌文案、付费咨询或广告内容。

## 信息架构

### 首页（自上而下）

1. **顶栏**：站点名 + 导航 `Posts / Archive / Tags / About`
2. **自述区**：渲染 About 页正文（与 `/about/` 同源）；可附「完整 About →」链接
3. **最新文章**：标题 + 日期的朴素列表（无编号）
4. **页脚**：年份、站点名、GitHub

### 文章页

- 标题、日期、可选分类/标签
- 正文长读排版；代码块深色底
- TOC：桌面端正文右侧粘性侧栏（`page.toc` 为真时）；移动端改为正文前静态目录，不粘滞遮挡
- 上一篇 / 下一篇文字链

### 其他页面

| 页面 | 内容 |
|------|------|
| About | 完整自述，同一套 page 样式 |
| Archive | 按年份分组的标题列表 |
| Tags / Tag | 标签列表 → 该标签下文章列表 |
| Categories / Category | 同 Tags 结构 |

## 视觉系统

### 配色（夜读暖金）

| Token | 值 | 用途 |
|-------|-----|------|
| `--bg` | `#1c1f24` | 页面背景 |
| `--surface` | `#23272e` | 轻量表面（如提示块，尽量少用） |
| `--text` | `#e7e2d8` | 正文 |
| `--muted` | `#a39e93` | 次要文字 |
| `--soft` | `#7a756c` | 标签/日期 |
| `--accent` | `#c9a227` | 链接悬停、少量强调 |
| `--line` | `rgba(231, 226, 216, 0.12)` | 分隔线 |

### 字体与版式

- 正文：中文友好衬线（如 `Noto Serif SC` / `Source Han Serif SC` + 系统回退）
- 导航、日期、小标签：系统无衬线
- 内容宽约 `680–720px`，居中；靠留白分层，少用粗边框与卡片
- 动效：仅链接悬停变色，无多余动画

### 明确移除的旧元素

- Hero 大标题「A small archive of days.」及 cream 画廊骨架
- `current-index` 终端两行
- 编号 `01 / 02` 文章索引（`post-index` 改为无编号标题列表，或替换为新 include）
- 首页 `page-links` 三卡片（首页不再 include）
- 奶油纸变量体系与粗黑边框布局

## 实现边界

- 改：`_layouts/*`、`_includes/*`、`assets/css/personal-archive.scss`（保留文件名，只替换变量与样式）、必要时微调 About 在首页的引用方式
- 不改：`_posts` 正文、permalink 规则、`_config.yml` 的 URL/collections/archives 设置、GitHub Actions 部署逻辑（除非构建失败需修）
- About 摘要：首页通过 Liquid 读取 `site.tabs`（或等价集合）中 About 页的 `content`，与 `/about/` 共用同一份 Markdown，不维护两份文案

## 验收标准

1. 首页可见 About 摘要与最新文章标题/日期列表。
2. 全站背景为夜读深色，强调色为暖金；无奶油纸/编号/终端残留。
3. 文章页正文可读，代码块对比清晰且可横向滚动。
4. Archive / Tags / Categories / About 视觉与首页一致。
5. 移动端（约 390 宽）导航可换行，无横向溢出。
6. 本地 `bundle exec jekyll build` 与 GitHub Actions 部署可通过。

## 参考

- 结构与气质：[离别歌](https://www.leavesongs.com/)
- 现有实现基线：本仓库自定义 Jekyll theme layer（2026-04-30 归档画廊改版）
- 演示确认：夜读暖金首页静态预览（brainstorm companion）
