# Personal Blog Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the Jekyll GitHub Pages blog as a personal archive gallery with a cream editorial layout, numbered indexes, and lightweight terminal detail.

**Architecture:** Keep Jekyll and the existing Markdown content. Add local `_layouts`, `_includes`, and one SCSS entrypoint to override Chirpy's visible page structure without editing the gem. Preserve post URLs, categories, tags, images, SEO tags, and GitHub Pages build behavior.

**Tech Stack:** Jekyll 4, Liquid templates, SCSS, GitHub Pages Actions, existing `jekyll-theme-chirpy` gem as a dependency source.

---

## File Map

- Create `_layouts/default.html`: base HTML document, SEO/favicons, shared header/footer, CSS entrypoint.
- Create `_layouts/home.html`: personal archive landing page and latest post index.
- Create `_layouts/post.html`: cream article page with metadata, tags, code-friendly content wrapper, and previous/next navigation.
- Create `_layouts/page.html`: generic tab/page wrapper for About and simple pages.
- Create `_layouts/archives.html`: year-grouped archive index.
- Create `_layouts/tags.html`: tag cloud/list landing page.
- Create `_layouts/tag.html`: single-tag post index.
- Create `_layouts/categories.html`: category landing page.
- Create `_layouts/category.html`: single-category post index.
- Create `_includes/site-header.html`: top navigation.
- Create `_includes/site-footer.html`: compact footer.
- Create `_includes/post-index.html`: reusable numbered post list.
- Create `_includes/page-links.html`: Archive/Tags/About entry strip used on home.
- Create `assets/css/personal-archive.scss`: full visual system and responsive behavior.
- Modify `_config.yml`: update description and force light mode for the new visual direction.

---

### Task 1: Base Layout And Shared Chrome

**Files:**
- Create: `_layouts/default.html`
- Create: `_includes/site-header.html`
- Create: `_includes/site-footer.html`
- Modify: `_config.yml`

- [ ] **Step 1: Create the base layout**

Create `_layouts/default.html`:

```liquid
<!doctype html>
<html lang="{{ site.alt_lang | default: site.lang | default: 'zh' }}">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <meta name="theme-color" content="#f6f3ec">
    {% seo title=false %}
    <title>
      {%- unless page.layout == 'home' -%}
        {{ page.title | append: ' | ' }}
      {%- endunless -%}
      {{ site.title }}
    </title>
    {% include_cached favicons.html %}
    <link rel="stylesheet" href="{{ '/assets/css/personal-archive.css' | relative_url }}">
  </head>
  <body class="archive-site layout-{{ page.layout | default: 'default' }}">
    {% include site-header.html %}
    <main class="site-main" id="main-content" aria-label="Main Content">
      {{ content }}
    </main>
    {% include site-footer.html %}
  </body>
</html>
```

- [ ] **Step 2: Create the header include**

Create `_includes/site-header.html`:

```liquid
<header class="site-header">
  <a class="site-brand" href="{{ '/' | relative_url }}" aria-label="{{ site.title | escape }}">
    AFK'S BLOG
  </a>
  <nav class="site-nav" aria-label="Primary navigation">
    <a href="{{ '/' | relative_url }}">Posts</a>
    <a href="{{ '/archives/' | relative_url }}">Archive</a>
    <a href="{{ '/tags/' | relative_url }}">Tags</a>
    <a href="{{ '/about/' | relative_url }}">About</a>
  </nav>
</header>
```

- [ ] **Step 3: Create the footer include**

Create `_includes/site-footer.html`:

```liquid
<footer class="site-footer">
  <span>{{ site.time | date: '%Y' }}</span>
  <span>{{ site.title }}</span>
  {% if site.github.username %}
    <a href="https://github.com/{{ site.github.username }}">GitHub</a>
  {% endif %}
</footer>
```

- [ ] **Step 4: Update site metadata**

Modify `_config.yml`:

```yaml
description: >-
  A small personal archive of posts, notes, reviews, and fragments.

theme_mode: light
```

Keep `theme: jekyll-theme-chirpy`, `url`, `baseurl`, `collections`, `defaults`, `jekyll-archives`, and existing post permalink settings unchanged.

- [ ] **Step 5: Build to verify Liquid includes resolve**

Run:

```bash
bundle exec jekyll build
```

Expected: build succeeds, or local Ruby reports the existing native extension issue (`eventmachine`, `racc`, or `http_parser.rb`). If native extensions fail locally, record that and continue implementation; GitHub Actions uses Ruby 3 with bundler cache.

- [ ] **Step 6: Commit**

```bash
git add _layouts/default.html _includes/site-header.html _includes/site-footer.html _config.yml
git commit -m "feat: add personal archive site shell"
```

---

### Task 2: Shared Numbered Post Index

**Files:**
- Create: `_includes/post-index.html`

- [ ] **Step 1: Create reusable numbered post list**

Create `_includes/post-index.html`:

```liquid
{% assign posts = include.posts | default: site.posts %}
{% assign empty_text = include.empty_text | default: 'No posts yet.' %}

{% if posts and posts.size > 0 %}
  <ol class="post-index" aria-label="{{ include.label | default: 'Posts' }}">
    {% for post in posts %}
      <li class="post-index__item">
        <a class="post-index__link" href="{{ post.url | relative_url }}">
          <span class="post-index__number">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
          <span class="post-index__title">{{ post.title }}</span>
          <time class="post-index__date" datetime="{{ post.date | date_to_xmlschema }}">
            {{ post.date | date: '%Y.%m.%d' }}
          </time>
        </a>
      </li>
    {% endfor %}
  </ol>
{% else %}
  <p class="empty-state">{{ empty_text }}</p>
{% endif %}
```

- [ ] **Step 2: Build to verify include syntax**

Run:

```bash
bundle exec jekyll build
```

Expected: build succeeds, or only the known local Ruby native extension issue appears.

- [ ] **Step 3: Commit**

```bash
git add _includes/post-index.html
git commit -m "feat: add numbered post index include"
```

---

### Task 3: Home Page Archive Gallery

**Files:**
- Create: `_layouts/home.html`
- Create: `_includes/page-links.html`

- [ ] **Step 1: Create page links include**

Create `_includes/page-links.html`:

```liquid
<section class="page-links" aria-label="Site sections">
  <a class="page-link-card" href="{{ '/archives/' | relative_url }}">
    <span class="page-link-card__number">01</span>
    <span class="page-link-card__title">Archive</span>
    <span class="page-link-card__text">按年份浏览留下来的文章。</span>
  </a>
  <a class="page-link-card" href="{{ '/tags/' | relative_url }}">
    <span class="page-link-card__number">02</span>
    <span class="page-link-card__title">Tags</span>
    <span class="page-link-card__text">按标签进入不同主题。</span>
  </a>
  <a class="page-link-card" href="{{ '/about/' | relative_url }}">
    <span class="page-link-card__number">03</span>
    <span class="page-link-card__title">About</span>
    <span class="page-link-card__text">一点关于我和这个博客。</span>
  </a>
</section>
```

- [ ] **Step 2: Create home layout**

Create `_layouts/home.html`:

```liquid
---
layout: default
---

{% assign visible_posts = site.posts | where_exp: 'post', 'post.hidden != true' %}

<section class="home-hero">
  <p class="eyebrow">WRITING ARCHIVE</p>
  <h1>A small archive of days.</h1>
  <p class="home-hero__intro">
    这里放文章、想法、复盘和一些长期留下来的记录。首页不强调单一主题，而是让内容自己形成索引。
  </p>
  <div class="current-index" aria-label="Current writing index">
    <span class="current-index__label">CURRENT INDEX</span>
    <span class="current-index__line current-index__line--muted">$ tail -f latest.log</span>
    <span class="current-index__line current-index__line--accent">writing, learning, wandering_</span>
  </div>
</section>

<section class="latest-posts">
  <div class="section-label">LATEST POSTS</div>
  <div class="section-content">
    {% include post-index.html posts=visible_posts label='Latest posts' empty_text='No posts yet.' %}
  </div>
</section>

{% include page-links.html %}
```

- [ ] **Step 3: Build and inspect generated home**

Run:

```bash
bundle exec jekyll build
```

Expected: `_site/index.html` contains `A small archive of days.`, `$ tail -f latest.log`, and at least the current post titles.

- [ ] **Step 4: Commit**

```bash
git add _layouts/home.html _includes/page-links.html
git commit -m "feat: add archive gallery home layout"
```

---

### Task 4: Generic Pages And About Page Presentation

**Files:**
- Create: `_layouts/page.html`
- Modify: `_tabs/about.md`

- [ ] **Step 1: Create page layout**

Create `_layouts/page.html`:

```liquid
---
layout: default
---

<article class="archive-page">
  <header class="page-heading">
    <p class="eyebrow">{{ page.title | default: 'Page' | upcase }}</p>
    <h1>{{ page.title }}</h1>
  </header>
  <div class="content prose">
    {{ content }}
  </div>
</article>
```

- [ ] **Step 2: Rewrite About content as personal archive copy**

Modify `_tabs/about.md` body after front matter:

```markdown
这里是 AFK 的个人博客。

我会在这里放文章、想法、复盘，以及一些长期留下来的记录。主题不会被固定在某一个方向，更多是把某段时间认真看过、做过、想过的东西整理下来。

保持写作，保持往上走。
```

Keep the existing front matter:

```yaml
---
icon: fas fa-info-circle
order: 4
---
```

- [ ] **Step 3: Build and verify about page**

Run:

```bash
bundle exec jekyll build
```

Expected: `_site/about/index.html` contains `这里是 AFK 的个人博客。`.

- [ ] **Step 4: Commit**

```bash
git add _layouts/page.html _tabs/about.md
git commit -m "feat: restyle generic pages"
```

---

### Task 5: Archive, Tags, And Categories Index Layouts

**Files:**
- Create: `_layouts/archives.html`
- Create: `_layouts/tags.html`
- Create: `_layouts/tag.html`
- Create: `_layouts/categories.html`
- Create: `_layouts/category.html`

- [ ] **Step 1: Create year archive layout**

Create `_layouts/archives.html`:

```liquid
---
layout: page
---

<div class="archive-list">
  {% for post in site.posts %}
    {% assign current_year = post.date | date: '%Y' %}
    {% if current_year != previous_year %}
      {% unless forloop.first %}</ol></section>{% endunless %}
      <section class="archive-year">
        <h2>{{ current_year }}</h2>
        <ol class="post-index post-index--compact">
      {% assign previous_year = current_year %}
    {% endif %}
          <li class="post-index__item">
            <a class="post-index__link" href="{{ post.url | relative_url }}">
              <span class="post-index__number">{{ forloop.index | prepend: '0' | slice: -2, 2 }}</span>
              <span class="post-index__title">{{ post.title }}</span>
              <time class="post-index__date" datetime="{{ post.date | date_to_xmlschema }}">
                {{ post.date | date: '%Y.%m.%d' }}
              </time>
            </a>
          </li>
    {% if forloop.last %}</ol></section>{% endif %}
  {% endfor %}
</div>
```

- [ ] **Step 2: Create tags landing layout**

Create `_layouts/tags.html`:

```liquid
---
layout: page
---

<div class="term-grid">
  {% assign sorted_tags = site.tags | sort %}
  {% for tag in sorted_tags %}
    {% assign tag_name = tag[0] %}
    {% assign tag_posts = tag[1] %}
    <a class="term-card" href="{{ '/tags/' | append: tag_name | slugify | append: '/' | relative_url }}">
      <span class="term-card__name">{{ tag_name }}</span>
      <span class="term-card__count">{{ tag_posts.size }} posts</span>
    </a>
  {% endfor %}
</div>
```

- [ ] **Step 3: Create single tag layout**

Create `_layouts/tag.html`:

```liquid
---
layout: page
---

{% assign tag_posts = site.tags[page.title] | default: page.posts %}
{% include post-index.html posts=tag_posts label=page.title empty_text='No posts for this tag.' %}
```

- [ ] **Step 4: Create categories landing layout**

Create `_layouts/categories.html`:

```liquid
---
layout: page
---

<div class="term-grid">
  {% assign sorted_categories = site.categories | sort %}
  {% for category in sorted_categories %}
    {% assign category_name = category[0] %}
    {% assign category_posts = category[1] %}
    <a class="term-card" href="{{ '/categories/' | append: category_name | slugify | append: '/' | relative_url }}">
      <span class="term-card__name">{{ category_name }}</span>
      <span class="term-card__count">{{ category_posts.size }} posts</span>
    </a>
  {% endfor %}
</div>
```

- [ ] **Step 5: Create single category layout**

Create `_layouts/category.html`:

```liquid
---
layout: page
---

{% assign category_posts = site.categories[page.title] | default: page.posts %}
{% include post-index.html posts=category_posts label=page.title empty_text='No posts for this category.' %}
```

- [ ] **Step 6: Build and verify archive outputs**

Run:

```bash
bundle exec jekyll build
```

Expected: `_site/archives/index.html`, `_site/tags/index.html`, and `_site/categories/index.html` build without Liquid errors. Tag/category detail pages generated by `jekyll-archives` still resolve.

- [ ] **Step 7: Commit**

```bash
git add _layouts/archives.html _layouts/tags.html _layouts/tag.html _layouts/categories.html _layouts/category.html
git commit -m "feat: add archive taxonomy layouts"
```

---

### Task 6: Article Layout

**Files:**
- Create: `_layouts/post.html`

- [ ] **Step 1: Create post layout**

Create `_layouts/post.html`:

```liquid
---
layout: default
---

<article class="post-page">
  <header class="post-hero">
    <p class="eyebrow">ARTICLE</p>
    <h1>{{ page.title }}</h1>
    <div class="post-meta">
      <time datetime="{{ page.date | date_to_xmlschema }}">{{ page.date | date: '%Y.%m.%d' }}</time>
      {% if page.categories.size > 0 %}
        <span>{{ page.categories | join: ' / ' }}</span>
      {% endif %}
    </div>
    {% if page.tags.size > 0 %}
      <div class="tag-row" aria-label="Tags">
        {% for tag in page.tags %}
          <a href="{{ '/tags/' | append: tag | slugify | append: '/' | relative_url }}">{{ tag }}</a>
        {% endfor %}
      </div>
    {% endif %}
  </header>

  <div class="post-shell">
    <div class="content prose">
      {{ content }}
    </div>
    {% if page.toc %}
      <aside class="post-toc" aria-label="Contents">
        <div class="post-toc__title">CONTENTS</div>
        {% include toc.html html=content %}
      </aside>
    {% endif %}
  </div>

  <nav class="post-nav" aria-label="Post navigation">
    {% if page.previous %}
      <a href="{{ page.previous.url | relative_url }}">
        <span>PREV</span>
        {{ page.previous.title }}
      </a>
    {% endif %}
    {% if page.next %}
      <a href="{{ page.next.url | relative_url }}">
        <span>NEXT</span>
        {{ page.next.title }}
      </a>
    {% endif %}
  </nav>
</article>
```

- [ ] **Step 2: Build and verify a real post**

Run:

```bash
bundle exec jekyll build
```

Expected: `_site/posts/sql注入总结/index.html` or the generated equivalent contains `ARTICLE`, post date, tags, and body content.

- [ ] **Step 3: Commit**

```bash
git add _layouts/post.html
git commit -m "feat: add personal archive post layout"
```

---

### Task 7: Visual System SCSS

**Files:**
- Create: `assets/css/personal-archive.scss`

- [ ] **Step 1: Create SCSS entrypoint**

Create `assets/css/personal-archive.scss`:

```scss
---
---

:root {
  --archive-bg: #f6f3ec;
  --archive-text: #000;
  --archive-muted: #686258;
  --archive-soft: #948e83;
  --archive-line: #000;
  --archive-rule: #ded9cf;
  --archive-accent: #d88a2d;
  --archive-dark: #050505;
  --archive-max: 1100px;
  --archive-mono: Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  --archive-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
}

* {
  box-sizing: border-box;
}

html {
  background: #1f1f22;
  color: var(--archive-text);
  font-family: var(--archive-sans);
  line-height: 1.5;
}

body {
  min-width: 320px;
  margin: 0;
  background: var(--archive-bg);
  color: var(--archive-text);
  -webkit-font-smoothing: antialiased;
}

a {
  color: inherit;
  text-decoration: none;
}

.site-header,
.site-main,
.site-footer {
  width: min(var(--archive-max), calc(100% - 32px));
  margin: 0 auto;
  background: var(--archive-bg);
}

.site-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 54px;
  border: 1px solid var(--archive-line);
  border-bottom: 0;
  font-family: var(--archive-mono);
  font-size: 11px;
  letter-spacing: .18em;
}

.site-brand,
.site-nav a {
  display: inline-flex;
  align-items: center;
  min-height: 54px;
  padding: 0 22px;
}

.site-nav {
  display: flex;
  align-items: center;
}

.site-nav a:hover,
.post-index__link:hover,
.page-link-card:hover,
.term-card:hover {
  color: var(--archive-accent);
}

.site-main {
  border: 1px solid var(--archive-line);
}

.site-footer {
  display: flex;
  gap: 18px;
  padding: 18px 22px 28px;
  border: 1px solid var(--archive-line);
  border-top: 0;
  color: var(--archive-soft);
  font-family: var(--archive-mono);
  font-size: 11px;
  letter-spacing: .12em;
}

.eyebrow,
.section-label,
.current-index__label {
  margin: 0;
  color: var(--archive-soft);
  font-family: var(--archive-mono);
  font-size: 11px;
  letter-spacing: .24em;
}

.home-hero {
  padding: clamp(48px, 8vw, 86px) clamp(28px, 5vw, 56px) clamp(36px, 6vw, 56px);
  border-bottom: 1px solid var(--archive-line);
}

.home-hero h1,
.page-heading h1,
.post-hero h1 {
  max-width: 760px;
  margin: 20px 0 0;
  font-size: clamp(42px, 7vw, 84px);
  font-weight: 620;
  line-height: .98;
  letter-spacing: 0;
}

.home-hero__intro {
  max-width: 620px;
  margin: 26px 0 0;
  color: var(--archive-muted);
  font-size: 15px;
  line-height: 1.85;
}

.current-index {
  display: grid;
  grid-template-columns: 170px 1fr;
  gap: 0;
  margin-top: 48px;
  padding: 18px 0;
  border-top: 1px solid var(--archive-line);
  border-bottom: 1px solid var(--archive-line);
}

.current-index__line {
  display: block;
  font-family: var(--archive-mono);
  font-size: 13px;
  line-height: 1.9;
}

.current-index__line--muted {
  color: var(--archive-soft);
}

.current-index__line--accent {
  color: var(--archive-accent);
}

.latest-posts,
.archive-year {
  display: grid;
  grid-template-columns: 220px 1fr;
  border-bottom: 1px solid var(--archive-line);
}

.section-label,
.archive-year h2 {
  padding: 26px 22px;
  border-right: 1px solid var(--archive-line);
  font-weight: 400;
}

.post-index {
  padding: 0;
  margin: 0;
  list-style: none;
}

.post-index__link {
  display: grid;
  grid-template-columns: 52px 1fr 130px;
  gap: 18px;
  align-items: center;
  min-height: 64px;
  padding: 0 22px;
  border-bottom: 1px solid var(--archive-rule);
  font-family: var(--archive-mono);
  font-size: 13px;
}

.post-index__item:last-child .post-index__link {
  border-bottom: 0;
}

.post-index__number {
  color: var(--archive-accent);
}

.post-index__date {
  color: var(--archive-soft);
  font-size: 11px;
  text-align: right;
}

.page-links,
.term-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
}

.page-link-card,
.term-card {
  min-height: 170px;
  padding: 22px;
  border-right: 1px solid var(--archive-line);
}

.page-link-card:last-child,
.term-card:nth-child(3n) {
  border-right: 0;
}

.page-link-card__number {
  display: block;
  margin-bottom: 18px;
  color: var(--archive-accent);
  font-family: var(--archive-mono);
  font-size: 12px;
}

.page-link-card__title,
.term-card__name {
  display: block;
  font-family: var(--archive-mono);
  font-size: 13px;
  letter-spacing: .14em;
  text-transform: uppercase;
}

.page-link-card__text,
.term-card__count {
  display: block;
  margin-top: 14px;
  color: var(--archive-muted);
  font-size: 13px;
  line-height: 1.75;
}

.archive-page,
.post-page {
  padding: clamp(34px, 5vw, 56px);
}

.page-heading {
  padding-bottom: 34px;
  border-bottom: 1px solid var(--archive-line);
}

.prose {
  max-width: 760px;
  color: var(--archive-text);
  font-size: 16px;
  line-height: 1.9;
}

.prose a {
  text-decoration: underline;
  text-decoration-thickness: 1px;
  text-underline-offset: 4px;
}

.prose img {
  max-width: 100%;
  height: auto;
  border: 1px solid var(--archive-line);
}

.prose pre,
.prose code {
  font-family: var(--archive-mono);
}

.prose pre {
  overflow-x: auto;
  padding: 18px;
  background: var(--archive-dark);
  color: var(--archive-bg);
}

.post-meta,
.tag-row {
  display: flex;
  flex-wrap: wrap;
  gap: 10px 16px;
  margin-top: 18px;
  color: var(--archive-soft);
  font-family: var(--archive-mono);
  font-size: 12px;
}

.tag-row a {
  padding: 6px 9px;
  border: 1px solid var(--archive-line);
  color: var(--archive-text);
}

.post-shell {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 220px;
  gap: 42px;
  margin-top: 42px;
}

.post-toc {
  position: sticky;
  top: 24px;
  align-self: start;
  padding: 16px;
  border: 1px solid var(--archive-line);
  font-family: var(--archive-mono);
  font-size: 11px;
}

.post-toc__title {
  margin-bottom: 12px;
  color: var(--archive-soft);
  letter-spacing: .18em;
}

.post-toc ul {
  padding-left: 16px;
  margin: 0;
}

.post-nav {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin-top: 46px;
}

.post-nav a {
  padding: 16px;
  border: 1px solid var(--archive-line);
}

.post-nav span {
  display: block;
  margin-bottom: 8px;
  color: var(--archive-soft);
  font-family: var(--archive-mono);
  font-size: 11px;
  letter-spacing: .18em;
}

.empty-state {
  padding: 22px;
  color: var(--archive-muted);
}

@media (max-width: 820px) {
  .site-header {
    align-items: flex-start;
    flex-direction: column;
  }

  .site-brand,
  .site-nav a {
    min-height: 42px;
    padding: 0 16px;
  }

  .site-nav {
    flex-wrap: wrap;
  }

  .current-index,
  .latest-posts,
  .archive-year,
  .page-links,
  .term-grid,
  .post-shell,
  .post-nav {
    grid-template-columns: 1fr;
  }

  .section-label,
  .archive-year h2 {
    border-right: 0;
    border-bottom: 1px solid var(--archive-line);
  }

  .post-index__link {
    grid-template-columns: 42px 1fr;
    min-height: 70px;
  }

  .post-index__date {
    grid-column: 2;
    text-align: left;
  }

  .page-link-card,
  .term-card {
    border-right: 0;
    border-bottom: 1px solid var(--archive-line);
  }

  .post-toc {
    position: static;
  }
}
```

- [ ] **Step 2: Build and verify CSS output**

Run:

```bash
bundle exec jekyll build
```

Expected: `_site/assets/css/personal-archive.css` exists and contains `.home-hero`.

- [ ] **Step 3: Commit**

```bash
git add assets/css/personal-archive.scss
git commit -m "feat: add personal archive visual system"
```

---

### Task 8: Local Browser Verification And Polish

**Files:**
- Modify only files created in Tasks 1-7 if verification finds concrete layout bugs.

- [ ] **Step 1: Start local server**

Run:

```bash
bundle exec jekyll serve --host 127.0.0.1 --port 4000
```

Expected: server starts at `http://127.0.0.1:4000/`. If local native extension errors block serving, run `bundle pristine eventmachine racc http_parser.rb` once, then retry. If it still fails, use GitHub Actions as the build verifier and note local limitation.

- [ ] **Step 2: Verify pages in browser**

Open these URLs:

```text
http://127.0.0.1:4000/
http://127.0.0.1:4000/archives/
http://127.0.0.1:4000/tags/
http://127.0.0.1:4000/categories/
http://127.0.0.1:4000/about/
http://127.0.0.1:4000/posts/sql注入总结/
```

Expected:

- Home uses cream background and no black hero panel.
- Home current index shows only `$ tail -f latest.log` and `writing, learning, wandering_`.
- Latest posts are numbered and dated.
- Archive/tags/categories pages use line-based indexes.
- About page uses personal blog copy.
- Article page has readable cream body and dark code blocks.

- [ ] **Step 3: Verify mobile viewport**

Use a browser viewport near `390x844`.

Expected:

- Header nav wraps without horizontal overflow.
- Home title does not overlap the index.
- Post rows display number, title, and date without clipping.
- Article content, images, and code blocks do not overflow the viewport except code blocks using internal horizontal scroll.

- [ ] **Step 4: Run production build**

Run:

```bash
JEKYLL_ENV=production bundle exec jekyll build
```

Expected: production build succeeds, or only known local Ruby native extension issue appears.

- [ ] **Step 5: Commit polish fixes**

If verification required changes:

```bash
git add _layouts _includes assets/css/personal-archive.scss _tabs/about.md _config.yml
git commit -m "fix: polish personal archive layout"
```

If no changes were required, skip this commit.

---

## Self-Review Checklist

- Spec coverage: Tasks 1-7 cover the custom Jekyll theme layer, cream archive gallery home, lightweight two-line index, post layout, archive/tags/categories/about pages, visual system, responsive behavior, and build/browser checks.
- Placeholder scan: no `TBD`, `TODO`, or undefined “implement later” steps are present.
- Type and name consistency: all includes and layouts referenced by later tasks are created by earlier tasks; CSS path in `_layouts/default.html` matches `assets/css/personal-archive.scss`; home layout references `post-index.html` and `page-links.html`, both created before use.
