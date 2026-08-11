# Leavesongs-Style Night Reading Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the custom Jekyll theme layer into a leavesongs-inspired night-reading blog: About summary on the home page, plain post lists, and a full-site dark palette with warm gold accents.

**Architecture:** Keep Jekyll, Chirpy as a dependency, and existing Markdown/permalinks. Rewrite local `_layouts`, `_includes`, and `assets/css/personal-archive.scss` so the visible UI matches the approved spec without editing the gem.

**Tech Stack:** Jekyll 4, Liquid, SCSS, GitHub Pages Actions, existing `jekyll-theme-chirpy` gem.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-11-leavesongs-style-redesign-design.md`
- Palette locked: bg `#1c1f24`, text `#e7e2d8`, muted `#a39e93`, soft `#7a756c`, accent `#c9a227`, line `rgba(231, 226, 216, 0.12)`, surface `#23272e`
- Content width about `680–720px`, centered; serif body, sans nav/dates
- No numbered indexes, terminal lines, cream paper, or home entry cards
- Do not rewrite `_posts` content; do not change permalink/`jekyll-archives` config unless build breaks
- Keep CSS entry filename `assets/css/personal-archive.scss`
- Local build may need `arch -x86_64` / vendor bundle on this Mac; GitHub Actions is the production verifier

---

## File Map

- Modify: `_layouts/default.html` — theme-color and body class remain; point stays on personal-archive.css
- Modify: `_includes/site-header.html` — brand/nav copy for reading-site tone
- Modify: `_includes/post-index.html` — title + date list, no numbers
- Modify: `_layouts/home.html` — About summary + latest posts only
- Modify: `_layouts/archives.html` — year groups without numbers
- Modify: `_layouts/page.html` — quieter page heading
- Modify: `_layouts/post.html` — keep TOC behavior; quiet hero
- Modify: `assets/css/personal-archive.scss` — full night-reading visual system
- Optional delete after unused: `_includes/page-links.html`

---

### Task 1: Base Chrome And Theme Color

**Files:**
- Modify: `_layouts/default.html`
- Modify: `_includes/site-header.html`

- [ ] **Step 1: Update theme-color to night background**

In `_layouts/default.html`, change:

```html
<meta name="theme-color" content="#f6f3ec">
```

to:

```html
<meta name="theme-color" content="#1c1f24">
```

- [ ] **Step 2: Soften header brand copy**

Replace `_includes/site-header.html` with:

```liquid
<header class="site-header">
  <a class="site-brand" href="{{ '/' | relative_url }}" aria-label="{{ site.title | escape }}">
    AFK's Blog
  </a>
  <nav class="site-nav" aria-label="Primary navigation">
    <a href="{{ '/' | relative_url }}">Posts</a>
    <a href="{{ '/archives/' | relative_url }}">Archive</a>
    <a href="{{ '/tags/' | relative_url }}">Tags</a>
    <a href="{{ '/about/' | relative_url }}">About</a>
  </nav>
</header>
```

- [ ] **Step 3: Commit**

```bash
git add _layouts/default.html _includes/site-header.html
git commit -m "style: set night-reading chrome and theme color"
```

---

### Task 2: Plain Post Index Include

**Files:**
- Modify: `_includes/post-index.html`

- [ ] **Step 1: Remove numbering from the reusable list**

Replace `_includes/post-index.html` with:

```liquid
{% assign posts = include.posts | default: site.posts %}
{% assign empty_text = include.empty_text | default: 'No posts yet.' %}

{% if posts and posts.size > 0 %}
  <ul class="post-index" aria-label="{{ include.label | default: 'Posts' }}">
    {% for post in posts %}
      <li class="post-index__item">
        <a class="post-index__link" href="{{ post.url | relative_url }}">
          <span class="post-index__title">{{ post.title }}</span>
          <time class="post-index__date" datetime="{{ post.date | date_to_xmlschema }}">
            {{ post.date | date: '%Y.%m.%d' }}
          </time>
        </a>
      </li>
    {% endfor %}
  </ul>
{% else %}
  <p class="empty-state">{{ empty_text }}</p>
{% endif %}
```

- [ ] **Step 2: Build and verify numbers are gone from home markup path**

Run:

```bash
export GEM_HOME="$HOME/.gem"
export PATH="$HOME/.gem/bin:$PATH"
arch -x86_64 bundle exec jekyll build
```

If native/platform issues block local build, note them and continue; GitHub Actions remains the gate.

Expected after later home/CSS tasks land: generated lists use `ul.post-index` and contain titles/dates without `post-index__number`.

- [ ] **Step 3: Commit**

```bash
git add _includes/post-index.html
git commit -m "feat: use plain title-date post index"
```

---

### Task 3: Home Page About Summary And Posts

**Files:**
- Modify: `_layouts/home.html`
- Stop using: `_includes/page-links.html` on home

- [ ] **Step 1: Rewrite home layout**

Replace `_layouts/home.html` with:

```liquid
---
layout: default
---

{% assign visible_posts = site.posts | where_exp: 'post', 'post.hidden != true' %}
{% assign about_page = nil %}
{% for tab in site.tabs %}
  {% if tab.url == '/about/' or tab.slug == 'about' %}
    {% assign about_page = tab %}
  {% endif %}
{% endfor %}

<section class="home-intro" aria-label="About summary">
  <div class="home-intro__body prose">
    {% if about_page %}
      {{ about_page.content }}
    {% else %}
      <p>{{ site.description }}</p>
    {% endif %}
  </div>
  <a class="home-intro__more" href="{{ '/about/' | relative_url }}">完整 About →</a>
</section>

<section class="latest-posts" aria-label="Latest posts">
  <h2 class="section-label">Posts</h2>
  {% include post-index.html posts=visible_posts label='Latest posts' empty_text='No posts yet.' %}
</section>
```

- [ ] **Step 2: Build and inspect home HTML**

Run:

```bash
export GEM_HOME="$HOME/.gem"
export PATH="$HOME/.gem/bin:$PATH"
arch -x86_64 bundle exec jekyll build
```

Then verify:

```bash
rg -n "完整 About|home-intro|current-index|page-link-card|A small archive of days" _site/index.html
```

Expected:
- Contains `home-intro` and `完整 About`
- Contains About copy such as `这里是 AFK 的个人博客`
- Does **not** contain `current-index`, `page-link-card`, or `A small archive of days`

- [ ] **Step 3: Commit**

```bash
git add _layouts/home.html
git commit -m "feat: rebuild home as about summary plus posts"
```

---

### Task 4: Archive And Page Layout Cleanup

**Files:**
- Modify: `_layouts/archives.html`
- Modify: `_layouts/page.html`
- Modify: `_layouts/post.html`

- [ ] **Step 1: Remove numbers from archive year lists**

Replace `_layouts/archives.html` with:

```liquid
---
layout: page
---

<div class="archive-list">
  {% for post in site.posts %}
    {% assign current_year = post.date | date: '%Y' %}
    {% if current_year != previous_year %}
      {% unless forloop.first %}</ul></section>{% endunless %}
      <section class="archive-year">
        <h2>{{ current_year }}</h2>
        <ul class="post-index post-index--compact">
      {% assign previous_year = current_year %}
    {% endif %}
          <li class="post-index__item">
            <a class="post-index__link" href="{{ post.url | relative_url }}">
              <span class="post-index__title">{{ post.title }}</span>
              <time class="post-index__date" datetime="{{ post.date | date_to_xmlschema }}">
                {{ post.date | date: '%Y.%m.%d' }}
              </time>
            </a>
          </li>
    {% if forloop.last %}</ul></section>{% endif %}
  {% endfor %}
</div>
```

- [ ] **Step 2: Quiet page heading**

Replace `_layouts/page.html` with:

```liquid
---
layout: default
---

<article class="archive-page">
  <header class="page-heading">
    <h1>{{ page.title }}</h1>
  </header>
  <div class="content prose">
    {{ content }}
  </div>
</article>
```

- [ ] **Step 3: Quiet post hero (keep TOC shell)**

Replace `_layouts/post.html` with:

```liquid
---
layout: default
---

<article class="post-page">
  <header class="post-hero">
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
          {% assign tag_slug = tag | slugify %}
          <a href="{{ '/tags/' | append: tag_slug | append: '/' | relative_url }}">{{ tag }}</a>
        {% endfor %}
      </div>
    {% endif %}
  </header>

  {% if page.toc %}
    <aside class="post-toc post-toc--mobile" aria-label="Contents">
      <div class="post-toc__title">CONTENTS</div>
      <nav class="post-toc__nav post-toc__nav--mobile" aria-label="Contents"></nav>
    </aside>
  {% endif %}

  <div class="post-shell">
    <div class="content prose">
      {{ content }}
    </div>
    {% if page.toc %}
      <aside class="post-toc post-toc--desktop" aria-label="Contents">
        <div class="post-toc__title">CONTENTS</div>
        <nav id="toc" class="post-toc__nav" aria-label="Contents"></nav>
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

Note: existing `assets/js/personal-archive.js` fills `#toc`. Keep that script hook in `default.html`. CSS in Task 5 must hide `.post-toc--mobile` on desktop and `.post-toc--desktop` on small screens, and ensure only one nav is populated — prefer keeping a single `#toc` in the desktop aside and let mobile CSS reorder/show the same aside before content if simpler.

**Simpler TOC alternative (preferred if JS only targets `#toc`):** keep one TOC aside inside `.post-shell` as today; use CSS `order` / media queries so on mobile the TOC appears above content without a second markup block. If choosing the simpler path, keep the current single-aside `post.html` structure and only remove the `ARTICLE` eyebrow:

```liquid
<header class="post-hero">
  <h1>{{ page.title }}</h1>
  ...
</header>
```

Use the simpler single-TOC path unless dual markup is required for layout.

- [ ] **Step 4: Commit**

```bash
git add _layouts/archives.html _layouts/page.html _layouts/post.html
git commit -m "feat: quiet archive and article page chrome"
```

---

### Task 5: Night-Reading Visual System SCSS

**Files:**
- Modify: `assets/css/personal-archive.scss` (full rewrite of styles; keep filename)

- [ ] **Step 1: Replace SCSS with night-reading system**

Overwrite `assets/css/personal-archive.scss` with:

```scss
---
---

:root {
  --archive-bg: #1c1f24;
  --archive-surface: #23272e;
  --archive-text: #e7e2d8;
  --archive-muted: #a39e93;
  --archive-soft: #7a756c;
  --archive-accent: #c9a227;
  --archive-line: rgba(231, 226, 216, 0.12);
  --archive-max: 720px;
  --archive-gutter: clamp(20px, 4vw, 28px);
  --archive-mono: Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  --archive-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
  --archive-serif: "Noto Serif SC", "Source Han Serif SC", "Songti SC", "SimSun", Georgia, serif;
}

* {
  box-sizing: border-box;
}

html {
  background: var(--archive-bg);
  color: var(--archive-text);
  font-family: var(--archive-serif);
  line-height: 1.75;
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
  width: min(var(--archive-max), 100%);
  margin: 0 auto;
  padding-left: var(--archive-gutter);
  padding-right: var(--archive-gutter);
}

.site-header {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 16px;
  min-height: 0;
  margin-top: 28px;
  padding-bottom: 18px;
  border-bottom: 1px solid var(--archive-line);
  font-family: var(--archive-sans);
  font-size: 14px;
}

.site-brand {
  font-weight: 600;
}

.site-nav {
  display: flex;
  flex-wrap: wrap;
  gap: 14px 18px;
}

.site-nav a,
.home-intro__more,
.footer a,
.post-index__link:hover .post-index__title,
.term-card:hover .term-card__name,
.tag-row a:hover,
.post-nav a:hover {
  color: var(--archive-muted);
}

.site-nav a:hover,
.home-intro__more:hover,
.post-index__link:hover .post-index__title,
.term-card:hover .term-card__name,
.tag-row a:hover,
.post-nav a:hover,
.site-footer a:hover {
  color: var(--archive-accent);
}

.site-footer {
  display: flex;
  gap: 16px;
  margin: 48px auto 40px;
  padding-top: 18px;
  border-top: 1px solid var(--archive-line);
  color: var(--archive-soft);
  font-family: var(--archive-sans);
  font-size: 12px;
}

.home-intro {
  padding: 48px 0 40px;
}

.home-intro__body.prose {
  max-width: none;
}

.home-intro__more {
  display: inline-block;
  margin-top: 8px;
  font-family: var(--archive-sans);
  font-size: 13px;
}

.section-label {
  margin: 0 0 18px;
  color: var(--archive-soft);
  font-family: var(--archive-sans);
  font-size: 13px;
  font-weight: 600;
  letter-spacing: .08em;
  text-transform: uppercase;
}

.latest-posts {
  padding-bottom: 24px;
}

.post-index {
  padding: 0;
  margin: 0;
  list-style: none;
  border-top: 1px solid var(--archive-line);
}

.post-index__link {
  display: flex;
  justify-content: space-between;
  gap: 20px;
  align-items: baseline;
  padding: 15px 0;
  border-bottom: 1px solid var(--archive-line);
  font-size: 16px;
}

.post-index__date {
  flex-shrink: 0;
  color: var(--archive-soft);
  font-family: var(--archive-sans);
  font-size: 13px;
}

.archive-page,
.post-page {
  padding: 40px 0 24px;
}

.page-heading,
.post-hero {
  margin-bottom: 28px;
  padding-bottom: 22px;
  border-bottom: 1px solid var(--archive-line);
}

.page-heading h1,
.post-hero h1 {
  margin: 0;
  font-size: clamp(28px, 5vw, 40px);
  font-weight: 600;
  line-height: 1.25;
}

.prose {
  max-width: 720px;
  color: var(--archive-text);
  font-size: 17px;
  line-height: 1.9;
}

.prose a {
  color: var(--archive-accent);
  text-decoration: underline;
  text-decoration-thickness: 1px;
  text-underline-offset: 3px;
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
  padding: 16px;
  background: #12151a;
  color: var(--archive-text);
  border: 1px solid var(--archive-line);
}

.prose :not(pre) > code {
  padding: .1em .35em;
  background: var(--archive-surface);
  border-radius: 3px;
  font-size: .9em;
}

.post-meta,
.tag-row {
  display: flex;
  flex-wrap: wrap;
  gap: 10px 16px;
  margin-top: 14px;
  color: var(--archive-soft);
  font-family: var(--archive-sans);
  font-size: 13px;
}

.tag-row a {
  padding: 4px 8px;
  border: 1px solid var(--archive-line);
  color: var(--archive-muted);
}

.post-shell {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 200px;
  gap: 36px;
  margin-top: 28px;
}

.post-toc {
  position: sticky;
  top: 24px;
  align-self: start;
  padding: 14px;
  border: 1px solid var(--archive-line);
  font-family: var(--archive-sans);
  font-size: 12px;
}

.post-toc__title {
  margin-bottom: 10px;
  color: var(--archive-soft);
  letter-spacing: .12em;
}

.post-toc[hidden] {
  display: none;
}

.post-toc__nav {
  display: grid;
  gap: 8px;
}

.post-toc__link {
  display: block;
  color: var(--archive-muted);
  line-height: 1.55;
}

.post-toc__link:hover {
  color: var(--archive-accent);
}

.post-toc__link--h3 {
  padding-left: 12px;
}

.post-toc__link--h4 {
  padding-left: 24px;
}

.post-nav {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin-top: 40px;
}

.post-nav a {
  padding: 14px;
  border: 1px solid var(--archive-line);
  font-family: var(--archive-sans);
  font-size: 14px;
}

.post-nav span {
  display: block;
  margin-bottom: 8px;
  color: var(--archive-soft);
  font-size: 11px;
  letter-spacing: .12em;
}

.archive-year {
  margin-bottom: 28px;
}

.archive-year h2 {
  margin: 0 0 12px;
  color: var(--archive-soft);
  font-family: var(--archive-sans);
  font-size: 13px;
  font-weight: 600;
  letter-spacing: .08em;
}

.term-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 12px;
}

.term-card {
  padding: 16px;
  border: 1px solid var(--archive-line);
}

.term-card__name {
  display: block;
  font-family: var(--archive-sans);
  font-size: 14px;
}

.term-card__count {
  display: block;
  margin-top: 8px;
  color: var(--archive-soft);
  font-family: var(--archive-sans);
  font-size: 12px;
}

.empty-state {
  padding: 18px 0;
  color: var(--archive-muted);
  font-family: var(--archive-sans);
}

@media (max-width: 820px) {
  .site-header {
    flex-direction: column;
    align-items: flex-start;
  }

  .post-shell,
  .post-nav {
    grid-template-columns: 1fr;
  }

  .post-toc {
    position: static;
    order: -1;
  }

  .post-shell {
    display: flex;
    flex-direction: column;
  }

  .post-index__link {
    flex-direction: column;
    gap: 4px;
  }
}
```

- [ ] **Step 2: Build and verify CSS tokens**

Run:

```bash
export GEM_HOME="$HOME/.gem"
export PATH="$HOME/.gem/bin:$PATH"
arch -x86_64 bundle exec jekyll build
rg -n "1c1f24|c9a227|home-intro|f6f3ec" _site/assets/css/personal-archive.css
```

Expected:
- Contains `#1c1f24` and `#c9a227` / `c9a227`
- Contains `.home-intro`
- Does **not** contain `#f6f3ec`

- [ ] **Step 3: Commit**

```bash
git add assets/css/personal-archive.scss
git commit -m "feat: apply night-reading warm-gold visual system"
```

---

### Task 6: Cleanup Unused Include And Full Verification

**Files:**
- Delete if unused: `_includes/page-links.html`
- Verify generated site pages

- [ ] **Step 1: Remove unused page-links include**

```bash
rg -n "page-links" _layouts _includes
```

If only the include file itself remains, delete it:

```bash
git rm _includes/page-links.html
```

- [ ] **Step 2: Production build**

Run:

```bash
export GEM_HOME="$HOME/.gem"
export PATH="$HOME/.gem/bin:$PATH"
JEKYLL_ENV=production arch -x86_64 bundle exec jekyll build
```

Expected: build succeeds, or only the known local Ruby platform issue appears.

- [ ] **Step 3: Content acceptance checks**

```bash
rg -n "这里是 AFK 的个人博客|完整 About|post-index__number|current-index|page-link-card|A small archive of days" _site/index.html
rg -n "1c1f24" _site/assets/css/personal-archive.css
test -f _site/about/index.html && test -f _site/archives/index.html && test -f _site/tags/index.html
```

Expected on home:
- About summary present
- No numbers/terminal/cards/old hero headline

- [ ] **Step 4: Manual browser pass**

Serve:

```bash
export GEM_HOME="$HOME/.gem"
export PATH="$HOME/.gem/bin:$PATH"
arch -x86_64 bundle exec jekyll serve --host 127.0.0.1 --port 4000
```

Open:
- `http://127.0.0.1:4000/`
- `http://127.0.0.1:4000/about/`
- `http://127.0.0.1:4000/archives/`
- `http://127.0.0.1:4000/tags/`
- one post URL under `/posts/`

Check desktop and ~390px width:
- Night background, warm-gold hover
- No horizontal overflow except code block internal scroll
- TOC not sticky-covering content on mobile

- [ ] **Step 5: Commit cleanup**

```bash
git add -A _includes _layouts assets/css
git status --short
git commit -m "chore: remove unused home cards include after redesign"
```

Skip this commit if Step 1 found no file to delete and no further diffs.

---

## Self-Review Checklist

- Spec coverage: home About summary, plain posts, night-gold palette, full-site layouts, removed cream/terminal/numbers/cards, TOC behavior, mobile rules, build verification — each mapped to Tasks 1–6.
- Placeholder scan: no TBD/TODO/implement-later steps; concrete Liquid/SCSS and commands included.
- Name consistency: CSS file remains `personal-archive.scss` → `/assets/css/personal-archive.css`; home uses `home-intro` + `post-index.html`; accent token `--archive-accent: #c9a227`.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-11-leavesongs-style-redesign.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks
2. **Inline Execution** — run tasks in this session with executing-plans and checkpoints

Which approach?
