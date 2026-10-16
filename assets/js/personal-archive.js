(function () {
  // 1. TOC 目录生成逻辑
  function initToc() {
    var toc = document.getElementById('toc');
    var content = document.querySelector('.content');

    if (!toc || !content) {
      return;
    }

    var headings = Array.prototype.slice.call(
      content.querySelectorAll('h1, h2, h3, h4')
    ).filter(function (heading) {
      return !heading.hasAttribute('data-toc-skip') && heading.textContent.trim();
    });

    if (headings.length === 0) {
      var wrapper = toc.closest('.post-toc');
      if (wrapper) {
        wrapper.hidden = true;
      }
      return;
    }

    headings.forEach(function (heading, index) {
      if (!heading.id) {
        heading.id = 'section-' + String(index + 1);
      }

      var link = document.createElement('a');
      var level = heading.tagName.toLowerCase();

      link.className = 'post-toc__link post-toc__link--' + level;
      link.href = '#' + encodeURIComponent(heading.id);
      link.textContent = heading.textContent.trim();

      toc.appendChild(link);
    });
  }

  // 2. 解析 GitHub 风格 Callout 提示框：[!TIP], [!NOTE], [!WARNING] 等
  function initCallouts() {
    var blockquotes = document.querySelectorAll('.prose blockquote');
    var alertTypes = {
      tip: {
        title: '提示 (Tip)',
        icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-.9 1.5-2.2 1.5-3.5A6 6 0 0 0 6 8c0 1 .2 2.2 1.5 3.5.7.7 1.3 1.5 1.5 2.5"/><path d="M9 18h6"/><path d="M10 22h4"/></svg>'
      },
      note: {
        title: '说明 (Note)',
        icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
      },
      warning: {
        title: '警告 (Warning)',
        icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
      },
      important: {
        title: '重要 (Important)',
        icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
      },
      caution: {
        title: '危险 (Caution)',
        icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
      }
    };

    blockquotes.forEach(function (bq) {
      var firstP = bq.querySelector('p');
      if (!firstP) return;

      var rawHtml = firstP.innerHTML;
      var match = rawHtml.match(/^\s*\[!(TIP|NOTE|WARNING|IMPORTANT|CAUTION)\]\s*(.*)/i);
      if (!match) return;

      var typeKey = match[1].toLowerCase();
      var meta = alertTypes[typeKey];
      if (!meta) return;

      bq.classList.add('callout', 'callout--' + typeKey);

      var remainingContent = match[2];
      if (remainingContent.trim()) {
        firstP.innerHTML = remainingContent;
      } else {
        firstP.remove();
      }

      var header = document.createElement('div');
      header.className = 'callout__title';
      header.innerHTML = meta.icon + '<span>' + meta.title + '</span>';
      bq.insertBefore(header, bq.firstChild);
    });
  }

  // 3. 优化 Rouge 代码块：将行号与代码行逐行绑定，避免换行时错位与两列分离
  function initCodeBlocks() {
    var rougeTables = document.querySelectorAll('.prose .rouge-table');
    rougeTables.forEach(function (table) {
      var gutterPre = table.querySelector('.rouge-gutter pre');
      var codePre = table.querySelector('.rouge-code pre');
      if (!gutterPre || !codePre) return;

      var gutterText = gutterPre.innerText.trim();
      if (!gutterText) return;

      var lineNumbers = gutterText.split('\n');
      var codeHtml = codePre.innerHTML;
      var codeLines = codeHtml.split('\n');
      if (codeLines[codeLines.length - 1] === '') {
        codeLines.pop();
      }

      var tbody = document.createElement('tbody');
      var total = Math.max(lineNumbers.length, codeLines.length);

      for (var i = 0; i < total; i++) {
        var tr = document.createElement('tr');
        tr.className = 'rouge-line';

        var tdGutter = document.createElement('td');
        tdGutter.className = 'rouge-gutter gl';
        tdGutter.textContent = lineNumbers[i] || '';

        var tdCode = document.createElement('td');
        tdCode.className = 'rouge-code';
        tdCode.innerHTML = codeLines[i] !== undefined ? (codeLines[i] || '&nbsp;') : '&nbsp;';

        tr.appendChild(tdGutter);
        tr.appendChild(tdCode);
        tbody.appendChild(tr);
      }

      table.innerHTML = '';
      table.appendChild(tbody);
    });
  }

  // 4. 自动美化 ASCII 架构层叠表（如 ┌───┐ ├───┤ └───┘），便于未来文章自动获得自适应矢量风格
  function autoEnhanceAsciiTables() {
    var pres = document.querySelectorAll('.prose pre');
    pres.forEach(function (pre) {
      if (pre.closest('.agent-architecture-diagram') || pre.closest('.auto-architecture-stack')) return;

      var text = pre.innerText || pre.textContent;
      if (!text) return;

      // 匹配包含 ┌、├、└ 的层叠框图
      if (text.indexOf('┌') !== -1 && text.indexOf('└') !== -1 && text.indexOf('├') !== -1) {
        var lines = text.split('\n');
        var items = [];
        lines.forEach(function (line) {
          line = line.trim();
          if (line.startsWith('│') && line.endsWith('│')) {
            var content = line.substring(1, line.length - 1).trim();
            if (content && !content.match(/^[─\s]+$/)) {
              items.push(content);
            }
          }
        });

        if (items.length >= 2) {
          var container = document.createElement('div');
          container.className = 'auto-architecture-stack';
          container.setAttribute('style', 'margin: 1.8em 0; border: 1px solid var(--archive-line); border-radius: 8px; background: #181b21; padding: 16px; display: grid; gap: 8px;');

          var colors = [
            { bg: '#1e232d', border: 'rgba(148, 163, 184, 0.3)', text: '#f1f5f9', badge: '#94a3b8' },
            { bg: '#152433', border: 'rgba(56, 189, 248, 0.3)', text: '#e0f2fe', badge: '#38bdf8' },
            { bg: '#241a31', border: 'rgba(192, 132, 252, 0.3)', text: '#f3e8ff', badge: '#c084fc' },
            { bg: '#282216', border: 'rgba(201, 162, 39, 0.4)', text: '#fef3c7', badge: '#fbbf24' }
          ];

          items.forEach(function (item, idx) {
            var c = colors[idx % colors.length];
            var card = document.createElement('div');
            card.setAttribute('style', 'display: flex; align-items: center; gap: 14px; padding: 10px 14px; border-radius: 6px; background: ' + c.bg + '; border: 1px solid ' + c.border + ';');

            var badge = document.createElement('span');
            badge.setAttribute('style', 'flex-shrink: 0; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: ' + c.badge + '; background: rgba(255,255,255,0.06);');
            badge.textContent = 'Layer ' + (idx + 1);

            var title = document.createElement('span');
            title.setAttribute('style', 'font-size: 13.5px; font-weight: 600; color: ' + c.text + ';');
            title.textContent = item;

            card.appendChild(badge);
            card.appendChild(title);
            container.appendChild(card);
          });

          var wrapper = pre.closest('.highlighter-rouge') || pre;
          wrapper.parentNode.insertBefore(container, wrapper);
          wrapper.style.display = 'none';
        }
      }
    });
  }

  // 5. 预计阅读时长校准（精确统计中英文字符与代码量）
  function initReadTime() {
    var readTimeEl = document.querySelector('.post-meta .read-time');
    var contentEl = document.querySelector('.content.prose');
    if (!readTimeEl || !contentEl) return;

    var text = contentEl.innerText || contentEl.textContent || '';
    var cjk = (text.match(/[\u4e00-\u9fa5]/g) || []).length;
    var nonCjk = (text.replace(/[\u4e00-\u9fa5]/g, ' ').match(/[a-zA-Z0-9_\-]+/g) || []).length;
    var totalWords = cjk + nonCjk;

    var minutes = Math.max(1, Math.ceil(totalWords / 300));
    readTimeEl.textContent = '预计阅读时长 ' + minutes + ' 分钟';
  }

  // 执行初始化
  initToc();
  initCallouts();
  initCodeBlocks();
  autoEnhanceAsciiTables();
  initReadTime();
})();
