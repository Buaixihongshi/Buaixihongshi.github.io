(function () {
  var toc = document.getElementById('toc');
  var content = document.querySelector('.content');

  if (!toc || !content) {
    return;
  }

  var headings = Array.prototype.slice.call(
    content.querySelectorAll('h2, h3, h4')
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
})();
