'use strict';

document.addEventListener('DOMContentLoaded', function () {
  fetch('data/index.json')
    .then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + r.statusText);
      return r.json();
    })
    .then(function (data) {
      populateHeaderStats(data);
      var groups = groupByLetter(data.domains || []);
      renderAlphaSections(groups);
      setupSearch(data.domains || []);
    })
    .catch(function (err) {
      showError('Failed to load index: ' + err.message);
    });
});

function populateHeaderStats(data) {
  var el = document.getElementById('hof-stats');
  if (el) {
    el.textContent = (data.total_domains || 0) + ' domains · ' + (data.total_certs || 0) + ' certs indexed';
  }
}

function groupByLetter(domains) {
  var groups = {};
  domains.forEach(function (d) {
    var letter = (d.domain || '?')[0].toUpperCase();
    if (!groups[letter]) groups[letter] = [];
    groups[letter].push(d);
  });
  return groups;
}

function renderAlphaSections(groups) {
  var container = document.getElementById('domain-list');
  if (!container) return;
  container.textContent = '';

  var letters = Object.keys(groups).sort();
  if (letters.length === 0) {
    var p = document.createElement('p');
    p.className = 'empty';
    p.textContent = 'No domains submitted yet. Be the first — run crtsh-recon --submit';
    container.appendChild(p);
    return;
  }

  letters.forEach(function (letter) {
    var section = document.createElement('section');
    section.className = 'alpha-section';
    section.id = 'alpha-' + letter;

    var heading = document.createElement('h2');
    heading.className = 'alpha-heading';
    heading.textContent = letter;
    section.appendChild(heading);

    var cards = document.createElement('div');
    cards.className = 'alpha-cards';

    groups[letter].forEach(function (d) {
      cards.appendChild(buildCard(d));
    });

    section.appendChild(cards);
    container.appendChild(section);
  });
}

function buildCard(d) {
  var card = document.createElement('article');
  card.className = 'domain-card';
  card.setAttribute('data-domain', d.domain || '');

  // Header row: domain + date
  var headerRow = document.createElement('div');
  headerRow.className = 'card-header-row';

  var domainSpan = document.createElement('span');
  domainSpan.className = 'card-domain';
  domainSpan.textContent = d.domain || '';
  headerRow.appendChild(domainSpan);

  var dateSpan = document.createElement('span');
  dateSpan.className = 'card-date';
  dateSpan.textContent = formatDate(d.last_refreshed || d.queried_at || '');
  headerRow.appendChild(dateSpan);
  card.appendChild(headerRow);

  // Stats pills
  var statsRow = document.createElement('div');
  statsRow.className = 'card-stats';
  statsRow.appendChild(makeStat(d.cert_count + ' certs', 'certs'));
  statsRow.appendChild(makeStat(d.direct_subdomains + ' direct', 'direct'));
  if (d.wildcards > 0) statsRow.appendChild(makeStat(d.wildcards + ' wildcard', 'wildcard'));
  if (d.san_leaks > 0) statsRow.appendChild(makeStat(d.san_leaks + ' leak', 'leak'));
  card.appendChild(statsRow);

  // Contributor
  if (d.display_name || d.display_loc) {
    var contrib = document.createElement('div');
    contrib.className = 'card-contributor';
    if (d.display_name) {
      var nameSpan = document.createElement('span');
      nameSpan.className = 'card-name';
      nameSpan.textContent = d.display_name;
      contrib.appendChild(nameSpan);
    }
    if (d.display_loc) {
      contrib.appendChild(document.createTextNode(d.display_loc));
    }
    card.appendChild(contrib);
  }

  // Detail panel (hidden by default)
  var detail = document.createElement('div');
  detail.className = 'card-detail';
  detail.hidden = true;
  card.appendChild(detail);

  // Click handler
  card.addEventListener('click', function () {
    toggleCard(card, detail, d.domain);
  });

  return card;
}

function makeStat(text, type) {
  var span = document.createElement('span');
  span.className = 'card-stat ' + type;
  span.textContent = text;
  return span;
}

function toggleCard(card, detail, domain) {
  var isExpanded = card.classList.contains('expanded');

  if (isExpanded) {
    card.classList.remove('expanded');
    detail.hidden = true;
    return;
  }

  card.classList.add('expanded');
  detail.hidden = false;

  // Only fetch if not already loaded
  if (detail.getAttribute('data-loaded') === 'true') return;

  detail.textContent = '';
  var loading = document.createElement('p');
  loading.className = 'detail-loading';
  loading.textContent = 'loading…';
  detail.appendChild(loading);

  fetch('data/domains/' + domain + '.json')
    .then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    })
    .then(function (data) {
      detail.textContent = '';
      renderDetail(detail, data);
      detail.setAttribute('data-loaded', 'true');
    })
    .catch(function (err) {
      detail.textContent = '';
      var p = document.createElement('p');
      p.className = 'detail-loading';
      p.textContent = 'Failed to load detail: ' + err.message;
      detail.appendChild(p);
    });
}

function renderDetail(container, data) {
  var entries = data.entries || [];
  var groups = { direct: [], wildcard: [], leak: [] };

  entries.forEach(function (e) {
    if (groups.hasOwnProperty(e.type)) groups[e.type].push(e);
  });

  Object.keys(groups).forEach(function (type) {
    groups[type].sort(function (a, b) {
      return (a.name || '').localeCompare(b.name || '');
    });
  });

  var sections = [
    { key: 'direct',   label: '[ // direct subdomains ]', cls: 'direct' },
    { key: 'wildcard', label: '[ // wildcard certs ]',     cls: 'wildcard' },
    { key: 'leak',     label: '[ // san leaks ]',          cls: 'leak' },
  ];

  sections.forEach(function (s) {
    var sec = document.createElement('div');
    sec.className = 'section';

    var h = document.createElement('h3');
    h.className = 'section-title ' + s.cls;
    h.textContent = s.label;
    sec.appendChild(h);

    var list = document.createElement('div');
    list.className = 'entry-list';

    if (groups[s.key].length === 0) {
      var empty = document.createElement('p');
      empty.className = 'empty';
      empty.textContent = 'none found';
      list.appendChild(empty);
    } else {
      groups[s.key].forEach(function (entry) {
        list.appendChild(buildEntryElement(entry));
      });
    }

    sec.appendChild(list);
    container.appendChild(sec);
  });
}

function buildEntryElement(entry) {
  var div = document.createElement('div');
  div.className = 'entry';

  var nameSpan = document.createElement('span');
  nameSpan.className = 'entry-name';
  nameSpan.textContent = entry.name || '';
  div.appendChild(nameSpan);

  var issuerSpan = document.createElement('span');
  issuerSpan.className = 'entry-issuer';
  issuerSpan.textContent = entry.issuer || '';
  div.appendChild(issuerSpan);

  var datesSpan = document.createElement('span');
  datesSpan.className = 'entry-dates';
  datesSpan.textContent = (entry.not_before || '') + ' → ' + (entry.not_after || '');
  div.appendChild(datesSpan);

  if (entry.crtsh_id != null) {
    var link = document.createElement('a');
    link.className = 'entry-link';
    link.href = 'https://crt.sh/?id=' + entry.crtsh_id;
    link.target = '_blank';
    link.rel = 'noopener';
    link.textContent = '[crt.sh ↗]';
    div.appendChild(link);
  }

  return div;
}

function setupSearch(domains) {
  var input = document.getElementById('search-input');
  var countEl = document.getElementById('search-count');
  if (!input) return;

  updateCount(domains.length, domains.length, countEl);

  input.addEventListener('input', function () {
    var query = input.value.trim().toLowerCase();
    var visible = 0;

    var cards = document.querySelectorAll('.domain-card');
    cards.forEach(function (card) {
      var domain = card.getAttribute('data-domain') || '';
      var match = !query || domain.includes(query);
      card.style.display = match ? '' : 'none';
      if (match) visible++;
    });

    // Hide alpha-sections that have no visible cards
    var sections = document.querySelectorAll('.alpha-section');
    sections.forEach(function (section) {
      var anyVisible = Array.from(section.querySelectorAll('.domain-card')).some(function (c) {
        return c.style.display !== 'none';
      });
      section.style.display = anyVisible ? '' : 'none';
    });

    updateCount(visible, domains.length, countEl);
  });
}

function updateCount(visible, total, el) {
  if (!el) return;
  el.textContent = visible === total
    ? total + ' domains'
    : visible + ' / ' + total + ' domains';
}

function formatDate(iso) {
  if (!iso) return '';
  return iso.slice(0, 10);
}

function showError(msg) {
  var box = document.getElementById('error-box');
  var msgEl = document.getElementById('error-message');
  if (msgEl) msgEl.textContent = msg;
  if (box) box.style.display = 'block';
}
