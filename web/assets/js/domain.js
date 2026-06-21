'use strict';

document.addEventListener('DOMContentLoaded', function () {
  var params = new URLSearchParams(window.location.search);
  var domain = params.get('d');

  if (!domain) {
    showError('No domain specified. ');
    var link = document.createElement('a');
    link.href = 'index.html';
    link.textContent = '← Go back to hall of fame';
    document.getElementById('error-message').appendChild(link);
    return;
  }

  document.title = 'crtsh-recon — ' + domain;
  setText('tool-name', domain);

  fetch('data/domains/' + encodeURIComponent(domain) + '.json')
    .then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + r.statusText);
      return r.json();
    })
    .then(function (data) {
      populatePage(data);
    })
    .catch(function (err) {
      showError('Failed to load data for ' + domain + ': ' + err.message);
    });
});

function populatePage(data) {
  var s = data.summary || {};

  setText('val-total-certs', s.total_certs != null ? s.total_certs : (data.cert_count || '—'));
  setText('val-direct',      s.direct_subdomains != null ? s.direct_subdomains : '—');
  setText('val-wildcards',   s.wildcards != null ? s.wildcards : '—');
  setText('val-leaks',       s.san_leaks != null ? s.san_leaks : '—');

  populateQueriedAt(data.last_refreshed || data.queried_at || '');

  var contrib = '';
  if (data.display_name) contrib += data.display_name;
  if (data.display_loc)  contrib += (contrib ? '  ·  ' : '') + data.display_loc;
  setText('contributor-meta', contrib);

  populateSections(data.entries || []);
}

function populateSections(entries) {
  var groups = { direct: [], wildcard: [], leak: [] };
  entries.forEach(function (e) {
    if (groups.hasOwnProperty(e.type)) groups[e.type].push(e);
  });

  Object.keys(groups).forEach(function (type) {
    groups[type].sort(function (a, b) {
      return (a.name || '').localeCompare(b.name || '');
    });
  });

  renderSection('list-direct',    groups.direct);
  renderSection('list-wildcards', groups.wildcard);
  renderSection('list-leaks',     groups.leak);
}

function renderSection(containerId, entries) {
  var container = document.getElementById(containerId);
  if (!container) return;
  container.textContent = '';

  if (entries.length === 0) {
    var p = document.createElement('p');
    p.className = 'empty';
    p.textContent = 'none found';
    container.appendChild(p);
    return;
  }

  entries.forEach(function (entry) {
    container.appendChild(buildEntry(entry));
  });
}

function buildEntry(entry) {
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

function populateQueriedAt(iso) {
  var el = document.getElementById('queried-at');
  if (!el) return;
  if (!iso) { el.textContent = 'unknown'; return; }
  var d = new Date(iso);
  if (isNaN(d.getTime())) { el.textContent = iso; return; }
  el.textContent = d.toUTCString().replace('GMT', 'UTC');
}

function setText(id, value) {
  var el = document.getElementById(id);
  if (el) el.textContent = value != null ? String(value) : '—';
}

function showError(msg) {
  var box   = document.getElementById('error-box');
  var msgEl = document.getElementById('error-message');
  if (msgEl) msgEl.textContent = msg;
  if (box)   box.style.display = 'block';
}
