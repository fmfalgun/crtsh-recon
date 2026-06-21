'use strict';

document.addEventListener('DOMContentLoaded', function () {
  fetch('data/demo.json')
    .then(function (response) {
      if (!response.ok) {
        throw new Error('HTTP ' + response.status + ' ' + response.statusText);
      }
      return response.json();
    })
    .then(function (data) {
      populateStats(data.summary);
      populateQueriedAt(data.queried_at);
      populateSections(data.entries);
    })
    .catch(function (err) {
      var errorBox = document.getElementById('error-box');
      var errorMsg = document.getElementById('error-message');
      if (errorMsg) errorMsg.textContent = 'Failed to load data: ' + err.message;
      if (errorBox) errorBox.style.display = 'block';
    });
});

function populateStats(summary) {
  setText('val-total-certs', summary.total_certs);
  setText('val-direct', summary.direct_subdomains);
  setText('val-wildcards', summary.wildcards);
  setText('val-leaks', summary.san_leaks);
}

function setText(id, value) {
  var el = document.getElementById(id);
  if (el) {
    el.textContent = value != null ? value : '-';
  }
}

function populateQueriedAt(iso) {
  var el = document.getElementById('queried-at');
  if (!el) return;
  if (!iso) {
    el.textContent = 'unknown';
    return;
  }
  var d = new Date(iso);
  if (isNaN(d.getTime())) {
    el.textContent = iso;
    return;
  }
  el.textContent = d.toUTCString().replace('GMT', 'UTC');
}

function populateSections(entries) {
  var groups = {
    direct: [],
    wildcard: [],
    leak: []
  };

  if (Array.isArray(entries)) {
    entries.forEach(function (entry) {
      if (groups.hasOwnProperty(entry.type)) {
        groups[entry.type].push(entry);
      }
    });
  }

  Object.keys(groups).forEach(function (type) {
    groups[type].sort(function (a, b) {
      return (a.name || '').localeCompare(b.name || '');
    });
  });

  renderSection('list-direct', groups.direct);
  renderSection('list-wildcards', groups.wildcard);
  renderSection('list-leaks', groups.leak);
}

function renderSection(sectionId, entries) {
  var container = document.getElementById(sectionId);
  if (!container) return;

  container.textContent = '';

  if (entries.length === 0) {
    var empty = document.createElement('p');
    empty.className = 'empty';
    empty.textContent = 'none found';
    container.appendChild(empty);
    return;
  }

  entries.forEach(function (entry) {
    container.appendChild(buildEntryElement(entry));
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
