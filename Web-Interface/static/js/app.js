// Loki IDS Dashboard JavaScript
const API_BASE = '/api';
let currentPage = 1;
let pageSize = 50;
let alertsChart = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    setupTabs();
    loadDashboard();
    setupWebSocket();
    setInterval(loadDashboard, 30000); // Refresh every 30 seconds
});

// Tab switching
function setupTabs() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(tab).classList.add('active');
            
            if (tab === 'alerts') loadAlerts();
            if (tab === 'signatures') loadSignatures();
            if (tab === 'blacklist') loadBlacklist();
        });
    });
}

// Dashboard
async function loadDashboard() {
    try {
        // Load stats
        const statsRes = await fetch(`${API_BASE}/stats`);
        const stats = await statsRes.json();
        
        document.getElementById('totalAlerts').textContent = stats.total_alerts.toLocaleString();
        document.getElementById('alerts24h').textContent = stats.alerts_last_24h.toLocaleString();
        
        // Load system status
        const statusRes = await fetch(`${API_BASE}/system/status`);
        const status = await statusRes.json();
        
        document.getElementById('blacklistSize').textContent = status.blacklist_size || 0;
        document.getElementById('idsStatus').textContent = status.ids_running ? 'Running' : 'Stopped';
        document.getElementById('idsStatus').style.color = status.ids_running ? '#4ade80' : '#f87171';
        
        // Update status indicator
        const statusDot = document.getElementById('statusDot');
        const statusText = document.getElementById('statusText');
        if (status.ids_running) {
            statusDot.classList.add('online');
            statusDot.classList.remove('offline');
            statusText.textContent = 'IDS Online';
        } else {
            statusDot.classList.add('offline');
            statusDot.classList.remove('online');
            statusText.textContent = 'IDS Offline';
        }
        
        // Update charts
        updateAlertsByTypeChart(stats.alerts_by_type);
        updateTopIPsList(stats.top_attacking_ips);
        
        // Load recent alerts
        const alertsRes = await fetch(`${API_BASE}/alerts?page=1&page_size=10`);
        const alertsData = await alertsRes.json();
        displayRecentAlerts(alertsData.alerts);
        
    } catch (error) {
        console.error('Error loading dashboard:', error);
    }
}

function updateAlertsByTypeChart(data) {
    const ctx = document.getElementById('alertsByTypeChart');
    if (!ctx) return;
    
    if (alertsChart) {
        alertsChart.destroy();
    }
    
    const labels = Object.keys(data);
    const values = Object.values(data);
    
    alertsChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: [
                    '#f87171',
                    '#fbbf24',
                    '#a78bfa'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#e6e6e6'
                    }
                }
            }
        }
    });
}

function updateTopIPsList(ips) {
    const container = document.getElementById('topIPsList');
    if (!container) return;
    
    if (ips.length === 0) {
        container.innerHTML = '<p style="color: #888;">No attacking IPs in the last 24 hours</p>';
        return;
    }
    
    container.innerHTML = ips.map(ip => `
        <div class="ip-item">
            <span>${ip.ip}</span>
            <span style="color: #4a9eff; font-weight: bold;">${ip.count} alerts</span>
        </div>
    `).join('');
}

function displayRecentAlerts(alerts) {
    const container = document.getElementById('recentAlertsList');
    if (!container) return;
    
    if (alerts.length === 0) {
        container.innerHTML = '<p style="color: #888;">No recent alerts</p>';
        return;
    }
    
    container.innerHTML = alerts.map(alert => `
        <div class="alert-item ${alert.type.toLowerCase()}">
            <div class="alert-info">
                <span class="alert-type">${alert.type}</span>
                <strong>${alert.src_ip}</strong> → ${alert.dst_ip || 'N/A'}
                <br>
                <small style="color: #888;">${alert.message}</small>
                <br>
                <small style="color: #666;">${new Date(alert.timestamp).toLocaleString()}</small>
            </div>
        </div>
    `).join('');
}

// Alerts
async function loadAlerts() {
    try {
        const typeFilter = document.getElementById('alertTypeFilter')?.value || '';
        const ipFilter = document.getElementById('ipFilter')?.value || '';
        
        let url = `${API_BASE}/alerts?page=${currentPage}&page_size=${pageSize}`;
        if (typeFilter) url += `&alert_type=${typeFilter}`;
        if (ipFilter) url += `&src_ip=${ipFilter}`;
        
        const res = await fetch(url);
        const data = await res.json();
        
        displayAlerts(data.alerts);
        updatePagination(data.total, data.page, data.page_size);
    } catch (error) {
        console.error('Error loading alerts:', error);
    }
}

function displayAlerts(alerts) {
    const container = document.getElementById('alertsList');
    if (!container) return;
    
    if (alerts.length === 0) {
        container.innerHTML = '<p style="color: #888;">No alerts found</p>';
        return;
    }
    
    container.innerHTML = alerts.map(alert => `
        <div class="alert-item ${alert.type.toLowerCase()}">
            <div class="alert-info">
                <span class="alert-type">${alert.type}</span>
                <strong>${alert.src_ip}:${alert.src_port || 'N/A'}</strong> → 
                ${alert.dst_ip || 'N/A'}:${alert.dst_port || 'N/A'}
                <br>
                <small style="color: #888;">${alert.message}</small>
                <br>
                <small style="color: #666;">${new Date(alert.timestamp).toLocaleString()}</small>
            </div>
            <button class="btn-delete" onclick="deleteAlert(${alert.id})">Delete</button>
        </div>
    `).join('');
}

function updatePagination(total, page, pageSize) {
    const pageInfo = document.getElementById('pageInfo');
    const totalPages = Math.ceil(total / pageSize);
    pageInfo.textContent = `Page ${page} of ${totalPages} (${total} total)`;
    
    document.getElementById('prevPage').disabled = page <= 1;
    document.getElementById('nextPage').disabled = page >= totalPages;
}

function changePage(delta) {
    currentPage += delta;
    if (currentPage < 1) currentPage = 1;
    loadAlerts();
}

async function deleteAlert(id) {
    if (!confirm('Delete this alert?')) return;
    
    try {
        await fetch(`${API_BASE}/alerts/${id}`, { method: 'DELETE' });
        loadAlerts();
    } catch (error) {
        console.error('Error deleting alert:', error);
        alert('Error deleting alert');
    }
}

// Signatures
async function loadSignatures() {
    try {
        const res = await fetch(`${API_BASE}/signatures`);
        const signatures = await res.json();
        
        const container = document.getElementById('signaturesList');
        if (signatures.length === 0) {
            container.innerHTML = '<p style="color: #888;">No signatures configured</p>';
            return;
        }
        
        container.innerHTML = signatures.map(sig => `
            <div class="signature-item">
                <div class="item-info">
                    <strong>${sig.name}</strong>
                    <span class="badge ${sig.enabled ? 'badge-enabled' : 'badge-disabled'}">${sig.enabled ? 'Enabled' : 'Disabled'}</span>
                    <br>
                    <small style="color: #888;">Pattern: <code>${sig.pattern}</code></small>
                    <br>
                    <small style="color: #666;">Action: ${sig.action}</small>
                    ${sig.description ? `<br><small style="color: #666;">${sig.description}</small>` : ''}
                </div>
                <div class="item-actions">
                    <button class="btn-edit" onclick="editSignature(${sig.id})">Edit</button>
                    <button class="btn-delete" onclick="deleteSignature(${sig.id})">Delete</button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading signatures:', error);
    }
}

let editingSignatureId = null;

function showAddSignatureModal() {
    editingSignatureId = null;
    document.getElementById('modalTitle').textContent = 'Add New Signature';
    document.getElementById('submitButton').textContent = 'Add Signature';
    document.getElementById('signatureForm').reset();
    document.getElementById('sigId').value = '';
    document.getElementById('sigEnabled').checked = true;
    document.getElementById('addSignatureModal').style.display = 'block';
}

function closeModal() {
    document.getElementById('addSignatureModal').style.display = 'none';
    editingSignatureId = null;
    document.getElementById('signatureForm').reset();
    document.getElementById('sigId').value = '';
}

async function editSignature(id) {
    try {
        // Fetch signature details
        const res = await fetch(`${API_BASE}/signatures/${id}`);
        const sig = await res.json();
        
        // Populate form
        editingSignatureId = id;
        document.getElementById('sigId').value = sig.id;
        document.getElementById('sigName').value = sig.name;
        document.getElementById('sigPattern').value = sig.pattern;
        document.getElementById('sigAction').value = sig.action;
        document.getElementById('sigDescription').value = sig.description || '';
        document.getElementById('sigEnabled').checked = sig.enabled;
        
        // Update modal title and button
        document.getElementById('modalTitle').textContent = 'Edit Signature';
        document.getElementById('submitButton').textContent = 'Update Signature';
        
        // Show modal
        document.getElementById('addSignatureModal').style.display = 'block';
    } catch (error) {
        console.error('Error loading signature:', error);
        alert('Error loading signature details');
    }
}

document.getElementById('signatureForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const signature = {
        name: document.getElementById('sigName').value,
        pattern: document.getElementById('sigPattern').value,
        action: document.getElementById('sigAction').value,
        description: document.getElementById('sigDescription').value,
        enabled: document.getElementById('sigEnabled').checked
    };
    
    try {
        const sigId = document.getElementById('sigId').value;
        
        if (sigId && editingSignatureId) {
            // Update existing signature
            await fetch(`${API_BASE}/signatures/${sigId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(signature)
            });
        } else {
            // Create new signature
            await fetch(`${API_BASE}/signatures`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(signature)
            });
        }
        
        closeModal();
        loadSignatures();
    } catch (error) {
        console.error('Error saving signature:', error);
        alert('Error saving signature: ' + (error.message || 'Unknown error'));
    }
});

async function deleteSignature(id) {
    if (!confirm('Delete this signature?')) return;
    
    try {
        await fetch(`${API_BASE}/signatures/${id}`, { method: 'DELETE' });
        loadSignatures();
    } catch (error) {
        console.error('Error deleting signature:', error);
        alert('Error deleting signature');
    }
}

async function reloadSignatures() {
    if (!confirm('Import signatures from YAML file to database? This will load YAML signatures into the database.')) return;
    
    try {
        const res = await fetch(`${API_BASE}/signatures/reload`, { method: 'POST' });
        const data = await res.json();
        alert(`Imported ${data.count} signatures from YAML file to database`);
        loadSignatures();
    } catch (error) {
        console.error('Error reloading signatures:', error);
        alert('Error reloading signatures');
    }
}

async function reloadIDSSignatures() {
    if (!confirm('Reload IDS signatures from database? This will update the IDS with latest database signatures (no restart needed).')) return;
    
    try {
        const res = await fetch(`${API_BASE}/system/reload-signatures`, { method: 'POST' });
        const data = await res.json();
        alert(`${data.message}\n\n${data.note || ''}`);
    } catch (error) {
        console.error('Error reloading IDS signatures:', error);
        alert('Error reloading IDS signatures');
    }
}

// Blacklist
async function loadBlacklist() {
    try {
        const res = await fetch(`${API_BASE}/blacklist`);
        const blacklist = await res.json();
        
        const container = document.getElementById('blacklistList');
        if (blacklist.length === 0) {
            container.innerHTML = '<p style="color: #888;">Blacklist is empty</p>';
            return;
        }
        
        container.innerHTML = blacklist.map(entry => `
            <div class="blacklist-item">
                <div class="item-info">
                    <strong>${entry.ip_address}</strong>
                    ${entry.reason ? `<br><small style="color: #888;">${entry.reason}</small>` : ''}
                    <br>
                    <small style="color: #666;">Added: ${new Date(entry.added_at).toLocaleString()}</small>
                </div>
                <div class="item-actions">
                    <button class="btn-delete" onclick="removeFromBlacklist('${entry.ip_address}')">Remove</button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading blacklist:', error);
    }
}

async function addToBlacklist() {
    const ip = document.getElementById('newIPInput').value.trim();
    const reason = document.getElementById('newIPReason').value.trim();
    
    if (!ip) {
        alert('Please enter an IP address');
        return;
    }
    
    try {
        await fetch(`${API_BASE}/blacklist`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip_address: ip, reason: reason || null })
        });
        document.getElementById('newIPInput').value = '';
        document.getElementById('newIPReason').value = '';
        loadBlacklist();
        loadDashboard();
    } catch (error) {
        console.error('Error adding to blacklist:', error);
        alert('Error adding to blacklist');
    }
}

async function removeFromBlacklist(ip) {
    if (!confirm(`Remove ${ip} from blacklist?`)) return;
    
    try {
        await fetch(`${API_BASE}/blacklist/${ip}`, { method: 'DELETE' });
        loadBlacklist();
        loadDashboard();
    } catch (error) {
        console.error('Error removing from blacklist:', error);
        alert('Error removing from blacklist');
    }
}

// WebSocket for real-time updates
function setupWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/alerts`);
    
    ws.onopen = () => {
        console.log('WebSocket connected');
    };
    
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'new_alert') {
            // Refresh dashboard if on dashboard tab
            if (document.getElementById('dashboard').classList.contains('active')) {
                loadDashboard();
            }
            // Refresh alerts if on alerts tab
            if (document.getElementById('alerts').classList.contains('active')) {
                loadAlerts();
            }
        }
    };
    
    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
    };
    
    ws.onclose = () => {
        console.log('WebSocket disconnected, reconnecting...');
        setTimeout(setupWebSocket, 5000);
    };
}

