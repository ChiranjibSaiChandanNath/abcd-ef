let lastFilename = '';

document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('fileInput');
    const fileLabelText = document.getElementById('fileLabelText');
    const uploadCard = document.getElementById('uploadCard');

    // Update label when file selected via click
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            fileLabelText.textContent = e.target.files[0].name;
            uploadCard.style.borderColor = '#38bdf8';
        }
    });

    // Drag and Drop Effects
    uploadCard.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadCard.classList.add('drag-over');
    });

    uploadCard.addEventListener('dragleave', (e) => {
        e.preventDefault();
        uploadCard.classList.remove('drag-over');
    });

    uploadCard.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadCard.classList.remove('drag-over');

        if (e.dataTransfer.files.length > 0) {
            fileInput.files = e.dataTransfer.files;
            fileLabelText.textContent = fileInput.files[0].name;
            uploadCard.style.borderColor = 'var(--primary-glow)';
        }
    });
});

async function analyzeFile() {
    const fileInput = document.getElementById('fileInput');
    if (!fileInput.files[0]) {
        alert('⚠️ Please select a file first!');
        return;
    }

    const btn = document.getElementById('analyzeBtn');
    btn.disabled = true;
    btn.innerHTML = `<div class="spinner" style="width:20px;height:20px;margin:0;border-width:2px;display:inline-block;vertical-align:middle;"></div> <span style="vertical-align:middle;margin-left:8px;">Running Analysis...</span>`;

    const resultsSection = document.getElementById('results');
    resultsSection.innerHTML = '';
    resultsSection.classList.remove('visible');

    const loader = document.getElementById('loader');
    loader.style.display = 'block';

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    lastFilename = fileInput.files[0].name;

    try {
        const response = await fetch('/analyze', { method: 'POST', body: formData });
        const data = await response.json();

        if (data.error) throw new Error(data.error);

        // VT Style Cache Hit
        if (data.status === 'complete') {
            handleAnalysisComplete(data.data, fileInput);
            return;
        }

        if (data.status === 'queued') {
            pollJobStatus(data.job_id, fileInput);
        }

    } catch (err) {
        handleAnalysisError(err);
    }
}

async function pollJobStatus(jobId, fileInput) {
    const loaderText = document.getElementById('loaderStatus');
    const loadingProgress = document.getElementById('loadingProgress');
    let attempts = 0;
    const maxAttempts = 60; // 2 minutes max

    const interval = setInterval(async () => {
        try {
            attempts++;
            if (attempts > maxAttempts) {
                clearInterval(interval);
                throw new Error('Analysis timed out. Please try again.');
            }

            const res = await fetch(`/api/status/${jobId}`);
            const jobData = await res.json();

            // Handle progress (backend should provide a 'progress' field 0-100)
            if (jobData.progress !== undefined) {
                loadingProgress.style.width = `${jobData.progress}%`;
                loaderText.innerText = `Analyzing: ${jobData.status_message || 'In progress...'}`;
            } else {
                // Fallback progress simulation
                const simulatedProgress = Math.min(attempts * 5, 95);
                loadingProgress.style.width = `${simulatedProgress}%`;
                loaderText.innerText = `VT Engine Analysis running... (${attempts})`;
            }

            if (jobData.status === 'complete') {
                loadingProgress.style.width = '100%';
                setTimeout(() => {
                    clearInterval(interval);
                    handleAnalysisComplete(jobData.data, fileInput);
                }, 400);
            } else if (jobData.status === 'failed') {
                clearInterval(interval);
                throw new Error(jobData.error || 'Background processing failed.');
            }
        } catch (err) {
            clearInterval(interval);
            handleAnalysisError(err);
        }
    }, 2000);
}

function handleAnalysisComplete(data, fileInput) {
    const loader = document.getElementById('loader');
    const btn = document.getElementById('analyzeBtn');

    lastFilename = data.report_filename || encodeURIComponent(fileInput.files[0].name);

    loader.style.display = 'none';
    btn.disabled = false;
    btn.innerHTML = `<i class="ph-bold ph-lightning btn-icon"></i> Analyze Now`;

    displayResults(data);
}

function handleAnalysisError(err) {
    const loader = document.getElementById('loader');
    const btn = document.getElementById('analyzeBtn');
    const resultsSection = document.getElementById('results');

    loader.style.display = 'none';
    btn.disabled = false;
    btn.innerHTML = `<i class="ph-bold ph-lightning btn-icon"></i> Analyze Now`;

    resultsSection.innerHTML = `
        <div class="card full-width" style="border-color: #ef4444;">
            <div class="card-header"><h3 style="color:#ef4444"><i class="ph-fill ph-warning-circle"></i> Analysis Error</h3></div>
            <p style="color:var(--text-secondary)">${err.message || err}</p>
        </div>`;
    resultsSection.style.display = 'block';
}

function displayResults(data) {
    const risk = data.risk || {};
    const hashes = data.hashes || {};
    const yara = data.yara || [];
    const pe = data.pe_info || {};

    // Risk mapping
    const riskClass = risk.label === 'CRITICAL' ? 'risk-CRITICAL' :
        risk.label === 'HIGH' ? 'risk-HIGH' :
        risk.label === 'MEDIUM' ? 'risk-MEDIUM' : 'risk-LOW';
    const riskEmoji = risk.label === 'CRITICAL' ? '🔥' :
        risk.label === 'HIGH' ? '🔴' :
        risk.label === 'MEDIUM' ? '🟡' : '🟢';
    const riskColor = risk.label === 'CRITICAL' ? '#f87171' :
        risk.label === 'HIGH' ? '#ef4444' :
        risk.label === 'MEDIUM' ? '#f59e0b' : '#10b981';

    // YARA badges
    const yaraHTML = yara.length === 0
        ? '<span class="badge badge-green"><i class="ph-fill ph-check-circle"></i> No signatures mapped</span>'
        : `<div class="badge-container">` + yara.map(y => `
            <div style="width:100%;">
                <span class="badge badge-red"><i class="ph-fill ph-warning-circle"></i> ${y.rule || 'Unknown'}</span>
                <div class="yara-desc">${y.description || ''}</div>
            </div>`).join('') + `</div>`;

    // Suspicious APIs
    const apisHTML = (pe.suspicious_apis || []).length === 0
        ? '<span class="badge badge-green"><i class="ph-fill ph-check-circle"></i> Clean behavior</span>'
        : `<div class="badge-container">` + pe.suspicious_apis.map(a =>
            `<span class="badge badge-yellow"><i class="ph-fill ph-lightning"></i> ${a}</span>`).join('') + `</div>`;

    // PE Sections
    const sectionsHTML = (pe.sections || []).length === 0
        ? '<span class="badge badge-blue"><i class="ph-fill ph-info"></i> Not a PE mapped executable</span>'
        : `<div class="badge-container">` + pe.sections.map(s =>
            `<span class="badge ${s.entropy > 7 ? 'badge-red' : 'badge-green'}">
                ${s.name} [Ent: ${s.entropy}]
            </span>`).join('') + `</div>`;

    const resultsSection = document.getElementById('results');

    // === SVG RADIAL GAUGE CALCULATIONS ===
    // Circumference of r=110 is 2 * PI * 110 = 691.15
    const circumference = 691.15;
    const strokeOffset = circumference - (risk.score / 100) * circumference;
    
    // Animate color from green to red based on score
    const gaugeColor = risk.score >= 85 ? '#f87171' : risk.score >= 70 ? '#ef4444' : risk.score >= 40 ? '#f59e0b' : '#10b981';

    resultsSection.innerHTML = `
        <nav class="vt-tabs">
            <button class="vt-tab active" onclick="switchTab('detection', this)">Detection</button>
            <button class="vt-tab" onclick="switchTab('details', this)">Details</button>
            <button class="vt-tab" onclick="switchTab('behavior', this)">Behavior</button>
        </nav>

        <div id="tab-detection" class="tab-panel active">
            <div class="results-grid visible" style="grid-template-columns: 1fr 1fr;">
                
                <!-- Radial Gauge Card -->
                <div class="card delay-1" style="display:flex; flex-direction:column; align-items:center;">
                    <div class="radial-container">
                        <svg class="radial-svg" viewBox="0 0 250 250">
                            <circle class="radial-bg" cx="125" cy="125" r="110"></circle>
                            <circle class="radial-progress" cx="125" cy="125" r="110" 
                                    style="stroke: ${gaugeColor}; stroke-dasharray: ${circumference}; stroke-dashoffset: ${circumference};">
                            </circle>
                        </svg>
                        <div class="radial-text">
                            <div class="radial-score">${risk.score} / 100</div>
                            <div class="radial-label" style="color: ${gaugeColor}">${risk.label}</div>
                        </div>
                    </div>
                    <p style="color:var(--text-secondary); text-align:center;">Heuristic Confidence Score</p>
                </div>

                <div style="display:flex; flex-direction:column; gap:20px;">
                    <!-- Artifact Summary -->
                    <div class="card delay-2">
                        <div class="card-header">
                            <i class="ph-duotone ph-file-magnifying-glass" style="font-size: 24px;"></i>
                            <h3>Artifact Target</h3>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Filename</span>
                            <span class="info-value">${data.filename}</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Detected Signature</span>
                            <span class="info-value" style="color:var(--primary-glow)">${data.file_type}</span>
                        </div>
                    </div>

                    <!-- YARA Matches -->
                    <div class="card delay-3">
                        <div class="card-header">
                            <i class="ph-duotone ph-target" style="font-size: 24px;"></i>
                            <h3>Static Engines (YARA)</h3>
                        </div>
                        ${yaraHTML}
                    </div>
                </div>
            </div>
        </div>

        <div id="tab-details" class="tab-panel">
            <div class="results-grid visible" style="grid-template-columns: 1fr;">
                
                <!-- Hashes -->
                <div class="card delay-1">
                    <div class="card-header">
                        <i class="ph-duotone ph-key" style="font-size: 24px;"></i>
                        <h3>Cryptographic Hashes</h3>
                    </div>
                    <div class="info-row">
                        <span class="info-label">MD5</span>
                        <span class="info-value">${hashes.md5 || 'N/A'}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">SHA1</span>
                        <span class="info-value">${hashes.sha1 || 'N/A'}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">SHA256</span>
                        <span class="info-value">${hashes.sha256 || 'N/A'}</span>
                    </div>
                </div>
                
                <!-- Structural Analysis View -->
                ${data.script_info ? `
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px;">
                    <!-- Script Indicators -->
                    <div class="card delay-2">
                        <div class="card-header">
                            <i class="ph-duotone ph-magnifying-glass" style="font-size: 24px;"></i>
                            <h3>Script Pattern Scan</h3>
                        </div>
                        <p style="color:var(--text-muted); font-size:12px; margin-bottom:12px;">Detected structural markers in payload</p>
                        <div class="api-list">
                            ${(data.script_info.indicators || []).length > 0 ? 
                                data.script_info.indicators.map(ind => `
                                    <div class="api-item">
                                        <i class="ph ph-warning-circle" style="color:#fbbf24;"></i>
                                        <span>${ind}</span>
                                    </div>
                                `).join('') : 
                                '<p style="color:var(--text-muted); font-size:13px; font-style:italic;">No dangerous patterns detected in script text.</p>'
                            }
                        </div>
                    </div>

                    <!-- Script Stats -->
                    <div class="card delay-3">
                        <div class="card-header">
                            <i class="ph-duotone ph-chart-line" style="font-size: 24px;"></i>
                            <h3>Payload Metrics</h3>
                        </div>
                        <p style="color:var(--text-muted); font-size:12px; margin-bottom:12px;">Quantitative structural data</p>
                        <div class="info-row">
                            <span class="info-label">File Entropy</span>
                            <span class="badge ${data.script_info.entropy > 5.5 ? 'badge-red' : 'badge-green'}">${data.script_info.entropy} bits</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Line Count</span>
                            <span class="info-value">${data.script_info.line_count}</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Total Characters</span>
                            <span class="info-value">${data.script_info.size}</span>
                        </div>
                    </div>
                </div>
                ` : (data.pe_info && data.pe_info.is_pe) ? `
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px;">
                    <!-- Suspicious APIs -->
                    <div class="card delay-2">
                        <div class="card-header">
                            <i class="ph-duotone ph-gear" style="font-size: 24px;"></i>
                            <h3>Import Address Table</h3>
                        </div>
                        <p style="color:var(--text-muted); font-size:12px; margin-bottom:12px;">Flagged systematic API imports</p>
                        ${apisHTML}
                    </div>

                    <!-- PE Sections -->
                    <div class="card delay-3">
                        <div class="card-header">
                            <i class="ph-duotone ph-package" style="font-size: 24px;"></i>
                            <h3>Segment Entropy Map</h3>
                        </div>
                        <p style="color:var(--text-muted); font-size:12px; margin-bottom:12px;">Segments > 7.0 entropy may imply packed payloads</p>
                        ${sectionsHTML}
                    </div>
                </div>
                ` : `
                <div class="card delay-2" style="text-align:center; padding: 40px; background: rgba(255,255,255,0.02);">
                    <i class="ph-duotone ph-file-dashed" style="font-size: 40px; color: var(--text-muted); margin-bottom: 15px;"></i>
                    <h3 style="color: var(--text-secondary);">Minimal Static Telemetry</h3>
                    <p style="color: var(--text-muted); font-size: 13px;">Advanced structural analysis is not available for this file type.</p>
                </div>
                `}

                <!-- Threat Intelligence Grid -->
                ${data.threat_intel ? `
                <div class="intel-grid" style="display:grid; grid-template-columns: 1fr 1fr; gap:20px; margin-top:20px;">
                    <!-- MITRE ATT&CK Mapping -->
                    <div class="card intel-card">
                        <div class="card-header">
                            <i class="ph-duotone ph-shield-check" style="font-size: 24px; color: #3b82f6;"></i>
                            <h3>MITRE ATT&CK Mapping</h3>
                        </div>
                        <div class="mitre-list">
                            ${(data.threat_intel.mitre || []).length > 0 ? 
                                data.threat_intel.mitre.map(t => `
                                    <div class="mitre-item">
                                        <div class="mitre-badge">${t.id}</div>
                                        <div class="mitre-content">
                                            <div class="mitre-name">${t.name}</div>
                                            <div class="mitre-desc">${t.desc}</div>
                                        </div>
                                    </div>
                                `).join('') : 
                                '<p class="empty-intel">No specific MITRE techniques mapped.</p>'
                            }
                        </div>
                    </div>

                    <!-- Sigma Rule Matches -->
                    <div class="card intel-card">
                        <div class="card-header">
                            <i class="ph-duotone ph-list-magnifying-glass" style="font-size: 24px; color: #10b981;"></i>
                            <h3>Sigma Detections</h3>
                        </div>
                        <div class="sigma-list">
                            ${(data.threat_intel.sigma || []).length > 0 ? 
                                data.threat_intel.sigma.map(s => `
                                    <div class="sigma-item">
                                        <div class="sigma-header">
                                            <span class="sigma-title">${s.title}</span>
                                            <span class="badge badge-green">${s.category}</span>
                                        </div>
                                        <div class="sigma-desc">${s.description}</div>
                                    </div>
                                `).join('') : 
                                '<p class="empty-intel">No Sigma rule alerts triggered.</p>'
                            }
                        </div>
                    </div>

                    <!-- IDS Network Alerts -->
                    <div class="card intel-card" style="grid-column: span 2;">
                        <div class="card-header">
                            <i class="ph-duotone ph-broadcast" style="font-size: 24px; color: #ef4444;"></i>
                            <h3>IDS Intrusion Alerts (Suricata)</h3>
                        </div>
                        <div class="ids-list">
                            ${(data.threat_intel.ids || []).length > 0 ? 
                                data.threat_intel.ids.map(i => `
                                    <div class="ids-item">
                                        <code class="ids-rule">${i.rule}</code>
                                        <div class="ids-meta">
                                            <span class="badge badge-red">${i.severity}</span>
                                            <span class="ids-desc">${i.description}</span>
                                        </div>
                                    </div>
                                `).join('') : 
                                '<p class="empty-intel" style="padding: 20px;">No network-based instruction patterns detected.</p>'
                            }
                        </div>
                    </div>
                </div>
                ` : ''}
                
            </div>
        </div>
        
        <div id="tab-behavior" class="tab-panel">
            <div class="behavior-timeline">
                ${(data.behavioral_analysis || []).length > 0 ? data.behavioral_analysis.map(event => {
                    let icon = 'ph-flask';
                    if (event.type === 'process') icon = 'ph-cpu';
                    if (event.type === 'network') icon = 'ph-globe-hemisphere-east';
                    if (event.type === 'file') icon = 'ph-file-arrow-down';
                    if (event.type === 'registry') icon = 'ph-list-checks';

                    return `
                        <div class="behavior-event sev-${event.severity}">
                            <div class="event-icon-wrapper event-${event.type}">
                                <i class="ph-duotone ${icon}"></i>
                            </div>
                            <div class="event-content">
                                <div class="event-header">
                                    <span class="event-summary">${event.summary}</span>
                                    <span class="badge ${event.severity === 'critical' ? 'badge-red' : event.severity === 'high' ? 'badge-red' : event.severity === 'medium' ? 'badge-yellow' : 'badge-green'}">
                                        ${event.severity.toUpperCase()}
                                    </span>
                                </div>
                                <div class="event-details">${event.details}</div>
                            </div>
                        </div>
                    `;
                }).join('') : `
                    <div class="card delay-1" style="text-align:center; padding: 60px;">
                        <i class="ph-duotone ph-check-circle" style="font-size: 48px; color: var(--risk-low); margin-bottom: 20px;"></i>
                        <h3>No Behavioral Anomalies</h3>
                        <p style="color: var(--text-muted); margin-top: 10px;">The sandbox execution did not capture any suspicious runtime behavior for this file.</p>
                    </div>
                `}
            </div>
        </div>

        <!-- Action Center -->
        <div class="card delay-4 full-width" style="text-align:center; margin-top: 20px;">
            <div class="actions-container" style="justify-content: center; max-width: 600px; margin: 0 auto;">
                <button class="btn btn-primary" onclick="downloadReport()"><i class="ph-bold ph-download-simple" style="margin-right: 6px;"></i> Download PDF Report</button>
                <button class="btn btn-outline" onclick="scanAgain()"><i class="ph-bold ph-arrows-clockwise" style="margin-right: 6px;"></i> Scan New Artifact</button>
            </div>
        </div>
    `;

    // Make the results container visible natively
    resultsSection.style.display = 'block';

    // Smooth scroll down and animate SVG radially
    setTimeout(() => {
        document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
        
        // Trigger stroke offset animation
        const progressCircle = document.querySelector('.radial-progress');
        if (progressCircle) {
            progressCircle.style.strokeDashoffset = strokeOffset;
        }
    }, 100);
}

function switchTab(tabId, btnElement) {
    // UI Button updates
    document.querySelectorAll('.vt-tab').forEach(b => b.classList.remove('active'));
    btnElement.classList.add('active');
    
    // Panel updates
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.getElementById('tab-' + tabId).classList.add('active');
}



function downloadReport() {
    window.open('/download_report/' + encodeURIComponent(lastFilename), '_blank');
}

function scanAgain() {
    document.getElementById('results').innerHTML = '';
    document.getElementById('fileInput').value = '';
    document.getElementById('fileLabelText').textContent = 'Choose a file...';
    document.getElementById('uploadCard').style.borderColor = 'rgba(65, 83, 115, 0.3)';
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// --- VT Style History Mechanism --- //

async function toggleHistory() {
    const historySection = document.getElementById('historySection');
    const uploadSection = document.querySelector('.upload-section');
    const resultsSection = document.getElementById('results');
    
    if (historySection.style.display === 'none') {
        historySection.style.display = 'block';
        uploadSection.style.display = 'none';
        resultsSection.style.display = 'none';
        
        // Fetch data
        const tbody = document.getElementById('historyTableBody');
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding: 20px;">Loading Archive...</td></tr>';
        
        try {
            const res = await fetch('/api/history');
            const data = await res.json();
            
            if (data.history.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding: 20px;">No historical analysis records found.</td></tr>';
                return;
            }
            
            tbody.innerHTML = data.history.map(item => `
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                    <td style="padding: 12px; color: var(--text-muted);">${item.timestamp}</td>
                    <td style="padding: 12px; font-family: monospace; color: var(--primary-glow);">${item.hash.substring(0,24)}...</td>
                    <td style="padding: 12px;">
                        <span class="badge ${item.risk === 'HIGH' ? 'badge-red' : item.risk === 'MEDIUM' ? 'badge-yellow' : 'badge-green'}">${item.risk}</span>
                    </td>
                    <td style="padding: 12px;">
                        <button class="btn btn-primary" style="padding: 4px 8px; font-size: 12px;" onclick="loadVTRecord('${item.job_id}', '${item.hash}')">Load Dashboard</button>
                    </td>
                </tr>
            `).join('');
        } catch(e) {
            tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding: 20px; color: #ef4444;">Error fetching history</td></tr>`;
        }
    } else {
        historySection.style.display = 'none';
        uploadSection.style.display = 'flex';
    }
}

async function loadVTRecord(jobId, hash) {
    toggleHistory(); // Close history modal
    
    const loader = document.getElementById('loader');
    loader.style.display = 'block';
    
    try {
        const res = await fetch(`/api/status/${jobId}`);
        const jobData = await res.json();
        
        if (jobData.status === 'complete') {
            handleAnalysisComplete(jobData.data, { files: [{name: hash + ".file"}] });
        } else {
            alert('Job is not fully complete or it failed.');
            loader.style.display = 'none';
        }
    } catch (err) {
        handleAnalysisError(err);
    }
}
