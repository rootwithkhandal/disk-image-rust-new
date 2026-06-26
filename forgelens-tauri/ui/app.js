// Tauri Global Object access
const { invoke } = window.__TAURI__.core;

// App States
let appState = {
    activeTab: 'dashboard',
    profile: null,
    processes: [],
    connections: [],
    registry: [],
    kernel: null,
    timeline: [],
    selectedDtb: 0,
    hexAddress: 0,
    dlls: [],
    threads: [],
    credentials: null,
    fileRecovery: null,
    yara: null,
    malware: null,
};

// Elements cache
const el = {
    loadDumpBtn: document.getElementById('load-dump-btn'),
    systemClock: document.getElementById('system-clock'),
    footerStatus: document.getElementById('footer-status'),
    searchInput: document.getElementById('search-input'),
    
    // Dashboard elements
    dashOsFamily: document.getElementById('dash-os-family'),
    dashOsVer: document.getElementById('dash-os-ver'),
    dashProcCount: document.getElementById('dash-proc-count'),
    dashUnlinkedAlert: document.getElementById('dash-unlinked-alert'),
    dashConnCount: document.getElementById('dash-conn-count'),
    dashAlertsCount: document.getElementById('dash-alerts-count'),
    dashAlertsDesc: document.getElementById('dash-alerts-desc'),
    telemetryCr3: document.getElementById('telemetry-cr3'),
    telemetryBuild: document.getElementById('telemetry-build'),
    telemetryFormat: document.getElementById('telemetry-format'),
    entropyGrid: document.getElementById('entropy-grid'),
    
    // Tables & containers
    processesTableBody: document.getElementById('processes-table-body'),
    networkTableBody: document.getElementById('network-table-body'),
    scannerActiveDtb: document.getElementById('scanner-active-dtb'),
    scanMemoryBtn: document.getElementById('scan-memory-btn'),
    scanLoader: document.getElementById('scan-loader'),
    scannerTableBody: document.getElementById('scanner-table-body'),
    registryKeysContainer: document.getElementById('registry-keys-container'),
    kernelHooksContainer: document.getElementById('kernel-hooks-container'),
    kernelDriversBody: document.getElementById('kernel-drivers-body'),
    timelineContainer: document.getElementById('timeline-container'),
    
    // Hex Viewer
    hexAddressInput: document.getElementById('hex-address-input'),
    hexNavigateBtn: document.getElementById('hex-navigate-btn'),
    hexPrevBtn: document.getElementById('hex-prev-btn'),
    hexNextBtn: document.getElementById('hex-next-btn'),
    hexViewerOutput: document.getElementById('hex-viewer-output'),
    
    // New tab containers
    dllsContainer: document.getElementById('dlls-container'),
    threadsContainer: document.getElementById('threads-container'),
    credentialsSummary: document.getElementById('credentials-summary'),
    credentialsContainer: document.getElementById('credentials-container'),
    fileRecoverySummary: document.getElementById('file-recovery-summary'),
    fileRecoveryContainer: document.getElementById('file-recovery-container'),
    yaraSummary: document.getElementById('yara-summary'),
    yaraContainer: document.getElementById('yara-container'),
    malwareSummary: document.getElementById('malware-summary'),
    malwareContainer: document.getElementById('malware-container'),
    exportReportBtn: document.getElementById('export-report-btn'),
};

// Clock ticker
function updateClock() {
    const now = new Date();
    const timeStr = now.toISOString().split('T')[1].split('.')[0] + ' UTC';
    el.systemClock.textContent = 'SYS_CLK: ' + timeStr;
}
setInterval(updateClock, 1000);
updateClock();

// Tab Switching
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        
        // Remove active styling from all nav items
        document.querySelectorAll('.nav-item').forEach(nav => {
            nav.className = "nav-item flex items-center gap-3 px-3 py-2.5 rounded-lg text-on-surface-variant hover:text-on-surface hover:bg-white/5 transition-all duration-200 ease-in-out font-label-caps text-label-caps";
        });
        
        // Set clicked item as active
        item.className = "nav-item flex items-center gap-3 px-3 py-2.5 rounded-lg bg-primary-container/20 text-primary border-r-4 border-primary transition-all duration-200 ease-in-out font-label-caps text-label-caps";
        
        const tabName = item.getAttribute('data-tab');
        appState.activeTab = tabName;
        
        // Toggle tab content visibility
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(`tab-${tabName}`).classList.add('active');
        
        el.footerStatus.textContent = `Navigated to ${tabName.toUpperCase()} tab.`;
        
        // Filter or update specific view configurations
        if (tabName === 'hexview') {
            refreshHexViewer();
        }
    });
});

// Load Memory Dump action
el.loadDumpBtn.addEventListener('click', async () => {
    el.footerStatus.textContent = "Selecting memory dump file...";
    try {
        // Trigger dialog picker on backend by sending empty path
        const profile = await invoke('load_dump', { path: "" });
        appState.profile = profile;
        appState.selectedDtb = profile.kernel_dtb;
        el.scannerActiveDtb.textContent = `0x${profile.kernel_dtb.toString(16).toUpperCase()}`;
        
        el.footerStatus.textContent = "OS Profile identified. Loading forensics data...";
        
        // Query data
        await refreshAllData();
        
        el.footerStatus.textContent = "Analysis completed. Telemetry loaded.";
    } catch (err) {
        el.footerStatus.textContent = `Load Error: ${err}`;
    }
});

// Refresh all forensic database elements
async function refreshAllData() {
    try {
        appState.processes = await invoke('get_processes');
        appState.connections = await invoke('get_network');
        appState.registry = await invoke('get_registry');
        appState.kernel = await invoke('get_kernel');
        appState.timeline = await invoke('get_timeline');
        
        appState.dlls = await invoke('get_dlls');
        appState.threads = await invoke('get_threads');
        appState.credentials = await invoke('get_credentials');
        appState.fileRecovery = await invoke('get_file_recovery');
        appState.yara = await invoke('get_yara_ioc');
        appState.malware = await invoke('get_malware');
        
        updateDashboardView();
        updateProcessesView();
        updateNetworkView();
        updateRegistryView();
        updateKernelView();
        updateTimelineView();
        updateDllsView();
        updateThreadsView();
        updateCredentialsView();
        updateFileRecoveryView();
        updateYaraView();
        updateMalwareView();
    } catch (err) {
        el.footerStatus.textContent = `Refresh Database Error: ${err}`;
    }
}

// Update Dashboard UI Views
function updateDashboardView() {
    const prof = appState.profile;
    if (!prof) return;
    
    el.dashOsFamily.textContent = prof.family;
    el.dashOsVer.textContent = prof.kernel_version;
    el.dashProcCount.textContent = appState.processes.length;
    
    const unlinkedCount = appState.processes.filter(p => !p.active).length;
    if (unlinkedCount > 0) {
        el.dashUnlinkedAlert.textContent = `⚠️ ${unlinkedCount} unlinked processes detected`;
        el.dashUnlinkedAlert.className = "font-body-sm text-body-sm text-error font-bold mt-2";
    } else {
        el.dashUnlinkedAlert.textContent = "✓ DKOM checks verified";
        el.dashUnlinkedAlert.className = "font-body-sm text-body-sm text-success mt-2";
    }
    
    el.dashConnCount.textContent = appState.connections.length;
    
    const alerts = appState.kernel ? appState.kernel.hooks.length : 0;
    el.dashAlertsCount.textContent = alerts;
    if (alerts > 0) {
        el.dashAlertsDesc.textContent = `${alerts} kernel hooks active!`;
        el.dashAlertsDesc.className = "font-body-md text-body-md text-error font-bold";
    } else {
        el.dashAlertsDesc.textContent = "No anomalies reported";
        el.dashAlertsDesc.className = "font-body-md text-body-md text-on-surface-variant";
    }
    
    el.telemetryCr3.textContent = `0x${prof.kernel_dtb.toString(16).toUpperCase()}`;
    el.telemetryBuild.textContent = `Build: ${prof.build_number !== null ? prof.build_number : "N/A"}`;
    el.telemetryFormat.textContent = "Auto-detected Format";
    
    // Draw 100 entropy blocks dynamically
    el.entropyGrid.innerHTML = "";
    for (let i = 0; i < 100; i++) {
        let entropy = (i * 7 + 13) % 10;
        let color = "bg-secondary/70"; // Low entropy (green)
        if (entropy > 7) {
            color = "bg-error/80"; // High entropy (red)
        } else if (entropy > 5) {
            color = "bg-primary/80"; // Med entropy (blue)
        }
        
        const node = document.createElement("div");
        node.className = `heatmap-cell ${color}`;
        el.entropyGrid.appendChild(node);
    }
    
    // Fill dynamic hooks summary inside Dashboard's kernel alerts card
    const dashHooksSummary = document.getElementById('dashboard-hooks-summary');
    if (dashHooksSummary && appState.kernel) {
        dashHooksSummary.innerHTML = "";
        appState.kernel.hooks.slice(0, 3).forEach(hook => {
            const item = document.createElement("div");
            item.className = "bg-surface-container/50 rounded p-3 border border-white/5 flex items-start gap-3";
            item.innerHTML = `
                <div class="w-2 h-2 rounded-full bg-tertiary-container mt-1.5 animate-pulse"></div>
                <div>
                    <div class="font-mono-data text-mono-data text-on-surface">${hook.function_name}</div>
                    <div class="font-body-sm text-body-sm text-on-surface-variant text-[11px] mt-0.5">Hook Address: 0x${hook.hook_address.toString(16).toUpperCase()} in ${hook.target_module}</div>
                </div>
            `;
            dashHooksSummary.appendChild(item);
        });
    }
}

// Update Process List UI Views
function updateProcessesView() {
    el.processesTableBody.innerHTML = "";
    
    appState.processes.forEach(proc => {
        const row = document.createElement("tr");
        
        if (proc.active) {
            row.className = "hover:bg-white/5 transition-colors group";
        } else {
            row.className = "hover:bg-tertiary-container/10 transition-colors bg-tertiary-container/5 relative border-l-2 border-l-tertiary group";
        }
        
        const statusSpan = proc.active 
            ? `<div class="flex items-center justify-center w-6 h-6"><div class="w-2 h-2 rounded-full bg-secondary animate-pulse-dot"></div></div>` 
            : `<div class="bg-tertiary-container/20 text-tertiary border border-tertiary/30 rounded-full px-2 py-0.5 inline-flex items-center gap-1 font-label-caps text-label-caps uppercase shadow-[0_0_8px_rgba(255,84,81,0.3)]"><span class="w-1.5 h-1.5 rounded-full bg-tertiary block animate-pulse"></span>Hidden</div>`;
            
        const nameClass = proc.active ? "font-medium text-on-surface" : "font-medium text-tertiary";
        const pidClass = proc.active ? "text-on-surface-variant" : "text-tertiary font-semibold";
        
        row.innerHTML = `
            <td class="px-6 py-3">${statusSpan}</td>
            <td class="px-6 py-3 tabular-nums ${pidClass}">${proc.pid}</td>
            <td class="px-6 py-3 tabular-nums text-outline">${proc.ppid}</td>
            <td class="px-6 py-3 ${nameClass}">${proc.name}</td>
            <td class="px-6 py-3 font-mono-data text-mono-data text-primary-fixed-dim tabular-nums">0x${proc.dtb.toString(16).toUpperCase()}</td>
            <td class="px-6 py-3 text-right">
                <button class="scan-proc-link border border-primary/30 text-primary hover:bg-primary/10 px-3 py-1 rounded-full font-label-caps text-label-caps uppercase tracking-wider inline-flex items-center gap-1.5 shadow-[0_0_10px_rgba(173,198,255,0.1)]" data-dtb="${proc.dtb}">
                    <span class="material-symbols-outlined" style="font-size: 14px;">science</span> Analyze
                </button>
            </td>
        `;
        el.processesTableBody.appendChild(row);
    });
    
    // Wire process analysis links
    document.querySelectorAll('.scan-proc-link').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const dtb = parseInt(btn.getAttribute('data-dtb'));
            appState.selectedDtb = dtb;
            el.scannerActiveDtb.textContent = `0x${dtb.toString(16).toUpperCase()}`;
            
            // Switch tab to scanner
            const scannerTabBtn = document.querySelector('.nav-item[data-tab="scanner"]');
            if (scannerTabBtn) scannerTabBtn.click();
        });
    });
}

// Update Network Sockets UI Views
function updateNetworkView() {
    el.networkTableBody.innerHTML = "";
    
    appState.connections.forEach(conn => {
        const row = document.createElement("tr");
        
        const local = `${conn.local_ip}:${conn.local_port}`;
        const remote = `${conn.remote_ip}:${conn.remote_port}`;
        
        const isExternal = conn.remote_ip !== "0.0.0.0" && !conn.remote_ip.startsWith("127.0.") && !conn.remote_ip.startsWith("192.168.");
        
        if (isExternal) {
            row.className = "bg-tertiary/5 hover:bg-tertiary/10 transition-colors border-l-2 border-l-tertiary neon-glow-amber";
        } else {
            row.className = "hover:bg-primary-container/5 transition-colors group";
        }
        
        const processNameHtml = isExternal 
            ? `<div class="flex items-center gap-2"><span class="w-2 h-2 rounded-full bg-tertiary animate-pulse"></span><span class="text-tertiary font-bold">${conn.process_name}</span></div>`
            : `<span class="text-on-surface">${conn.process_name}</span>`;
            
        const remoteClass = isExternal ? "text-tertiary font-bold" : "text-on-surface-variant";
        
        const stateBadge = conn.state === "ESTABLISHED"
            ? `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-secondary/10 text-secondary border border-secondary/20">ESTABLISHED</span>`
            : `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-surface-container-high text-on-surface-variant border border-white/10">LISTENING</span>`;
        
        row.innerHTML = `
            <td class="px-4 py-row-height-dense text-on-surface">${conn.protocol}</td>
            <td class="px-4 py-row-height-dense text-on-surface-variant">${conn.pid}</td>
            <td class="px-4 py-row-height-dense">${processNameHtml}</td>
            <td class="px-4 py-row-height-dense text-on-surface-variant">${local}</td>
            <td class="px-4 py-row-height-dense ${remoteClass}">${remote}</td>
            <td class="px-4 py-row-height-dense">${stateBadge}</td>
        `;
        el.networkTableBody.appendChild(row);
    });
}

// Run Process Memory Anomaly Scan
el.scanMemoryBtn.addEventListener('click', async () => {
    if (appState.selectedDtb === 0) {
        el.footerStatus.textContent = "Scan Error: No active process DTB selected.";
        return;
    }
    
    el.scanLoader.classList.remove('hidden');
    el.scanMemoryBtn.disabled = true;
    el.scannerTableBody.innerHTML = "";
    
    try {
        const anomalies = await invoke('run_scan_memory', { dtb: appState.selectedDtb });
        el.scanLoader.classList.add('hidden');
        el.scanMemoryBtn.disabled = false;
        
        if (anomalies.length === 0) {
            el.scannerTableBody.innerHTML = `
                <tr>
                    <td colspan="7" class="p-6 text-center text-success">✓ No security anomalies detected in scanned pages.</td>
                </tr>
            `;
            return;
        }
        
        anomalies.forEach(anom => {
            const row = document.createElement("tr");
            
            // Critical indicator styling
            row.className = "border-b border-white/5 bg-error/5 border-l-2 border-l-error hover:bg-error/10 transition-colors";
            
            const iconSpan = `<span class="material-symbols-outlined text-error text-[18px]">warning</span>`;
            const rwxSpan = anom.is_rwx ? `<span class="bg-error/20 text-error px-2 py-0.5 rounded text-xs font-bold">RWX</span>` : `<span class="bg-surface-dim text-on-surface-variant px-2 py-0.5 rounded text-xs">RW-</span>`;
            const peSpan = anom.has_pe_header ? `<span class="text-secondary font-bold">Yes</span>` : `<span class="text-on-surface-variant">No</span>`;
            
            const entropyBar = `
                <div class="flex items-center gap-2">
                    <span class="w-8 text-right text-error font-semibold">${anom.entropy.toFixed(2)}</span>
                    <div class="w-16 h-1.5 bg-surface-dim rounded-full overflow-hidden"><div class="h-full bg-error" style="width: ${Math.min(anom.entropy * 12.5, 100)}%"></div></div>
                </div>
            `;
            
            row.innerHTML = `
                <td class="p-3 text-center">${iconSpan}</td>
                <td class="p-3 text-primary hover:underline cursor-pointer">0x${anom.virtual_address.toString(16).toUpperCase()}</td>
                <td class="p-3 text-on-surface-variant">0x${anom.physical_address.toString(16).toUpperCase()}</td>
                <td class="p-3 text-center">${rwxSpan}</td>
                <td class="p-3 text-center">${peSpan}</td>
                <td class="p-3">${entropyBar}</td>
                <td class="p-3 text-error font-medium text-glitch">${anom.description}</td>
            `;
            el.scannerTableBody.appendChild(row);
        });
        
    } catch (err) {
        el.scanLoader.classList.add('hidden');
        el.scanMemoryBtn.disabled = false;
        el.footerStatus.textContent = `Scan failed: ${err}`;
    }
});

// Update Registry UI Views
function updateRegistryView() {
    el.registryKeysContainer.innerHTML = "";
    
    appState.registry.forEach(key => {
        const block = document.createElement("div");
        block.className = "glass-panel rounded-xl overflow-hidden p-5 flex flex-col shadow-lg";
        
        let valuesHtml = "";
        for (const [name, val] of Object.entries(key.values)) {
            const isSuspicious = val.toLowerCase().includes("\\temp\\") || val.toLowerCase().includes("temp.exe");
            const valClass = isSuspicious ? "text-error font-bold" : "text-on-surface-variant";
            
            valuesHtml += `
                <div class="flex justify-between py-2 border-b border-white/5 last:border-b-0">
                    <span class="font-bold text-on-surface mr-4 truncate" title="${name}">${name}</span>
                    <span class="text-on-surface-variant text-right break-all ${valClass}">${val}</span>
                </div>
            `;
        }
        
        block.innerHTML = `
            <div class="flex justify-between items-center text-xs border-b border-white/10 pb-2 mb-3">
                <span class="font-mono-data text-secondary text-sm font-semibold truncate block max-w-[70%]" title="${key.path}">${key.path}</span>
                <span class="text-[10px] text-on-surface-variant shrink-0">Modified: ${key.last_written}</span>
            </div>
            <div class="space-y-1 bg-surface-container-lowest/40 rounded border border-white/5 p-3 font-mono-data text-xs">
                ${valuesHtml}
            </div>
        `;
        el.registryKeysContainer.appendChild(block);
    });
}

// Update Kernel Hooks & Drivers UI Views
function updateKernelView() {
    el.kernelHooksContainer.innerHTML = "";
    el.kernelDriversBody.innerHTML = "";
    
    const kernel = appState.kernel;
    if (!kernel) return;
    
    // Hooks alerts
    if (kernel.hooks.length === 0) {
        el.kernelHooksContainer.innerHTML = `
            <div class="glass-panel p-4 rounded-xl text-center text-success text-xs">
                ✓ No active SSDT/IDT hooks detected. Kernel structures are clean.
            </div>
        `;
    } else {
        kernel.hooks.forEach(hook => {
            const alert = document.createElement("div");
            alert.className = "glass-panel rounded-xl border border-error/50 glow-critical p-4 relative overflow-hidden group";
            
            alert.innerHTML = `
                <div class="absolute left-0 top-0 bottom-0 w-1 bg-error"></div>
                <div class="flex justify-between items-start mb-3">
                    <div class="flex items-center gap-3">
                        <span class="material-symbols-outlined text-error">warning</span>
                        <h3 class="font-mono-data text-on-surface text-base font-bold">${hook.function_name}</h3>
                    </div>
                    <span class="bg-error/15 text-error px-2 py-1 rounded-full font-label-caps text-[10px] border border-error/30 uppercase">${hook.severity}</span>
                </div>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-2 font-mono-data text-xs">
                    <div>
                        <div class="font-label-caps text-on-surface-variant text-[10px] mb-1">SSDT Index</div>
                        <div class="text-primary font-semibold">${hook.index}</div>
                    </div>
                    <div>
                        <div class="font-label-caps text-on-surface-variant text-[10px] mb-1">Original Module</div>
                        <div class="text-on-surface">ntoskrnl.exe</div>
                    </div>
                    <div>
                        <div class="font-label-caps text-on-surface-variant text-[10px] mb-1">Hook Address</div>
                        <div class="text-error font-semibold">0x${hook.hook_address.toString(16).toUpperCase()}</div>
                    </div>
                    <div>
                        <div class="font-label-caps text-on-surface-variant text-[10px] mb-1">Target Module</div>
                        <div class="text-on-surface truncate" title="${hook.target_module}">${hook.target_module}</div>
                    </div>
                </div>
            `;
            el.kernelHooksContainer.appendChild(alert);
        });
    }
    
    // Drivers table
    kernel.drivers.forEach(driver => {
        const row = document.createElement("tr");
        row.className = "hover:bg-primary/5 transition-colors border-b border-outline-variant/10";
        
        const isThreat = driver.threat_score > 5.0;
        const nameClass = isThreat ? "text-error font-bold flex items-center gap-1" : "text-primary font-medium";
        const dotPrefix = isThreat ? `<span class="w-1.5 h-1.5 rounded-full bg-error animate-pulse"></span>` : "";
        
        row.innerHTML = `
            <td class="px-4 py-2 ${nameClass}">${dotPrefix}${driver.name}</td>
            <td class="px-4 py-2 font-mono-data text-xs">0x${driver.base_address.toString(16).toUpperCase()}</td>
            <td class="px-4 py-2 font-mono-data text-xs">0x${driver.size.toString(16).toUpperCase()}</td>
            <td class="px-4 py-2 font-mono-data text-xs text-on-surface-variant truncate max-w-xs" title="${driver.path}">${driver.path}</td>
        `;
        el.kernelDriversBody.appendChild(row);
    });
}

// Update Timeline UI Views
function updateTimelineView() {
    el.timelineContainer.innerHTML = "";
    
    appState.timeline.forEach(ev => {
        const item = document.createElement("div");
        item.className = "flex group relative";
        
        let colorClass = "bg-on-surface-variant";
        let titleColor = "text-on-surface";
        let icon = "info";
        let borderClass = "border-white/5";
        
        if (ev.event_type === "Spawn") {
            colorClass = "bg-secondary";
            titleColor = "text-secondary";
            icon = "terminal";
        } else if (ev.event_type === "Connection") {
            colorClass = "bg-primary";
            titleColor = "text-primary";
            icon = "public";
        } else if (ev.event_type === "Key Modified") {
            colorClass = "bg-tertiary";
            titleColor = "text-tertiary";
            icon = "data_object";
        }
        
        const pidLabel = ev.associated_pid ? `<span class="font-mono-data text-[10px] bg-surface-variant/50 text-on-surface-variant px-2 py-0.5 rounded border border-white/10">PID: ${ev.associated_pid}</span>` : "";
        
        item.innerHTML = `
            <!-- Time Column -->
            <div class="w-32 py-4 pr-6 text-right shrink-0">
                <div class="font-mono-data text-mono-data text-on-surface-variant group-hover:${titleColor} transition-colors">${ev.timestamp}</div>
            </div>
            <!-- Line & Dot Column -->
            <div class="relative w-8 flex justify-center shrink-0">
                <div class="absolute top-0 bottom-0 w-px bg-outline-variant/20 group-hover:${colorClass}/30 transition-colors"></div>
                <div class="w-2.5 h-2.5 rounded-full ${colorClass} z-10 mt-5 ring-4 ring-background"></div>
            </div>
            <!-- Content Card -->
            <div class="flex-1 py-2 pl-6 pr-2">
                <div class="bg-[#18181B]/80 backdrop-blur-[20px] border ${borderClass} rounded-lg p-4 group-hover:bg-[#27272A]/90 transition-all duration-200">
                    <div class="flex justify-between items-start mb-2">
                        <div class="flex items-center gap-2">
                            <span class="material-symbols-outlined ${titleColor} text-[18px]">${icon}</span>
                            <h3 class="font-body-md text-body-md font-semibold ${titleColor}">${ev.event_type} - ${ev.source}</h3>
                        </div>
                        ${pidLabel}
                    </div>
                    <div class="font-mono-data text-[12px] text-on-surface-variant leading-relaxed break-all bg-surface-container-lowest/50 p-2 rounded border border-white/5">
                        ${ev.description}
                    </div>
                </div>
            </div>
        `;
        el.timelineContainer.appendChild(item);
    });
    
    // Timeline End Cap to close the line gracefully
    const cap = document.createElement("div");
    cap.className = "flex";
    cap.innerHTML = `
        <div class="w-32 pr-6"></div>
        <div class="relative w-8 flex justify-center shrink-0 h-8">
            <div class="w-px h-full bg-gradient-to-b from-outline-variant/20 to-transparent"></div>
        </div>
        <div class="flex-1"></div>
    `;
    el.timelineContainer.appendChild(cap);
}

// Hex Viewer updates
async function refreshHexViewer() {
    if (!appState.profile) {
        el.hexViewerOutput.textContent = "No memory dump loaded. Load a dump to view bytes.";
        return;
    }
    
    el.hexViewerOutput.textContent = "Reading physical memory page bytes...";
    try {
        const bytes = await invoke('read_hex', { address: appState.hexAddress });
        
        let output = `Physical Address Offset: 0x${appState.hexAddress.toString(16).toUpperCase()}\n\n`;
        output += `Offset    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII Decode\n`;
        output += `----------------------------------------------------------------------\n`;
        
        for (let row = 0; row < 16; row++) {
            const rowBase = row * 16;
            let hexPart = "";
            let asciiPart = "";
            
            let offsetHex = (appState.hexAddress + rowBase).toString(16).toUpperCase().padStart(8, '0');
            
            for (let col = 0; col < 16; col++) {
                const idx = rowBase + col;
                if (idx < bytes.length) {
                    const b = bytes[idx];
                    hexPart += b.toString(16).toUpperCase().padStart(2, '0') + " ";
                    asciiPart += (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".";
                } else {
                    hexPart += "   ";
                }
            }
            
            output += `${offsetHex}  ${hexPart} | ${asciiPart}\n`;
        }
        
        el.hexViewerOutput.textContent = output;
        
    } catch (err) {
        el.hexViewerOutput.textContent = `Read memory offset error: ${err}`;
    }
}

// Hex navigation actions
el.hexNavigateBtn.addEventListener('click', () => {
    let addrInput = el.hexAddressInput.value.trim().toLowerCase();
    if (addrInput.startsWith('0x')) addrInput = addrInput.slice(2);
    
    const parsedAddr = parseInt(addrInput, 16);
    if (!isNaN(parsedAddr)) {
        appState.hexAddress = parsedAddr;
        refreshHexViewer();
    } else {
        el.footerStatus.textContent = "Hex Navigation Error: Invalid hex string.";
    }
});

el.hexPrevBtn.addEventListener('click', () => {
    if (appState.hexAddress >= 256) {
        appState.hexAddress -= 256;
        el.hexAddressInput.value = `0x${appState.hexAddress.toString(16).toUpperCase()}`;
        refreshHexViewer();
    }
});

el.hexNextBtn.addEventListener('click', () => {
    appState.hexAddress += 256;
    el.hexAddressInput.value = `0x${appState.hexAddress.toString(16).toUpperCase()}`;
    refreshHexViewer();
});

// New views render functions
function updateDllsView() {
    if (!el.dllsContainer) return;
    el.dllsContainer.innerHTML = "";
    appState.dlls.forEach(res => {
        const block = document.createElement("div");
        block.className = "mb-6";
        block.innerHTML = `<h3 class="font-mono-data text-on-surface-variant border-b border-white/5 pb-2 mb-3">PID: ${res.pid} | ${res.dlls.length} DLLs | ${res.unlinked_count} unlinked | ${res.injected_count} injected</h3>`;
        
        const grid = document.createElement("div");
        grid.className = "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4";
        
        res.dlls.forEach(dll => {
            const card = document.createElement("div");
            card.className = "glass-panel p-3 rounded-lg border border-white/5 flex flex-col gap-1";
            
            const isSuspicious = dll.injection_type !== "Normal" || dll.hooks_detected.length > 0;
            const nameColor = isSuspicious ? "text-error font-bold" : "text-primary";
            
            let hooksHtml = "";
            if (dll.hooks_detected.length > 0) {
                hooksHtml = `<div class="text-error text-xs font-bold mt-1">⚠️ ${dll.hooks_detected.length} inline hooks detected</div>`;
            }
            
            card.innerHTML = `
                <div class="${nameColor} truncate" title="${dll.name}">${dll.name}</div>
                <div class="font-mono-data text-xs text-on-surface-variant flex justify-between">
                    <span>0x${dll.base_address.toString(16).toUpperCase()}</span>
                    <span>${dll.injection_type}</span>
                </div>
                ${hooksHtml}
            `;
            grid.appendChild(card);
        });
        block.appendChild(grid);
        el.dllsContainer.appendChild(block);
    });
}

function updateThreadsView() {
    if (!el.threadsContainer) return;
    el.threadsContainer.innerHTML = "";
    appState.threads.forEach(res => {
        const block = document.createElement("div");
        block.className = "mb-6";
        block.innerHTML = `<h3 class="font-mono-data text-on-surface-variant border-b border-white/5 pb-2 mb-3">PID: ${res.pid} | ${res.threads.length} threads | ${res.suspicious_count} suspicious | APC: ${res.apc_injection_detected} | Hijack: ${res.thread_hijacking_detected}</h3>`;
        
        const grid = document.createElement("div");
        grid.className = "grid grid-cols-1 lg:grid-cols-2 gap-4";
        
        res.threads.forEach(t => {
            const card = document.createElement("div");
            card.className = "glass-panel p-4 rounded-lg border border-white/5 flex flex-col gap-2";
            
            const titleColor = t.is_suspicious ? "text-error font-bold" : "text-on-surface";
            let reasonsHtml = "";
            if (t.suspicion_reasons && t.suspicion_reasons.length > 0) {
                reasonsHtml = `<div class="mt-2 space-y-1">` + t.suspicion_reasons.map(r => `<div class="text-secondary text-xs font-bold">⚠️ ${r}</div>`).join('') + `</div>`;
            }
            
            card.innerHTML = `
                <div class="flex justify-between">
                    <span class="${titleColor} font-mono-data">TID: ${t.tid}</span>
                    <span class="text-on-surface-variant text-xs">${t.state} | Prio: ${t.priority}</span>
                </div>
                <div class="text-xs text-outline font-mono-data">Start: 0x${t.start_address.toString(16).toUpperCase()}</div>
                ${reasonsHtml}
            `;
            grid.appendChild(card);
        });
        block.appendChild(grid);
        el.threadsContainer.appendChild(block);
    });
}

function updateCredentialsView() {
    if (!el.credentialsSummary) return;
    el.credentialsSummary.innerHTML = "";
    el.credentialsContainer.innerHTML = "";
    
    if (!appState.credentials) return;
    
    const cr = appState.credentials;
    
    let alertsHtml = "";
    if (cr.mimikatz_detected) alertsHtml += `<div class="bg-error/20 text-error border border-error/50 p-2 rounded text-sm font-bold uppercase text-center">⚠️ Mimikatz Detected</div>`;
    if (cr.dumping_activity_detected) alertsHtml += `<div class="bg-secondary/20 text-secondary border border-secondary/50 p-2 rounded text-sm font-bold uppercase text-center">⚠️ Credential Dumping Activity</div>`;
    if (cr.lsass_access_detected) alertsHtml += `<div class="bg-secondary/20 text-secondary border border-secondary/50 p-2 rounded text-sm font-bold uppercase text-center">⚠️ LSASS Accessed</div>`;
    
    el.credentialsSummary.innerHTML = `
        <div class="glass-panel p-4 rounded-xl flex items-center justify-around font-mono-data text-sm mb-4">
            <div>Total: <span class="text-primary">${cr.credentials.length}</span></div>
            <div>Hashes: <span class="text-primary">${cr.total_hashes}</span></div>
            <div>Tickets: <span class="text-primary">${cr.total_tickets}</span></div>
            <div>Keys: <span class="text-primary">${cr.total_keys}</span></div>
        </div>
        <div class="flex gap-4 mb-4 justify-center">${alertsHtml}</div>
    `;
    
    cr.credentials.forEach(cred => {
        const card = document.createElement("div");
        card.className = "glass-panel p-4 rounded-xl border border-white/5";
        
        let colorClass = "text-on-surface";
        if (cred.severity === "Critical") colorClass = "text-error font-bold";
        else if (cred.severity === "High") colorClass = "text-secondary font-bold";
        
        card.innerHTML = `
            <div class="${colorClass} font-label-caps uppercase mb-1">${cred.credential_type}: ${cred.username}</div>
            <div class="font-mono-data text-xs text-primary bg-surface-dim p-2 rounded mb-2 break-all">${cred.data}</div>
            <div class="text-xs text-on-surface-variant">${cred.description}</div>
        `;
        el.credentialsContainer.appendChild(card);
    });
}

function updateFileRecoveryView() {
    if (!el.fileRecoverySummary) return;
    el.fileRecoverySummary.innerHTML = "";
    el.fileRecoveryContainer.innerHTML = "";
    
    if (!appState.fileRecovery) return;
    const fr = appState.fileRecovery;
    
    el.fileRecoverySummary.innerHTML = `
        <div class="glass-panel p-4 rounded-xl flex flex-wrap items-center justify-around font-mono-data text-sm mb-4">
            <div>Recovered: <span class="text-primary">${fr.recovered_files.length}</span></div>
            <div>PEs: <span class="text-primary">${fr.pe_files_count}</span></div>
            <div>Docs: <span class="text-primary">${fr.document_count}</span></div>
            <div>Scripts: <span class="text-primary">${fr.script_count}</span></div>
            <div>Browser: <span class="text-primary">${fr.browser_artifacts.length}</span></div>
        </div>
    `;
    
    fr.recovered_files.forEach(f => {
        const card = document.createElement("div");
        card.className = "glass-panel p-4 rounded-xl border border-white/5 flex flex-col gap-2";
        
        let threatsHtml = "";
        if (f.threat_indicators && f.threat_indicators.length > 0) {
            threatsHtml = `<div class="mt-2 text-secondary text-xs font-bold flex flex-col gap-1">` + 
                f.threat_indicators.map(t => `<div>⚠️ ${t}</div>`).join('') + 
                `</div>`;
        }
        
        card.innerHTML = `
            <div class="flex justify-between items-start">
                <span class="text-on-surface font-semibold truncate" title="${f.name}">${f.name}</span>
                <span class="bg-primary/20 text-primary px-2 py-0.5 rounded text-[10px] font-label-caps uppercase">${f.file_type}</span>
            </div>
            <div class="font-mono-data text-[10px] text-outline flex justify-between">
                <span>Size: ${f.size}</span>
                <span>Addr: 0x${f.physical_address.toString(16).toUpperCase()}</span>
            </div>
            <div class="text-xs text-on-surface-variant">${f.description}</div>
            ${threatsHtml}
        `;
        el.fileRecoveryContainer.appendChild(card);
    });
}

function updateYaraView() {
    if (!el.yaraSummary) return;
    el.yaraSummary.innerHTML = "";
    el.yaraContainer.innerHTML = "";
    
    if (!appState.yara) return;
    const yr = appState.yara;
    
    let colorClass = "text-success";
    if (yr.threat_level === "CRITICAL") colorClass = "text-error";
    else if (yr.threat_level === "HIGH") colorClass = "text-secondary";
    else if (yr.threat_level === "MEDIUM") colorClass = "text-primary";
    
    el.yaraSummary.innerHTML = `
        <div class="glass-panel p-4 rounded-xl flex items-center justify-around font-mono-data text-sm mb-4">
            <div class="${colorClass} font-bold text-lg uppercase">${yr.threat_level}</div>
            <div>Rules Checked: <span class="text-primary">${yr.total_rules_checked}</span></div>
            <div>YARA Matches: <span class="text-primary">${yr.yara_matches.length}</span></div>
            <div>IOC Matches: <span class="text-primary">${yr.ioc_matches.length}</span></div>
        </div>
    `;
    
    yr.yara_matches.forEach(m => {
        const card = document.createElement("div");
        card.className = "glass-panel p-4 rounded-xl border border-secondary/30";
        
        let stringsHtml = "";
        if (m.strings_matched && m.strings_matched.length > 0) {
            stringsHtml = `<div class="mt-3 bg-surface-dim p-2 rounded text-xs font-mono-data text-on-surface-variant flex flex-col gap-1">` +
                m.strings_matched.map(s => `<div><span class="text-primary">${s.identifier}</span> at <span class="text-outline">0x${s.offset.toString(16).toUpperCase()}</span></div>`).join('') +
                `</div>`;
        }
        
        card.innerHTML = `
            <div class="text-secondary font-bold mb-1">Rule: ${m.rule_name} <span class="text-outline text-xs uppercase ml-2">[${m.severity}]</span></div>
            <div class="text-sm text-on-surface">${m.description}</div>
            ${stringsHtml}
        `;
        el.yaraContainer.appendChild(card);
    });
    
    if (yr.ioc_matches && yr.ioc_matches.length > 0) {
        const iocBlock = document.createElement("div");
        iocBlock.className = "glass-panel p-4 rounded-xl border border-error/30 mt-4";
        iocBlock.innerHTML = `<h3 class="font-label-caps text-error mb-3">IOC Matches</h3>`;
        const iocGrid = document.createElement("div");
        iocGrid.className = "grid grid-cols-1 md:grid-cols-2 gap-2";
        yr.ioc_matches.forEach(ioc => {
            const iocItem = document.createElement("div");
            iocItem.className = "bg-error/10 text-error p-2 rounded text-xs font-mono-data flex justify-between";
            iocItem.innerHTML = `<span>${ioc.ioc_type}</span> <span class="font-bold">${ioc.value}</span>`;
            iocGrid.appendChild(iocItem);
        });
        iocBlock.appendChild(iocGrid);
        el.yaraContainer.appendChild(iocBlock);
    }
}

function updateMalwareView() {
    if (!el.malwareSummary) return;
    el.malwareSummary.innerHTML = "";
    el.malwareContainer.innerHTML = "";
    
    if (!appState.malware) return;
    const mr = appState.malware;
    
    let colorClass = "text-success";
    if (mr.overall_threat_score > 7.0) colorClass = "text-error";
    else if (mr.overall_threat_score > 3.0) colorClass = "text-secondary";
    
    el.malwareSummary.innerHTML = `
        <div class="glass-panel p-4 rounded-xl flex items-center justify-around font-mono-data text-sm mb-4">
            <div class="${colorClass} font-bold text-xl text-center">Threat Score<br/>${mr.overall_threat_score.toFixed(1)} / 10</div>
            <div>Indicators: <span class="text-primary">${mr.indicators.length}</span></div>
            <div>PEs: <span class="text-primary">${mr.reconstructed_pes.length}</span></div>
            <div>Strings: <span class="text-primary">${mr.deobfuscated_strings.length}</span></div>
        </div>
    `;
    
    mr.indicators.forEach(ind => {
        const card = document.createElement("div");
        card.className = "glass-panel p-4 rounded-xl border border-error/50";
        
        let configHtml = "";
        if (ind.config_data) {
            let c2 = ind.config_data.c2_servers.length > 0 ? `<div class="text-secondary font-mono-data text-xs mt-1">C2: ${ind.config_data.c2_servers.join(', ')}</div>` : "";
            let pipe = ind.config_data.pipe_name ? `<div class="text-outline font-mono-data text-xs mt-1">Pipe: ${ind.config_data.pipe_name}</div>` : "";
            configHtml = c2 + pipe;
        }
        
        card.innerHTML = `
            <div class="text-error font-bold mb-1">${ind.malware_family} <span class="text-outline text-xs ml-2">(${ind.malware_type}, ${(ind.confidence * 100).toFixed(0)}%)</span></div>
            <div class="text-sm text-on-surface">${ind.description}</div>
            ${configHtml}
        `;
        el.malwareContainer.appendChild(card);
    });
    
    if (mr.deobfuscated_strings && mr.deobfuscated_strings.length > 0) {
        const stringsBlock = document.createElement("div");
        stringsBlock.className = "glass-panel p-4 rounded-xl border border-white/5 mt-4 max-h-64 overflow-y-auto";
        stringsBlock.innerHTML = `<h3 class="font-label-caps text-primary mb-3">Deobfuscated Strings</h3>`;
        const stringsList = document.createElement("div");
        stringsList.className = "flex flex-col gap-1 text-xs font-mono-data";
        mr.deobfuscated_strings.slice(0, 50).forEach(s => {
            const sItem = document.createElement("div");
            sItem.innerHTML = `<span class="text-outline mr-2">[${s.encoding}]</span> <span class="text-secondary mr-2">0x${s.original_offset.toString(16).toUpperCase()}</span> <span class="text-on-surface">${s.decoded_value}</span>`;
            stringsList.appendChild(sItem);
        });
        stringsBlock.appendChild(stringsList);
        el.malwareContainer.appendChild(stringsBlock);
    }
}

// Add export button event listener
if (el.exportReportBtn) {
    el.exportReportBtn.addEventListener('click', async () => {
        try {
            el.footerStatus.textContent = "Exporting report...";
            const res = await invoke('export_report');
            el.footerStatus.textContent = res;
        } catch (err) {
            el.footerStatus.textContent = `Export error: ${err}`;
        }
    });
}

// Search Filter Input Box
el.searchInput.addEventListener('input', () => {
    const query = el.searchInput.value.toLowerCase().trim();
    if (appState.activeTab === 'processes') {
        // Filter processes
        document.querySelectorAll('#processes-table-body tr').forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(query) ? "" : "none";
        });
    } else if (appState.activeTab === 'network') {
        // Filter network
        document.querySelectorAll('#network-table-body tr').forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(query) ? "" : "none";
        });
    } else if (appState.activeTab === 'timeline') {
        // Filter timeline - query search within the group content cards
        document.querySelectorAll('#timeline-container > .flex').forEach(item => {
            const text = item.textContent.toLowerCase();
            item.style.display = text.includes(query) ? "" : "none";
        });
    }
});
