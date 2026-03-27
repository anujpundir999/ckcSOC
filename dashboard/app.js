/* ═══════════════════════════════════════════════════════
   ckcSOC Dashboard — Data Fetching & Chart Rendering
   ═══════════════════════════════════════════════════════ */

const API_BASE = '/api/dashboard';

// ── Utility ──
function $(sel) { return document.querySelector(sel); }
function $$(sel) { return document.querySelectorAll(sel); }

function formatTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleString('en-IN', {
        month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
}

function truncate(s, n = 12) {
    return s && s.length > n ? s.slice(0, n) + '…' : (s || '—');
}

const CHART_COLORS = [
    '#6366f1', '#06b6d4', '#10b981', '#f59e0b',
    '#f43f5e', '#a855f7', '#ec4899', '#14b8a6'
];

// ── Minimal Canvas Chart Library ──
class MiniChart {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        this.ctx = this.canvas.getContext('2d');
        this.dpr = window.devicePixelRatio || 1;
    }

    resize() {
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.w = rect.width;
        this.h = rect.height;
        this.canvas.width = this.w * this.dpr;
        this.canvas.height = this.h * this.dpr;
        this.canvas.style.width = this.w + 'px';
        this.canvas.style.height = this.h + 'px';
        this.ctx.scale(this.dpr, this.dpr);
    }

    drawDonut(data, legendId) {
        this.resize();
        const cx = this.w / 2, cy = this.h / 2;
        const radius = Math.min(cx, cy) - 20;
        const inner = radius * 0.55;
        const total = data.reduce((s, d) => s + d.value, 0);
        if (total === 0) return;

        let angle = -Math.PI / 2;
        data.forEach((d, i) => {
            const slice = (d.value / total) * Math.PI * 2;
            this.ctx.beginPath();
            this.ctx.arc(cx, cy, radius, angle, angle + slice);
            this.ctx.arc(cx, cy, inner, angle + slice, angle, true);
            this.ctx.closePath();
            this.ctx.fillStyle = CHART_COLORS[i % CHART_COLORS.length];
            this.ctx.fill();
            angle += slice;
        });

        // Center text
        this.ctx.fillStyle = '#f1f5f9';
        this.ctx.font = '700 24px Inter';
        this.ctx.textAlign = 'center';
        this.ctx.textBaseline = 'middle';
        this.ctx.fillText(total.toLocaleString(), cx, cy - 8);
        this.ctx.font = '400 11px Inter';
        this.ctx.fillStyle = '#94a3b8';
        this.ctx.fillText('total', cx, cy + 12);

        // Legend
        if (legendId) {
            const el = document.getElementById(legendId);
            el.innerHTML = data.map((d, i) =>
                `<div class="legend-item">
                    <span class="legend-dot" style="background:${CHART_COLORS[i % CHART_COLORS.length]}"></span>
                    ${d.label}: ${d.value.toLocaleString()}
                </div>`
            ).join('');
        }
    }

    drawBars(data, legendId) {
        this.resize();
        const pad = { top: 20, right: 20, bottom: 40, left: 20 };
        const w = this.w - pad.left - pad.right;
        const h = this.h - pad.top - pad.bottom;
        const max = Math.max(...data.map(d => d.value), 1);
        const barW = Math.min(w / data.length - 8, 40);
        const gap = (w - barW * data.length) / (data.length + 1);

        data.forEach((d, i) => {
            const x = pad.left + gap + i * (barW + gap);
            const barH = (d.value / max) * h;
            const y = pad.top + h - barH;

            // Bar with gradient
            const grad = this.ctx.createLinearGradient(x, y, x, pad.top + h);
            grad.addColorStop(0, CHART_COLORS[i % CHART_COLORS.length]);
            grad.addColorStop(1, CHART_COLORS[i % CHART_COLORS.length] + '33');
            this.ctx.fillStyle = grad;

            // Rounded top bar
            const r = Math.min(barW / 2, 6);
            this.ctx.beginPath();
            this.ctx.moveTo(x + r, y);
            this.ctx.arcTo(x + barW, y, x + barW, y + barH, r);
            this.ctx.lineTo(x + barW, pad.top + h);
            this.ctx.lineTo(x, pad.top + h);
            this.ctx.arcTo(x, y, x + r, y, r);
            this.ctx.fill();

            // Value label
            this.ctx.fillStyle = '#f1f5f9';
            this.ctx.font = '500 10px JetBrains Mono';
            this.ctx.textAlign = 'center';
            this.ctx.fillText(d.value, x + barW / 2, y - 6);

            // X label
            this.ctx.fillStyle = '#64748b';
            this.ctx.font = '400 9px Inter';
            this.ctx.save();
            this.ctx.translate(x + barW / 2, pad.top + h + 12);
            this.ctx.rotate(Math.PI / 6);
            this.ctx.fillText(d.label, 0, 0);
            this.ctx.restore();
        });

        if (legendId) {
            const el = document.getElementById(legendId);
            el.innerHTML = '';
        }
    }
}

// ── Data Fetching ──
async function fetchJSON(endpoint) {
    try {
        const r = await fetch(API_BASE + endpoint);
        return await r.json();
    } catch (e) {
        console.warn(`Fetch ${endpoint} failed:`, e);
        return null;
    }
}

// ── Render Functions ──
function renderPipelinePhases(phases) {
    const flow = $('#pipeline-flow');
    flow.innerHTML = '';
    phases.forEach((p, i) => {
        if (i > 0) {
            const arrow = document.createElement('div');
            arrow.className = 'phase-arrow';
            flow.appendChild(arrow);
        }
        const node = document.createElement('div');
        node.className = 'phase-node';
        node.innerHTML = `
            <div class="phase-circle">${p.id}</div>
            <span class="phase-label">${p.name}</span>
        `;
        flow.appendChild(node);
    });
}

function renderIncidents(incidents) {
    const tbody = $('#incidents-tbody');
    if (!incidents.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No high-severity incidents</td></tr>';
        return;
    }
    tbody.innerHTML = incidents.slice(0, 20).map(r => {
        const flags = (r.escalation_flags || []).map(f =>
            `<span class="tag tag-flag">${f.replace(/_/g, ' ')}</span>`
        ).join('');
        const statusClass = r.approval_status?.startsWith('approved') ? 'tag-approved'
                          : r.approval_status === 'rejected' ? 'tag-rejected' : 'tag-pending';
        return `<tr>
            <td><span class="mono">${truncate(r.fingerprint_sha256, 16)}</span></td>
            <td>${flags || '—'}</td>
            <td><span class="tag ${statusClass}">${r.approval_status || 'pending'}</span></td>
            <td><span class="mono">${r.model_version || '—'}</span></td>
            <td>${formatTime(r.timestamp_utc)}</td>
        </tr>`;
    }).join('');
}

function renderAudit(records) {
    const tbody = $('#audit-tbody');
    if (!records.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No audit records</td></tr>';
        return;
    }
    tbody.innerHTML = records.slice(-20).reverse().map(r => {
        const statusClass = r.status?.startsWith('approved') ? 'tag-approved'
                          : r.status === 'rejected' ? 'tag-rejected' : 'tag-escalated';
        const actionCount = r.approved_actions?.length || 0;
        return `<tr>
            <td><span class="mono">${truncate(r.cluster_id, 14)}</span></td>
            <td><span class="tag ${statusClass}">${r.status || '—'}</span></td>
            <td>${truncate(r.reason, 40)}</td>
            <td>${actionCount} actions</td>
            <td>${formatTime(r.timestamp_utc)}</td>
        </tr>`;
    }).join('');
}

// ── Main Refresh ──
const sourceChart = new MiniChart('source-chart');
const flagsChart = new MiniChart('flags-chart');

async function refreshAll() {
    const [summary, incidents, audit, severity, dataset] = await Promise.all([
        fetchJSON('/summary'),
        fetchJSON('/incidents'),
        fetchJSON('/audit'),
        fetchJSON('/severity-distribution'),
        fetchJSON('/dataset-stats'),
    ]);

    // Stats
    if (dataset) {
        $('#total-events').textContent = (dataset.total_events || 0).toLocaleString();
    }
    if (summary) {
        $('#model-version').textContent = summary.model_version || '—';
        $('#total-incidents').textContent = summary.total_incidents || 0;
        $('#total-approvals').textContent = summary.total_approvals || 0;
        $('#drift-status').textContent = summary.latest_drift?.status || 'Stable';
        renderPipelinePhases(summary.phases || []);
    }

    // Source donut chart
    if (dataset && dataset.by_source) {
        const data = Object.entries(dataset.by_source)
            .map(([label, value]) => ({ label, value }))
            .sort((a, b) => b.value - a.value);
        sourceChart.drawDonut(data, 'source-legend');
    }

    // Flags bar chart
    if (severity && severity.by_flag) {
        const data = Object.entries(severity.by_flag)
            .map(([label, value]) => ({ label: label.replace(/_/g, ' '), value }))
            .sort((a, b) => b.value - a.value);
        if (data.length > 0) {
            flagsChart.drawBars(data, 'flags-legend');
        }
    }

    // Tables
    if (incidents) renderIncidents(incidents.incidents || []);
    if (audit) renderAudit(audit.records || []);

    // Footer
    $('#last-refresh').textContent = `Last refresh: ${new Date().toLocaleTimeString()}`;
}

// ── Init ──
window.addEventListener('DOMContentLoaded', refreshAll);
window.addEventListener('resize', () => {
    sourceChart.resize();
    flagsChart.resize();
});

// Auto-refresh every 30s
setInterval(refreshAll, 30000);
