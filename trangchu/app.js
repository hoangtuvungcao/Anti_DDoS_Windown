/* ==========================================================================
   WAF-SHIELD ENTERPRISE — OFFICIAL LANDING PAGE JAVASCRIPT ENGINE
   Canvas Cyber Particles • Interactive DDoS Simulator • Config Generator
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
    initCyberCanvas();
    initSimulator();
    initConfigGenerator();
    initDocsSearch();
});

/* --------------------------------------------------------------------------
   1. CYBER BACKGROUND PARTICLES & GRID CANVAS
   -------------------------------------------------------------------------- */
function initCyberCanvas() {
    const canvas = document.getElementById('cyberCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    let width = canvas.width = window.innerWidth;
    let height = canvas.height = window.innerHeight;

    window.addEventListener('resize', () => {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    });

    const particles = [];
    const numParticles = Math.min(width > 768 ? 60 : 30, 80);

    for (let i = 0; i < numParticles; i++) {
        particles.push({
            x: Math.random() * width,
            y: Math.random() * height,
            vx: (Math.random() - 0.5) * 0.4,
            vy: (Math.random() - 0.5) * 0.4,
            radius: Math.random() * 1.8 + 0.8,
            color: Math.random() > 0.4 ? 'rgba(0, 240, 255,' : 'rgba(59, 130, 246,'
        });
    }

    function animate() {
        ctx.clearRect(0, 0, width, height);

        // Draw connections
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < 130) {
                    const alpha = (1 - dist / 130) * 0.15;
                    ctx.strokeStyle = `rgba(0, 240, 255, ${alpha})`;
                    ctx.lineWidth = 0.6;
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.stroke();
                }
            }
        }

        // Draw & update particles
        for (const p of particles) {
            p.x += p.vx;
            p.y += p.vy;

            if (p.x < 0 || p.x > width) p.vx *= -1;
            if (p.y < 0 || p.y > height) p.vy *= -1;

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
            ctx.fillStyle = p.color + '0.7)';
            ctx.shadowBlur = 8;
            ctx.shadowColor = '#00f0ff';
            ctx.fill();
            ctx.shadowBlur = 0;
        }

        requestAnimationFrame(animate);
    }
    animate();
}

/* --------------------------------------------------------------------------
   2. INTERACTIVE DDOS ATTACK & MITIGATION SIMULATOR
   -------------------------------------------------------------------------- */
let currentAttackType = 'SYN_FLOOD';
let simInterval = null;

function initSimulator() {
    const simCanvas = document.getElementById('simCanvas');
    if (!simCanvas) return;
    const ctx = simCanvas.getContext('2d');

    let simW = simCanvas.width = simCanvas.offsetWidth || 500;
    let simH = simCanvas.height = simCanvas.offsetHeight || 260;

    window.addEventListener('resize', () => {
        if (simCanvas.offsetWidth) {
            simW = simCanvas.width = simCanvas.offsetWidth;
            simH = simCanvas.height = simCanvas.offsetHeight;
        }
    });

    const packets = [];

    function spawnPacket() {
        const isMalicious = Math.random() < 0.78;
        packets.push({
            x: 20,
            y: Math.random() * (simH - 40) + 20,
            speed: Math.random() * 3 + 2.5,
            isMalicious: isMalicious,
            type: currentAttackType,
            status: 'inbound', // 'inbound', 'dropped', 'passed'
            alpha: 1
        });
    }

    setInterval(spawnPacket, 80);

    function updateSimStats() {
        const ppsVal = document.getElementById('simStatPPS');
        const dropVal = document.getElementById('simStatDrop');
        const vectorVal = document.getElementById('simStatVector');

        if (ppsVal) {
            const pps = Math.floor(Math.random() * 4000 + 120000);
            ppsVal.innerText = (pps / 1000).toFixed(1) + ' kPPS';
        }
        if (dropVal) {
            const drops = (99.8 + Math.random() * 0.19).toFixed(2);
            dropVal.innerText = drops + '% Blocked';
        }
        if (vectorVal) {
            vectorVal.innerText = currentAttackType;
        }
    }
    setInterval(updateSimStats, 800);

    function renderSim() {
        ctx.fillStyle = '#030712';
        ctx.fillRect(0, 0, simW, simH);

        // Draw Shield Gate
        const gateX = simW * 0.6;
        ctx.strokeStyle = '#00f0ff';
        ctx.lineWidth = 3;
        ctx.shadowBlur = 15;
        ctx.shadowColor = '#00f0ff';
        ctx.beginPath();
        ctx.moveTo(gateX, 15);
        ctx.lineTo(gateX, simH - 15);
        ctx.stroke();
        ctx.shadowBlur = 0;

        // Gate Label
        ctx.fillStyle = '#00f0ff';
        ctx.font = 'bold 11px JetBrains Mono';
        ctx.fillText('WAF KERNEL GATEWAY', gateX - 60, 24);

        // Server node on the right
        const srvX = simW - 35;
        const srvY = simH / 2;
        ctx.fillStyle = '#10b981';
        ctx.beginPath();
        ctx.arc(srvX, srvY, 12, 0, Math.PI * 2);
        ctx.shadowBlur = 12;
        ctx.shadowColor = '#10b981';
        ctx.fill();
        ctx.shadowBlur = 0;

        ctx.fillStyle = '#fff';
        ctx.font = 'bold 10px Outfit';
        ctx.fillText('SERVER', srvX - 18, srvY + 24);

        // Update packets
        for (let i = packets.length - 1; i >= 0; i--) {
            const p = packets[i];
            p.x += p.speed;

            if (p.x >= gateX && p.status === 'inbound') {
                if (p.isMalicious) {
                    p.status = 'dropped';
                } else {
                    p.status = 'passed';
                }
            }

            if (p.status === 'dropped') {
                p.alpha -= 0.08;
                p.y += (Math.random() - 0.5) * 4;
            }

            // Draw packet
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.isMalicious ? 3.5 : 4, 0, Math.PI * 2);
            if (p.status === 'dropped') {
                ctx.fillStyle = `rgba(239, 68, 68, ${Math.max(0, p.alpha)})`;
            } else if (p.status === 'passed') {
                ctx.fillStyle = '#10b981';
            } else {
                ctx.fillStyle = p.isMalicious ? '#ef4444' : '#38bdf8';
            }
            ctx.fill();

            if (p.alpha <= 0 || p.x > simW) {
                packets.splice(i, 1);
            }
        }

        requestAnimationFrame(renderSim);
    }
    renderSim();
}

function switchSimAttack(type) {
    currentAttackType = type;
    document.querySelectorAll('.sim-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    showToast(`Đã chuyển luồng giả lập: ${type}`, 'info');
}

/* --------------------------------------------------------------------------
   3. COPY TO CLIPBOARD & TOAST NOTIFICATION
   -------------------------------------------------------------------------- */
function copyCode(elementId, label = 'mã lệnh') {
    const el = document.getElementById(elementId);
    if (!el) return;
    const text = el.innerText || el.textContent;

    navigator.clipboard.writeText(text.trim()).then(() => {
        showToast(`Đã sao chép ${label} vào bộ nhớ tạm!`, 'success');
    }).catch(() => {
        showToast('Không thể sao chép tự động', 'error');
    });
}

function showToast(message, type = 'info') {
    let container = document.getElementById('toastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = 'toast';
    let iconSvg = '<svg width="16" height="16" fill="none" stroke="#00f0ff" stroke-width="2" viewBox="0 0 24 24"><path d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>';
    if (type === 'success') {
        iconSvg = '<svg width="16" height="16" fill="none" stroke="#10b981" stroke-width="2" viewBox="0 0 24 24"><path d="M5 13l4 4L19 7"/></svg>';
    } else if (type === 'error') {
        iconSvg = '<svg width="16" height="16" fill="none" stroke="#ef4444" stroke-width="2" viewBox="0 0 24 24"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>';
    }

    toast.innerHTML = `${iconSvg} <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3200);
}


/* --------------------------------------------------------------------------
   4. INTERACTIVE CONFIG.JSON GENERATOR
   -------------------------------------------------------------------------- */
function initConfigGenerator() {
    updateGeneratedConfig();
}

function updateGeneratedConfig() {
    const preset = document.getElementById('cfgPreset') ? document.getElementById('cfgPreset').value : 'HYBRID';
    const webPort = document.getElementById('cfgWebPort') ? parseInt(document.getElementById('cfgWebPort').value) || 8080 : 8080;
    const webPass = document.getElementById('cfgWebPass') ? document.getElementById('cfgWebPass').value : 'admin_sec_2026';
    const flowPPS = document.getElementById('cfgFlowPPS') ? parseInt(document.getElementById('cfgFlowPPS').value) || 120 : 120;
    const geoMode = document.getElementById('cfgGeoMode') ? document.getElementById('cfgGeoMode').value : 'AUTO';

    const configObj = {
        "system_mode": "AUTO",
        "peace_mode": {
            "udp_pps_per_flow": flowPPS,
            "udp_bps_per_flow": 1048576,
            "udp_pps_per_ip": flowPPS * 3,
            "subnet_pps_limit": flowPPS * 10,
            "tcp_max_conn_per_ip": preset === 'WEB' || preset === 'HYBRID' ? 100 : 50,
            "tcp_conn_rate_per_ip": 30,
            "tcp_idle_timeout_sec": 90
        },
        "war_mode": {
            "trigger_pps": 4000,
            "trigger_bps": 31457280,
            "udp_pps_per_flow": 35,
            "udp_pps_per_ip": 80,
            "subnet_pps_limit": 200,
            "geoip_mode": geoMode
        },
        "web": {
            "enabled": true,
            "port": webPort,
            "username": "admin",
            "password": webPass,
            "allow_lan": true
        }
    };

    const preview = document.getElementById('configJsonPreview');
    if (preview) {
        preview.textContent = JSON.stringify(configObj, null, 2);
    }
}

function downloadCustomConfig() {
    const preview = document.getElementById('configJsonPreview');
    if (!preview) return;
    const content = preview.textContent;
    const blob = new Blob([content], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'config.json';
    document.body.appendChild(a);
    a.click();
    document.body.appendChild(a);
    a.remove();
    URL.revokeObjectURL(url);
    showToast('Đã tải file config.json tùy biến!', 'success');
}


/* --------------------------------------------------------------------------
   5. DOCUMENTATION SEARCH & TAB FILTER
   -------------------------------------------------------------------------- */
function initDocsSearch() {
    const searchInput = document.getElementById('docsSearchInput');
    if (!searchInput) return;

    searchInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const blocks = document.querySelectorAll('.docs-block');

        blocks.forEach(block => {
            const text = block.textContent.toLowerCase();
            if (text.includes(query)) {
                block.style.display = 'block';
            } else {
                block.style.display = 'none';
            }
        });
    });
}
