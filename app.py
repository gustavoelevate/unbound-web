from flask import Flask, jsonify, request, Response
import subprocess
import re
import os

app = Flask(__name__)

BLOCKLIST_FILE = os.getenv("BLOCKLIST_FILE", "/etc/unbound/blocklist.conf")
LOG_FILE       = os.getenv("LOG_FILE",       "/var/log/unbound/unbound.log")
HOST           = os.getenv("HOST",           "0.0.0.0")
PORT           = int(os.getenv("PORT",       "8080"))

# --- Garantir que o arquivo de blocklist existe ---
if not os.path.exists(BLOCKLIST_FILE):
    open(BLOCKLIST_FILE, "w").close()

# ─────────────────────────────────────────────────
# STATS
# ─────────────────────────────────────────────────
@app.route("/api/stats")
def stats():
    try:
        out = subprocess.check_output(["unbound-control", "stats"], text=True)
        data = {}
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                data[k.strip()] = v.strip()

        queries   = int(data.get("total.num.queries", 0))
        cachehits = int(data.get("total.num.cachehits", 0))
        cachemiss = int(data.get("total.num.cachemiss", 0))
        prefetch  = int(data.get("total.num.prefetch", 0))
        expired   = int(data.get("total.num.expired", 0))
        recurse   = int(data.get("total.num.recursivereplies", 0))
        req_avg   = float(data.get("total.requestlist.avg", 0))
        req_max   = int(data.get("total.requestlist.max", 0))

        hit_rate = round((cachehits / queries * 100), 2) if queries > 0 else 0

        threads = {}
        for k, v in data.items():
            m = re.match(r"^(thread\d+)\.num\.queries$", k)
            if m:
                t = m.group(1)
                threads[t] = {
                    "queries":   int(data.get(f"{t}.num.queries", 0)),
                    "cachehits": int(data.get(f"{t}.num.cachehits", 0)),
                    "cachemiss": int(data.get(f"{t}.num.cachemiss", 0)),
                }

        return jsonify({
            "queries": queries,
            "cachehits": cachehits,
            "cachemiss": cachemiss,
            "prefetch": prefetch,
            "expired": expired,
            "recursivereplies": recurse,
            "hit_rate": hit_rate,
            "requestlist_avg": req_avg,
            "requestlist_max": req_max,
            "threads": threads,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────
# BLOCKLIST
# ─────────────────────────────────────────────────
def read_blocklist():
    domains = []
    if not os.path.exists(BLOCKLIST_FILE):
        return domains
    with open(BLOCKLIST_FILE) as f:
        for line in f:
            line = line.strip()
            m = re.match(r'^local-zone:\s+"([^"]+)"\s+always_nxdomain', line)
            if m:
                domains.append(m.group(1))
    return domains

def write_blocklist(domains):
    with open(BLOCKLIST_FILE, "w") as f:
        for d in sorted(set(domains)):
            f.write(f'local-zone: "{d}" always_nxdomain\n')

def reload_unbound():
    subprocess.run(["unbound-control", "reload"], check=True)

@app.route("/api/blocklist", methods=["GET"])
def blocklist_get():
    return jsonify({"domains": read_blocklist()})

@app.route("/api/blocklist", methods=["POST"])
def blocklist_add():
    domain = request.json.get("domain", "").strip().lower()
    if not domain or not re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', domain):
        return jsonify({"error": "Domínio inválido"}), 400
    domains = read_blocklist()
    if domain in domains:
        return jsonify({"error": "Domínio já bloqueado"}), 409
    domains.append(domain)
    write_blocklist(domains)
    reload_unbound()
    return jsonify({"ok": True, "domain": domain})

@app.route("/api/blocklist/<domain>", methods=["DELETE"])
def blocklist_delete(domain):
    domain = domain.strip().lower()
    domains = read_blocklist()
    if domain not in domains:
        return jsonify({"error": "Domínio não encontrado"}), 404
    domains.remove(domain)
    write_blocklist(domains)
    reload_unbound()
    return jsonify({"ok": True, "domain": domain})


# ─────────────────────────────────────────────────
# LOGS (streaming SSE)
# ─────────────────────────────────────────────────
@app.route("/api/logs/stream")
def logs_stream():
    def generate():
        try:
            proc = subprocess.Popen(
                ["tail", "-n", "100", "-f", LOG_FILE],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            for line in proc.stdout:
                yield f"data: {line.rstrip()}\n\n"
        except Exception as e:
            yield f"data: ERRO: {str(e)}\n\n"
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/api/logs/last")
def logs_last():
    n = request.args.get("n", 200)
    try:
        out = subprocess.check_output(["tail", "-n", str(n), LOG_FILE], text=True)
        return jsonify({"lines": out.splitlines()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────
# FRONTEND (single page)
# ─────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Unbound DNS Manager</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"/>
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet"/>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<style>
  body { background:#0f1117; color:#e2e8f0; font-family:'Segoe UI',sans-serif; }
  .sidebar { width:220px; min-height:100vh; background:#1a1d2e; position:fixed; top:0; left:0; padding:24px 0; z-index:100; }
  .sidebar .brand { font-size:1.1rem; font-weight:700; color:#7c8cf8; padding:0 20px 24px; border-bottom:1px solid #2d3155; }
  .sidebar .nav-link { color:#94a3b8; padding:10px 20px; border-radius:0; display:flex; align-items:center; gap:10px; transition:.2s; }
  .sidebar .nav-link:hover, .sidebar .nav-link.active { color:#fff; background:#2d3155; }
  .main { margin-left:220px; padding:28px; }
  .page { display:none; }
  .page.active { display:block; }
  .card { background:#1a1d2e; border:1px solid #2d3155; border-radius:12px; }
  .stat-card { background:linear-gradient(135deg,#1a1d2e,#2d3155); border:1px solid #3d4170; border-radius:12px; padding:20px; }
  .stat-card .value { font-size:2rem; font-weight:700; color:#7c8cf8; }
  .stat-card .label { color:#94a3b8; font-size:.85rem; margin-top:4px; }
  .badge-hit { background:#1a3a2a; color:#4ade80; }
  .badge-miss { background:#3a1a1a; color:#f87171; }
  #log-box { background:#0a0c14; border:1px solid #2d3155; border-radius:8px; height:500px; overflow-y:auto; padding:12px; font-family:monospace; font-size:.78rem; color:#94a3b8; }
  #log-box .line { padding:1px 0; border-bottom:1px solid #0f1117; }
  #log-box .line:hover { background:#1a1d2e; color:#e2e8f0; }
  .domain-badge { background:#1e2235; border:1px solid #3d4170; border-radius:6px; padding:4px 10px; display:inline-flex; align-items:center; gap:8px; margin:3px; font-size:.82rem; }
  .domain-badge .del { cursor:pointer; color:#f87171; }
  .domain-badge .del:hover { color:#ff4444; }
  #search-domain { background:#0f1117; border:1px solid #2d3155; color:#e2e8f0; border-radius:8px; padding:8px 12px; width:100%; margin-bottom:12px; }
  #search-domain:focus { outline:none; border-color:#7c8cf8; }
  .btn-primary { background:#7c8cf8; border:none; }
  .btn-primary:hover { background:#6070e8; }
  .refresh-btn { background:#2d3155; border:1px solid #3d4170; color:#94a3b8; border-radius:8px; padding:6px 14px; cursor:pointer; font-size:.82rem; transition:.2s; }
  .refresh-btn:hover { background:#3d4170; color:#fff; }
  .chart-wrap { position:relative; height:260px; }
  .thread-table th { color:#7c8cf8; font-weight:600; }
  input.form-control { background:#0f1117; border:1px solid #2d3155; color:#e2e8f0; }
  input.form-control:focus { background:#0f1117; border-color:#7c8cf8; color:#e2e8f0; box-shadow:none; }
  .toast-container { position:fixed; bottom:24px; right:24px; z-index:9999; }
  .live-dot { width:8px; height:8px; background:#4ade80; border-radius:50%; display:inline-block; animation:pulse 1.5s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
</style>
</head>
<body>

<div class="sidebar">
  <div class="brand"><i class="bi bi-shield-check me-2"></i>Unbound DNS</div>
  <nav class="nav flex-column mt-3">
    <a class="nav-link active" href="#" onclick="showPage('stats',this)"><i class="bi bi-bar-chart-line"></i> Estatísticas</a>
    <a class="nav-link" href="#" onclick="showPage('blocklist',this)"><i class="bi bi-slash-circle"></i> Bloqueios</a>
    <a class="nav-link" href="#" onclick="showPage('logs',this)"><i class="bi bi-terminal"></i> Logs</a>
  </nav>
</div>

<div class="main">

  <!-- STATS -->
  <div id="page-stats" class="page active">
    <div class="d-flex justify-content-between align-items-center mb-4">
      <h4 class="mb-0 fw-bold">Estatísticas DNS</h4>
      <button class="refresh-btn" onclick="loadStats()"><i class="bi bi-arrow-clockwise me-1"></i>Atualizar</button>
    </div>
    <div class="row g-3 mb-4">
      <div class="col-md-3"><div class="stat-card"><div class="value" id="s-queries">—</div><div class="label">Total de Consultas</div></div></div>
      <div class="col-md-3"><div class="stat-card"><div class="value" id="s-hitrate">—</div><div class="label">Cache Hit Rate</div></div></div>
      <div class="col-md-3"><div class="stat-card"><div class="value" id="s-cachehits">—</div><div class="label">Cache Hits</div></div></div>
      <div class="col-md-3"><div class="stat-card"><div class="value" id="s-cachemiss">—</div><div class="label">Cache Miss</div></div></div>
      <div class="col-md-3"><div class="stat-card"><div class="value" id="s-prefetch">—</div><div class="label">Prefetch</div></div></div>
      <div class="col-md-3"><div class="stat-card"><div class="value" id="s-expired">—</div><div class="label">Expirados Servidos</div></div></div>
      <div class="col-md-3"><div class="stat-card"><div class="value" id="s-recurse">—</div><div class="label">Respostas Recursivas</div></div></div>
      <div class="col-md-3"><div class="stat-card"><div class="value" id="s-reqavg">—</div><div class="label">Req. List Avg</div></div></div>
    </div>
    <div class="row g-3 mb-4">
      <div class="col-md-6">
        <div class="card p-3">
          <h6 class="text-muted mb-3">Cache Hit vs Miss</h6>
          <div class="chart-wrap"><canvas id="chart-hit"></canvas></div>
        </div>
      </div>
      <div class="col-md-6">
        <div class="card p-3">
          <h6 class="text-muted mb-3">Distribuição de Consultas</h6>
          <div class="chart-wrap"><canvas id="chart-dist"></canvas></div>
        </div>
      </div>
    </div>
    <div class="card p-3">
      <h6 class="text-muted mb-3">Por Thread</h6>
      <table class="table table-dark table-sm thread-table mb-0">
        <thead><tr><th>Thread</th><th>Consultas</th><th>Cache Hits</th><th>Cache Miss</th></tr></thead>
        <tbody id="thread-table"></tbody>
      </table>
    </div>
  </div>

  <!-- BLOCKLIST -->
  <div id="page-blocklist" class="page">
    <div class="d-flex justify-content-between align-items-center mb-4">
      <h4 class="mb-0 fw-bold">Domínios Bloqueados</h4>
      <span class="badge bg-secondary" id="block-count">0 domínios</span>
    </div>
    <div class="card p-3 mb-3">
      <div class="d-flex gap-2">
        <input type="text" class="form-control" id="new-domain" placeholder="exemplo.com.br" onkeydown="if(event.key==='Enter')addDomain()"/>
        <button class="btn btn-primary px-4" onclick="addDomain()"><i class="bi bi-plus-lg me-1"></i>Bloquear</button>
      </div>
    </div>
    <div class="card p-3">
      <input type="text" id="search-domain" placeholder="Filtrar domínios..." oninput="renderDomains()"/>
      <div id="domain-list"></div>
    </div>
  </div>

  <!-- LOGS -->
  <div id="page-logs" class="page">
    <div class="d-flex justify-content-between align-items-center mb-4">
      <h4 class="mb-0 fw-bold">Logs em Tempo Real <span class="live-dot ms-2"></span></h4>
      <div class="d-flex gap-2">
        <button class="refresh-btn" onclick="clearLogs()"><i class="bi bi-trash me-1"></i>Limpar</button>
        <button class="refresh-btn" id="btn-pause" onclick="togglePause()"><i class="bi bi-pause-fill me-1"></i>Pausar</button>
      </div>
    </div>
    <div id="log-box"></div>
  </div>

</div>

<div class="toast-container">
  <div id="toast" class="toast align-items-center text-white border-0" role="alert">
    <div class="d-flex">
      <div class="toast-body" id="toast-msg"></div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
function showPage(name, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  el.classList.add('active');
  if (name === 'stats') loadStats();
  if (name === 'blocklist') loadBlocklist();
  if (name === 'logs') startLogs();
}

function showToast(msg, ok=true) {
  const t = document.getElementById('toast');
  t.className = 'toast align-items-center text-white border-0 ' + (ok ? 'bg-success' : 'bg-danger');
  document.getElementById('toast-msg').textContent = msg;
  new bootstrap.Toast(t, {delay:3000}).show();
}

function fmt(n) { return Number(n).toLocaleString('pt-BR'); }

let chartHit = null, chartDist = null;

function initCharts(data) {
  const opts = { responsive:true, maintainAspectRatio:false,
    plugins:{ legend:{ labels:{ color:'#94a3b8' } } } };
  if (chartHit) chartHit.destroy();
  chartHit = new Chart(document.getElementById('chart-hit'), {
    type: 'doughnut',
    data: { labels: ['Cache Hit', 'Cache Miss'],
      datasets: [{ data: [data.cachehits, data.cachemiss],
        backgroundColor: ['#4ade80','#f87171'], borderWidth:0 }] },
    options: { ...opts }
  });
  if (chartDist) chartDist.destroy();
  chartDist = new Chart(document.getElementById('chart-dist'), {
    type: 'bar',
    data: { labels: ['Hits', 'Miss', 'Prefetch', 'Expirados', 'Recursivas'],
      datasets: [{ label: 'Consultas',
        data: [data.cachehits, data.cachemiss, data.prefetch, data.expired, data.recursivereplies],
        backgroundColor: ['#4ade80','#f87171','#7c8cf8','#fbbf24','#38bdf8'],
        borderRadius: 6, borderWidth:0 }] },
    options: { ...opts, plugins:{ legend:{ display:false } },
      scales:{ x:{ ticks:{ color:'#94a3b8' }, grid:{ color:'#2d3155' } },
               y:{ ticks:{ color:'#94a3b8' }, grid:{ color:'#2d3155' } } } }
  });
}

async function loadStats() {
  try {
    const r = await fetch('/api/stats');
    const d = await r.json();
    document.getElementById('s-queries').textContent   = fmt(d.queries);
    document.getElementById('s-hitrate').textContent   = d.hit_rate + '%';
    document.getElementById('s-cachehits').textContent = fmt(d.cachehits);
    document.getElementById('s-cachemiss').textContent = fmt(d.cachemiss);
    document.getElementById('s-prefetch').textContent  = fmt(d.prefetch);
    document.getElementById('s-expired').textContent   = fmt(d.expired);
    document.getElementById('s-recurse').textContent   = fmt(d.recursivereplies);
    document.getElementById('s-reqavg').textContent    = d.requestlist_avg;
    initCharts(d);
    const tbody = document.getElementById('thread-table');
    tbody.innerHTML = '';
    for (const [t, v] of Object.entries(d.threads)) {
      tbody.innerHTML += `<tr>
        <td><span class="badge bg-secondary">${t}</span></td>
        <td>${fmt(v.queries)}</td>
        <td><span class="badge badge-hit">${fmt(v.cachehits)}</span></td>
        <td><span class="badge badge-miss">${fmt(v.cachemiss)}</span></td>
      </tr>`;
    }
  } catch(e) { showToast('Erro ao carregar stats', false); }
}

let allDomains = [];

async function loadBlocklist() {
  const r = await fetch('/api/blocklist');
  const d = await r.json();
  allDomains = d.domains;
  document.getElementById('block-count').textContent = allDomains.length + ' domínios';
  renderDomains();
}

function renderDomains() {
  const q = document.getElementById('search-domain').value.toLowerCase();
  const list = document.getElementById('domain-list');
  const filtered = allDomains.filter(d => d.includes(q));
  if (filtered.length === 0) {
    list.innerHTML = '<p class="text-muted mt-3 text-center">Nenhum domínio encontrado.</p>';
    return;
  }
  list.innerHTML = filtered.map(d =>
    `<span class="domain-badge">
      <i class="bi bi-slash-circle text-danger"></i>${d}
      <span class="del" onclick="deleteDomain('${d}')"><i class="bi bi-x-lg"></i></span>
    </span>`
  ).join('');
}

async function addDomain() {
  const input = document.getElementById('new-domain');
  const domain = input.value.trim();
  if (!domain) return;
  try {
    const r = await fetch('/api/blocklist', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({domain})
    });
    const d = await r.json();
    if (!r.ok) { showToast(d.error || 'Erro', false); return; }
    showToast('Domínio bloqueado: ' + domain);
    input.value = '';
    loadBlocklist();
  } catch(e) { showToast('Erro ao bloquear', false); }
}

async function deleteDomain(domain) {
  try {
    const r = await fetch('/api/blocklist/' + encodeURIComponent(domain), {method:'DELETE'});
    const d = await r.json();
    if (!r.ok) { showToast(d.error || 'Erro', false); return; }
    showToast('Domínio desbloqueado: ' + domain);
    loadBlocklist();
  } catch(e) { showToast('Erro ao desbloquear', false); }
}

let logPaused = false;
let logSource = null;
const MAX_LINES = 500;

function startLogs() {
  if (logSource) return;
  const box = document.getElementById('log-box');
  logSource = new EventSource('/api/logs/stream');
  logSource.onmessage = (e) => {
    if (logPaused) return;
    const div = document.createElement('div');
    div.className = 'line';
    div.textContent = e.data;
    box.appendChild(div);
    while (box.children.length > MAX_LINES) box.removeChild(box.firstChild);
    box.scrollTop = box.scrollHeight;
  };
}

function clearLogs() { document.getElementById('log-box').innerHTML = ''; }

function togglePause() {
  logPaused = !logPaused;
  const btn = document.getElementById('btn-pause');
  btn.innerHTML = logPaused
    ? '<i class="bi bi-play-fill me-1"></i>Retomar'
    : '<i class="bi bi-pause-fill me-1"></i>Pausar';
}

loadStats();
</script>
</body>
</html>"""

@app.route("/")
def index():
    return HTML

if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False)
