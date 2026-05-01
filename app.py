from flask import Flask, jsonify, request, Response
import subprocess
import re
import os
import time
import threading
from collections import deque
from datetime import datetime

app = Flask(__name__)

BLOCKLIST_FILE = os.getenv("BLOCKLIST_FILE", "/etc/unbound/blocklist.conf")
LOG_FILE       = os.getenv("LOG_FILE",       "/var/log/unbound/unbound.log")
HOST           = os.getenv("HOST",           "0.0.0.0")
PORT           = int(os.getenv("PORT",       "8080"))
HISTORY_POINTS = 720  # 12 horas x 60 minutos = 720 pontos (1 por minuto)

if not os.path.exists(BLOCKLIST_FILE):
    open(BLOCKLIST_FILE, "w").close()

# Historia em memoria (720 pontos = 12h)
history = {
    "timestamps": deque(maxlen=HISTORY_POINTS),
    "qps":        deque(maxlen=HISTORY_POINTS),
    "cachehits":  deque(maxlen=HISTORY_POINTS),
    "cachemiss":  deque(maxlen=HISTORY_POINTS),
    "dnssec_ok":  deque(maxlen=HISTORY_POINTS),
    "dnssec_bad": deque(maxlen=HISTORY_POINTS),
    "resp_avg":   deque(maxlen=HISTORY_POINTS),
    "resp_med":   deque(maxlen=HISTORY_POINTS),
}
last_queries = {"total": 0, "cachehits": 0, "cachemiss": 0, "ts": time.time()}

def parse_stats():
    try:
        out = subprocess.check_output(["unbound-control", "stats"], text=True)
        d = {}
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                d[k.strip()] = v.strip()
        return d
    except:
        return {}

def collect():
    global last_queries
    while True:
        try:
            d = parse_stats()
            now = time.time()
            total     = int(d.get("total.num.queries", 0))
            cachehits = int(d.get("total.num.cachehits", 0))
            cachemiss = int(d.get("total.num.cachemiss", 0))
            elapsed   = now - last_queries["ts"]
            qps = max(0, (total - last_queries["total"]) / elapsed) if elapsed > 0 else 0
            ch  = max(0, cachehits - last_queries["cachehits"])
            cm  = max(0, cachemiss - last_queries["cachemiss"])

            # Tempo de resposta: unbound retorna em segundos, converter para ms
            resp_avg_s = float(d.get("total.recursion.time.avg", 0))
            resp_med_s = float(d.get("total.recursion.time.median", 0))
            # Valores acima de 10s sao anomalias (acumulado), ignorar
            resp_avg_ms = round(resp_avg_s * 1000, 3) if resp_avg_s < 10 else 0
            resp_med_ms = round(resp_med_s * 1000, 3) if resp_med_s < 10 else 0

            history["timestamps"].append(datetime.now().strftime("%H:%M"))
            history["qps"].append(round(qps, 1))
            history["cachehits"].append(ch)
            history["cachemiss"].append(cm)
            history["dnssec_ok"].append(int(d.get("total.num.dnssec_secure", 0)))
            history["dnssec_bad"].append(int(d.get("total.num.dnssec_bogus", 0)))
            history["resp_avg"].append(resp_avg_ms)
            history["resp_med"].append(resp_med_ms)

            last_queries = {"total": total, "cachehits": cachehits, "cachemiss": cachemiss, "ts": now}
        except Exception as e:
            print(f"Collector error: {e}")
        time.sleep(60)

threading.Thread(target=collect, daemon=True).start()

# API Stats
@app.route("/api/stats")
def stats():
    try:
        d = parse_stats()
        queries   = int(d.get("total.num.queries", 0))
        cachehits = int(d.get("total.num.cachehits", 0))
        cachemiss = int(d.get("total.num.cachemiss", 0))
        hit_rate  = round(cachehits / queries * 100, 1) if queries > 0 else 0

        now     = time.time()
        elapsed = now - last_queries["ts"]
        qps     = round(max(0, (queries - last_queries["total"]) / elapsed), 1) if elapsed > 0 else 0

        # Tempo de resposta correto
        resp_avg_s = float(d.get("total.recursion.time.avg", 0))
        resp_med_s = float(d.get("total.recursion.time.median", 0))
        resp_avg_ms = round(resp_avg_s * 1000, 3) if resp_avg_s < 10 else 0
        resp_med_ms = round(resp_med_s * 1000, 3) if resp_med_s < 10 else 0

        # Tipos de consulta - usar num_queries_type
        qtypes = {}
        for k, v in d.items():
            m = re.match(r"^num\.query\.type\.(\w+)$", k)
            if m:
                qtypes[m.group(1)] = int(v)
        # Fallback para prefixo total
        if not qtypes:
            for k, v in d.items():
                m = re.match(r"^total\.num\.queries_type\.(\w+)$", k)
                if m:
                    qtypes[m.group(1)] = int(v)
        # Fallback thread0
        if not qtypes:
            for k, v in d.items():
                m = re.match(r"^thread0\.num\.queries_type\.(\w+)$", k)
                if m:
                    qtypes[m.group(1)] = int(v)

        try:
            subprocess.check_output(["unbound-control", "status"], stderr=subprocess.DEVNULL)
            status = "active"
        except:
            status = "inactive"

        return jsonify({
            "status": status,
            "queries": queries,
            "cachehits": cachehits,
            "cachemiss": cachemiss,
            "hit_rate": hit_rate,
            "qps": qps,
            "resp_avg": resp_avg_ms,
            "resp_med": resp_med_ms,
            "requestlist_avg": round(float(d.get("total.requestlist.avg", 0)), 3),
            "requestlist_max": int(d.get("total.requestlist.max", 0)),
            "prefetch": int(d.get("total.num.prefetch", 0)),
            "expired": int(d.get("total.num.expired", 0)),
            "rrsets": int(d.get("msg.cache.count", 0)),
            "messages": int(d.get("rrset.cache.count", 0)),
            "dnssec_ok": int(d.get("total.num.dnssec_secure", 0)),
            "dnssec_bad": int(d.get("total.num.dnssec_bogus", 0)),
            "unwanted_replies": int(d.get("unwanted.replies", 0)),
            "unwanted_queries": int(d.get("unwanted.queries", 0)),
            "qtypes": qtypes,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# API History com filtro de periodo
@app.route("/api/history")
def api_history():
    hours = int(request.args.get("hours", 1))
    points = min(hours * 60, HISTORY_POINTS)
    ts   = list(history["timestamps"])
    qps  = list(history["qps"])
    ch   = list(history["cachehits"])
    cm   = list(history["cachemiss"])
    dok  = list(history["dnssec_ok"])
    dbad = list(history["dnssec_bad"])
    ravg = list(history["resp_avg"])
    rmed = list(history["resp_med"])
    # Pegar os ultimos N pontos
    return jsonify({
        "timestamps": ts[-points:],
        "qps":        qps[-points:],
        "cachehits":  ch[-points:],
        "cachemiss":  cm[-points:],
        "dnssec_ok":  dok[-points:],
        "dnssec_bad": dbad[-points:],
        "resp_avg":   ravg[-points:],
        "resp_med":   rmed[-points:],
    })

# API debug - mostrar todas as chaves do unbound-control stats
@app.route("/api/debug/stats")
def debug_stats():
    d = parse_stats()
    return jsonify(d)

# Blocklist
def read_blocklist():
    domains = []
    if not os.path.exists(BLOCKLIST_FILE):
        return domains
    with open(BLOCKLIST_FILE) as f:
        for line in f:
            m = re.match(r'^local-zone:\s+"([^"]+)"\s+always_nxdomain', line.strip())
            if m:
                domains.append(m.group(1))
    return domains

def write_blocklist(domains):
    with open(BLOCKLIST_FILE, "w") as f:
        for d in sorted(set(domains)):
            f.write(f'local-zone: "{d}" always_nxdomain\n')

def sanitize_domain(raw):
    # Remove formato markdown [texto](url) -> texto
    cleaned = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', raw)
    # Remove http:// ou https://
    cleaned = re.sub(r'https?://', '', cleaned)
    # Remove barras e espacos
    cleaned = cleaned.strip().strip('/').lower()
    return cleaned

def reload_unbound():
    subprocess.run(["unbound-control", "reload"], check=True)

@app.route("/api/blocklist", methods=["GET"])
def blocklist_get():
    return jsonify({"domains": read_blocklist()})

@app.route("/api/blocklist", methods=["POST"])
def blocklist_add():
    raw = request.json.get("domain", "")
    domain = sanitize_domain(raw)
    if not domain or not re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', domain):
        return jsonify({"error": "Dominio invalido: " + domain}), 400
    domains = read_blocklist()
    if domain in domains:
        return jsonify({"error": "Dominio ja bloqueado"}), 409
    domains.append(domain)
    write_blocklist(domains)
    reload_unbound()
    return jsonify({"ok": True, "domain": domain})

@app.route("/api/blocklist/<domain>", methods=["DELETE"])
def blocklist_delete(domain):
    domain = sanitize_domain(domain)
    domains = read_blocklist()
    if domain not in domains:
        return jsonify({"error": "Dominio nao encontrado"}), 404
    domains.remove(domain)
    write_blocklist(domains)
    reload_unbound()
    return jsonify({"ok": True})

# Logs SSE
@app.route("/api/logs/stream")
def logs_stream():
    def generate():
        try:
            proc = subprocess.Popen(["tail", "-n", "100", "-f", LOG_FILE],
                                    stdout=subprocess.PIPE, text=True)
            for line in proc.stdout:
                yield f"data: {line.rstrip()}\n\n"
        except Exception as e:
            yield f"data: ERRO: {e}\n\n"
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

HTML = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>DNS Recursivo</title>
<link rel="icon" type="image/png" href="/static/favicon.png?v=2"/>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"/>
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet"/>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<style>
:root{--bg:#f8f9fc;--card:#fff;--border:#e5e9f0;--text:#1a1d2e;--muted:#6b7280;--primary:#3b82f6;--success:#10b981;--danger:#ef4444;--warning:#f59e0b;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;font-size:14px;}
.sidebar{width:220px;min-height:100vh;background:#fff;border-right:1px solid var(--border);position:fixed;top:0;left:0;z-index:100;}
.brand{padding:20px;font-size:1rem;font-weight:700;color:var(--primary);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;}
.nav-item{padding:10px 20px;display:flex;align-items:center;gap:10px;color:#374151;cursor:pointer;border-left:3px solid transparent;transition:.15s;font-size:.875rem;}
.nav-item:hover{background:#eff6ff;color:var(--primary);}
.nav-item.active{background:#eff6ff;color:var(--primary);border-left-color:var(--primary);font-weight:600;}
.main{margin-left:220px;padding:28px;min-height:100vh;}
.page{display:none;}.page.active{display:block;}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:10px;}
.topbar h4{font-size:1.1rem;font-weight:700;}
.badge-status{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;border-radius:20px;font-size:.78rem;font-weight:600;}
.badge-active{background:#d1fae5;color:#065f46;}.badge-inactive{background:#fee2e2;color:#991b1b;}
.dot{width:7px;height:7px;border-radius:50%;}.dot-green{background:#10b981;}.dot-red{background:#ef4444;}
.section-title{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:12px;}
.metric-card{background:#fff;border:1px solid var(--border);border-radius:10px;padding:18px 20px;}
.metric-card .label{font-size:.75rem;color:var(--muted);margin-bottom:6px;display:flex;align-items:center;gap:5px;}
.metric-card .value{font-size:1.65rem;font-weight:700;color:var(--text);line-height:1;}
.metric-card .sub{font-size:.72rem;margin-top:5px;}
.sub-green{color:var(--success);}.sub-yellow{color:var(--warning);}.sub-blue{color:var(--primary);}
.chart-card{background:#fff;border:1px solid var(--border);border-radius:10px;padding:18px 20px;}
.chart-title{font-size:.8rem;font-weight:600;margin-bottom:8px;display:flex;align-items:center;gap:5px;}
.chart-wrap{position:relative;height:200px;}.chart-wrap-sm{position:relative;height:160px;}
.refresh-btn{background:#fff;border:1px solid var(--border);color:var(--muted);border-radius:8px;padding:6px 14px;cursor:pointer;font-size:.8rem;transition:.15s;display:inline-flex;align-items:center;gap:5px;}
.refresh-btn:hover{border-color:var(--primary);color:var(--primary);}
.period-btn{background:#fff;border:1px solid var(--border);color:var(--muted);border-radius:6px;padding:4px 10px;cursor:pointer;font-size:.75rem;transition:.15s;}
.period-btn:hover,.period-btn.active{background:var(--primary);border-color:var(--primary);color:#fff;}
.tooltip-icon{color:var(--muted);font-size:.75rem;cursor:help;}
.domain-tag{display:inline-flex;align-items:center;gap:6px;background:#f1f5f9;border:1px solid var(--border);border-radius:6px;padding:4px 10px;margin:3px;font-size:.8rem;}
.domain-tag .del{cursor:pointer;color:var(--danger);font-size:.75rem;}
.domain-tag .del:hover{color:#b91c1c;}
#search-domain{background:#fff;border:1px solid var(--border);border-radius:8px;padding:8px 12px;width:100%;font-size:.85rem;outline:none;}
#search-domain:focus{border-color:var(--primary);}
#log-box{background:#0f1117;border:1px solid var(--border);border-radius:8px;height:500px;overflow-y:auto;padding:12px;font-family:monospace;font-size:.75rem;color:#94a3b8;}
#log-box .line{padding:1px 0;white-space:pre-wrap;word-break:break-all;}
#log-box .line:hover{color:#e2e8f0;}
.live-dot{width:7px;height:7px;background:var(--success);border-radius:50%;display:inline-block;animation:pulse 1.5s infinite;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.toast-container{position:fixed;bottom:24px;right:24px;z-index:9999;}
.period-group{display:flex;gap:4px;align-items:center;}
</style>
</head>
<body>
<div class="sidebar">
  <div class="brand" style="font-size: 1.4rem;"><img src="/static/logo.png" style="width: 60px; height: 60px; margin-right: 12px; object-fit: contain; background-color: white; border-radius: 50%; padding: 5px;" alt="Logo"/> DNS Manager</div>
  <div style="padding:16px 0">
    <div class="nav-item active" onclick="showPage('dashboard',this)"><i class="bi bi-speedometer2"></i> Dashboard</div>
    <div class="nav-item" onclick="showPage('blocklist',this)"><i class="bi bi-slash-circle"></i> Bloqueios</div>
    <div class="nav-item" onclick="showPage('logs',this)"><i class="bi bi-terminal"></i> Logs</div>
  </div>
</div>
<div class="main">

  <!-- DASHBOARD -->
  <div id="page-dashboard" class="page active">
    <div class="topbar">
      <h4><img src="/static/logo.png" style="width: 80px; height: 80px; object-fit: contain; background-color: white; border-radius: 50%; padding: 6px;" class="me-3" alt="Logo"/>DNS Recursivo</h4>
      <div class="d-flex align-items-center gap-2">
        <button class="refresh-btn" onclick="loadAll()"><i class="bi bi-arrow-clockwise"></i> Atualizar</button>
        <span id="status-badge" class="badge-status badge-active"><span class="dot dot-green"></span> Unbound Ativo</span>
      </div>
    </div>

    <div class="section-title">Métricas Críticas</div>
    <div class="row g-3 mb-4">
      <div class="col-md-3"><div class="metric-card"><div class="label">Consultas por Segundo <i class="bi bi-question-circle tooltip-icon" title="QPS atual"></i></div><div class="value" id="m-qps">—</div><div class="sub sub-green">QPS atual</div></div></div>
      <div class="col-md-3"><div class="metric-card"><div class="label">Tempo de resposta <i class="bi bi-question-circle tooltip-icon" title="Tempo médio de resolução recursiva em ms"></i></div><div class="value" id="m-resp">—</div><div class="sub sub-yellow" id="m-resp-sub">média | mediana: —</div></div></div>
      <div class="col-md-3"><div class="metric-card"><div class="label">Cache Hit Ratio <i class="bi bi-question-circle tooltip-icon" title="Percentual servido do cache"></i></div><div class="value" id="m-hitrate">—</div><div class="sub sub-green" id="m-hitrate-sub">hits: — | miss: —</div></div></div>
      <div class="col-md-3"><div class="metric-card"><div class="label">Request List <i class="bi bi-question-circle tooltip-icon" title="Tamanho da fila de requisições"></i></div><div class="value" id="m-reqavg">—</div><div class="sub sub-yellow" id="m-reqavg-sub">max: —</div></div></div>
    </div>

    <div class="section-title">Segurança e Performance</div>
    <div class="row g-3 mb-4">
      <div class="col-md-3"><div class="metric-card"><div class="label">DNSSEC Validação <i class="bi bi-question-circle tooltip-icon" title="Respostas DNSSEC validadas"></i></div><div class="value" id="m-dnssec">—</div><div class="sub sub-green" id="m-dnssec-sub">validados: — | inválidos: —</div></div></div>
      <div class="col-md-3"><div class="metric-card"><div class="label">Prefetch e Cache <i class="bi bi-question-circle tooltip-icon" title="Entradas de prefetch e cache"></i></div><div class="value" id="m-prefetch">—</div><div class="sub sub-blue" id="m-prefetch-sub">RRsets: — | Mensagens: —</div></div></div>
      <div class="col-md-3"><div class="metric-card"><div class="label">Queries Indesejadas <i class="bi bi-question-circle tooltip-icon" title="Queries bloqueadas"></i></div><div class="value" id="m-unwanted">—</div><div class="sub sub-green" id="m-unwanted-sub">respostas: —</div></div></div>
      <div class="col-md-3"><div class="metric-card"><div class="label">Domínios bloqueados</div><div class="value" id="m-blocked">—</div><div class="sub sub-blue">na blocklist</div></div></div>
    </div>

    <!-- Grafico Cache Performance com seletor de periodo -->
    <div class="row g-3 mb-4">
      <div class="col-12">
        <div class="chart-card">
          <div class="d-flex justify-content-between align-items-center mb-2">
            <div class="chart-title mb-0"><i class="bi bi-graph-up text-primary"></i> Performance do Cache</div>
            <div class="period-group">
              <span style="font-size:.72rem;color:var(--muted);margin-right:4px">Período:</span>
              <button class="period-btn active" onclick="setPeriod(1,this)">1h</button>
              <button class="period-btn" onclick="setPeriod(3,this)">3h</button>
              <button class="period-btn" onclick="setPeriod(6,this)">6h</button>
              <button class="period-btn" onclick="setPeriod(12,this)">12h</button>
            </div>
          </div>
          <div style="font-size:.7rem;color:var(--muted);margin-bottom:8px">Atualizado a cada 5s | Histórico coletado a cada minuto</div>
          <div class="chart-wrap"><canvas id="chart-cache"></canvas></div>
        </div>
      </div>
    </div>

    <!-- Grafico Tipos de Consulta -->
    <div class="row g-3 mb-4">
      <div class="col-md-5">
        <div class="chart-card">
          <div class="chart-title"><i class="bi bi-bar-chart text-primary"></i> Tipos de Consulta</div>
          <div class="chart-wrap"><canvas id="chart-qtypes"></canvas></div>
        </div>
      </div>
      <div class="col-md-7">
        <div class="chart-card">
          <div class="d-flex justify-content-between align-items-center mb-2">
            <div class="chart-title mb-0">Tempo de Resposta (ms)</div>
            <div class="period-group">
              <button class="period-btn active" onclick="setRespPeriod(1,this)">1h</button>
              <button class="period-btn" onclick="setRespPeriod(3,this)">3h</button>
              <button class="period-btn" onclick="setRespPeriod(6,this)">6h</button>
              <button class="period-btn" onclick="setRespPeriod(12,this)">12h</button>
            </div>
          </div>
          <div class="chart-wrap"><canvas id="chart-resp"></canvas></div>
        </div>
      </div>
    </div>

    <!-- DNSSEC -->
    <div class="section-title">Métricas Detalhadas</div>
    <div class="row g-3">
      <div class="col-md-6">
        <div class="chart-card">
          <div class="chart-title">DNSSEC (Última Hora)</div>
          <div class="chart-wrap-sm"><canvas id="chart-dnssec"></canvas></div>
        </div>
      </div>
    </div>
  </div>

  <!-- BLOCKLIST -->
  <div id="page-blocklist" class="page">
    <div class="topbar"><h4><i class="bi bi-slash-circle me-2 text-danger"></i>Domínios Bloqueados</h4><span class="badge bg-secondary" id="block-count">0 domínios</span></div>
    <div class="chart-card mb-3"><div class="d-flex gap-2"><input type="text" class="form-control" id="new-domain" placeholder="exemplo.com.br" onkeydown="if(event.key==='Enter')addDomain()"/><button class="btn btn-danger px-4" onclick="addDomain()"><i class="bi bi-plus-lg me-1"></i>Bloquear</button></div></div>
    <div class="chart-card"><input type="text" id="search-domain" placeholder="Filtrar domínios..." oninput="renderDomains()"/><div id="domain-list" class="mt-3"></div></div>
  </div>

  <!-- LOGS -->
  <div id="page-logs" class="page">
    <div class="topbar"><h4><i class="bi bi-terminal me-2"></i>Logs em Tempo Real <span class="live-dot ms-1"></span></h4><div class="d-flex gap-2"><button class="refresh-btn" onclick="clearLogs()"><i class="bi bi-trash"></i> Limpar</button><button class="refresh-btn" id="btn-pause" onclick="togglePause()"><i class="bi bi-pause-fill"></i> Pausar</button></div></div>
    <div id="log-box"></div>
  </div>
</div>

<div class="toast-container"><div id="toast" class="toast align-items-center text-white border-0" role="alert"><div class="d-flex"><div class="toast-body" id="toast-msg"></div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div></div></div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
// Nav
function showPage(name,el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  el.classList.add('active');
  if(name==='dashboard')loadAll();
  if(name==='blocklist')loadBlocklist();
  if(name==='logs')startLogs();
}
function showToast(msg,ok=true){
  const t=document.getElementById('toast');
  t.className='toast align-items-center text-white border-0 '+(ok?'bg-success':'bg-danger');
  document.getElementById('toast-msg').textContent=msg;
  new bootstrap.Toast(t,{delay:3000}).show();
}
function fmt(n){return Number(n).toLocaleString('pt-BR');}

// Charts
let charts={};
const CO={
  responsive:true,maintainAspectRatio:false,animation:false,
  plugins:{legend:{labels:{color:'#6b7280',font:{size:11},boxWidth:12}}},
  scales:{
    x:{ticks:{color:'#9ca3af',font:{size:10},maxTicksLimit:10},grid:{color:'#f1f5f9'}},
    y:{ticks:{color:'#9ca3af',font:{size:10}},grid:{color:'#f1f5f9'}}
  }
};
function makeChart(id,type,data,opts={}){
  if(charts[id])charts[id].destroy();
  charts[id]=new Chart(document.getElementById(id),{type,data,options:{...CO,...opts}});
}

// Periodos
let cachePeriod=1, respPeriod=1;
function setPeriod(h,el){
  cachePeriod=h;
  document.querySelectorAll('.period-group')[0].querySelectorAll('.period-btn').forEach(b=>b.classList.remove('active'));
  el.classList.add('active');
  loadHistory();
}
function setRespPeriod(h,el){
  respPeriod=h;
  document.querySelectorAll('.period-group')[1].querySelectorAll('.period-btn').forEach(b=>b.classList.remove('active'));
  el.classList.add('active');
  loadHistory();
}

// Stats
async function loadStats(){
  try{
    const r=await fetch('/api/stats');
    const d=await r.json();
    const badge=document.getElementById('status-badge');
    if(d.status==='active'){badge.className='badge-status badge-active';badge.innerHTML='<span class="dot dot-green"></span> Unbound Ativo';}
    else{badge.className='badge-status badge-inactive';badge.innerHTML='<span class="dot dot-red"></span> Unbound Inativo';}

    document.getElementById('m-qps').textContent=d.qps;
    document.getElementById('m-resp').textContent=d.resp_avg+' ms';
    document.getElementById('m-resp-sub').textContent='média | mediana: '+d.resp_med+' ms';
    document.getElementById('m-hitrate').textContent=d.hit_rate+'%';
    document.getElementById('m-hitrate-sub').textContent='hits: '+fmt(d.cachehits)+' | miss: '+fmt(d.cachemiss);
    document.getElementById('m-reqavg').textContent=d.requestlist_avg;
    document.getElementById('m-reqavg-sub').textContent='max: '+fmt(d.requestlist_max);
    const dt=d.dnssec_ok+d.dnssec_bad;
    const dp=dt>0?((d.dnssec_ok/dt)*100).toFixed(1):'0.0';
    document.getElementById('m-dnssec').textContent=dp+'%';
    document.getElementById('m-dnssec-sub').textContent='validados: '+fmt(d.dnssec_ok)+' | inválidos: '+d.dnssec_bad;
    document.getElementById('m-prefetch').textContent=fmt(d.prefetch);
    document.getElementById('m-prefetch-sub').textContent='RRsets: '+fmt(d.rrsets)+' | Mensagens: '+fmt(d.messages);
    document.getElementById('m-unwanted').textContent=fmt(d.unwanted_queries);
    document.getElementById('m-unwanted-sub').textContent='respostas: '+fmt(d.unwanted_replies);

    // Tipos de consulta
    const qt=d.qtypes||{};
    const ql=Object.keys(qt).filter(k=>qt[k]>0).sort((a,b)=>qt[b]-qt[a]).slice(0,8);
    if(ql.length>0){
      makeChart('chart-qtypes','bar',{
        labels:ql,
        datasets:[{data:ql.map(k=>qt[k]),backgroundColor:['#3b82f6','#10b981','#f59e0b','#ef4444','#8b5cf6','#06b6d4','#f97316','#84cc16'],borderRadius:5,borderWidth:0}]
      },{plugins:{legend:{display:false}}});
    }
  }catch(e){console.error('stats error:',e);}
}

// History
async function loadHistory(){
  try{
    // Carregar periodo maior entre os dois graficos
    const maxH=Math.max(cachePeriod,respPeriod);
    const r=await fetch('/api/history?hours='+maxH);
    const h=await r.json();

    // Calcular pontos para cada grafico
    const cachePoints=cachePeriod*60;
    const respPoints=respPeriod*60;
    const ts=h.timestamps;
    const tsLen=ts.length;

    const cacheTs=ts.slice(-Math.min(cachePoints,tsLen));
    const cacheCh=h.cachehits.slice(-Math.min(cachePoints,tsLen));
    const cacheCm=h.cachemiss.slice(-Math.min(cachePoints,tsLen));
    const cacheQps=h.qps.slice(-Math.min(cachePoints,tsLen));

    const respTs=ts.slice(-Math.min(respPoints,tsLen));
    const respAvg=h.resp_avg.slice(-Math.min(respPoints,tsLen));
    const respMed=h.resp_med.slice(-Math.min(respPoints,tsLen));

    makeChart('chart-cache','line',{
      labels:cacheTs,
      datasets:[
        {label:'Consultas/s',data:cacheQps,borderColor:'#3b82f6',backgroundColor:'rgba(59,130,246,.06)',tension:.4,fill:false,pointRadius:0,borderWidth:1.5},
        {label:'Cache Hits',data:cacheCh,borderColor:'#10b981',backgroundColor:'rgba(16,185,129,.1)',tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
        {label:'Cache Miss',data:cacheCm,borderColor:'#ef4444',backgroundColor:'rgba(239,68,68,.08)',tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
      ]
    });

    makeChart('chart-resp','line',{
      labels:respTs,
      datasets:[
        {label:'Médio (ms)',data:respAvg,borderColor:'#3b82f6',backgroundColor:'rgba(59,130,246,.08)',tension:.4,fill:false,pointRadius:0,borderWidth:1.5},
        {label:'Mediano (ms)',data:respMed,borderColor:'#10b981',backgroundColor:'rgba(16,185,129,.08)',tension:.4,fill:false,pointRadius:0,borderWidth:1.5},
      ]
    });

    makeChart('chart-dnssec','line',{
      labels:ts.slice(-60),
      datasets:[
        {label:'Validados',data:h.dnssec_ok.slice(-60),borderColor:'#10b981',backgroundColor:'rgba(16,185,129,.1)',tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
        {label:'Inválidos',data:h.dnssec_bad.slice(-60),borderColor:'#ef4444',backgroundColor:'rgba(239,68,68,.08)',tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
      ]
    });

  }catch(e){console.error('history error:',e);}
}

async function loadBlockedCount(){
  const r=await fetch('/api/blocklist');
  const d=await r.json();
  document.getElementById('m-blocked').textContent=fmt(d.domains.length);
}

function loadAll(){loadStats();loadHistory();loadBlockedCount();}

// Blocklist
let allDomains=[];
async function loadBlocklist(){
  const r=await fetch('/api/blocklist');const d=await r.json();
  allDomains=d.domains;
  document.getElementById('block-count').textContent=allDomains.length+' domínios';
  renderDomains();
}
function renderDomains(){
  const q=document.getElementById('search-domain').value.toLowerCase();
  const list=document.getElementById('domain-list');
  const f=allDomains.filter(d=>d.includes(q));
  if(!f.length){list.innerHTML='<p style="color:var(--muted);text-align:center;padding:16px">Nenhum domínio encontrado.</p>';return;}
  list.innerHTML=f.map(d=>`<span class="domain-tag"><i class="bi bi-slash-circle" style="color:var(--danger)"></i>${d}<span class="del" onclick="deleteDomain('${d}')"><i class="bi bi-x-lg"></i></span></span>`).join('');
}
async function addDomain(){
  const input=document.getElementById('new-domain');
  const domain=input.value.trim();
  if(!domain)return;
  const r=await fetch('/api/blocklist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain})});
  const d=await r.json();
  if(!r.ok){showToast(d.error||'Erro',false);return;}
  showToast('Domínio bloqueado: '+d.domain);
  input.value='';
  loadBlocklist();
  loadBlockedCount();
}
async function deleteDomain(domain){
  const r=await fetch('/api/blocklist/'+encodeURIComponent(domain),{method:'DELETE'});
  if(!r.ok){showToast('Erro ao desbloquear',false);return;}
  showToast('Desbloqueado: '+domain);
  loadBlocklist();
  loadBlockedCount();
}

// Logs
let logPaused=false,logSource=null;
function startLogs(){
  if(logSource)return;
  const box=document.getElementById('log-box');
  logSource=new EventSource('/api/logs/stream');
  logSource.onmessage=(e)=>{
    if(logPaused)return;
    const div=document.createElement('div');
    div.className='line';
    div.textContent=e.data;
    box.appendChild(div);
    while(box.children.length>500)box.removeChild(box.firstChild);
    box.scrollTop=box.scrollHeight;
  };
}
function clearLogs(){document.getElementById('log-box').innerHTML='';}
function togglePause(){
  logPaused=!logPaused;
  document.getElementById('btn-pause').innerHTML=logPaused?'<i class="bi bi-play-fill"></i> Retomar':'<i class="bi bi-pause-fill"></i> Pausar';
}

// Init: stats a cada 5s, history a cada 60s
loadAll();
setInterval(loadStats,5000);
setInterval(loadHistory,60000);
setInterval(loadBlockedCount,30000);
</script>
</body>
</html>"""

@app.route("/")
def index():
    return HTML

if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False)
