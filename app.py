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
HISTORY_POINTS = 60

if not os.path.exists(BLOCKLIST_FILE):
    open(BLOCKLIST_FILE, "w").close()

history = {
    "timestamps": deque(maxlen=HISTORY_POINTS),
    "qps":        deque(maxlen=HISTORY_POINTS),
    "cachehits":  deque(maxlen=HISTORY_POINTS),
    "cachemiss":  deque(maxlen=HISTORY_POINTS),
    "dnssec_ok":  deque(maxlen=HISTORY_POINTS),
    "dnssec_bad": deque(maxlen=HISTORY_POINTS),
    "resp_avg":   deque(maxlen=HISTORY_POINTS),
    "resp_med":   deque(maxlen=HISTORY_POINTS),
    "tcp":        deque(maxlen=HISTORY_POINTS),
    "ipv6":       deque(maxlen=HISTORY_POINTS),
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

            history["timestamps"].append(datetime.now().strftime("%H:%M"))
            history["qps"].append(round(qps, 1))
            history["cachehits"].append(ch)
            history["cachemiss"].append(cm)
            history["dnssec_ok"].append(int(d.get("total.num.dnssec_secure", 0)))
            history["dnssec_bad"].append(int(d.get("total.num.dnssec_bogus", 0)))
            history["resp_avg"].append(round(float(d.get("total.recursion.time.avg", 0)) * 1000, 3))
            history["resp_med"].append(round(float(d.get("total.recursion.time.median", 0)) * 1000, 3))
            history["tcp"].append(int(d.get("total.num.queries_tcp", 0)))
            history["ipv6"].append(int(d.get("total.num.queries_ipv6", 0)))

            last_queries = {"total": total, "cachehits": cachehits, "cachemiss": cachemiss, "ts": now}
        except Exception as e:
            print(f"Collector error: {e}")
        time.sleep(60)

threading.Thread(target=collect, daemon=True).start()

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

        qtypes = {}
        for k, v in d.items():
            m = re.match(r"^total\.num\.queries_type\.(\w+)$", k)
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
            "resp_avg": round(float(d.get("total.recursion.time.avg", 0)) * 1000, 3),
            "resp_med": round(float(d.get("total.recursion.time.median", 0)) * 1000, 3),
            "requestlist_avg": round(float(d.get("total.requestlist.avg", 0)), 3),
            "requestlist_max": int(d.get("total.requestlist.max", 0)),
            "prefetch": int(d.get("total.num.prefetch", 0)),
            "expired": int(d.get("total.num.expired", 0)),
            "rrsets": int(d.get("msg.cache.count", 0)),
            "messages": int(d.get("rrset.cache.count", 0)),
            "dnssec_ok": int(d.get("total.num.dnssec_secure", 0)),
            "dnssec_bad": int(d.get("total.num.dnssec_bogus", 0)),
            "tcp": int(d.get("total.num.queries_tcp", 0)),
            "ipv6": int(d.get("total.num.queries_ipv6", 0)),
            "unwanted_replies": int(d.get("unwanted.replies", 0)),
            "unwanted_queries": int(d.get("unwanted.queries", 0)),
            "qtypes": qtypes,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/history")
def api_history():
    return jsonify({
        "timestamps": list(history["timestamps"]),
        "qps":        list(history["qps"]),
        "cachehits":  list(history["cachehits"]),
        "cachemiss":  list(history["cachemiss"]),
        "dnssec_ok":  list(history["dnssec_ok"]),
        "dnssec_bad": list(history["dnssec_bad"]),
        "resp_avg":   list(history["resp_avg"]),
        "resp_med":   list(history["resp_med"]),
        "tcp":        list(history["tcp"]),
        "ipv6":       list(history["ipv6"]),
    })

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
    return jsonify({"ok": True})

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
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"/>
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet"/>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<style>
:root{--bg:#f8f9fc;--card:#ffffff;--border:#e5e9f0;--text:#1a1d2e;--muted:#6b7280;--primary:#3b82f6;--success:#10b981;--danger:#ef4444;--warning:#f59e0b;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;font-size:14px;}
.sidebar{width:220px;min-height:100vh;background:#fff;border-right:1px solid var(--border);position:fixed;top:0;left:0;z-index:100;display:flex;flex-direction:column;}
.brand{padding:20px;font-size:1rem;font-weight:700;color:var(--primary);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;}
.nav-item{padding:10px 20px;display:flex;align-items:center;gap:10px;color:#374151;cursor:pointer;border-left:3px solid transparent;transition:.15s;font-size:.875rem;}
.nav-item:hover{background:#eff6ff;color:var(--primary);}
.nav-item.active{background:#eff6ff;color:var(--primary);border-left-color:var(--primary);font-weight:600;}
.main{margin-left:220px;padding:28px;min-height:100vh;}
.page{display:none;}.page.active{display:block;}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;}
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
.chart-wrap{position:relative;height:180px;}.chart-wrap-sm{position:relative;height:150px;}
.refresh-btn{background:#fff;border:1px solid var(--border);color:var(--muted);border-radius:8px;padding:6px 14px;cursor:pointer;font-size:.8rem;transition:.15s;display:flex;align-items:center;gap:5px;}
.refresh-btn:hover{border-color:var(--primary);color:var(--primary);}
.tooltip-icon{color:var(--muted);font-size:.75rem;cursor:help;}
.domain-tag{display:inline-flex;align-items:center;gap:6px;background:#f1f5f9;border:1px solid var(--border);border-radius:6px;padding:4px 10px;margin:3px;font-size:.8rem;}
.domain-tag .del{cursor:pointer;color:var(--danger);font-size:.75rem;}
.domain-tag .del:hover{color:#b91c1c;}
#search-domain{background:#fff;border:1px solid var(--border);border-radius:8px;padding:8px 12px;width:100%;font-size:.85rem;outline:none;}
#search-domain:focus{border-color:var(--primary);}
#log-box{background:#0f1117;border:1px solid var(--border);border-radius:8px;height:500px;overflow-y:auto;padding:12px;font-family:monospace;font-size:.75rem;color:#94a3b8;}
#log-box .line{padding:1px 0;}#log-box .line:hover{color:#e2e8f0;}
.live-dot{width:7px;height:7px;background:var(--success);border-radius:50%;display:inline-block;animation:pulse 1.5s infinite;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.toast-container{position:fixed;bottom:24px;right:24px;z-index:9999;}
</style>
</head>
<body>
<div class="sidebar">
  <div class="brand"><i class="bi bi-globe2"></i> DNS Manager</div>
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
      <h4><i class="bi bi-globe2 me-2 text-primary"></i>DNS Recursivo</h4>
      <div class="d-flex align-items-center gap-2">
        <button class="refresh-btn" onclick="loadAll()"><i class="bi bi-arrow-clockwise"></i> Atualizar</button>
        <span id="status-badge" class="badge-status badge-active"><span class="dot dot-green"></span> Unbound Ativo</span>
      </div>
    </div>
    <div class="section-title">Métricas Críticas</div>
    <div class="row g-3 mb-4">
      <div class="col-md-3"><div class="metric-card"><div class="label">Consultas por Segundo <i class="bi bi-question-circle tooltip-icon" title="QPS atual"></i></div><div class="value" id="m-qps">—</div><div class="sub sub-green">QPS atual</div></div></div>
      <div class="col-md-3"><div class="metric-card"><div class="label">Tempo de resposta <i class="bi bi-question-circle tooltip-icon" title="Tempo médio de resolução recursiva"></i></div><div class="value" id="m-resp">—</div><div class="sub sub-yellow" id="m-resp-sub">média | mediana: —</div></div></div>
      <div class="col-md-3"><div class="metric-card"><div class="label">Cache Hit Ratio <i class="bi bi-question-circle tooltip-icon" title="Percentual servido do cache"></i></div><div class="value" id="m-hitrate">—</div><div class="sub sub-green" id="m-hitrate-sub">hits: — | miss: —</div></div></div>
      <div class="col-md-3"><div class="metric-card"><div class="label">Request List <i class="bi bi-question-circle tooltip-icon" title="Tamanho da fila de requisições"></i></div><div class="value" id="m-reqavg">—</div><div class="sub sub-yellow" id="m-reqavg-sub">max: —</div></div></div>
    </div>
    <div class="section-title">Segurança e Performance</div>
    <div class="row g-3 mb-4">
      <div class="col-md-3"><div class="metric-card"><div class="label">DNSSEC Validação <i class="bi bi-question-circle tooltip-icon" title="Respostas DNSSEC validadas"></i></div><div class="value" id="m-dnssec">—</div><div class="sub sub-green" id="m-dnssec-sub">validados: — | inválidos: —</div></div></div>
      <div class="col-md-3"><div class="metric-card"><div class="label">Queries TCP/IPv6 <i class="bi bi-question-circle tooltip-icon" title="Consultas via TCP e IPv6"></i></div><div class="value" id="m-tcp">—</div><div class="sub sub-blue" id="m-tcp-sub">TCP totais | IPv6: —</div></div></div>
      <div class="col-md-3"><div class="metric-card"><div class="label">Prefetch e Cache <i class="bi bi-question-circle tooltip-icon" title="Entradas de prefetch e cache"></i></div><div class="value" id="m-prefetch">—</div><div class="sub sub-blue" id="m-prefetch-sub">RRsets: — | Mensagens: —</div></div></div>
      <div class="col-md-3"><div class="metric-card"><div class="label">Queries Indesejadas <i class="bi bi-question-circle tooltip-icon" title="Queries bloqueadas"></i></div><div class="value" id="m-unwanted">—</div><div class="sub sub-green" id="m-unwanted-sub">respostas: —</div></div></div>
    </div>
    <div class="section-title">Bloqueios ativos</div>
    <div class="row g-3 mb-4">
      <div class="col-md-3"><div class="metric-card"><div class="label">Domínios bloqueados</div><div class="value" id="m-blocked">—</div><div class="sub sub-blue">na blocklist</div></div></div>
    </div>
    <div class="row g-3 mb-4">
      <div class="col-md-8">
        <div class="chart-card">
          <div class="chart-title"><i class="bi bi-graph-up text-primary"></i> Performance do Cache (Última Hora)</div>
          <div style="font-size:.7rem;color:var(--muted);margin-bottom:8px">Dados coletados a cada minuto após o início da aplicação</div>
          <div class="chart-wrap"><canvas id="chart-cache"></canvas></div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="chart-card">
          <div class="chart-title"><i class="bi bi-bar-chart text-primary"></i> Tipos de Consulta</div>
          <div class="chart-wrap"><canvas id="chart-qtypes"></canvas></div>
        </div>
      </div>
    </div>
    <div class="section-title">Métricas Detalhadas</div>
    <div class="row g-3">
      <div class="col-md-4"><div class="chart-card"><div class="chart-title">DNSSEC (Última Hora)</div><div class="chart-wrap-sm"><canvas id="chart-dnssec"></canvas></div></div></div>
      <div class="col-md-4"><div class="chart-card"><div class="chart-title">Tempos de Resposta</div><div class="chart-wrap-sm"><canvas id="chart-resp"></canvas></div></div></div>
      <div class="col-md-4"><div class="chart-card"><div class="chart-title">Queries TCP e IPv6</div><div class="chart-wrap-sm"><canvas id="chart-tcp"></canvas></div></div></div>
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
function showPage(name,el){document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));document.getElementById('page-'+name).classList.add('active');el.classList.add('active');if(name==='dashboard')loadAll();if(name==='blocklist')loadBlocklist();if(name==='logs')startLogs();}
function showToast(msg,ok=true){const t=document.getElementById('toast');t.className='toast align-items-center text-white border-0 '+(ok?'bg-success':'bg-danger');document.getElementById('toast-msg').textContent=msg;new bootstrap.Toast(t,{delay:3000}).show();}
function fmt(n){return Number(n).toLocaleString('pt-BR');}
let charts={};
const CO={responsive:true,maintainAspectRatio:false,animation:false,plugins:{legend:{labels:{color:'#6b7280',font:{size:11},boxWidth:12}}},scales:{x:{ticks:{color:'#9ca3af',font:{size:10},maxTicksLimit:8},grid:{color:'#f1f5f9'}},y:{ticks:{color:'#9ca3af',font:{size:10}},grid:{color:'#f1f5f9'}}}};
function makeChart(id,type,data,opts={}){if(charts[id])charts[id].destroy();charts[id]=new Chart(document.getElementById(id),{type,data,options:{...CO,...opts}});}
async function loadStats(){
  try{
    const r=await fetch('/api/stats');const d=await r.json();
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
    const dt=d.dnssec_ok+d.dnssec_bad;const dp=dt>0?((d.dnssec_ok/dt)*100).toFixed(1):'0.0';
    document.getElementById('m-dnssec').textContent=dp+'%';
    document.getElementById('m-dnssec-sub').textContent='validados: '+fmt(d.dnssec_ok)+' | inválidos: '+d.dnssec_bad;
    document.getElementById('m-tcp').textContent=fmt(d.tcp);
    document.getElementById('m-tcp-sub').textContent='TCP totais | IPv6: '+fmt(d.ipv6);
    document.getElementById('m-prefetch').textContent=fmt(d.prefetch);
    document.getElementById('m-prefetch-sub').textContent='RRsets: '+fmt(d.rrsets)+' | Mensagens: '+fmt(d.messages);
    document.getElementById('m-unwanted').textContent=fmt(d.unwanted_queries);
    document.getElementById('m-unwanted-sub').textContent='respostas: '+fmt(d.unwanted_replies);
    const qt=d.qtypes||{};const ql=Object.keys(qt).sort((a,b)=>qt[b]-qt[a]).slice(0,6);const qv=ql.map(k=>qt[k]);
    makeChart('chart-qtypes','bar',{labels:ql,datasets:[{data:qv,backgroundColor:['#3b82f6','#10b981','#f59e0b','#ef4444','#8b5cf6','#06b6d4'],borderRadius:5,borderWidth:0}]},{plugins:{legend:{display:false}}});
  }catch(e){console.error(e);}
}
async function loadHistory(){
  try{
    const r=await fetch('/api/history');const h=await r.json();const ts=h.timestamps;
    makeChart('chart-cache','line',{labels:ts,datasets:[
      {label:'Consultas/s',data:h.qps,borderColor:'#3b82f6',backgroundColor:'rgba(59,130,246,.08)',tension:.4,fill:false,pointRadius:0,borderWidth:1.5},
      {label:'Cache Hits',data:h.cachehits,borderColor:'#10b981',backgroundColor:'rgba(16,185,129,.1)',tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
      {label:'Cache Miss',data:h.cachemiss,borderColor:'#ef4444',backgroundColor:'rgba(239,68,68,.08)',tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
    ]});
    makeChart('chart-dnssec','line',{labels:ts,datasets:[
      {label:'Validados',data:h.dnssec_ok,borderColor:'#10b981',backgroundColor:'rgba(16,185,129,.1)',tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
      {label:'Inválidos',data:h.dnssec_bad,borderColor:'#ef4444',backgroundColor:'rgba(239,68,68,.08)',tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
    ]});
    makeChart('chart-resp','line',{labels:ts,datasets:[
      {label:'Médio',data:h.resp_avg,borderColor:'#3b82f6',backgroundColor:'rgba(59,130,246,.08)',tension:.4,fill:false,pointRadius:0,borderWidth:1.5},
      {label:'Mediano',data:h.resp_med,borderColor:'#10b981',backgroundColor:'rgba(16,185,129,.08)',tension:.4,fill:false,pointRadius:0,borderWidth:1.5},
    ]});
    makeChart('chart-tcp','line',{labels:ts,datasets:[
      {label:'Queries TCP',data:h.tcp,borderColor:'#3b82f6',backgroundColor:'rgba(59,130,246,.1)',tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
      {label:'Queries IPv6',data:h.ipv6,borderColor:'#f59e0b',backgroundColor:'rgba(245,158,11,.08)',tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
    ]});
  }catch(e){console.error(e);}
}
async function loadBlockedCount(){const r=await fetch('/api/blocklist');const d=await r.json();document.getElementById('m-blocked').textContent=fmt(d.domains.length);}
function loadAll(){loadStats();loadHistory();loadBlockedCount();}
let allDomains=[];
async function loadBlocklist(){const r=await fetch('/api/blocklist');const d=await r.json();allDomains=d.domains;document.getElementById('block-count').textContent=allDomains.length+' domínios';renderDomains();}
function renderDomains(){const q=document.getElementById('search-domain').value.toLowerCase();const list=document.getElementById('domain-list');const f=allDomains.filter(d=>d.includes(q));if(!f.length){list.innerHTML='<p style="color:var(--muted);text-align:center;padding:16px">Nenhum domínio encontrado.</p>';return;}list.innerHTML=f.map(d=>`<span class="domain-tag"><i class="bi bi-slash-circle" style="color:var(--danger)"></i>${d}<span class="del" onclick="deleteDomain('${d}')"><i class="bi bi-x-lg"></i></span></span>`).join('');}
async function addDomain(){const input=document.getElementById('new-domain');const domain=input.value.trim();if(!domain)return;const r=await fetch('/api/blocklist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain})});const d=await r.json();if(!r.ok){showToast(d.error||'Erro',false);return;}showToast('Domínio bloqueado: '+domain);input.value='';loadBlocklist();}
async function deleteDomain(domain){const r=await fetch('/api/blocklist/'+encodeURIComponent(domain),{method:'DELETE'});if(!r.ok){showToast('Erro ao desbloquear',false);return;}showToast('Desbloqueado: '+domain);loadBlocklist();}
let logPaused=false,logSource=null;
function startLogs(){if(logSource)return;const box=document.getElementById('log-box');logSource=new EventSource('/api/logs/stream');logSource.onmessage=(e)=>{if(logPaused)return;const div=document.createElement('div');div.className='line';div.textContent=e.data;box.appendChild(div);while(box.children.length>500)box.removeChild(box.firstChild);box.scrollTop=box.scrollHeight;};}
function clearLogs(){document.getElementById('log-box').innerHTML='';}
function togglePause(){logPaused=!logPaused;document.getElementById('btn-pause').innerHTML=logPaused?'<i class="bi bi-play-fill"></i> Retomar':'<i class="bi bi-pause-fill"></i> Pausar';}
loadAll();setInterval(loadAll,30000);
</script>
</body>
</html>"""

@app.route("/")
def index():
    return HTML

if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False)
