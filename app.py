from flask import Flask, jsonify, request, Response
import subprocess
import re
import os
import json
import time
import threading
from collections import deque
from datetime import datetime
import psutil

app = Flask(__name__)

BLOCKLIST_FILE = os.getenv("BLOCKLIST_FILE", "/etc/unbound/blocklist.conf")
LOG_FILE       = os.getenv("LOG_FILE",       "/var/log/unbound/unbound.log")
HISTORY_FILE   = os.getenv("HISTORY_FILE",   "/var/lib/unbound-web/history.json")
HOST           = os.getenv("HOST",           "0.0.0.0")
PORT           = int(os.getenv("PORT",       "8080"))
COLLECT_INTERVAL = 30  # segundos entre coletas de historico
POINTS_PER_HOUR = 3600 // COLLECT_INTERVAL  # 120 pontos/h
HISTORY_POINTS = 24 * POINTS_PER_HOUR  # 24 horas = 2880 pontos (1 a cada 30s)

if not os.path.exists(BLOCKLIST_FILE):
    open(BLOCKLIST_FILE, "w").close()

HISTORY_KEYS = (
    "timestamps", "qps", "cachehits", "cachemiss",
    "dnssec_ok", "dnssec_bad", "resp_avg", "resp_med",
    "qps_a", "qps_aaaa", "qps_cname", "qps_servfail",
)
history = {k: deque(maxlen=HISTORY_POINTS) for k in HISTORY_KEYS}
last_queries = {"total": 0, "cachehits": 0, "cachemiss": 0, "sum_time": 0, "ts": time.time()}
sliding_5min = deque(maxlen=60)


def save_history():
    try:
        os.makedirs(os.path.dirname(HISTORY_FILE) or ".", exist_ok=True)
        tmp = HISTORY_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump({k: list(history[k]) for k in HISTORY_KEYS}, f)
        os.replace(tmp, HISTORY_FILE)
    except Exception as e:
        print(f"save_history error: {e}")


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return
    try:
        with open(HISTORY_FILE) as f:
            data = json.load(f)
        for k in HISTORY_KEYS:
            for item in data.get(k, [])[-HISTORY_POINTS:]:
                history[k].append(item)
        print(f"Loaded {len(history['timestamps'])} pontos do historico")
    except Exception as e:
        print(f"load_history error: {e}")


def get_qtype(d, qtype):
    for k in (f"num.query.type.{qtype}",
              f"total.num.queries_type.{qtype}",
              f"thread0.num.queries_type.{qtype}"):
        if k in d:
            return int(d[k])
    return 0


def get_servfail(d):
    return int(d.get("num.answer.rcode.SERVFAIL",
                     d.get("total.num.answer.rcode.SERVFAIL", 0)))


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
            dnssec_ok_cum = int(d.get("num.answer.secure", d.get("total.num.dnssec_secure", 0)))
            dnssec_bad_cum = int(d.get("num.answer.bogus", d.get("total.num.dnssec_bogus", 0)))
            qa_cum    = get_qtype(d, "A")
            qaaaa_cum = get_qtype(d, "AAAA")
            qcname_cum = get_qtype(d, "CNAME")
            qsf_cum   = get_servfail(d)

            resp_avg_s = float(d.get("total.recursion.time.avg", 0))
            resp_med_s = float(d.get("total.recursion.time.median", 0))
            sum_time_s = cachemiss * resp_avg_s

            if last_queries["total"] == 0:
                last_queries = {"total": total, "cachehits": cachehits, "cachemiss": cachemiss,
                                "sum_time": sum_time_s, "dnssec_ok": dnssec_ok_cum, "dnssec_bad": dnssec_bad_cum,
                                "qa": qa_cum, "qaaaa": qaaaa_cum, "qcname": qcname_cum, "qsf": qsf_cum,
                                "ts": now}
                time.sleep(COLLECT_INTERVAL)
                continue

            elapsed = now - last_queries["ts"]
            qps  = max(0, (total - last_queries["total"]) / elapsed) if elapsed > 0 else 0
            qpsa = max(0, (qa_cum - last_queries.get("qa", 0)) / elapsed) if elapsed > 0 else 0
            qps4 = max(0, (qaaaa_cum - last_queries.get("qaaaa", 0)) / elapsed) if elapsed > 0 else 0
            qpsc = max(0, (qcname_cum - last_queries.get("qcname", 0)) / elapsed) if elapsed > 0 else 0
            qpsf = max(0, (qsf_cum - last_queries.get("qsf", 0)) / elapsed) if elapsed > 0 else 0
            ch  = max(0, cachehits - last_queries["cachehits"])
            cm  = max(0, cachemiss - last_queries["cachemiss"])
            dok = max(0, dnssec_ok_cum - last_queries.get("dnssec_ok", 0))
            dbad = max(0, dnssec_bad_cum - last_queries.get("dnssec_bad", 0))

            old_sum = last_queries.get("sum_time", 0)
            d_sum = sum_time_s - old_sum

            if cm > 0 and cachemiss >= last_queries["cachemiss"]:
                resp_avg_1m_s = d_sum / cm
            else:
                resp_avg_1m_s = resp_avg_s

            resp_avg_ms = round(resp_avg_1m_s * 1000, 3) if resp_avg_1m_s < 10 else 0
            resp_med_ms = round(resp_med_s * 1000, 3) if resp_med_s < 10 else 0

            history["timestamps"].append(datetime.now().strftime("%H:%M"))
            history["qps"].append(round(qps, 1))
            history["cachehits"].append(ch)
            history["cachemiss"].append(cm)
            history["dnssec_ok"].append(dok)
            history["dnssec_bad"].append(dbad)
            history["resp_avg"].append(resp_avg_ms)
            history["resp_med"].append(resp_med_ms)
            history["qps_a"].append(round(qpsa, 1))
            history["qps_aaaa"].append(round(qps4, 1))
            history["qps_cname"].append(round(qpsc, 1))
            history["qps_servfail"].append(round(qpsf, 1))

            last_queries = {"total": total, "cachehits": cachehits, "cachemiss": cachemiss,
                            "sum_time": sum_time_s, "dnssec_ok": dnssec_ok_cum, "dnssec_bad": dnssec_bad_cum,
                            "qa": qa_cum, "qaaaa": qaaaa_cum, "qcname": qcname_cum, "qsf": qsf_cum,
                            "ts": now}
            save_history()
        except Exception as e:
            print(f"Collector error: {e}")
        time.sleep(COLLECT_INTERVAL)

load_history()
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

        # Tempo de resposta (média dos últimos 5 minutos)
        resp_avg_s = float(d.get("total.recursion.time.avg", 0))
        resp_med_s = float(d.get("total.recursion.time.median", 0))
        sum_time_s = cachemiss * resp_avg_s
        
        if len(sliding_5min) > 0 and cachemiss < sliding_5min[-1][0]:
            sliding_5min.clear()
        sliding_5min.append((cachemiss, sum_time_s))
        
        if len(sliding_5min) > 1:
            old_cm, old_sum = sliding_5min[0]
            d_cm = cachemiss - old_cm
            d_sum = sum_time_s - old_sum
            resp_avg_5m_s = (d_sum / d_cm) if d_cm > 0 else 0
        else:
            resp_avg_5m_s = resp_avg_s
            
        resp_avg_ms = round(resp_avg_5m_s * 1000, 3) if resp_avg_5m_s < 10 else 0
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

        uptime_s = float(d.get("time.up", 0))
        days, rem = divmod(uptime_s, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, _ = divmod(rem, 60)
        if days > 0:
            uptime = f"{int(days)}d {int(hours)}h {int(minutes)}m"
        elif hours > 0:
            uptime = f"{int(hours)}h {int(minutes)}m"
        else:
            uptime = f"{int(minutes)}m"

        return jsonify({
            "status": status,
            "uptime": uptime,
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
            "dnssec_ok": int(d.get("num.answer.secure", d.get("total.num.dnssec_secure", 0))),
            "dnssec_bad": int(d.get("num.answer.bogus", d.get("total.num.dnssec_bogus", 0))),
            "unwanted_replies": int(d.get("unwanted.replies", 0)),
            "unwanted_queries": int(d.get("unwanted.queries", 0)),
            "qtypes": qtypes,
            "servfail": int(d.get("num.answer.rcode.SERVFAIL", 0)),
            "sys_cpu": psutil.cpu_percent(interval=None),
            "sys_mem": psutil.virtual_memory().percent,
            "sys_disk": psutil.disk_usage('/').percent,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# API History com filtro de periodo
@app.route("/api/history")
def api_history():
    hours = int(request.args.get("hours", 1))
    points = min(hours * POINTS_PER_HOUR, HISTORY_POINTS)
    ts   = list(history["timestamps"])
    qps  = list(history["qps"])
    ch   = list(history["cachehits"])
    cm   = list(history["cachemiss"])
    dok  = list(history["dnssec_ok"])
    dbad = list(history["dnssec_bad"])
    ravg = list(history["resp_avg"])
    rmed = list(history["resp_med"])
    qa = list(history["qps_a"])
    qaaaa = list(history["qps_aaaa"])
    qcname = list(history["qps_cname"])
    qsf = list(history["qps_servfail"])
    return jsonify({
        "timestamps":   ts[-points:],
        "qps":          qps[-points:],
        "cachehits":    ch[-points:],
        "cachemiss":    cm[-points:],
        "dnssec_ok":    dok[-points:],
        "dnssec_bad":   dbad[-points:],
        "resp_avg":     ravg[-points:],
        "resp_med":     rmed[-points:],
        "qps_a":        qa[-points:],
        "qps_aaaa":     qaaaa[-points:],
        "qps_cname":    qcname[-points:],
        "qps_servfail": qsf[-points:],
        "points_per_hour": POINTS_PER_HOUR,
    })

# API debug - mostrar todas as chaves do unbound-control stats
@app.route("/api/debug/stats")
def debug_stats():
    d = parse_stats()
    return jsonify(d)

advanced_stats_cache = {"ts": 0, "data": None}

@app.route("/api/stats/advanced")
def stats_advanced():
    global advanced_stats_cache
    import time
    
    # Retorna do cache se tiver sido processado a menos de 10 minutos (600 segundos)
    if advanced_stats_cache["data"] and (time.time() - advanced_stats_cache["ts"]) < 600:
        return jsonify(advanced_stats_cache["data"])
        
    try:
        d_stats = parse_stats()
        queries = float(d_stats.get("total.num.queries", 0))
        uptime = float(d_stats.get("time.up", 1))
        qps = queries / uptime if uptime > 0 else 50
        
        # 12 horas estático
        lines_to_read = int(qps * 3 * 3600 * 12)
        lines_to_read = min(lines_to_read, 300000) # limite reduzido para uso levíssimo de CPU
        lines_to_read = max(lines_to_read, 50000)
        
        proc = subprocess.Popen(["tail", "-n", str(lines_to_read), LOG_FILE], stdout=subprocess.PIPE, text=True)
        out, _ = proc.communicate()
        
        top_domains = {}
        top_servfail = {}
        top_ips = {}
        
        import re
        re_domain = re.compile(r'([a-zA-Z0-9_\.-]+)\.\s+[A-Z]+\s+IN')
        re_ip = re.compile(r'(?:info:|reply:|query:)\s+([a-fA-F0-9\.:]+)')
        re_ip_fallback = re.compile(r'(?:reply:|servfail|warning:|error:)\s+([a-fA-F0-9\.:]+)')
        
        for line in out.splitlines():
            # Extrair dominio
            m_domain = re_domain.search(line)
            if not m_domain: continue
            
            domain = m_domain.group(1).lower()
            if domain.startswith('<'): domain = domain[1:]

            # Extrair IP
            ip = None
            m_ip = re_ip.search(line)
            if m_ip:
                ip = m_ip.group(1)
                if ip in ("reply:", "servfail", "warning:", "error:"):
                    m2 = re_ip_fallback.search(line)
                    if m2: ip = m2.group(1)
            
            if ip and (ip.startswith('<') or ip.lower() in ("servfail", "warning:", "error:", "reply:")):
                ip = None
                
            if ip:
                top_ips[ip] = top_ips.get(ip, 0) + 1
                
            line_lower = line.lower()
            if "servfail" in line_lower:
                top_servfail[domain] = top_servfail.get(domain, 0) + 1
            elif "reply:" not in line_lower:
                top_domains[domain] = top_domains.get(domain, 0) + 1
                    
        def get_top(d, n=10):
            return [{"name": k, "count": v} for k, v in sorted(d.items(), key=lambda item: item[1], reverse=True)[:n]]
            
        res = {
            "top_domains": get_top(top_domains),
            "top_servfail": get_top(top_servfail),
            "top_ips": get_top(top_ips)
        }
        
        advanced_stats_cache["data"] = res
        advanced_stats_cache["ts"] = time.time()
        
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
    # Cabecalho "server:" e necessario porque blocklist.conf e incluido fora
    # da clausula server: do unbound.conf, e local-zone so e valido dentro dela.
    with open(BLOCKLIST_FILE, "w") as f:
        f.write("server:\n")
        for d in sorted(set(domains)):
            f.write(f'    local-zone: "{d}" always_nxdomain\n')

def sanitize_domain(raw):
    cleaned = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', raw)
    cleaned = re.sub(r'https?://', '', cleaned)
    cleaned = cleaned.strip().strip('/').lower()
    return cleaned

def apply_blocklist(domains, previous):
    """Escreve a blocklist e recarrega o Unbound; reverte em caso de erro."""
    write_blocklist(domains)
    check = subprocess.run(["unbound-checkconf"], capture_output=True, text=True)
    if check.returncode != 0:
        write_blocklist(previous)
        raise RuntimeError(check.stderr.strip() or check.stdout.strip() or "unbound-checkconf falhou")
    reload = subprocess.run(["unbound-control", "reload"], capture_output=True, text=True)
    if reload.returncode != 0:
        write_blocklist(previous)
        raise RuntimeError(reload.stderr.strip() or reload.stdout.strip() or "unbound-control reload falhou")

SYNC_TIME_FILE = os.path.dirname(HISTORY_FILE) + "/botnet_sync.txt"

@app.route("/api/blocklist", methods=["GET"])
def blocklist_get():
    domains = read_blocklist()
    last_sync = "Nunca"
    if os.path.exists(SYNC_TIME_FILE):
        with open(SYNC_TIME_FILE, "r") as f:
            last_sync = f.read().strip()
            
    q = request.args.get("q", "").lower()
    if q:
        filtered = [d for d in domains if q in d][:100]
        return jsonify({"domains": filtered, "total": len(domains), "last_sync": last_sync})
    return jsonify({"domains": [], "total": len(domains), "last_sync": last_sync})

@app.route("/api/blocklist/clear_all", methods=["POST"])
def blocklist_clear_all():
    try:
        previous = read_blocklist()
        apply_blocklist([], previous)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": f"Falha ao remover bloqueios: {e}"}), 500

@app.route("/api/blocklist", methods=["POST"])
def blocklist_add():
    raw = request.json.get("domain", "")
    domain = sanitize_domain(raw)
    if not domain or not re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', domain):
        return jsonify({"error": "Dominio invalido: " + domain}), 400
    domains = read_blocklist()
    if domain in domains:
        return jsonify({"error": "Dominio ja bloqueado"}), 409
    try:
        apply_blocklist(domains + [domain], domains)
    except Exception as e:
        return jsonify({"error": f"Falha ao aplicar bloqueio: {e}"}), 500
    return jsonify({"ok": True, "domain": domain})

@app.route("/api/blocklist/<domain>", methods=["DELETE"])
def blocklist_delete(domain):
    domain = sanitize_domain(domain)
    domains = read_blocklist()
    if domain not in domains:
        return jsonify({"error": "Dominio nao encontrado"}), 404
    new_domains = [d for d in domains if d != domain]
    try:
        apply_blocklist(new_domains, domains)
    except Exception as e:
        return jsonify({"error": f"Falha ao remover bloqueio: {e}"}), 500
    return jsonify({"ok": True})

@app.route("/api/blocklist/sync_botnet", methods=["POST"])
def blocklist_sync_botnet():
    sources = [
        "https://v.firebog.net/hosts/Prigent-Malware.txt",
        "https://urlhaus.abuse.ch/downloads/hostfile/"
    ]
    try:
        import urllib.request
        new_domains = set()
        for url in sources:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=15) as response:
                    data = response.read().decode('utf-8', errors='ignore')
                for line in data.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] in ('127.0.0.1', '0.0.0.0'):
                        domain = parts[1]
                    else:
                        domain = parts[0]
                    domain = sanitize_domain(domain)
                    if domain and domain != 'localhost':
                        new_domains.add(domain)
            except Exception as e:
                print(f"Erro ao buscar {url}: {e}")
                    
        previous = read_blocklist()
        domains = set(previous)
        initial_count = len(domains)
        domains.update(new_domains)
        
        apply_blocklist(list(domains), previous)
        
        try:
            with open(SYNC_TIME_FILE, "w") as f:
                f.write(datetime.now().strftime("%d/%m/%Y %H:%M"))
        except:
            pass
        
        return jsonify({"ok": True, "added": len(domains) - initial_count, "total": len(domains)})
    except Exception as e:
        return jsonify({"error": f"Falha na sincronizacao: {e}"}), 500

# Logs SSE
@app.route("/api/logs/stream")
def logs_stream():
    ip = request.args.get("ip", "").strip()
    if not ip:
        def empty():
            yield "data: Por favor informe um IP para buscar logs.\n\n"
        return Response(empty(), mimetype="text/event-stream")
        
    def generate():
        try:
            # Tailing more lines backward so when you connect you immediately see recent requests from that IP
            tail = subprocess.Popen(["tail", "-n", "10000", "-f", LOG_FILE], stdout=subprocess.PIPE, text=True)
            grep = subprocess.Popen(["grep", "--line-buffered", ip], stdin=tail.stdout, stdout=subprocess.PIPE, text=True)
            for line in grep.stdout:
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
<title>DNS Elevate</title>
<link rel="icon" type="image/png" href="/static/favicon.png?v=2"/>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"/>
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet"/>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Montserrat:wght@300;400;500&family=Playfair+Display:ital,wght@0,400;0,500;1,400&display=swap" rel="stylesheet"/>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<style>
:root{
  --bg:#f8f7fb;
  --bg-grad:linear-gradient(135deg,#ffffff 0%,#f1eef8 100%);
  --card:#fff;
  --border:#e4e0ef;
  --text:#1c1836;
  --muted:#666085;
  --primary:#6a1e9c;
  --primary-dark:#282362;
  --primary-light:#9d59ca;
  --primary-soft:#f3edf9;
  --success:#10b981;
  --danger:#ef4444;
  --warning:#f59e0b;
  --nav-hover:#f3edf9;
  --domain-bg:#f3edf9;
}
[data-theme="dark"]{
  --bg:#14112e;
  --bg-grad:linear-gradient(135deg,#181438 0%,#0f0d23 100%);
  --card:#211d47;
  --border:#352e68;
  --text:#f8f7fb;
  --muted:#a39dc1;
  --primary:#9d59ca;
  --primary-dark:#6a1e9c;
  --primary-light:#c596e8;
  --primary-soft:#352e68;
  --nav-hover:#352e68;
  --domain-bg:#1c1836;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg-grad);background-attachment:fixed;color:var(--text);font-family:'Inter','Segoe UI',sans-serif;font-size:14px;font-feature-settings:'cv11','ss01';transition:color 0.3s;}
.sidebar{width:220px;min-height:100vh;background:var(--card);border-right:1px solid var(--border);position:fixed;top:0;left:0;z-index:100;transition:background 0.3s, border-color 0.3s;}
.brand{padding:16px 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;cursor:pointer;}
.brand-logo{width:56px;height:56px;object-fit:contain;flex-shrink:0;border-radius:50%;background:#fff;padding:2px;}
.brand-text{display:flex;flex-direction:column;align-items:flex-end;line-height:1;}
.brand-text .top{font-family:'Montserrat',sans-serif;font-size:1.5rem;font-weight:400;letter-spacing:.03em;color:var(--primary-dark);line-height:1;}
[data-theme="dark"] .brand-text .top{color:var(--text);}
.brand-text .bot{font-family:'Playfair Display',serif;font-size:1.1rem;font-weight:400;color:var(--primary);margin-top:-4px;letter-spacing:0;line-height:1;margin-right:2px;}
.nav-item{padding:11px 22px;display:flex;align-items:center;gap:10px;color:var(--text);cursor:pointer;border-left:3px solid transparent;transition:.15s;font-size:.875rem;font-weight:500;}
.nav-item:hover{background:var(--nav-hover);color:var(--primary);}
.nav-item.active{background:var(--nav-hover);color:var(--primary);border-left-color:var(--primary);font-weight:600;}
.main{margin-left:220px;padding:28px;min-height:100vh;}
.page{display:none;}.page.active{display:block;}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:10px;}
.topbar h4{font-family:'Montserrat',sans-serif;font-size:1.8rem;font-weight:400;letter-spacing:.03em;color:var(--primary-dark);display:flex;align-items:baseline;gap:8px;margin:0;}
[data-theme="dark"] .topbar h4{color:var(--text);}
.topbar h4 .net{font-family:'Playfair Display',serif;font-size:1.4rem;font-weight:400;color:var(--primary);letter-spacing:0;}
.topbar-logo{width:56px;height:56px;object-fit:contain;border-radius:50%;background:#fff;padding:2px;}
.badge-status{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;border-radius:20px;font-size:.78rem;font-weight:600;}
.badge-active{background:#d1fae5;color:#065f46;}.badge-inactive{background:#fee2e2;color:#991b1b;}
.dot{width:7px;height:7px;border-radius:50%;}.dot-green{background:#10b981;}.dot-red{background:#ef4444;}
.section-title{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--primary);margin-bottom:12px;}
.metric-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:18px 20px;transition:background 0.3s, border-color 0.3s, transform 0.15s;}
.metric-card:hover{border-color:var(--primary-light);}
.metric-card .label{font-size:.75rem;color:var(--muted);margin-bottom:6px;display:flex;align-items:center;gap:5px;font-weight:500;}
.metric-card .value{font-size:1.65rem;font-weight:700;color:var(--text);line-height:1;letter-spacing:-.01em;}
.metric-card .sub{font-size:.72rem;margin-top:5px;}
.sub-green{color:var(--success);}.sub-yellow{color:var(--warning);}.sub-blue{color:var(--primary);}
.text-primary{color:var(--primary)!important;}
.text-info{color:var(--primary-light)!important;}
.chart-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:18px 20px;transition:background 0.3s, border-color 0.3s;}
.chart-title{font-size:.85rem;font-weight:600;margin-bottom:8px;display:flex;align-items:center;gap:6px;color:var(--text);}
.chart-wrap{position:relative;height:200px;}.chart-wrap-sm{position:relative;height:160px;}
.refresh-btn{background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:6px 14px;cursor:pointer;font-size:.8rem;transition:.15s;display:inline-flex;align-items:center;gap:5px;font-weight:500;}
.refresh-btn:hover{border-color:var(--primary);color:var(--primary);background:var(--primary-soft);}
.period-btn{background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:4px 10px;cursor:pointer;font-size:.75rem;transition:.15s;font-weight:500;}
.period-btn:hover{border-color:var(--primary);color:var(--primary);}
.period-btn.active{background:var(--primary);border-color:var(--primary);color:#fff;}
.tooltip-icon{color:var(--muted);font-size:.75rem;cursor:help;}
.domain-tag{display:inline-flex;align-items:center;gap:6px;background:var(--domain-bg);border:1px solid var(--border);border-radius:6px;padding:4px 10px;margin:3px;font-size:.8rem;color:var(--text);}
.domain-tag .del{cursor:pointer;color:var(--danger);font-size:.75rem;}
.domain-tag .del:hover{color:#b91c1c;}
#search-domain{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:8px 12px;width:100%;font-size:.85rem;outline:none;color:var(--text);font-family:inherit;}
#search-domain:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-soft);}
#new-domain{font-family:inherit;}
#new-domain:focus{border-color:var(--primary)!important;box-shadow:0 0 0 3px var(--primary-soft)!important;}
.btn-danger{background:var(--primary)!important;border-color:var(--primary)!important;}
.btn-danger:hover{background:var(--primary-dark)!important;border-color:var(--primary-dark)!important;}
#log-box{background:#0f0820;border:1px solid var(--border);border-radius:8px;height:500px;overflow-y:auto;padding:12px;font-family:'Menlo','Consolas',monospace;font-size:.75rem;color:#a89dc4;}
#log-box .line{padding:1px 0;white-space:pre-wrap;word-break:break-all;}
#log-box .line:hover{color:#e2d9f5;}
.live-dot{width:7px;height:7px;background:var(--success);border-radius:50%;display:inline-block;animation:pulse 1.5s infinite;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
@keyframes spin{100%{transform:rotate(360deg)}}
.spin{animation:spin 1s linear infinite;display:inline-block;}
.toast-container{position:fixed;bottom:24px;right:24px;z-index:9999;}
.period-group{display:flex;gap:4px;align-items:center;}
#theme-toggle{padding:6px 10px;}
</style>
</head>
<body>
<div class="sidebar">
  <div class="brand" onclick="showPage('dashboard', document.querySelectorAll('.nav-item')[0])" style="justify-content:center; padding:32px 16px 24px 16px;">
    <img src="/static/logo.png" alt="Elevate Network" style="width:55%; max-height:none; object-fit:contain; border-radius:8px; box-shadow:0 4px 12px rgba(40,35,98,.15);"/>
  </div>
  <div style="padding:16px 0">
    <div class="nav-item active" onclick="showPage('dashboard',this)"><i class="bi bi-speedometer2"></i> Dashboard</div>
    <div class="nav-item" onclick="showPage('blocklist',this)"><i class="bi bi-slash-circle"></i> Bloqueios</div>
    <div class="nav-item" onclick="showPage('advanced',this)"><i class="bi bi-bar-chart-steps"></i> Avançado</div>
    <div class="nav-item" onclick="showPage('logs',this)"><i class="bi bi-terminal"></i> Logs</div>
  </div>
</div>
<div class="main">

  <!-- DASHBOARD -->
  <div id="page-dashboard" class="page active">
    <div class="topbar" style="justify-content: space-between;">
      <img src="/static/unbound-logo.png" alt="Unbound Logo" style="max-height: 55px; object-fit: contain; margin-left: 4px;"/>
      <div class="d-flex align-items-center gap-2">
        <button class="refresh-btn" onclick="loadAll()"><i class="bi bi-arrow-clockwise"></i> Atualizar</button>
        <button id="theme-toggle" class="refresh-btn" onclick="toggleTheme()" title="Alternar Tema"><i class="bi bi-moon-fill" id="theme-icon"></i></button>
        <span id="status-badge" class="badge-status badge-active"><span class="dot dot-green"></span> Unbound Ativo</span>
      </div>
    </div>

    <div class="section-title">System Metrics (Real-time)</div>
    <div class="row g-3 mb-4">
      <div class="col-md-4"><div class="metric-card"><div class="label">CPU Utilization</div><div class="value" id="m-sys-cpu">—</div><div class="sub" id="m-sys-cpu-bar" style="height:4px;background:var(--border);border-radius:2px;margin-top:8px;overflow:hidden;"><div style="width:0%;height:100%;background:var(--success);transition:width 0.5s;"></div></div></div></div>
      <div class="col-md-4"><div class="metric-card"><div class="label">Memory Utilization</div><div class="value" id="m-sys-mem">—</div><div class="sub" id="m-sys-mem-bar" style="height:4px;background:var(--border);border-radius:2px;margin-top:8px;overflow:hidden;"><div style="width:0%;height:100%;background:var(--success);transition:width 0.5s;"></div></div></div></div>
      <div class="col-md-4"><div class="metric-card"><div class="label">Disk Utilization</div><div class="value" id="m-sys-disk">—</div><div class="sub" id="m-sys-disk-bar" style="height:4px;background:var(--border);border-radius:2px;margin-top:8px;overflow:hidden;"><div style="width:0%;height:100%;background:var(--success);transition:width 0.5s;"></div></div></div></div>
    </div>

    <div class="section-title">DNS Traffic (Real-time)</div>
    <div class="row g-3 mb-4">
      <div class="col-md-2"><div class="metric-card" style="text-align:center"><div class="label justify-content-center">TOTAL Queries</div><div class="value text-primary" id="m-tot-q" style="font-size:1.8rem">—</div></div></div>
      <div class="col-md-2"><div class="metric-card" style="text-align:center"><div class="label justify-content-center">Type A</div><div class="value text-success" id="m-tot-a" style="font-size:1.8rem">—</div></div></div>
      <div class="col-md-2"><div class="metric-card" style="text-align:center"><div class="label justify-content-center">Type AAAA</div><div class="value text-warning" id="m-tot-aaaa" style="font-size:1.8rem">—</div></div></div>
      <div class="col-md-2"><div class="metric-card" style="text-align:center"><div class="label justify-content-center">Type CNAME</div><div class="value" style="color:var(--primary-light);font-size:1.8rem;" id="m-tot-cname">—</div></div></div>
      <div class="col-md-2"><div class="metric-card" style="text-align:center"><div class="label justify-content-center">SERVFAIL</div><div class="value text-danger" id="m-tot-servfail" style="font-size:1.8rem">—</div></div></div>
      <div class="col-md-2"><div class="metric-card" style="text-align:center"><div class="label justify-content-center">Cache Hits</div><div class="value text-info" id="m-tot-hits" style="font-size:1.8rem">—</div></div></div>
    </div>

    <div class="row g-3 mb-4">
      <div class="col-12">
        <div class="chart-card">
          <div class="d-flex justify-content-between align-items-center mb-2">
            <div class="chart-title mb-0"><i class="bi bi-activity text-primary"></i> Consultas DNS</div>
            <div class="period-group">
              <button class="period-btn active" onclick="setRtPeriod(0,this)">5 Min</button>
              <button class="period-btn" onclick="setRtPeriod(1,this)">1h</button>
              <button class="period-btn" onclick="setRtPeriod(3,this)">3h</button>
              <button class="period-btn" onclick="setRtPeriod(6,this)">6h</button>
              <button class="period-btn" onclick="setRtPeriod(12,this)">12h</button>
              <button class="period-btn" onclick="setRtPeriod(24,this)">24h</button>
            </div>
          </div>
          <div class="chart-wrap"><canvas id="chart-realtime"></canvas></div>
        </div>
      </div>
    </div>

    <div class="section-title">Métricas Críticas & Segurança</div>
    <div class="row g-3 mb-4">
      <div class="col-md-3"><div class="metric-card"><div class="label">Consultas por Segundo <i class="bi bi-question-circle tooltip-icon" title="QPS atual"></i></div><div class="value" id="m-qps">—</div><div class="sub sub-green">QPS atual</div></div></div>
      <div class="col-md-3"><div class="metric-card"><div class="label">Tempo de resposta <i class="bi bi-question-circle tooltip-icon" title="Tempo médio de resolução recursiva em ms"></i></div><div class="value" id="m-resp">—</div><div class="sub sub-yellow" id="m-resp-sub">média | mediana: —</div></div></div>
      <div class="col-md-3"><div class="metric-card"><div class="label">Cache Hit Ratio <i class="bi bi-question-circle tooltip-icon" title="Percentual servido do cache"></i></div><div class="value" id="m-hitrate">—</div><div class="sub sub-green" id="m-hitrate-sub">hits: — | miss: —</div></div></div>
      <div class="col-md-3"><div class="metric-card"><div class="label">Request List <i class="bi bi-question-circle tooltip-icon" title="Tamanho da fila de requisições"></i></div><div class="value" id="m-reqavg">—</div><div class="sub sub-yellow" id="m-reqavg-sub">max: —</div></div></div>
    </div>
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
              <button class="period-btn" onclick="setPeriod(24,this)">24h</button>
            </div>
          </div>
          <div style="font-size:.7rem;color:var(--muted);margin-bottom:8px">Atualizado a cada 30s | Histórico coletado a cada 30s</div>
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
              <button class="period-btn" onclick="setRespPeriod(24,this)">24h</button>
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
          <div class="d-flex justify-content-between align-items-center mb-2">
            <div class="chart-title mb-0">DNSSEC</div>
            <div class="period-group">
              <button class="period-btn active" onclick="setDnssecPeriod(1,this)">1h</button>
              <button class="period-btn" onclick="setDnssecPeriod(3,this)">3h</button>
              <button class="period-btn" onclick="setDnssecPeriod(6,this)">6h</button>
              <button class="period-btn" onclick="setDnssecPeriod(12,this)">12h</button>
              <button class="period-btn" onclick="setDnssecPeriod(24,this)">24h</button>
            </div>
          </div>
          <div class="chart-wrap-sm"><canvas id="chart-dnssec"></canvas></div>
        </div>
      </div>
    </div>
  </div>

  <!-- BLOCKLIST -->
  <div id="page-blocklist" class="page">
    <div class="topbar">
      <h4><i class="bi bi-slash-circle me-2 text-danger"></i>Domínios Bloqueados</h4>
      <div class="d-flex align-items-center gap-3">
        <button class="refresh-btn text-danger" onclick="clearAllBlocks()" title="Remover todos os bloqueios e limpar lista" style="border-color:var(--danger)">
          <i class="bi bi-trash"></i> Limpar Tudo
        </button>
        <button class="refresh-btn text-warning d-flex flex-column align-items-center justify-content-center" onclick="syncBotnet()" id="btn-sync" title="Baixar lista atualizada de Botnets/C2C" style="border-color:var(--warning); padding: 4px 12px; line-height: 1.2;">
          <div><i class="bi bi-shield-lock-fill"></i> Sincronizar C2C/Botnet</div>
          <small id="sync-time" style="font-size: 0.65rem; opacity: 0.8;">Última: Carregando...</small>
        </button>
        <span class="badge bg-secondary" id="block-count">0 domínios</span>
      </div>
    </div>
    <div class="chart-card mb-3"><div class="d-flex gap-2"><input type="text" class="form-control" id="new-domain" placeholder="exemplo.com.br" onkeydown="if(event.key==='Enter')addDomain()"/><button class="btn btn-danger px-4" onclick="addDomain()"><i class="bi bi-plus-lg me-1"></i>Bloquear</button></div></div>
    <div class="chart-card"><input type="text" id="search-domain" placeholder="Filtrar domínios..." oninput="renderDomains()"/><div id="domain-list" class="mt-3"></div></div>
  </div>

  <!-- ADVANCED STATS -->
  <div id="page-advanced" class="page">
    <div class="topbar">
      <h4><i class="bi bi-bar-chart-steps me-2 text-primary"></i>Estatísticas Avançadas (Top 10)</h4>
      <div class="d-flex align-items-center gap-3">
        <div class="period-group">
          <span style="font-size:.72rem;color:var(--muted);margin-right:4px">Período fixo: Últimas 12h</span>
        </div>
        <button class="refresh-btn text-primary" onclick="loadAdvancedStats()">
          <i class="bi bi-arrow-clockwise"></i> Atualizar
        </button>
      </div>
    </div>
    
    <div class="row g-3 mb-4">
      <div class="col-md-4">
        <div class="chart-card">
          <div class="chart-title"><i class="bi bi-globe me-2 text-success"></i>Top Domínios Resolvidos</div>
          <div id="list-top-domains" class="mt-3"></div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="chart-card">
          <div class="chart-title"><i class="bi bi-exclamation-triangle me-2 text-danger"></i>Top SERVFAIL</div>
          <div id="list-top-servfail" class="mt-3"></div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="chart-card">
          <div class="chart-title"><i class="bi bi-pc-display me-2 text-info"></i>Top IPs Clientes</div>
          <div id="list-top-ips" class="mt-3"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- LOGS -->
  <div id="page-logs" class="page">
    <div class="topbar">
      <h4><i class="bi bi-terminal me-2"></i>Logs em Tempo Real <span class="live-dot ms-1" style="display:none" id="log-live-dot"></span></h4>
      <div class="d-flex align-items-center gap-2">
        <input type="text" id="log-ip-filter" class="form-control form-control-sm" placeholder="Digite um IP..." style="width: 150px; border-color:var(--border); background:var(--card); color:var(--text)" onkeydown="if(event.key==='Enter')startLogs()"/>
        <button class="refresh-btn text-primary" onclick="startLogs()"><i class="bi bi-funnel"></i> Filtrar</button>
        <button class="refresh-btn" onclick="clearLogs()"><i class="bi bi-trash"></i> Limpar</button>
        <button class="refresh-btn" id="btn-pause" onclick="togglePause()"><i class="bi bi-pause-fill"></i> Pausar</button>
      </div>
    </div>
    <div id="log-box">
      <div id="log-msg-default" style="color:var(--muted);text-align:center;padding:40px;font-size:0.9rem;">
        <i class="bi bi-funnel" style="font-size:2rem;display:block;margin-bottom:10px;"></i>
        Digite um endereço de IP acima e clique em Filtrar para iniciar o monitoramento ao vivo.
      </div>
    </div>
  </div>
</div>

<div class="toast-container"><div id="toast" class="toast align-items-center text-white border-0" role="alert"><div class="d-flex"><div class="toast-body" id="toast-msg"></div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div></div></div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
// Theme
function toggleTheme() {
  const isDark = document.body.getAttribute('data-theme') === 'dark';
  const newTheme = isDark ? 'light' : 'dark';
  document.body.setAttribute('data-theme', newTheme);
  localStorage.setItem('theme', newTheme);
  document.getElementById('theme-icon').className = newTheme === 'dark' ? 'bi bi-sun-fill' : 'bi bi-moon-fill';
}
// Init Theme
const savedTheme = localStorage.getItem('theme') || 'light';
if(savedTheme === 'dark') {
  document.body.setAttribute('data-theme', 'dark');
  document.getElementById('theme-icon').className = 'bi bi-sun-fill';
}

// Nav
function showPage(name,el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  el.classList.add('active');
  if(name==='dashboard')loadAll();
  if(name==='blocklist')loadBlocklist();
  if(name==='advanced')loadAdvancedStats();
}
function showToast(msg,ok=true){
  const t=document.getElementById('toast');
  t.className='toast align-items-center text-white border-0 '+(ok?'bg-success':'bg-danger');
  document.getElementById('toast-msg').textContent=msg;
  new bootstrap.Toast(t,{delay:3000}).show();
}
function fmt(n){return Number(n).toLocaleString('pt-BR');}

// Charts - Paleta Elevate (roxos + cores semânticas)
const PALETTE={
  primary:'#6a1e9c',
  primaryDark:'#282362',
  lavender:'#9d59ca',
  lavenderLight:'#c596e8',
  indigo:'#4b42ad',
  deepPurple:'#1c1836',
  success:'#10b981',
  danger:'#ef4444',
  warning:'#f59e0b',
  cyan:'#06b6d4',
};
let charts={};
function chartColors(){
  const dark=document.body.getAttribute('data-theme')==='dark';
  return {
    text: dark?'#a89dc4':'#6b6783',
    grid: dark?'rgba(167,139,250,.08)':'rgba(124,58,237,.08)',
  };
}
function chartOptions(){
  const c=chartColors();
  return {
    responsive:true,maintainAspectRatio:false,animation:false,
    plugins:{legend:{labels:{color:c.text,font:{size:11,family:'Inter'},boxWidth:12}}},
    scales:{
      x:{ticks:{color:c.text,font:{size:10,family:'Inter'},maxTicksLimit:10},grid:{color:c.grid}},
      y:{ticks:{color:c.text,font:{size:10,family:'Inter'}},grid:{color:c.grid}}
    }
  };
}
function makeChart(id,type,data,opts={}){
  if(charts[id])charts[id].destroy();
  charts[id]=new Chart(document.getElementById(id),{type,data,options:{...chartOptions(),...opts}});
}

// Periodos
const POINTS_PER_HOUR = 120; // historico a cada 30s
let cachePeriod=1, respPeriod=1, rtPeriod=0, dnssecPeriod=1;
function setPeriod(h,el){
  cachePeriod=h;
  el.parentNode.querySelectorAll('.period-btn').forEach(b=>b.classList.remove('active'));
  el.classList.add('active');
  loadHistory();
}
function setRespPeriod(h,el){
  respPeriod=h;
  el.parentNode.querySelectorAll('.period-btn').forEach(b=>b.classList.remove('active'));
  el.classList.add('active');
  loadHistory();
}
function setDnssecPeriod(h,el){
  dnssecPeriod=h;
  el.parentNode.querySelectorAll('.period-btn').forEach(b=>b.classList.remove('active'));
  el.classList.add('active');
  loadHistory();
}
function setRtPeriod(h,el){
  rtPeriod=h;
  el.parentNode.querySelectorAll('.period-btn').forEach(b=>b.classList.remove('active'));
  el.classList.add('active');
  if(h>0) loadHistory();
  else renderRtChart(rtLabels, rtDataTotal, rtDataA, rtDataAAAA, rtDataCNAME, rtDataServfail);
}
function renderRtChart(labels, total, a, aaaa, cname, sf) {
  if(charts['chart-realtime']){
    charts['chart-realtime'].data.labels=labels;
    charts['chart-realtime'].data.datasets[0].data=total;
    charts['chart-realtime'].data.datasets[1].data=a;
    charts['chart-realtime'].data.datasets[2].data=aaaa;
    charts['chart-realtime'].data.datasets[3].data=cname;
    charts['chart-realtime'].data.datasets[4].data=sf;
    charts['chart-realtime'].update(rtPeriod===0?{duration:0}:undefined);
  } else {
    makeChart('chart-realtime','line',{
      labels:labels,
      datasets:[
        {label:'Total QPS',data:total,borderColor:PALETTE.primary,tension:.4,pointRadius:0,borderWidth:2.5},
        {label:'A QPS',data:a,borderColor:PALETTE.indigo,tension:.4,pointRadius:0,borderWidth:1.5},
        {label:'AAAA QPS',data:aaaa,borderColor:PALETTE.warning,tension:.4,pointRadius:0,borderWidth:1.5},
        {label:'CNAME QPS',data:cname,borderColor:PALETTE.lavender,tension:.4,pointRadius:0,borderWidth:1.5},
        {label:'SERVFAIL',data:sf,borderColor:PALETTE.danger,tension:.4,pointRadius:0,borderWidth:1.5}
      ]
    },{animation:{duration:0}});
  }
}

// Realtime globals
let rtLabels=Array(60).fill('');let rtDataTotal=Array(60).fill(0);let rtDataA=Array(60).fill(0);
let rtDataAAAA=Array(60).fill(0);let rtDataCNAME=Array(60).fill(0);let rtDataServfail=Array(60).fill(0);
let lastStats=null;let lastStatsTs=0;

// Stats
async function loadStats(){
  try{
    const r=await fetch('/api/stats');
    const d=await r.json();
    const badge=document.getElementById('status-badge');
    if(d.status==='active'){badge.className='badge-status badge-active';badge.innerHTML='<span class="dot dot-green"></span> Unbound Ativo (Uptime: '+d.uptime+')';}
    else{badge.className='badge-status badge-inactive';badge.innerHTML='<span class="dot dot-red"></span> Unbound Inativo';}

    // System Metrics
    document.getElementById('m-sys-cpu').textContent=d.sys_cpu+'%';
    document.getElementById('m-sys-cpu-bar').firstChild.style.width=d.sys_cpu+'%';
    document.getElementById('m-sys-cpu-bar').firstChild.style.background=d.sys_cpu>85?'var(--danger)':(d.sys_cpu>60?'var(--warning)':'var(--success)');
    document.getElementById('m-sys-mem').textContent=d.sys_mem+'%';
    document.getElementById('m-sys-mem-bar').firstChild.style.width=d.sys_mem+'%';
    document.getElementById('m-sys-mem-bar').firstChild.style.background=d.sys_mem>85?'var(--danger)':(d.sys_mem>60?'var(--warning)':'var(--success)');
    document.getElementById('m-sys-disk').textContent=d.sys_disk+'%';
    document.getElementById('m-sys-disk-bar').firstChild.style.width=d.sys_disk+'%';
    document.getElementById('m-sys-disk-bar').firstChild.style.background=d.sys_disk>85?'var(--danger)':(d.sys_disk>60?'var(--warning)':'var(--success)');

    const qt=d.qtypes||{};
    // DNS Totals
    document.getElementById('m-tot-q').textContent=fmt(d.queries);
    document.getElementById('m-tot-a').textContent=fmt(qt['A']||0);
    document.getElementById('m-tot-aaaa').textContent=fmt(qt['AAAA']||0);
    document.getElementById('m-tot-cname').textContent=fmt(qt['CNAME']||0);
    document.getElementById('m-tot-servfail').textContent=fmt(d.servfail||0);
    document.getElementById('m-tot-hits').textContent=fmt(d.cachehits||0);

    // Realtime chart
    const now = performance.now();
    if(lastStats){
       const elapsed = (now - lastStatsTs) / 1000;
       if(elapsed > 0){
           const dq = Math.max(0, d.queries - lastStats.queries) / elapsed;
           const da = Math.max(0, (qt['A']||0) - ((lastStats.qtypes||{})['A']||0)) / elapsed;
           const daaaa = Math.max(0, (qt['AAAA']||0) - ((lastStats.qtypes||{})['AAAA']||0)) / elapsed;
           const dcname = Math.max(0, (qt['CNAME']||0) - ((lastStats.qtypes||{})['CNAME']||0)) / elapsed;
           const dsf = Math.max(0, (d.servfail||0) - (lastStats.servfail||0)) / elapsed;

           const dt = new Date();
           rtLabels.push(dt.getHours().toString().padStart(2,'0')+':'+dt.getMinutes().toString().padStart(2,'0')+':'+dt.getSeconds().toString().padStart(2,'0'));
           rtLabels.shift();
           rtDataTotal.push(dq.toFixed(1)); rtDataTotal.shift();
           rtDataA.push(da.toFixed(1)); rtDataA.shift();
           rtDataAAAA.push(daaaa.toFixed(1)); rtDataAAAA.shift();
           rtDataCNAME.push(dcname.toFixed(1)); rtDataCNAME.shift();
           rtDataServfail.push(dsf.toFixed(1)); rtDataServfail.shift();

           if(rtPeriod===0) renderRtChart(rtLabels, rtDataTotal, rtDataA, rtDataAAAA, rtDataCNAME, rtDataServfail);
       }
    }
    lastStats = d;
    lastStatsTs = now;

    // Critical Metrics Update
    document.getElementById('m-qps').textContent=d.qps;
    document.getElementById('m-resp').textContent=d.resp_avg+' ms';
    document.getElementById('m-resp-sub').textContent='média | mediana: '+d.resp_med+' ms';
    document.getElementById('m-hitrate').textContent=d.hit_rate+'%';
    document.getElementById('m-hitrate-sub').textContent='hits: '+fmt(d.cachehits)+' | miss: '+fmt(d.cachemiss);
    document.getElementById('m-reqavg').textContent=d.requestlist_avg;
    document.getElementById('m-reqavg-sub').textContent='max: '+fmt(d.requestlist_max);
    const dt2=d.dnssec_ok+d.dnssec_bad;
    const dp=dt2>0?((d.dnssec_ok/dt2)*100).toFixed(1):'0.0';
    document.getElementById('m-dnssec').textContent=dp+'%';
    document.getElementById('m-dnssec-sub').textContent='validados: '+fmt(d.dnssec_ok)+' | inválidos: '+d.dnssec_bad;
    document.getElementById('m-prefetch').textContent=fmt(d.prefetch);
    document.getElementById('m-prefetch-sub').textContent='RRsets: '+fmt(d.rrsets)+' | Mensagens: '+fmt(d.messages);
    document.getElementById('m-unwanted').textContent=fmt(d.unwanted_queries);
    document.getElementById('m-unwanted-sub').textContent='respostas: '+fmt(d.unwanted_replies);

    // Tipos de consulta
    const ql=Object.keys(qt).filter(k=>qt[k]>0).sort((a,b)=>qt[b]-qt[a]).slice(0,8);
    if(ql.length>0){
      makeChart('chart-qtypes','bar',{
        labels:ql,
        datasets:[{data:ql.map(k=>qt[k]),backgroundColor:[PALETTE.primary,PALETTE.lavender,PALETTE.indigo,PALETTE.deepPurple,PALETTE.success,PALETTE.warning,PALETTE.cyan,PALETTE.danger],borderRadius:5,borderWidth:0}]
      },{plugins:{legend:{display:false}}});
    }
  }catch(e){console.error('stats error:',e);}
}

// History
async function loadHistory(){
  try{
    const maxH=Math.max(cachePeriod,respPeriod,rtPeriod,dnssecPeriod);
    const r=await fetch('/api/history?hours='+maxH);
    const h=await r.json();
    const pph=h.points_per_hour||POINTS_PER_HOUR;

    const cachePoints=cachePeriod*pph;
    const respPoints=respPeriod*pph;
    const dnssecPoints=dnssecPeriod*pph;
    const ts=h.timestamps;
    const tsLen=ts.length;

    const cacheTs=ts.slice(-Math.min(cachePoints,tsLen));
    const cacheCh=h.cachehits.slice(-Math.min(cachePoints,tsLen));
    const cacheCm=h.cachemiss.slice(-Math.min(cachePoints,tsLen));
    const cacheQps=h.qps.slice(-Math.min(cachePoints,tsLen));

    const respTs=ts.slice(-Math.min(respPoints,tsLen));
    const respAvg=h.resp_avg.slice(-Math.min(respPoints,tsLen));
    const respMed=h.resp_med.slice(-Math.min(respPoints,tsLen));

    const dnssecTs=ts.slice(-Math.min(dnssecPoints,tsLen));
    const dnssecOk=h.dnssec_ok.slice(-Math.min(dnssecPoints,tsLen));
    const dnssecBad=h.dnssec_bad.slice(-Math.min(dnssecPoints,tsLen));

    makeChart('chart-cache','line',{
      labels:cacheTs,
      datasets:[
        {label:'Consultas/s',data:cacheQps,borderColor:PALETTE.primary,backgroundColor:'rgba(124,58,237,.06)',tension:.4,fill:false,pointRadius:0,borderWidth:1.8},
        {label:'Cache Hits',data:cacheCh,borderColor:PALETTE.success,backgroundColor:'rgba(16,185,129,.1)',tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
        {label:'Cache Miss',data:cacheCm,borderColor:PALETTE.danger,backgroundColor:'rgba(239,68,68,.08)',tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
      ]
    });

    makeChart('chart-resp','line',{
      labels:respTs,
      datasets:[
        {label:'Médio (ms)',data:respAvg,borderColor:PALETTE.primary,backgroundColor:'rgba(124,58,237,.08)',tension:.4,fill:false,pointRadius:0,borderWidth:1.8},
        {label:'Mediano (ms)',data:respMed,borderColor:PALETTE.lavender,backgroundColor:'rgba(167,139,250,.08)',tension:.4,fill:false,pointRadius:0,borderWidth:1.5},
      ]
    });

    makeChart('chart-dnssec','line',{
      labels:dnssecTs,
      datasets:[
        {label:'Validados',data:dnssecOk,borderColor:PALETTE.success,backgroundColor:'rgba(16,185,129,.1)',tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
        {label:'Inválidos',data:dnssecBad,borderColor:PALETTE.danger,backgroundColor:'rgba(239,68,68,.08)',tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
      ]
    });

    if(rtPeriod>0){
      const rtPoints=rtPeriod*pph;
      const rts=ts.slice(-Math.min(rtPoints,tsLen));
      const rqps=h.qps.slice(-Math.min(rtPoints,tsLen));
      const ra=h.qps_a.slice(-Math.min(rtPoints,tsLen));
      const raaaa=h.qps_aaaa.slice(-Math.min(rtPoints,tsLen));
      const rcname=h.qps_cname.slice(-Math.min(rtPoints,tsLen));
      const rsf=h.qps_servfail.slice(-Math.min(rtPoints,tsLen));
      renderRtChart(rts, rqps, ra, raaaa, rcname, rsf);
    }

  }catch(e){console.error('history error:',e);}
}

async function loadBlockedCount(){
  const r=await fetch('/api/blocklist');
  const d=await r.json();
  document.getElementById('m-blocked').textContent=fmt(d.total);
}

function loadAll(){loadStats();loadHistory();loadBlockedCount();}

// Blocklist
async function loadBlocklist(){
  const r=await fetch('/api/blocklist');const d=await r.json();
  document.getElementById('block-count').textContent=fmt(d.total)+' domínios';
  document.getElementById('sync-time').textContent='Última: '+d.last_sync;
  renderDomains();
}
let searchTimeout;
function renderDomains(){
  const q=document.getElementById('search-domain').value.toLowerCase().trim();
  const list=document.getElementById('domain-list');
  
  if(!q || q.length < 3){
    list.innerHTML='<p style="color:var(--muted);text-align:center;padding:16px">Digite ao menos 3 caracteres para buscar um domínio.</p>';
    return;
  }
  
  list.innerHTML='<p style="color:var(--muted);text-align:center;padding:16px"><i class="bi bi-arrow-repeat spin"></i> Buscando...</p>';
  
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(async () => {
    try {
      const r = await fetch('/api/blocklist?q=' + encodeURIComponent(q));
      const d = await r.json();
      if(!d.domains.length){
        list.innerHTML='<p style="color:var(--muted);text-align:center;padding:16px">Nenhum domínio encontrado.</p>';
        return;
      }
      list.innerHTML=d.domains.map(dom=>`<span class="domain-tag"><i class="bi bi-slash-circle" style="color:var(--danger)"></i>${dom}<span class="del" onclick="deleteDomain('${dom}')"><i class="bi bi-x-lg"></i></span></span>`).join('');
      if(d.domains.length === 100){
        list.innerHTML += '<p style="color:var(--muted);text-align:center;padding:16px;font-size:0.8rem;">Exibindo os primeiros 100 resultados. Refine sua busca.</p>';
      }
    } catch(e) {
      list.innerHTML='<p style="color:var(--danger);text-align:center;padding:16px">Erro na busca.</p>';
    }
  }, 300);
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
async function clearAllBlocks(){
  if(!confirm('Atenção: Isso removerá TODOS os domínios bloqueados. Tem certeza?')) return;
  const r=await fetch('/api/blocklist/clear_all',{method:'POST'});
  if(!r.ok){showToast('Erro ao limpar a lista',false);return;}
  showToast('Todos os bloqueios foram removidos com sucesso.');
  document.getElementById('search-domain').value = '';
  loadBlocklist();
  loadBlockedCount();
}
async function syncBotnet(){
  const btn=document.getElementById('btn-sync');
  const icon=btn.innerHTML;
  btn.innerHTML='<i class="bi bi-arrow-repeat spin"></i> Sincronizando...';
  btn.disabled=true;
  try{
    const r=await fetch('/api/blocklist/sync_botnet',{method:'POST'});
    const d=await r.json();
    if(!r.ok) showToast(d.error||'Erro na sincronização',false);
    else{ showToast(`Sincronizado! ${fmt(d.added)} novos de ${fmt(d.total)} total.`); loadBlocklist(); loadBlockedCount(); }
  }catch(e){showToast('Erro na requisição: '+e,false);}
  btn.innerHTML=icon;
  btn.disabled=false;
}

// Advanced Stats
async function loadAdvancedStats(){
  const lists = ['domains', 'servfail', 'ips'];
  lists.forEach(l => {
    document.getElementById('list-top-'+l).innerHTML = '<p style="color:var(--muted);text-align:center;padding:16px"><i class="bi bi-arrow-repeat spin"></i> Carregando...</p>';
  });
  
  try {
    const r = await fetch('/api/stats/advanced');
    const d = await r.json();
    if(!r.ok) throw new Error(d.error || 'Erro desconhecido');
    
    function renderList(targetId, data) {
      const list = document.getElementById(targetId);
      if(!data || !data.length){
        list.innerHTML = '<p style="color:var(--muted);font-size:0.85rem;text-align:center;">Nenhum dado encontrado nos logs recentes.</p>';
        return;
      }
      let html = '<div style="display:flex;flex-direction:column;gap:8px;">';
      const maxCount = data[0].count;
      data.forEach((item, idx) => {
        const pct = Math.max(5, Math.round((item.count / maxCount) * 100));
        html += `
          <div style="display:flex;flex-direction:column;gap:4px;">
            <div style="display:flex;justify-content:space-between;font-size:0.8rem;color:var(--text);">
              <span style="font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:70%;" title="${item.name}">${idx+1}. ${item.name}</span>
              <span style="color:var(--muted);">${fmt(item.count)}</span>
            </div>
            <div style="height:6px;background:var(--border);border-radius:3px;overflow:hidden;">
              <div style="width:${pct}%;height:100%;background:var(--primary);border-radius:3px;"></div>
            </div>
          </div>
        `;
      });
      html += '</div>';
      list.innerHTML = html;
    }
    
    renderList('list-top-domains', d.top_domains);
    renderList('list-top-servfail', d.top_servfail);
    renderList('list-top-ips', d.top_ips);
  } catch(e) {
    lists.forEach(l => {
      document.getElementById('list-top-'+l).innerHTML = '<p style="color:var(--danger);text-align:center;font-size:0.85rem;">Erro ao carregar dados.<br><small style="color:var(--muted);">Verifique se "log-queries: yes" está ativo no unbound.conf.</small></p>';
    });
  }
}

// Logs
let logPaused=false,logSource=null;
function startLogs(){
  const ip=document.getElementById('log-ip-filter').value.trim();
  const box=document.getElementById('log-box');
  if(!ip){
    showToast('Por favor, informe um IP de origem para visualizar os logs.', false);
    return;
  }
  
  if(logSource){ logSource.close(); logSource=null; }
  
  document.getElementById('log-live-dot').style.display='inline-block';
  box.innerHTML='';
  logSource=new EventSource('/api/logs/stream?ip=' + encodeURIComponent(ip));
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
function clearLogs(){
  if(logSource){ logSource.close(); logSource=null; }
  document.getElementById('log-live-dot').style.display='none';
  document.getElementById('log-ip-filter').value = '';
  document.getElementById('log-box').innerHTML = `
    <div id="log-msg-default" style="color:var(--muted);text-align:center;padding:40px;font-size:0.9rem;">
      <i class="bi bi-funnel" style="font-size:2rem;display:block;margin-bottom:10px;"></i>
      Digite um endereço de IP acima e clique em Filtrar para iniciar o monitoramento ao vivo.
    </div>
  `;
}
function togglePause(){
  logPaused=!logPaused;
  document.getElementById('btn-pause').innerHTML=logPaused?'<i class="bi bi-play-fill"></i> Retomar':'<i class="bi bi-pause-fill"></i> Pausar';
}

// Init: stats a cada 5s, history a cada 30s
loadAll();
setInterval(loadStats,5000);
setInterval(loadHistory,30000);
setInterval(loadBlockedCount,30000);
</script>
</body>
</html>"""

@app.route("/")
def index():
    return HTML

if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False)
