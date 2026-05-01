# 🛡️ Unbound DNS Web Interface

Interface web leve para monitoramento e gerenciamento do servidor DNS [Unbound](https://nlnetlabs.nl/projects/unbound/about/), construída com Python + Flask.

## ✨ Funcionalidades

- 📊 **Estatísticas em tempo real** — consultas, cache hit/miss, prefetch, threads
- 🚫 **Gerenciamento de bloqueios** — bloqueie e desbloqueie domínios com um clique
- 📜 **Logs ao vivo** — streaming em tempo real do log do Unbound com pause/resume

## 🖥️ Requisitos

- Debian 12 (ou derivado)
- Python 3.11+
- Unbound instalado e rodando
- `unbound-control` configurado e funcional
- Usuário com permissão de leitura nos arquivos do Unbound

## 🚀 Instalação

### 1. Clone o repositório

```bash
git clone https://github.com/SEU_USUARIO/unbound-web.git /opt/unbound-web
cd /opt/unbound-web
```

### 2. Crie o ambiente virtual e instale dependências

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

### 3. Configure o arquivo de blocklist no Unbound

```bash
touch /etc/unbound/blocklist.conf

# Adicione ao unbound.conf (se ainda não existir)
grep -q "blocklist.conf" /etc/unbound/unbound.conf || \
  echo 'include: "/etc/unbound/blocklist.conf"' >> /etc/unbound/unbound.conf

chmod 664 /etc/unbound/blocklist.conf
```

### 4. Ajuste as variáveis de ambiente (opcional)

Copie e edite o arquivo de configuração:

```bash
cp .env.example .env
nano .env
```

### 5. Instale como serviço systemd

```bash
cp unbound-web.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now unbound-web
systemctl status unbound-web
```

### 6. Acesse no navegador

```
http://IP-DO-SERVIDOR:8080
```

## ⚙️ Configuração

As configurações ficam no arquivo `.env`:

| Variável | Padrão | Descrição |
|---|---|---|
| `BLOCKLIST_FILE` | `/etc/unbound/blocklist.conf` | Caminho do arquivo de bloqueios |
| `LOG_FILE` | `/var/log/unbound/unbound.log` | Caminho do log do Unbound |
| `PORT` | `8080` | Porta da interface web |
| `HOST` | `0.0.0.0` | Interface de rede |

## 📁 Estrutura do Projeto

```
unbound-web/
├── app.py                  # Aplicação principal (Flask)
├── requirements.txt        # Dependências Python
├── unbound-web.service     # Unit file para systemd
├── .env.example            # Exemplo de configuração
├── .gitignore
└── README.md
```

## 🔒 Segurança

> ⚠️ Esta interface **não possui autenticação** por padrão. Recomenda-se:
> - Expor apenas em rede interna/VPN
> - Usar um reverse proxy (Nginx/Caddy) com autenticação básica
> - Configurar firewall para restringir acesso à porta 8080

Exemplo de bloqueio via `iptables`:

```bash
# Permitir apenas sua rede interna
iptables -A INPUT -p tcp --dport 8080 -s 192.168.0.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP
```

## 📄 Licença

MIT License — veja o arquivo [LICENSE](LICENSE) para detalhes.
