#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# IP Reputation Aggregator - Setup HTTPS (Nginx 443)
# Modes:
#  A) Local (127.0.0.1) via mkcert (dev)
#  B) Public IP via self-signed cert with SAN (prod-ish)
# ==========================================================

# -----------------------------
# Config defaults (editable)
# -----------------------------
APP_DIR="${APP_DIR:-/opt/ip-intel-app}"
VENV_DIR="${VENV_DIR:-$APP_DIR/venv}"
SERVICE_NAME="${SERVICE_NAME:-ipintel}"
BIND_ADDR="${BIND_ADDR:-127.0.0.1}"
APP_PORT="${APP_PORT:-8000}"
NGINX_SITE_NAME="${NGINX_SITE_NAME:-ipintel}"
SSL_DIR="${SSL_DIR:-/etc/ssl/ipintel}"
SYSTEM_USER="${SYSTEM_USER:-www-data}"
SYSTEM_GROUP="${SYSTEM_GROUP:-www-data}"

# Colors
ok()  { echo -e "\e[32m[OK]\e[0m $*"; }
inf() { echo -e "\e[34m[INFO]\e[0m $*"; }
wrn() { echo -e "\e[33m[WARN]\e[0m $*"; }
err() { echo -e "\e[31m[ERR]\e[0m $*"; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Execute como root: sudo $0"
    exit 1
  fi
}

detect_os() {
  if [[ -f /etc/debian_version ]]; then
    OS_FAMILY="debian"
  else
    OS_FAMILY="unknown"
  fi
  inf "Sistema detectado: $OS_FAMILY"
}

ensure_packages() {
  inf "Instalando pacotes do sistema..."
  apt update
  DEBIAN_FRONTEND=noninteractive apt install -y python3-venv python3-pip nginx curl ca-certificates openssl git libnss3-tools
  ok "Pacotes instalados."
}

setup_app_env() {
  if [[ ! -d "$APP_DIR" ]]; then
    err "Diretório $APP_DIR não encontrado. Copie seu projeto para lá e rode novamente."
    exit 1
  fi
  inf "Criando virtualenv e instalando dependências..."
  python3 -m venv "$VENV_DIR"
  # shellcheck disable=SC1090
  source "$VENV_DIR/bin/activate"
  if [[ -f "$APP_DIR/requirements.txt" ]]; then
    pip install --upgrade pip
    pip install -r "$APP_DIR/requirements.txt"
  else
    wrn "requirements.txt não encontrado. Instalando dependências básicas."
    pip install fastapi "uvicorn[standard]" httpx pydantic
  fi
  ok "Ambiente Python pronto."
}

create_systemd_service() {
  inf "Criando serviço systemd: $SERVICE_NAME"
  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<SERVICE
[Unit]
Description=IP Intelligence FastAPI Service
After=network.target

[Service]
User=${SYSTEM_USER}
Group=${SYSTEM_GROUP}
WorkingDirectory=${APP_DIR}
Environment=PATH=${VENV_DIR}/bin
ExecStart=${VENV_DIR}/bin/gunicorn -k uvicorn.workers.UvicornWorker main:app --bind ${BIND_ADDR}:${APP_PORT} --workers 4
Restart=always

[Install]
WantedBy=multi-user.target
SERVICE

  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}"
  systemctl --no-pager --full status "${SERVICE_NAME}" || true
  ok "Serviço ${SERVICE_NAME} ativo."
}

mkcert_install() {
  if command -v mkcert >/dev/null 2>&1; then
    ok "mkcert já instalado."
    return
  fi
  inf "Instalando mkcert..."
  local url="https://github.com/FiloSottile/mkcert/releases/latest/download/mkcert-v1.4.4-linux-amd64"
  curl -L "$url" -o /usr/local/bin/mkcert
  chmod +x /usr/local/bin/mkcert
  ok "mkcert instalado."
}

generate_cert_local() {
  inf "Gerando certificado local para 127.0.0.1 (::1) via mkcert..."
  mkcert -install
  mkdir -p "$SSL_DIR"
  mkcert 127.0.0.1 ::1
  # Pega últimos arquivos gerados (nome usa sufixo +N)
  CRT_FILE="$(ls -t 127.0.0.1+*.pem | head -n1)"
  KEY_FILE="${CRT_FILE/.pem/-key.pem}"
  mv "$CRT_FILE" "$SSL_DIR/ip.crt"
  mv "$KEY_FILE" "$SSL_DIR/ip.key"
  chown root:root "$SSL_DIR/ip.crt" "$SSL_DIR/ip.key"
  chmod 600 "$SSL_DIR/ip.key"
  ok "Certificado local criado em $SSL_DIR"
}

generate_cert_self_signed() {
  local SERVER_IP="$1"
  if [[ -z "$SERVER_IP" ]]; then
    err "IP público não informado para certificado autoassinado."
    exit 1
  fi
  inf "Gerando certificado autoassinado (SAN=IP:$SERVER_IP)..."
  mkdir -p "$SSL_DIR"
  cat > /tmp/ipopenssl.cnf <<CONF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
C = BR
ST = SP
L = Sao Paulo
O = Sentrix
CN = ${SERVER_IP}

[req_ext]
subjectAltName = @alt_names

[alt_names]
IP.1 = ${SERVER_IP}
CONF

  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "${SSL_DIR}/ip.key" \
    -out "${SSL_DIR}/ip.crt" \
    -config /tmp/ipopenssl.cnf

  chmod 600 "${SSL_DIR}/ip.key"
  ok "Certificado autoassinado criado em $SSL_DIR (válido 365 dias)."
}

write_nginx_conf() {
  inf "Escrevendo configuração Nginx (${NGINX_SITE_NAME})..."
  cat > "/etc/nginx/sites-available/${NGINX_SITE_NAME}" <<NGX
server {
    listen 443 ssl default_server;
    server_name _;

    ssl_certificate ${SSL_DIR}/ip.crt;
    ssl_certificate_key ${SSL_DIR}/ip.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    # HSTS opcional (comente se for ambiente de testes)
    # add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    location / {
        proxy_pass http://${BIND_ADDR}:${APP_PORT};
        proxy_set_header Host                \$host;
        proxy_set_header X-Real-IP           \$remote_addr;
        proxy_set_header X-Forwarded-For     \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto   \$scheme;
    }
}

server {
    listen 80 default_server;
    server_name _;
    return 301 https://\$host\$request_uri;
}
NGX

  ln -sf "/etc/nginx/sites-available/${NGINX_SITE_NAME}" "/etc/nginx/sites-enabled/${NGINX_SITE_NAME}"
  # Remove default, se existir
  if [[ -e /etc/nginx/sites-enabled/default ]]; then
    rm -f /etc/nginx/sites-enabled/default
  fi

  nginx -t
  systemctl restart nginx
  ok "Nginx configurado e reiniciado."
}

secure_env_file() {
  if [[ -f "$APP_DIR/.env" ]]; then
    inf "Ajustando permissões do .env"
    chown "${SYSTEM_USER}:${SYSTEM_GROUP}" "$APP_DIR/.env" || true
    chmod 600 "$APP_DIR/.env" || true
    ok ".env protegido."
  else
    wrn "Arquivo .env não encontrado em ${APP_DIR}. Lembre-se de criar e preencher suas chaves."
  fi
}

configure_firewall() {
  if command -v ufw >/dev/null 2>&1; then
    inf "Ajustando firewall (UFW) para HTTPS..."
    ufw allow 'Nginx Full' || true
    # Porta do app não precisa estar aberta externamente
    ufw delete allow ${APP_PORT} >/dev/null 2>&1 || true
    ok "Firewall atualizado."
  else
    wrn "UFW não encontrado. Garanta que a porta 443 esteja aberta no seu provedor."
  fi
}

show_summary_local() {
  cat <<TXT

=========================================================
✅ INSTALAÇÃO CONCLUÍDA (MODO LOCAL - mkcert)
---------------------------------------------------------
App (gunicorn):   ${BIND_ADDR}:${APP_PORT}
Nginx (HTTPS):     https://127.0.0.1
Certificados:      ${SSL_DIR}/ip.crt | ${SSL_DIR}/ip.key
Service:           systemctl status ${SERVICE_NAME}

Se acessar de outra máquina, instale a CA do mkcert nessa máquina
ou use o modo IP público (autoassinado).

Logs:
  journalctl -u ${SERVICE_NAME} -f
  tail -f /var/log/nginx/access.log /var/log/nginx/error.log
=========================================================
TXT
}

show_summary_public() {
  local SERVER_IP="$1"
  cat <<TXT

=========================================================
✅ INSTALAÇÃO CONCLUÍDA (IP PÚBLICO - AUTOASSINADO)
---------------------------------------------------------
App (gunicorn):   ${BIND_ADDR}:${APP_PORT}
Nginx (HTTPS):     https://${SERVER_IP}
Certificados:      ${SSL_DIR}/ip.crt | ${SSL_DIR}/ip.key
Service:           systemctl status ${SERVICE_NAME}

Atenção: o navegador exibirá alerta de segurança (cert autoassinado).
Você pode prosseguir ou instalar sua CA interna.

Logs:
  journalctl -u ${SERVICE_NAME} -f
  tail -f /var/log/nginx/access.log /var/log/nginx/error.log
=========================================================
TXT
}

ask_mode() {
  if [[ "${MODE:-}" == "local" ]]; then
    CHOICE="A"
    return
  elif [[ "${MODE:-}" == "public" ]]; then
    CHOICE="B"
    return
  fi

  echo "Selecione o modo de HTTPS por IP:"
  echo "  [A] Local (127.0.0.1) com mkcert (recomendado para DEV)"
  echo "  [B] IP público com certificado autoassinado (SAN=IP)"
  read -rp "Escolha (A/B): " CHOICE
  CHOICE="${CHOICE^^}"
}

main() {
  require_root
  detect_os
  ensure_packages
  setup_app_env
  create_systemd_service
  secure_env_file
  configure_firewall

  ask_mode

  case "$CHOICE" in
    A)
      mkcert_install
      generate_cert_local
      write_nginx_conf
      show_summary_local
      ;;
    B)
      SERVER_IP="${SERVER_IP:-}"
      if [[ -z "$SERVER_IP" ]]; then
        read -rp "Informe o IP público do servidor (ex: 203.0.113.10): " SERVER_IP
      fi
      generate_cert_self_signed "$SERVER_IP"
      write_nginx_conf
      show_summary_public "$SERVER_IP"
      ;;
    *)
      err "Opção inválida. Execute novamente e escolha A ou B."
      exit 1
      ;;
  esac
}

main "$@"
