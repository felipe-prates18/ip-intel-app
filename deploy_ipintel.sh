#!/usr/bin/env bash
set -euo pipefail

# ============================
# ASPER IP Intelligence - Deploy helper
# ============================

# ---- Config padrão (ajuste se precisar) ----
APP_DIR="${APP_DIR:-/opt/ip-intel-app}"
VENV_DIR="${VENV_DIR:-$APP_DIR/venv}"
SERVICE_NAME="${SERVICE_NAME:-ipintel}"
NGINX_SITE="${NGINX_SITE:-/etc/nginx/sites-available/ipintel}"  # opcional
PY_REQ="${PY_REQ:-$APP_DIR/requirements.txt}"
ENV_FILE="${ENV_FILE:-$APP_DIR/.env}"

# Flags
RELOAD_NGINX="${RELOAD_NGINX:-auto}"   # auto|yes|no
SHOW_LOGS="${SHOW_LOGS:-yes}"          # yes|no
GIT_PULL="${GIT_PULL:-auto}"           # auto|yes|no

# ---- Helpers ----
ok(){   echo -e "\e[32m[OK]\e[0m $*"; }
inf(){  echo -e "\e[34m[INFO]\e[0m $*"; }
wrn(){  echo -e "\e[33m[WARN]\e[0m $*"; }
err(){  echo -e "\e[31m[ERR]\e[0m $*"; }
die(){  err "$*"; exit 1; }

require_root(){
  if [[ $EUID -ne 0 ]]; then
    die "Execute como root: sudo $0"
  fi
}

backup_files(){
  local ts; ts="$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$APP_DIR/.backups/$ts"
  for f in main.py index.html; do
    [[ -f "$APP_DIR/$f" ]] && cp -a "$APP_DIR/$f" "$APP_DIR/.backups/$ts/" || true
  done
  ok "Backup leve criado em $APP_DIR/.backups/$ts"
}

maybe_git_pull(){
  if [[ "$GIT_PULL" == "no" ]]; then
    inf "Pulando git pull (GIT_PULL=no)."
    return
  fi
  if [[ -d "$APP_DIR/.git" ]]; then
    inf "Repositório git detectado; atualizando..."
    pushd "$APP_DIR" >/dev/null
      git fetch --all -p
      git pull --ff-only
    popd >/dev/null
    ok "Código atualizado via git."
  else
    if [[ "$GIT_PULL" == "yes" ]]; then
      die "GIT_PULL=yes mas $APP_DIR não é repo git."
    fi
    wrn "Sem .git em $APP_DIR — nada a puxar (arquivos locais)."
  fi
}

ensure_venv_and_deps(){
  if [[ ! -d "$VENV_DIR" ]]; then
    inf "Criando venv em $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
  fi
  # shellcheck disable=SC1090
  source "$VENV_DIR/bin/activate"
  pip install --upgrade pip >/dev/null
  if [[ -f "$PY_REQ" ]]; then
    inf "Instalando dependências de $PY_REQ ..."
    pip install -r "$PY_REQ"
  else
    wrn "requirements.txt não encontrado; instalando básicos."
    pip install fastapi "uvicorn[standard]" httpx pydantic pydantic-settings gunicorn
  fi
  deactivate
  ok "Ambiente Python pronto."
}

fix_permissions(){
  if [[ -f "$ENV_FILE" ]]; then
    chown www-data:www-data "$ENV_FILE" || true
    chmod 600 "$ENV_FILE" || true
  fi
  if [[ -d "$APP_DIR/static" ]]; then
    chown -R root:www-data "$APP_DIR/static" || true
    chmod -R 750 "$APP_DIR/static" || true
  fi
  chown -R root:www-data "$APP_DIR"
  chmod -R 750 "$APP_DIR"
  ok "Permissões ajustadas."
}

restart_service(){
  inf "Reiniciando serviço $SERVICE_NAME ..."
  systemctl daemon-reload
  systemctl restart "$SERVICE_NAME"
  sleep 1
  systemctl --no-pager --full status "$SERVICE_NAME" || true
}

maybe_reload_nginx(){
  if [[ "$RELOAD_NGINX" == "no" ]]; then
    inf "Pulando Nginx (RELOAD_NGINX=no)."
    return
  fi
  if [[ -f "$NGINX_SITE" ]]; then
    inf "Validando configuração do Nginx ..."
    nginx -t
    systemctl reload nginx
    ok "Nginx recarregado."
  else
    if [[ "$RELOAD_NGINX" == "yes" ]]; then
      die "RELOAD_NGINX=yes, mas arquivo $NGINX_SITE não existe."
    fi
    wrn "Config do Nginx não encontrada em $NGINX_SITE — ignorando."
  fi
}

tail_logs(){
  if [[ "$SHOW_LOGS" == "yes" ]]; then
    echo
    inf "Logs recentes do serviço (CTRL+C para sair):"
    journalctl -u "$SERVICE_NAME" -n 50 -f
  else
    inf "SHOW_LOGS=no — não exibindo logs."
  fi
}

main(){
  require_root
  [[ -d "$APP_DIR" ]] || die "Diretório $APP_DIR não existe."

  backup_files
  maybe_git_pull
  ensure_venv_and_deps
  fix_permissions
  restart_service
  maybe_reload_nginx
  tail_logs
}

main "$@"
