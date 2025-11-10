# ASPER IP Intel App — Plataforma de Reputação, Análise e Insights de IPs/Domínios

## Visão Geral
A **ASPER IP Intel App** é uma aplicação **web** desenvolvida em **Python (FastAPI)** e **HTML/CSS/JS** para consultas centralizadas de **reputação e informações de IPs e domínios** em múltiplas fontes públicas e privadas de Threat Intelligence.

A nova versão inclui integração opcional com **OpenAI GPT-4-mini**, permitindo a geração automática de **insights analíticos** sobre os resultados coletados, sem alterar o fluxo tradicional de consultas.

## Funcionalidades Principais

| Módulo | Descrição |
|--------|------------|
| **Consulta de IP Único** | Realiza consultas em múltiplas fontes (VirusTotal, AbuseIPDB, IPQualityScore, IPinfo.io, OTX AlienVault). |
| **Consulta de Domínio** | Analisa reputação e dados WHOIS, cruzando informações de diferentes fontes. |
| **Consulta em Lote (CSV/XLSX)** | Permite upload de listas de IPs/Domínios para análise massiva, com pré-visualização e exportação de resultados. |
| **Exportação de Resultados** | Resultados disponíveis em **CSV** e **JSON**, com colunas padronizadas e prontas para integração. |
| **Geração de Insights com IA (opcional)** | Analisa automaticamente os resultados e gera um relatório executivo de risco e recomendações. |
| **Frontend Integrado e Responsivo** | Interface moderna, responsiva e compatível com browsers recentes, utilizando um layout de painel contínuo. |
| **Execução Segura via HTTPS** | Operação em ambiente corporativo com **NGINX** reverso e suporte a certificados SSL válidos. |

## Arquitetura da Aplicação
┌───────────────────────────────┐
│ NGINX (443)                   │
│ ─ Proxy reverso HTTPS         │
│ ─ SSL/TLS + redirecionamento  │
│ ─ Timeout / upload config.    │
└───────────────┬───────────────┘
                │
┌───────────────▼───────────────┐
│ Gunicorn + FastAPI            │
│ ─ Endpoints REST (/api/*)     │
│ ─ Lógica de consultas APIs    │
│ ─ Upload / parse CSV/XLSX     │
│ ─ Exportação de resultados    │
│ ─ Integração com OpenAI       │
└───────────────┬───────────────┘
                │
┌───────────────▼───────────────┐
│ Fontes Externas               │
│ ─ VirusTotal                  │
│ ─ AbuseIPDB                   │
│ ─ IPQualityScore              │
│ ─ IPinfo.io                   │
│ ─ OTX AlienVault              │
│ ─ OpenAI (opcional)           │
└───────────────────────────────┘

/opt/ip-intel-app/
├── venv/ # Ambiente virtual Python
├── main.py # Backend FastAPI (com integração IA)
├── config.py # Configurações e flags (ENABLE_AI)
├── requirements.txt # Dependências
├── static/ # Diretório estático
│ ├── index.html # Frontend principal
│ ├── logo-asper.png # Logo exibida na página
│ ├── favicon.png # Ícone do navegador
│ └── (outros recursos estáticos)
├── .env # Variáveis de ambiente e chaves API
└── README.md # Documentação


## Variáveis de Ambiente (.env)
O arquivo `.env` define as chaves de API e o comportamento da aplicação:

# === CHAVES DE API ===
VT_API_KEY=chave_virustotal
ABUSEIPDB_API_KEY=chave_abuseipdb
OTX_API_KEY=chave_otx
IPQS_API_KEY=chave_ipqualityscore
IPINFO_API_KEY=chave_ipinfo

# === OPENAI (opcional) ===
OPENAI_API_KEY=sua_chave_openai
OPENAI_MODEL=gpt-4o-mini
ENABLE_AI=true   # true = botão visível / false = IA desativada

# === CONFIGURAÇÕES GERAIS ===
REQUEST_TIMEOUT_SECONDS=30
CONNECT_TIMEOUT_SECONDS=10
LOG_LEVEL=info
Se ENABLE_AI=false, o botão “Gerar Insights com IA” não é exibido no frontend, e as rotas /api/insights e /api/ai-status continuam disponíveis, mas retornam mensagens de controle.

# === Instalação no Servidor Linux (Ubuntu/Debian) ===

sudo apt update
sudo apt install -y python3 python3-venv python3-pip nginx git

cd /opt
sudo git clone <seu-repo> ip-intel-app
cd ip-intel-app

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
nano .env

uvicorn main:app --host 0.0.0.0 --port 8000
Upload e Exportação
Upload
Aceita arquivos CSV ou XLSX.

# === Novo parser CSV evita erros de detecção de delimitador. === 

Linhas de cabeçalho são ignoradas automaticamente quando detectadas.

# === Exportação === 
Resultados disponíveis em JSON ou CSV, com as colunas:

type,ip,vt_malicious,vt_suspicious,abuse_score,ipqs_fraud_score,ipqs_proxy,ipqs_vpn,ipqs_tor,city,region,country,otx_pulses,isp,asn,score
Integração de IA
Rotas
Endpoint	Método	Descrição
/api/ai-status	GET	Retorna se o módulo de IA está habilitado.
/api/insights	POST	Recebe o contexto de análise e gera um texto de insights baseado nos dados das fontes.

# === Exemplo de Request ===

curl -X POST https://<host>/api/insights \
  -H "Content-Type: application/json" \
  -d '{"context":{"type":"ip","query":"8.8.8.8","sources":{...}}}'

# === Exemplo de Response === 

{
  "insights": "O endereço IP 8.8.8.8 apresenta baixo risco, sem indicadores de abuso recentes..."
}
Logs e Troubleshooting


journalctl -u ipintel -n 50 --no-pager
tail -n 50 /var/log/nginx/error.log
curl -s -k https://<host>/api/ai-status

# === Segurança Recomendada === 
Permitir apenas portas 22 e 443.

Manter o diretório /opt/ip-intel-app com acesso restrito.

Aplicar permissões 600 no .env para proteger chaves de API.

Configurar HTTPS válido via Nginx (ou autoassinado para ambientes internos).

# === Deploy via systemd + Nginx === 
Arquivo de serviço systemd
Crie /etc/systemd/system/ipintel.service:

[Unit]
Description=ASPER IP Intelligence App
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/ip-intel-app
Environment="PATH=/opt/ip-intel-app/venv/bin"
ExecStart=/opt/ip-intel-app/venv/bin/gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --bind 127.0.0.1:8000
Restart=always

[Install]
WantedBy=multi-user.target

# === Ative e inicie: === 

sudo systemctl daemon-reload
sudo systemctl enable ipintel
sudo systemctl start ipintel

# === Configuração Nginx === 
Arquivo /etc/nginx/sites-available/ipintel:


server {
    listen 80;
    server_name ipintel.local;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name ipintel.local;

    ssl_certificate     /etc/ssl/certs/ipintel.crt;
    ssl_certificate_key /etc/ssl/private/ipintel.key;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    client_max_body_size 50M;
}

# === Ative o site: === 

sudo ln -s /etc/nginx/sites-available/ipintel /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# === Licença === 
Projeto de uso interno da ASPER Cyber Defense, sob licença MIT.

# === Autor === 
Cyber Defense | Detection Engineering
Desenvolvido e mantido por Felipe Prates (Senior Cyber Defense Analyst)
felipe.santos@asper.tec.br
