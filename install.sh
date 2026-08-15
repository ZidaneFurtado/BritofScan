#!/usr/bin/env bash
# ============================================================
#  BritofScan — Script de Instalação para Ubuntu/Debian
#  Uso: sudo bash install.sh
# ============================================================

set -euo pipefail

# ── Cores ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}✔${RESET}  $*"; }
info() { echo -e "${CYAN}→${RESET}  $*"; }
warn() { echo -e "${YELLOW}⚠${RESET}  $*"; }
err()  { echo -e "${RED}✘${RESET}  $*"; }
banner() {
  echo -e "\n${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e "  $*"
  echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"
}

# ── Verificar root ────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  err "Este script precisa de ser executado como root."
  echo "  Usa: sudo bash install.sh"
  exit 1
fi

banner "BritofScan — Instalação de Dependências"

# ── Sistema base ──────────────────────────────────────────────
banner "1/6 · Atualizar sistema"
apt-get update -qq
apt-get install -y -qq \
  curl wget git unzip python3 python3-pip \
  build-essential libpcap-dev libssl-dev \
  ca-certificates gnupg lsb-release
ok "Dependências base instaladas"

# ── Node.js 20 ────────────────────────────────────────────────
banner "2/6 · Node.js 20"
if command -v node &>/dev/null && [[ $(node -v | cut -d. -f1 | tr -d 'v') -ge 20 ]]; then
  ok "Node.js $(node -v) já instalado"
else
  info "A instalar Node.js 20 via NodeSource..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - &>/dev/null
  apt-get install -y -qq nodejs
  ok "Node.js $(node -v) instalado"
fi

# ── Ferramentas de pentest via apt ────────────────────────────
banner "3/6 · Ferramentas de pentest (apt)"

TOOLS_APT=(nmap masscan nikto gobuster dnsrecon)
for tool in "${TOOLS_APT[@]}"; do
  if command -v "$tool" &>/dev/null; then
    ok "$tool já instalado"
  else
    info "A instalar $tool..."
    apt-get install -y -qq "$tool" && ok "$tool instalado" || warn "Falha ao instalar $tool"
  fi
done

# ── theHarvester ──────────────────────────────────────────────
banner "4/6 · theHarvester, Sublist3r, Amass, Nuclei"

# theHarvester
if command -v theHarvester &>/dev/null; then
  ok "theHarvester já instalado"
else
  info "A instalar theHarvester..."
  if apt-get install -y -qq theharvester 2>/dev/null; then
    ok "theHarvester instalado via apt"
  else
    git clone --quiet https://github.com/laramies/theHarvester.git /opt/theHarvester 2>/dev/null || true
    pip3 install -q -r /opt/theHarvester/requirements/base.txt 2>/dev/null || true
    ln -sf /opt/theHarvester/theHarvester.py /usr/local/bin/theHarvester
    ok "theHarvester instalado via git"
  fi
fi

# Sublist3r
if command -v sublist3r &>/dev/null; then
  ok "Sublist3r já instalado"
else
  info "A instalar Sublist3r..."
  git clone --quiet https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r 2>/dev/null || true
  pip3 install -q -r /opt/Sublist3r/requirements.txt 2>/dev/null || true
  ln -sf /opt/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
  chmod +x /usr/local/bin/sublist3r
  ok "Sublist3r instalado"
fi

# Amass
if command -v amass &>/dev/null; then
  ok "Amass já instalado"
else
  info "A instalar Amass..."
  AMASS_VER="v4.2.0"
  AMASS_URL="https://github.com/owasp-amass/amass/releases/download/${AMASS_VER}/amass_linux_amd64.zip"
  wget -q "$AMASS_URL" -O /tmp/amass.zip
  unzip -q /tmp/amass.zip -d /tmp/amass_extract
  mv /tmp/amass_extract/amass_linux_amd64/amass /usr/local/bin/amass
  chmod +x /usr/local/bin/amass
  rm -rf /tmp/amass.zip /tmp/amass_extract
  ok "Amass instalado"
fi

# Nuclei
if command -v nuclei &>/dev/null; then
  ok "Nuclei já instalado"
else
  info "A instalar Nuclei..."
  NUCLEI_VER="v3.2.0"
  NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_3.2.0_linux_amd64.zip"
  wget -q "$NUCLEI_URL" -O /tmp/nuclei.zip
  unzip -q /tmp/nuclei.zip -d /tmp/nuclei_extract
  mv /tmp/nuclei_extract/nuclei /usr/local/bin/nuclei
  chmod +x /usr/local/bin/nuclei
  rm -rf /tmp/nuclei.zip /tmp/nuclei_extract
  nuclei -update-templates &>/dev/null &
  ok "Nuclei instalado (templates a atualizar em background)"
fi

# ── Wordlists SecLists ────────────────────────────────────────
banner "5/6 · Wordlists SecLists"

SECLISTS_DIR="/usr/share/seclists"
if [[ -d "$SECLISTS_DIR" ]]; then
  ok "SecLists já instalado em $SECLISTS_DIR"
else
  info "A instalar SecLists (pode demorar alguns minutos)..."
  if apt-get install -y -qq seclists 2>/dev/null; then
    ok "SecLists instalado via apt"
  else
    mkdir -p "$SECLISTS_DIR"
    git clone --quiet --depth 1 https://github.com/danielmiessler/SecLists.git "$SECLISTS_DIR"
    ok "SecLists instalado via git"
  fi
fi

# Verificar wordlists específicas usadas pelo BritofScan
DIRS_WL="$SECLISTS_DIR/Discovery/Web-Content/raft-medium-directories.txt"
DNS_WL="$SECLISTS_DIR/Discovery/DNS/subdomains-top1million-20000.txt"

[[ -f "$DIRS_WL" ]] && ok "Wordlist diretórios: $DIRS_WL" || warn "Wordlist de diretórios não encontrada: $DIRS_WL"
[[ -f "$DNS_WL"  ]] && ok "Wordlist subdomínios: $DNS_WL"  || warn "Wordlist de subdomínios não encontrada: $DNS_WL"

# ── Dependências Node.js ──────────────────────────────────────
banner "6/6 · Dependências Node.js do BritofScan"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/package.json" ]]; then
  info "A instalar pacotes npm..."
  cd "$SCRIPT_DIR"
  npm install --silent
  ok "Dependências npm instaladas"
else
  warn "package.json não encontrado em $SCRIPT_DIR — executa 'npm install' manualmente"
fi

# ── Configuração .env ─────────────────────────────────────────
if [[ -f "$SCRIPT_DIR/.env" ]]; then
  ok ".env já existe"
else
  if [[ -f "$SCRIPT_DIR/.env.example" ]]; then
    cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
    warn ".env criado a partir do .env.example — configura as variáveis antes de iniciar"
  fi
fi

# ── Sumário final ─────────────────────────────────────────────
banner "Verificação Final"

declare -A TOOL_CHECKS=(
  [nmap]="nmap"
  [masscan]="masscan"
  [gobuster]="gobuster"
  [nikto]="nikto"
  [dnsrecon]="dnsrecon"
  [theHarvester]="theHarvester"
  [sublist3r]="sublist3r"
  [amass]="amass"
  [nuclei]="nuclei"
  [node]="node"
  [npm]="npm"
  [python3]="python3"
)

MISSING=0
for name in "${!TOOL_CHECKS[@]}"; do
  cmd="${TOOL_CHECKS[$name]}"
  if command -v "$cmd" &>/dev/null; then
    ok "$name"
  else
    err "$name — NÃO ENCONTRADO"
    MISSING=$((MISSING + 1))
  fi
done

echo ""
if [[ $MISSING -eq 0 ]]; then
  echo -e "${GREEN}${BOLD}✔ Todas as ferramentas instaladas com sucesso!${RESET}"
else
  echo -e "${YELLOW}${BOLD}⚠ $MISSING ferramenta(s) em falta — verifica acima${RESET}"
fi

echo ""
echo -e "${BOLD}Para iniciar o BritofScan:${RESET}"
echo -e "  ${CYAN}cp .env.example .env${RESET}   ← configura as variáveis"
echo -e "  ${CYAN}npm run dev${RESET}             ← inicia o servidor"
echo -e "  ${CYAN}Abre http://localhost:3001${RESET}"
echo ""
