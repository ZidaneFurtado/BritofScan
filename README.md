# BritofScan v1.0 — Plataforma Pentest

Projeto de Licenciatura em Informática — Universidade da Maia
Autor: Zidane de Jesus de Brito Furtado (A039908)

## Versão e identificação do pacote

- **Versão do pacote:** 1.0
- **Data de entrega:** 6 de setembro de 2026
- **Correspondência:** este código corresponde integralmente ao relatório final entregue na mesma data, incluindo todas as correções descritas na Secção 4.1 (Casos de Correção Testados) e detalhadas no Anexo A.

## Pré-requisitos e versões testadas

| Componente | Versão testada |
|---|---|
| Node.js | ≥ 18.x (LTS) |
| npm | ≥ 9.x |
| Python | 3.12.3 |
| Nmap | recente (testado com a versão do repositório Ubuntu 24.04) |
| Nikto | recente |
| Nuclei | recente |
| Amass | recente |
| Gobuster | recente |
| TheHarvester | 4.11.1 (**obrigatório** — versões anteriores usam a fonte "bing", descontinuada) |

## Instalação

```bash
# 1. Extrair o pacote e instalar dependências Node.js
npm install

# 2. Instalar ferramentas de sistema (Ubuntu/Debian)
sudo apt install nmap nikto whois dnsrecon curl python3 python3-pip

# 3. Instalar TheHarvester (versão oficial, não via pip genérico)
git clone https://github.com/laramies/theHarvester.git ~/theHarvester
cd ~/theHarvester && pip3 install . --break-system-packages
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc

# 4. Instalar Nuclei, Amass, Gobuster
# (via go install ou binários oficiais de cada projeto — ver documentação oficial)
```

## Configuração

Copia `.env.example` para `.env` e preenche com valores próprios:

```bash
cp .env.example .env
```

```
PORT=3001
HOST=127.0.0.1
JWT_SECRET=<gerar com: openssl rand -hex 32 — obrigatório, a aplicação recusa arrancar sem isto>
FIREBASE_PROJECT_ID=<opcional — integração preparada mas não invocada nesta versão>
FIREBASE_CLIENT_EMAIL=<opcional>
FIREBASE_PRIVATE_KEY=<opcional>
```

## Execução

```bash
npm start
```

A aplicação fica disponível em `http://127.0.0.1:3001` — **por desenho, não acessível a partir de outras máquinas na rede**, coerente com o âmbito estritamente local e laboratorial deste protótipo (ver Secção 4.2 do relatório).




## Estrutura do projeto

```
api/
├── modules/       # Lógica de negócio (fases de scan, scoring, relatórios)
├── routes/        # Endpoints da API REST
├── middleware/    # Autenticação e rate limiting
├── utils/         # Persistência de dados, documentação da API
└── server.js      # Ponto de entrada
frontend/          # Interface web (HTML/CSS/JavaScript)
tests/             # Scripts de validação automatizada
.env.example       # Modelo de configuração (sem valores reais)
```

## Limitações conhecidas

Ver Secção 4.2 (Análise Crítica dos Resultados) do relatório para a lista completa e atualizada de limitações e correções parciais, incluindo isolamento de processos, revalidação de redirecionamentos HTTP, e replay de eventos WebSocket após reconexão.