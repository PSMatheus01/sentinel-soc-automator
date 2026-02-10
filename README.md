<div align="center">

# 🛡️ Sentinel SOC Automator
### Automação de Defesa Cibernética & Resposta a Incidentes (ChatOps)

<!-- BADGES EM LINHA ÚNICA PARA ALINHAMENTO HORIZONTAL -->
<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Wazuh-SIEM-blueviolet?style=for-the-badge&logo=wazuh&logoColor=white" alt="Wazuh" />
  <img src="https://img.shields.io/badge/Docker-Container-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/Telegram-ChatOps-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License" />
</p>

<br>

**Sentinel SOC Automator** é uma Prova de Conceito (POC) de alta fidelidade para automação de triagem e resposta a incidentes de segurança. O sistema integra o **Wazuh SIEM** com uma interface de ChatOps via Telegram.

> ⚡ **Conceito API:** Eu chamo essa abordagem de *"Ação Preventiva Imediata"*.

[Demonstração](#demo) • [Instalação](#install) • [Roadmap](#roadmap)

</div>

---

##  Funcionalidades

| Recurso | Descrição |
| :--- | :--- |
| 📡 **Monitoramento Real-Time** | Captura de eventos críticos via integração direta com sistema de arquivos do Wazuh (*Sidecar Pattern*). |
| 🚨 **Triagem Interativa** | Alertas formatados no Telegram com botões de ação imediata (Inline Keyboards). |
| 🛡️ **Active Response** | Bloqueio de IPs atacantes via Firewall (`iptables`/`nftables`) através da API do Wazuh. |
| 🧠 **Enriquecimento** | Integração com Threat Intelligence (**AbuseIPDB** / **VirusTotal**) para contexto. |
| ⚔️ **Red Team Sim** | Módulo de simulação de ataque integrado para validação de regras de detecção. |

---

##  Arquitetura Técnica

O projeto utiliza uma arquitetura de microsserviços containerizados. Abaixo, o fluxo de dados do sistema:

```
    A[Atacante] -->|Brute Force| B(Servidor Alvo)
    B -->|Log Event| C[Wazuh Manager]
    C -->|Filebeat/Sidecar| D[ Sentinel Bot Python]
    D -->|Enriquecimento| E[VirusTotal/AbuseIPDB]
    D -->|Alerta JSON| F[Telegram Admin]
    F -->|Decisão: BLOQUEAR| D
    D -->|API Trigger| C
    C -->|Active Response| G[Firewall/Block]
    G -.->|Drop Connection| A
```

*   **Wazuh Manager:** Motor de detecção e correlação de eventos.
*   **Sentinel Bot (Python):** Middleware assíncrono que orquestra a comunicação entre o SIEM e a API do Telegram.
*   **Docker-to-Docker Volume Mapping:** Compartilhamento seletivo de logs para processamento de baixo overhead (*Bypass de Indexer*).

---

<a id="demo"></a>
##  Demonstração Prática (Fluxo de Operação)

O Sentinel SOC Automator transforma eventos complexos de segurança em decisões simples.

<div align="center">
<table>
  <tr>
    <td align="center"><b>1. Monitoramento de Saúde</b></td>
    <td align="center"><b>2. Detecção de Intrusão</b></td>
    <td align="center"><b>3. Resposta Ativa</b></td>
  </tr>
  <tr>
    <td align="center"><img src="assets/02 - Status.png" width="250" alt="Status Check"></td>
    <td align="center"><img src="assets/04 - Check.png" width="250" alt="Alerta Detectado"></td>
    <td align="center"><img src="assets/07- Bloqueio.png" width="250" alt="Bloqueio Efetuado"></td>
  </tr>
  <tr>
    <td align="center"><i>Verificação de conectividade com o motor Wazuh.</i></td>
    <td align="center"><i>Alerta de Brute Force com enriquecimento de dados.</i></td>
    <td align="center"><i>IP isolado do sistema após decisão do analista.</i></td>
  </tr>
</table>
</div>

> **Nota:** O modo `🔍 Ver Log Completo` permite uma análise forense detalhada antes da tomada de decisão, reduzindo a incidência de falsos positivos.

---

<a id="install"></a>
##  Instalação e Configuração

### Pré-requisitos
*    Docker & Docker Compose
*    Python 3.11+
*    Token de Bot do Telegram (via `@BotFather`)

### Passo a Passo

**1. Clone o repositório:**
```bash
git clone https://github.com/PSMatheus01/sentinel-soc-automator.git
cd sentinel-soc-automator
```

**2. Configure as variáveis de ambiente:**
```bash
cp .env.example .env
# Edite o arquivo .env com suas chaves de API e IDs do Telegram
```

**3. Inicie a infraestrutura:**
```bash
docker-compose up -d --build
```

**4. Aplique o patch de configuração do Wazuh** (Apenas no primeiro boot):
```bash
python fix_wazuh.py
```

###  Segurança
*   **Whitelist de Acesso:** Apenas IDs de usuários listados no `.env` podem interagir com o bot.
*   **Self-Healing Auth:** Gerenciamento automático de expiração de tokens JWT.

---

<a id="roadmap"></a>
##  Visão de Futuro e Roadmap Profissional

Este projeto foi desenhado para ser a base de um ecossistema de segurança distribuído.

*   [ ] **1. Inteligência Artificial e Resposta Preditiva (AIOps)**
    *   Integração com LLMs (GPT-4/Claude) para análise semântica de logs.
    *   Sugestão automática de remediação baseada no framework MITRE ATT&CK.

*   [ ] **2. Expansão de Infraestrutura (Cloud Native)**
    *   Suporte a clusters Kubernetes (K8s) para monitorar Pods.
    *   Serverless Functions (AWS Lambda) para processamento em escala.

*   [ ] **3. Central de Inteligência de Ameaças (Threat Intel Hub)**
    *   Conexão nativa com Shodan e GreyNoise para *Risk Scoring* dinâmico.

*   [ ] **4. Dashboards de Governança**
    *   Relatórios automáticos de conformidade (LGPD/GDPR) via ELK Stack e Grafana.

---

<div align="center">

**Nota Legal:** *Esta ferramenta foi desenvolvida para fins educacionais e de segurança defensiva. O uso em ambientes de produção deve ser precedido de auditoria de segurança.*

<sub>Desenhado por PSMatheus01</sub>
