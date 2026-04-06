# 🔥 NFHACK — NFS Auditing Tool

> **Auditoria, enumeração e exploração de compartilhamentos NFS de forma automatizada e interativa.**

---

## 📌 Visão Geral

O **NFHACK** é uma ferramenta de pentest focada em **detecção e exploração de serviços NFS (Network File System)** em redes locais.

Ela permite:

- Identificar hosts com NFS ativo
- Enumerar compartilhamentos expostos
- Testar permissões (READ / WRITE)
- Analisar riscos automaticamente
- Gerar relatórios 
- Explorar shares via **shell interativa**

---

## ⚡ Features

✔️ Scanner de rede com multithreading  
✔️ Enumeração automática via `showmount`  
✔️ Verificação de permissões (leitura/escrita)  
✔️ Classificação de risco (BAIXO → CRÍTICO)  
✔️ Relatórios automáticos  
✔️ Shell interativa estilo pentest  
✔️ Download de arquivos remotos  
✔️ Logs completos da sessão  

---

## 🧠 Análise Inteligente de Risco

A ferramenta classifica os shares com base em:

- 📂 Paths críticos (`/`, `/root`, `/etc`, etc.)
- 🌐 Acesso aberto (`*`)
- ✍️ Permissão de escrita
- 📖 Permissão de leitura
- 📦 Exposição de dados

### Níveis de risco:

| Nível     | Descrição |
|----------|----------|
| 🔴 CRÍTICO | Acesso a paths sensíveis do sistema |
| 🟣 ALTO    | Subpaths críticos ou acesso aberto |
| 🟡 MÉDIO   | Dados sensíveis ou escrita permitida |
| 🟢 BAIXO   | Baixo impacto |
| 🔵 INFO    | Não acessível |

---

## 🛠️ Instalação

### Requisitos:

- Python 3.x
- Linux (recomendado)
- Permissão root
- Pacotes do sistema:

```bash
sudo apt install nfs-common
git clone https://github.com/nanxsec/NfsHack
cd NfsHack
sudo python3 nfhack.py
```
---

## 🎮 Menu Interativo

```bash
[1] Escanear hosts com NFS ativo
[2] Enumerar shares de um host
[3] Verificar permissões dos shares
[4] Analisar nível de risco
[5] Gerar relatório
[6] Explorar share (shell interativa)
[0] Sair
```
---

### 🌐 Scanner de Rede

Suporte a:

  - IP único → 192.168.0.10
  - Rede /24 → 192.168.0.0

Utiliza multithreading para alta performance

---

## 📂 Shell Interativa

Após montar um share, você pode navegar como um sistema remoto:

### Comandos disponíveis:

```bash
ls                  → listar arquivos
cd <dir>            → entrar em diretório
cd ..               → voltar
pwd                 → caminho atual
cat <arquivo>       → ler arquivo
download <arquivo>  → baixar arquivo
exit                → sair
```
---

## 📄 Relatórios

Os relatórios são salvos em:

loot/report.txt

Incluem:
- Host analisado
- Shares encontrados
- Permissões
- Classificação de risco
- Justificativa técnica
- Arquivos visíveis
---

## 📁 Estrutura do Projeto

```bash
nfhack/
├── nfhack.py          # CLI principal
├── core/
│   ├── scanner.py     # Scanner de rede/NFS
│   ├── auditor.py     # Enumeração e análise
│   └── utils.py       # Logs e utilidades
├── loot/
│   ├── session.log
│   ├── report.txt
│   └── downloads/
```
---

## ⚠️ Aviso Legal

Esta ferramenta foi desenvolvida **exclusivamente para fins educacionais e testes autorizados**.

O uso indevido pode violar leis locais e internacionais.

---

## 👨‍💻 Autor

**Nanoxsec**
