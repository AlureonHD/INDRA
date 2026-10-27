INDRA — Python Security Toolkit

🇺🇸 English

INDRA is a Python-based security toolkit designed to organize cybersecurity utilities into a single, terminal-based interface with a red-and-black visual theme.

Features

- Network: Network information and diagnostic utilities.
- Website: Website analysis and basic security checks.
- OSINT: Open-source intelligence using publicly available information.
- People: Public-information research.
- Sites: Website and domain reconnaissance.
- Profiles: Public social media profile research.
- System: System information and diagnostic tools.
- Forensics: Basic digital investigation utilities.
- Utilities: General-purpose tools and helper functions.

Project Goals

INDRA aims to provide an organized, modular environment for learning about cybersecurity, digital reconnaissance, and security analysis through Python.

Responsible Use

Use INDRA only on systems you own or have explicit permission to test. OSINT features should rely on legally accessible public information. Users are responsible for complying with applicable laws and the terms of the services they access.

Language: Python
Interface: Terminal / CLI

---

🇧🇷 Português

INDRA é uma ferramenta de segurança digital desenvolvida em Python, criada para reunir e organizar utilitários de cibersegurança em uma única interface de terminal com visual vermelho e preto.

Recursos

- Network: Informações e ferramentas de diagnóstico de redes.
- Website: Análise de sites e verificações básicas de segurança.
- OSINT: Inteligência de fontes abertas com informações publicamente disponíveis.
- People: Pesquisa de informações públicas sobre pessoas.
- Sites: Reconhecimento de sites e domínios.
- Profiles: Pesquisa de perfis públicos em redes sociais.
- System: Informações e ferramentas de diagnóstico do sistema.
- Forensics: Utilitários básicos para investigação digital.
- Utilities: Ferramentas gerais e funções auxiliares.

Objetivos do Projeto

O INDRA busca oferecer um ambiente organizado e modular para aprender sobre cibersegurança, reconhecimento digital e análise de segurança utilizando Python.

Uso Responsável

Utilize o INDRA somente em sistemas próprios ou para os quais você tenha autorização explícita para realizar testes. Os recursos de OSINT devem utilizar informações públicas e legalmente acessíveis. O usuário é responsável por respeitar as leis aplicáveis e os termos dos serviços utilizados.

Linguagem: Python
Interface: Terminal / CLI

INDRA — Installation Guide

Requirements

- Python 3
- Git (optional, for cloning the repository)
- A terminal or command prompt

1. Termux (Android)

Install Termux from a trusted source: https://termux.dev/

Update packages and install Python and Git:

pkg update && pkg upgrade
pkg install python git

Clone the repository:

git clone https://github.com/YOUR-USERNAME/INDRA.git
cd INDRA

Run INDRA:

python INDRA.py

2. Windows

1. Install Python from https://www.python.org/downloads/
2. Open Command Prompt or PowerShell.
3. Clone the repository:

git clone https://github.com/YOUR-USERNAME/INDRA.git
cd INDRA

4. Run the tool:

python INDRA.py

If "python" does not work, try:

py INDRA.py

3. macOS

Install Python from https://www.python.org/downloads/macos/

Open Terminal and run:

git clone https://github.com/YOUR-USERNAME/INDRA.git
cd INDRA
python3 INDRA.py

4. Linux

On Debian or Ubuntu, install the required packages:

sudo apt update
sudo apt install python3 python3-pip git

Clone and run:

git clone https://github.com/YOUR-USERNAME/INDRA.git
cd INDRA
python3 INDRA.py

For other distributions, install Python 3 and Git using your distribution's package manager.

Running from a Downloaded ZIP

If you downloaded the source code as a ZIP file:

1. Extract the archive.
2. Open a terminal inside the extracted folder.
3. Run the appropriate command:

python INDRA.py

On macOS and many Linux systems, use "python3 INDRA.py".

Troubleshooting

Python not found: Check that Python 3 is installed and available in your PATH.

Module not found: If the repository contains a "requirements.txt" file, install its dependencies:

python -m pip install -r requirements.txt

On macOS/Linux, you may need:

python3 -m pip install -r requirements.txt

Repository not found: Replace "YOUR-USERNAME/INDRA" with the actual GitHub username and repository name.

Responsible Use

INDRA is intended for educational cybersecurity, authorized security testing, and research using publicly available information. Only test systems you own or have explicit permission to assess. Respect privacy, applicable laws, and service terms.
