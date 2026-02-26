# ai-secrets-scanner 🔐

> AI-powered secrets scanner that detects hardcoded API keys, credentials, and sensitive data in source code repositories.

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)
![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4.1-412991?style=flat-square&logo=openai&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Security](https://img.shields.io/badge/Category-devsecops-red?style=flat-square)

## Overview

AI-powered secrets scanner that detects hardcoded API keys, credentials, and sensitive data in source code repositories. This tool is designed for security professionals who want to augment their workflows with AI-driven intelligence, reducing manual analysis time and surfacing actionable insights faster.

## Features

- **AI-Driven Analysis** — Leverages GPT-4.1 for deep contextual reasoning beyond simple pattern matching.
- **Rich Terminal Output** — Color-coded, structured output with tables and formatted Markdown.
- **Flexible Input** — Accepts files, stdin pipes, and direct arguments for seamless workflow integration.
- **MITRE ATT&CK Integration** — Maps findings to the ATT&CK framework where applicable.
- **Actionable Output** — Every analysis includes concrete remediation and response recommendations.

## Installation

```bash
git clone https://github.com/rawqubit/ai-secrets-scanner.git
cd ai-secrets-scanner
pip install -r requirements.txt
export OPENAI_API_KEY="your-api-key-here"
```

## Usage

```bash
python main.py .
python main.py /path/to/repo --ai-review
python main.py src/ --severity-filter critical
```

Run `python main.py --help` for full usage information.

## Requirements

- Python 3.9+
- OpenAI API key (set as `OPENAI_API_KEY` environment variable)

## License

MIT License — see [LICENSE](LICENSE) for details.
