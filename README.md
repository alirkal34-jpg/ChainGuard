<div align="center">

# 🛡️ ChainGuard
### Advanced Python Package Security Scanner

[![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Tkinter](https://img.shields.io/badge/GUI-Tkinter-orange?logo=python&logoColor=white)](https://docs.python.org/3/library/tkinter.html)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Supply%20Chain-red)](https://github.com/alirkal34-jpg/ChainGuard)

*Protecting your software supply chain from typosquatting, malicious packages, and supply chain attacks*

[Features](#-features) • [Demo](#-demo) • [Installation](#-installation) • [Usage](#-usage) • [Architecture](#-architecture) • [Contributing](#-contributing)

</div>

---

## 📖 Overview

**ChainGuard** is an advanced security tool designed to protect Python projects from **software supply chain attacks**. Built as a comprehensive security scanner, it detects malicious packages, typosquatting attempts, and vulnerable dependencies through multi-layered analysis combining CVE databases, static analysis, dynamic behavior monitoring, and threat intelligence.

### 🎯 The Problem

Software supply chain attacks have surged by **300%** in recent years. Attackers exploit developer trust by:
- Publishing packages with names similar to popular libraries (e.g., `reqests` instead of `requests`)
- Injecting malicious code into legitimate-looking packages
- Exploiting dependency confusion vulnerabilities
- Hiding backdoors in deep dependency trees

---

## ✨ Features

### 🔍 **Multi-Layered Detection**

ChainGuard employs four complementary security analysis techniques:

| Layer | Detection Method | Coverage |
|-------|-----------------|----------|
| **CVE Scanning** | Known vulnerability databases | Published CVEs |
| **Static Analysis** | AST-based code inspection | Malicious patterns, suspicious imports |
| **Dynamic Analysis** | Runtime behavior monitoring | Network calls, file operations |
| **Threat Intelligence** | Community-sourced indicators | Typosquatting, malicious packages |

### 🎨 **Interactive GUI Dashboard**

- **Project Selection**: Easily browse and select Python projects
- **Real-Time Scanning**: Live progress tracking with detailed logs
- **Visual Results**: Color-coded security status (Safe, Suspicious, Malicious)
- **Risk Scoring**: Quantified risk assessment for each package
- **AI-Powered Analysis**: Optional Gemini AI integration for advanced threat detection

### 🔬 **Advanced Security Analysis**

#### **Typosquatting Detection**
Uses **Levenshtein Distance** algorithm to identify packages suspiciously similar to popular libraries:
```python
Distance("requests", "reqests") = 1  ⚠️ HIGH RISK
Distance("numpy", "numpz") = 1       ⚠️ HIGH RISK
```

#### **Static Code Analysis**
- **AST Parsing**: Deep inspection of Python source code
- **Taint Analysis**: Tracks data flow from user inputs to dangerous sinks
- **Pattern Matching**: Detects obfuscated code, suspicious network calls
- **Import Analysis**: Flags dangerous imports (`subprocess`, `socket`, `eval`)

#### **Dynamic Behavior Monitoring**
- Network activity tracking
- File system operations monitoring
- Process execution detection
- Environment variable access logging

#### **Metadata Verification**
- Author email validation
- License integrity checks
- Homepage verification
- Publication date anomaly detection

---

## 🎬 Demo

### Detection Results

ChainGuard successfully identified **5 malicious** and **1 suspicious** package out of 24 analyzed dependencies.

**Performance Comparison:**

| Tool | Total Packages | Malicious | Suspicious | Detection Basis |
|------|---------------|-----------|------------|-----------------|
| **ChainGuard** | 24 | 5 | 1 | CVE + Static + Dynamic + TI |
| pip-audit | 24 | 1 | 0 | CVE / OSV only |

*ChainGuard leverages behavioral, structural, and threat intelligence indicators beyond traditional vulnerability databases.*

---

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- tkinter (usually included with Python)

### Install Dependencies

```bash
git clone https://github.com/alirkal34-jpg/ChainGuard.git
cd ChainGuard/ChainGuard-main
pip install -r requirements.txt
```

### Optional: Gemini AI Integration

For advanced AI-powered threat analysis:

```bash
pip install google-generativeai
export GEMINI_API_KEY="your-api-key-here"
```

---

## 📘 Usage

### GUI Mode (Recommended)

```bash
cd ChainGuard-main/src
python chain_guard.py
```

**Workflow:**
1. Click **"Select Project"** to choose your Python project directory
2. Click **"Scan"** to analyze all Python files
3. Review detected packages in the results table
4. Click **"Security Analysis"** to perform deep security scanning
5. Double-click any package for detailed threat report

### Command Line Mode

```python
from chain_guard import ChainGuardScanner

scanner = ChainGuardScanner()
results = scanner.scan_project("/path/to/project")
scanner.generate_report(results)
```

---

## 🏗️ Architecture

### System Design

```
┌─────────────────────────────────────────────────────────────┐
│                     ChainGuard Core                         │
├─────────────────────────────────────────────────────────────┤
│  ┌───────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │ File Scanner  │→│ AST Parser   │→│ Package         │  │
│  │               │  │              │  │ Extractor       │  │
│  └───────────────┘  └──────────────┘  └─────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                   Security Analysis Engine                  │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │ CVE Scanner  │  │ Static       │  │ Dynamic         │  │
│  │              │  │ Analyzer     │  │ Monitor         │  │
│  └──────────────┘  └──────────────┘  └─────────────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │ Typosquat    │  │ Metadata     │  │ Threat          │  │
│  │ Detector     │  │ Validator    │  │ Intelligence    │  │
│  └──────────────┘  └──────────────┘  └─────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                   Reporting & Visualization                 │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

#### **DataFlowAnalyzer**
AST-based taint analysis for tracking user input through code execution paths.

```python
class DataFlowAnalyzer(ast.NodeVisitor):
    """Tracks data flow from sources (user input) to sinks (dangerous functions)"""
    - Monitors: input(), sys.argv, os.environ, request.*
    - Detects: Code injection, command injection, path traversal
```

#### **Security Scanner**
Multi-layered package analysis with configurable detection strategies.

#### **GUI Controller**
Tkinter-based interface for intuitive project scanning and result visualization.

---

## 🔧 Configuration

### Custom Detection Rules

Create `config.json` in the project root:

```json
{
  "threshold": {
    "levenshtein_distance": 2,
    "risk_score": 50
  },
  "excluded_packages": ["internal-pkg"],
  "trusted_sources": ["pypi.org"],
  "enable_ai": false
}
```

---

## 📊 Project Structure

```
ChainGuard/
├── ChainGuard-main/
│   ├── src/
│   │   ├── chain_guard.py      # Main GUI application
│   │   └── app.py              # Test application
│   ├── requirements.txt        # Python dependencies
│   └── README.md              # This file
├── LICENSE                     # MIT License
└── .gitignore                 # Git ignore rules
```

---

## 🎓 Academic Background

This project was developed for the **Introduction to Cybersecurity** course, based on comprehensive research into:

- **Typosquatting Attacks**: Name similarity exploitation
- **Dependency Confusion**: Public/private package conflicts
- **Supply Chain Compromise**: Multi-stage attack propagation
- **Behavioral Analysis**: Runtime threat detection

### Research References

- [Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks](https://arxiv.org/abs/2005.09535)
- [Towards Measuring Supply Chain Attacks on Package Managers for Interpreted Languages](https://arxiv.org/abs/2002.01139)

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Ali Rubar Kal**

- GitHub: [@alirkal34-jpg](https://github.com/alirkal34-jpg)
- Project: [ChainGuard](https://github.com/alirkal34-jpg/ChainGuard)

---

## 🙏 Acknowledgments

- **Course**: Introduction to Cybersecurity
- **Inspiration**: Real-world supply chain attack incidents
- **Community**: Python security research community

---

## 📈 Future Roadmap

- [ ] Integration with CI/CD pipelines
- [ ] Support for npm, Maven, NuGet packages
- [ ] Machine learning-based anomaly detection
- [ ] Cloud-based threat intelligence database
- [ ] Browser extension for package manager websites
- [ ] Automated remediation suggestions

---

<div align="center">

**⭐ Star this repository if you find it helpful!**

Made with ❤️ for a safer software supply chain

</div>
