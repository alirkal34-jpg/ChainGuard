# 🛡️ Supply Chain Sentinel (Project ChainGuard)

> An automated **Software Supply Chain Security** tool designed to detect **typosquatting attacks** and analyze package metadata integrity using **Levenshtein Distance** algorithms.

![Python](https://img.shields.io/badge/Language-Python_3.x-blue?logo=python&logoColor=white) ![Streamlit](https://img.shields.io/badge/Interface-Web_UI-red?logo=streamlit&logoColor=white) ![Algorithm](https://img.shields.io/badge/Algorithm-Levenshtein_Distance-orange)

## 🚨 The Problem

Software supply chain attacks have increased by 300% in recent years. Attackers publish malicious packages with names similar to popular ones (e.g., `reqests` instead of `requests`) to trick developers. Detecting these manually in large dependency trees is error-prone and difficult.

## 🛠️ The Solution

This project, developed as **ChainGuard**, implements a dual-layer verification system:
1.  **Typosquatting Detection:** Uses **Levenshtein Distance** to calculate string similarity between installed packages and a trusted dataset (top 5000 PyPI packages).
2.  **Metadata Analysis:** Inspects package details (Author, Email, License) to identify suspicious inconsistencies or missing information.

## ⚡ Key Features

* **Interactive Web Dashboard:** Built with **Streamlit** for easy file uploading and visual reporting.
* **Similarity Analysis:** Flags packages that are suspiciously similar (but not identical) to popular libraries.
* **Metadata Inspection:** Extracts and verifies author emails, homepages, and license types from `metadata.json`.
* **Academic Basis:** Based on comprehensive research into Typosquatting and Dependency Confusion attacks (see `docs/Security_Report.pdf`).

## 📂 Project Structure
<img width="991" height="273" alt="image" src="https://github.com/user-attachments/assets/35012591-a62e-4b96-8497-fb2b0cf874d7" />
