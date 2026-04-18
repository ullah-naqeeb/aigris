# 🛡️ AIGRIS (ARTICIAL INTELLIGENCE FOR REAL TIME INFORMATION SECURITY)

**Aigris** is an experimental cybersecurity agent designed to protect users from modern digital threats through a local, AI-powered DNS Proxy. 

The project focuses on **privacy-by-design**, moving threat detection from the cloud directly to the user's device. By intercepting and analyzing DNS queries locally using Machine Learning, Aigris can block phishing, malware, and tracking at the network level before any connection is even established.

---

## 🚀 Project Vision & Status
> **Note:** This project is currently in the **Early Development stage**. The structure below represents the planned architecture and ongoing implementation.

- **Phase 1 (Current):** Developing ONNX file using python,the C++ Core and the local DNS Proxy for real-time domain filtering.

## 🧠 Planned Architecture
* **On-Device AI:** Uses **ONNX Runtime** for local inference—no DNS logs ever leave the machine.
* **Zero-Cloud Latency:** Fast local lookups with intelligent caching.
* **Minimal Footprint:** Engineered in C++ to maintain a RAM usage under 200MB.

## 🛠️ Tech Stack (Selected)
- **Language:** C++ (Network & Core logic)
- **AI Engine:** ONNX Runtime (Local Inference)
- **Target OS:** Windows (Initial Development), planned Linux/Android support.

---

## 📂 Proposed Repository Structure
- `/core`: Central logic for decision making and threat scoring.
- `/brain`: Placeholder for AI models (.onnx) and dataset training scripts.
- `/sensors`: Modules for additional system-level monitoring.
- `/docs`: Technical specifications and architectural diagrams.
