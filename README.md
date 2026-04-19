# 🛡️ AIGRIS
**Artificial Intelligence for Real-Time Information Security**



![Status](https://img.shields.io/badge/status-in%20development-orange)




![Platform](https://img.shields.io/badge/platform-Windows-blue)




![License](https://img.shields.io/badge/license-MIT-green)



> A lightweight, local cybersecurity agent designed to protect
> everyday users — without ever sending data to the cloud.

---

## 💡 The Idea

Most security software reacts *after* a threat has already connected
to your device. AIGRIS intercepts threats **before** — analyzing DNS
traffic locally with a Machine Learning model, blocking phishing domains
and malware before the browser loads even a single byte.

Everything runs on your device. No logs ever leave your machine.
No cloud subscription required.

---

## 🛡️ What AIGRIS Protects You From

| Threat | Description |
|---|---|
| Phishing | Fake websites and emails impersonating banks or services |
| Malware domains | Connections to trojan, ransomware and spyware distribution sites |
| Drive-by downloads | Malicious files that install automatically just by visiting a page |
| Malicious browser extensions | Extensions that spy on browsing or steal credentials |
| Suspicious login attempts | Repeated or unusual access attempts to your system |
| Banking fraud | Sites impersonating financial institutions to steal payment data |
| Rogue Wi-Fi (Evil Twin) | Fake hotspots mimicking trusted networks to intercept traffic |
| Social engineering | Manipulative patterns in messages or web content |

> Phase 1 targets home users against the most common real-world threats.
> Advanced enterprise threats are scoped for Phase 3.

---

## 🎯 Who It's For

- Home users who want simple, automatic protection
- Non-technical people: natural language alerts, zero configuration
- No cybersecurity knowledge required

---

## 🏗️ Architecture
┌─────────────────────────────────────┐
│           UI (Python/Qt)            │  ← Plain-language alerts
│  "I blocked a site impersonating    │
│   your bank"                        │
└──────────────┬──────────────────────┘
│ Local socket
┌──────────────▼──────────────────────┐
│         Core Engine (C++)           │  ← Main orchestrator
│   ┌──────────────────────────────┐  │
│   │       ONNX Runtime           │  │  ← Local AI, zero cloud
│   └──────────────────────────────┘  │
│   ┌──────────┐  ┌───────────────┐   │
│   │DNS Proxy │  │   Sensors     │   │  ← Sleep until needed
│   └──────────┘  └───────────────┘   │
└─────────────────────────────────────┘
**Performance targets:** RAM < 200MB · CPU < 5% idle · Standard consumer hardware

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Core Engine | C++17 |
| AI Inference | ONNX Runtime |
| Model Training | Python / scikit-learn |
| UI | Python / PyQt6 |
| IPC | Local sockets |

---

## 🔬 Roadmap

**Foundation**
- [x] Architecture design
- [ ] Local DNS Proxy (C++)
- [ ] Domain classification model (Python → ONNX)
- [ ] Local inference with ONNX Runtime
- [ ] UI — plain-language notifications

**Threat Coverage — Phase 1**
- [ ] Phishing detection (DNS + URL analysis)
- [ ] Malware domain blocking
- [ ] Drive-by download prevention
- [ ] Malicious browser extension detection
- [ ] Suspicious login attempt monitoring
- [ ] Banking fraud site detection
- [ ] Rogue Wi-Fi / Evil Twin detection
- [ ] Basic social engineering pattern recognition

**Expansion**
- [ ] Android port (Phase 2)
- [ ] Enterprise multi-device management (Phase 3)
- [ ] Linux server support (Phase 3)

---

## 📁 Structure
/core       → central logic and orchestration
/brain      → AI models (.onnx) and training scripts
/sensors    → monitoring modules (DNS, network, system)
/ui         → graphical interface
/docs       → technical specs and architecture diagrams
---

## 🔒 Design Principles

**Privacy by design** — no data ever leaves the device  
**Set and forget** — automatic protection, zero configuration  
**Minimal footprint** — engineered to run unnoticed in the background  
**Modular** — built to scale from desktop to mobile to enterprise

---

## ⚠️ Disclaimer

Experimental project built for learning and research purposes.  
Not yet ready for production use.  
Installation instructions will be available with the first release.

---

## 👤 Author

Personal project by a first-year Computer Engineering student,
built with the goal of learning by creating something real.

---

## 📄 License

MIT — see [LICENSE](LICENSE)
