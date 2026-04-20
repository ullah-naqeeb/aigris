# 🛡️ AIGRIS
**Artificial Intelligence for Real-Time Information Security**

Aigris is an ambitious, privacy-first security agent designed to protect everyday users from common digital threats using on-device Artificial Intelligence. Developed as a university project, Aigris aims to prove that high-level security doesn't have to come at the cost of personal privacy.

---

## 👁️ The Vision
In a world where security apps often collect as much data as they protect, **Aigris** takes a different path. 

- **Phase 1 (Current):** Protecting regular users from daily threats (Phishing, Malware, Identity Theft).

## ✨ Key Features (Phase 1)
- **Proactive Phishing Detection:** Real-time analysis of SMS, emails, and suspicious URLs.
- **Malware Defense:** Identification of common Trojans, Ransomware, and Spyware.
- **Web Safety:** Monitoring for drive-by downloads and malicious browser extensions.
- **Network Security:** Detection of "Evil Twin" Wi-Fi attacks and suspicious access attempts.
- **Real-time Alerts:** Clear, non-technical notifications to keep users informed without overwhelming them.

## 🛠️ Technical Constraints & Architecture
Aigris is built with a focus on efficiency and total privacy:

- **100% On-Device:** No cloud processing. All AI inference happens locally to ensure zero data leakage.
- **Consumer Hardware Ready:** Optimized to run on standard mobile devices, not dedicated servers.
- **Resource Efficient:** 
  - **RAM:** 100-200MB maximum footprint.
  - **CPU:** <5% usage during idle/background monitoring.
- **Modular Design:** A plug-and-play architecture that allows for future scaling and the addition of new security modules.

## 🧠 Technology Stack
- **Language:** Kotlin / Android SDK
- **AI Engine:** ONNX Runtime (optimized for mobile inference)
- **Local Monitoring:** Android VpnService / Accessibility Services (where applicable)

## 🚧 Project Status
**Note:** This is a **work-in-progress university project**. 
I am a CS student building this one line of code at a time. It is currently in the early development phase. My goal is to bridge the gap between complex cybersecurity and everyday usability.

## 🤝 Contributing
Since this is a project born out of passion and learning, contributions, suggestions, and feedback are more than welcome. If you are interested in on-device AI or mobile security, feel free to open an issue or reach out.

---

*“Security shouldn't be a luxury, and privacy shouldn't be a trade-off.”*

## 📄 License

MIT — see [LICENSE](LICENSE)
