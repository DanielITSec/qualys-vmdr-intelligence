## 🔄 Automated Product Patching (Endpoint Hygiene)

**Purpose:** Streamlines the update process for common third-party applications (Browsers, Meeting Clients, and Utilities).

* **Problem:** Outdated software is a primary vector for ransomware and initial access. Applications like **Google Chrome**, **Microsoft Edge**, **Zoom**, **AnyDesk**, and **7-Zip** frequently receive patches for vulnerabilities listed in the **CISA KEV** catalog or associated with **Public Exploits** and **Weaponized** payloads.

* **Solution:** PowerShell-based automation that checks for the latest versions, validates digital signatures, and deploys updates silently, reducing the window of exposure without manual intervention.
