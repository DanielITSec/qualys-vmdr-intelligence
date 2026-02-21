# ⚙️ Security & Vulnerability Automation

This directory contains **PowerShell** scripts and automation workflows designed to integrate with **Qualys APIs** and **Microsoft Graph**. The goal is to transform manual vulnerability management into a streamlined, automated lifecycle.
<br><br>

## 💡 Philosophy
In a hybrid infrastructure, speed of remediation is just as important as the accuracy of detection. These tools focus on:
* **Reducing Mean Time to Remediate (MTTR):** Speeding up the response to critical threats.
* **Eliminating Manual Errors:** Ensuring consistent asset tagging and reporting.
* **Governance at Scale:** Maintaining compliance across Entra ID and On-premise ecosystems.


## 🚀 Featured Scripts

### 1. Qualys Asset Tagging Automation
**Purpose:** Automatically assigns Qualys Asset Tags based on registry keys, hostnames, or Entra ID attributes.
* **Problem:** Manual tagging is prone to failure, leading to "blind spots" in critical scan reports.
* **Solution:** Uses the Qualys `v2/asset/` API to apply tags dynamically, ensuring 100% visibility for business-critical servers.

### 2. Entra ID / M365 Security Audit
**Purpose:** Audits security group ownership and GPO enforcement status across OUs.
* **Tech:** Leverages **Microsoft Graph API** to identify orphaned groups and ensure that security policies are correctly linked according to the organization's Risk Assessment.

### 3. Vulnerability Reporting & Sync
**Purpose:** Extracts high-priority findings (QDS > 80) and formats them for stakeholders.
* **Function:** Bridges the gap between SecOps and IT Ops by providing actionable, filtered data instead of raw, massive spreadsheets.

---

## 🛠️ Usage & Setup

### Prerequisites
* **PowerShell 7.x** recommended.
* **Modules:** `Microsoft.Graph`, `PowershellGet`.
* **API Access:** Valid Qualys API credentials and Microsoft Graph Scopes (`Group.ReadWrite.All`, etc.).

### Security Best Practices
> [!IMPORTANT]
> **Credential Management:** These scripts are designed to work with environment variables or secure credential objects (e.g., `Export-CliXml` or Azure Key Vault). **Never hardcode API keys or passwords in the source code.**

---

> [!NOTE]  
> *All scripts in this directory are sanitized versions of real-world solutions. Sensitive data like URLs, IDs, and Credentials have been replaced with placeholders.*
