# Threat Intelligence & Risk-Based Queries (QQL)

This section contains Qualys Query Language (QQL) templates designed to identify high-risk vulnerabilities based on global threat intelligence feeds.

---

## 1. Known Exploited Vulnerabilities (CISA KEV)
**Objective:** Identify vulnerabilities that are confirmed to be exploited in the wild. This is the highest priority tier (Tier 1).

```sql
vulnerabilities.vulnerability.cisaKev: "true"
