[← Back to Main Portfolio](https://github.com/barryhuriwaka/cybersecurity-portfolio)

<div align="center">

# 🔥 CYBERSECURITY CASE STUDY 002  
### **Business Email Compromise • MFA Fatigue • Financial Fraud Prevention**

</div>

---

# CASE STUDY 002 — Business Email Compromise (BEC) Attempt  
**Status:** Contained  
**Severity:** High  
**Category:** Identity Threat / Email Compromise  

---

## 🧭 Executive Summary  

A Business Email Compromise attempt targeted a finance employee through CFO impersonation.  
The attacker attempted fraudulent financial activity and created a suspicious inbox rule to hide incoming messages.

---

## 🎯 Objectives  

- Determine whether the mailbox was compromised  
- Identify suspicious sign‑ins and MFA fatigue attempts  
- Detect malicious inbox rules  
- Assess financial fraud risk  
- Contain and secure the account  

---

## 👤 User & Alert Details  

| Field | Details |
|-------|---------|
| **User** | sarah.miller@brisbanetech.com.au |
| **Role** | Finance Officer |
| **Suspicious Location** | Lagos, Nigeria |
| **Alert Source** | Microsoft Defender for Office 365 |
| **Authentication** | MFA Enabled |

---

## 🔍 Initial Indicators  

- User reported unexpected MFA prompts  
- Suspicious inbox rule created  
- Sign‑in attempts from Nigeria  
- CFO impersonation email  
- Reply‑to mismatch  

---

## 📊 KQL Queries Used  

```kusto
SigninLogs
| where UserPrincipalName == "sarah.miller@brisbanetech.com.au"
```

```kusto
OfficeActivity
| where Operation == "New-InboxRule"
```

---

## 📁 Evidence Summary  

### Malicious Inbox Rule  

| Field | Value |
|-------|--------|
| **Name** | RSS‑Filter |
| **Action** | MoveToFolder |
| **Folder** | RSS Feeds |
| **Condition** | Apply to all unread messages |

---

## 🧠 Analyst Assessment  

### Indicators of Compromise  

- MFA fatigue  
- Suspicious inbox rule  
- Foreign login attempts  
- Impersonation email  

### Likely Attack Chain  

1. Credentials obtained  
2. MFA fatigue attack  
3. Inbox rule creation  
4. Fraudulent payment attempt  

---

## 🛡️ Containment Actions  

- Disabled inbox rule  
- Forced password reset  
- Revoked sessions  
- Blocked IP range  
- Alerted finance team  

---

## 🧬 MITRE ATT&CK Mapping  

| Tactic | Technique | ID |
|--------|-----------|----|
| Initial Access | Phishing | T1566 |
| Credential Access | MFA Fatigue | T1110.003 |
| Persistence | Mailbox Rule Creation | T1098.002 |

---

## 🕒 Timeline (AEST)  

| Time | Event |
|------|--------|
| 11:42 | Failed login from Nigeria |
| 11:46 | Inbox rule created |
| 11:50 | CFO impersonation email received |
| 12:10 | SOC begins investigation |

---

## 📁 Repo Structure  

```
/diagrams
/logs
/queries
/reports
/artifacts
README.md
```

---

[← Previous Case Study — Suspicious Login Activity](https://github.com/barryhuriwaka/soc-investigation-suspicious-logins)  
[Next Case Study → Case Study 003 — Phishing & Credential Harvesting](https://github.com/barryhuriwaka/Phishing-Credential-Harvesting)
