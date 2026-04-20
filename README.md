# CASE STUDY 002 - Business Email Compromise (BEC) Attempt  
**Status:** Contained  
**Severity:** High  
**Category:** Identity Threat / Email Compromise / Social Engineering  

---

## 🧭 Executive Summary  
A Business Email Compromise (BEC) attempt targeted a finance employee through CFO impersonation.  
The attacker attempted to initiate fraudulent financial activity and created a suspicious inbox rule to hide incoming messages.

Investigation confirmed:  
- Failed MFA attempts from Nigeria  
- Malicious inbox rule creation  
- A spoofed CFO email requesting urgent payment  

The attack was contained before any financial loss occurred.

---

## 🎯 Objectives  
- Determine whether the user’s mailbox was compromised  
- Identify suspicious sign‑ins and MFA fatigue attempts  
- Detect malicious inbox rules or forwarding rules  
- Assess whether financial fraud was attempted  
- Contain and secure the affected account  

---

## 👤 User & Alert Details  

| Field | Details |
|-------|---------|
| **User** | sarah.miller@brisbanetech.com.au |
| **Role** | Finance Officer |
| **Normal Location** | Brisbane, QLD |
| **Suspicious Location** | Lagos, Nigeria |
| **Alert Source** | Microsoft Defender for Office 365 |
| **Alert Type** | Suspicious Inbox Rule Created |
| **Authentication** | MFA Enabled |

---

## 🔍 Initial Indicators  
- User reported unexpected MFA prompts  
- Defender flagged a suspicious inbox rule  
- Sign‑in attempts from Nigeria  
- CFO impersonation email requesting urgent payment  
- Reply‑to domain mismatch  

---

## 📊 KQL Queries Used  

### **Suspicious Sign‑Ins**
```kql
SigninLogs
| where UserPrincipalName == "sarah.miller@brisbanetech.com.au"
| project TimeGenerated, IPAddress, Location, ResultType, ResultDescription
```

### **Inbox Rule Creation**
```kql
OfficeActivity
| where UserId == "sarah.miller@brisbanetech.com.au"
| where Operation == "New-InboxRule"
| project TimeGenerated, Operation, Parameters
```

### **MFA Fatigue Attempts**
```kql
SigninLogs
| where UserPrincipalName == "sarah.miller@brisbanetech.com.au"
| where ResultDescription contains "MFA"
```

---

## 📁 Evidence Summary  

### **Suspicious Inbox Rule**
```
Name: RSS-Filter
Action: MoveToFolder
Folder: RSS Feeds
Condition: Apply to all unread messages
CreatedBy: Unknown session
```

### **Suspicious Sign‑In Attempts**
| Time (AEST) | IP | Location | Result |
|-------------|----|----------|--------|
| 11:42 | 102.89.221.14 | Lagos, Nigeria | Failed |
| 11:43 | 102.89.221.14 | Lagos, Nigeria | Failed |
| 11:44 | 102.89.221.14 | Lagos, Nigeria | MFA Required |

### **BEC Email Indicators**
- Display name spoofing  
- Urgent financial request  
- Reply‑to mismatch  
- No previous conversation thread  

---

## 🧠 Analyst Assessment  

### **Indicators of Compromise**
- MFA fatigue attack  
- Suspicious inbox rule creation  
- Foreign login attempts  
- High‑risk user activity flagged  
- CFO impersonation email  

### **Likely Attack Chain**
1. Attacker obtained credentials (phishing or breach dump)  
2. Attempted login from Nigeria  
3. Triggered MFA fatigue to trick the user  
4. Created an inbox rule to hide replies  
5. Sent a fraudulent payment request  

**Risk Level:** **High**  
BEC attacks frequently lead to financial loss. Early detection prevented escalation.

---

## 🛡️ Containment Actions  

### **Immediate**
- Disabled malicious inbox rule  
- Forced password reset  
- Revoked all active sessions  
- Blocked Nigerian IP range  
- Alerted the finance team  

### **Investigation**
- Reviewed mailbox audit logs  
- Checked for forwarding rules  
- Verified no external access tokens  
- Searched for similar phishing attempts  

### **Recovery**
- Re‑enabled account with MFA  
- User completed phishing awareness refresher  
- Finance workflows updated to require verbal confirmation  

---

## 🧬 MITRE ATT&CK Mapping  

| Tactic | Technique | ID | Reason |
|--------|-----------|----|--------|
| Initial Access | Phishing | T1566 | CFO impersonation email |
| Credential Access | MFA Fatigue | T1110.003 | Multiple MFA prompts |
| Persistence | Mailbox Rule Creation | T1098.002 | Rule to hide replies |
| Defense Evasion | Valid Accounts | T1078 | Attempted login with stolen creds |
| Impact | Financial Fraud | T1656 | Attempted payment redirection |

---

## 🕒 Timeline (AEST)

| Time | Event |
|------|--------|
| 11:42 | Failed login from Nigeria |
| 11:43 | Second failed login |
| 11:44 | MFA challenge triggered |
| 11:46 | Suspicious inbox rule created |
| 11:50 | CFO impersonation email received |
| 12:05 | User reports MFA prompts |
| 12:10 | SOC begins investigation |
| 12:20 | Account secured |

---

## 📁 Recommended Repo Structure  
```
/diagrams
/logs
/queries
/reports
/artifacts
README.md
```
[← Back to Main Portfolio](https://github.com/barryhuriwaka/cybersecurity-portfolio)
