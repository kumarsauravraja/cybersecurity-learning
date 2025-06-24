# TryHackMe - Intro to SOC

## 📝 Summary
The “Intro to SOC” room provides a basic overview of what a Security Operations Center (SOC) is, its roles, and how security analysts detect/respond to threats in real-time.

## 🧠 Key Concepts

### 1. SOC Tiers:
- **Tier 1 (Alert Analyst):** Monitors alerts, escalates incidents
- **Tier 2 (Incident Responder):** Investigates incidents, collects evidence
- **Tier 3 (Threat Hunter):** Proactively hunts for advanced threats

### 2. Correlation Rules:
- Rules in a SIEM system (like Splunk or Elastic) that connect multiple logs to detect patterns — e.g., multiple failed logins followed by access from a new IP.

### 3. SIEM Tools:
- Security Information and Event Management tools are central to SOC operations. They collect, normalize, and analyze logs from different sources.

## 💻 Commands
- Example:  
  `grep "Failed password" /var/log/auth.log` – Search for failed SSH logins on Linux

