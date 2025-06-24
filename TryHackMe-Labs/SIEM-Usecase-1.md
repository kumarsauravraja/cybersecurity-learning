# SIEM Use-Case: Brute Force Login Detection

## 🎯 Objective:
Detect multiple failed login attempts in a short time window to identify potential brute-force attacks.

---

## 🛠️ Log Source:
- **Windows Security Logs**
- **Event ID: 4625** → Failed login attempt

---

## 📊 Detection Logic:
- Monitor for 5 or more failed login attempts from the **same source IP** or **username** within 2 minutes.
- Fields to look at:
  - `src_ip` (source IP)
  - `user` (target username)
  - `EventCode` (4625)
  - `timestamp`

---

## 🧠 Example SIEM Query (in Splunk format):
```spl
index=windows EventCode=4625
| stats count by src_ip, user
| where count > 5
