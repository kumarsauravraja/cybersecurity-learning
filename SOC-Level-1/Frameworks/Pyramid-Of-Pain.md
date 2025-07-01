# Pyramid of Pain – TryHackMe

## Room Completed
- Name: Pyramid of Pain
- Platform: TryHackMe

## My Understanding
The Pyramid of Pain is a framework that explains how defenders can cause difficulties for attackers, depending on which indicators they detect and block. The pyramid is organized from low to high levels:

At the lowest level are things like hashes and IP addresses, which attackers can easily change.

At the higher levels are Tactics, Techniques, and Procedures (TTPs), which are much harder and more costly for attackers to modify.

As defenders block higher levels in the pyramid, it increases the attacker’s pain, because they have to change their entire strategy instead of just switching an IP or hash.

## The 6 Levels of the Pyramid

| Level | Indicator Type | Example | Difficulty for Attacker |
|-------|----------------|---------|------------------------|
| 1 | Hash Values | File hash (MD5, SHA256) | Easy to change |
| 2 | IP Addresses | Malicious IP | Easy to change |
| 3 | Domain Names | Malicious domain | Moderate |
| 4 | Network/Host Artifacts | Registry keys, file paths | Harder |
| 5 | Tools | Cobalt Strike, Mimikatz | Very hard |
| 6 | TTPs | Lateral movement techniques | Extremely hard |

## Why It Matters
Higher in the pyramid = more pain for attackers because changing TTPs takes time, money, and skill.
### Task 1 – Introduction
- Pyramid of Pain helps SOC, Threat Hunters, and IR teams improve detection and incident response.

### Task 2 – Hash Values (Trivial)
- Hashes uniquely identify files (e.g. MD5, SHA256)
- Attackers can easily change hashes by modifying the file
- Example: echo command changes file hash
---

### Task 3 – IP Addresses (Easy)

- IP addresses identify devices on a network, such as desktops, servers, or IoT devices.
- Blocking known malicious IP addresses is a basic defense tactic.
- Weakness: attackers can quickly change their public IPs or use techniques like Fast Flux to rotate IPs associated with malicious domains.
- **Fast Flux:** Technique where multiple IP addresses are tied to a single domain and rotate frequently to hide malicious infrastructure.
- **Example from TryHackMe:** The first malicious IP contacted by a process was `50.87.136.52`.

---

### Task 4 – Domain Names (Simple)

- Domains map readable names to IP addresses (e.g., evilcorp.com).
- Changing domains requires more effort than changing IPs because attackers must purchase, register, and manage DNS records.
- Attackers often use techniques like:
  - **Punycode Attacks:** Unicode characters used to mimic legitimate domains (e.g., `xn--addas-o4a.de` → `adıdas.de`).
  - **URL Shorteners:** To hide malicious destinations behind short links (e.g., bit.ly, tinyurl.com).
- Defenders analyze proxy logs and DNS logs to detect malicious domains.
- **Example from TryHackMe:**
  - First suspicious domain: `craftingalegacy.com`
  - Redirected short URL example: `https://tinyurl.com/bw7t8p4u` → `https://tryhackme.com/`

---

### Task 5 – Host Artifacts (Annoying)

- Host artifacts are traces left on the infected system, like:
  - Suspicious process execution (e.g. `regidle.exe`)
  - Dropped files (e.g. `G_jugk.exe`)
  - Registry values or unique Indicators of Compromise (IOCs)

- These are **harder for attackers to change**, as they often relate to how the attack interacts with the operating system.

- Example: In the given analysis report, a malicious EXE (`G_jugk.exe`) is dropped, and the process `regidle.exe` communicates with `96.126.101.6` over port 8080.

- **Why it matters:** Detecting host artifacts forces attackers to change their tools or payloads, which slows them down and increases defender advantage.

---

### Task 6 – Network Artifacts (Annoying)

- Network artifacts are patterns in how malware behaves over the network — like:
  - Suspicious **User-Agent strings**
  - Unique **URI patterns**
  - Command-and-Control (C2) traffic behavior
  - POST request anomalies

- These are still **harder to change** than hashes or IPs, but attackers can sometimes customize or randomize them.

- Example from TryHackMe:
  - The User-Agent seen in the PCAP belongs to **Internet Explorer**.
  - Number of POST requests visible in packet capture (PCAP) screenshot = [you can fill this if known].

- Tools like **Wireshark**, **TShark**, or **IDS logs (e.g. Snort)** help identify such artifacts.

- **Why it matters:** Spotting these patterns allows defenders to block specific communication behaviors rather than relying on IP/domain-level blocking.

---

### Task 7 – Tools (Challenging)

- Tools include utilities and software attackers use to create:
  - Malicious macros (maldocs)
  - Backdoors
  - Custom .EXE or .DLL payloads
  - Password crackers

- If defenders detect these tools, attackers face significant hurdles:
  - Need to develop entirely new tools
  - Spend money and time
  - Acquire new skills

- Detection techniques:
  - Antivirus signatures
  - Detection rules
  - **YARA rules** (for identifying malware patterns)
  - Fuzzy hashing (e.g. SSDeep) for similarity analysis of malware samples

- Useful Resources:
  - MalwareBazaar
  - Malshare
  - SOC Prime Threat Detection Marketplace

- **Example from TryHackMe:** A Trojan drops `Stealer.exe` in the Temp folder.

- **Key Terms:**
  - Fuzzy Hashing → context triggered piecewise hashes (CTPH)

---

### Task 8 – TTPs (Tough)

- **TTPs = Tactics, Techniques, and Procedures**
  - Refers to how adversaries operate end-to-end
  - Covers the entire attack lifecycle:
    - Phishing
    - Initial access
    - Privilege escalation
    - Lateral movement
    - Data exfiltration

- Detecting TTPs impacts attackers the most because:
  - TTPs are deeply tied to their operating methods
  - Changing TTPs requires significant reengineering

- Example:
  - Detecting Pass-the-Hash via Windows Event Log monitoring allows quick remediation and prevents lateral movement.

- From TryHackMe:
  - The MITRE ATT&CK Matrix lists **9 techniques** under the Exfiltration category.
  - Chimera (China-based hacking group) uses a **commercial remote access tool (RAT)** for C2 and exfiltration. (You can fill the tool’s name if you have it.)

---

### Task 9 – Practical: The Pyramid of Pain

- Practical exercise in TryHackMe:
  - Deploy a static website provided in the room.
  - Drag indicators to the correct tiers in the Pyramid of Pain.
  - Submit your configuration to retrieve a flag.

- **Note:** Enter the flag value once solved.



## Screenshot
[Optional]
