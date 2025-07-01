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

## Screenshot
[Optional]
