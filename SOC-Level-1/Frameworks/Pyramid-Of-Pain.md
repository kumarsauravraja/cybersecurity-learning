# Pyramid of Pain – TryHackMe

## Room Completed
- Name: Pyramid of Pain
- Platform: TryHackMe

## My Understanding
Pyramid of Pain ek attacker framework hai jo batata hai ki defenders attackers ko kitna dard de sakte hain, depending on kaunse indicators wo block karte hain. Is pyramid mein low se high levels tak indicators arranged hote hain — jaise:

Lowest level → Hashes, IP addresses — jo attackers aasani se change kar sakte hain.

Higher levels → Tactics, Techniques, aur Procedures (TTPs) — inhe change karna attackers ke liye bahut mushkil aur costly hota hai.

Jaise-jaise defender pyramid ke higher level pe block karta hai, attacker ka pain badhta rehta hai, kyunki unhe poori strategy badalni padti hai, na ki sirf IP ya hash replace karna.

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
