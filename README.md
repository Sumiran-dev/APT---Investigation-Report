# 🕵️‍♂️ Advanced Persistent Threat (APT) Investigation Report

**Project:** Investigating an APT Attack on *imreallynotbatman.com*  
**Tools Used:** Splunk, Suricata, Sysmon, Stream:HTTP, IIS Logs, Robtex, VirusTotal, DomainTools, ThreatCrowd  
**Kill Chain Reference:** Lockheed Martin Cyber Kill Chain  
**Investigator:** Sumiran Bastola  
**Duration:** Multi-phase analysis conducted in stages across the full attack lifecycle  
**Objective:** Identify and trace the APT group's attack path from recon to defacement, correlate threat actor infrastructure, and extract tactical indicators for defense.

---

## 🔍 1. Reconnaissance

### ✅ What I Did

- Used `sourcetype=stream:http` and `sourcetype=suricata` in Splunk to identify scanning activity.
- Identified the suspicious IP **40.80.148.42**, heavily querying `imreallynotbatman.com`.

### 💡 How I Did It

- Ran Splunk search across `index=botsv1` for mentions of the domain.
- Used `stats count by src` to isolate source IPs and narrowed down via high traffic volume (95% from this IP).
- Validated findings using Suricata logs to ensure it wasn't a false positive.

### 📊 Result

- Successfully identified **40.80.148.42** as the source of scanning activity.
- Tool used: **Acunetix Web Vulnerability Scanner**, confirmed via `http_user_agent`.

### 😓 Challenge

- Differentiating between legitimate and malicious scans without false positives.
- Required corroboration across multiple sourcetypes to build confidence.
![image](https://github.com/user-attachments/assets/7e37dc0f-e98c-4153-b934-b3deadaf3692)

![image](https://github.com/user-attachments/assets/eab98901-724d-4efd-a1a3-cbd16df93f64)

![image](https://github.com/user-attachments/assets/6be19ef2-ba4f-471e-88dd-ceb77ef23ae0)

![image](https://github.com/user-attachments/assets/3cce686a-8f9a-4fdb-8aa4-b8c8f8f8e9a9)

---

## 💣 2. Weaponization

### ✅ What I Did

- Mapped attacker infrastructure to IPs and domains.
- Used **Robtex, VirusTotal, ThreatCrowd**, and **DomainTools** for OSINT correlation.

### 💡 How I Did It

- Queried Robtex with attacker FQDN: `prankglassinebracket.jumpingcrab.com`
- Pivoted IP **23.22.63.114** and found several spoofed Wayne Enterprises domains.

### 📊 Result

- Mapped attacker’s infrastructure including malware delivery points.
- Identified email address linked to multiple domains registered by the APT group.

### 🎯 Special Finding

- Discovered custom malware with a **special hex tag** using VirusTotal comments — converted via HEX-to-ASCII.
![image](https://github.com/user-attachments/assets/ac466e7b-1e86-471e-82db-85cbe0c42391)

![image](https://github.com/user-attachments/assets/89c8e086-3dbc-4cd4-b9a9-614a7da8cc0d)

![image](https://github.com/user-attachments/assets/44caedb6-f0e1-4a22-b3c0-bbdf8333b951)

![image](https://github.com/user-attachments/assets/b3e8903d-887e-4100-91f6-f1159098af0d)

---

## 📩 3. Delivery

### ✅ What I Did

- Confirmed the fallback malware used in phishing campaigns via threat intelligence.

### 💡 How I Did It

- Used **ThreatMiner** and **VirusTotal** to get associated hashes and filenames linked to infrastructure.
- Extracted **SHA256** hash of malware from VirusTotal submissions tied to the attacker’s IP.

### 📊 Result

- Identified the specific custom malware variant the attackers would use if direct compromise failed.
![image](https://github.com/user-attachments/assets/ac2a507c-3750-4df5-832a-bbe4b465f7b4)

![image](https://github.com/user-attachments/assets/e96fe3f0-a3dc-44df-b568-854dc6658d9b)

![image](https://github.com/user-attachments/assets/aa0dfb43-240a-4acd-952c-482120e67a14)

---

## 💥 4. Exploitation

### ✅ What I Did

- Tracked brute-force attack attempts and analyzed login attempts in `stream:http`.

### 💡 How I Did It

- Filtered POST requests to the webserver IP (192.168.250.70).
- Extracted passwords using `rex` command from `form_data`.
- Identified **23.22.63.114** as the origin of brute force attempts with **412** requests.

### 🎯 Results

- First password tried: **123456**
- Successful login password: **batman**
- Attacker who gained access: **40.80.148.42**
- Time between success and access: **~92.17 seconds**
- Total unique passwords tried: **412**
- Average password length: **7 characters**

### 😓 Challenge

- Filtering massive HTTP data to accurately isolate login attempts.
- Needed regular expressions and time sorting to extract exact password used and timestamp.
![image](https://github.com/user-attachments/assets/0d2ea15c-3007-4341-bffe-a8d2cd5021b3)

![image](https://github.com/user-attachments/assets/aca7d1f8-a420-4fcb-acfd-c2a294fa98bb)

![image](https://github.com/user-attachments/assets/3fb4708f-4e61-406c-bb3a-eb69fe9b4d4c)

![image](https://github.com/user-attachments/assets/5280b8e8-07f1-46e3-acb4-d742a85407cb)

---

## 📦 5. Installation

### ✅ What I Did

- Identified the malicious executable uploaded to the server.

### 💡 How I Did It

- Searched `.exe` file uploads in `stream:http` and `suricata`.
- Found file **3791.exe**, uploaded via POST from **40.80.148.42**.

### 🔐 Hash Verification

- Used `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` to extract MD5.
- Isolated with `CommandLine=3791.exe` and `EventCode=1`.

### 📊 Result

- Identified uploaded malware file and confirmed its MD5 hash using Sysmon logs.
![image](https://github.com/user-attachments/assets/880010fd-d504-4f1b-897d-3187b7a14d55)

![image](https://github.com/user-attachments/assets/4e99a433-f29a-419b-9e94-be47934e0072)
![image](https://github.com/user-attachments/assets/0e5efd9d-d5ef-434d-9c8a-a17f0253f212)

![image](https://github.com/user-attachments/assets/da3e1e78-2a67-459f-8fd3-5865e50b47f9)

---

## 🌐 6. Command & Control (C2)

### ✅ What I Did

- Determined the domain used by attacker to connect back to the compromised host.

### 💡 How I Did It

- Used `stream:http` and Fortinet firewall logs.
- Located the file `poisonivy-is-coming-for-you-batman.jpeg` being accessed from external IP.
- Extracted FQDN: **prankglassinebracket.jumpingcrab.com**
![image](https://github.com/user-attachments/assets/3064d44c-22c1-44f6-85d5-80ca9d232c5c)

![image](https://github.com/user-attachments/assets/a71db70d-3eba-4936-8fd8-90172f063022)

---

## 🎯 7. Action on Objectives

### ✅ What I Did

- Traced the actual file used to deface the website.

### 💡 How I Did It

- Used a combination of `suricata`, `stream:http`, and `fgt_utm` firewall logs.
- Looked at traffic from internal (web server) to external sources.
- Found three files: two PHP and one JPEG.

### 📊 Final Defacement File

- **poisonivy-is-coming-for-you-batman.jpeg**
- Corroborated across all data sources: Suricata, Stream, Fortigate.
![image](https://github.com/user-attachments/assets/1e2bdf2f-42a4-4b27-a202-8767f1fadcbd)

![image](https://github.com/user-attachments/assets/1ab116cc-4e2f-4415-8748-4254b9cdd3df)

![image](https://github.com/user-attachments/assets/6b412c29-5e94-4156-90ca-4813da322b1f)

![image](https://github.com/user-attachments/assets/7af8eee2-811b-478d-839a-4d9fca2e252a)

---

## 🧠 Challenges & Lessons Learned

| Challenge                                       | How I Solved It                               | Impact                                     |
| ---------------------------------------------- | --------------------------------------------- | ------------------------------------------ |
| Multiple IPs interacting with the system        | Used `stats` and `sort` to identify anomalies | Accurate attacker identification           |
| Extracting password data from messy `form_data` | Used `rex` regex and `eval len()`             | Enabled detailed password analysis         |
| Determining file upload origin                  | Correlated Suricata, Stream, and Sysmon       | Mapped exact attacker actions              |
| Tracing malware origins without file access     | Used VirusTotal & ThreatMiner                 | Obtained actionable hashes                 |
| Time delta calculation                          | Used `transaction` command in Splunk          | Precisely measured attacker movement speed |

---

## 🧩 Summary of Attack Path (Kill Chain View)

1. **Recon**: 40.80.148.42 scanned imreallynotbatman.com with Acunetix.  
2. **Weaponization**: Created spoofed Wayne domains + preconfigured malware.  
3. **Delivery**: Planned spear-phishing fallback malware (not needed).  
4. **Exploitation**: 23.22.63.114 brute-forced; password “batman” reused successfully.  
5. **Installation**: Uploaded 3791.exe from 40.80.148.42.  
6. **C2**: Connected back to prankglassinebracket.jumpingcrab.com.  
7. **Objectives**: Defaced web server with a custom image.  

---

## 📘 Final Thoughts

This investigation was an intense journey through data correlation, OSINT pivoting, and Splunk mastery. From raw logs to adversary infrastructure, every detail told part of the story. It wasn’t just about detection — it was about understanding the “why” behind the “what”.

> I didn’t just trace an attack — I walked in the footsteps of an adversary and outpaced them using logic, empathy for defenders, and relentless curiosity.

---

## 📣 Lockheed Martin Kill Chain - APT and Threat Picture - APT 

![Screenshot 2025-06-03 133811](https://github.com/user-attachments/assets/1eb9c7ca-24cf-437f-bd6f-c21d5d0c84eb)

![Screenshot 2025-06-03 133940](https://github.com/user-attachments/assets/d63653d3-9627-4d3e-986e-3dff4c5c8090)

