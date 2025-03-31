---
layout: post
title: Easily Manage IPTables Across Multiple Nodes with Firewall Manager
category: cybersecurity
tags: [cybersecurity, wazuh, blue team, yara, firewall, SOAR, SIEM, OpenCTI]
fullview: false
description: Streamline IPTables management across multiple nodes with Firewall Manager, seamlessly integrating with SIEM and SOAR for enhanced security and automation.
---

![Firewall](/images/dashboard-firewall.png)

# TL;DR  
Managing IPTables manually on multiple nodes was a tedious and inefficient process. Each time a threat was detected, I had to log in to individual servers to apply firewall rules manually. This approach was not scalable and introduced delays in threat response.  

To address this, I developed **Firewall Manager**, a centralized tool that integrates with **SIEM** through **SOAR**. With Firewall Manager, security teams can automate firewall rule enforcement across multiple nodes, improving efficiency and response time.  

---




# Why Firewall Manager?  

Traditional firewall management on distributed infrastructures often requires administrators to configure IPTables manually on each server. This method has several challenges:  

✅ **Time-consuming:** Manually updating IPTables on multiple nodes can be slow, especially during active incidents.  
✅ **Error-prone:** Manual configurations increase the risk of misconfigurations, potentially leaving security gaps.  
✅ **Lack of centralization:** Without a unified dashboard, monitoring and managing firewall rules across multiple servers is difficult.  
✅ **Delayed threat mitigation:** Threat actors can exploit the time gap between detection and response.  

Firewall Manager solves these problems by **automating** and **centralizing** firewall management, ensuring **faster and more accurate** responses to security threats.  

---

# How It Works  

Firewall Manager acts as an intermediary between **SIEM, SOAR, and individual nodes** running IPTables. The workflow consists of the following steps:  

### **1. Event Detection**  
- SIEM continuously monitors network traffic and logs security events.  
- When a suspicious or malicious activity is detected, an event is generated and sent to SOAR.  

### **2. Threat Analysis & Decision Making**  
- SOAR forwards the detected event to **Firewall Manager** via API.  
- Security analysts can review the event and choose to either **ignore** or **block** the detected IP.  
- If blocking is selected, Firewall Manager automatically propagates the blocking rule to the affected nodes.  

### **3. IP Blocking Mechanism**  
- Firewall Manager uses a client-server model to distribute firewall rules:  
  - **Firewall-Server:** The central control unit that manages firewall rules and communicates with SIEM and SOAR.  
  - **Firewall-Client:** Runs on each server and enforces blocking rules received from the Firewall-Server.  
- This ensures that every node updates its IPTables configuration **instantly** when a threat is identified.  

### **4. Continuous Monitoring & Logging**  
- Every action taken (ignored or blocked) is logged for security auditing.  
- Analysts can review past logs to analyze attack patterns and improve defensive strategies.  

---

# Key Features  

### **🔍 IP Region Detection**  
Firewall Manager can detect the geographical origin of an IP address using threat intelligence databases. This allows security teams to:  
✅ Identify patterns of attacks originating from specific regions.  
✅ Block traffic from high-risk countries or regions based on policies.  
✅ Gain deeper insights into attack sources for better defensive measures.  

### **🛑 Automatic IP Blocking**  
Instead of relying on manual intervention, Firewall Manager automatically blocks **malicious** and **suspicious** IPs based on real-time events from SIEM. This ensures:  
✅ **Faster** response times, reducing potential attack damage.  
✅ **Consistent** rule enforcement across all nodes.  
✅ **Minimized human error** by automating repetitive firewall tasks.  

### **🔗 Threat Intelligence Enrichment with OpenCTI**  
Firewall Manager integrates with **OpenCTI** to enrich detected threats with contextual data. When an IP is flagged as suspicious, it is cross-checked against:  
✅ Global threat intelligence feeds.  
✅ Known attack patterns and previously observed malicious activities.  
✅ Reputation scores to assess the risk level before taking action.  

This enrichment helps analysts make informed decisions and reduces false positives.  

### **📜 Comprehensive Event Logging**  
All processed events are logged in detail, providing a **complete security audit trail**. Logged data includes:  
✅ Source IP address and region information.  
✅ Actions taken (ignored, blocked, or whitelisted).  
✅ Timestamp and event metadata for forensic analysis.  

With detailed logs, security teams can analyze past attacks, fine-tune security policies, and ensure compliance with regulatory requirements.  

---

# Download Firewall Manager  

🚀 **Get started with Firewall Manager now!**  

- **Firewall Manager API**: [GitHub Repository](https://github.com/adriyansyah-mf/CentralizedFirewall.git)  
- **Firewall Manager Frontend**: [GitHub Repository](https://github.com/adriyansyah-mf/CentralizedFirewallFE.git)  
- **Firewall Manager Client (Debian Package)**: [Download `.deb`](https://github.com/adriyansyah-mf/CentralizedFirewall/releases/download/client/firewall-client_deb.deb)  

> 🔔 **Note:** This tool is still in development, and I will be adding more features and support for additional package formats like `.rpm` soon! Stay tuned for updates!  

---

# Benefits of Using Firewall Manager  

Using Firewall Manager provides several key benefits for security teams and IT administrators:  

🚀 **Rapid Threat Mitigation** – Automatically blocks malicious IPs in real time, reducing response time from minutes to seconds.  
🔄 **Centralized Firewall Management** – No need to log in to multiple servers; manage everything from one control panel.  
🔎 **Better Visibility** – Gain insights into attack sources, patterns, and high-risk regions.  
📊 **Audit-Ready Logging** – Maintain comprehensive logs for compliance and incident analysis.  
🔧 **Seamless Integration** – Works with existing SIEM & SOAR solutions without disrupting operations.  

---

# Conclusion  

Managing IPTables across multiple nodes manually is inefficient and risky. **Firewall Manager** solves this problem by **automating** and **centralizing** firewall rule management, ensuring a faster and more effective security response.  

By integrating with **SIEM, SOAR, and OpenCTI**, Firewall Manager enables security teams to:  
✅ Automate firewall rule enforcement across multiple servers.  
✅ Enrich threat data for better decision-making.  
✅ Improve visibility and auditing capabilities.  

With **real-time blocking, threat intelligence integration, and comprehensive logging**, Firewall Manager enhances **cyber defense capabilities** for modern IT infrastructures.  

If you're looking for a **scalable, automated, and efficient** way to manage IPTables across multiple nodes, **Firewall Manager is the solution you need!** 🚀  

---

# Images
Agent List:
![Firewall](/images/agent-list-firewall.png)

Event Listing:
![Firewall](/images/event-list.png)

Detail Events:
![Firewall](/images/details-events.png)

Blocked Lists:
![Firewall](/images/blocked-lists.png)


## Sponsor This Project 

If you find this project helpful, consider supporting me through GitHub Sponsors:  

[![Sponsor](https://img.shields.io/badge/Sponsor-GitHub-%23ea4aaa?style=for-the-badge&logo=github)](https://github.com/sponsors/adriyansyah-mf)

