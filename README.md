# Automated-Windows-Forensics-Artifact-Extractor-WinFAE-
This repository contains WinFAE (Windows Forensic Artifact Extractor), a lightweight, incident-response triage script written in PowerShell. It is designed to be executed on a suspected compromised host to gather volatile memory-like forensics, active execution vectors, and common persistence mechanisms.

## 📌 Project Overview
During an active incident response engagement, speed is everything. Responders need to collect volatile indicators from suspected hosts without modifying system files or causing unnecessary business downtime.

**WinFAE** is a lightweight, agentless PowerShell forensic acquisition script. It extracts crucial volatile artifacts—including running processes, established network connections, persistence registries, local DNS modifications, and critical security log entries—and packages them into a structured, audit-ready **JSON payload** compressed inside a secure zip file for remote ingestion.

---

## 🏗️ Technical Architecture & Data Collection Flow
Below is the execution flow of how WinFAE targets volatile memory and persistent storage objects while running inside the kernel memory safety context:

```mermaid
graph TD
    A[Admin Execution: Get-ForensicArtifacts.ps1] --> B{Privilege Validation}
    B -- No --> C[Terminate & Alert Log]
    B -- Yes --> D[Generate Triage Folder]
    
    subgraph Live Extraction Engine
        D --> E[01 System Metadata]
        D --> F[02 Volatile Processes + SHA-256]
        D --> G[03 Network Connections + PID Mapping]
        D --> H[04 Run/RunOnce Registry Keys]
        D --> I[05 Custom Scheduled Tasks]
        D --> J[06 DNS Hosts File]
        D --> K[07 Event Log Extracts: Event ID 4624/4688]
    end
    
    E & F & G & H & I & J & K --> L[Convert to JSON]
    L --> M[Zip Compression & Archive Generation]
    M --> N[Secure Transmission to Incident Response Server]


