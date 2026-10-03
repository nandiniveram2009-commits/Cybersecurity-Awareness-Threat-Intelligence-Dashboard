
#Cybersecurity Awareness & Threat Intelligence Dashboard


## Overview 

The Cybersecurity Awareness & Threat Intelligence Dashboard is a comprehensive, enterprise-grade defensive security platform. It bridges the gap between machine-speed technical threat intelligence and human-centric cybersecurity education. By ingesting threat feeds, validating Indicators of Compromise (IOCs), scoring risk and confidence, and mapping adversary behaviors to MITRE ATT&CK, the platform empowers Security Operations Center (SOC) analysts, incident responders, and IT administrators. Simultaneously, it educates everyday users and students through integrated awareness modules, interactive quizzes, and personalized learning recommendations.
## Problem statement 

Modern Security Operations Centers (SOCs) and IT teams are constantly overwhelmed by floods of disconnected alerts, unverified threat intelligence feeds, and uncontextualized Common Vulnerabilities and Exposures (CVEs). Simultaneously, organizations suffer from a critical human firewall vulnerability: employees falling victim to phishing, social engineering, and poor credential hygiene. Disconnected technical defense and security awareness training lead to slower incident response times, alert fatigue, patch delays, and preventable enterprise breaches.
##  Objectives 

Build a Unified Dashboard: Ingest, normalize, and enrich threat intelligence feeds containing IOCs, CVEs, and trending malware TTPs.

Implement Rigorous IOC Validation & Enrichment: Verify the syntactic validity of IPs, domains, URLs, file hashes, and CVE identifiers safely without interacting with live malicious infrastructure.

Calculate Multi-Factor Risk & Confidence Scores: Deliver objective 0–100 risk and confidence ratings to help analysts prioritize triage queues.

Map Adversary TTPs: Categorize threats against the MITRE ATT&CK framework to understand how adversaries operate.

Promote Organizational Resilience: Combine technical telemetry with an interactive Cybersecurity Awareness Center and scoring quiz engine to reduce human error.
## Cybersecurity Relevance 

Modern enterprises, financial institutions, healthcare providers, and academic universities rely on integrated CTI platforms to maintain situational awareness. This project demonstrates practical competencies for key cybersecurity roles:
SOC Analyst: Triage alerts, investigate IOCs, and manage investigation queues.
Threat Intelligence Analyst: Ingest, parse, and enrich threat feeds with source reliability ratings.
Incident Response Analyst: Trace threat timelines and examine correlated indicator clusters.
Security Awareness Specialist: Evaluate user awareness scores and assign targeted learning recommendations.
Vulnerability Analyst: Prioritize CVE remediation using contextual asset criticality and exposure weights.
## Feature 

IOC Search Tool: Instantly query synthetic indicators across local datasets without network exposure.
Interactive SOC Dashboard: Real-time analytics charts and statistics on threat trends, severities, and categories.
Threat Detail Views: Deep dive into individual threat records, associated indicators, and analyst notes.
Vulnerability & CVE Manager: Prioritize software patching beyond basic CVSS scores.
Security Awareness Center: 14+ educational modules covering phishing, passwords, MFA, and ransomware.
Interactive Quiz Engine: 30+ scenario-based questions with instant scoring and tailored module recommendations.
Executive Summary View: Non-technical management overview highlighting key organizational risks and trends.
## Architecture 

[Synthetic/Public Defensive Threat Data]
                   │
                   ▼
         [Data Ingestion Layer]
                   │
                   ▼
            [Normalization]
                   │
                   ▼
      [IOC Validation & Extraction]
                   │
                   ▼
          [Threat Enrichment]
                   │
                   ▼
      [Risk + Confidence Engine]
                   │
                   ▼
         [Correlation Engine]
                   │
          ┌────────┴────────┐
          ▼                 ▼
   [Alert Engine]    [ATT&CK Mapper]
          │                 │
          └────────┬────────┘
                   ▼
            [SOC Dashboard]
                   │
                   ▼
         [Analyst / User View]
## Technology stack

Frontend: HTML5, CSS3, JavaScript (Fetch API, responsive modern layout).

Backend: Python Flask REST API service.

Data Processing: Pandas for threat dataset analytics.

Storage: CSV flat-file synthetic intelligence database with SQLite relational schema support.
## Thread Intelligence 

Threat intelligence is evidence-based knowledge about adversary motives, targets, and attack behaviors. This platform treats threat intelligence as structured data, ensuring analysts have instant access to contextual historical records (first seen, last seen, source reliability, and frequency) during an active investigation.
## Thread Intelligence types

Strategic Threat Intelligence: High-level trends and adversary motivations for executive leadership.
Tactical Threat Intelligence: Details regarding adversary TTPs and phishing indicators used for SOC triage.
Operational Threat Intelligence: Campaign-specific intelligence regarding targeted attacks.
Technical Threat Intelligence: Machine-readable IOCs (IPs, domains, hashes) integrated into defensive controls.
## IOC analysis 
An Indicator of Compromise (IOC) is an forensic artifact indicating potential intrusion.

Important Limitation: An IOC match ≠ an automatic confirmed compromise. Indicators can be recycled, stale, or shared by benign infrastructure.

IOC Lifecycle: Observed →Validated→
 Enriched → Scored → Investigated →
 Monitored → Expired/Closed.


## Thread enrichment 


Enrichment appends rich contextual metadata to raw indicators. When an indicator is searched, the enrichment engine pulls historical sighting frequency, associated threat categories, confidence levels, and MITRE mappings from local storage without executing network queries.
## Risk scoring 

The risk scoring engine computes a 0–100 score based on:

Severity (30%)
Confidence (25%)
Observation Frequency (25%)
Source Reliability (20%)
Classifications: 0–20 (Informational), 21–40 (Low), 41–60 (Medium), 61–80 (High), 81–100 (Critical).
## Confidence scoring 

Risk Score: Evaluates how potentially damaging or concerning an event or indicator may be.
Confidence Score: Evaluates how trustworthy and verified the underlying intelligence source is. High risk + low confidence indicates potential noise requiring analyst verification.
## Thread Correlation 

The correlation engine groups disparate indicators, alerts, and threat observations sharing campaign IDs, time windows, or categories into cohesive Threat Clusters, reducing alert fatigue and highlighting multi-stage campaigns.
## MITRE ATT&CK

Adversary behaviors are mapped using MITRE ATT&CK:

Tactic: The adversary's tactical goal ("Why").
Technique: The method used to achieve the goal ("How").

Mapping: Synthetic records link specific phishing, credential theft, and malware categories to standard ATT&CK technique IDs (e.g., T1566 - Phishing).

## Vulnerability  Awareness 

Tracks CVE entries and calculates vulnerability remediation priority scores by synthesizing CVSS base scores with asset criticality, internet exposure status, and active exploitation evidence.
## Alerts management 

Generates alerts based on risk thresholds, high-priority vulnerabilities, and repeated observations. Integrates alert deduplication and correlation to prevent analyst alert fatigue during high-volume indicator floods.
## SOC workflow

Tier-1 SOC analysts follow a structured lifecycle:
Threat Feed →IOC Detection → Validation → Enrichment → Scoring →Alert → SOC Queue → Triage → Resolution→ Documentation.
## Cybersecurity awareness centre 

An educational hub providing modules on Phishing, Password Security, MFA, Social Engineering, Ransomware, Safe Browsing, Secure Wi-Fi, Software Updates, Data Privacy, Mobile Security, Remote Work Security, Cloud Account Security, Incident Reporting, and AI Scam Awareness. 
## Awareness quiz 

A 30+ question interactive testing suite evaluating user competency across core awareness domains with immediate feedback, explanations, and score breakdowns.
## Executive dashboard 

A simplified, non-technical management view displaying overall threat landscape metrics, critical threat counts, vulnerability exposure summaries, awareness score trends, and recommended defensive budget and policy priorities.
## API documentation 


## Previcy vs security 

Defensive Boundary: Never automatically visits suspicious URLs or interacts with active malware.
Input Validation: Strict regex and type checking on all API endpoints.
Environment Configuration: Sensitive parameters handled via environment variables (.env).
## Results 

Successfully implements a fully functional, offline-capable defensive CTI dashboard and awareness platform containing 2,000+ synthetic threat records, robust IOC validation engines, risk scoring algorithms, and interactive educational modules.
## Limitations 

Relies on synthetic or public demo datasets rather than real-time commercial threat intelligence API feeds (e.g., VirusTotal, MISP).

Correlation is rule-based rather than utilizing advanced machine learning anomaly detection.
## Future improvement 

Integration with MISP (Malware Information Sharing Platform) and STIX/TAXII feed parsers.

Role-Based Access Control (RBAC) for Senior SOC Analysts vs. General Users.

Live EDR (Endpoint Detection and Response) telemetry webhook ingestion.
## Learning outcomes 

Mastered Python backend development with Flask REST APIs.

Gained deep practical knowledge of SOC workflows, CTI lifecycle, and IOC validation.

Developed responsive frontend data visualizations for cybersecurity metrics.
## Disclaimer 

This project is designed exclusively for defensive cybersecurity education, threat-intelligence analysis, and security awareness. It does not execute, deploy, or interact with malicious payloads or unauthorized systems.
## Author

* **GitHub:** [nandiniveram2009](https://github.com)
* **LinkedIn:** [Nandini Verma](https://linkedin.com)



## Risk scoring 

The risk scoring engine computes a 0–100 score based on:

Severity (30%)
Confidence (25%)
Observation Frequency (25%)
Source Reliability (20%)
Classifications: 0–20 (Informational), 21–40 (Low), 41–60 (Medium), 61–80 (High), 81–100 (Critical).
## API documentation 


## API documentation 


## Limitations 

Relies on synthetic or public demo datasets rather than real-time commercial threat intelligence API feeds (e.g., VirusTotal, MISP).

Correlation is rule-based rather than utilizing advanced machine learning anomaly detection.
## API documentation 

