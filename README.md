# SOC Automation & AI Triage Lab

An integrated Security Operations Center (SIEM/SOAR) automation pipeline built on Ubuntu, Wazuh, and n8n. Features custom MITRE ATT&CK detection rules, VirusTotal threat intelligence enrichment, dynamic Linux firewall active response, and an Ollama-powered AI triage assistant. Includes end-to-end evidence logs, attack telemetry, and prompt-injection security evaluations.

## Architecture & Components

* **SIEM Layer:** Wazuh Manager deployed on Ubuntu, ingesting system logs, Windows Sysmon/security events, and custom detection rules.
* **SOAR Automation:** n8n workflow engine handling automated alert processing, threat intelligence lookups, and Discord routing.
* **Threat Intelligence:** Automated API queries to VirusTotal for public indicator scoring.
* **Active Response:** Dynamic execution of Linux firewall (`iptables`) drop commands via the Wazuh API based on confidence thresholds.
* **AI Triage Integration:** Local Ollama model generating automated severity ratings, summaries, and MITRE mapping.

## Repository Structure

```text
soc-repo/
├── rules/          # Custom Wazuh XML detection rules
├── ai/             # Custom Ollama AI triage integration script
├── config/         # Wazuh shared agent configurations and integrations block
├── soar/           # Exported n8n automation playbook (n8n_playbook.json)
└── evidence/       # Captured test logs, accuracy data, and prompt-injection results
