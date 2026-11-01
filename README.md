# Mirage

Mirage is an adaptive honeypot that imitates real HTTP services (a REST API, an admin panel, an OpenAI-compatible endpoint). It uses a hybrid LLM architecture (a local model plus a stronger one) to generate believable, session-consistent responses, classifies attacker sessions, maps behaviour to MITRE ATT&CK and exports IoCs as STIX 2.1 / MISP.
