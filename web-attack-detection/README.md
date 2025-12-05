Detecting Web Attacks in Splunk Using Self-Generated Logs
(Full Hands-On SOC Project: XSS • SQL Injection • LFI • Recon • Brute Force)

As part of my SOC learning pathway, I wanted to understand how real attacks appear in logs — not just theory.
Instead of using pre-collected datasets, I generated my own attack traffic on a Kali Linux machine, ingested it into Splunk, and built detections like a real SOC Analyst.

📌 Project Covers

Brute-force login detection

XSS detection

SQL Injection detection

Directory Traversal / LFI detection

Reconnaissance pattern detection

Creating alerts from attack spikes

Challenges I faced & how I fixed them

1. Setting Up the Environment

I installed and started Apache:

sudo apt install apache2 -y
sudo systemctl enable apache2
sudo systemctl start apache2


Then I verified logs exist:

/var/log/apache2/access.log

2. Generating Real Attack Logs on My Own Machine

To simulate real-world adversary behavior, I wrote my own script (attack.sh) that performs:

XSS injections

SQL injection payloads

Directory Traversal / LFI

Recon scanning

Automated repeated requests

attack.sh
#!/bin/bash

# XSS
curl "http://localhost/search.php?q=<script>alert(1)</script>"

# SQL Injection
curl "http://localhost/product.php?id=1 UNION SELECT username,password FROM users"

# LFI
curl "http://localhost/index.php?page=../../../../etc/passwd"
curl "http://localhost/index.php?page=php://filter/convert.base64-encode/resource=index.php"

# Recon
curl "http://localhost/wp-admin"
curl "http://localhost/phpmyadmin"
curl "http://localhost/server-status"
curl "http://localhost/randompage123"


Executed repeatedly:

for i in {1..50}; do ./attack.sh; done

3. Issues I Faced (and Fixes)
❌ 1. Permission Denied While Copying Logs
cp: Permission denied


Fix:

sudo cp /var/log/apache2/access.log /home/kali/access.log

❌ 2. Log Not Showing in File Manager

~ under root means /root, not /home/kali.

❌ 3. Splunk Mis-Detected Sourcetype

Splunk set logs as apache_error.

Fix: Manually selected apache:access

❌ 4. SQL Injection Not Detected

Payloads were URL-encoded (%20UNION%20SELECT).

Fix:

eval decoded = urldecode(uri)

❌ 5. IPv6 (::1) Broke Regex

Fix:

rex field=_raw "^(?<clientip>[^\s]+)"

4. Uploading Logs into Splunk

Uploaded access.log

Sourcetype → apache:access

Index → main

Splunk ingested 1,737 total events.

5. Brute-Force Detection
index=main "password check failed"
| rex field=_raw "user \((?<user>[^)]+)\)"
| bucket _time span=1m
| stats count by _time user host
| where count >= 5

6. XSS Detection
index=main sourcetype="apache:access"
| search "<script>" OR "javascript:" OR "onerror="

7. SQL Injection Detection
Encoded payload fix
| eval decoded = urldecode(uri)
| where match(decoded,"(?i)(union|select|sleep|benchmark|outfile|load_file|1=1)")

8. Directory Traversal / LFI Detection
| eval decoded = urldecode(uri)
| where match(decoded,"(\.\./|/etc/passwd|php://filter)")

9. Reconnaissance Detection
index=main sourcetype="apache:access"
| search "wp-admin" OR "phpmyadmin" OR "server-status" OR "/admin"

10. What I Learned

Reading raw logs → understanding attacker behavior

Regex + field extraction in Splunk

URL decoding for encoded payloads

Building SOC-style detection rules

Time-based correlation (bucket, timechart)

Recon behavior analysis

Thinking like a threat hunter

11. Final Thoughts

This project helped me deeply understand how SIEM systems detect real-world attack patterns.
I will keep expanding this repository with:

RCE detection

Malware beaconing analysis

MITRE ATT&CK mapping

Custom dashboards
