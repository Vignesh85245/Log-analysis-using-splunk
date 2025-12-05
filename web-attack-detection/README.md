Detecting Web Attacks in Splunk Using Self-Generated Logs (Full Hands-On SOC Project)
XSS • SQL Injection • LFI • Recon • Brute Force — All Detected Using Splunk

As part of my SOC learning pathway, I wanted to understand how real attacks appear in logs — not just theory.
So instead of using pre-collected datasets, I decided to generate my own attack traffic on a Kali Linux machine, ingest it into Splunk, and build detections like a real SOC Analyst.

This project covers:

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

SQL Injection payloads

Directory Traversal / LFI

Reconnaissance scans

Rapid automated requests

Attack Script:
#!/bin/bash

# XSS
curl "http://localhost/search.php?q=<script>alert(1)</script>"

# SQL Injection
curl "http://localhost/product.php?id=1 UNION SELECT username,password FROM users"

# LFI Attacks
curl "http://localhost/index.php?page=../../../../etc/passwd"
curl "http://localhost/index.php?page=php://filter/convert.base64-encode/resource=index.php"

# Recon
curl "http://localhost/wp-admin"
curl "http://localhost/phpmyadmin"
curl "http://localhost/server-status"
curl "http://localhost/randompage123"


Then I executed it repeatedly:

for i in {1..50}; do ./attack.sh; done


This produced thousands of logs, perfect for SOC threat hunting.

3. Issues I Faced While Generating Logs (And How I Fixed Them)
    1.Permission denied while copying logs
      cp: Permission denied
      Fix: sudo cp /var/log/apache2/access.log /home/kali/access.log

    2. Log file not showing in File Manager
       Because ~ under root means /root, not /home/kali.
       Fix: Copy file correctly.

    3. Splunk misidentified sourcetype as "apache_error"
       This caused incomplete field extraction.
       Fix: Set sourcetype manually → apache:access

   4. SQLi Not Detected Initially
      Payloads were URL encoded:
      %20UNION%20SELECT
      Fix: eval decoded = urldecode(uri)

  5. "::1" Loopback IPv6 not matching regex
     I was extracting only IPv4.
     Fix: rex field=_raw "^(?<clientip>[^\s]+)"

4. Uploading Logs into Splunk

Once logs were ready:
I uploaded access.log
Chose sourcetype → apache:access
Indexed into → main

Splunk ingested:
1,737 total events

Clean, structured, searchable logs.

5. Brute Force Detection (Authentication Logs)
SPL Query
index=main "password check failed"
| rex field=_raw "user \((?<user>[^)]+)\)"
| bucket _time span=1m
| stats count by _time user host
| where count >= 5


This identified repeated failed login attempts — signature of brute-force.

6. XSS Detection
Simple keyword detection
index=main sourcetype="apache:access"
| search "<script>" OR "javascript:" OR "onerror="

Structured output
| table _time clientip method uri status useragent

Timeline (attack spikes)
| timechart span=1m count

7. SQL Injection Detection
Initial direct match
index=main sourcetype="apache:access"
| search "UNION SELECT" OR "' OR 1=1" OR "information_schema"


Detected 0 events — because payloads were encoded.

Decoded detection (working query)
index=main sourcetype="apache:access"
| rex field=_raw "\"(?<method>GET|POST) (?<uri>\S+)"
| eval decoded=urldecode(uri)
| where match(decoded,"(?i)(union|select|sleep|benchmark|outfile|load_file|1=1)")
| table _time clientip decoded


Now SQLi payloads were successfully detected.

8. Directory Traversal / LFI Detection
Basic detection
index=main sourcetype="apache:access"
| search "../" OR "/etc/passwd" OR "php://filter"


Detected → 433 LFI attempts

Stronger regex-based detection
| eval decoded=urldecode(uri)
| where match(decoded,"(\.\./|/etc/passwd|php://filter)")

Group by attacker IP
| stats count AS attempts by clientip

9. Reconnaissance Detection (Scanning Behavior)
Searching common sensitive paths
index=main sourcetype="apache:access"
| search "wp-admin" OR "phpmyadmin" OR "/admin" OR "/server-status" OR ".git"

Hits per endpoint
| stats count by uri

Scan activity per IP
| stats count AS scans by clientip

Recon timeline
| eval is_recon=if(uri LIKE "%admin%" OR uri LIKE "%phpmyadmin%" OR uri LIKE "%wp-admin%" OR uri LIKE "%server-status%",1,0)
| where is_recon=1
| timechart span=1m count


Detected scanning bursts clearly.

10. What I Learned from This Project

This hands-on lab taught me:

How real attacks appear in raw logs

Seeing the exact payloads inside access.log was eye-opening.

How to extract fields using regex (rex)

Splunk becomes powerful when logs are structured.

How to use urldecode() for encoded attacks

A real SOC technique.

How to build SOC-style detections

With time buckets, thresholds, and grouping.

How attackers perform recon

Which URLs they target first.

How to validate detection logic using timecharts

Visual spikes confirm active attacks.

How to think like a threat hunter

Focus on patterns, not individual events.

11. Final Thoughts

This project gave me a deep understanding of:

Web attack patterns

How SIEM systems detect threats

How blue teams monitor indicators

How to convert logs → insights → detections

It was one of the most practical SOC exercises I’ve done, and I’ll continue adding more attack types and detection rules.
