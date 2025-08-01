# Sample Network Captures Analysis
# Network Security Lab - CCNAv7 Aligned

## Capture File: ssh-brute-force-attack.pcap

### Attack Scenario
- **Source IP**: 203.0.113.50 (External attacker)
- **Target IP**: 192.168.30.10 (DMZ Web Server)
- **Attack Type**: SSH Brute Force
- **Duration**: 15 minutes
- **Total Packets**: 2,847 packets

### Attack Timeline
```
Time     Source          Destination     Protocol  Info
10:15:23 203.0.113.50   192.168.30.10   TCP       SSH connection attempt 1
10:15:24 203.0.113.50   192.168.30.10   SSH       Login: admin/password
10:15:25 192.168.30.10  203.0.113.50    SSH       Authentication failed
10:15:26 203.0.113.50   192.168.30.10   SSH       Login: admin/123456
10:15:27 192.168.30.10  203.0.113.50    SSH       Authentication failed
10:15:28 203.0.113.50   192.168.30.10   SSH       Login: root/password
10:15:29 192.168.30.10  203.0.113.50    SSH       Authentication failed
...
[Pattern continues with common username/password combinations]
...
10:18:45 203.0.113.50   192.168.30.10   TCP       Connection blocked by firewall
```

### Key Observations
1. **Attack Pattern**: Sequential login attempts with common credentials
2. **Rate**: 3-4 attempts per second
3. **Usernames Tried**: admin, root, user, administrator, guest
4. **Passwords Tried**: password, 123456, admin, root, qwerty
5. **IDS Response**: Snort detected pattern after 5th attempt
6. **Firewall Action**: Source IP blocked after 10 failed attempts

### Wireshark Analysis Commands
```bash
# Filter SSH traffic
tcp.port == 22

# Filter failed authentication
ssh and tcp.flags.reset == 1

# Count connection attempts per minute
frame.time_relative >= 0 and frame.time_relative <= 60

# Show unique source IPs attempting SSH
tcp.port == 22 and tcp.flags.syn == 1
```

### Snort IDS Alerts Generated
```
[**] [1:1000001:1] SSH Brute Force Attempt [**]
[Classification: Attempted Administrator Privilege Gain] 
[Priority: 1]
{TCP} 203.0.113.50:54321 -> 192.168.30.10:22

[**] [1:1000002:1] Multiple SSH Connection Attempts [**]
[Classification: Detection of a Network Scan] 
[Priority: 2]
{TCP} 203.0.113.50:54322 -> 192.168.30.10:22
```

---

## Capture File: web-application-attack.pcap

### Attack Scenario
- **Source IP**: 203.0.113.75 (External attacker)
- **Target IP**: 192.168.30.10 (DMZ Web Server)
- **Attack Type**: SQL Injection + XSS
- **Duration**: 8 minutes
- **Total Packets**: 1,234 packets

### Attack Details
```
Time     Method  URI                                      Attack Type
14:22:10 GET     /login.php?user=admin&pass=admin        Normal login
14:22:15 GET     /login.php?user=admin'--&pass=test      SQL Injection
14:22:18 POST    /search.php                              SQL Injection
                 Data: query='; DROP TABLE users; --
14:22:25 GET     /comment.php?msg=<script>alert('XSS')</script>  XSS
14:22:30 POST    /upload.php                              File Upload
                 Content: malicious.php
```

### Malicious Payloads Detected
1. **SQL Injection Attempts**:
   - `' OR '1'='1' --`
   - `'; DROP TABLE users; --`
   - `UNION SELECT username,password FROM users`

2. **Cross-Site Scripting (XSS)**:
   - `<script>alert('XSS')</script>`
   - `<img src=x onerror=alert('XSS')>`
   - `javascript:alert('XSS')`

3. **Directory Traversal**:
   - `../../../etc/passwd`
   - `..\..\..\..\windows\system32\config\sam`

### Server Responses
```
HTTP/1.1 500 Internal Server Error
Content-Type: text/html
Content-Length: 1234

<html><body>
MySQL Error: You have an error in your SQL syntax
Warning: mysql_query() expects parameter 1 to be string
</body></html>
```

---

## Capture File: internal-lateral-movement.pcap

### Attack Scenario
- **Source IP**: 192.168.20.45 (Compromised user workstation)
- **Target IPs**: Various internal hosts
- **Attack Type**: Network reconnaissance and lateral movement
- **Duration**: 25 minutes
- **Total Packets**: 5,678 packets

### Reconnaissance Activities
```
Time     Source          Destination     Protocol  Activity
15:45:10 192.168.20.45  192.168.10.1    ICMP      Ping sweep - Admin network
15:45:11 192.168.20.45  192.168.10.2    ICMP      Ping sweep
15:45:12 192.168.20.45  192.168.10.3    ICMP      Ping sweep
...
15:47:30 192.168.20.45  192.168.10.100  TCP       Port scan - Common ports
15:47:31 192.168.20.45  192.168.10.100  TCP       SYN to 22/tcp (SSH)
15:47:32 192.168.20.45  192.168.10.100  TCP       SYN to 23/tcp (Telnet)
15:47:33 192.168.20.45  192.168.10.100  TCP       SYN to 80/tcp (HTTP)
15:47:34 192.168.20.45  192.168.10.100  TCP       SYN to 443/tcp (HTTPS)
15:47:35 192.168.20.45  192.168.10.100  TCP       SYN to 3389/tcp (RDP)
```

### Blocked Attempts (Firewall Logs)
```
15:47:30 DENY 192.168.20.45:54321 -> 192.168.10.100:22 TCP
15:47:31 DENY 192.168.20.45:54322 -> 192.168.10.100:23 TCP
15:47:32 DENY 192.168.20.45:54323 -> 192.168.10.100:3389 TCP
```

---

## Capture File: dns-tunneling-detection.pcap

### Attack Scenario
- **Source IP**: 192.168.30.10 (DMZ server)
- **Target IP**: 8.8.8.8 (Google DNS)
- **Attack Type**: DNS Tunneling (Data Exfiltration)
- **Duration**: 45 minutes
- **Total Packets**: 8,901 packets

### Suspicious DNS Queries
```
Time     Query Type  Domain Name                           Length
16:10:15 TXT         aGVsbG8gd29ybGQ.malicious.com        45 bytes
16:10:16 TXT         dGhpcyBpcyBhIHRlc3Q.malicious.com    48 bytes
16:10:17 TXT         c2VjcmV0IGRhdGE.malicious.com        42 bytes
```

### Analysis Results
- **Encoded Data**: Base64 encoded strings in subdomain
- **Query Frequency**: 1 query every 2-3 seconds
- **Data Pattern**: Consistent payload sizes
- **Domain**: Recently registered suspicious domain

### Decoded Content
```bash
# Base64 decoding reveals:
aGVsbG8gd29ybGQ = "hello world"
dGhpcyBpcyBhIHRlc3Q = "this is a test"
c2VjcmV0IGRhdGE = "secret data"
```

---

## Analysis Tools and Techniques

### Wireshark Filters for Security Analysis
```bash
# Detect port scans
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024

# Find failed login attempts
ssh and tcp.flags.reset==1

# Detect large file transfers
tcp.len > 1460

# Find suspicious DNS queries
dns.qry.name contains "base64" or dns.qry.name contains "encoded"

# Detect SQL injection patterns
http.request.uri contains "union" or http.request.uri contains "select"

# Find XSS attempts
http.request.uri contains "script" or http.request.uri contains "alert"

# Detect password attacks
http.request.method == "POST" and http.content_type == "application/x-www-form-urlencoded"
```

### Statistical Analysis
```
Traffic Distribution by Protocol:
├── TCP: 78.4% (Web, SSH, Database)
├── UDP: 15.2% (DNS, DHCP, SNMP)
├── ICMP: 4.1% (Ping, Traceroute)
├── Other: 2.3% (ARP, STP, LLDP)

Top Talkers by Volume:
├── 192.168.30.10 (Web Server): 45.2GB
├── 192.168.20.45 (User PC): 12.1GB
├── 192.168.10.100 (Admin Server): 8.7GB

Security Events Detected:
├── Brute Force Attacks: 23 incidents
├── Web Application Attacks: 17 incidents
├── Port Scans: 41 incidents
├── Malware Communication: 8 incidents
├── Policy Violations: 156 incidents
```

### Incident Response Actions
1. **Immediate Response**:
   - Block suspicious source IPs
   - Isolate compromised systems
   - Preserve evidence (packet captures)

2. **Investigation**:
   - Analyze attack vectors
   - Identify data accessed
   - Determine impact scope

3. **Recovery**:
   - Patch vulnerabilities
   - Update security policies
   - Strengthen monitoring

4. **Lessons Learned**:
   - Update incident procedures
   - Enhance security training
   - Improve detection rules
