# Network Security Lab Setup Guide
# CCNAv7 Aligned Implementation

## Prerequisites

### Hardware Requirements
- **Minimum**: 8GB RAM, 100GB storage, dual-core processor
- **Recommended**: 16GB RAM, 250GB SSD, quad-core processor
- **Network**: 2 NICs (one for management, one for lab traffic)

### Software Requirements
- Cisco Packet Tracer (latest version)
- pfSense ISO (CE version 2.7.0 or newer)
- VirtualBox or VMware (for pfSense virtualization)
- Wireshark (latest stable release)
- Text editor (Notepad++, VS Code, or similar)

### Knowledge Prerequisites
- Basic networking concepts (OSI model, TCP/IP)
- VLAN configuration experience
- Basic Linux command line
- Familiarity with firewall concepts

---

## Lab Setup Instructions

### Phase 1: Network Infrastructure Setup

#### Step 1: Cisco Packet Tracer Configuration

1. **Create New Network Topology**
   - Open Cisco Packet Tracer
   - Create a new blank network

2. **Add Network Devices**
   ```
   Devices Required:
   - 1x Router (2911 or similar)
   - 1x Layer 2 Switch (2960 or similar)
   - 3x End Devices (PCs)
   - 1x Server (for DMZ)
   ```

3. **Physical Connections**
   - Connect Router Gi0/0 to Switch Gi0/1 (trunk)
   - Connect PCs to switch access ports:
     - Admin PC → Fa0/1 (VLAN 10)
     - User PC → Fa0/6 (VLAN 20)
     - DMZ Server → Fa0/16 (VLAN 30)

#### Step 2: VLAN Configuration

1. **Apply Switch Configuration**
   ```bash
   # Copy the vlan-config.txt content to switch CLI
   Switch> enable
   Switch# configure terminal
   Switch(config)# [paste configuration]
   ```

2. **Apply Router Configuration**
   ```bash
   # Copy the router-config.txt content to router CLI
   Router> enable
   Router# configure terminal
   Router(config)# [paste configuration]
   ```

3. **Verify VLAN Operation**
   ```bash
   # On Switch
   Switch# show vlan brief
   Switch# show interfaces trunk
   
   # On Router
   Router# show ip interface brief
   Router# show ip route
   ```

#### Step 3: Test Inter-VLAN Connectivity

1. **Configure PC IP Addresses**
   - Admin PC: 192.168.10.10/24, Gateway: 192.168.10.1
   - User PC: 192.168.20.10/24, Gateway: 192.168.20.1
   - DMZ Server: 192.168.30.10/24, Gateway: 192.168.30.1

2. **Test Connectivity**
   ```bash
   # From Admin PC (should succeed)
   ping 192.168.20.10
   ping 192.168.30.10
   
   # From User PC (should be restricted)
   ping 192.168.10.10  # Should fail
   ping 192.168.30.10  # HTTP/HTTPS only
   ```

### Phase 2: pfSense Firewall Setup

#### Step 1: pfSense Installation

1. **Virtual Machine Setup**
   - Create new VM in VirtualBox/VMware
   - Allocate 2GB RAM, 20GB storage
   - Configure 2 network adapters:
     - Adapter 1: NAT (WAN interface)
     - Adapter 2: Host-only (LAN interface)

2. **Install pfSense**
   - Boot from pfSense ISO
   - Follow installation wizard
   - Set up WAN/LAN interfaces

3. **Initial Configuration**
   ```bash
   # Access pfSense console
   # Configure WAN: DHCP or static IP
   # Configure LAN: 10.0.0.1/30
   # Set admin password
   ```

#### Step 2: pfSense Web Configuration

1. **Access Web Interface**
   - Navigate to https://10.0.0.1
   - Login with admin credentials
   - Complete setup wizard

2. **Interface Configuration**
   - Configure WAN interface (internet connection)
   - Configure LAN interface (internal network)
   - Create VLAN interfaces (if using single NIC)

3. **Apply Firewall Rules**
   - Navigate to Firewall → Rules
   - Apply rules from `pfsense-firewall-rules.txt`
   - Test rule effectiveness

#### Step 3: NAT and Port Forwarding

1. **Configure Outbound NAT**
   - Firewall → NAT → Outbound
   - Set up automatic NAT for internal networks

2. **Set Up Port Forwarding**
   - Firewall → NAT → Port Forward
   - Configure rules for DMZ services
   - Test external access to web server

### Phase 3: Snort IDS Integration

#### Step 1: Install Snort Package

1. **Package Installation**
   - System → Package Manager
   - Available Packages → Search "Snort"
   - Install Snort package

2. **Download Rule Sets**
   - Services → Snort → Global Settings
   - Configure rule update settings
   - Download initial rule sets

#### Step 2: Configure IDS Interfaces

1. **WAN Interface Configuration**
   - Services → Snort → Interface Settings
   - Add WAN interface
   - Configure according to `snort-ids-config.txt`

2. **DMZ Interface Configuration**
   - Add DMZ VLAN interface
   - Configure monitoring rules
   - Set up alerting

#### Step 3: Custom Rules and Tuning

1. **Add Custom Rules**
   - Services → Snort → Rules
   - Add custom detection rules
   - Enable appropriate rule categories

2. **Configure Alerting**
   - Set up email notifications
   - Configure syslog forwarding
   - Test alert generation

### Phase 4: Monitoring and Logging

#### Step 1: Centralized Logging

1. **Syslog Server Setup**
   - Install syslog server on admin network
   - Configure log retention policies
   - Set up log rotation

2. **Configure Log Sources**
   - pfSense: Status → System Logs → Settings
   - Router: Configure syslog destination
   - Switch: Set up logging

#### Step 2: Traffic Monitoring

1. **Wireshark Setup**
   - Install on admin workstation
   - Configure capture interfaces
   - Set up display filters

2. **Baseline Traffic Patterns**
   - Capture normal traffic for 24-48 hours
   - Document typical communication flows
   - Establish performance baselines

### Phase 5: Security Testing

#### Step 1: Vulnerability Assessment

1. **Network Scanning**
   ```bash
   # Use Nmap for network discovery
   nmap -sn 192.168.0.0/16
   nmap -sS -O 192.168.30.10
   ```

2. **Web Application Testing**
   - Test for SQL injection
   - Test for XSS vulnerabilities
   - Test authentication mechanisms

#### Step 2: Attack Simulation

1. **SSH Brute Force Test**
   ```bash
   # Use Hydra for SSH brute force
   hydra -l admin -P passwords.txt ssh://192.168.30.10
   ```

2. **Web Attack Testing**
   ```bash
   # Test SQL injection
   curl "http://192.168.30.10/search.php?q=' OR '1'='1' --"
   
   # Test XSS
   curl "http://192.168.30.10/comment.php?msg=<script>alert('XSS')</script>"
   ```

3. **Network Reconnaissance**
   ```bash
   # Port scanning from user network
   nmap -sS 192.168.10.0/24
   nmap -sS 192.168.30.0/24
   ```

#### Step 3: Incident Response Testing

1. **Simulate Security Incidents**
   - Trigger IDS alerts
   - Test automatic blocking
   - Verify log collection

2. **Response Procedures**
   - Document incident response steps
   - Test communication procedures
   - Verify evidence preservation

---

## Troubleshooting Guide

### Common Issues and Solutions

#### VLAN Connectivity Problems

**Issue**: Inter-VLAN routing not working
```bash
# Verification steps
show ip interface brief
show vlan brief
show interfaces trunk

# Common fixes
- Check trunk configuration
- Verify VLAN assignments
- Confirm router sub-interfaces
```

**Issue**: Access control not working
```bash
# Check ACL configuration
show access-lists
show ip interface [interface]

# Common fixes
- Verify ACL direction (in/out)
- Check ACL order (most specific first)
- Confirm ACL application to interface
```

#### pfSense Firewall Issues

**Issue**: Cannot access web interface
```bash
# Check interface configuration
- Verify IP addressing
- Check cable connections
- Confirm browser settings (HTTPS)
```

**Issue**: Rules not blocking traffic
```bash
# Troubleshooting steps
- Check rule order (most specific first)
- Verify interface application
- Check NAT rules interaction
- Review firewall logs
```

#### Snort IDS Problems

**Issue**: No alerts generating
```bash
# Verification steps
- Check rule downloads
- Verify interface monitoring
- Confirm rule categories enabled
- Review preprocessor settings
```

**Issue**: Too many false positives
```bash
# Tuning steps
- Add suppression rules
- Adjust rule thresholds
- Configure pass lists
- Fine-tune preprocessors
```

### Performance Optimization

#### Router Performance
```bash
# Optimize router settings
ip cef
ip route-cache
no ip domain-lookup
scheduler allocate 20000 1000
```

#### Switch Performance
```bash
# Optimize switch settings
spanning-tree mode rapid-pvst
spanning-tree portfast default
udld enable
storm-control broadcast level 10.00
```

#### pfSense Performance
```bash
# System tuning
net.inet.ip.intr_queue_maxlen=1000
net.route.netisr_maxqlen=1024
kern.ipc.maxsockbuf=2097152
net.inet.tcp.recvbuf_max=2097152
```

---

## Maintenance Procedures

### Daily Tasks
- [ ] Review security alerts
- [ ] Check system health status
- [ ] Verify backup operations
- [ ] Monitor bandwidth utilization

### Weekly Tasks
- [ ] Update Snort rule sets
- [ ] Review firewall logs
- [ ] Test backup procedures
- [ ] Analyze traffic patterns

### Monthly Tasks
- [ ] Security rule review
- [ ] Performance baseline update
- [ ] Documentation updates
- [ ] Penetration testing

### Quarterly Tasks
- [ ] Full security assessment
- [ ] Disaster recovery testing
- [ ] Hardware health check
- [ ] Training updates

---

## Documentation Standards

### Configuration Management
- All configurations stored in version control
- Change logs maintained for all modifications
- Regular configuration backups
- Documentation updates with changes

### Incident Documentation
- Detailed incident reports
- Evidence preservation procedures
- Lessons learned documentation
- Process improvement recommendations

### Performance Metrics
- Baseline measurements
- Regular performance monitoring
- Capacity planning documentation
- Trend analysis reports
