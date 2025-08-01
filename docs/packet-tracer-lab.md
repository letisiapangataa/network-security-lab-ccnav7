# Cisco Packet Tracer Lab Instructions
# Network Security Lab - CCNAv7 Implementation

## Packet Tracer File: NetworkSecurityLab.pkt

### Device Placement and Configuration

#### Physical Topology
```
Internet Cloud
     |
[pfSense Firewall] (External - simulated)
     |
[Router 2911] (Gateway)
     |
[Switch 2960] (Core Switch)
     |
   +-+-+-+
   |   |   |
[Admin] [User] [DMZ]
 PC     PC    Server
```

### Step-by-Step Configuration

#### 1. Add Devices to Workspace
1. **Router**: Cisco 2911
   - Add to workspace
   - Turn on device
   - Connect console cable for initial config

2. **Switch**: Cisco Catalyst 2960
   - Add to workspace  
   - Turn on device
   - Connect to router via GigabitEthernet

3. **End Devices**:
   - Admin PC (VLAN 10)
   - User PC (VLAN 20)
   - DMZ Server (VLAN 30)

#### 2. Physical Connections
```
Router Gi0/0 ⟷ Switch Gi0/1 (Trunk)
Switch Fa0/1 ⟷ Admin PC (Access VLAN 10)
Switch Fa0/6 ⟷ User PC (Access VLAN 20)  
Switch Fa0/16 ⟷ DMZ Server (Access VLAN 30)
```

#### 3. Router Configuration Commands

```cisco
! Basic configuration
Router> enable
Router# configure terminal
Router(config)# hostname SecurityRouter
Router(config)# enable secret cisco123

! Configure sub-interfaces for VLANs
Router(config)# interface gigabitethernet 0/0
Router(config-if)# no shutdown
Router(config-if)# exit

! Admin VLAN 10
Router(config)# interface gigabitethernet 0/0.10
Router(config-subif)# encapsulation dot1Q 10
Router(config-subif)# ip address 192.168.10.1 255.255.255.0
Router(config-subif)# no shutdown
Router(config-subif)# exit

! User VLAN 20
Router(config)# interface gigabitethernet 0/0.20
Router(config-subif)# encapsulation dot1Q 20
Router(config-subif)# ip address 192.168.20.1 255.255.255.0
Router(config-subif)# no shutdown
Router(config-subif)# exit

! DMZ VLAN 30
Router(config)# interface gigabitethernet 0/0.30
Router(config-subif)# encapsulation dot1Q 30
Router(config-subif)# ip address 192.168.30.1 255.255.255.0
Router(config-subif)# no shutdown
Router(config-subif)# exit

! DHCP Configuration
Router(config)# ip dhcp excluded-address 192.168.10.1 192.168.10.10
Router(config)# ip dhcp excluded-address 192.168.20.1 192.168.20.10

Router(config)# ip dhcp pool ADMIN_POOL
Router(dhcp-config)# network 192.168.10.0 255.255.255.0
Router(dhcp-config)# default-router 192.168.10.1
Router(dhcp-config)# dns-server 8.8.8.8
Router(dhcp-config)# exit

Router(config)# ip dhcp pool USER_POOL
Router(dhcp-config)# network 192.168.20.0 255.255.255.0
Router(dhcp-config)# default-router 192.168.20.1
Router(dhcp-config)# dns-server 8.8.8.8
Router(dhcp-config)# exit

! Access Control Lists
Router(config)# access-list 110 permit ip 192.168.10.0 0.0.0.255 any
Router(config)# access-list 110 deny ip 192.168.20.0 0.0.0.255 192.168.10.0 0.0.0.255
Router(config)# access-list 110 permit tcp 192.168.20.0 0.0.0.255 192.168.30.0 0.0.0.255 eq 80
Router(config)# access-list 110 permit tcp 192.168.20.0 0.0.0.255 192.168.30.0 0.0.0.255 eq 443
Router(config)# access-list 110 permit ip any any

Router(config)# interface gigabitethernet 0/0.20
Router(config-subif)# ip access-group 110 in
Router(config-subif)# exit

Router(config)# exit
Router# copy running-config startup-config
```

#### 4. Switch Configuration Commands

```cisco
! Basic configuration
Switch> enable
Switch# configure terminal
Switch(config)# hostname SecuritySwitch
Switch(config)# enable secret cisco123

! Create VLANs
Switch(config)# vlan 10
Switch(config-vlan)# name ADMIN_VLAN
Switch(config-vlan)# exit

Switch(config)# vlan 20
Switch(config-vlan)# name USER_VLAN
Switch(config-vlan)# exit

Switch(config)# vlan 30
Switch(config-vlan)# name DMZ_VLAN
Switch(config-vlan)# exit

! Configure access ports
Switch(config)# interface fastethernet 0/1
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 10
Switch(config-if)# no shutdown
Switch(config-if)# exit

Switch(config)# interface fastethernet 0/6
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 20
Switch(config-if)# no shutdown
Switch(config-if)# exit

Switch(config)# interface fastethernet 0/16
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 30
Switch(config-if)# no shutdown
Switch(config-if)# exit

! Configure trunk port to router
Switch(config)# interface gigabitethernet 0/1
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk allowed vlan 10,20,30
Switch(config-if)# no shutdown
Switch(config-if)# exit

Switch(config)# exit
Switch# copy running-config startup-config
```

#### 5. End Device Configuration

**Admin PC (192.168.10.10)**
```
IP Configuration:
├── IP Address: 192.168.10.10
├── Subnet Mask: 255.255.255.0
├── Default Gateway: 192.168.10.1
└── DNS Server: 8.8.8.8
```

**User PC (192.168.20.10)**
```
IP Configuration:
├── IP Address: 192.168.20.10
├── Subnet Mask: 255.255.255.0
├── Default Gateway: 192.168.20.1
└── DNS Server: 8.8.8.8
```

**DMZ Server (192.168.30.10)**
```
IP Configuration:
├── IP Address: 192.168.30.10
├── Subnet Mask: 255.255.255.0
├── Default Gateway: 192.168.30.1
└── DNS Server: 8.8.8.8

Services Enabled:
├── HTTP Server (Port 80)
├── HTTPS Server (Port 443)
├── SSH Server (Port 22)
└── DNS Server (Port 53)
```

### Verification and Testing Commands

#### Router Verification
```cisco
! Check interface status
Router# show ip interface brief

! Verify VLAN sub-interfaces
Router# show interfaces
Router# show ip route

! Check DHCP operation
Router# show ip dhcp binding
Router# show ip dhcp conflict

! Verify ACL operation
Router# show access-lists
Router# show ip interface gigabitethernet 0/0.20
```

#### Switch Verification
```cisco
! Check VLAN configuration
Switch# show vlan brief
Switch# show vlan

! Verify trunk operation
Switch# show interfaces trunk
Switch# show interfaces gigabitethernet 0/1 switchport

! Check port assignments
Switch# show interfaces status
Switch# show mac address-table
```

#### Connectivity Testing
```cmd
! From Admin PC (should work)
C:\> ping 192.168.20.10
C:\> ping 192.168.30.10
C:\> tracert 192.168.20.10

! From User PC (restricted)
C:\> ping 192.168.10.10     # Should timeout (blocked by ACL)
C:\> ping 192.168.30.10     # Should work
C:\> telnet 192.168.30.10 80 # Should work (HTTP allowed)
C:\> telnet 192.168.30.10 22 # Should timeout (SSH blocked)

! From DMZ Server
C:\> ping 192.168.10.1      # Gateway should work
C:\> ping 192.168.10.10     # Should timeout (internal access blocked)
C:\> ping 8.8.8.8          # Internet should work
```

### Security Testing Scenarios

#### Scenario 1: VLAN Isolation Test
1. **Objective**: Verify User VLAN cannot access Admin VLAN
2. **Test**: Ping from User PC to Admin PC
3. **Expected Result**: Request timeout due to ACL blocking

#### Scenario 2: DMZ Access Control
1. **Objective**: Verify User VLAN can access web services in DMZ
2. **Test**: HTTP request from User PC to DMZ Server
3. **Expected Result**: Successful web page access

#### Scenario 3: Administrative Override
1. **Objective**: Verify Admin VLAN has full network access
2. **Test**: Access all VLANs from Admin PC
3. **Expected Result**: Successful connectivity to all networks

### Troubleshooting Guide

#### Common Issues in Packet Tracer

**Issue**: Inter-VLAN routing not working
```cisco
! Check router sub-interface configuration
Router# show interfaces summary
Router# show ip interface brief

! Verify VLAN encapsulation
Router# show interfaces gigabitethernet 0/0.10
```

**Issue**: VLAN access ports not working
```cisco
! Check VLAN assignment
Switch# show interfaces fastethernet 0/1 switchport
Switch# show vlan brief

! Verify port status
Switch# show interfaces status
```

**Issue**: Trunk not passing VLANs
```cisco
! Check trunk configuration
Switch# show interfaces gigabitethernet 0/1 trunk
Switch# show interfaces gigabitethernet 0/1 switchport

! Verify allowed VLANs
Switch# show running-config interface gigabitethernet 0/1
```

### Advanced Configuration Options

#### Port Security (Enhanced Version)
```cisco
! Configure port security on user ports
Switch(config)# interface range fastethernet 0/6-15
Switch(config-if-range)# switchport port-security
Switch(config-if-range)# switchport port-security maximum 1
Switch(config-if-range)# switchport port-security violation shutdown
Switch(config-if-range)# switchport port-security mac-address sticky
```

#### DHCP Snooping
```cisco
! Enable DHCP snooping
Switch(config)# ip dhcp snooping
Switch(config)# ip dhcp snooping vlan 20,30

! Configure trusted ports
Switch(config)# interface gigabitethernet 0/1
Switch(config-if)# ip dhcp snooping trust
```

#### Dynamic ARP Inspection
```cisco
! Enable DAI
Switch(config)# ip arp inspection vlan 20,30

! Configure trusted ports
Switch(config)# interface gigabitethernet 0/1
Switch(config-if)# ip arp inspection trust
```

### Lab Extensions

#### Extension 1: Additional VLANs
- Add Guest VLAN (40) with limited internet access
- Add Server VLAN (50) for internal services
- Implement more granular ACLs

#### Extension 2: Redundancy
- Add second switch for redundancy
- Configure spanning tree protocol
- Implement HSRP for gateway redundancy

#### Extension 3: Monitoring
- Add SNMP configuration
- Configure syslog to central server
- Implement network time protocol (NTP)

### Documentation Requirements

When completing the lab, document:
1. **Configuration commands used**
2. **Verification output from show commands**
3. **Test results and screenshots**
4. **Any issues encountered and solutions**
5. **Security implications of design choices**

This Packet Tracer lab provides hands-on experience with:
- VLAN configuration and management
- Inter-VLAN routing with router-on-a-stick
- Access control list implementation
- Network security best practices
- Troubleshooting network connectivity issues
