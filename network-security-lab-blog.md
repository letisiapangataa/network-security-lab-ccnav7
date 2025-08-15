# Building a Network Security Lab: A CCNAv7-Aligned Guide

## Introduction

In today’s digital landscape, understanding network security is essential for IT professionals and students alike. This blog post walks you through the design and implementation of a hands-on network security lab, aligned with the CCNAv7 curriculum. The lab simulates a real-world enterprise environment, complete with VLAN segmentation, firewall protection, intrusion detection, and secure network management.

## Lab Topology Overview

The lab is structured to provide a comprehensive learning experience, covering key security concepts and best practices. Here’s a high-level overview of the network topology:

- **Internet**: Simulated external network for testing perimeter security.
- **pfSense Firewall**: Acts as the primary security gateway, integrating Snort IDS for intrusion detection.
- **Cisco Router (Router-on-a-Stick)**: Handles inter-VLAN routing and serves as the gateway for internal networks.
- **Cisco Catalyst Switch**: Provides Layer 2 switching and VLAN segmentation.
- **VLANs**:
  - VLAN 10: Admin (192.168.10.0/24)
  - VLAN 20: Users (192.168.20.0/24)
  - VLAN 30: DMZ (192.168.30.0/24)
  - VLAN 99: Management
- **End Devices**: Admin PCs, User PCs, Web Server, DNS Server, File Server.

## Network Diagram

![Network Topology Diagram](diagrams/vlan-topology.txt)

*For a graphical version, import the topology into draw.io or your preferred diagramming tool.*

## Key Security Features

- **Firewall Protection**: pfSense is configured with strict rules to control inbound and outbound traffic.
- **Intrusion Detection**: Snort IDS monitors network traffic for suspicious activity and potential threats.
- **VLAN Segmentation**: Separates network traffic by department and function, reducing the attack surface.
- **DMZ Implementation**: Hosts public-facing services in a separate VLAN to isolate them from internal resources.
- **Network Management**: Dedicated VLAN for secure management access to network devices.

## Lab Setup Steps

1. **Configure VLANs** on the Cisco switch and assign ports to the appropriate VLANs.
2. **Set up the router** for inter-VLAN routing (Router-on-a-Stick configuration).
3. **Deploy pfSense** as the network firewall and integrate Snort IDS.
4. **Apply firewall rules** to restrict and monitor traffic between VLANs and the Internet.
5. **Connect and configure end devices** in their respective VLANs.
6. **Test connectivity and security policies** to ensure proper segmentation and protection.

## Learning Outcomes

By completing this lab, you will:

- Gain practical experience with VLANs, firewalls, and IDS/IPS.
- Understand the principles of network segmentation and defense-in-depth.
- Learn how to secure network management and public-facing services.
- Develop troubleshooting skills in a controlled, hands-on environment.

## Conclusion

This network security lab provides a robust platform for learning and experimentation. Whether you’re preparing for CCNAv7 certification or seeking to enhance your cybersecurity skills, this lab setup offers valuable, real-world experience.

---

*Explore the repository for configuration files, setup guides, and analysis scripts to get started!*
