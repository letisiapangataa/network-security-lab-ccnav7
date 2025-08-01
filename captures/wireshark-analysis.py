# Wireshark Analysis Scripts
# Network Security Lab - Traffic Analysis Automation

# Python script for automated packet analysis
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict, Counter
import ipaddress
import base64
import re

class NetworkTrafficAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.connections = defaultdict(int)
        self.protocols = Counter()
        self.suspicious_activities = []
        
    def load_packets(self):
        """Load packets from PCAP file"""
        try:
            capture = pyshark.FileCapture(self.pcap_file)
            for packet in capture:
                self.packets.append(packet)
                self.analyze_packet(packet)
            capture.close()
            print(f"Loaded {len(self.packets)} packets from {self.pcap_file}")
        except Exception as e:
            print(f"Error loading PCAP file: {e}")
    
    def analyze_packet(self, packet):
        """Analyze individual packet for security indicators"""
        try:
            # Count protocols
            if hasattr(packet, 'highest_layer'):
                self.protocols[packet.highest_layer] += 1
            
            # Analyze TCP connections
            if hasattr(packet, 'tcp'):
                src_ip = packet.ip.src if hasattr(packet, 'ip') else 'Unknown'
                dst_ip = packet.ip.dst if hasattr(packet, 'ip') else 'Unknown'
                dst_port = packet.tcp.dstport
                connection = f"{src_ip}:{dst_ip}:{dst_port}"
                self.connections[connection] += 1
                
                # Detect potential attacks
                self.detect_port_scan(src_ip, dst_ip, dst_port)
                self.detect_brute_force(packet)
            
            # Analyze HTTP traffic
            if hasattr(packet, 'http'):
                self.analyze_http_traffic(packet)
            
            # Analyze DNS traffic
            if hasattr(packet, 'dns'):
                self.analyze_dns_traffic(packet)
                
        except Exception as e:
            print(f"Error analyzing packet: {e}")
    
    def detect_port_scan(self, src_ip, dst_ip, dst_port):
        """Detect potential port scanning activity"""
        # Simple port scan detection based on connection patterns
        src_connections = [conn for conn in self.connections.keys() if conn.startswith(src_ip)]
        unique_ports = set([conn.split(':')[2] for conn in src_connections])
        
        if len(unique_ports) > 10:  # More than 10 different ports
            self.suspicious_activities.append({
                'type': 'Port Scan',
                'source': src_ip,
                'target': dst_ip,
                'ports': len(unique_ports),
                'severity': 'Medium'
            })
    
    def detect_brute_force(self, packet):
        """Detect brute force login attempts"""
        if hasattr(packet, 'tcp') and hasattr(packet, 'ip'):
            # SSH brute force detection
            if packet.tcp.dstport == '22':
                src_ip = packet.ip.src
                ssh_attempts = [conn for conn in self.connections.keys() 
                              if conn.startswith(src_ip) and conn.endswith(':22')]
                
                if len(ssh_attempts) > 5:  # More than 5 SSH attempts
                    self.suspicious_activities.append({
                        'type': 'SSH Brute Force',
                        'source': src_ip,
                        'attempts': len(ssh_attempts),
                        'severity': 'High'
                    })
    
    def analyze_http_traffic(self, packet):
        """Analyze HTTP traffic for web attacks"""
        try:
            if hasattr(packet.http, 'request_uri'):
                uri = packet.http.request_uri.lower()
                
                # SQL Injection detection
                sql_patterns = ['union', 'select', 'drop', 'insert', '--', ';']
                if any(pattern in uri for pattern in sql_patterns):
                    self.suspicious_activities.append({
                        'type': 'SQL Injection',
                        'source': packet.ip.src if hasattr(packet, 'ip') else 'Unknown',
                        'uri': uri,
                        'severity': 'High'
                    })
                
                # XSS detection
                xss_patterns = ['<script', 'javascript:', 'alert(', 'onerror=']
                if any(pattern in uri for pattern in xss_patterns):
                    self.suspicious_activities.append({
                        'type': 'XSS Attack',
                        'source': packet.ip.src if hasattr(packet, 'ip') else 'Unknown',
                        'uri': uri,
                        'severity': 'Medium'
                    })
                
                # Directory traversal detection
                if '../' in uri or '..\\' in uri:
                    self.suspicious_activities.append({
                        'type': 'Directory Traversal',
                        'source': packet.ip.src if hasattr(packet, 'ip') else 'Unknown',
                        'uri': uri,
                        'severity': 'Medium'
                    })
        except AttributeError:
            pass
    
    def analyze_dns_traffic(self, packet):
        """Analyze DNS traffic for tunneling and suspicious queries"""
        try:
            if hasattr(packet.dns, 'qry_name'):
                domain = packet.dns.qry_name.lower()
                
                # DNS tunneling detection (long subdomains with base64)
                subdomains = domain.split('.')
                for subdomain in subdomains:
                    if len(subdomain) > 20:  # Unusually long subdomain
                        try:
                            # Check if it's base64 encoded
                            base64.b64decode(subdomain)
                            self.suspicious_activities.append({
                                'type': 'DNS Tunneling',
                                'source': packet.ip.src if hasattr(packet, 'ip') else 'Unknown',
                                'domain': domain,
                                'severity': 'High'
                            })
                        except:
                            pass
                
                # Suspicious domain patterns
                suspicious_domains = ['malicious.com', 'evil.org', 'badactor.net']
                if any(sus_domain in domain for sus_domain in suspicious_domains):
                    self.suspicious_activities.append({
                        'type': 'Suspicious Domain',
                        'source': packet.ip.src if hasattr(packet, 'ip') else 'Unknown',
                        'domain': domain,
                        'severity': 'Medium'
                    })
        except AttributeError:
            pass
    
    def generate_statistics(self):
        """Generate traffic statistics"""
        stats = {
            'total_packets': len(self.packets),
            'protocols': dict(self.protocols.most_common()),
            'top_connections': dict(Counter(self.connections).most_common(10)),
            'suspicious_activities': len(self.suspicious_activities),
            'security_events': self.suspicious_activities
        }
        return stats
    
    def create_visualizations(self):
        """Create traffic visualization charts"""
        # Protocol distribution pie chart
        plt.figure(figsize=(12, 8))
        
        plt.subplot(2, 2, 1)
        protocols = dict(self.protocols.most_common(5))
        plt.pie(protocols.values(), labels=protocols.keys(), autopct='%1.1f%%')
        plt.title('Top 5 Protocols Distribution')
        
        # Top connections bar chart
        plt.subplot(2, 2, 2)
        top_conns = dict(Counter(self.connections).most_common(10))
        plt.bar(range(len(top_conns)), list(top_conns.values()))
        plt.title('Top 10 Connections by Packet Count')
        plt.xticks(range(len(top_conns)), list(top_conns.keys()), rotation=45, ha='right')
        
        # Security events by type
        plt.subplot(2, 2, 3)
        event_types = Counter([event['type'] for event in self.suspicious_activities])
        if event_types:
            plt.bar(event_types.keys(), event_types.values())
            plt.title('Security Events by Type')
            plt.xticks(rotation=45, ha='right')
        
        # Severity distribution
        plt.subplot(2, 2, 4)
        severities = Counter([event['severity'] for event in self.suspicious_activities])
        if severities:
            colors = {'High': 'red', 'Medium': 'orange', 'Low': 'yellow'}
            bar_colors = [colors.get(sev, 'blue') for sev in severities.keys()]
            plt.bar(severities.keys(), severities.values(), color=bar_colors)
            plt.title('Security Events by Severity')
        
        plt.tight_layout()
        plt.savefig('traffic_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()
    
    def export_report(self, filename='analysis_report.txt'):
        """Export analysis report to file"""
        stats = self.generate_statistics()
        
        with open(filename, 'w') as f:
            f.write("Network Traffic Analysis Report\n")
            f.write("=" * 40 + "\n\n")
            
            f.write(f"Total Packets Analyzed: {stats['total_packets']}\n")
            f.write(f"Total Security Events: {stats['suspicious_activities']}\n\n")
            
            f.write("Protocol Distribution:\n")
            for protocol, count in stats['protocols'].items():
                percentage = (count / stats['total_packets']) * 100
                f.write(f"  {protocol}: {count} packets ({percentage:.1f}%)\n")
            
            f.write("\nTop Connections:\n")
            for connection, count in stats['top_connections'].items():
                f.write(f"  {connection}: {count} packets\n")
            
            f.write("\nSecurity Events:\n")
            for event in stats['security_events']:
                f.write(f"  [{event['severity']}] {event['type']}")
                if 'source' in event:
                    f.write(f" from {event['source']}")
                if 'uri' in event:
                    f.write(f" - URI: {event['uri']}")
                if 'domain' in event:
                    f.write(f" - Domain: {event['domain']}")
                f.write("\n")
        
        print(f"Report exported to {filename}")

# Usage example
if __name__ == "__main__":
    # Analyze different capture files
    capture_files = [
        "ssh-brute-force-attack.pcap",
        "web-application-attack.pcap", 
        "internal-lateral-movement.pcap",
        "dns-tunneling-detection.pcap"
    ]
    
    for pcap_file in capture_files:
        print(f"\nAnalyzing {pcap_file}...")
        analyzer = NetworkTrafficAnalyzer(pcap_file)
        analyzer.load_packets()
        
        # Generate statistics and visualizations
        stats = analyzer.generate_statistics()
        print(f"Found {stats['suspicious_activities']} security events")
        
        # Export detailed report
        report_name = f"{pcap_file.replace('.pcap', '')}_analysis.txt"
        analyzer.export_report(report_name)
        
        # Create visualizations
        chart_name = f"{pcap_file.replace('.pcap', '')}_charts.png"
        analyzer.create_visualizations()
    
    print("\nAnalysis complete. Check generated reports and charts.")
