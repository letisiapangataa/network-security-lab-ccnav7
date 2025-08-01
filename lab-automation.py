# Network Security Lab - Utility Scripts
# Automation tools for lab management and monitoring

import subprocess
import json
import csv
import datetime
import socket
import threading
import time
import os
from ipaddress import IPv4Network, IPv4Address

class NetworkSecurityLabManager:
    def __init__(self):
        self.networks = {
            'admin': '192.168.10.0/24',
            'user': '192.168.20.0/24', 
            'dmz': '192.168.30.0/24'
        }
        self.critical_hosts = {
            'router': '192.168.10.1',
            'admin_pc': '192.168.10.10',
            'user_pc': '192.168.20.10',
            'dmz_server': '192.168.30.10',
            'pfsense': '10.0.0.1'
        }
        self.test_results = []

    def ping_host(self, host, count=4):
        """Ping a host and return success rate"""
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(['ping', '-n', str(count), host], 
                                      capture_output=True, text=True, timeout=30)
            else:  # Linux/Unix
                result = subprocess.run(['ping', '-c', str(count), host], 
                                      capture_output=True, text=True, timeout=30)
            
            success = result.returncode == 0
            return {'host': host, 'success': success, 'output': result.stdout}
        except subprocess.TimeoutExpired:
            return {'host': host, 'success': False, 'output': 'Timeout'}
        except Exception as e:
            return {'host': host, 'success': False, 'output': str(e)}

    def scan_network(self, network):
        """Scan a network for active hosts"""
        active_hosts = []
        net = IPv4Network(network)
        
        def ping_worker(host):
            result = self.ping_host(str(host), count=1)
            if result['success']:
                active_hosts.append(str(host))
        
        threads = []
        for host in net.hosts():
            thread = threading.Thread(target=ping_worker, args=(host,))
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= 50:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for thread in threads:
            thread.join()
        
        return active_hosts

    def test_connectivity_matrix(self):
        """Test connectivity between all VLANs according to security policy"""
        test_matrix = [
            # Source, Destination, Expected Result, Description
            ('192.168.10.10', '192.168.20.10', True, 'Admin to User (should work)'),
            ('192.168.10.10', '192.168.30.10', True, 'Admin to DMZ (should work)'),
            ('192.168.20.10', '192.168.10.10', False, 'User to Admin (should be blocked)'),
            ('192.168.20.10', '192.168.30.10', True, 'User to DMZ (should work for web)'),
            ('192.168.30.10', '192.168.10.10', False, 'DMZ to Admin (should be blocked)'),
            ('192.168.30.10', '192.168.20.10', False, 'DMZ to User (should be blocked)'),
        ]
        
        results = []
        for source, destination, expected, description in test_matrix:
            print(f"Testing: {description}")
            result = self.ping_host(destination)
            actual = result['success']
            
            test_result = {
                'source': source,
                'destination': destination,
                'expected': expected,
                'actual': actual,
                'passed': expected == actual,
                'description': description,
                'timestamp': datetime.datetime.now().isoformat()
            }
            results.append(test_result)
            
            status = "PASS" if test_result['passed'] else "FAIL"
            print(f"  Result: {status} (Expected: {expected}, Actual: {actual})")
        
        return results

    def test_port_accessibility(self, host, ports):
        """Test if specific ports are accessible on a host"""
        results = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((host, port))
                accessible = result == 0
                sock.close()
                
                results.append({
                    'host': host,
                    'port': port,
                    'accessible': accessible,
                    'timestamp': datetime.datetime.now().isoformat()
                })
            except Exception as e:
                results.append({
                    'host': host,
                    'port': port,
                    'accessible': False,
                    'error': str(e),
                    'timestamp': datetime.datetime.now().isoformat()
                })
        
        return results

    def run_security_tests(self):
        """Run comprehensive security tests"""
        print("Starting Network Security Lab Tests...")
        print("=" * 50)
        
        # Test 1: Host Availability
        print("\n1. Testing Host Availability:")
        for name, host in self.critical_hosts.items():
            result = self.ping_host(host)
            status = "UP" if result['success'] else "DOWN"
            print(f"  {name} ({host}): {status}")
        
        # Test 2: Network Discovery
        print("\n2. Network Discovery:")
        for name, network in self.networks.items():
            print(f"  Scanning {name} network ({network})...")
            active_hosts = self.scan_network(network)
            print(f"    Active hosts: {len(active_hosts)}")
            for host in active_hosts[:5]:  # Show first 5
                print(f"      {host}")
            if len(active_hosts) > 5:
                print(f"      ... and {len(active_hosts) - 5} more")
        
        # Test 3: Connectivity Matrix
        print("\n3. Testing Security Policy Compliance:")
        connectivity_results = self.test_connectivity_matrix()
        passed = sum(1 for r in connectivity_results if r['passed'])
        total = len(connectivity_results)
        print(f"  Security tests passed: {passed}/{total}")
        
        # Test 4: Service Availability
        print("\n4. Testing Service Availability:")
        dmz_services = [80, 443, 22, 53]  # HTTP, HTTPS, SSH, DNS
        service_results = self.test_port_accessibility('192.168.30.10', dmz_services)
        
        service_names = {80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 53: 'DNS'}
        for result in service_results:
            service = service_names.get(result['port'], f"Port {result['port']}")
            status = "AVAILABLE" if result['accessible'] else "UNAVAILABLE"
            print(f"  {service}: {status}")
        
        # Compile final report
        return {
            'timestamp': datetime.datetime.now().isoformat(),
            'connectivity_tests': connectivity_results,
            'service_tests': service_results,
            'summary': {
                'connectivity_passed': passed,
                'connectivity_total': total,
                'services_available': sum(1 for r in service_results if r['accessible']),
                'services_total': len(service_results)
            }
        }

    def generate_report(self, results, filename='security_test_report.json'):
        """Generate detailed test report"""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Also create CSV summary
        csv_filename = filename.replace('.json', '.csv')
        with open(csv_filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Test Type', 'Source', 'Destination', 'Expected', 'Actual', 'Result'])
            
            for test in results['connectivity_tests']:
                writer.writerow([
                    'Connectivity',
                    test['source'],
                    test['destination'], 
                    test['expected'],
                    test['actual'],
                    'PASS' if test['passed'] else 'FAIL'
                ])
            
            for test in results['service_tests']:
                writer.writerow([
                    'Service',
                    'Client',
                    f"{test['host']}:{test['port']}",
                    'Available',
                    'Available' if test['accessible'] else 'Unavailable',
                    'PASS' if test['accessible'] else 'FAIL'
                ])
        
        print(f"\nReports generated:")
        print(f"  Detailed: {filename}")
        print(f"  Summary: {csv_filename}")

class TrafficGenerator:
    """Generate test traffic for security analysis"""
    
    def __init__(self):
        self.attack_patterns = {
            'ssh_brute_force': {
                'target': '192.168.30.10',
                'port': 22,
                'method': 'tcp_connect'
            },
            'web_scan': {
                'target': '192.168.30.10',
                'ports': [80, 443, 8080, 8443],
                'method': 'port_scan'
            },
            'ping_sweep': {
                'targets': ['192.168.10.0/24', '192.168.30.0/24'],
                'method': 'icmp_ping'
            }
        }

    def generate_ssh_brute_force(self, target, duration=60):
        """Simulate SSH brute force attack"""
        print(f"Generating SSH brute force traffic to {target}")
        usernames = ['admin', 'root', 'user', 'administrator']
        passwords = ['password', '123456', 'admin', 'root']
        
        start_time = time.time()
        attempts = 0
        
        while time.time() - start_time < duration:
            for username in usernames:
                for password in passwords:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        sock.connect((target, 22))
                        sock.close()
                        attempts += 1
                        time.sleep(0.5)  # Realistic delay between attempts
                    except:
                        pass
                    
                    if time.time() - start_time >= duration:
                        break
                if time.time() - start_time >= duration:
                    break
        
        print(f"Generated {attempts} SSH connection attempts")
        return attempts

    def generate_port_scan(self, target, ports):
        """Simulate port scanning"""
        print(f"Generating port scan traffic to {target}")
        scan_results = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                sock.close()
                
                scan_results.append({
                    'port': port,
                    'open': result == 0,
                    'timestamp': datetime.datetime.now().isoformat()
                })
                time.sleep(0.1)  # Small delay between port attempts
            except Exception as e:
                scan_results.append({
                    'port': port,
                    'open': False,
                    'error': str(e),
                    'timestamp': datetime.datetime.now().isoformat()
                })
        
        open_ports = [r['port'] for r in scan_results if r['open']]
        print(f"Scan complete. Open ports: {open_ports}")
        return scan_results

    def generate_ping_sweep(self, network):
        """Simulate network reconnaissance"""
        print(f"Generating ping sweep of {network}")
        net = IPv4Network(network)
        responses = []
        
        for host in list(net.hosts())[:20]:  # Limit to first 20 hosts
            try:
                if os.name == 'nt':
                    result = subprocess.run(['ping', '-n', '1', str(host)], 
                                          capture_output=True, timeout=5)
                else:
                    result = subprocess.run(['ping', '-c', '1', str(host)], 
                                          capture_output=True, timeout=5)
                
                if result.returncode == 0:
                    responses.append(str(host))
                time.sleep(0.05)  # Small delay between pings
            except:
                pass
        
        print(f"Ping sweep complete. {len(responses)} hosts responded")
        return responses

def main():
    """Main function to run lab tests"""
    print("Network Security Lab - Test Suite")
    print("=" * 40)
    
    # Initialize lab manager
    lab = NetworkSecurityLabManager()
    
    # Run security tests
    results = lab.run_security_tests()
    
    # Generate reports
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"lab_test_results_{timestamp}.json"
    lab.generate_report(results, report_file)
    
    # Optional: Generate test traffic (uncomment to enable)
    # print("\n" + "=" * 50)
    # print("OPTIONAL: Generate Test Traffic for IDS Testing")
    # response = input("Generate test traffic? (y/N): ")
    # if response.lower() == 'y':
    #     traffic_gen = TrafficGenerator()
    #     traffic_gen.generate_ssh_brute_force('192.168.30.10', 30)
    #     traffic_gen.generate_port_scan('192.168.30.10', [22, 23, 80, 443, 3389])
    #     traffic_gen.generate_ping_sweep('192.168.10.0/24')
    
    print(f"\nLab testing complete!")
    print(f"Overall Results:")
    print(f"  Connectivity Tests: {results['summary']['connectivity_passed']}/{results['summary']['connectivity_total']} passed")
    print(f"  Service Tests: {results['summary']['services_available']}/{results['summary']['services_total']} available")

if __name__ == "__main__":
    main()
