import socket

# Function to scan IP addresses and detect open ports
def scan_network(ip_range, ports):
    vulnerable_devices = []
    for i in range(1, 255):  # Scan IP range
        ip = ip_range + str(i)
        for port in ports:  # Specify ports to check
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:  # Port is open
                    vulnerability = check_vulnerabilities(port)
                    if vulnerability:
                        vulnerable_devices.append((ip, port, vulnerability))
                sock.close()
            except socket.error:
                pass
    return vulnerable_devices

# Function to check vulnerabilities based on port number
def check_vulnerabilities(port):
    if port == 80:
        vulnerability = input("Enter vulnerability information for port 80: ")
        return vulnerability or None
    elif port == 443:
        vulnerability = input("Enter vulnerability information for port 443: ")
        return vulnerability or None
    elif port == 8080:
        vulnerability = input("Enter vulnerability information for port 8080: ")
        return vulnerability or None
    else:
        return None

# Specify the IP range to scan (e.g., '192.168.0.')
ip_range = input("Enter the IP range to scan (e.g., '192.168.0.'): ")

# Specify the ports to scan
ports_input = input("Enter the ports to scan (comma-separated): ")
ports = [int(p) for p in ports_input.split(",")]

# Scan the network and get vulnerable devices
vulnerable_devices = scan_network(ip_range, ports)

# Print the results
if vulnerable_devices:
    print('Vulnerable devices found:')
    for device in vulnerable_devices:
        print('IP:', device[0])
        print('Port:', device[1])
        print('Vulnerability:', device[2])
        print('-----------------------------')
else:
    print('No vulnerable devices found.')
