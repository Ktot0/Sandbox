import json
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from scapy.layers.dns import DNS
import threading

# Global variable to store captured data
captured_data = {
    'dns_queries': [],
    'http_requests': [],
    'https_requests': [],
    'icmp_requests': [],
    'syn_packets': []
}

# Global variable for the stop event
stop_event = threading.Event()

def packet_callback(packet, target_ip):
    try:
        # Check if the packet has an IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Filter packets based on the target IP
            if src_ip != target_ip and dst_ip != target_ip:
                return  # Skip packets not matching the target IP

            # Capture DNS queries (both UDP and TCP)
            if (UDP in packet and packet[UDP].dport == 53) or (TCP in packet and packet[TCP].dport == 53):
                if DNS in packet and packet[DNS].qd:
                    dns_query = packet[DNS].qd.qname.decode()
                    captured_data['dns_queries'].append({
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'requested_domain': dns_query
                    })
                    return  # DNS identified, so we can return

            # Capture HTTP requests
            if TCP in packet and packet[TCP].dport == 80:
                if Raw in packet:
                    payload = packet[Raw].load.decode(errors='ignore')
                    captured_data['http_requests'].append({
                        'source_ip': src_ip,
                        'destination_ip': dst_ip,
                        'content': payload
                    })
                    return  # HTTP identified, so we can return

            # Capture HTTPS requests
            if TCP in packet and packet[TCP].dport == 443:
                captured_data['https_requests'].append({
                    'source_ip': src_ip,
                    'destination_ip': dst_ip
                })
                return  # HTTPS identified, so we can return

            # Capture TCP SYN packets
            if TCP in packet and packet[TCP].flags == 'S':  # SYN flag only
                captured_data['syn_packets'].append({
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'source_port': packet[TCP].sport,
                    'destination_port': packet[TCP].dport,
                    'timestamp': packet.time
                })
                return  # SYN identified, so we can return

            # Capture ICMP packets
            if ICMP in packet:
                captured_data['icmp_requests'].append({
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'type': packet[ICMP].type,
                    'code': packet[ICMP].code
                })
                return  # ICMP identified, so we can return

    except Exception as e:
        print(f"Error processing packet: {e}")

def capture_packets(interface, target_ip):
    global captured_data
    global stop_event

    # Clear previous data
    captured_data = {
        'dns_queries': [],
        'http_requests': [],
        'https_requests': [],
        'icmp_requests': [],
        'syn_packets': []
    }

    # Sniff all traffic and stop when stop_event is set
    sniff(iface=interface, prn=lambda p: packet_callback(p, target_ip), store=0, stop_filter=lambda x: stop_event.is_set())

def run(interface_name, target_ip):
    global stop_event

    # Ensure stop_event is cleared before starting a new capture
    stop_event.clear()

    print(f"Starting packet capture on interface: {interface_name} for IP: {target_ip}")
    capture_thread = threading.Thread(target=capture_packets, args=(interface_name, target_ip))
    capture_thread.start()
    return capture_thread

def stop(capture_thread, filename):
    global stop_event

    # Signal the capture thread to stop
    stop_event.set()
    capture_thread.join()

    # Save the captured data
    print(f"Stopping packet capture and saving results to {filename}")
    with open(filename, 'w') as f:
        json.dump(captured_data, f, indent=4)
    print(f"Results saved to {filename}")

