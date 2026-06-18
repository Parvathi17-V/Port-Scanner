import socket
import textwrap
import struct
import json
from datetime import datetime
from typing import Dict, List, Tuple
import sys

# Protocol Numbers
PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

class PacketSniffer:
    def __init__(self, interface=None):
        """
        Initialize the packet sniffer.
        
        Args:
            interface (str): Network interface to sniff on (optional)
        """
        self.interface = interface
        self.packets = []
        self.packet_count = 0
        self.start_time = None
        
    def create_socket(self):
        """Create and configure the raw socket for packet sniffing."""
        try:
            if sys.platform == "win32":
                # Windows
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                # Linux/Mac
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            print("✓ Socket created successfully\n")
        except PermissionError:
            print("❌ Error: This program requires root/administrator privileges!")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error creating socket: {e}")
            sys.exit(1)

    def parse_ipv4_packet(self, data: bytes) -> Tuple[str, str, str, str, bytes]:
        """
        Parse IPv4 packet.
        
        Args:
            data (bytes): Raw packet data
            
        Returns:
            Tuple: (version, header_length, ttl, proto, payload)
        """
        version_header_length = data[0]
        header_length = (version_header_length & 15) * 4
        ttl = data[8]
        proto = data[9]
        src = self.format_ipv4(data[12:16])
        target = self.format_ipv4(data[16:20])
        return src, target, ttl, proto, data[header_length:]

    def parse_icmp_packet(self, data: bytes) -> Tuple[str, str, str]:
        """
        Parse ICMP packet.
        
        Args:
            data (bytes): ICMP packet data
            
        Returns:
            Tuple: (icmp_type, code, checksum)
        """
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum

    def parse_tcp_segment(self, data: bytes) -> Tuple[int, int, str, str, str]:
        """
        Parse TCP segment.
        
        Args:
            data (bytes): TCP segment data
            
        Returns:
            Tuple: (src_port, dest_port, sequence, acknowledgment, flags)
        """
        (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:12])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        
        flags = []
        if flag_syn: flags.append("SYN")
        if flag_ack: flags.append("ACK")
        if flag_fin: flags.append("FIN")
        if flag_rst: flags.append("RST")
        if flag_psh: flags.append("PSH")
        if flag_urg: flags.append("URG")
        
        return src_port, dest_port, sequence, acknowledgment, ",".join(flags)

    def parse_udp_segment(self, data: bytes) -> Tuple[int, int, int]:
        """
        Parse UDP segment.
        
        Args:
            data (bytes): UDP segment data
            
        Returns:
            Tuple: (src_port, dest_port, length)
        """
        src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, length

    def format_multi_line(self, prefix: str, bytes_data: bytes, size: int = 80) -> str:
        """
        Format bytes data for display.
        
        Args:
            prefix (str): Prefix for each line
            bytes_data (bytes): Data to format
            size (int): Size of each line
            
        Returns:
            str: Formatted string
        """
        if isinstance(bytes_data, bytes):
            bytes_data = ''.join(r'\\x{:02x}'.format(byte) for byte in bytes_data)
            if size % 2:
                size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(bytes_data, size)])

    def format_ipv4(self, bytes_addr: bytes) -> str:
        """
        Format IPv4 address from bytes.
        
        Args:
            bytes_addr (bytes): 4 bytes representing IP address
            
        Returns:
            str: Formatted IP address
        """
        bytes_iter = iter(bytes_addr)
        return '.'.join(map(str, bytes_iter))

    def sniff(self, packet_count: int = 0, timeout: int = None):
        """
        Sniff packets from the network.
        
        Args:
            packet_count (int): Number of packets to sniff (0 = infinite)
            timeout (int): Timeout in seconds
        """
        self.create_socket()
        self.start_time = datetime.now()
        
        if timeout:
            self.sock.settimeout(timeout)
        
        print(f"{'='*80}")
        print(f"🔍 NETWORK PACKET SNIFFER")
        print(f"{'='*80}")
        print(f"Starting packet capture...")
        if packet_count > 0:
            print(f"Capturing {packet_count} packets")
        else:
            print(f"Capturing packets indefinitely (Press Ctrl+C to stop)")
        print(f"{'='*80}\n")
        
        try:
            while True:
                if packet_count > 0 and self.packet_count >= packet_count:
                    break
                
                try:
                    raw_data, addr = self.sock.recvfrom(65535)
                    self.packet_count += 1
                    
                    if sys.platform != "win32":
                        # Linux/Mac - skip Ethernet header
                        dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', raw_data[:14])
                        raw_data = raw_data[14:]
                    
                    # Parse IPv4
                    src, target, ttl, proto, payload = self.parse_ipv4_packet(raw_data)
                    
                    # Store packet info
                    packet_info = self.create_packet_info(src, target, ttl, proto, payload)
                    self.packets.append(packet_info)
                    
                    # Display packet
                    self.display_packet(packet_info)
                    
                except socket.timeout:
                    break
                except Exception as e:
                    continue
                    
        except KeyboardInterrupt:
            print(f"\n{'='*80}")
            print("Capture stopped by user")
            print(f"{'='*80}\n")
        finally:
            if sys.platform == "win32":
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self.sock.close()

    def create_packet_info(self, src: str, target: str, ttl: int, proto: int, payload: bytes) -> Dict:
        """
        Create packet information dictionary.
        
        Args:
            src (str): Source IP
            target (str): Destination IP
            ttl (int): Time to live
            proto (int): Protocol number
            payload (bytes): Packet payload
            
        Returns:
            Dict: Packet information
        """
        packet_info = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src,
            "dst_ip": target,
            "ttl": ttl,
            "protocol": PROTO_MAP.get(proto, "Other"),
            "protocol_num": proto,
            "payload_size": len(payload)
        }
        
        # Parse protocol-specific info
        if proto == 1:  # ICMP
            icmp_type, code, checksum = self.parse_icmp_packet(payload)
            packet_info["icmp_type"] = icmp_type
            packet_info["icmp_code"] = code
            packet_info["checksum"] = checksum
            
        elif proto == 6:  # TCP
            src_port, dest_port, sequence, acknowledgment, flags = self.parse_tcp_segment(payload)
            packet_info["src_port"] = src_port
            packet_info["dst_port"] = dest_port
            packet_info["sequence"] = sequence
            packet_info["acknowledgment"] = acknowledgment
            packet_info["flags"] = flags
            
        elif proto == 17:  # UDP
            src_port, dest_port, length = self.parse_udp_segment(payload)
            packet_info["src_port"] = src_port
            packet_info["dst_port"] = dest_port
            packet_info["length"] = length
        
        return packet_info

    def display_packet(self, packet_info: Dict):
        """
        Display packet information.
        
        Args:
            packet_info (Dict): Packet information dictionary
        """
        print(f"Packet #{self.packet_count} | {packet_info['timestamp']}")
        print(f"{'─'*80}")
        print(f"IPv4 Packet:")
        print(f"  Source IP: {packet_info['src_ip']}")
        print(f"  Destination IP: {packet_info['dst_ip']}")
        print(f"  TTL: {packet_info['ttl']}")
        print(f"  Protocol: {packet_info['protocol']} ({packet_info['protocol_num']})")
        print(f"  Payload Size: {packet_info['payload_size']} bytes")
        
        if packet_info['protocol'] == 'ICMP':
            print(f"\nICMP Packet:")
            print(f"  Type: {packet_info['icmp_type']}")
            print(f"  Code: {packet_info['icmp_code']}")
            print(f"  Checksum: {packet_info['checksum']}")
            
        elif packet_info['protocol'] == 'TCP':
            print(f"\nTCP Segment:")
            print(f"  Source Port: {packet_info['src_port']}")
            print(f"  Destination Port: {packet_info['dst_port']}")
            print(f"  Sequence: {packet_info['sequence']}")
            print(f"  Acknowledgment: {packet_info['acknowledgment']}")
            print(f"  Flags: {packet_info['flags']}")
            
        elif packet_info['protocol'] == 'UDP':
            print(f"\nUDP Segment:")
            print(f"  Source Port: {packet_info['src_port']}")
            print(f"  Destination Port: {packet_info['dst_port']}")
            print(f"  Length: {packet_info['length']}")
        
        print(f"{'─'*80}\n")

    def display_statistics(self):
        """Display packet capture statistics."""
        if not self.packets:
            print("No packets captured.")
            return
        
        duration = (datetime.now() - self.start_time).total_seconds()
        
        protocols = {}
        for packet in self.packets:
            proto = packet['protocol']
            protocols[proto] = protocols.get(proto, 0) + 1
        
        print(f"\n{'='*80}")
        print(f"📊 CAPTURE STATISTICS")
        print(f"{'='*80}")
        print(f"Total Packets: {len(self.packets)}")
        print(f"Duration: {duration:.2f} seconds")
        print(f"Packets/Second: {len(self.packets)/duration:.2f}")
        print(f"\nProtocol Breakdown:")
        for proto, count in protocols.items():
            percentage = (count / len(self.packets)) * 100
            print(f"  {proto}: {count} ({percentage:.1f}%)")
        print(f"{'='*80}\n")

    def save_pcap(self, filename: str = "capture.json"):
        """
        Save captured packets to JSON file.
        
        Args:
            filename (str): Output filename
        """
        try:
            with open(filename, 'w') as f:
                json.dump(self.packets, f, indent=2)
            print(f"✓ Packets saved to: {filename}\n")
        except IOError as e:
            print(f"❌ Error saving packets: {e}\n")

    def filter_packets(self, protocol: str = None, src_ip: str = None, dst_ip: str = None) -> List[Dict]:
        """
        Filter captured packets.
        
        Args:
            protocol (str): Filter by protocol
            src_ip (str): Filter by source IP
            dst_ip (str): Filter by destination IP
            
        Returns:
            List[Dict]: Filtered packets
        """
        filtered = self.packets
        
        if protocol:
            filtered = [p for p in filtered if p['protocol'].upper() == protocol.upper()]
        
        if src_ip:
            filtered = [p for p in filtered if p['src_ip'] == src_ip]
        
        if dst_ip:
            filtered = [p for p in filtered if p['dst_ip'] == dst_ip]
        
        return filtered

    def display_filter_results(self, filtered_packets: List[Dict]):
        """
        Display filtered packet results.
        
        Args:
            filtered_packets (List[Dict]): Filtered packets
        """
        if not filtered_packets:
            print("No packets match the filter criteria.\n")
            return
        
        print(f"\n{'='*80}")
        print(f"🔎 FILTERED RESULTS ({len(filtered_packets)} packets)")
        print(f"{'='*80}\n")
        
        print(f"{'#':<5} {'Time':<20} {'Protocol':<10} {'Source IP':<20} {'Dest IP':<20}")
        print(f"{'-'*80}")
        
        for i, packet in enumerate(filtered_packets, 1):
            print(f"{i:<5} {packet['timestamp']:<20} {packet['protocol']:<10} "
                  f"{packet['src_ip']:<20} {packet['dst_ip']:<20}")
        
        print(f"{'='*80}\n")


def main():
    """Main application interface."""
    print(f"\n{'='*80}")
    print(f"🔍 NETWORK PACKET SNIFFER v1.0")
    print(f"{'='*80}\n")
    
    sniffer = PacketSniffer()
    
    while True:
        print("1. Start packet capture")
        print("2. View statistics")
        print("3. Filter packets")
        print("4. Save packets to file")
        print("5. Exit")
        print()
        
        choice = input("Enter your choice (1-5): ").strip()
        
        if choice == "1":
            try:
                packet_limit = input("Enter number of packets to capture (0 for infinite): ").strip()
                packet_limit = int(packet_limit) if packet_limit else 0
                
                timeout = input("Enter timeout in seconds (0 for no timeout): ").strip()
                timeout = int(timeout) if timeout and int(timeout) > 0 else None
                
                sniffer.sniff(packet_limit, timeout)
                
                if sniffer.packets:
                    sniffer.display_statistics()
                    
            except ValueError:
                print("❌ Invalid input. Please enter valid numbers.\n")
            except KeyboardInterrupt:
                print("\nCapture interrupted.\n")
        
        elif choice == "2":
            if sniffer.packets:
                sniffer.display_statistics()
            else:
                print("No packets captured yet. Start capture first.\n")
        
        elif choice == "3":
            if not sniffer.packets:
                print("No packets captured. Start capture first.\n")
                continue
            
            print("\nFilter Options:")
            print("1. By Protocol (TCP/UDP/ICMP)")
            print("2. By Source IP")
            print("3. By Destination IP")
            print("4. Back to main menu")
            
            filter_choice = input("\nEnter filter option (1-4): ").strip()
            
            if filter_choice == "1":
                protocol = input("Enter protocol (TCP/UDP/ICMP): ").strip().upper()
                filtered = sniffer.filter_packets(protocol=protocol)
            elif filter_choice == "2":
                src_ip = input("Enter source IP: ").strip()
                filtered = sniffer.filter_packets(src_ip=src_ip)
            elif filter_choice == "3":
                dst_ip = input("Enter destination IP: ").strip()
                filtered = sniffer.filter_packets(dst_ip=dst_ip)
            else:
                continue
            
            sniffer.display_filter_results(filtered)
        
        elif choice == "4":
            if sniffer.packets:
                filename = input("Enter filename (default: capture.json): ").strip()
                if not filename:
                    filename = "capture.json"
                sniffer.save_pcap(filename)
            else:
                print("No packets to save.\n")
        
        elif choice == "5":
            print("Thank you for using Network Packet Sniffer. Goodbye! 👋\n")
            break
        
        else:
            print("❌ Invalid choice. Please try again.\n")


if __name__ == "__main__":
    main()
