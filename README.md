# WiFiCracker

A Python-based tool for capturing WiFi handshakes and cracking passwords.

![Banner](https://img.shields.io/badge/WiFiCracker-v1.0-blue)
![Python](https://img.shields.io/badge/Python-3.x-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Disclaimer

**This tool is for educational purposes only.**

Do not use this tool on networks you don't own or have explicit permission to test. Unauthorized access to networks is illegal and unethical.

## Features

- Capture WiFi handshakes (4-way EAPOL handshake)
- Send deauthentication packets to force handshakes
- Crack captured handshakes using dictionary attacks
- Verify handshake captures
- Support for targeted captures (by BSSID/ESSID)

## Requirements

- Python 3.x
- Scapy library
- Aircrack-ng suite
- Wireless interface with monitor mode support
- Root/Administrator privileges

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/username/wificracker.git
   cd wificracker
   ```

2. Install the required dependencies:
   ```
   pip install scapy
   sudo apt-get install aircrack-ng  # For Debian/Ubuntu
   ```

## Usage

### Basic Usage

```
sudo python3 wificracker.py --mode both -i wlan0 -w /path/to/wordlist.txt
```

### Capture Only Mode

```
sudo python3 wificracker.py --mode capture -i wlan0 -o handshake.cap
```

### Crack Only Mode

```
sudo python3 wificracker.py --mode crack -f handshake.cap -w /path/to/wordlist.txt
```

### Target Specific Access Point

```
sudo python3 wificracker.py --mode both -i wlan0 -b 00:11:22:33:44:55 -e "MyNetwork" -w /path/to/wordlist.txt
```

### Force Handshake with Deauthentication

```
sudo python3 wificracker.py --mode both -i wlan0 -b 00:11:22:33:44:55 --deauth -w /path/to/wordlist.txt
```

## Command Line Options

### Mode Selection
- `--mode {capture,crack,both}`: Select operation mode (default: both)

### Handshake Capture Options
- `-i, --interface`: Wireless interface to use
- `-c, --channel`: WiFi channel to monitor
- `-b, --bssid`: Target BSSID (AP MAC address)
- `-e, --essid`: Target ESSID (AP name)
- `-o, --output`: Output capture file name
- `-t, --timeout`: Capture timeout in seconds (default: 300)
- `--deauth`: Send deauthentication packets to force handshake

### Password Cracking Options
- `-w, --wordlist`: Path to wordlist file for cracking
- `-f, --capture-file`: Capture file to crack (when in crack-only mode)

## How It Works

1. **Capture Mode**: Puts the wireless interface into monitor mode and captures network traffic, focusing on EAPOL packets that contain the 4-way handshake.

2. **Deauthentication**: Optionally sends deauth packets to force clients to reconnect, triggering handshakes.

3. **Handshake Verification**: Checks if a complete 4-way handshake has been captured.

4. **Password Cracking**: Uses the Aircrack-ng suite to perform dictionary attacks against the captured handshake.

## Acknowledgments

- Original by: Sambhav Mehra
- Tool utilizes the Scapy library for packet manipulation
- Uses Aircrack-ng for handshake verification and password cracking

## License

This project is licensed under the MIT License - see the LICENSE file for details.
