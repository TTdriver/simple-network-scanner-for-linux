# Simple Network Scanner for Linux

A lightweight Linux graphical interface for basic network discovery and port scanning using a user-installed copy of Nmap.

## Features

- Discover devices on a local network
- Scan ports on selected devices
- Display IP addresses, hostnames, MAC addresses, vendors, and open ports
- Save scan results with automatically generated filenames
- Light and dark modes
- Simple interface intended for home-lab users

## Requirements

Install the required system packages on Debian, Ubuntu, or Zorin OS:

```bash
sudo apt update
sudo apt install python3 python3-tk nmap iproute2 policykit-1
```

No pip packages are required.

## Running

```bash
python3 simple-network-scanner.py
```

Some scan types may require elevated privileges. The application may use `pkexec` when needed.

## Nmap notice

Simple Network Scanner for Linux is an independent graphical frontend for Nmap.

This project does not include, distribute, or automatically install Nmap. Users must install Nmap separately through their Linux distribution.

Nmap is a registered trademark of the Nmap Project. This project is not affiliated with, sponsored by, or endorsed by the Nmap Project.

Only scan networks and systems that you own or have explicit permission to test.

## License

This project is licensed under the GNU General Public License v3.0.
