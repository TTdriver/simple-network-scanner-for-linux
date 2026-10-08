# Simple Network Scanner for Linux

Latest V1.1.0

A lightweight Linux graphical interface for basic network discovery and port scanning using a user-installed copy of Nmap.

<img width="1103" height="711" alt="image" src="https://github.com/user-attachments/assets/bf0ece3e-00f4-43f9-b994-4a86cf22ce0d" />


## Features

- Discover devices on a local network
- Scan ports on selected devices
- Display IP addresses, hostnames, MAC addresses, vendors, and open ports
- Save scan results with automatically generated filenames
- Light and dark modes
- Simple interface intended for home-lab users

## Downloading the application

1. Open this project on GitHub.
2. Click the green **Code** button.
3. Click **Download ZIP**.
4. Open your Downloads folder.
5. Extract the ZIP file.
6. Open the extracted folder.

You can also extract it from a terminal:

```bash
cd ~/Downloads
unzip simple-network-scanner-for-linux-main.zip
cd simple-network-scanner-for-linux-main
```

## Requirements

This application depends on **Nmap** to perform network scans. Nmap is not included with this project and must be installed separately.

On Debian, Ubuntu, Zorin OS, Linux Mint, and other Debian-based distributions, install the required packages with:

```bash
sudo apt update
sudo apt install python3 python3-tk nmap iproute2 policykit-1 unzip
```

Verify that Nmap is installed:

```bash
nmap --version
```

If Nmap is installed correctly, the command will display the installed Nmap version.

No pip packages are required. The application uses only Python standard-library modules.

## Install a clickable desktop application

After extracting the download, open a terminal in the application folder and run:

```bash
python3 install.py
```

This installs the app for your user, adds it to the application menu, and creates a desktop shortcut. No administrator access is needed for installation. Double-click **Simple Network Scanner** on your desktop to open it. If Linux asks, right-click the shortcut and choose **Allow Launching**. Desktop icons must be enabled in your desktop environment to see the shortcut.

The app and icon are stored in `~/.local/share/simple-network-scanner/` (or your configured `XDG_DATA_HOME`). You can move or delete the downloaded folder after installation.

## Running without installation

```bash
python3 simple-network-scanner.py
```

Some scan types require elevated privileges. The application uses `pkexec` to request authorization when needed. Targets support IPv4 addresses, IPv4 subnets, and hostnames; IPv6 is not supported yet.

If Linux denies permission to stop an administrator scan, the app displays a warning and remains open until Nmap finishes.

## Updating the application

Download and extract the newest ZIP file, then run `python3 install.py` again to update the installed app and shortcuts.

## Nmap notice

Simple Network Scanner for Linux is an independent graphical frontend for Nmap.

This project does not include, distribute, or automatically install Nmap. Users must install Nmap separately through their Linux distribution.

Nmap is a registered trademark of the Nmap Project. This project is not affiliated with, sponsored by, or endorsed by the Nmap Project.

Only scan networks and systems that you own or have explicit permission to test.

## License

This project is licensed under the GNU General Public License v3.0.

## Development checks

Run the standard-library tests with:

```bash
python3 -m unittest discover -s tests -v
```
