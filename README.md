# Simple Network Scanner for Linux

**Version 1.1.1** · A simple Linux desktop app for discovering network devices and checking open ports.

## Download and install

**[Download Simple Network Scanner v1.1.1 (.deb)](https://github.com/TTdriver/simple-network-scanner-for-linux/raw/refs/heads/main/downloads/simple-network-scanner_1.1.1_all.deb)**

For Zorin OS 18, Ubuntu 24.04, Linux Mint 22, and compatible Debian-based systems with Python 3.10 or newer:

1. Download the `.deb` file using the link above. You do not need to download the source ZIP.
2. Open your Downloads folder and double-click the file.
3. Choose **Install** and enter your Linux password if requested.
4. Open **Simple Network Scanner** from your application menu.

The package lists Python, Tkinter, Nmap, iproute2, and pkexec as dependencies. Your software installer obtains missing dependencies from your distribution's repositories. An internet connection may be needed. No pip packages or virtual environment are required.

If double-clicking opens an archive viewer, right-click the file and choose **Open With → Software Install** (the name varies by desktop). If your system has no graphical package installer, open a terminal in Downloads and run:

```bash
sudo apt install ./simple-network-scanner_1.1.1_all.deb
```

The package has been built and inspected on Zorin OS 18.1; other distributions have not been tested directly.

## Add a desktop shortcut

The `.deb` adds an application-menu entry. Use your desktop's **Add to Desktop** or **Create Shortcut** action on that entry, if available. Desktop icons must be enabled. If prompted, right-click the shortcut and choose **Allow Launching**.

## Using the app

- **Detect Network** fills in your local IPv4 subnet, or enter an IP address, hostname, or subnet yourself.
- Choose **Device Discovery** to find devices without requesting administrator access.
- Choose **Device Discovery w/MAC** to request administrator access and retrieve available local MAC/vendor information.
- Choose **Quick Port Scan** or **Standard Port Scan** to check open ports.
- Click **Start scan**. **Stop** requests cancellation.
- Use **Copy IP**, **Save**, and the **Devices**, **Ports**, and **Raw Output** tabs as needed.
- Use **Dark Mode** to switch between charcoal and light appearances.

Changing scan types clears previous results. Save anything you want to keep first. IPv6 is not supported yet. MAC information is generally available only on the local network, and a device that does not respond to discovery may still be online.

If Linux denies permission to stop an administrator scan, the app displays a warning and remains open until Nmap finishes.

## Updating or removing

To update, download the newer `.deb`, close the app, and install it the same way. Updates are manual. To remove it, use your software manager or `sudo apt remove simple-network-scanner`.

### If you previously used `install.py`

The older installer creates a separate per-user copy that can override the packaged application. Before switching to the `.deb`, remove its **Simple Network Scanner** desktop shortcut and these two items from your home folder (show hidden files in your file manager):

- `~/.local/share/applications/simple-network-scanner.desktop`
- `~/.local/share/simple-network-scanner/`

If you configured `XDG_DATA_HOME`, those items are under that directory instead. Saved scans are not stored in the application folder by default. Keep any files you saved there before removing it.

Then install the `.deb` and create a new desktop shortcut from the application-menu entry.

## Source-code alternative

Download the repository ZIP using **Code → Download ZIP**, extract it, and install the system requirements:

```bash
sudo apt install python3 python3-tk nmap iproute2 pkexec
```

Run `python3 simple-network-scanner.py` from the extracted folder. Alternatively, `python3 install.py` installs a per-user copy with a menu entry and desktop shortcut. Use one installation method to avoid duplicate copies.

## Nmap notice and license

This is an independent graphical frontend for Nmap. Nmap is not bundled in the app or `.deb`; the package manager installs it separately from your distribution's repositories when needed.

Nmap is a registered trademark of the Nmap Project. This project is not affiliated with, sponsored by, or endorsed by the Nmap Project.

Only scan networks and systems that you own or have explicit permission to test.

This project is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE).

## Development checks

```bash
python3 -m unittest discover -s tests -v
```

## Update notifications

The app checks GitHub once at launch in the background, with a five-second timeout. A small muted link appears in the bottom-right corner only when a newer version is available. Clicking it opens the download instructions. No popups, repeated checks, or automatic installations occur. Offline failures stay silent.

For maintainers: update `APP_VERSION`, the root `VERSION` file, and the downloadable installer together when publishing an update. Versions use `major.minor.patch`.

## Give Thanks

If you’d like to say thanks by buying me a drink or helping cover AI tokens, it’s appreciated.

[Give Thanks](https://thanks.kerchnerlabs.com)
