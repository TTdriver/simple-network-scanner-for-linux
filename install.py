#!/usr/bin/env python3
"""Install desktop launchers for the current user; no root access required."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

APP_ID = 'simple-network-scanner'

def desktop_quote(value):
    value = str(value).replace('%', '%%')
    for character in ('\\', '"', '`', '$'):
        value = value.replace(character, '\\' + character)
    # Desktop-entry string escaping happens before Exec argument escaping.
    return '"' + value.replace('\\', '\\\\') + '"'

def install():
    import tkinter  # Verify the GUI dependency before creating launchers.
    source = Path(__file__).resolve().parent
    home = Path.home()
    data = Path(os.environ.get('XDG_DATA_HOME', home / '.local/share'))
    destination = data / APP_ID
    destination.mkdir(parents=True, exist_ok=True)
    for filename in ('simple-network-scanner.py', 'network-scanner.svg', 'LICENSE'):
        target = destination / filename
        if (source / filename).resolve() != target.resolve():
            shutil.copy2(source / filename, target)
    launcher = '\n'.join([
        '[Desktop Entry]', 'Version=1.0', 'Type=Application',
        'Name=Simple Network Scanner', 'Comment=Discover devices and scan open ports',
        'Exec=' + desktop_quote(sys.executable) + ' ' + desktop_quote(destination / 'simple-network-scanner.py'),
        'Icon=' + str(destination / 'network-scanner.svg'),
        'Terminal=false', 'Categories=Network;Utility;', 'StartupNotify=true', '',
    ])
    applications = data / 'applications'
    applications.mkdir(parents=True, exist_ok=True)
    menu_entry = applications / (APP_ID + '.desktop')
    menu_entry.write_text(launcher, encoding='utf-8')
    menu_entry.chmod(0o755)
    desktop = home / 'Desktop'
    if shutil.which('xdg-user-dir'):
        result = subprocess.run(['xdg-user-dir', 'DESKTOP'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            desktop = Path(result.stdout.strip())
    # Some desktops disable the Desktop folder by mapping it to HOME.
    if desktop != home:
        desktop.mkdir(parents=True, exist_ok=True)
        shortcut = desktop / 'Simple Network Scanner.desktop'
        shortcut.write_text(launcher, encoding='utf-8')
        shortcut.chmod(0o755)
        if shutil.which('gio'):
            subprocess.run(['gio', 'set', str(shortcut), 'metadata::trusted', 'true'],
                           capture_output=True, timeout=5)
        print(f'Desktop shortcut: {shortcut}')
    print(f'Installed application: {destination}')
    print('Open Simple Network Scanner from your application menu or desktop.')
    print('If your desktop asks, right-click the shortcut and choose Allow Launching.')
    if not shutil.which('nmap'):
        print('Nmap is required: sudo apt install nmap')

if __name__ == '__main__':
    try:
        install()
    except (ImportError, OSError, subprocess.SubprocessError) as error:
        print(f'Installation failed: {error}', file=sys.stderr)
        sys.exit(1)
