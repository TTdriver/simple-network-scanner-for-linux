#!/usr/bin/env python3
"""Install the app and desktop/menu launchers for the current user."""
from pathlib import Path
import os
import shutil
import subprocess


def main():
    source = Path(__file__).resolve().parent
    data = Path(os.environ.get('XDG_DATA_HOME', str(Path.home() / '.local/share')))
    destination = data / 'simple-network-scanner'
    destination.mkdir(parents=True, exist_ok=True)
    for name in ('simple-network-scanner.py', 'README.md', 'LICENSE', 'CHANGELOG.md'):
        origin = source / name
        target = destination / name
        if origin.resolve() != target.resolve():
            shutil.copy2(origin, target)
    # Escape the executable argument according to the desktop-entry specification.
    argument = str(destination / 'simple-network-scanner.py').replace('%', '%%')
    for character in ('\\', '"', '`', '$'):
        argument = argument.replace(character, '\\' + character)
    argument = argument.replace('\\', '\\\\')
    entry = ('[Desktop Entry]\nType=Application\nName=Simple Network Scanner\n'
             'Comment=Discover devices and scan network ports\n'
             f'Exec=python3 "{argument}"\nIcon=network-workgroup\n'
             'Terminal=false\nCategories=Network;\n')
    desktop = Path.home() / 'Desktop'
    if shutil.which('xdg-user-dir'):
        result = subprocess.run(['xdg-user-dir', 'DESKTOP'], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            desktop = Path(result.stdout.strip())
    folders = [data / 'applications']
    if desktop != Path.home():
        folders.append(desktop)
    for folder in folders:
        folder.mkdir(parents=True, exist_ok=True)
        launcher = folder / 'simple-network-scanner.desktop'
        launcher.write_text(entry, encoding='utf-8')
        launcher.chmod(0o755)
        if folder == desktop and shutil.which('gio'):
            subprocess.run(['gio', 'set', str(launcher), 'metadata::trusted', 'true'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f'Installed to {destination}')
    print('Open Simple Network Scanner from your desktop or applications menu.')
    print('If your desktop requests it, right-click the icon and choose Allow Launching.')


if __name__ == '__main__':
    main()
