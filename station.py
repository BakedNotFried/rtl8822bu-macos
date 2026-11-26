#!/usr/bin/python3
"""Run one RTL8822BU station. The guest only receives this physical USB adapter."""
import argparse
import contextlib
import ctypes
import ipaddress
import os
import re
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BUILD = Path(__file__).resolve().parent
ADMIN_SCRIPT = '''on run args
    do shell script (quoted form of (item 1 of args) & " " & quoted form of (item 2 of args) & " --session " & quoted form of (item 3 of args) & " " & quoted form of (item 4 of args)) with administrator privileges
end run'''


def guest_command(log):
    qemu = (BUILD / 'qemu.path').read_text().splitlines()[-1]
    return [qemu, '-machine', 'virt', '-accel', 'hvf', '-cpu', 'host', '-m', '512M',
            '-nodefaults', '-no-reboot', '-display', 'none', '-monitor', 'none', '-serial', 'file:' + str(log),
            '-nic', 'none', '-kernel', str(BUILD/'guest/Image'), '-initrd', str(BUILD/'guest/initramfs.gz'),
            '-append', 'console=ttyAMA0 rdinit=/init panic=-1', '-device', 'virtio-serial-pci',
            '-chardev', 'null,id=boot',
            '-device', 'virtconsole,chardev=boot,nr=0',
            '-chardev', 'stdio,id=link,signal=off', '-device', 'virtconsole,chardev=link,nr=1',
            '-device', 'qemu-xhci,id=usb', '-device', 'usb-host,bus=usb.0,vendorid=0x0bda,productid=0xb812']


def stop_child(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def read_line(fd, seconds):
    deadline = time.monotonic() + seconds
    line = bytearray()
    while len(line) < 128:
        wait = max(0, deadline - time.monotonic())
        if not select.select([fd], [], [], wait)[0]:
            raise RuntimeError('Timed out waiting for the guest.')
        char = os.read(fd, 1)
        if not char:
            raise RuntimeError('The guest stopped before completing setup.')
        if char == b'\n':
            if re.fullmatch(rb'ERROR [a-z-]+', line):
                raise RuntimeError(line.decode())
            return bytes(line)
        line.extend(char)
    raise RuntimeError('Invalid guest response.')


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        block = sock.recv(size - len(data))
        if not block:
            raise RuntimeError('Temporary Ethernet helper stopped.')
        data.extend(block)
    return bytes(data)


def root_peer(sock):
    uid, gid = ctypes.c_uint(), ctypes.c_uint()
    return (ctypes.CDLL(None).getpeereid(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid)) == 0
            and uid.value == 0)


@contextlib.contextmanager
def host_link(mac, directory):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        path = str(directory/'s')
        listener.bind(path)
        listener.listen(1)
        args = ['/usr/bin/osascript', '-e', ADMIN_SCRIPT, str(BUILD/'host-link-helper'),
                mac, path, str(os.getuid())]
        print('Approve the temporary Ethernet connection in the macOS administrator dialog.', flush=True)
        launcher = subprocess.Popen(args, start_new_session=True, stdout=subprocess.DEVNULL)
        connected = False
        try:
            limit = time.monotonic() + 120
            while launcher.poll() is None and time.monotonic() < limit:
                if not select.select([listener], [], [], .25)[0]:
                    continue
                conn, _ = listener.accept()
                with conn:
                    if not root_peer(conn):
                        continue
                    connected = True
                    conn.settimeout(30)
                    n = int.from_bytes(read_exact(conn, 2), 'big')
                    if not 4 < n < 16:
                        raise RuntimeError('Invalid interface announcement.')
                    name = read_exact(conn, n).decode('ascii')
                    if not re.fullmatch('feth[0-9]+', name):
                        raise RuntimeError('Unexpected host interface.')
                    print(f'Host interface: {name} (macOS DHCP started)', flush=True)
                    try:
                        yield conn, name
                    finally:
                        with contextlib.suppress(OSError):
                            conn.shutdown(socket.SHUT_WR)
                            conn.settimeout(2)
                            while conn.recv(8192):
                                pass
                    return
            raise RuntimeError('Temporary interface approval was canceled or expired.')
        finally:
            if connected:
                try:
                    launcher.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    print("Waiting for temporary interface teardown.", file=sys.stderr)
                    launcher.wait()
                if launcher.returncode:
                    raise RuntimeError('Check temporary interface teardown.')
            else:
                stop_child(launcher)


def relay(guest, conn, name):
    host = conn.fileno()
    rx, tx = guest.stdout.fileno(), guest.stdin.fileno()
    for fd in (host, rx, tx):
        os.set_blocking(fd, False)
    # Both ends use identically framed Ethernet records. Preserve order and
    # stop reading when a slow destination has enough data buffered.
    destinations = {host: tx, rx: host}
    queues = {tx: bytearray(), host: bytearray()}
    next_check = 0
    while True:
        if time.monotonic() >= next_check:
            result = subprocess.run(['/usr/sbin/ipconfig', 'getifaddr', name],
                                    capture_output=True, text=True, timeout=3)
            addr = result.stdout.strip()
            ip = ipaddress.IPv4Address(addr) if addr and result.returncode == 0 else None
            if ip and not (ip.is_link_local or ip.is_unspecified):
                print(f'Host link ready on {name} with IPv4 address {addr}', flush=True)
                next_check = float('inf')
            else:
                next_check = time.monotonic() + 1
        readers = [fd for fd, dest in destinations.items() if len(queues[dest]) < 262144]
        writers = [fd for fd, data in queues.items() if data]
        readable, writable, _ = select.select(readers, writers, [], 1)
        for fd in writable:
            with contextlib.suppress(BlockingIOError):
                n = os.write(fd, queues[fd])
                del queues[fd][:n]
        for fd in readable:
            with contextlib.suppress(BlockingIOError):
                data = os.read(fd, 32768)
                if not data:
                    raise RuntimeError('Station link closed.')
                queues[destinations[fd]].extend(data)


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--connect', metavar='SSID')
    modes.add_argument('--connect-saved', metavar='SSID')
    modes.add_argument('--probe', action='store_true')
    args = parser.parse_args()
    ssid = args.connect if args.connect is not None else args.connect_saved
    if not args.probe and (not ssid or len(ssid.encode()) > 32 or any(ord(c) < 32 for c in ssid)):
        parser.error('Supply an exact network name of 1–32 UTF-8 bytes.')
    if os.getuid() == 0:
        parser.error('Run this command as your regular macOS user.')
    subprocess.run([str(BUILD/'usb-probe')], check=True)
    os.umask(0o077)
    directory = Path(tempfile.mkdtemp(prefix='rtl8822bu-', dir='/private/tmp'))
    log = directory/'boot.log'
    print(f'Starting isolated RTL8822BU guest. Kernel log: {log}', flush=True)
    with (directory/'qemu.log').open('xb') as diagnostics:
        guest = subprocess.Popen(guest_command(log), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=diagnostics, start_new_session=True, bufsize=0)
    try:
        fd = guest.stdout.fileno()
        if read_line(fd, 180) != b'READY':
            raise RuntimeError('Unexpected guest startup message.')
        print('Linux wireless interface ready for USB 0bda:b812.', flush=True)
        if args.probe:
            return
        mode = '--connect-saved' if args.connect_saved is not None else '--connect'
        guest.stdin.write(b'JOIN ' + ssid.encode().hex().encode() + b' ')
        subprocess.run([str(BUILD/'psk'), mode, ssid], stdout=guest.stdin, check=True)
        guest.stdin.write(b'\n')
        response = read_line(fd, 75)
        if not re.fullmatch(rb'LINK (?:[0-9a-f]{2}:){5}[0-9a-f]{2}', response):
            raise RuntimeError('Guest could not confirm the requested WPA2 connection.')
        print(f'Joined {ssid} over 2.4 GHz WPA2-Personal/CCMP.', flush=True)
        with host_link(response[5:].decode(), directory) as (conn, name):
            relay(guest, conn, name)
    finally:
        guest.stdin.close()
        stop_child(guest)
        guest.stdout.close()


if __name__ == '__main__':
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupt)
    try:
        main()
    except KeyboardInterrupt:
        pass
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
        sys.exit(str(exc))
