# Stretch 2.4 GHz Wi-Fi on Apple silicon

Connect a Realtek RTL8822BU USB Wi-Fi dongle to the Stretch router from an Apple silicon Mac. A small Terminal companion handles Wi-Fi and gives macOS a temporary Ethernet connection that your apps can use. The built-in Wi-Fi menu continues to control the Mac’s own radio.

The companion boots a small ARM64 Linux guest from files inside the checkout. The guest receives the USB dongle and runs the Linux RTL8822BU driver. A private connection carries IPv4 traffic back to macOS. The dongle is the guest’s only network connection. All guest files are local to the checkout or to its temporary session.

**Hardware test:** On an M1 Max MacBook Pro running macOS 27.2.1, the dongle joined the Stretch router over 2.4 GHz WPA2. macOS received a DHCP lease and the router answered three out of three pings through the dongle. Built-in Wi-Fi kept the default route. Connecting to a robot application and testing other Apple silicon models are still pending.

## What you need

- An Apple silicon Mac with Apple Command Line Tools and a Realtek RTL8822BU dongle with USB ID `0bda:b812`.
- The exact name and password of the Stretch router’s **2.4 GHz** network. It must broadcast its name and offer **WPA2-Personal with AES/CCMP** with protected management frames optional or disabled. The companion uses DHCPv4 to get an address automatically.

## Connect to Stretch

**1. Get the source and build.** Run these commands as your regular macOS user. The first build downloads the guest kernel, firmware and tools from Alpine Linux. It uses an existing USB-capable QEMU or downloads a project-local copy from Homebrew. Allow several minutes for this step. The build uses the macOS SDK and leaves its outputs inside the checkout.

```sh
gh repo clone BakedNotFried/rtl8822bu-macos
cd rtl8822bu-macos
station="$(sh build-station.sh)"
```

**2. Plug in the dongle and connect.** In the same Terminal, enter the exact 2.4 GHz network name when prompted. The saved-password command reads the Keychain entry for that exact name. macOS may ask you to authorize access.

```sh
printf 'Stretch 2.4 GHz network name: '
IFS= read -r ssid
"$station" --connect-saved "$ssid"
```

If the password is not saved, use `"$station" --connect "$ssid"` to enter it in a secure dialog. After Wi-Fi authentication, approve the macOS administrator prompt to create the temporary Ethernet connection. This installs no software.

**3. Use both connections.** Leave built-in Wi-Fi on for internet access. When the station prints `Host link ready` and an IPv4 address, open the Stretch service at the address supplied by the robot’s operator. Keep the station running while you use it. This setup works best when Stretch and your internet Wi-Fi use different IP subnets.

Press **Control-C** to disconnect and release the temporary interfaces. To reconnect, run the same connect command again. For a hardware-only check, run `"$station" --probe`. It boots the guest, verifies that the driver can bring up the dongle, and exits.

## Check the connection

The station’s Terminal reports when the guest has joined the selected network using 2.4 GHz WPA2-Personal. Look for the line starting with `Host interface:` to find the dongle’s macOS interface name. In a **second Terminal**, set `dongle` to that name. The example uses `feth0`. Check the name again after reconnecting.

```sh
dongle=feth0
ipconfig getsummary "$dongle"
```

The summary shows the Mac’s IPv4 address on Stretch and the settings supplied by the router, including the subnet mask, gateway, and DNS servers. For just the Mac’s address, run `ipconfig getifaddr "$dongle"`.

To check which connection macOS will use for the robot, replace `ROBOT_IP` with the **robot’s IPv4 address**. Look for the `interface:` line in the result. It should match the dongle’s interface name.

```sh
route -n get ROBOT_IP
```

## Change connection settings

**Set a static IPv4 address.** In the second Terminal, replace `RESERVED_IP` with the address the Stretch operator assigned to **your Mac** and `SUBNET_MASK` with their dotted mask (for example, `255.255.255.0`). This replaces DHCP on the dongle for the current session and requires administrator approval. Manual mode sets only the address and mask.

```sh
sudo ipconfig set "$dongle" MANUAL RESERVED_IP SUBNET_MASK
```

**Return to automatic addressing.** Run this in the same Terminal to request a fresh DHCP lease. The companion also starts with DHCP each time you reconnect.

```sh
sudo ipconfig set "$dongle" DHCP
```

**Switch Wi-Fi networks.** In the **original Terminal**, press **Control-C**, then run the command below with the new network’s exact name inside the quotes. Use `--connect-saved` if its password is already saved on this Mac.

```sh
"$station" --connect "New network name"
```

[Original RTL8192CU companion and host interface](https://github.com/BakedNotFried/rtl8192cu-macos) · [Linux RTL8822BU driver](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/realtek/rtw88/rtw8822bu.c) · [Alpine Linux packages](https://pkgs.alpinelinux.org/)
