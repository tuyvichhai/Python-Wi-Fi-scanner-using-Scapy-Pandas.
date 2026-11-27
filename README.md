# Wi-Fi Scanner (Python + Scapy)

A Python script that sniffs 802.11 beacon frames to list nearby Wi-Fi access points along with their BSSID, SSID, signal strength (`dBm`), channel, and encryption type.

## Features
- Real-time table view updated with `pandas`
- Safe SSID decoding (handles hidden and non-UTF-8 SSIDs)
- Cross-platform screen clearing (`cls` on Windows, `clear` on Linux/macOS)
- Channel hopping support on Linux via `iwconfig`

## Requirements
- Python 3.x
- `scapy`, `pandas`
- **Windows:** Npcap installed, and run terminal/IDE as Administrator
- **Linux:** Wi-Fi adapter supporting monitor mode (e.g., `wlan0mon`)

## Disclaimer
For educational and authorized network testing purposes only.
