import os
import subprocess
import time
from threading import Lock, Thread

import pandas
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, conf, sniff

networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
networks.set_index("BSSID", inplace=True)
lock = Lock()


interface = conf.iface if os.name == "nt" else "wlan0mon"


def clear_screen():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


def extract_ssid(packet):
    layer = packet.getlayer(Dot11Elt)
    while layer is not None:
        if layer.ID == 0:
            raw_ssid = layer.info or b""
            decoded = raw_ssid.decode("utf-8", errors="replace").strip("\x00")
            return decoded if decoded else "<Hidden>"
        layer = layer.payload.getlayer(Dot11Elt)
    return "<Unknown>"


def callback(packet):
    if not packet.haslayer(Dot11Beacon) or not packet.haslayer(Dot11):
        return

    bssid = packet[Dot11].addr2
    if not bssid:
        return

    ssid = extract_ssid(packet)
    dbm_signal = getattr(packet, "dBm_AntSignal", "N/A")

    stats = packet[Dot11Beacon].network_stats()
    channel = stats.get("channel", "N/A")
    crypto = ", ".join(sorted(stats.get("crypto", []))) or "OPEN"

    with lock:
        networks.loc[bssid] = [ssid, dbm_signal, channel, crypto]


def print_all():
    while True:
        clear_screen()
        with lock:
            if networks.empty:
                print("Scanning for Wi-Fi networks...")
            else:
                print(networks.to_string())
        time.sleep(0.5)


def change_channel(max_channel=11):
    if os.name == "nt":
        return

    ch = 1
    while True:
        subprocess.run(
            ["iwconfig", interface, "channel", str(ch)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        ch = (ch % max_channel) + 1
        time.sleep(0.5)


if __name__ == "__main__":
    printer = Thread(target=print_all, daemon=True)
    printer.start()

    channel_changer = Thread(target=change_channel, daemon=True)
    channel_changer.start()

    try:
        sniff(prn=callback, iface=interface, store=False)
    except PermissionError:
        print("\nError: សូមរត់ PyCharm/Terminal ជា Administrator (ឬ sudo លើ Linux)។")
    except Exception as e:
        print(f"\nError ពេល sniff: {e}")
    except KeyboardInterrupt:
        print("\nStopped.")