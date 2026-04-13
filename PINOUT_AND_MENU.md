# Evil-BW16 v1.0.3 — Pinout & Menu Map

## Pinout

### OLED (I²C SSD1306, 128×64)
| Pin | BW16 GPIO |
|-----|-----------|
| SDA | GPIO 8 |
| SCL | GPIO 7 |
| VCC | 3.3V |
| GND | GND |

### 5-Way Joystick
| Direction | BW16 GPIO |
|-----------|-----------|
| Up | GPIO 12 |
| Down | GPIO 13 |
| Left | GPIO 14 |
| Right | GPIO 15 |
| Middle | GPIO 16 |
| GND | GND |

> All joystick pins use internal pull-ups. Direction pin connects to GND when pressed.

## Menu Map

```
MAIN MENU
├── Scan              → Runs WiFi scan, shows results
├── Attack >          → ATTACK SUBMENU
│   ├── Deauth On     → Start deauth attack
│   ├── Disassoc      → Start continuous disassociation
│   ├── Rnd Atk       → Attack random AP from scan list
│   ├── Single AP     → SINGLE AP SELECT (pick one AP, attack it)
│   ├── Signal Jam    → Rapid channel cycling + deauth on all channels
│   └── Timer         → TIMER SUBMENU (10s / 30s / 60s / 120s / 300s)
├── Stop All          → Kills everything (universal stop)
├── Flood >           → FLOOD SUBMENU
│   ├── Beacon Flood  → Spam fake APs with random SSIDs
│   ├── Probe Flood   → Flood air with probe requests
│   └── Deauth Sniff  → Sniff deauth frames, clone source MAC, send targeted deauth
├── Sniffer >         → SNIFFER SUBMENU
│   ├── All           → Sniff all frames
│   ├── Beacon        → Sniff beacons only
│   ├── Probe         → Sniff probe requests/responses
│   ├── Deauth        → Sniff deauth/disassoc frames
│   ├── EAPOL         → Sniff EAPOL handshake frames
│   ├── Pwnagotchi    → Sniff Pwnagotchi beacons
│   ├── Stop Sniff    → Stop sniffer
│   └── Hop On/Off    → Toggle channel hopping
├── Hop On/Off        → Toggle channel hopping (quick access)
├── Config            → CONFIG SUBMENU
│   ├── Ch Start      → Start channel (1=2.4GHz, 36=5GHz)
│   ├── Cycle ms      → Delay between attack cycles
│   ├── Scan ms       → WiFi scan duration
│   ├── Frames        → Frames per AP per burst
│   ├── LED           → Toggle LED indicators
│   └── Hop           → Channel hop settings
├── Info              → Show device info + TX stats
└── TX Stats          → Show TX success/fail counts on serial
```

## Navigation

| Input | Action |
|-------|--------|
| Up/Down | Move cursor |
| Middle or Right | Select / enter submenu |
| Left | Back to parent menu |
