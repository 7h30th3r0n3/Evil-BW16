#include <Arduino.h>

extern "C" {
#include "platform_stdlib.h"
#include "wifi_conf.h"
}

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
// Utility Functions
// =========================

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

// Add these globals at the start of the file, after the includes
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
const int CHANNELS_2GHZ[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
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


void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("\n[INFO] WiFi Sniffer Commands:");
  Serial.println("start           - Start the sniffer in ALL mode");
  Serial.println("sniff beacon    - Start/Switch to beacon capture");
  Serial.println("sniff probe     - Start/Switch to probe requests/responses");
  Serial.println("sniff deauth    - Start/Switch to deauth/disassoc frames");
  Serial.println("sniff eapol     - Start/Switch to EAPOL frames");
  Serial.println("sniff pwnagotchi- Start/Switch to Pwnagotchi beacons");
  Serial.println("sniff all       - Start/Switch to all frames");
  Serial.println("stop            - Stop sniffing");
  Serial.println("hop on          - Enable channel hopping");
  Serial.println("hop off         - Disable channel hopping");
  Serial.println("set ch X        - Set to specific channel X");
  
  Serial.println("\n[INFO] Waiting for command to start...");
}

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
            if (currentChannelIndex >= numCustomChannels) {
                currentChannelIndex = 0;
            }
            currentChannel = customChannels[currentChannelIndex];
        } else {
            if (currentChannelIndex >= sizeof(CHANNELS_2GHZ)/sizeof(CHANNELS_2GHZ[0])) {
                currentChannelIndex = 0;
            }
            currentChannel = CHANNELS_2GHZ[currentChannelIndex];
        }
        
        setChannel(currentChannel);
        Serial.print("[HOP] Switched to channel ");
        Serial.println(currentChannel);
        lastHopTime = millis();
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

void processCommand(String command) {
  command.toLowerCase();
  command.trim();
  
  if (command == "start") {
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
  else if (command == "stop") {
    stopSniffing();
  }
  else {
    Serial.println("[ERROR] Unknown command");
  }
}

void loop() {
  // Check for serial commands
  if (Serial.available()) {
    String command = Serial.readStringUntil('\n');
    processCommand(command);
  }
  
  // Handle channel hopping if enabled
  if (isSniffing) {
    hopChannel();
  }
  
  delay(100);
}
