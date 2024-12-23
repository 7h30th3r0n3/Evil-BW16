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



// =========================
// Promiscuous Callback
// =========================
void promisc_callback(unsigned char *buf, unsigned int len, void * /*userdata*/) {
  // Checks the minimum size to contain the 802.11 header
  if (!buf || len < sizeof(wifi_ieee80211_mac_hdr)) {
    return;
  }

  // Interpret the header
  wifi_ieee80211_mac_hdr *hdr = (wifi_ieee80211_mac_hdr *)buf;
  // Frame Control
  uint16_t fc = hdr->frame_control;
  uint8_t ftype    = ieee80211_get_type(fc);
  uint8_t fsubtype = ieee80211_get_subtype(fc);

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

  Serial.println("[INFO] Enabling promiscuous mode...");

  // 1) Enable WiFi in PROMISC mode
  wifi_on(RTW_MODE_PROMISC);
  wifi_enter_promisc_mode();

  // 2) Set channel
  wifi_set_channel(36);

  // 3) Start capture (depending on your SDK, use RTW_PROMISC_ENABLE / RTW_PROMISC_ENABLE_2 / etc.)
  wifi_set_promisc(RTW_PROMISC_ENABLE_2, promisc_callback, 1);

  Serial.println("[INFO] Sniffer initialized, listening.");
}

void loop() {
  // The promiscuous callback (promisc_callback) is invoked in the background
  // as soon as a packet is intercepted on the current channel.
  delay(100);
}
