/*
 * WiFi Deauth Attack Detector - ESP8266 Code
 * Monitors WiFi for deauthentication attacks
 * 
 * SETUP INSTRUCTIONS:
 * 1. Set DIP switches: 5,6,7 ON (rest OFF) - ESP8266 Programming Mode
 * 2. Arduino IDE Settings:
 *    - Board: "Generic ESP8266 Module"
 *    - Upload Speed: 9600
 *    - Flash Size: "4MB (FS:2MB OTA:~1019KB)"
 * 3. Upload this code
 * 4. Set DIP switches: 5,6 ON (rest OFF) - Run Mode
 * 5. Open Serial Monitor at 115200 baud
 */

#include <ESP8266WiFi.h>

extern "C" {
  #include <user_interface.h>
}

// Deauth detection settings
#define DEAUTH_THRESHOLD 100      // Burst threshold - 100+ in 1 second = attack
#define TIME_WINDOW 1000          // Time window in ms (1 second)
#define CHANNEL_HOP_INTERVAL 3000 // How often to change channels
#define MIN_BURST_RATE 50         // Minimum rate to even log activity

// Track unique attacks (same source spamming)
#define MAX_TRACKED_ATTACKERS 10
struct Attacker {
  uint8_t mac[6];
  unsigned long count;
  unsigned long lastSeen;
};
Attacker attackers[MAX_TRACKED_ATTACKERS];

// Packet structure for deauth frames
typedef struct {
  unsigned frame_ctrl:16;
  unsigned duration_id:16;
  uint8_t addr1[6]; // receiver address
  uint8_t addr2[6]; // sender address
  uint8_t addr3[6]; // BSSID
  unsigned sequence_ctrl:16;
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0];
} wifi_ieee80211_packet_t;

// Statistics
unsigned long deauthCount = 0;
unsigned long lastDeauthTime = 0;
unsigned long deauthsInWindow = 0;
unsigned long windowStartTime = 0;
int currentChannel = 1;
unsigned long lastChannelHop = 0;
unsigned long alertCooldown = 0;
#define ALERT_COOLDOWN_TIME 5000

// Per-channel rate tracking
unsigned long channelDeauthCount[15] = {0};
unsigned long channelWindowStart[15] = {0};

// Channel to monitor (1-14)
void setChannel(int channel) {
  wifi_set_channel(channel);
  currentChannel = channel;
}

// Check if MAC is broadcast or multicast (these are often legitimate)
bool isBroadcastOrMulticast(uint8_t *mac) {
  return (mac[0] == 0xFF) || (mac[0] & 0x01);
}

// Find or add attacker
int findAttacker(uint8_t *mac) {
  unsigned long now = millis();
  
  // Find existing
  for (int i = 0; i < MAX_TRACKED_ATTACKERS; i++) {
    if (memcmp(attackers[i].mac, mac, 6) == 0) {
      // Reset if old entry
      if (now - attackers[i].lastSeen > TIME_WINDOW * 2) {
        attackers[i].count = 0;
      }
      return i;
    }
  }
  
  // Find empty slot
  for (int i = 0; i < MAX_TRACKED_ATTACKERS; i++) {
    if (attackers[i].lastSeen == 0 || now - attackers[i].lastSeen > TIME_WINDOW * 3) {
      memcpy(attackers[i].mac, mac, 6);
      attackers[i].count = 0;
      attackers[i].lastSeen = now;
      return i;
    }
  }
  
  return -1;
}

// Callback for promiscuous mode
void sniffer_callback(uint8_t *buffer, uint16_t length) {
  wifi_ieee80211_packet_t *packet = (wifi_ieee80211_packet_t *)buffer;
  
  // Check if this is a deauth or disassoc frame
  // Deauth = 0xC0, Disassoc = 0xA0
  uint16_t frameControl = packet->hdr.frame_ctrl;
  uint8_t frameType = (frameControl & 0x0C) >> 2;
  uint8_t frameSubType = (frameControl & 0xF0) >> 4;
  
  // Type 0 = Management, SubType 12 = Deauth, SubType 10 = Disassoc
  if (frameType == 0 && (frameSubType == 12 || frameSubType == 10)) {
    unsigned long currentTime = millis();
    
    // Filter out broadcast/multicast (these are often legitimate network management)
    if (isBroadcastOrMulticast(packet->hdr.addr1)) {
      return; // Ignore legitimate broadcast deauths
    }
    
    deauthCount++;
    lastDeauthTime = currentTime;
    
    // Track per-channel rate
    if (currentTime - channelWindowStart[currentChannel] > TIME_WINDOW) {
      channelWindowStart[currentChannel] = currentTime;
      channelDeauthCount[currentChannel] = 1;
    } else {
      channelDeauthCount[currentChannel]++;
    }
    
    int rate = channelDeauthCount[currentChannel];
    
    // Track source MAC for repeat offenders
    int attackerIdx = findAttacker(packet->hdr.addr2);
    if (attackerIdx >= 0) {
      attackers[attackerIdx].count++;
      attackers[attackerIdx].lastSeen = currentTime;
    }
    
    // Only log and alert if rate is suspiciously high
    if (rate >= MIN_BURST_RATE) {
      char addr1[18], addr2[18];
      snprintf(addr1, sizeof(addr1), "%02X:%02X:%02X:%02X:%02X:%02X",
               packet->hdr.addr1[0], packet->hdr.addr1[1], packet->hdr.addr1[2],
               packet->hdr.addr1[3], packet->hdr.addr1[4], packet->hdr.addr1[5]);
      snprintf(addr2, sizeof(addr2), "%02X:%02X:%02X:%02X:%02X:%02X",
               packet->hdr.addr2[0], packet->hdr.addr2[1], packet->hdr.addr2[2],
               packet->hdr.addr2[3], packet->hdr.addr2[4], packet->hdr.addr2[5]);
      
      Serial.print("[CH");
      Serial.print(currentChannel);
      Serial.print("] ");
      
      if (frameSubType == 12) {
        Serial.print("DEAUTH");
      } else {
        Serial.print("DISASSOC");
      }
      
      Serial.print(" | Rate: ");
      Serial.print(rate);
      Serial.print("/sec | ");
      Serial.print(addr2);
      Serial.print(" → ");
      Serial.println(addr1);
      
      // Alert on sustained high-rate attacks
      if (rate >= DEAUTH_THRESHOLD && (currentTime - alertCooldown > ALERT_COOLDOWN_TIME)) {
        Serial.println();
        Serial.println("╔═══════════════════════════════════════════════╗");
        Serial.println("║  🚨 DEAUTH ATTACK DETECTED! 🚨               ║");
        Serial.println("╠═══════════════════════════════════════════════╣");
        Serial.print("║  Channel: ");
        Serial.print(currentChannel);
        Serial.print("  | Rate: ");
        Serial.print(rate);
        Serial.println(" pkts/sec         ║");
        Serial.print("║  Attacker: ");
        Serial.print(addr2);
        Serial.println("      ║");
        Serial.println("║                                               ║");
        Serial.println("║  This is a REAL attack - way above normal!   ║");
        Serial.println("╚═══════════════════════════════════════════════╝");
        Serial.println();
        
        alertCooldown = currentTime;
      }
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(500);
  
  Serial.println("\n\n");
  Serial.println("╔═══════════════════════════════════════════════╗");
  Serial.println("║     WiFi Deauth Attack Detector v1.0         ║");
  Serial.println("║     Monitoring for malicious activity...     ║");
  Serial.println("╚═══════════════════════════════════════════════╝");
  Serial.println();
  
  // Set WiFi to station mode and disconnect
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  
  // Enable promiscuous mode
  wifi_set_opmode(STATION_MODE);
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(sniffer_callback);
  wifi_promiscuous_enable(1);
  
  // Start on channel 1
  setChannel(1);
  windowStartTime = millis();
  
  // Initialize attacker tracking
  for (int i = 0; i < MAX_TRACKED_ATTACKERS; i++) {
    attackers[i].lastSeen = 0;
    attackers[i].count = 0;
  }
  
  Serial.println("✓ Promiscuous mode enabled");
  Serial.println("✓ Filtering broadcast/multicast deauths (legitimate)");
  Serial.print("✓ Attack threshold: ");
  Serial.print(DEAUTH_THRESHOLD);
  Serial.println(" unicast packets/sec");
  Serial.print("✓ Logging threshold: ");
  Serial.print(MIN_BURST_RATE);
  Serial.println(" packets/sec");
  Serial.println();
  Serial.println("Monitoring started. Legitimate traffic filtered.");
  Serial.println("─────────────────────────────────────────────────");
  Serial.println();
}

void loop() {
  unsigned long currentTime = millis();
  
  // Channel hopping to monitor all channels
  if (currentTime - lastChannelHop > CHANNEL_HOP_INTERVAL) {
    lastChannelHop = currentTime;
    currentChannel++;
    if (currentChannel > 14) {
      currentChannel = 1;
    }
    setChannel(currentChannel);
    
    // Print status update
    Serial.print("→ Ch ");
    Serial.print(currentChannel);
    Serial.print(" | Rate: ");
    Serial.print(channelDeauthCount[currentChannel]);
    Serial.print("/sec");
    
    // Show if this channel looks suspicious
    if (channelDeauthCount[currentChannel] >= MIN_BURST_RATE) {
      Serial.print(" ⚠️ HIGH");
    } else if (channelDeauthCount[currentChannel] > 20) {
      Serial.print(" ⚡ Elevated");
    } else {
      Serial.print(" ✓ Normal");
    }
    
    Serial.print(" | Total: ");
    Serial.println(deauthCount);
  }
  
  delay(10);
}
