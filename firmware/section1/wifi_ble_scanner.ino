#include <Arduino.h>
#include <WiFi.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <vector>

#define WIFI_SCAN_ATTEMPTS      2
#define BLE_SCAN_DURATION_SEC   8
#define RSSI_FLOOR_DBM         -85
#define THREAT_SCORE_THRESHOLD  40

const char* SUSPICIOUS_SSID_KEYWORDS[] = {
  "cam", "ipcam", "camera", "spy", "hidden",
  "vstarcam", "iegeek", "wansview", "reolink",
  "esp32cam", "esp8266", "ov2640",
  "tracker", "track", "gps", "gt06", "tk103",
  nullptr
};

const char* SUSPICIOUS_OUI[] = {
  "E0:AB", "A4:CF", "24:6F", "D8:BF", "CC:50", nullptr
};

struct WiFiResult {
  String ssid, bssid, reason;
  int32_t rssi;
  uint8_t channel, encType;
  int threatScore;
};

struct BLEResult {
  String name, address, reason;
  int rssi, threatScore;
};

std::vector<WiFiResult> wifiResults;
std::vector<BLEResult>  bleResults;

class BLEResultCallback : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice dev) override {
    int rssi = dev.getRSSI();
    if (rssi < RSSI_FLOOR_DBM) return;

    BLEResult r;
    r.address     = dev.getAddress().toString().c_str();
    r.rssi        = rssi;
    r.threatScore = 0;
    r.reason      = "";
    r.name        = dev.haveName() ? dev.getName().c_str() : "(unnamed)";

    if (r.name == "(unnamed)")     { r.threatScore += 25; r.reason += "unnamed "; }
    if (rssi > -55)                { r.threatScore += 20; r.reason += "very-close "; }
    else if (rssi > -65)           { r.threatScore += 10; r.reason += "close "; }
    if (!dev.haveServiceUUID())    { r.threatScore += 15; r.reason += "no-uuid "; }
    if (dev.haveManufacturerData() && r.name == "(unnamed)") {
      r.threatScore += 20; r.reason += "anon-mfr-data ";
    }

    String lower = r.name;
    lower.toLowerCase();
    for (int i = 0; SUSPICIOUS_SSID_KEYWORDS[i]; i++) {
      if (lower.indexOf(SUSPICIOUS_SSID_KEYWORDS[i]) >= 0) {
        r.threatScore += 40; r.reason += "suspicious-name "; break;
      }
    }

    r.threatScore = min(r.threatScore, 100);
    bleResults.push_back(r);
  }
};

int scoreWiFi(WiFiResult& r) {
  int score = 0;
  r.reason = "";
  String lower = r.ssid;
  lower.toLowerCase();

  for (int i = 0; SUSPICIOUS_SSID_KEYWORDS[i]; i++) {
    if (lower.indexOf(SUSPICIOUS_SSID_KEYWORDS[i]) >= 0) {
      score += 50; r.reason += "suspicious-ssid "; break;
    }
  }
  if (r.ssid == "(hidden)")        { score += 20; r.reason += "hidden-ssid "; }
  if (r.encType == WIFI_AUTH_OPEN) { score += 20; r.reason += "open-network "; }
  if (r.rssi > -50)                { score += 15; r.reason += "very-close "; }
  else if (r.rssi > -65)           { score += 8;  r.reason += "close "; }

  String bUp = r.bssid;
  bUp.toUpperCase();
  for (int i = 0; SUSPICIOUS_OUI[i]; i++) {
    if (bUp.startsWith(SUSPICIOUS_OUI[i])) {
      score += 30; r.reason += "suspect-vendor "; break;
    }
  }
  return min(score, 100);
}

void runWiFiScan() {
  Serial.println("[WiFi] Scanning...");
  wifiResults.clear();
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  for (int attempt = 0; attempt < WIFI_SCAN_ATTEMPTS; attempt++) {
    int found = WiFi.scanNetworks(false, true);
    Serial.print("[WiFi] Pass ");
    Serial.print(attempt + 1);
    Serial.print(": ");
    Serial.print(found);
    Serial.println(" networks");

    for (int i = 0; i < found; i++) {
      int32_t rssi = WiFi.RSSI(i);
      if (rssi < RSSI_FLOOR_DBM) continue;
      String bssid = WiFi.BSSIDstr(i);
      bool dup = false;
      for (auto& e : wifiResults) {
        if (e.bssid == bssid) {
          if (rssi > e.rssi) e.rssi = rssi;
          dup = true;
          break;
        }
      }
      if (!dup) {
        WiFiResult r;
        r.ssid    = WiFi.SSID(i).isEmpty() ? "(hidden)" : WiFi.SSID(i);
        r.bssid   = bssid;
        r.rssi    = rssi;
        r.channel = WiFi.channel(i);
        r.encType = WiFi.encryptionType(i);
        wifiResults.push_back(r);
      }
    }
    WiFi.scanDelete();
    if (attempt < WIFI_SCAN_ATTEMPTS - 1) delay(500);
  }

  for (auto& r : wifiResults) r.threatScore = scoreWiFi(r);
  Serial.print("[WiFi] Unique networks: ");
  Serial.println((int)wifiResults.size());
}

void runBLEScan() {
  Serial.println("[BLE] Scanning...");
  bleResults.clear();
  BLEDevice::init("");
  BLEScan* pScan = BLEDevice::getScan();
  pScan->setAdvertisedDeviceCallbacks(new BLEResultCallback(), false);
  pScan->setActiveScan(true);
  pScan->setInterval(100);
  pScan->setWindow(99);
  pScan->start(BLE_SCAN_DURATION_SEC, false);
  pScan->clearResults();
  Serial.print("[BLE] Devices found: ");
  Serial.println((int)bleResults.size());
}

void printReport() {
  int threats = 0;
  Serial.println("");
  Serial.println("+----------------------------------+");
  Serial.println("|   SWOOPR - SCAN REPORT           |");
  Serial.println("+----------------------------------+");

  Serial.println("");
  Serial.println("-- WiFi Networks --");
  if (wifiResults.empty()) {
    Serial.println("  None detected.");
  } else {
    for (auto& r : wifiResults) {
      bool f = r.threatScore >= THREAT_SCORE_THRESHOLD;
      if (f) threats++;
      Serial.print("  SSID: "); Serial.println(r.ssid);
      Serial.print("  BSSID: "); Serial.print(r.bssid);
      Serial.print("  CH:"); Serial.print(r.channel);
      Serial.print("  "); Serial.println(r.encType == WIFI_AUTH_OPEN ? "OPEN" : "ENCRYPTED");
      Serial.print("  RSSI: "); Serial.print(r.rssi);
      Serial.print(" dBm  Score: "); Serial.print(r.threatScore);
      Serial.println(f ? "  <<< FLAGGED" : "");
      if (r.reason.length()) { Serial.print("  Flags: "); Serial.println(r.reason); }
      Serial.println("  ---");
    }
  }

  Serial.println("");
  Serial.println("-- BLE Devices --");
  if (bleResults.empty()) {
    Serial.println("  None detected.");
  } else {
    for (auto& r : bleResults) {
      bool f = r.threatScore >= THREAT_SCORE_THRESHOLD;
      if (f) threats++;
      Serial.print("  Name: "); Serial.println(r.name);
      Serial.print("  MAC: "); Serial.println(r.address);
      Serial.print("  RSSI: "); Serial.print(r.rssi);
      Serial.print(" dBm  Score: "); Serial.print(r.threatScore);
      Serial.println(f ? "  <<< FLAGGED" : "");
      if (r.reason.length()) { Serial.print("  Flags: "); Serial.println(r.reason); }
      Serial.println("  ---");
    }
  }

  Serial.println("");
  Serial.println("+----------------------------------+");
  if (threats == 0) {
    Serial.println("|  RESULT: CLEAR                   |");
  } else {
    Serial.print("|  RESULT: ");
    Serial.print(threats);
    Serial.println(" DEVICE(S) FLAGGED       |");
  }
  Serial.println("+----------------------------------+");
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("SWOOPR - Section 1 - WiFi + BLE Scanner");
  Serial.println("Starting scan...");
  runWiFiScan();
  runBLEScan();
  printReport();
  Serial.println("Done. Reset board to scan again.");
}

void loop() {
  delay(10000);
}