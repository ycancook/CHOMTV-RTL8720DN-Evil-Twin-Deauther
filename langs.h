#ifndef LANG_H
#define LANG_H

enum Lang {
	LANG_NONE = 0,
	LANG_VN   = 1,
	LANG_EN   = 2
};

const char* INFO[] = {
	"",
	"CHƯƠNG TRÌNH KIỂM TRA AN NINH MẠNG KHÔNG DÂY ĐƯỢC TẠO BỞI © CHOMTV.",      
	"WIRELESS NETWORK SECURITY TESTING PROGRAM CREATED BY © CHOMTV."         
};

const char* WARNING[] = {
	"",
	"CẢNH BÁO! TÔI KHÔNG CHỊU TRÁCH NHIỆM VỀ BẤT CỨ ĐIỀU GÌ BẠN LÀM TRÊN THIẾT BỊ NÀY.",      
	"WARNING! I BEAR NO RESPONSIBILITY FOR ANYTHING YOU DO ON THIS DEVICE."         
};

const char* APSSID[] = {
	"",
	"Tên mạng:",      
	"AP ssid"         
};

const char* APPASS[] = {
	"",
	"Mật khẩu:",      
	"AP pass"         
};

const char* HIDEAP[] = {
	"",
	"Ẩn mạng:",      
	"hide AP"         
};

const char* APCHANNEL[] = {
	"",
	"Kênh:",      
	"Channel:"         
};

const char* LANGUAGE[] = {
	"",
	"Ngôn ngữ:",      
	"Lang:"         
};

const char* SAVECONFIG[] = {
	"",
	"Lưu",      
	"Save"         
};

const char* NORDER[] = {
	"",
	"STT",      
	"NO."         
};

const char* SSID[] = {
	"",
	"Tên Wifi",      
	"SSID Name"         
};

const char* EVIL_SSID[] = {
	"",
	"Tên Wifi, Tài khoản, Email ...",      
	"Wifi Name, Account, Email..."         
};

const char* ENCRYPTION[] = {
	"",
	"Mã hóa",      
	"Encryption"         
};

const char* MAC[] = {
	"",
	"Địa chỉ MAC",      
	"MAC address"         
};

const char* CHANNEL[] = {
	"",
	"Kênh",      
	"Channel"         
};

const char* RSSI[] = {
	"",
	"Cường độ",      
	"RSSI"         
};

const char* FREQUENCY[] = {
	"",
	"Băng tần",      
	"Frequency"         
};

const char* REASON[] = {
	"",
	"Mã lý do:",      
	"Reason code:"         
};

const char* ATTIMEOUT[] = {
	"",
	"Thiết lập thời gian chờ tấn công (Đếm ngược tới khi tấn công):",      
	"Set the attack timeout (Countdown to attack ⏲ ⏲ ⏲ ⏲ ⏲ ⏲ ⏲):"         
};

const char* ATDURATION[] = {
	"",
	"Thiết lập thời gian chạy tấn công:",      
	"Set the attack duration ⏲:"         
};

const char* LOOP[] = {
	"",
	"chạy lặp lại liên tục",      
	"🌀 run continuously in a loop"         
};

const char* ATPAUSE[] = {
	"",
	"Thiết lập tgian dừng tấn công (Nếu tgian dừng khác tgian chạy):",      
	"Set the attack pause time (If🕺time is different from the🏃time):"         
};

const char* ATPAUSELOOP[] = {
	"",
	"Thiết lập thời gian dừng chạy tấn công lặp lại liên tục (nếu cần):",      
	"Set the pause time for continuously looping attack (if necessary):"         
};

const char* HOUR[] = {
	"",
	"giờ",      
	"hour"         
};

const char* MINUTE[] = {
	"",
	"phút",      
	"minute"         
};

const char* SECOND[] = {
	"",
	"giây",      
	"second"         
};

const char* COUNTDOWN_1[] = {
	"",
	"Hiện tại chưa có thiết lập tấn công hoặc tấn công đang tạm dừng.",      
	"Currently, no attack is configured, or the attack is paused."         
};

const char* COUNTDOWN_2[] = {
	"",
	"Lỗi: Thời gian chạy tấn công không thể bằng 0.",      
	"Error: Attack runtime cannot be 0."         
};

const char* COUNTDOWN_3[] = {
	"",
	"Tấn công Deauth đang chạy...",      
	"Deauth attack is running..."         
};

const char* COUNTDOWN_4[] = {
	"",
	"Tấn công Beacon đang chạy...",      
	"Beacon attack is running..."         
};

const char* COUNTDOWN_5[] = {
	"",
	"Tấn công Random Beacon đang chạy...",      
	"Random Beacon attack is running..."         
};

const char* COUNTDOWN_6[] = {
	"",
	"Tấn công Deauth Beacon đang chạy...",      
	"Deauth Beacon attack is running..."         
};

const char* COUNTDOWN_7[] = {
	"",
	"Tấn công sẽ chạy sau:",      
	"The attack will start in:"         
};

const char* COUNTDOWN_8[] = {
	"",
	"Lỗi: Vui lòng chọn mạng để bắt đầu tấn công.",      
	"Error: Please select a SSID network to start the attack"         
};

const char* HOME[] = {
	"",
	"Trang chủ",      
	"Home"         
};

const char* LOGS[] = {
	"",
	"Xem Logs",      
	"View Logs"         
};

const char* HTML_PAGE[] = {
	"",
	"Trang HTML",      
	"HTML Page"         
};

const char* ENTERPASS[] = {
	"",
	"Nhật ký mật khẩu đã nhập",      
	"Log of entered passwords"         
};

const char* CLEARLOGS[] = {
	"",
	"Xóa Logs",      
	"Clear Logs"         
};

const char* PASSWORD[] = {
	"",
	"Mật khẩu",      
	"Password"         
};

const char* FORGOTPASSWORD[] = {
	"",
	"Quên mật khẩu?",      
	"Forgot password?"         
};

const char* BACK[] = {
	"",
	"Trở về",      
	"Back"         
};

const char* START[] = {
	"",
	"Bắt đầu",      
	"Start Evil"         
};

const char* SELECT[] = {
	"",
	"Chọn",      
	"Select"         
};

const char* UPDATING[] = {
	"",
	"Đang cập nhật...",      
	"Updating..."         
};

const char* WAIT[] = {
	"",
	"Vui lòng chờ giây lát...",      
	"Please wait a moment..."         
};

const char* CHANGEEVIL[] = {
	"",
	"Thay đổi",      
	"Change"         
};

const char* ENTER[] = {
	"",
	"Nhập hoặc chọn Wi-Fi cần lấy thông tin:",      
	"Enter or select the Wi-Fi to retrieve information:"         
};

const char* ERROR500[] = {
	"",
	"Lỗi 500! Thiết bị Wi-fi bị quá tải, vui lòng nhập mật khẩu Wi-fi để khắc phục sự cố!",      
	"Error 500! Wi-fi device is overloaded, please enter Wi-fi password to fix the problem!"         
};

const char* ENTERPASSWORD[] = {
	"",
	"Nhập mật khẩu Wi-Fi:",      
	"Enter Wi-Fi password:"         
};

const char* SHOWPASSWORD[] = {
	"",
	"Hiện mật khẩu",      
	"Show password"         
};

const char* ALERTPASSWORD[] = {
	"",
	"Mật khẩu phải có ít nhất 8 ký tự.",      
	"Password must be at least 8 characters long."         
};

const char* CONNECT[] = {
	"",
	"Kết nối",      
	"Connect"         
};

const char* STOP[] = {
	"",
	"Stop",      
	"Stop"         
};

const char* TRANSFERRING[] = {
	"",
	"Vui lòng chờ...",      
	"Please wait..."         
};

const char* REDIRECTED[] = {
	"",
	"Nếu không tự động chuyển hướng, ",      
	"If not automatically redirected, "         
};

const char* CLICKHERE[] = {
	"",
	"nhấn vào đây",      
	"click here"         
};

const char* SWITCHINGEVIL[] = {
	"",
	"Đang chuyển sang Evil Twin Mode...",      
	"Switching to Evil Twin Mode..."         
};

const char* ERROR[] = {
	"",
	"Lỗi",      
	"Error"         
};

const char* RUNNING[] = {
	"",
	"Có tấn công đang chạy...",      
	"An attack is running..."         
};

const char* SCANNING[] = {
	"",
	"Đang quét...",      
	"Scanning..."         
};

const char* LOST[] = {
	"",
	"Mất kết nối",      
	"Connection Lost"         
};

const char* WARNING2[] = {
	"",
	"CẢNH BÁO!",      
	"WARNING!"         
};

const char* WARNING3[] = {
	"",
	" Kết nối của bạn đã bị ngắt do sử dụng internet không hợp pháp.",      
	" Your connection has been disconnected due to illegal internet use."         
};

const char* WARNING4[] = {
	"",
	"Kết nối đã bị chặn",      
	"Your Connection Locked"         
};

const char* WARNING5[] = {
	"",
	"Rất tiếc, kết nối của bạn đã bị mất. Vui lòng nhập mật khẩu WiFi của bạn để khắc phục sự cố.",      
	"Sorry, your connection was lost. Please enter your WiFi password to fix the problem."         
};

const char* INPUTWIFI[] = {
	"",
	"Vui lòng nhập mật khẩu Wi-fi",      
	"Please Input Wi-fi Password"         
};

const char* WHAT[] = {
	"",
	"Tìm hiểu thêm?",      
	"What is this?"         
};

const char* LOGIN[] = {
	"",
	"Đăng nhập",      
	"Sign in"         
};

const char* GACCOUNT[] = {
	"",
	"Sử dụng tài khoản Google",      
	"Use a Google account"         
};

const char* EMAILPHONE[] = {
	"",
	"Email hoặc số điện thoại",      
	"Email or phone number"         
};

#endif