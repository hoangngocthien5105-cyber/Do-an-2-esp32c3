#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include "mbedtls/md.h"

// ==========================================
// THÔNG TIN CẤU HÌNH VÀ UUID CHUẨN XÁC
// ==========================================
#define DEVICE_NAME         "SMARTKEY_C3"
#define SERVICE_UUID        "12345678-1234-1234-1234-1234567890AB"
#define CHALLENGE_CHAR_UUID "12345678-1234-1234-1234-1234567890AC"
#define RESPONSE_CHAR_UUID  "12345678-1234-1234-1234-1234567890AD"

// 32-byte Secret Key đồng bộ với ESP32-WROOM-32 (SK001)
static const uint8_t SECRET_KEY[32] = {
    0x53, 0x4B, 0x30, 0x30, 0x31, 0x5F, 0x53, 0x45, 
    0x43, 0x52, 0x45, 0x54, 0x5F, 0x4B, 0x45, 0x59,
    0x5F, 0x32, 0x30, 0x32, 0x36, 0x5F, 0x48, 0x4D,
    0x41, 0x43, 0x5F, 0x53, 0x48, 0x41, 0x32, 0x35
};

// Con trỏ đối tượng BLE Characteristic
BLECharacteristic *pChallengeCharacteristic = nullptr;
BLECharacteristic *pResponseCharacteristic  = nullptr;
BLEServer         *pServer                  = nullptr;

// Cờ trạng thái kết nối
static volatile bool deviceConnected    = false;
static volatile bool oldDeviceConnected = false;

// ==========================================
// HÀM TÍNH TOÁN HMAC-SHA256 QUA MBEDTLS
// ==========================================
bool compute_hmac_sha256(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         uint8_t *output) {
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);

    if (md_info == nullptr) {
        return false;
    }

    mbedtls_md_init(&ctx);
    int ret = mbedtls_md_setup(&ctx, md_info, 1); // 1 = HMAC
    if (ret != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_starts(&ctx, key, key_len);
    if (ret != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_update(&ctx, data, data_len);
    if (ret != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }

    ret = mbedtls_md_hmac_finish(&ctx, output);
    mbedtls_md_free(&ctx);

    return (ret == 0);
}

// ==========================================
// CALLBACK QUẢN LÝ KẾT NỐI BLE SERVER
// ==========================================
class ServerCallbacks : public BLEServerCallbacks {
    void onConnect(BLEServer* pServerInstance) override {
        deviceConnected = true;
        Serial.println("[BLE] ESP32 chinh da ket noi!");
    }

    void onDisconnect(BLEServer* pServerInstance) override {
        deviceConnected = false;
        Serial.println("[BLE] ESP32 chinh da ngat ket noi!");
    }
};

// ==========================================
// CALLBACK XỬ LÝ KHI NHẬN CHALLENGE GHI TỪ CENTRAL
// ==========================================
class ChallengeCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic *pChar) override {
        // Tương thích cả ESP32 Core 2.x (std::string) và Core 3.x (uint8_t* / String)
        const uint8_t *data = pChar->getData();
        size_t len = pChar->getLength();

        // 1. Kiểm tra kích thước chính xác 16 byte nhị phân thô
        if (len != 16 || data == nullptr) {
            Serial.println("[AUTH] Challenge khong hop le!");
            return;
        }

        Serial.println("[AUTH] Da nhan Challenge 16 byte!");
        Serial.println("[AUTH] Dang tinh HMAC-SHA256...");

        // 2. Tính toán HMAC-SHA256 (Secret Key: 32 bytes, Challenge: 16 bytes)
        uint8_t response[32];
        if (compute_hmac_sha256(SECRET_KEY, sizeof(SECRET_KEY), data, len, response)) {
            Serial.println("[AUTH] Da tao Response 32 byte!");

            // 3. Cập nhật dữ liệu vào Response Characteristic (READ & NOTIFY)
            pResponseCharacteristic->setValue(response, sizeof(response));
            pResponseCharacteristic->notify();

            Serial.println("[AUTH] Da gui Response qua NOTIFY!");
        } else {
            Serial.println("[AUTH] Tinh toan HMAC that bai!");
        }
    }
};

// ==========================================
// SETUP
// ==========================================
void setup() {
    Serial.begin(115200);
    // Đợi tối đa 3 giây để kịp kết nối Serial Monitor qua USB CDC (không bị treo nếu không cắm máy tính)
    unsigned long startWait = millis();
    while (!Serial && (millis() - startWait < 3000)) {
        delay(10);
    }
    delay(500);

    Serial.println("[SMARTKEY] ESP32-C3 dang khoi dong...");

    // 1. Khởi tạo BLE Device
    BLEDevice::init(DEVICE_NAME);

    // === [ĐIỀU CHỈNH CÔNG SUẤT PHÁT BLE] ===
    // Giảm từ -6 dBm (~5m) xuống -12 dBm (~2-3m)
    // Áp dụng cho cả mặc định (kết nối) và Advertising
    BLEDevice::setPower(ESP_PWR_LVL_N12, ESP_BLE_PWR_TYPE_DEFAULT);
    BLEDevice::setPower(ESP_PWR_LVL_N12, ESP_BLE_PWR_TYPE_ADV);
    Serial.println("[BLE] TX Power da dat muc -12 dBm!");
    // =======================================

    // 2. Tạo BLE Server & gán Callback
    pServer = BLEDevice::createServer();
    pServer->setCallbacks(new ServerCallbacks());

    // 3. Tạo BLE Service
    BLEService *pService = pServer->createService(SERVICE_UUID);

    // 4. Tạo Challenge Characteristic (Chỉ hỗ trợ WRITE)
    pChallengeCharacteristic = pService->createCharacteristic(
        CHALLENGE_CHAR_UUID,
        BLECharacteristic::PROPERTY_WRITE
    );
    pChallengeCharacteristic->setCallbacks(new ChallengeCallbacks());

    // 5. Tạo Response Characteristic (Hỗ trợ READ và NOTIFY)
    pResponseCharacteristic = pService->createCharacteristic(
        RESPONSE_CHAR_UUID,
        BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY
    );
    // Thêm Descriptor 2902 bắt buộc để Central có thể đăng ký NOTIFY
    pResponseCharacteristic->addDescriptor(new BLE2902());

    // 6. Bắt đầu Service
    pService->start();

    // 7. Cấu hình BLE Advertising
    BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
    pAdvertising->addServiceUUID(SERVICE_UUID);
    pAdvertising->setScanResponse(true);
    pAdvertising->setMinPreferred(0x06); // Hỗ trợ kết nối nhanh với iPhone/Central
    pAdvertising->setMinPreferred(0x12);

    // 8. Bắt đầu quảng bá
    BLEDevice::startAdvertising();

    Serial.println("[BLE] BLE Peripheral da san sang!");
    Serial.println("[BLE] Dang quang ba SMARTKEY_C3...");
}

// ==========================================
// LOOP
// ==========================================
void loop() {
    // Xử lý tự động quảng bá lại khi ngắt kết nối an toàn ngoài callback
    if (!deviceConnected && oldDeviceConnected) {
        delay(500); // Chờ BLE stack giải phóng phiên cũ
        pServer->startAdvertising();
        Serial.println("[BLE] Advertising da khoi dong lai!");
        oldDeviceConnected = deviceConnected;
    }

    // Cập nhật trạng thái kết nối
    if (deviceConnected && !oldDeviceConnected) {
        oldDeviceConnected = deviceConnected;
    }

    delay(20);
}
