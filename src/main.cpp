
#include <Arduino.h>

void setup() {
    Serial.begin(115200);
    delay(2000);

    Serial.println();
    Serial.println("================================");
    Serial.println("       ESP32-C3 SERIAL TEST");
    Serial.println("================================");
    Serial.println("ESP32-C3 khoi dong thanh cong!");
    Serial.println("Serial Monitor dang hoat dong.");
}

void loop() {
    static int count = 0;

    count++;

    Serial.print("ESP32-C3 dang chay - Lan: ");
    Serial.println(count);

    delay(2000);
}