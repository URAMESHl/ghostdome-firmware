/*

TTGO T-BEAM Tracker for The Things Network

Copyright (C) 2018 by Xose Pérez <xose dot perez at gmail dot com>

This code requires LMIC library by Matthijs Kooijman
https://github.com/matthijskooijman/arduino-lmic

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#pragma once

#include <Arduino.h>

#ifdef RV3028_RTC
#include "Melopero_RV3028.h"
#endif
#ifdef PCF8563_RTC
#include "pcf8563.h"
#endif

// -----------------------------------------------------------------------------
// Version
// -----------------------------------------------------------------------------

// If app version is not specified we assume we are not being invoked by the build script
#ifndef APP_VERSION
#error APP_VERSION must be set by the build environment
#endif

// FIXME: This is still needed by the Bluetooth Stack and needs to be replaced by something better. Remnant of the old versioning
// system.
#ifndef HW_VERSION
#define HW_VERSION "1.0"
#endif

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Convert a preprocessor name into a quoted string
#define xstr(s) ystr(s)
#define ystr(s) #s

/// Convert a preprocessor name into a quoted string and if that string is empty use "unset"
#define optstr(s) (xstr(s)[0] ? xstr(s) : "unset")

// Nop definition for these attributes that are specific to ESP32
#ifndef EXT_RAM_ATTR
#define EXT_RAM_ATTR
#endif
#ifndef IRAM_ATTR
#define IRAM_ATTR
#endif
#ifndef RTC_DATA_ATTR
#define RTC_DATA_ATTR
#endif
#ifndef EXT_RAM_BSS_ATTR
#define EXT_RAM_BSS_ATTR EXT_RAM_ATTR
#endif

// -----------------------------------------------------------------------------
// Regulatory overrides
// -----------------------------------------------------------------------------

// Override user saved region, for producing region-locked builds
// #define REGULATORY_LORA_REGIONCODE meshtastic_Config_LoRaConfig_RegionCode_SG_923

// Total system gain in dBm to subtract from Tx power to remain within regulatory and Tx PA limits
// The value consists of PA gain + antenna gain (if variant has a non-removable antenna)
// TX_GAIN_LORA should be set with definitions below for common modules, or in variant.h.

// Gain for common modules with transmit PAs
#ifdef EBYTE_E22_900M30S
// 10dB PA gain and 30dB rated output; based on measurements from
// https://github.com/S5NC/EBYTE_ESP32-S3/blob/main/E22-900M30S%20power%20output%20testing.txt
#define TX_GAIN_LORA 7
#define SX126X_MAX_POWER 22
#endif

#ifdef EBYTE_E22_900M33S
// 25dB PA gain and 33dB rated output; based on TX Power Curve from E22-900M33S_UserManual_EN_v1.0.pdf
#define TX_GAIN_LORA 25
#define SX126X_MAX_POWER 8
#endif

#ifdef NICERF_MINIF27
// Note that datasheet power level of 9 corresponds with SX1262 at 22dBm
// Maximum output power of 29dBm with VCC_PA = 5V
#define TX_GAIN_LORA 7
#define SX126X_MAX_POWER 22
#endif

#ifdef NICERF_F30_HF
// Maximum output power of 29.6dBm with VCC = 5V and SX1262 at 22dBm
#define TX_GAIN_LORA 8
#define SX126X_MAX_POWER 22
#endif

#ifdef NICERF_F30_LF
// Maximum output power of 32.0dBm with VCC = 5V and SX1262 at 22dBm
#define TX_GAIN_LORA 10
#define SX126X_MAX_POWER 22
#endif

// Default system gain to 0 if not defined
#ifndef TX_GAIN_LORA
#define TX_GAIN_LORA 0
#endif

// -----------------------------------------------------------------------------
// Feature toggles
// -----------------------------------------------------------------------------

// Disable use of the NTP library and related features
// #define DISABLE_NTP

// Disable the welcome screen and allow
// #define DISABLE_WELCOME_UNSET

// -----------------------------------------------------------------------------
// OLED & Input
// -----------------------------------------------------------------------------
#if defined(SEEED_WIO_TRACKER_L1) && !defined(SEEED_WIO_TRACKER_L1_EINK)
#define SSD1306_ADDRESS 0x3D
#define USE_SH1106
#else
#define SSD1306_ADDRESS 0x3C
#endif
#define ST7567_ADDRESS 0x3F

// The SH1106 controller is almost, but not quite, the same as SSD1306
// Define this if you know you have that controller or your "SSD1306" misbehaves.
// #define USE_SH1106

// Define if screen should be mirrored left to right
// #define SCREEN_MIRROR

// I2C Keyboards (M5Stack, RAK14004, T-Deck, T-Deck Pro, T-Lora Pager, CardKB, BBQ10, MPR121, TCA8418)
#define CARDKB_ADDR 0x5F
#define TDECK_KB_ADDR 0x55
#define BBQ10_KB_ADDR 0x1F
#define MPR121_KB_ADDR 0x5A
#define TCA8418_KB_ADDR 0x34

// -----------------------------------------------------------------------------
// SENSOR
// -----------------------------------------------------------------------------
#define BME_ADDR 0x76
#define BME_ADDR_ALTERNATE 0x77
#define MCP9808_ADDR 0x18
#define INA_ADDR 0x40
#define INA_ADDR_ALTERNATE 0x41
#define INA_ADDR_WAVESHARE_UPS 0x43
#define INA3221_ADDR 0x42
#define MAX1704X_ADDR 0x36
#define QMC6310_ADDR 0x1C
#define QMI8658_ADDR 0x6B
#define QMC5883L_ADDR 0x0D
#define HMC5883L_ADDR 0x1E
#define SHTC3_ADDR 0x70
#define LPS22HB_ADDR 0x5C
#define LPS22HB_ADDR_ALT 0x5D
#define SHT31_4x_ADDR 0x44
#define SHT31_4x_ADDR_ALT 0x45
#define PMSA0031_ADDR 0x12
#define QMA6100P_ADDR 0x12
#define AHT10_ADDR 0x38
#define RCWL9620_ADDR 0x57
#define VEML7700_ADDR 0x10
#define TSL25911_ADDR 0x29
#define OPT3001_ADDR 0x45
#define OPT3001_ADDR_ALT 0x44
#define MLX90632_ADDR 0x3A
#define DFROBOT_LARK_ADDR 0x42
#define DFROBOT_RAIN_ADDR 0x1d
#define NAU7802_ADDR 0x2A
#define MAX30102_ADDR 0x57
#define SCD4X_ADDR 0x62
#define MLX90614_ADDR_DEF 0x5A
#define CGRADSENS_ADDR 0x66
#define LTR390UV_ADDR 0x53
#define XPOWERS_AXP192_AXP2101_ADDRESS 0x34 // same adress as TCA8418_KB
#define PCT2075_ADDR 0x37
#define BQ27220_ADDR 0x55 // same address as TDECK_KB
#define BQ25896_ADDR 0x6B
#define LTR553ALS_ADDR 0x23

// -----------------------------------------------------------------------------
// ACCELEROMETER
// -----------------------------------------------------------------------------
#define MPU6050_ADDR 0x68
#define STK8BXX_ADDR 0x18
#define LIS3DH_ADDR 0x18
#define LIS3DH_ADDR_ALT 0x19
#define BMA423_ADDR 0x19
#define LSM6DS3_ADDR 0x6A
#define BMX160_ADDR 0x69
#define ICM20948_ADDR 0x69
#define ICM20948_ADDR_ALT 0x68
#define BHI260AP_ADDR 0x28
#define BMM150_ADDR 0x13

// -----------------------------------------------------------------------------
// LED
// -----------------------------------------------------------------------------
#define NCP5623_ADDR 0x38
#define LP5562_ADDR 0x30

// -----------------------------------------------------------------------------
// Security
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// IO Expander
// -----------------------------------------------------------------------------
#define TCA9535_ADDR 0x20
#define TCA9555_ADDR 0x26

// -----------------------------------------------------------------------------
// Touchscreen
// -----------------------------------------------------------------------------
#define FT6336U_ADDR 0x48
#define CST328_ADDR 0x1A

// -----------------------------------------------------------------------------
// RAK12035VB Soil Monitor (using RAK12023 up to 3 RAK12035 monitors can be connected)
// - the default i2c address for this sensor is 0x20, and users are instructed to
// set 0x21 and 0x22 for the second and third sensor if present.
// -----------------------------------------------------------------------------
#define RAK120351_ADDR 0x20
#define RAK120352_ADDR 0x21
#define RAK120353_ADDR 0x22

// -----------------------------------------------------------------------------
// BIAS-T Generator
// -----------------------------------------------------------------------------
#define TPS65233_ADDR 0x60

// convert 24-bit color to 16-bit (56K)
#define COLOR565(r, g, b) (((r & 0xF8) << 8) | ((g & 0xFC) << 3) | ((b & 0xF8) >> 3))

/* Step #1: offer chance for variant-specific defines */
#include "variant.h"

#if defined(VEXT_ENABLE) && !defined(VEXT_ON_VALUE)
// Older variant.h files might not be defining this value, so stay with the old default
#define VEXT_ON_VALUE LOW
#endif

// -----------------------------------------------------------------------------
// GPS
// -----------------------------------------------------------------------------

#ifndef GPS_BAUDRATE
#define GPS_BAUDRATE 9600
#define GPS_BAUDRATE_FIXED 0
#else
#define GPS_BAUDRATE_FIXED 1
#endif

#ifndef GPS_THREAD_INTERVAL
#define GPS_THREAD_INTERVAL 200
#endif

/* Step #2: follow with defines common to the architecture;
   also enable HAS_ option not specifically disabled by variant.h */
#include "architecture.h"

#ifndef DEFAULT_REBOOT_SECONDS
#define DEFAULT_REBOOT_SECONDS 7
#endif

#ifndef DEFAULT_SHUTDOWN_SECONDS
#define DEFAULT_SHUTDOWN_SECONDS 2
#endif

#ifndef MINIMUM_SAFE_FREE_HEAP
#define MINIMUM_SAFE_FREE_HEAP 1500
#endif

#ifndef WIRE_INTERFACES_COUNT
// Officially an NRF52 macro
// Repurposed cross-platform to identify devices using Wire1
#if defined(I2C_SDA1) || defined(PIN_WIRE1_SDA)
#define WIRE_INTERFACES_COUNT 2
#elif HAS_WIRE
#define WIRE_INTERFACES_COUNT 1
#endif
#endif

/* Step #3: mop up with disabled values for HAS_ options not handled by the above two */

#ifndef HAS_WIFI
#define HAS_WIFI 0
#endif
#ifndef HAS_ETHERNET
#define HAS_ETHERNET 0
#endif
#ifndef HAS_SCREEN
#define HAS_SCREEN 0
#endif
#ifndef HAS_TFT
#define HAS_TFT 0
#endif
#ifndef HAS_WIRE
#define HAS_WIRE 0
#endif
#ifndef HAS_GPS
#define HAS_GPS 0
#endif
#ifndef HAS_BUTTON
#define HAS_BUTTON 0
#endif
#ifndef HAS_TRACKBALL
#define HAS_TRACKBALL 0
#endif
#ifndef HAS_TOUCHSCREEN
#define HAS_TOUCHSCREEN 0
#endif
#ifndef HAS_TELEMETRY
#define HAS_TELEMETRY 0
#endif
#ifndef HAS_SENSOR
#define HAS_SENSOR 0
#endif
#ifndef HAS_RADIO
#define HAS_RADIO 0
#endif
#ifndef HAS_RTC
#define HAS_RTC 0
#endif
#ifndef HAS_CPU_SHUTDOWN
#define HAS_CPU_SHUTDOWN 0
#endif
#ifndef HAS_BLUETOOTH
#define HAS_BLUETOOTH 0
#endif

#ifndef HW_VENDOR
#error HW_VENDOR must be defined
#endif

#ifndef TB_DOWN
#define TB_DOWN 255
#endif
#ifndef TB_UP
#define TB_UP 255
#endif
#ifndef TB_LEFT
#define TB_LEFT 255
#endif
#ifndef TB_RIGHT
#define TB_RIGHT 255
#endif
#ifndef TB_PRESS
#define TB_PRESS 255
#endif

// Support multiple RGB LED configuration
#if defined(HAS_NCP5623) || defined(HAS_LP5562) || defined(RGBLED_RED) || defined(HAS_NEOPIXEL) || defined(UNPHONE)
#define HAS_RGB_LED
#endif

// default mapping of pins
#if defined(PIN_BUTTON2) && !defined(CANCEL_BUTTON_PIN)
#define ALT_BUTTON_PIN PIN_BUTTON2
#endif
#if defined ALT_BUTTON_PIN

#ifndef ALT_BUTTON_ACTIVE_LOW
#define ALT_BUTTON_ACTIVE_LOW true
#endif
#ifndef ALT_BUTTON_ACTIVE_PULLUP
#define ALT_BUTTON_ACTIVE_PULLUP true
#endif
#endif

// -----------------------------------------------------------------------------
// Global switches to turn off features for a minimized build
// -----------------------------------------------------------------------------

// #define MESHTASTIC_MINIMIZE_BUILD 1
#ifdef MESHTASTIC_MINIMIZE_BUILD
#define MESHTASTIC_EXCLUDE_MODULES 1
#define MESHTASTIC_EXCLUDE_WIFI 1
#define MESHTASTIC_EXCLUDE_BLUETOOTH 1
#define MESHTASTIC_EXCLUDE_GPS 1
#define MESHTASTIC_EXCLUDE_SCREEN 1
#define MESHTASTIC_EXCLUDE_MQTT 1
#define MESHTASTIC_EXCLUDE_POWERMON 1
#define MESHTASTIC_EXCLUDE_I2C 1
#define MESHTASTIC_EXCLUDE_PKI 1
#define MESHTASTIC_EXCLUDE_POWER_FSM 1
#define MESHTASTIC_EXCLUDE_TZ 1
#endif

// Turn off all optional modules
#ifdef MESHTASTIC_EXCLUDE_MODULES
#define MESHTASTIC_EXCLUDE_AUDIO 1
#define MESHTASTIC_EXCLUDE_DETECTIONSENSOR 1
#define MESHTASTIC_EXCLUDE_ENVIRONMENTAL_SENSOR 1
#define MESHTASTIC_EXCLUDE_HEALTH_TELEMETRY 1
#define MESHTASTIC_EXCLUDE_EXTERNALNOTIFICATION 1
#define MESHTASTIC_EXCLUDE_PAXCOUNTER 1
#define MESHTASTIC_EXCLUDE_POWER_TELEMETRY 1
#define MESHTASTIC_EXCLUDE_RANGETEST 1
#define MESHTASTIC_EXCLUDE_REMOTEHARDWARE 1
#define MESHTASTIC_EXCLUDE_STOREFORWARD 1
#define MESHTASTIC_EXCLUDE_TEXTMESSAGE 1
#define MESHTASTIC_EXCLUDE_ATAK 1
#define MESHTASTIC_EXCLUDE_CANNEDMESSAGES 1
#define MESHTASTIC_EXCLUDE_NEIGHBORINFO 1
#define MESHTASTIC_EXCLUDE_TRACEROUTE 1
#define MESHTASTIC_EXCLUDE_WAYPOINT 1
#define MESHTASTIC_EXCLUDE_INPUTBROKER 1
#define MESHTASTIC_EXCLUDE_SERIAL 1
#define MESHTASTIC_EXCLUDE_POWERSTRESS 1
#define MESHTASTIC_EXCLUDE_ADMIN 1
#endif

// // Turn off wifi even if HW supports wifi (webserver relies on wifi and is also disabled)
#ifdef MESHTASTIC_EXCLUDE_WIFI
#define MESHTASTIC_EXCLUDE_WEBSERVER 1
#undef HAS_WIFI
#define HAS_WIFI 0
#endif

// Allow code that needs internet to just check HAS_NETWORKING rather than HAS_WIFI || HAS_ETHERNET
#define HAS_NETWORKING (HAS_WIFI || HAS_ETHERNET)

// // Turn off Bluetooth
#ifdef MESHTASTIC_EXCLUDE_BLUETOOTH
#undef HAS_BLUETOOTH
#define HAS_BLUETOOTH 0
#endif

// // Turn off GPS
#ifdef MESHTASTIC_EXCLUDE_GPS
#undef HAS_GPS
#define HAS_GPS 0
#undef MESHTASTIC_EXCLUDE_RANGETEST
#define MESHTASTIC_EXCLUDE_RANGETEST 1
#endif

// Turn off Screen
#ifdef MESHTASTIC_EXCLUDE_SCREEN
#undef HAS_SCREEN
#define HAS_SCREEN 0
#endif

#include "DebugConfiguration.h"
#include "RF95Configuration.h"


// ============================================================================
// BITCHAT MESH CONFIGURATION - Updated with Proper Libraries (v2.0)
// ============================================================================

// Enable BitChat mesh with proper crypto libraries
#define ENABLE_BITCHAT_MESH

// Disable old mesh implementation (comment out if still needed for migration)
// #define ENABLE_GHOSTDOME_BLE_MESH

// ============================================================================
// REQUIRED LIBRARY DEPENDENCIES - Based on BitChat Android
// ============================================================================

// CRITICAL: Add these libraries to platformio.ini:
//
// lib_deps = 
//     bblanchon/ArduinoJson@^6.21.0
//     h2zero/NimBLE-Arduino@^1.4.0
//     rweather/Crypto@^0.4.0              # X25519, Ed25519, AES-GCM
//     bodiroga/ArduinoLZ4@^1.0.0           # LZ4 compression
//     argon2id/ArduinoArgon2@^1.0.0        # Argon2id key derivation
//     ivanseidel/ArduinoThread@^2.1.1      # Thread management

// ============================================================================
// BITCHAT MESH SETTINGS - Matching Android Implementation Exactly
// ============================================================================

// Protocol Configuration (matching BitChat Android exactly)
#define BITCHAT_PROTOCOL_VERSION 1
#define BITCHAT_MAX_TTL 7
#define BITCHAT_DEFAULT_TTL 7
#define BITCHAT_MAX_PACKET_SIZE 4096
#define BITCHAT_HEADER_SIZE 13

// Peer Management (matching BitChat limits)
#define BITCHAT_MAX_PEERS 50
#define BITCHAT_PEER_TIMEOUT_MS 30000  // 30 seconds
#define BITCHAT_CLEANUP_INTERVAL_MS 30000

// Message Management (optimized for ESP32)
#define BITCHAT_MAX_SEEN_MESSAGES 1000
#define BITCHAT_MAX_RELAY_HISTORY 500
#define BITCHAT_MESSAGE_MEMORY_MS 300000  // 5 minutes
#define BITCHAT_RELAY_MEMORY_MS 60000     // 1 minute

// Store and Forward (matching BitChat)
#define BITCHAT_STORE_FORWARD_ENABLED true
#define BITCHAT_MAX_CACHED_MESSAGES_PER_PEER 100
#define BITCHAT_MESSAGE_CACHE_AGE_MS 86400000  // 24 hours

// Fragmentation (matching BitChat limits)
#define BITCHAT_FRAGMENTATION_ENABLED true
#define BITCHAT_MAX_FRAGMENT_SIZE 512
#define BITCHAT_MAX_MESSAGE_SIZE 32768  // 32KB
#define BITCHAT_FRAGMENT_TIMEOUT_MS 30000

// Compression and Padding (matching BitChat exactly)
#define BITCHAT_COMPRESSION_ENABLED true
#define BITCHAT_COMPRESSION_THRESHOLD 100  // bytes (BitChat Android uses 100 bytes)
#define BITCHAT_PADDING_ENABLED true

// ============================================================================
// BLUETOOTH LE CONFIGURATION - BitChat Compatible
// ============================================================================

// Device Configuration (must match BitChat apps exactly)
#define BT_DEVICE_NAME "GhostDome"
#define BT_APPEARANCE 0x0000

// BitChat Service UUIDs - EXACT SAME AS ANDROID/iOS
#define BITCHAT_SERVICE_UUID "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
#define BITCHAT_TX_CHAR_UUID "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"
#define BITCHAT_RX_CHAR_UUID "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"

// Connection Management (matching BitChat Android)
#define BITCHAT_MAX_CONNECTIONS 4
#define BITCHAT_AUTO_CONNECT_ENABLED true
#define BITCHAT_CONNECTION_TIMEOUT_MS 10000

// Power Mode Configurations (EXACT BitChat Android values)
// Performance Mode (>60% battery or charging)
#define BITCHAT_PERF_SCAN_INTERVAL_MS 50     // Matching BitChat exactly
#define BITCHAT_PERF_SCAN_WINDOW_MS 30
#define BITCHAT_PERF_ADV_MIN_INTERVAL_MS 100
#define BITCHAT_PERF_ADV_MAX_INTERVAL_MS 150
#define BITCHAT_PERF_MAX_CONNECTIONS 8

// Balanced Mode (30-60% battery) - DEFAULT
#define BITCHAT_BAL_SCAN_INTERVAL_MS 80      // Matching BitChat exactly
#define BITCHAT_BAL_SCAN_WINDOW_MS 40
#define BITCHAT_BAL_ADV_MIN_INTERVAL_MS 100
#define BITCHAT_BAL_ADV_MAX_INTERVAL_MS 200
#define BITCHAT_BAL_MAX_CONNECTIONS 4

// Power Saver Mode (<30% battery)
#define BITCHAT_SAVER_SCAN_INTERVAL_MS 160   // Matching BitChat exactly
#define BITCHAT_SAVER_SCAN_WINDOW_MS 40
#define BITCHAT_SAVER_ADV_MIN_INTERVAL_MS 300
#define BITCHAT_SAVER_ADV_MAX_INTERVAL_MS 500
#define BITCHAT_SAVER_MAX_CONNECTIONS 2

// Ultra Low Power Mode (<10% battery)
#define BITCHAT_ULP_SCAN_INTERVAL_MS 640     // Matching BitChat exactly
#define BITCHAT_ULP_SCAN_WINDOW_MS 40
#define BITCHAT_ULP_ADV_MIN_INTERVAL_MS 1000
#define BITCHAT_ULP_ADV_MAX_INTERVAL_MS 2000
#define BITCHAT_ULP_MAX_CONNECTIONS 1

// ============================================================================
// CRYPTOGRAPHY CONFIGURATION - Matching BitChat Android Exactly
// ============================================================================

// Noise Protocol (EXACT BitChat implementation)
#define BITCHAT_NOISE_PROTOCOL_NAME "Noise_XX_25519_AESGCM_SHA256"
#define BITCHAT_NOISE_SESSION_TIMEOUT_MS 86400000  // 24 hours
#define BITCHAT_NOISE_HANDSHAKE_TIMEOUT_MS 30000   // 30 seconds
#define BITCHAT_NOISE_REKEY_THRESHOLD 1000000      // 1M messages

// X25519 Key Exchange (using rweather/Crypto)
#define BITCHAT_X25519_KEY_SIZE 32
#define BITCHAT_X25519_ENABLED true

// Ed25519 Signatures (using rweather/Crypto)
#define BITCHAT_SIGNATURES_ENABLED true
#define BITCHAT_ED25519_PUBLIC_KEY_SIZE 32
#define BITCHAT_ED25519_PRIVATE_KEY_SIZE 64
#define BITCHAT_ED25519_SIGNATURE_SIZE 64

// AES-256-GCM Transport Encryption (using rweather/Crypto)
#define BITCHAT_AES_GCM_ENABLED true
#define BITCHAT_AES_GCM_KEY_SIZE 32      // AES-256
#define BITCHAT_AES_GCM_IV_SIZE 12       // 96-bit IV
#define BITCHAT_AES_GCM_TAG_SIZE 16      // 128-bit authentication tag

// Channel Encryption (Argon2id + AES-256-GCM) - BitChat Android values
#define BITCHAT_CHANNEL_CRYPTO_ENABLED true
#define BITCHAT_ARGON2_TIME_COST 3              // Matching BitChat
#define BITCHAT_ARGON2_MEMORY_COST 65536        // 64MB (BitChat uses 65536)
#define BITCHAT_ARGON2_PARALLELISM 1
#define BITCHAT_ARGON2_HASH_LENGTH 32

// LZ4 Compression (using proper LZ4 library)
#define BITCHAT_LZ4_ENABLED true
#define BITCHAT_LZ4_COMPRESSION_LEVEL 1         // Fast compression
#define BITCHAT_LZ4_ACCELERATION 1

// Key Storage
#define BITCHAT_KEY_STORAGE_NAMESPACE "bitchat_id"
#define BITCHAT_PERSISTENT_KEYS_ENABLED true

// ============================================================================
// LIBRARY INTEGRATION CONSTANTS
// ============================================================================

// rweather/Crypto Configuration
#define CRYPTO_X25519_ENABLED true
#define CRYPTO_ED25519_ENABLED true 
#define CRYPTO_AES_GCM_ENABLED true
#define CRYPTO_SHA256_ENABLED true

// LZ4 Configuration
#define LZ4_COMPRESSION_ENABLED true
#define LZ4_ACCELERATION_DEFAULT 1

// Argon2 Configuration  
#define ARGON2_TYPE_ID 2                        // Argon2id
#define ARGON2_SALT_LENGTH 16
#define ARGON2_OUTPUT_LENGTH 32

// ============================================================================
// DEBUGGING AND LOGGING
// ============================================================================

// Debug Configuration
#define BITCHAT_DEBUG_ENABLED true
#define BITCHAT_VERBOSE_LOGGING false
#define BITCHAT_PACKET_LOGGING false
#define BITCHAT_PERFORMANCE_METRICS true
#define BITCHAT_CRYPTO_DEBUG false              // Disable crypto debug for security

// Debug Intervals
#define BITCHAT_DEBUG_INTERVAL_MS 30000
#define BITCHAT_STATUS_REPORT_INTERVAL_MS 60000

// Log Levels per Component (matching BitChat Android)
#define BITCHAT_MESH_LOG_LEVEL ESP_LOG_DEBUG
#define BITCHAT_BLE_LOG_LEVEL ESP_LOG_DEBUG
#define BITCHAT_CRYPTO_LOG_LEVEL ESP_LOG_INFO    // Reduced for security
#define BITCHAT_PEER_LOG_LEVEL ESP_LOG_DEBUG
#define BITCHAT_FRAGMENT_LOG_LEVEL ESP_LOG_DEBUG
#define BITCHAT_COMPRESSION_LOG_LEVEL ESP_LOG_INFO

// ============================================================================
// INTEGRATION WITH EXISTING GHOSTDOME FEATURES
// ============================================================================

// GhostDome Blockchain Integration
#define BITCHAT_BLOCKCHAIN_MESSAGES_ENABLED true
#define BITCHAT_BLOCKCHAIN_MESSAGE_PREFIX "BLOCKCHAIN:"

// GhostDome Identity Integration  
#define BITCHAT_GHOSTDOME_IDENTITY_ENABLED true
#define BITCHAT_GHOSTDOME_NICKNAME_PREFIX "GhostDome-"

// GhostDome Transaction Support
#define BITCHAT_TRANSACTION_MESSAGES_ENABLED true
#define BITCHAT_TRANSACTION_MESSAGE_PREFIX "TRANSACTION:"

// Emergency Features (matching BitChat)
#define BITCHAT_EMERGENCY_WIPE_ENABLED true
#define BITCHAT_PANIC_TRIPLE_TAP_ENABLED true

// ============================================================================
// HARDWARE SPECIFIC SETTINGS
// ============================================================================

// ESP32 Specific Optimizations
#define BITCHAT_ESP32_OPTIMIZATIONS_ENABLED true
#define BITCHAT_USE_HARDWARE_RNG true
#define BITCHAT_USE_HARDWARE_SHA256 true
#define BITCHAT_USE_MBEDTLS_FALLBACK true        // Fallback to mbedTLS if needed

// Memory Configuration (optimized for ESP32)
#define BITCHAT_STACK_SIZE_MESH_TASK 8192
#define BITCHAT_STACK_SIZE_BLE_TASK 4096
#define BITCHAT_STACK_SIZE_CRYPTO_TASK 6144      // Increased for crypto operations
#define BITCHAT_STACK_SIZE_COMPRESSION_TASK 4096

// FreeRTOS Task Priorities
#define BITCHAT_MESH_TASK_PRIORITY 5
#define BITCHAT_BLE_TASK_PRIORITY 6
#define BITCHAT_CRYPTO_TASK_PRIORITY 4
#define BITCHAT_COMPRESSION_TASK_PRIORITY 3

// Memory Pool Sizes
#define BITCHAT_MESSAGE_POOL_SIZE 50
#define BITCHAT_FRAGMENT_POOL_SIZE 20
#define BITCHAT_CRYPTO_BUFFER_SIZE 1024

// ============================================================================
// COMPATIBILITY SETTINGS
// ============================================================================

// BitChat Android/iOS Compatibility
#define BITCHAT_ANDROID_COMPATIBLE true
#define BITCHAT_IOS_COMPATIBLE true
#define BITCHAT_STRICT_PROTOCOL_COMPLIANCE true

// Version Compatibility
#define BITCHAT_MIN_SUPPORTED_VERSION 1
#define BITCHAT_MAX_SUPPORTED_VERSION 1

// Binary Protocol Compatibility
#define BITCHAT_BINARY_PROTOCOL_V1 true
#define BITCHAT_TLV_ENCODING_ENABLED true
#define BITCHAT_BIG_ENDIAN_INTEGERS true         // BitChat uses big-endian

// Feature Flags for Future Compatibility
#define BITCHAT_FUTURE_IPv6_SUPPORT false
#define BITCHAT_FUTURE_FILE_TRANSFER false
#define BITCHAT_FUTURE_AUDIO_STREAMING false
#define BITCHAT_FUTURE_VIDEO_CALLING false

// ============================================================================
// PERFORMANCE TUNING
// ============================================================================

// Message Processing
#define BITCHAT_MAX_MESSAGES_PER_TICK 10
#define BITCHAT_MESSAGE_QUEUE_SIZE 100
#define BITCHAT_CRYPTO_QUEUE_SIZE 20

// BLE Performance
#define BITCHAT_BLE_MTU_SIZE 512                 // Maximum MTU
#define BITCHAT_BLE_PREFERRED_MTU 244            // Preferred MTU for reliability
#define BITCHAT_BLE_MAX_RETRIES 3

// Compression Performance
#define BITCHAT_COMPRESSION_MIN_RATIO 0.9        // Only use if <90% of original size
#define BITCHAT_MAX_COMPRESSION_TIME_MS 100      // Timeout compression after 100ms

// ============================================================================
// SECURITY SETTINGS
// ============================================================================

// Key Management Security
#define BITCHAT_SECURE_KEY_STORAGE true
#define BITCHAT_KEY_DERIVATION_ITERATIONS 100000 // For legacy key storage
#define BITCHAT_RANDOM_SEED_ENTROPY_SOURCES 3

// Session Security
#define BITCHAT_FORWARD_SECRECY_ENABLED true
#define BITCHAT_REPLAY_PROTECTION_ENABLED true
#define BITCHAT_NONCE_WINDOW_SIZE 100

// Network Security
#define BITCHAT_ANTI_REPLAY_CACHE_SIZE 1000
#define BITCHAT_MAX_HOPS_WITHOUT_SIGNATURE 3     // Limit unsigned message propagation

// ============================================================================
// VALIDATION MACROS
// ============================================================================

// Compile-time validation
#if !defined(ENABLE_BITCHAT_MESH) && !defined(ENABLE_GHOSTDOME_BLE_MESH)
#error "Must enable either BITCHAT or old GHOSTDOME BLE mesh"
#endif

#if defined(ENABLE_BITCHAT_MESH) && defined(ENABLE_GHOSTDOME_BLE_MESH)
#warning "Both mesh implementations enabled - this may cause conflicts"
#endif

#if BITCHAT_MAX_PACKET_SIZE > 65535
#error "BITCHAT_MAX_PACKET_SIZE cannot exceed 65535 bytes"
#endif

#if BITCHAT_MAX_PEERS > 255
#error "BITCHAT_MAX_PEERS cannot exceed 255"
#endif

#if BITCHAT_MAX_TTL > 255
#error "BITCHAT_MAX_TTL cannot exceed 255"
#endif

#if BITCHAT_COMPRESSION_THRESHOLD > 1024
#warning "BITCHAT_COMPRESSION_THRESHOLD > 1024 may impact performance"
#endif

// Library validation
#ifndef CRYPTO_X25519_ENABLED
#error "rweather/Crypto library with X25519 support is required"
#endif

#ifndef LZ4_COMPRESSION_ENABLED
#error "LZ4 compression library is required"
#endif

// ============================================================================
// UTILITY MACROS
// ============================================================================

// Convert milliseconds to FreeRTOS ticks
#define BITCHAT_MS_TO_TICKS(ms) (pdMS_TO_TICKS(ms))

// Check if BitChat mesh is enabled
#ifdef ENABLE_BITCHAT_MESH
#define BITCHAT_ENABLED 1
#else
#define BITCHAT_ENABLED 0
#endif

// Feature availability macros
#define BITCHAT_HAS_STORE_FORWARD (BITCHAT_ENABLED && BITCHAT_STORE_FORWARD_ENABLED)
#define BITCHAT_HAS_FRAGMENTATION (BITCHAT_ENABLED && BITCHAT_FRAGMENTATION_ENABLED)
#define BITCHAT_HAS_COMPRESSION (BITCHAT_ENABLED && BITCHAT_COMPRESSION_ENABLED && LZ4_COMPRESSION_ENABLED)
#define BITCHAT_HAS_CHANNEL_CRYPTO (BITCHAT_ENABLED && BITCHAT_CHANNEL_CRYPTO_ENABLED)
#define BITCHAT_HAS_NOISE_PROTOCOL (BITCHAT_ENABLED && CRYPTO_X25519_ENABLED)
#define BITCHAT_HAS_SIGNATURES (BITCHAT_ENABLED && CRYPTO_ED25519_ENABLED)

// Crypto feature checks
#define BITCHAT_CRYPTO_READY (CRYPTO_X25519_ENABLED && CRYPTO_ED25519_ENABLED && CRYPTO_AES_GCM_ENABLED)

// Memory allocation helpers
#define BITCHAT_MALLOC(size) heap_caps_malloc(size, MALLOC_CAP_8BIT)
#define BITCHAT_FREE(ptr) heap_caps_free(ptr)
