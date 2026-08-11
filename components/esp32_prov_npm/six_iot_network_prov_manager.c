/* Wi-Fi Provisioning Manager Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>
#include <freertos/task.h>

#include <esp_event.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <nvs_flash.h>

#include <network_provisioning/manager.h>

#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_BLE
#include <network_provisioning/scheme_ble.h>
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_BLE */

#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP
#include <network_provisioning/scheme_softap.h>
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP */
#include "qrcode.h"
#include "six_iot_config.h"
#include "six_iot_creds.h"
#include "six_iot_network_prov_manager.h"
#include "six_iot_util.h"
// #include "esp_rmaker_user_mapping.pb-c.h"
#include "esp_six_user_mapping.pb-c.h"

// extern const uint8_t device_cert_pem_start[] asm("_binary_device_cert_pem_start");
// extern const uint8_t device_cert_pem_end[] asm("_binary_device_cert_pem_end");

static const char *TAG = "app";

static const char *SEC2_SALT_KEY = "salt";
static const char *SEC2_VERIFIER_KEY = "verifier";
static const char *SEC2_USERNAME_KEY = "username";
static const char *SEC2_PWD_KEY = "pop";
static const char *SEC2_NAME_KEY = "name";

/* Event loop to handle the callback */
static esp_event_loop_handle_t s_six_iot_loop = NULL;

/* IoT config type */
static six_iot_config_t *s_iot_cfg = NULL;

/* The status of the provision operation */
static six_iot_event_t s_six_iot_conn_status = PROVISION_STATUS_NOT_START;

static void _six_iot_init_network_prov_manager(wifi_ap_config_t *config);

static void s_report_provision_status(six_iot_event_t status, char *msg, void *args) {
	ESP_LOGD(TAG, "s_report_provision_status.msg: %s", msg);
	s_six_iot_conn_status = status;
	if (s_six_iot_loop) {
		if ((status == PROVISION_STATUS_AS_STA_CONN_TO_AP_SUCCEED || status == PROVISION_STATUS_BIND_DEVICE_REC_CMD) &&
			args) {
			char *data = args;
			size_t size = strlen(data) + 1U;
			esp_event_post_to(s_six_iot_loop, SIX_IOT_EVENT, status, data, size, 100 / portTICK_PERIOD_MS);
		} else {
			size_t size = args ? strlen((const char *)args) + 1U : 0U;
			esp_event_post_to(s_six_iot_loop, SIX_IOT_EVENT, status, args, size, 100 / portTICK_PERIOD_MS);
		}
	}
}

#if CONFIG_EXAMPLE_PROV_SECURITY_VERSION_2
#if CONFIG_EXAMPLE_PROV_SEC2_DEV_MODE
#define EXAMPLE_PROV_SEC2_USERNAME "wifiprov"
#define EXAMPLE_PROV_SEC2_PWD "abcd1234"

/* This salt,verifier has been generated for username = "wifiprov" and password = "abcd1234"
 * IMPORTANT NOTE: For production cases, this must be unique to every device
 * and should come from device manufacturing partition.*/
static const char sec2_salt[] = {0x03, 0x6e, 0xe0, 0xc7, 0xbc, 0xb9, 0xed, 0xa8,
								 0x4c, 0x9e, 0xac, 0x97, 0xd9, 0x3d, 0xec, 0xf4};

static const char sec2_verifier[] = {
	0x7c, 0x7c, 0x85, 0x47, 0x65, 0x08, 0x94, 0x6d, 0xd6, 0x36, 0xaf, 0x37, 0xd7, 0xe8, 0x91, 0x43, 0x78, 0xcf, 0xfd,
	0x61, 0x6c, 0x59, 0xd2, 0xf8, 0x39, 0x08, 0x12, 0x72, 0x38, 0xde, 0x9e, 0x24, 0xa4, 0x70, 0x26, 0x1c, 0xdf, 0xa9,
	0x03, 0xc2, 0xb2, 0x70, 0xe7, 0xb1, 0x32, 0x24, 0xda, 0x11, 0x1d, 0x97, 0x18, 0xdc, 0x60, 0x72, 0x08, 0xcc, 0x9a,
	0xc9, 0x0c, 0x48, 0x27, 0xe2, 0xae, 0x89, 0xaa, 0x16, 0x25, 0xb8, 0x04, 0xd2, 0x1a, 0x9b, 0x3a, 0x8f, 0x37, 0xf6,
	0xe4, 0x3a, 0x71, 0x2e, 0xe1, 0x27, 0x86, 0x6e, 0xad, 0xce, 0x28, 0xff, 0x54, 0x46, 0x60, 0x1f, 0xb9, 0x96, 0x87,
	0xdc, 0x57, 0x40, 0xa7, 0xd4, 0x6c, 0xc9, 0x77, 0x54, 0xdc, 0x16, 0x82, 0xf0, 0xed, 0x35, 0x6a, 0xc4, 0x70, 0xad,
	0x3d, 0x90, 0xb5, 0x81, 0x94, 0x70, 0xd7, 0xbc, 0x65, 0xb2, 0xd5, 0x18, 0xe0, 0x2e, 0xc3, 0xa5, 0xf9, 0x68, 0xdd,
	0x64, 0x7b, 0xb8, 0xb7, 0x3c, 0x9c, 0xfc, 0x00, 0xd8, 0x71, 0x7e, 0xb7, 0x9a, 0x7c, 0xb1, 0xb7, 0xc2, 0xc3, 0x18,
	0x34, 0x29, 0x32, 0x43, 0x3e, 0x00, 0x99, 0xe9, 0x82, 0x94, 0xe3, 0xd8, 0x2a, 0xb0, 0x96, 0x29, 0xb7, 0xdf, 0x0e,
	0x5f, 0x08, 0x33, 0x40, 0x76, 0x52, 0x91, 0x32, 0x00, 0x9f, 0x97, 0x2c, 0x89, 0x6c, 0x39, 0x1e, 0xc8, 0x28, 0x05,
	0x44, 0x17, 0x3f, 0x68, 0x02, 0x8a, 0x9f, 0x44, 0x61, 0xd1, 0xf5, 0xa1, 0x7e, 0x5a, 0x70, 0xd2, 0xc7, 0x23, 0x81,
	0xcb, 0x38, 0x68, 0xe4, 0x2c, 0x20, 0xbc, 0x40, 0x57, 0x76, 0x17, 0xbd, 0x08, 0xb8, 0x96, 0xbc, 0x26, 0xeb, 0x32,
	0x46, 0x69, 0x35, 0x05, 0x8c, 0x15, 0x70, 0xd9, 0x1b, 0xe9, 0xbe, 0xcc, 0xa9, 0x38, 0xa6, 0x67, 0xf0, 0xad, 0x50,
	0x13, 0x19, 0x72, 0x64, 0xbf, 0x52, 0xc2, 0x34, 0xe2, 0x1b, 0x11, 0x79, 0x74, 0x72, 0xbd, 0x34, 0x5b, 0xb1, 0xe2,
	0xfd, 0x66, 0x73, 0xfe, 0x71, 0x64, 0x74, 0xd0, 0x4e, 0xbc, 0x51, 0x24, 0x19, 0x40, 0x87, 0x0e, 0x92, 0x40, 0xe6,
	0x21, 0xe7, 0x2d, 0x4e, 0x37, 0x76, 0x2f, 0x2e, 0xe2, 0x68, 0xc7, 0x89, 0xe8, 0x32, 0x13, 0x42, 0x06, 0x84, 0x84,
	0x53, 0x4a, 0xb3, 0x0c, 0x1b, 0x4c, 0x8d, 0x1c, 0x51, 0x97, 0x19, 0xab, 0xae, 0x77, 0xff, 0xdb, 0xec, 0xf0, 0x10,
	0x95, 0x34, 0x33, 0x6b, 0xcb, 0x3e, 0x84, 0x0f, 0xb9, 0xd8, 0x5f, 0xb8, 0xa0, 0xb8, 0x55, 0x53, 0x3e, 0x70, 0xf7,
	0x18, 0xf5, 0xce, 0x7b, 0x4e, 0xbf, 0x27, 0xce, 0xce, 0xa8, 0xb3, 0xbe, 0x40, 0xc5, 0xc5, 0x32, 0x29, 0x3e, 0x71,
	0x64, 0x9e, 0xde, 0x8c, 0xf6, 0x75, 0xa1, 0xe6, 0xf6, 0x53, 0xc8, 0x31, 0xa8, 0x78, 0xde, 0x50, 0x40, 0xf7, 0x62,
	0xde, 0x36, 0xb2, 0xba};
#endif

static uint8_t hex_char_to_val(char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return 0;
}

static size_t hex_string_to_bytes(const char *hex_str, uint8_t *out_buf, size_t buf_len) {
	size_t len = strlen(hex_str);
	if (len % 2 != 0 || len / 2 > buf_len) {
		return 0; // Invalid length
	}
	for (size_t i = 0; i < len; i += 2) {
		out_buf[i / 2] = (hex_char_to_val(hex_str[i]) << 4) | hex_char_to_val(hex_str[i + 1]);
	}
	return len / 2;
}

static esp_err_t example_get_sec2_salt(const char **salt, uint16_t *salt_len) {
#if CONFIG_EXAMPLE_PROV_SEC2_DEV_MODE
	ESP_LOGD(TAG, "Development mode: using hard coded salt");
	*salt = sec2_salt;
	*salt_len = sizeof(sec2_salt);
	return ESP_OK;
#elif CONFIG_EXAMPLE_PROV_SEC2_PROD_MODE
	char *nvs_salt_hex = get_network_prov_field(SEC2_SALT_KEY);
	if (!nvs_salt_hex) {
		ESP_LOGE(TAG, "Failed to get salt!");
		*salt = NULL;
		*salt_len = 0;
		return ESP_FAIL;
	}
	// CRITICAL: We need a persistent buffer to hold the raw bytes.
	// Using 'static' ensures this memory is not freed when the function returns.
	static uint8_t s_salt_buffer[16] = {0};
	// Convert the Hex String into the Binary Buffer
	size_t converted_len = hex_string_to_bytes(nvs_salt_hex, s_salt_buffer, sizeof(s_salt_buffer));
	free(nvs_salt_hex);
	if (converted_len != 16) {
		ESP_LOGE(TAG, "Failed to convert salt: Invalid length or format");
		*salt = NULL;
		*salt_len = 0;
		return ESP_FAIL;
	}
	// Assign the pointer to our static binary buffer
	*salt = (const char *)s_salt_buffer;
	*salt_len = (uint16_t)converted_len;
	return ESP_OK;
#endif
}

static esp_err_t example_get_sec2_verifier(const char **verifier, uint16_t *verifier_len) {
#if CONFIG_EXAMPLE_PROV_SEC2_DEV_MODE
	ESP_LOGD(TAG, "Development mode: using hard coded verifier");
	*verifier = sec2_verifier;
	*verifier_len = sizeof(sec2_verifier);
	return ESP_OK;
#elif CONFIG_EXAMPLE_PROV_SEC2_PROD_MODE
	char *nvs_verifier_hex = get_network_prov_field(SEC2_VERIFIER_KEY);
	if (!nvs_verifier_hex) {
		ESP_LOGE(TAG, "Failed to get verifier!");
		*verifier = NULL;
		*verifier_len = 0;
		return ESP_FAIL;
	}
	const size_t EXPECTED_VERIFIER_LEN = 384; // 3072 bits / 8 = 384 bytes
	static uint8_t s_verifier_buffer[384];
	// Convert the Hex String into the Binary Buffer
	size_t converted_len = hex_string_to_bytes(nvs_verifier_hex, s_verifier_buffer, sizeof(s_verifier_buffer));
	free(nvs_verifier_hex);
	// 2. The verifier MUST be exactly 384 bytes for SRP-3072/SHA-256 standard groups
	if (converted_len != EXPECTED_VERIFIER_LEN) {
		ESP_LOGE(TAG, "Failed to convert verifier: Invalid length %d (expected %d)", (int)converted_len,
				 (int)EXPECTED_VERIFIER_LEN);
		*verifier = NULL;
		*verifier_len = 0;
		return ESP_FAIL;
	}
	// Assign the pointer to our static binary buffer
	*verifier = (const char *)s_verifier_buffer;
	*verifier_len = (uint16_t)converted_len;
	return ESP_OK;
#endif
}
#endif

/* Signal Wi-Fi events on this event-group */
const int WIFI_CONNECTED_EVENT = BIT0;
static EventGroupHandle_t wifi_event_group;

#define PROV_QR_VERSION "v1"
#define PROV_TRANSPORT_SOFTAP "softap"
#define PROV_TRANSPORT_BLE "ble"
#define QRCODE_BASE_URL "https://espressif.github.io/esp-jumpstart/qrcode.html"

/* Event handler for catching system events */
static void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
	if (event_base == NETWORK_PROV_EVENT) {
		switch (event_id) {
		case NETWORK_PROV_START:
			ESP_LOGD(TAG, "Provisioning started");
			break;
		case NETWORK_PROV_WIFI_CRED_RECV: {
			wifi_sta_config_t *wifi_sta_cfg = (wifi_sta_config_t *)event_data;
			ESP_LOGD(TAG,
					 "Received Wi-Fi credentials"
					 "\n\tSSID     : %s\n\tPassword : %s",
					 (const char *)wifi_sta_cfg->ssid, (const char *)wifi_sta_cfg->password);
			break;
		}
		case NETWORK_PROV_WIFI_CRED_FAIL: {
			network_prov_wifi_sta_fail_reason_t *reason = (network_prov_wifi_sta_fail_reason_t *)event_data;
			ESP_LOGE(TAG,
					 "Provisioning failed!\n\tReason : %s"
					 "\n\tPlease reset to factory and retry provisioning",
					 (*reason == NETWORK_PROV_WIFI_STA_AUTH_ERROR) ? "Wi-Fi station authentication failed"
																   : "Wi-Fi access-point not found");
#ifdef CONFIG_EXAMPLE_RESET_PROV_MGR_ON_FAILURE
			/* Reset the state machine on provisioning failure.
			 * This is enabled by the CONFIG_EXAMPLE_RESET_PROV_MGR_ON_FAILURE configuration.
			 * It allows the provisioning manager to retry the provisioning process
			 * based on the number of attempts specified in wifi_conn_attempts. After attempting
			 * the maximum number of retries, the provisioning manager will reset the state machine
			 * and the provisioning process will be terminated.
			 */
			network_prov_mgr_reset_wifi_sm_state_on_failure();
#endif
			break;
		}
		case NETWORK_PROV_WIFI_CRED_SUCCESS:
			ESP_LOGD(TAG, "Provisioning successful");
			break;
		case NETWORK_PROV_END:
			/* De-initialize manager once provisioning is finished */
			esp_err_t err = network_prov_mgr_deinit();
			if (err != ESP_OK) {
				ESP_LOGE(TAG, "Failed to de-initialize provisioning manager: %s", esp_err_to_name(err));
			}
			break;
		default:
			break;
		}
	} else if (event_base == WIFI_EVENT) {
		switch (event_id) {
		case WIFI_EVENT_STA_START:
			esp_wifi_connect();
			break;
		case WIFI_EVENT_STA_DISCONNECTED:
			ESP_LOGD(TAG, "Disconnected. Connecting to the AP again...");
			esp_wifi_connect();
			break;
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP
		case WIFI_EVENT_AP_STACONNECTED:
			ESP_LOGD(TAG, "SoftAP transport: Connected!");
			break;
		case WIFI_EVENT_AP_STADISCONNECTED:
			ESP_LOGD(TAG, "SoftAP transport: Disconnected!");
			break;
#endif
		default:
			break;
		}
	} else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
		ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
		ESP_LOGD(TAG, "Connected with IP Address:" IPSTR, IP2STR(&event->ip_info.ip));
		/* Signal main application to continue execution */
		xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_EVENT);
		/* Report successful connection status to the SDK*/
		s_report_provision_status(PROVISION_STATUS_AS_STA_CONN_TO_AP_SUCCEED,
								  "Device connect to AP succeed, IP is got!", NULL);
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_BLE
	} else if (event_base == PROTOCOMM_TRANSPORT_BLE_EVENT) {
		switch (event_id) {
		case PROTOCOMM_TRANSPORT_BLE_CONNECTED:
			ESP_LOGD(TAG, "BLE transport: Connected!");
			break;
		case PROTOCOMM_TRANSPORT_BLE_DISCONNECTED:
			ESP_LOGD(TAG, "BLE transport: Disconnected!");
			break;
		default:
			break;
		}
#endif
	} else if (event_base == PROTOCOMM_SECURITY_SESSION_EVENT) {
		switch (event_id) {
		case PROTOCOMM_SECURITY_SESSION_SETUP_OK:
			ESP_LOGD(TAG, "Secured session established!");
			break;
		case PROTOCOMM_SECURITY_SESSION_INVALID_SECURITY_PARAMS:
			ESP_LOGE(TAG, "Received invalid security parameters for establishing secure session!");
			break;
		case PROTOCOMM_SECURITY_SESSION_CREDENTIALS_MISMATCH:
			ESP_LOGE(TAG, "Received incorrect username and/or PoP for establishing secure session!");
			break;
		default:
			break;
		}
	}
}

static void wifi_init_sta(void) {
	/* Start Wi-Fi in station mode */
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_start());
}

static void get_device_service_name(char *service_name, size_t max) {
#ifdef CONFIG_EXAMPLE_PROV_SEC2_PROD_MODE
	char *nvs_name = get_network_prov_field(SEC2_NAME_KEY);
	if (nvs_name) {
		snprintf(service_name, max, nvs_name);
		free(nvs_name);
	}
#elif
	uint8_t eth_mac[6];
	const char *ssid_prefix = "PROV_";
	esp_wifi_get_mac(WIFI_IF_STA, eth_mac);
	snprintf(service_name, max, "%s%02X%02X%02X", ssid_prefix, eth_mac[3], eth_mac[4], eth_mac[5]);
#endif
}

/* Handler for the optional provisioning endpoint registered by the application.
 * The data format can be chosen by applications. Here, we are using plain ascii text.
 * Applications can choose to use other formats like protobuf, JSON, XML, etc.
 * Note that memory for the response buffer must be allocated using heap as this buffer
 * gets freed by the protocomm layer once it has been sent by the transport layer.
 */
esp_err_t custom_prov_data_handler(uint32_t session_id, const uint8_t *inbuf, ssize_t inlen, uint8_t **outbuf,
								   ssize_t *outlen, void *priv_data) {
	if (inbuf) {
		ESP_LOGD(TAG, "Received data: %.*s", inlen, (char *)inbuf);
	}
	char response[] = "SUCCESS";
	*outbuf = (uint8_t *)strdup(response);
	if (*outbuf == NULL) {
		ESP_LOGE(TAG, "System out of memory");
		return ESP_ERR_NO_MEM;
	}
	*outlen = strlen(response) + 1; /* +1 for NULL terminating byte */

	return ESP_OK;
}

esp_err_t cloud_user_assoc_handler(uint32_t session_id, const uint8_t *inbuf, ssize_t inlen, uint8_t **outbuf,
								   ssize_t *outlen, void *priv_data) {
	if (!inbuf || inlen <= 0) {
		return ESP_ERR_INVALID_ARG;
	}

	/* Unpack the incoming payload as RMakerConfigPayload */
	Com__Six__Iot__SixConfigPayload *payload = com__six__iot__six_config_payload__unpack(NULL, (size_t)inlen, inbuf);
	if (!payload) {
		ESP_LOGW(TAG, "cloud_user_assoc_handler: failed to unpack payload");
		return ESP_ERR_INVALID_ARG;
	}

	/* Default response */
	Com__Six__Iot__RespSetUserMapping resp = COM__SIX__IOT__RESP_SET_USER_MAPPING__INIT;
	resp.status = COM__SIX__IOT__SIX_CONFIG_STATUS__Success;
	resp.nodeid = (s_iot_cfg && s_iot_cfg->iam.device_guid) ? s_iot_cfg->iam.device_guid : "";
	resp.productid = (s_iot_cfg && s_iot_cfg->iot_product_id) ? s_iot_cfg->iot_product_id : "";

	/* Prepare wrapper payload */
	Com__Six__Iot__SixConfigPayload out = COM__SIX__IOT__SIX_CONFIG_PAYLOAD__INIT;
	out.msg = COM__SIX__IOT__SIX_CONFIG_MSG_TYPE__TypeRespSetUserMapping;
	out.payload_case = COM__SIX__IOT__SIX_CONFIG_PAYLOAD__PAYLOAD_RESP_SET_USER_MAPPING;
	out.resp_set_user_mapping = &resp;

	esp_err_t ret = ESP_OK;

	char *signature = NULL;

	if (payload->msg == COM__SIX__IOT__SIX_CONFIG_MSG_TYPE__TypeCmdSetUserMapping &&
		payload->payload_case == COM__SIX__IOT__SIX_CONFIG_PAYLOAD__PAYLOAD_CMD_SET_USER_MAPPING &&
		payload->cmd_set_user_mapping) {

		char *challenge = payload->cmd_set_user_mapping->challenge;
		if (challenge == NULL) {
			resp.status = COM__SIX__IOT__SIX_CONFIG_STATUS__InvalidState;
			ret = ESP_ERR_INVALID_ARG;
			goto flush_resp;
		}
		ESP_LOGD(TAG, "cloud_user_assoc_handler: received challenge=%s", challenge);
		/* Post the bind-device event so main SDK can handle the bind request */
		s_report_provision_status(PROVISION_STATUS_BIND_DEVICE_REQ_CHALLENGE_CMD, "App request binding challenge",
								  challenge);

		char *private_key_pem = get_device_private_key();
		if (!private_key_pem) {
			ESP_LOGE(TAG, "can't get the private key of the device");
			resp.status = COM__SIX__IOT__SIX_CONFIG_STATUS__InvalidParam;
			ret = ESP_ERR_NO_MEM;
			goto flush_resp;
		}

		signature = sign_data_with_rsa_private_key(challenge, (char *)private_key_pem);
		free(private_key_pem);

		if (signature == NULL) {
			resp.status = COM__SIX__IOT__SIX_CONFIG_STATUS__InvalidState;
			ret = ESP_ERR_INVALID_ARG;
			goto flush_resp;
		}
		resp.signature = signature;
		resp.challenge = challenge;
	} else {
		ESP_LOGW(TAG, "cloud_user_assoc_handler: unexpected message type or payload");
		resp.status = COM__SIX__IOT__SIX_CONFIG_STATUS__InvalidParam;
		ret = ESP_ERR_INVALID_ARG;
	}

flush_resp:

	/* Pack response wrapper */
	size_t out_size = com__six__iot__six_config_payload__get_packed_size(&out);
	uint8_t *buf = (uint8_t *)malloc(out_size);
	if (!buf) {
		com__six__iot__six_config_payload__free_unpacked(payload, NULL);
		if (signature) {
			free(signature);
		}
		return ESP_ERR_NO_MEM;
	}
	com__six__iot__six_config_payload__pack(&out, buf);
	*outbuf = buf;
	*outlen = (ssize_t)out_size;

	com__six__iot__six_config_payload__free_unpacked(payload, NULL);
	if (signature) {
		free(signature);
	}
	return ret;
}

static void wifi_prov_print_qr(const char *name, const char *username, const char *pop, const char *transport) {
	if (!name || !transport) {
		ESP_LOGW(TAG, "Cannot generate QR code payload. Data missing.");
		return;
	}
	char payload[150] = {0};
	if (pop) {
#if CONFIG_EXAMPLE_PROV_SECURITY_VERSION_1
		snprintf(payload, sizeof(payload),
				 "{\"ver\":\"%s\",\"name\":\"%s\""
				 ",\"pop\":\"%s\",\"transport\":\"%s\"}",
				 PROV_QR_VERSION, name, pop, transport);
#elif CONFIG_EXAMPLE_PROV_SECURITY_VERSION_2
		snprintf(payload, sizeof(payload),
				 "{\"ver\":\"%s\",\"name\":\"%s\""
				 ",\"username\":\"%s\",\"pop\":\"%s\",\"transport\":\"%s\"}",
				 PROV_QR_VERSION, name, username, pop, transport);
#endif
	} else {
		snprintf(payload, sizeof(payload),
				 "{\"ver\":\"%s\",\"name\":\"%s\""
				 ",\"transport\":\"%s\",\"network\":\"wifi\"}",
				 PROV_QR_VERSION, name, transport);
	}
	// TODO: Add the network protocol type to the QR code payload
#ifdef CONFIG_EXAMPLE_PROV_SHOW_QR
	ESP_LOGD(TAG, "Scan this QR code from the provisioning application for Provisioning.");
	esp_qrcode_config_t cfg = ESP_QRCODE_CONFIG_DEFAULT();
	esp_qrcode_generate(&cfg, payload);
#endif /* CONFIG_EXAMPLE_PROV_SHOW_QR */
	ESP_LOGD(TAG, "If QR code is not visible, copy paste the below URL in a browser.\n%s?data=%s", QRCODE_BASE_URL,
			 payload);
}

#ifdef CONFIG_EXAMPLE_PROV_ENABLE_APP_CALLBACK
void wifi_prov_app_callback(void *user_data, wifi_prov_cb_event_t event, void *event_data) {
	/**
	 * This is blocking callback, any configurations that needs to be set when a particular
	 * provisioning event is triggered can be set here.
	 */
	switch (event) {
	case WIFI_PROV_SET_STA_CONFIG: {
		/**
		 * Wi-Fi configurations can be set here before the Wi-Fi is enabled in
		 * STA mode.
		 */
		wifi_config_t *wifi_config = (wifi_config_t *)event_data;
		(void)wifi_config;
		break;
	}
	default:
		break;
	}
}

const wifi_prov_event_handler_t wifi_prov_event_handler = {
	.event_cb = wifi_prov_app_callback,
	.user_data = NULL,
};
#endif /* EXAMPLE_PROV_ENABLE_APP_CALLBACK */

static void _six_iot_init_network_prov_manager(wifi_ap_config_t *ap_config) {
	/* Initialize TCP/IP */
	ESP_ERROR_CHECK(esp_netif_init());

	/* Initialize the event loop */
	ESP_ERROR_CHECK(esp_event_loop_create_default());
	wifi_event_group = xEventGroupCreate();

	/* Register our event handler for Wi-Fi, IP and Provisioning related events */
	ESP_ERROR_CHECK(esp_event_handler_register(NETWORK_PROV_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_BLE
	ESP_ERROR_CHECK(esp_event_handler_register(PROTOCOMM_TRANSPORT_BLE_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
#endif
	ESP_ERROR_CHECK(
		esp_event_handler_register(PROTOCOMM_SECURITY_SESSION_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
	ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL));

	/* Initialize Wi-Fi including netif with default config */
	esp_netif_create_default_wifi_sta();
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP
	esp_netif_create_default_wifi_ap();
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP */
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	/* Configuration for the provisioning manager */
	network_prov_mgr_config_t config = {
#ifdef CONFIG_EXAMPLE_RESET_PROV_MGR_ON_FAILURE
		.network_prov_wifi_conn_cfg =
			{
				.wifi_conn_attempts = CONFIG_EXAMPLE_PROV_MGR_CONNECTION_CNT,
			},
#endif
	/* What is the Provisioning Scheme that we want ?
	 * network_prov_scheme_softap or network_prov_scheme_ble */
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_BLE
		.scheme = network_prov_scheme_ble,
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_BLE */
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP
		.scheme = network_prov_scheme_softap,
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP */
#ifdef CONFIG_EXAMPLE_PROV_ENABLE_APP_CALLBACK
		.app_event_handler = wifi_prov_event_handler,
#endif /* EXAMPLE_PROV_ENABLE_APP_CALLBACK */

	/* Any default scheme specific event handler that you would
	 * like to choose. Since our example application requires
	 * neither BT nor BLE, we can choose to release the associated
	 * memory once provisioning is complete, or not needed
	 * (in case when device is already provisioned). Choosing
	 * appropriate scheme specific event handler allows the manager
	 * to take care of this automatically. This can be set to
	 * NETWORK_PROV_EVENT_HANDLER_NONE when using network_prov_scheme_softap*/
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_BLE
		.scheme_event_handler = NETWORK_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_BLE */
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP
									.scheme_event_handler = NETWORK_PROV_EVENT_HANDLER_NONE
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP */
	};

	/* Initialize provisioning manager with the
	 * configuration parameters set above */
	ESP_ERROR_CHECK(network_prov_mgr_init(config));

	bool provisioned = false;
#ifdef CONFIG_EXAMPLE_RESET_PROVISIONED
	network_prov_mgr_reset_wifi_provisioning();
#else
	/* Let's find out if the device is provisioned */
	ESP_ERROR_CHECK(network_prov_mgr_is_wifi_provisioned(&provisioned));

#endif
	/* If device is not yet provisioned start provisioning service */
	if (!provisioned) {
		ESP_LOGD(TAG, "Starting provisioning");

		/* What is the Device Service Name that we want
		 * This translates to :
		 *     - Wi-Fi SSID when scheme is network_prov_scheme_softap
		 *     - device name when scheme is network_prov_scheme_ble
		 */
		char service_name[12];
		get_device_service_name(service_name, sizeof(service_name));

#ifdef CONFIG_EXAMPLE_PROV_SECURITY_VERSION_1
		/* What is the security level that we want (0, 1, 2):
		 *      - NETWORK_PROV_SECURITY_0 is simply plain text communication.
		 *      - NETWORK_PROV_SECURITY_1 is secure communication which consists of secure handshake
		 *          using X25519 key exchange and proof of possession (pop) and AES-CTR
		 *          for encryption/decryption of messages.
		 *      - NETWORK_PROV_SECURITY_2 SRP6a based authentication and key exchange
		 *        + AES-GCM encryption/decryption of messages
		 */
		network_prov_security_t security = NETWORK_PROV_SECURITY_1;

		/* Do we want a proof-of-possession (ignored if Security 0 is selected):
		 *      - this should be a string with length > 0
		 *      - NULL if not used
		 */
		const char *pop = "abcd1234";

		/* This is the structure for passing security parameters
		 * for the protocomm security 1.
		 */
		network_prov_security1_params_t *sec_params = pop;

		const char *username = NULL;

#elif CONFIG_EXAMPLE_PROV_SECURITY_VERSION_2
		network_prov_security_t security = NETWORK_PROV_SECURITY_2;
		/* The username must be the same one, which has been used in the generation of salt and verifier */

#if CONFIG_EXAMPLE_PROV_SEC2_DEV_MODE
		/* This pop field represents the password that will be used to generate salt and verifier.
		 * The field is present here in order to generate the QR code containing password.
		 * In production this password field shall not be stored on the device */
		const char *username = EXAMPLE_PROV_SEC2_USERNAME;
		const char *pop = EXAMPLE_PROV_SEC2_PWD;
#elif CONFIG_EXAMPLE_PROV_SEC2_PROD_MODE
		/* The username and password shall not be embedded in the firmware,
		 * they should be provided to the user by other means.
		 * e.g. QR code sticker */
		char *username = get_network_prov_field(SEC2_USERNAME_KEY);
		char *pop = get_network_prov_field(SEC2_PWD_KEY);
#endif
		/* This is the structure for passing security parameters
		 * for the protocomm security 2.
		 * If dynamically allocated, sec2_params pointer and its content
		 * must be valid till NETWORK_PROV_END event is triggered.
		 */
		network_prov_security2_params_t sec2_params = {};

		ESP_ERROR_CHECK(example_get_sec2_salt(&sec2_params.salt, &sec2_params.salt_len));
		ESP_ERROR_CHECK(example_get_sec2_verifier(&sec2_params.verifier, &sec2_params.verifier_len));

		network_prov_security2_params_t *sec_params = &sec2_params;
#endif
		/* What is the service key (could be NULL)
		 * This translates to :
		 *     - Wi-Fi password when scheme is network_prov_scheme_softap
		 *          (Minimum expected length: 8, maximum 64 for WPA2-PSK)
		 *     - simply ignored when scheme is network_prov_scheme_ble
		 */
		const char *service_key = NULL;

#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_BLE
		/* This step is only useful when scheme is network_prov_scheme_ble. This will
		 * set a custom 128 bit UUID which will be included in the BLE advertisement
		 * and will correspond to the primary GATT service that provides provisioning
		 * endpoints as GATT characteristics. Each GATT characteristic will be
		 * formed using the primary service UUID as base, with different auto assigned
		 * 12th and 13th bytes (assume counting starts from 0th byte). The client side
		 * applications must identify the endpoints by reading the User Characteristic
		 * Description descriptor (0x2901) for each characteristic, which contains the
		 * endpoint name of the characteristic */
		uint8_t custom_service_uuid[] = {
			/* LSB <---------------------------------------
			 * ---------------------------------------> MSB */
			0xb4, 0xdf, 0x5a, 0x1c, 0x3f, 0x6b, 0xf4, 0xbf, 0xea, 0x4a, 0x82, 0x03, 0x04, 0x90, 0x1a, 0x02,
		};

		/* If your build fails with linker errors at this point, then you may have
		 * forgotten to enable the BT stack or BTDM BLE settings in the SDK (e.g. see
		 * the sdkconfig.defaults in the example project) */
		network_prov_scheme_ble_set_service_uuid(custom_service_uuid);
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_BLE */

		/* An optional endpoint that applications can create if they expect to
		 * get some additional custom data during provisioning workflow.
		 * The endpoint name can be anything of your choice.
		 * This call must be made before starting the provisioning.
		 */
		network_prov_mgr_endpoint_create("custom-data");
		/* Create endpoint for cloud user association commands (protobuf payload) */
		network_prov_mgr_endpoint_create("cloud_user_assoc");

		/* Do not stop and de-init provisioning even after success,
		 * so that we can restart it later. */
#ifdef CONFIG_EXAMPLE_REPROVISIONING
		network_prov_mgr_disable_auto_stop(1000);
#endif
		/* Start provisioning service */
		ESP_ERROR_CHECK(
			network_prov_mgr_start_provisioning(security, (const void *)sec_params, service_name, service_key));

		/* The handler for the optional endpoint created above.
		 * This call must be made after starting the provisioning, and only if the endpoint
		 * has already been created above.
		 */
		network_prov_mgr_endpoint_register("custom-data", custom_prov_data_handler, NULL);
		/* Register handler for cloud user association endpoint */
		network_prov_mgr_endpoint_register("cloud_user_assoc", cloud_user_assoc_handler, NULL);

		/* Uncomment the following to wait for the provisioning to finish and then release
		 * the resources of the manager. Since in this case de-initialization is triggered
		 * by the default event loop handler, we don't need to call the following */
		// network_prov_mgr_wait();
		// network_prov_mgr_deinit();
		/* Print QR code for provisioning */
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_BLE
		wifi_prov_print_qr(service_name, username, pop, PROV_TRANSPORT_BLE);
#else  /* CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP */
		wifi_prov_print_qr(service_name, username, pop, PROV_TRANSPORT_SOFTAP);
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_BLE */

// free the username and pop which is allocated in heap
#ifdef CONFIG_EXAMPLE_PROV_SEC2_PROD_MODE
		if (username) {
			free(username);
		}
		if (pop) {
			free(pop);
		}
#endif

	} else {
		ESP_LOGD(TAG, "Already provisioned, starting Wi-Fi STA");

		/* We don't need the manager as device is already provisioned,
		 * so let's release it's resources */
		ESP_ERROR_CHECK(network_prov_mgr_deinit());

		ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
		/* Start Wi-Fi station */
		wifi_init_sta();
	}
}

void six_iot_start_network_prov_manager_mode(six_iot_config_t *iot_config, wifi_ap_config_t *config,
											 esp_event_loop_handle_t loop_handle) {
	s_iot_cfg = iot_config;
	s_six_iot_loop = loop_handle;
	s_report_provision_status(PROVISION_STATUS_START_DEVICE_IN_BLUFI_MODE, "Start the device in blufi mode", NULL);
	_six_iot_init_network_prov_manager(config);
}
