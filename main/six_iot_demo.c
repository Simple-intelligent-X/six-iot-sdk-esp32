#include <cJson.h>
#include <driver/gpio.h>
#include <esp_log.h>

#include "six_iot_config.h"
#include "six_iot_log.h"
#include "six_iot_ota.h"
#include "six_iot_sdk.h"
#include "six_iot_shadow.h"
#include "version.h"

// for ESP-Devkits-V4, except the LED for the power, no other programable LED on the borad
// 23
#define BLINK_GPIO CONFIG_BLINK_LED_GPIO 
// 32 
#define RELAY_GPIO CONFIG_RELAY_GPIO

static const char *TAG = "six_iot_demo";
static char *s_product_id = NULL;
static char *s_device_guid = NULL;
static esp_mqtt_client_handle_t s_mqtt_client = NULL;

static int s_light_status = 0;
static char *s_device_status = NULL;

static char *s_topic_update = NULL;
static char *s_topic_update_delta = NULL;
static char *s_topic_ota = NULL;

void s_init_device_static_res();
void s_init_shadow_topics();

static void report_device_status() {
	char *topic = s_topic_update;
	char *payload = s_device_status;
	int payload_len = strlen(payload);
	if (topic == NULL) {
		ESP_LOGE(TAG, "Topic for report is not initialized or requested!");
		return;
	}
	if (payload == NULL) {
		ESP_LOGE(TAG, "Payload for report is not initialized!");
		return;
	}
	int msg_id = esp_mqtt_client_publish(s_mqtt_client, topic, payload, payload_len, 1, 0);
	ESP_LOGD(TAG, "Publish to topic: %s, msg_id: %d", topic, msg_id);
	// Note: We do NOT free 'payload' as it points to either a literal or the static s_device_status.
}

static void publish_light_status(int on) {
	char *topic = s_topic_update;
	char *json = NULL;
	if (on) {
		json = "{\"state\": {\"reported\": {\"light\": \"on\"}}}";
	} else {
		json = "{\"state\": {\"reported\": {\"light\": \"off\"}}}";
	}
	int msg_id = esp_mqtt_client_publish(s_mqtt_client, topic, json, strlen(json), 1, 0);
	ESP_LOGD(TAG, "Publish to topic: %s, the msg_id is: %d\n", topic, msg_id);
}

static void s_configure_led(void) {
	// ESP_LOGD(TAG, "Example configured to blink GPIO LED!");
	gpio_reset_pin(BLINK_GPIO);

	#ifdef CONFIG_TEST_RELAY_GPIO
		gpio_reset_pin(RELAY_GPIO);
	#endif
	/* Set the GPIO as a push/pull output */
	gpio_set_direction(BLINK_GPIO, GPIO_MODE_OUTPUT);

	#ifdef CONFIG_TEST_RELAY_GPIO
		gpio_set_direction(RELAY_GPIO, GPIO_MODE_OUTPUT);
	#endif
}

static void s_blink_led_on(void) {
	/* Set the GPIO level according to the state (LOW or HIGH)*/
	gpio_set_level(BLINK_GPIO, 1);
	#ifdef CONFIG_TEST_RELAY_GPIO
		gpio_set_level(RELAY_GPIO, 1);
	#endif
	ESP_LOGI(TAG, "GPIO %d and GPIO %d for LED and Relay is set to HIGH", BLINK_GPIO, RELAY_GPIO);
}

static void s_blink_led_off(void) {
	/* Set the GPIO level according to the state (LOW or HIGH)*/
	gpio_set_level(BLINK_GPIO, 0);
	#ifdef CONFIG_TEST_RELAY_GPIO
		gpio_set_level(RELAY_GPIO, 0);
	#endif
}

static int s_parse_light_json(char *data) {
	int light_on = -1; // default to off
	cJSON *json = cJSON_Parse(data);
	if (json == NULL) {
		ESP_LOGE(TAG, "Failed to parse JSON data");
		return -1;
	}
	cJSON *state = cJSON_GetObjectItemCaseSensitive(json, "state");
	// cJSON *desired = cJSON_GetObjectItemCaseSensitive(json, "desired");
	if (cJSON_IsObject(state)) {
		ESP_LOGD(TAG, "Find desired json object"); // Changed to DEBUG log
		cJSON *light = cJSON_GetObjectItemCaseSensitive(state, "light");
		if (cJSON_IsString(light) && (light->valuestring != NULL)) {
			ESP_LOGD(TAG, "Find json light attribute: %s", light->valuestring); // Debug log
			if (strcmp(light->valuestring, "on") == 0) {
				light_on = 1;
			} else if (strcmp(light->valuestring, "off") == 0) {
				light_on = 0;
			} else {
				ESP_LOGE(TAG, "Unknown light value: %s", light->valuestring);
			}
		}
	}
	cJSON_Delete(json); // DELETE the parsed tree. CRITICAL!
	return light_on;
}

static void s_control_led(esp_mqtt_event_handle_t event) {
	int on = s_parse_light_json(event->data);
	if (on == -1) {
		ESP_LOGE(TAG, "Failed to parse light status from JSON, no action taken");
		return;
	}
	if (on == 1) {
		s_blink_led_on();
	} else if (on == 0) {
		s_blink_led_off();
	}
	s_light_status = on;
	publish_light_status(on);
}

static void s_handle_ota_req(esp_mqtt_event_handle_t event) {
	ESP_LOGW(TAG, "s_handle_ota_req");
	cJSON *json = cJSON_Parse(event->data);
	if (NULL == json) {
		ESP_LOGE(TAG, "Can't parse OTA payload");
		return;
	}	
	char *version = six_iot_parse_shadow_str_attr(json, "version");
	char *url = NULL;
	int proceed_with_ota = 0; // Flag
	if (version != NULL) {
		if (strcmp(version, PROJECT_VERSION) != 0) {
			// Versions are different, check for URL
			url = six_iot_parse_shadow_str_attr(json, "url");
			if (url != NULL) {
				proceed_with_ota = 1;
			} else {
				ESP_LOGE(TAG, "URL not found in OTA payload");
			}
		} else {
			ESP_LOGD(TAG, "OTA skipped, version is current: %s", PROJECT_VERSION);
		}
	} else {
		ESP_LOGE(TAG, "Version not found in OTA payload");
	}
	if (proceed_with_ota) {
		ota(url);
	}
	cJSON_Delete(json); // Delete the parsed JSON tree
}

/**
 * "SDK callback method"
 *
 * Will use the c_init_firmware to intialize the LED GPIO pin
 *
 */
void init_firmware(void) {
	s_configure_led();
	// init the static resource to report the device status
	s_init_device_static_res();
}

void s_init_shadow_topics() {
	if (s_topic_update == NULL) {
		s_topic_update = six_iot_get_shadow_topic(s_product_id, s_device_guid, Update);
	}
	if (s_topic_update_delta == NULL) {
		s_topic_update_delta = six_iot_get_shadow_topic(s_product_id, s_device_guid, UpdateDelta);
	}
	if (s_topic_ota == NULL) {
		s_topic_ota = six_iot_get_shadow_topic(s_product_id, s_device_guid, Ota);
	}
}

void s_init_device_static_res() {
	// s_device_status_root
	cJSON *s_device_status_root = cJSON_CreateObject();
	cJSON *firmware = cJSON_CreateObject();
	cJSON *reported = cJSON_CreateObject();
	cJSON *state = cJSON_CreateObject();
	cJSON_AddStringToObject(firmware, "version", PROJECT_VERSION);
	cJSON_AddItemToObject(reported, "firmware", firmware);
	cJSON_AddItemToObject(state, "reported", reported);
	cJSON_AddItemToObject(s_device_status_root, "state", state);
	s_device_status = cJSON_PrintUnformatted(s_device_status_root);
	cJSON_Delete(s_device_status_root);
}

/**
 * "SDK callback method"
 *
 * Handle the MQTT event to turn on or off the LED
 *
 */
void six_iot_handle_mqtt_event(const six_iot_config_t *s_iot_conf, esp_event_base_t base, int32_t event_id,
							   esp_mqtt_event_handle_t event) {
	switch ((esp_mqtt_event_id_t)event_id) {
	case MQTT_EVENT_CONNECTED:
		s_mqtt_client = event->client;
		s_product_id = s_iot_conf->iot_product_id;
		s_device_guid = s_iot_conf->mqtt_clientid;
		s_init_shadow_topics();
		report_device_status();
		publish_light_status(s_light_status);
		break;
	case MQTT_EVENT_DATA:
		if (strncmp(event->topic, s_topic_update_delta, event->topic_len) == 0) {
			s_control_led(event);
			return;
		} else if (strncmp(event->topic, s_topic_ota, event->topic_len) == 0) {
			s_handle_ota_req(event);
			return;
		}
		break;
	default:
		break;
	}
}

void app_main(void) {
	ESP_LOGD(TAG, "Start app_main, heap size is: %ld", esp_get_free_heap_size());
	// call the c_init_firmware to let the specific firmware to initialize the board
	init_firmware();
	six_iot_run_sdk();
}