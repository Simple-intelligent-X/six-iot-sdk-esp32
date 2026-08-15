/*
 * six_iot_mqtt.c
 *
 *  Created on: 2023年7月23日
 *      Author: Stephen Yu
 *
 */
#include "esp_mac.h"
#include <esp_event.h>
#include <esp_log.h>
#include <esp_netif.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <lwip/dns.h>
#include <lwip/netdb.h>
#include <lwip/sockets.h>
#include <mqtt_client.h>
#include <nvs_flash.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "six_iam_jwt.h"
#include "six_iot_config.h"
#include "six_iot_creds.h"
#include "six_iot_device.h"
#include "six_iot_log.h"
#include "six_iot_mqtt.h"
#include "six_iot_nvs.h"
#include "six_iot_shadow.h"
#include "six_iot_util.h"

static const char *TAG = "six_iot_mqtt";

// extern const uint8_t device_cert_pem_start[] asm("_binary_device_cert_pem_start");
// extern const uint8_t device_cert_pem_end[] asm("_binary_device_cert_pem_end");

#ifdef CONFIG_AWS_ROOT_CA
extern const uint8_t aws_root_ca_pem_start[] asm("_binary_aws_root_ca_pem_start");
extern const uint8_t aws_root_ca_pem_end[] asm("_binary_aws_root_ca_pem_end");
#endif

#ifdef CONFIG_DEFAULT_ROOT_CA
extern const uint8_t six_ca_pem_start[] asm("_binary_six_ca_pem_start");
extern const uint8_t six_ca_pem_end[] asm("_binary_six_ca_pem_end");
#endif

// #if CONFIG_AWS_MQTT_BROKER && CONFIG_AWS_ROOT_CA
// #define AWS_AUTH_PASSWORD_BUFFER_SIZE 1024
// static char aws_auth_password_buffer[AWS_AUTH_PASSWORD_BUFFER_SIZE];
// #endif

#define SSL_CONTIGUOUS_HEAP_SIZE_NEED 25000
#define SSL_HEAP_SIZE_NEED 40000

#define SIX_IOT_MQTT_CONN_KEEPALIVE CONFIG_SDK_MQTT_CONN_KEEPALIVE

// portMAX_DELAY
#define MQTT_DISCONNECT_EVENT_DELAY pdMS_TO_TICKS(100)
#define MQTT_CLIENT_ERROR_EVENT_DELAY pdMS_TO_TICKS(100)
#define MQTT_CLIENT_WATCH_DOG_EVENT_FIRST_DELAY pdMS_TO_TICKS(5000)
#define MQTT_CLIENT_WATCH_DOG_INTERVAL pdMS_TO_TICKS(1000 * 10)
#define MQTT_CLIENT_STOP_EVENT_DELAY pdMS_TO_TICKS(100)
// FIX(6): timeout for taking s_mqtt_state_mutex around state reads/writes.
#define MQTT_STATE_LOCK_TIMEOUT pdMS_TO_TICKS(50)

static char *s_iot_sdk_update_delta_topic = NULL;
static char *s_iot_sdk_ota_topic = NULL;
static char *s_iot_sdk_ping_topic = NULL;
static char *s_iot_sdk_lwt_topic = NULL;
static char *s_iot_sdk_log_topic = NULL;

static six_iot_config_t *s_iot_cfg;

static esp_mqtt_client_handle_t client = NULL;

static esp_mqtt_client_config_t s_mqtt_cfg;

static esp_event_loop_handle_t s_six_iot_event_loop = NULL;

static six_iot_mqtt_event_handler_t s_mqtt_external_handler = NULL;

static mqtt_client_state_t s_mqtt_state = MQTT_STATE_READY;

void _six_iot_request_new_token_handler(bool success, char *new_password, char *access_token);

void _six_iot_update_s_mqtt_cfg_newpwd(char *new_password);

void six_iot_handle_mqtt_conn_error();

void _six_iot_format_log_msg(const char *log_str);

static void s_mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data);

static void s_subscribe_update_delta_topic(esp_event_base_t base, int32_t event_id, esp_mqtt_event_handle_t event);

static void s_subscribe_ota_topic(esp_event_base_t base, int32_t event_id, esp_mqtt_event_handle_t event);

static bool s_mqtt_connected = false;
static bool s_mqtt_connected_once = false;

#define LOG_BUFFER_SIZE 1024 + 10 + 128
static char s_log_buffer[LOG_BUFFER_SIZE];
static char s_error_msg[256];

static char *s_current_mqtt_password = NULL;

// fed from xTaskGetTickCount()/1000 which silently
// assumed a 1ms tick period. Now stores whole seconds derived from
// esp_timer_get_time() (always microseconds regardless of tick rate).
static int64_t s_mqtt_disconnect_time_start = 0;
#define MAX_DISCONNECT_TICKS_SECONDS 60

static SemaphoreHandle_t s_mqtt_state_mutex = NULL;

// centralize client teardown so every failure path can safely
// destroy a half-initialized client instead of leaking it and leaving
// the global `client` pointer stuck non-NULL forever.
static void s_destroy_mqtt_client(void) {
	if (client) {
		esp_mqtt_client_destroy(client);
		client = NULL;
	}
}

// all reads/writes of s_mqtt_state now go through these helpers
// so six_iot_reconnect_mqtt() and six_iot_handle_mqtt_conn_error() can't
// race each other. Falls back to unlocked access only if called before
// the mutex exists (shouldn't happen in normal startup order).
static mqtt_client_state_t s_get_mqtt_state(void) {
	mqtt_client_state_t state;
	if (s_mqtt_state_mutex && xSemaphoreTake(s_mqtt_state_mutex, MQTT_STATE_LOCK_TIMEOUT) == pdTRUE) {
		state = s_mqtt_state;
		xSemaphoreGive(s_mqtt_state_mutex);
	} else {
		state = s_mqtt_state;
	}
	return state;
}

static void s_set_mqtt_state(mqtt_client_state_t new_state) {
	if (s_mqtt_state_mutex && xSemaphoreTake(s_mqtt_state_mutex, MQTT_STATE_LOCK_TIMEOUT) == pdTRUE) {
		s_mqtt_state = new_state;
		xSemaphoreGive(s_mqtt_state_mutex);
	} else {
		s_mqtt_state = new_state;
	}
}

void _six_iot_request_new_token_handler(bool success, char *new_password, char *access_token) {
	if (!success) {
		six_log_message("Failed to get new token from IAM service!");
	}
	_six_iot_update_s_mqtt_cfg_newpwd(new_password);
}

// when there is disconnect event is reported, we will not handle reconnect in the mqtt event task, will send event to
// the six_iot_event_loop task to handle the reconnect
void six_iot_reconnect_mqtt() {
	if (s_mqtt_state_mutex && xSemaphoreTake(s_mqtt_state_mutex, MQTT_STATE_LOCK_TIMEOUT) != pdTRUE) {
		ESP_LOGW(TAG, "Could not acquire mqtt state lock, skip this round reconnect");
		six_log_message("Could not acquire mqtt state lock, skip this round reconnect");
		return;
	}
	if (s_mqtt_state == MQTT_STATE_RECONNECTING) {
		ESP_LOGW(TAG, "MQTT client is reconnecting, skip this round reconnect");
		six_log_message("MQTT client is reconnecting, skip this round reconnect");
		if (s_mqtt_state_mutex) {
			xSemaphoreGive(s_mqtt_state_mutex);
		}
		return;
	}
	s_mqtt_state = MQTT_STATE_RECONNECTING;
	if (s_mqtt_state_mutex) {
		xSemaphoreGive(s_mqtt_state_mutex);
	}

	// stop the client here instead of in six_iot_handle_mqtt_conn_error().
	// six_iot_reconnect_mqtt() is invoked from the consumer of
	// the SIX_IOT_EVENT/MQTT_DISCONNECTED event on s_six_iot_event_loop
	if (client) {
		esp_mqtt_client_stop(client);
	}

	char *id_token = six_nvs_read_id_token();
	if (NULL != id_token && !six_iam_token_expired(id_token, Second)) {
		ESP_LOGD(TAG, "Reconnect mqtt client with token in nvs");
		six_log_message("Reconnect mqtt client with token in nvs");
		_six_iot_request_new_token_handler(true, id_token, NULL);
		free(id_token);
	} else {
		free(id_token);
		ESP_LOGD(TAG, "Reqest the new token to reconnect the mqtt client");
		six_log_message("Reqest the new token to reconnect the mqtt client");
		// request the new id_token and set the callback handler
		six_iot_refresh_device_tokens_with_handler(_six_iot_request_new_token_handler);
	}
}

void six_iot_handle_mqtt_conn_error() {
	if (xSemaphoreTake(s_mqtt_state_mutex, MQTT_STATE_LOCK_TIMEOUT) != pdTRUE) {
		ESP_LOGW(TAG, "six_iot_handle_mqtt_conn_error is executing, skip it");
		six_log_message("six_iot_handle_mqtt_conn_error is executing, skip it");
		return;
	}
	if (s_mqtt_state == MQTT_STATE_RECONNECTING) {
		ESP_LOGW(TAG, "MQTT client is reconnecting, skip this round event post");
		six_log_message("MQTT client is reconnecting, skip this round event post");
		xSemaphoreGive(s_mqtt_state_mutex);
		return;
	}
	esp_err_t ret =
		esp_event_post_to(s_six_iot_event_loop, SIX_IOT_EVENT, MQTT_CONN_ERR, NULL, 0, MQTT_DISCONNECT_EVENT_DELAY);
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "Failed to post MQTT_CONN_ERR event: %s", esp_err_to_name(ret));
		six_log_message("Failed to post MQTT_CONN_ERR event");
	}
	xSemaphoreGive(s_mqtt_state_mutex);
}

static char *_get_error_msg(char *msg, esp_err_t err) {
	memset(s_error_msg, 0, sizeof(s_error_msg));
	snprintf(s_error_msg, sizeof(s_error_msg) - 1, "%s, err: %s", msg, esp_err_to_name(err));
	return s_error_msg;
}

void _six_iot_update_s_mqtt_cfg_newpwd(char *new_password) {
	if (NULL == new_password) {
		six_defregment_heap(TAG);
		ESP_LOGE(TAG, "New password is NULL, cannot reconfigure mqtt client!");
		six_log_message("New password is NULL, cannot reconfigure mqtt client!");
		s_set_mqtt_state(MQTT_CREATE_CLIENT_FAIL);
		return;
	}

	if (s_current_mqtt_password != NULL) {
		free(s_current_mqtt_password);
		s_current_mqtt_password = NULL;
	}
	// Assign the new global pointer
	s_current_mqtt_password = strdup(new_password);
	// Point the config to the managed pointer
	s_mqtt_cfg.credentials.authentication.password = s_current_mqtt_password;

	if (client) {
		ESP_LOGD(TAG, "Update config of the client to apply new pwd");
		esp_err_t ret = esp_mqtt_set_config(client, &s_mqtt_cfg);
		if (ret != ESP_OK) {
			six_defregment_heap(TAG);
			ESP_LOGE(TAG, "Failed to update config for mqtt client, err: %d", ret);
			six_log_message(_get_error_msg("Failed to update config for mqtt client", ret));
			// Destroy it so the next attempt can actually re-init from scratch.
			s_destroy_mqtt_client();
			s_set_mqtt_state(MQTT_CREATE_CLIENT_FAIL);
			return;
		}
	} else {
		ESP_LOGD(TAG, "MQTT client is NULL, creating a new client");
		six_log_message("MQTT client is NULL, creating a new client");
		client = esp_mqtt_client_init(&s_mqtt_cfg);
		if (client == NULL) {
			six_defregment_heap(TAG);
			ESP_LOGE(TAG, "Failed to initialize new mqtt client!");
			six_log_message("Failed to initialize new mqtt client!");
			s_set_mqtt_state(MQTT_CREATE_CLIENT_FAIL);
			return;
		}
		esp_err_t ret =
			esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, s_mqtt_event_handler, s_mqtt_external_handler);
		if (ret != ESP_OK) {
			six_defregment_heap(TAG);
			ESP_LOGE(TAG, "Failed to register event for new mqtt client, err: %d", ret);
			six_log_message(_get_error_msg("Failed to register event for new mqtt client", ret));
			s_destroy_mqtt_client();
			s_set_mqtt_state(MQTT_CREATE_CLIENT_FAIL);
			return;
		}
		ret = esp_mqtt_client_start(client);
		if (ret != ESP_OK) {
			six_defregment_heap(TAG);
			ESP_LOGE(TAG, "Failed to start new mqtt client, err: %d", ret);
			six_log_message(_get_error_msg("Failed to start new mqtt client", ret));
			s_destroy_mqtt_client();
			s_set_mqtt_state(MQTT_CREATE_CLIENT_FAIL);
			return;
		}
	}
	s_set_mqtt_state(MQTT_STATE_READY);
}

/*
 * @brief Event handler registered to receive MQTT events
 *
 *  This function is called by the MQTT client event loop.
 *
 * @param handler_args user data registered to the event.
 * @param base Event base for the handler(always MQTT Base in this example).
 * @param event_id The id for the received event.
 * @param event_data The data for the event, esp_mqtt_event_handle_t.
 */
static void s_mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data) {
	ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%ld", base, event_id);
	esp_mqtt_event_handle_t event = event_data;
	switch ((esp_mqtt_event_id_t)event_id) {
	case MQTT_EVENT_CONNECTED:
		ESP_LOGD(TAG, "MQTT_EVENT_CONNECTED");
		s_mqtt_connected = true;
		s_mqtt_connected_once = true;
		six_log_message("MQTT connected");
		s_subscribe_update_delta_topic(base, event_id, event);
		s_subscribe_ota_topic(base, event_id, event);
		six_iot_publish_conn_online_msg();
		break;
	case MQTT_EVENT_BEFORE_CONNECT:
		ESP_LOGD(TAG, "MQTT try to connect");
		six_defregment_heap(TAG);
		six_memory_snapshot(TAG);
		break;
	case MQTT_EVENT_DISCONNECTED:
		ESP_LOGD(TAG, "MQTT_EVENT_DISCONNECTED");
		six_log_message("MQTT disconnected");
		s_mqtt_connected = false;
		s_mqtt_disconnect_time_start = esp_timer_get_time() / 1000000;
		break;
	case MQTT_EVENT_SUBSCRIBED:
		ESP_LOGD(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
		break;
	case MQTT_EVENT_UNSUBSCRIBED:
		ESP_LOGD(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
		break;
	case MQTT_EVENT_PUBLISHED:
		ESP_LOGD(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
		break;
	case MQTT_EVENT_DATA:
		ESP_LOGD(TAG, "MQTT_EVENT_DATA");
		ESP_LOGD(TAG, "TOPIC = %.*s\r\n", event->topic_len, event->topic);
		ESP_LOGD(TAG, "DATA = %.*s\r\n", event->data_len, event->data);
		break;
	case MQTT_EVENT_ERROR:
		ESP_LOGD(TAG, "MQTT_EVENT_ERROR");

		char error_msg[128];
		if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
			ESP_LOGE(TAG, "esp-tls error: 0x%x", event->error_handle->esp_tls_last_esp_err);
			ESP_LOGE(TAG, "TLS stack error: -0x%x", -event->error_handle->esp_tls_stack_err);
			ESP_LOGE(TAG, "Socket errno: %d", event->error_handle->esp_transport_sock_errno);
			snprintf(error_msg, sizeof(error_msg),
					 "MQTT_EVENT_ERROR: esp-tls error=0x%x, TLS stack error=-0x%x, socket errno=%d",
					 event->error_handle->esp_tls_last_esp_err, -event->error_handle->esp_tls_stack_err,
					 event->error_handle->esp_transport_sock_errno);
			six_log_message(error_msg);
		}

		if (event->error_handle->error_type == MQTT_ERROR_TYPE_CONNECTION_REFUSED) {
			if (event->error_handle->connect_return_code == MQTT_CONNECTION_REFUSE_BAD_USERNAME ||
				event->error_handle->connect_return_code == MQTT_CONNECTION_REFUSE_NOT_AUTHORIZED) {
				ESP_LOGE(TAG, "Authentication failed - may need to update the password");
				snprintf(error_msg, sizeof(error_msg),
						 "MQTT_EVENT_ERROR: Authentication failed, connection return code=%d",
						 event->error_handle->connect_return_code);
				six_log_message(error_msg);
				if (s_mqtt_cfg.credentials.authentication.password) {
					ESP_LOGW(TAG, "Auth failed with a credential set (redacted)");
				}
				six_iot_handle_mqtt_conn_error();
			}
		}
		break;
	default:
		ESP_LOGD(TAG, "MQTT other event id:%d", event->event_id);
		break;
	}

	// call the six_iot_mqtt_event_handler_t to let the caller to do the operation
	six_iot_mqtt_event_handler_t mqtt_handler = handler_args;
	if (mqtt_handler) {
		(*mqtt_handler)(base, event_id, event);
	}
}

// static const char *alpn_protos[] = {"mqtt", NULL};

void six_iot_start_mqtt(six_iot_config_t *iot_config, char *mqtt_endpoint, char *mqtt_clientid, char *mqtt_username,
						char *mqtt_password, esp_event_loop_handle_t loop_handle,
						six_iot_mqtt_event_handler_t handler) {
	if (s_mqtt_state_mutex == NULL) {
		s_mqtt_state_mutex = xSemaphoreCreateMutex();
		if (s_mqtt_state_mutex == NULL) {
			ESP_LOGE(TAG, "Failed to create MQTT state mutex!");
			return;
		}
	}
	six_log_message("six_iot_start_mqtt is called");
	s_iot_cfg = iot_config;
	s_six_iot_event_loop = loop_handle;
	s_mqtt_external_handler = handler;
	s_mqtt_cfg.broker.address.uri = mqtt_endpoint;
#if CONFIG_DEFAULT_MQTT_BROKER && CONFIG_DEFAULT_ROOT_CA
	s_mqtt_cfg.credentials.username = mqtt_username;
	if (s_current_mqtt_password != NULL) {
		free(s_current_mqtt_password);
	}
	s_current_mqtt_password = strdup(mqtt_password);
	s_mqtt_cfg.credentials.authentication.password = s_current_mqtt_password;
	s_mqtt_cfg.broker.verification.certificate = (const char *)six_ca_pem_start;
	s_mqtt_cfg.broker.verification.certificate_len = six_ca_pem_end - six_ca_pem_start;
	s_mqtt_cfg.broker.verification.skip_cert_common_name_check = true;
#endif
#if CONFIG_AWS_MQTT_BROKER && CONFIG_AWS_ROOT_CA
	if (s_current_mqtt_password != NULL) {
		free(s_current_mqtt_password);
	}
	s_current_mqtt_password = strdup(mqtt_password);
	s_mqtt_cfg.credentials.username = CONFIG_AWS_IOT_USERNAME_WITH_AUTHORIZER;
	s_mqtt_cfg.credentials.authentication.password = s_current_mqtt_password;
	// s_mqtt_cfg.credentials.username = "username?x-amz-customauthorizer-name=six-iot-authorizer";
	// s_mqtt_cfg.credentials.authentication.certificate = (const char*) device_cert_pem_start;
	// s_mqtt_cfg.credentials.authentication.key = get_device_private_key(),
	s_mqtt_cfg.broker.verification.certificate = (const char *)aws_root_ca_pem_start,
	s_mqtt_cfg.broker.verification.certificate_len = aws_root_ca_pem_end - aws_root_ca_pem_start;
#endif
	s_mqtt_cfg.credentials.client_id = mqtt_clientid;

	// enable auto-connect
	// s_mqtt_cfg.network.disable_auto_reconnect = true;

	s_iot_sdk_update_delta_topic =
		six_iot_get_shadow_topic(s_iot_cfg->iot_product_id, s_iot_cfg->mqtt_clientid, UpdateDelta);
	s_iot_sdk_ota_topic = six_iot_get_shadow_topic(s_iot_cfg->iot_product_id, s_iot_cfg->mqtt_clientid, Ota);
	s_iot_sdk_ping_topic = six_iot_get_shadow_topic(s_iot_cfg->iot_product_id, s_iot_cfg->mqtt_clientid, Ping);
	s_iot_sdk_lwt_topic = six_iot_get_shadow_topic(s_iot_cfg->iot_product_id, s_iot_cfg->mqtt_clientid, Lwt);
	s_iot_sdk_log_topic = six_iot_get_shadow_topic(s_iot_cfg->iot_product_id, s_iot_cfg->mqtt_clientid, Log);

	s_mqtt_cfg.session.keepalive = SIX_IOT_MQTT_CONN_KEEPALIVE;
	// set the clean session to false to receive the offline messages
	s_mqtt_cfg.session.disable_clean_session = true;
	s_mqtt_cfg.session.last_will.topic = s_iot_sdk_lwt_topic;
	s_mqtt_cfg.session.last_will.msg = "{\"status\":\"Offline\"}";
	s_mqtt_cfg.session.last_will.msg_len = strlen(s_mqtt_cfg.session.last_will.msg);
	s_mqtt_cfg.session.last_will.qos = 1;
	// we need to retain the LWT message on mqtt broker
	s_mqtt_cfg.session.last_will.retain = true;

	s_destroy_mqtt_client();

	client = esp_mqtt_client_init(&s_mqtt_cfg);
	if (client == NULL) {
		ESP_LOGE(TAG, "Failed to initialize mqtt client!");
		six_log_message("Failed to initialize mqtt client!");
		s_set_mqtt_state(MQTT_CREATE_CLIENT_FAIL);
		return;
	}
	// configure_aws_iot_alpn(client);
	esp_err_t ret = esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, s_mqtt_event_handler, handler);
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "Failed to register event for mqtt client, err: %d", ret);
		six_log_message(_get_error_msg("Failed to register event for mqtt client", ret));
		s_destroy_mqtt_client();
		s_set_mqtt_state(MQTT_CREATE_CLIENT_FAIL);
		return;
	}
	ret = esp_mqtt_client_start(client);
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "Failed to start mqtt client, err: %d", ret);
		six_log_message(_get_error_msg("Failed to start mqtt client", ret));
		s_destroy_mqtt_client();
		s_set_mqtt_state(MQTT_CREATE_CLIENT_FAIL);
		return;
	}
	esp_event_post_to(s_six_iot_event_loop, SIX_IOT_EVENT, MQTT_CLIENT_WATCH_DOG, NULL, 0,
					  MQTT_CLIENT_WATCH_DOG_EVENT_FIRST_DELAY);
}

void six_iot_start_watchdog_for_mqtt_client() {
	ESP_LOGD(TAG, "six_iot_start_watchdog_for_mqtt_client event is triggered");
	if (!s_mqtt_connected && s_mqtt_connected_once) {
		six_defregment_heap(TAG);

		int64_t current_time = esp_timer_get_time() / 1000000;
		int64_t elapsed_time = current_time - s_mqtt_disconnect_time_start;
		// watchdog is triggered
		if (elapsed_time >= MAX_DISCONNECT_TICKS_SECONDS) {
			ESP_LOGE(TAG, "Watchdog triggered: MQTT disconnected for over %lld seconds. Forcing manual reconnect.",
					 (long long)elapsed_time);
			six_log_message("Watchdog triggered: MQTT disconnected for over 60 seconds. Forcing manual reconnect.");
			six_iot_handle_mqtt_conn_error();
			// Reset the watchdog timer immediately to prevent re-triggering soon
			s_mqtt_disconnect_time_start = esp_timer_get_time() / 1000000;
		} else {
			ESP_LOGW(TAG, "MQTT watchdog monitoring. Disconnected time: %lld seconds.", (long long)elapsed_time);
		}
	}
}

bool six_iot_publish_conn_online_msg() {
	if (MQTT_STATE_RECONNECTING == s_get_mqtt_state()) {
		ESP_LOGW(TAG, "MQTT client is disconnecting, skip conn status message");
		return false;
	}
	if (!client) {
		ESP_LOGW(TAG, "MQTT client is NULL, can't publish conn status message through NULL client");
		return true;
	}
	if (!s_mqtt_connected_once) {
		ESP_LOGW(TAG, "MQTT client has never connected, skip conn status message");
		return false;
	}
	if (!s_mqtt_connected) {
		ESP_LOGW(TAG, "MQTT client is not connected, can't publish conn status message through non-connected client");
		return true;
	}
	// we will use the LWT topic to report the conn status
	char *topic = s_iot_sdk_lwt_topic;
	char *payload = "{\"status\":\"Online\"}";
	int payload_len = strlen(payload);
	// we need to retain the conn status message on mqtt broker
	int msg_id = esp_mqtt_client_publish(client, topic, payload, payload_len, 1, 1);
	if (msg_id == -1) {
		ESP_LOGE(TAG, "Publish failed: Invalid parameters or MQTT client not connected");
		return true;
	} else if (msg_id == 0) {
		ESP_LOGE(TAG, "Publish failed: Message too long or network error");
		return true;
	}
	ESP_LOGD(TAG, "Publish to topic: %s, msg_id: %d", topic, msg_id);
	// six_log_message("Publish ping message succeed");
	return false;
}

esp_err_t six_iot_publish_log_msg(char *log) {
	if (log == NULL) {
		ESP_LOGW(TAG, "log is NULL, return directly");
		return ESP_FAIL;
	}
	if (MQTT_STATE_RECONNECTING == s_get_mqtt_state()) {
		ESP_LOGW(TAG, "MQTT client is disconnecting, skip log message");
		return false;
	}
	if (!client) {
		ESP_LOGW(TAG, "client is NULL, can't publish log message through NULL client");
		return ESP_FAIL;
	}
	if (!s_mqtt_connected) {
		ESP_LOGW(TAG, "client is not connected, can't publish log message through non-connected client");
		return ESP_FAIL;
	}
	int size = sizeof(char) * (strlen(log) + 1);
	ESP_LOGD(TAG, "upload log: %s, size is: %d", log, size);
	char *topic = s_iot_sdk_log_topic;
	_six_iot_format_log_msg(log);
	int msg_id = esp_mqtt_client_publish(client, topic, s_log_buffer, strlen(s_log_buffer), 1, 0);
	if (msg_id == -1) {
		ESP_LOGE(TAG, "Publish failed: Invalid parameters or MQTT client not connected");
		return ESP_FAIL;
	} else if (msg_id == 0) {
		ESP_LOGE(TAG, "Publish failed: Message too long or network error");
		return ESP_FAIL;
	}
	ESP_LOGD(TAG, "Publish to topic: %s, msg_id: %d", topic, msg_id);
	return ESP_OK;
}

void _six_iot_format_log_msg(const char *log) {
	// Clear the buffer first
	memset(s_log_buffer, 0, sizeof(s_log_buffer));

	// Calculate available space for the log string (total buffer size minus fixed JSON overhead)
	// Fixed format: {"log":"}" + null terminator = 10 characters overhead
	size_t max_log_len = LOG_BUFFER_SIZE - 10;

	// Check if the log string fits, truncate if necessary
	size_t log_len = strlen(log);
	if (log_len > max_log_len) {
		log_len = max_log_len;
	}

	// Format the JSON message safely
	int written = snprintf(s_log_buffer, sizeof(s_log_buffer), "%.*s", (int)log_len, log);
	// Check for errors
	if (written < 0) {
		// snprintf failed
		ESP_LOGE(TAG, "snprintf failed when formatting log message");
	} else if (written >= sizeof(s_log_buffer)) {
		// Buffer was truncated (shouldn't happen due to our check, but good practice)
		s_log_buffer[sizeof(s_log_buffer) - 1] = '\0';
	}
	ESP_LOGD(TAG, "Formatted log message: %s", s_log_buffer);
}

static void s_subscribe_update_delta_topic(esp_event_base_t base, int32_t event_id, esp_mqtt_event_handle_t event) {
	char *topic = s_iot_sdk_update_delta_topic;
	int msg_id = esp_mqtt_client_subscribe(event->client, topic, 1);
	ESP_LOGD(TAG, "subscribe to topic: %s, the msg_id is: %d\n", topic, msg_id);
}

// subcribe to the "ota" topic, when there is ota need, an MQTT publisher can publish the ota data
static void s_subscribe_ota_topic(esp_event_base_t base, int32_t event_id, esp_mqtt_event_handle_t event) {
	char *topic = s_iot_sdk_ota_topic;
	int msg_id = esp_mqtt_client_subscribe(event->client, topic, 1);
	ESP_LOGD(TAG, "subscribe to topic: %s, the msg_id is: %d\n", topic, msg_id);
}
