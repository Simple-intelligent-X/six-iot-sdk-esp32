/*
 * six_iam_jwt.c
 *
 *  Created on: 2023年7月22日
 *      Author: Stephen Yu
 */
#include <string.h>
#include <cJson.h>
#include <esp_err.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_netif.h>
#include <esp_sntp.h>
#include <esp_timer.h>
#include <esp_wifi.h>
#include <mqtt_client.h>
#include <nvs_flash.h>

#ifdef CONFIG_ESP32_PROV_SOFTAP
#include "six_iot_prov_softap.h"
#endif
#ifdef CONFIG_ESP32_PROV_BLUFI
#include "six_iot_prov_blufi.h"
#endif

#ifdef CONFIG_ESP32_NETWORK_PROV_MANAGER
#include "six_iot_network_prov_manager.h"
#endif

#include "six_iam_jwt.h"
#include "six_iot_config.h"
#include "six_iot_device.h"
#include "six_iot_log.h"
#include "six_iot_mqtt.h"
#include "six_iot_nvs.h"
#include "six_iot_sdk.h"
#include "six_iot_shadow.h"
#include "six_iot_util.h"
#include "six_iot_creds.h"

static const char *TAG = "six_iot_sdk";

// define the main task parameters
#define MAIN_TASK_DELAY 1000 / portTICK_PERIOD_MS

// define the sdk event loop parameters
#define SIX_IOT_SDK_EVENT_LOOP_TASK_NAME "SixIotSdkEventLoopTask"
#define SIX_IOT_SDK_EVENT_LOOP_TASK_STACK_SIZE (1024 * 8)
#define SIX_IOT_SDK_EVENT_LOOP_TASK_PRIORITY configMAX_PRIORITIES - 2
#define SIX_IOT_SDK_EVENT_LOOP_QUEUE_SIZE 30
// for the single core chip, only 0 can be used
#define SIX_IOT_SDK_EVENT_LOOP_TASK_CORE_ID 0
static esp_event_loop_handle_t six_iot_sdk_event_loop_handle = NULL;

// ADDITIONS FOR LOG UPLOAD TASK
#define LOG_UPLOAD_TASK_NAME "LogUploadTask"
#define LOG_UPLOAD_TASK_STACK_SIZE (1024 * 6) // Needs large stack for file ops/network
#define LOG_UPLOAD_TASK_PRIORITY configMAX_PRIORITIES - 3 // Lower priority than Event Loop
#define LOG_UPLOAD_QUEUE_LENGTH 10
static TaskHandle_t log_upload_task_handle = NULL;
static QueueHandle_t log_upload_queue = NULL;

static esp_timer_handle_t s_sdk_timer;
static u_int32_t s_sdk_timer_tick = 0;
static const int LOG_TIMER_TICKS = 1;		  // every 1 minute
static const int MQTT_CLIENT_TIMER_TICKS = 1; // every 10 seconds
#define SDK_TIMER_INTERVAL 10000 * 1000
#define MQTT_CLIENT_WATCH_DOG_EVENT_DELAY pdMS_TO_TICKS(100)
#define LOG_UPLOAD_REQ_EVENT_DELAY pdMS_TO_TICKS(100)

// for the sntp sync, only do one sync after the device is connected to internet
static bool sntp_synced = false;

// user_global_uuid need to be obtained from the pair process and be used in "bind device" process.
static char *s_user_global_uuid = NULL;

// hold the id token and access token of the device
static six_iam_tokens_t s_device_tokens;

void six_iot_event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data);

void start_mqtt_client(char *id_token);

void six_iot_mqtt_handler(esp_event_base_t base, int32_t event_id, esp_mqtt_event_handle_t event);

void six_iot_sntp_time_cb(struct timeval *tv);

// void six_iot_set_time_zone();

void six_iot_init_sntp();

void _six_init_sdk_timer();

void _sdk_timer_callback(void *arg);

// Forward declaration for the log upload task
static void log_upload_task(void *pvParameters);

static bool s_sntp_sync_event_triggered = false;

#define NVS_PARTITION_TO_WIPE "nvs"

static six_iot_config_t s_iot_cfg = {
	iam : {device_guid : NULL, token_endpoint : CONFIG_SDK_TOKEN_ENDPOINT},
	mqtt_endpoint : CONFIG_SDK_MQTT_ENDPOINT,
	mqtt_handler : six_iot_mqtt_handler,
	//iot_product_id : CONFIG_SDK_PRODUCT_ID,
	iot_product_id: NULL,
	iot_bind_device_endpoint : CONFIG_SDK_BIND_DEVICE_ENDPOINT,
	iot_log_endpoint : CONFIG_SDK_LOG_ENDPOINT
};

static wifi_ap_config_t s_softap_cfg = {
	ssid : CONFIG_SDK_AP_SSID,
	password : CONFIG_SDK_AP_PASSWORD,
	//.ssid_len = CONFIG_SDK_AP_SSID_LEN,
	.channel = 2,
	.max_connection = 10,
	.authmode = WIFI_AUTH_WPA_WPA2_PSK,
	.pmf_cfg =
		{
			.required = false,
		}
};

// The actual task function
static void log_upload_task(void *pvParameters) {
    ESP_LOGI(TAG, "Log Upload Task started.");
    uint8_t notification_data;

    while (1) {
        // Wait for the timer to signal a LOG_UPLOAD_REQ
        if (xQueueReceive(log_upload_queue, &notification_data, portMAX_DELAY) == pdPASS) {
            // Log upload event received. Execute the blocking operation.
            // This function is now executing in a separate task and will not block
            // the SixIotSdkEventLoopTask.
            six_log_upload();
        }
    }
    // Task should never exit but included for completeness
    vTaskDelete(NULL);
}

void six_iot_init_sntp() {
	if (!sntp_synced) {
		ESP_LOGD(TAG, "init the SNTP");
		sntp_set_time_sync_notification_cb(six_iot_sntp_time_cb);
		esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
		esp_sntp_setservername(0, CONFIG_SDK_SNTP_URL);
		esp_sntp_init();
	}
}

void six_iot_sntp_time_cb(struct timeval *tv) {
	ESP_LOGD(TAG, "six_iot_sntp_time_cb.tv_sec: %lld", tv->tv_sec);
	sntp_synced = true;
	esp_event_post_to(six_iot_sdk_event_loop_handle, SIX_IOT_EVENT, PROVISION_STATUS_SNTP_SYNCED, NULL, 0,
					  100 / portTICK_PERIOD_MS);
}

void six_iot_event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
	if (event_base != SIX_IOT_EVENT) {
		ESP_LOGW(TAG, "six_iot_event_handler will only handle SIX_IOT_EVENT");
		return;
	}

	switch (event_id) {
	/*
	When the device in "STA" mode and when it connect to the public AP
	successfully, it means there is connection, first need to sync the timer
	through SNTP server
	*/
	case PROVISION_STATUS_AS_STA_CONN_TO_AP_SUCCEED:
		ESP_LOGD(TAG, "event: PROVISION_STATUS_AS_STA_CONN_TO_AP_SUCCEED");
		if (!sntp_synced) {
			six_iot_init_sntp();
		} else {
			esp_event_post_to(six_iot_sdk_event_loop_handle, SIX_IOT_EVENT, PROVISION_STATUS_SNTP_SYNCED, NULL, 0,
							  100 / portTICK_PERIOD_MS);
		}
		break;
	/*
	After the timer is synced, to exchange the ID token to connect to the MQTT
	broker
	*/
	case PROVISION_STATUS_SNTP_SYNCED:
		if (s_sntp_sync_event_triggered) {
			ESP_LOGD(TAG, "SNTP sync event already triggered before, skip repeated processing");
			return;
		}
		ESP_LOGD(TAG, "SNTP synchronized, trigger token exchange, free heap size before exchange tokens: %ld",
				 esp_get_free_heap_size());
		s_sntp_sync_event_triggered = true;
#ifdef CONFIG_ESP32_PROV_SOFTAP
		six_iam_exchange_device_tokens(&s_iot_cfg, six_iot_sdk_event_loop_handle);
#endif

#if defined(CONFIG_ESP32_PROV_BLUFI) || defined(CONFIG_ESP32_NETWORK_PROV_MANAGER)  
		six_iam_exchange_device_tokens(&s_iot_cfg, six_iot_sdk_event_loop_handle);
#endif
		break;
	/*
	When the id_token of the device is obtained,
	then connect the device to the MQTT broker right away
	*/
	case PROVISION_STATUS_DEVICE_AUTH_EXG_ID_TOKEN_SUCCEED:
		// free the old id_token first
		if (s_device_tokens.id_token != NULL) {
			free(s_device_tokens.id_token);
		}
		s_device_tokens.id_token = (char *)calloc(strlen((char *)event_data) + 1, sizeof(char));
		strncpy(s_device_tokens.id_token, (char *)event_data, strlen((char *)event_data));
		ESP_LOGD(TAG, "Obtain the id_token successfully, start the MQTT client with id_token: %s\n",
				 s_device_tokens.id_token);
		// connect the device with MQTT Broker using device id_token
		start_mqtt_client(s_device_tokens.id_token);
		// free the id_token after the MQTT client is started
		free(s_device_tokens.id_token);
		s_device_tokens.id_token = NULL;
		break;
	/*
	When the access_token is obtained, will use the access_token to bind the
	device with the user(principal)
	*/
	case PROVISION_STATUS_DEVICE_AUTH_EXG_ACCESS_TOKEN_SUCCEED:
		// release the access token first
		if (s_device_tokens.access_token != NULL) {
			free(s_device_tokens.access_token);
		}
		s_device_tokens.access_token = (char *)calloc(strlen((char *)event_data) + 1, sizeof(char));
		strncpy(s_device_tokens.access_token, (char *)event_data, strlen((char *)event_data));
		ESP_LOGD(TAG, "Obtain the access_token successfully, access_token: %s\n", s_device_tokens.access_token);
		// only if both "s_user_global_uuid" and the "access token" is not NULL,
		// then initiate the bind_device request to bind the device with the
		// principal(e.g. APP user)
		if (s_user_global_uuid != NULL && s_device_tokens.access_token != NULL) {
#ifdef CONFIG_ESP32_PROV_BLUFI
			six_iot_bind_device(&s_iot_cfg, s_user_global_uuid, s_device_tokens.access_token,
								six_iot_sdk_event_loop_handle);
#endif
#ifdef CONFIG_ESP32_PROV_SOFTAP
			six_iot_bind_device(&s_iot_cfg, s_user_global_uuid, s_device_tokens.access_token,
								six_iot_sdk_event_loop_handle);
#endif
			free(s_device_tokens.access_token);
			s_device_tokens.access_token = NULL;
		}
		break;
	/*
	When the device received the BIND_DEVICE request from app, it will also
	trigger the bind device operation
	*/
	case PROVISION_STATUS_BIND_DEVICE_REC_CMD:
		s_user_global_uuid = (char *)calloc(strlen((char *)event_data) + 1, sizeof(char));
		strncpy(s_user_global_uuid, (char *)event_data, strlen((char *)event_data));
		ESP_LOGD(TAG, "Receive principal id and to bind the device with it, principal: %s\n", s_user_global_uuid);
		// only if both "s_user_global_uuid" and the "access token" is not NULL,
		// then initiate the bind_device request to bind the device with the
		// principal(e.g. APP user)
		if (s_user_global_uuid != NULL && s_device_tokens.access_token != NULL) {
#ifdef CONFIG_ESP32_PROV_BLUFI
			six_iot_bind_device(&s_iot_cfg, s_user_global_uuid, s_device_tokens.access_token,
								six_iot_sdk_event_loop_handle);
#endif
#ifdef CONFIG_ESP32_PROV_SOFTAP
			six_iot_bind_device(&s_iot_cfg, s_user_global_uuid, s_device_tokens.access_token,
								six_iot_sdk_event_loop_handle);
#endif
			free(s_device_tokens.access_token);
			s_device_tokens.access_token = NULL;
		}
		break;
	case REFRESH_DEVICE_TOKEN_INTENT:
		six_iot_refresh_device_tokens();
		break;
	case MQTT_DISCONNECTED:
		six_iot_reconnect_mqtt();
		break;
	case MQTT_CLIENT_WATCH_DOG:
		six_iot_watch_client();
		break;
	case MQTT_ERROR:
		six_iot_handle_mqtt_conn_error();
		break;
	case LOG_UPLOAD_REQ:
		//six_log_upload();
		ESP_LOGW(TAG, "Received deprecated LOG_UPLOAD_REQ event. Skipping.");
		break;
	case PROVISION_STATUS_BIND_DEVICE_OK:
		ESP_LOGD(TAG, "Bind device to principal: %s succeed!\n", (char *)event_data);
		break;
	default:
		ESP_LOGD(TAG, "Other event: %d", (int)event_id);
		break;
	}
}

// start the mqtt_client
void start_mqtt_client(char *id_token) {
	// s_id_token = id_token;
	ESP_LOGD(TAG, "start_mqtt_client, id_token is: %s\n", id_token);
	s_iot_cfg.mqtt_clientid = s_iot_cfg.iam.device_guid;
	s_iot_cfg.mqtt_username = six_iot_parse_openid_from_jwt(id_token);
	s_iot_cfg.mqtt_password = id_token;
	six_iot_start_mqtt(&s_iot_cfg, s_iot_cfg.mqtt_endpoint, s_iot_cfg.mqtt_clientid, s_iot_cfg.mqtt_username, id_token,
					   six_iot_sdk_event_loop_handle, six_iot_mqtt_handler);
}

// MQTT handler to handle the interesting event ids
void six_iot_mqtt_handler(esp_event_base_t base, int32_t event_id, esp_mqtt_event_handle_t event) {
	switch ((esp_mqtt_event_id_t)event_id) {
	case MQTT_EVENT_CONNECTED:
		break;
	case MQTT_EVENT_DATA:
		break;
	default:
		break;
	}
	// call the sdk method implemented by specific firmware
	six_iot_handle_mqtt_event(&s_iot_cfg, base, event_id, event);
}

void run_six_iot_sdk_main_task() {
	// set the MQTT clientid and username as the same with device global uuid
	s_iot_cfg.mqtt_clientid = s_iot_cfg.iam.device_guid;
	s_iot_cfg.mqtt_username = "username_unset";
	s_iot_cfg.mqtt_handler = six_iot_mqtt_handler;

	// create an event loop to handle the provision events
	esp_event_loop_args_t loop_args = {.queue_size = SIX_IOT_SDK_EVENT_LOOP_QUEUE_SIZE,
									   .task_name = SIX_IOT_SDK_EVENT_LOOP_TASK_NAME,
									   .task_priority = SIX_IOT_SDK_EVENT_LOOP_TASK_PRIORITY,
									   .task_stack_size = SIX_IOT_SDK_EVENT_LOOP_TASK_STACK_SIZE,
									   .task_core_id = SIX_IOT_SDK_EVENT_LOOP_TASK_CORE_ID};

	// create the event loop with the configurations
	esp_err_t ret = esp_event_loop_create(&loop_args, &six_iot_sdk_event_loop_handle);
	ESP_ERROR_CHECK(ret);

	// register the six_iot_event_handler on the events that published on
	// loop_handle
	ret = esp_event_handler_register_with(six_iot_sdk_event_loop_handle, SIX_IOT_EVENT, ESP_EVENT_ANY_ID,
										  six_iot_event_handler, NULL);
	ESP_ERROR_CHECK(ret);

	// --- ADDITION: Initialize Log Upload Queue and Task ---
    log_upload_queue = xQueueCreate(LOG_UPLOAD_QUEUE_LENGTH, sizeof(uint8_t));
    if (log_upload_queue == NULL) {
        ESP_LOGE(TAG, "Failed to create Log Upload Queue!");
        return;
    }

    if (xTaskCreate(log_upload_task, LOG_UPLOAD_TASK_NAME, LOG_UPLOAD_TASK_STACK_SIZE, 
                    NULL, LOG_UPLOAD_TASK_PRIORITY, &log_upload_task_handle) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create Log Upload Task!");
        return;
    }
    // --- END ADDITION ---	

	_six_init_sdk_timer();

#ifdef CONFIG_ESP32_PROV_SOFTAP
	s_softap_cfg.ssid_len = strlen(CONFIG_SDK_AP_SSID);
	six_iot_start_softap_mode(&s_iot_cfg, &s_softap_cfg, six_iot_sdk_event_loop_handle);
#endif

#ifdef CONFIG_ESP32_PROV_BLUFI
	six_iot_start_blufi_mode(&s_iot_cfg, &s_softap_cfg, six_iot_sdk_event_loop_handle);
#endif

#ifdef CONFIG_ESP32_NETWORK_PROV_MANAGER
	six_iot_start_network_prov_manager_mode(&s_iot_cfg, &s_softap_cfg, six_iot_sdk_event_loop_handle);
#endif
	// Run the event loop. This is a blocking call.
	// The task will now wait here, processing events as they come in.
	ESP_ERROR_CHECK(esp_event_loop_run(six_iot_sdk_event_loop_handle, portMAX_DELAY));

	// The code below will only be reached if the loop stops.
	// Clean up the event loop when the task is done.
	ESP_ERROR_CHECK(esp_event_loop_delete(six_iot_sdk_event_loop_handle));

	// Delete the task itself when done.
	vTaskDelete(NULL);
}

// main entry point
void six_iot_run_sdk(void) {
	//if SDK user select to has a clean start, then 
	#ifdef CONFIG_FACTORY_RESET
		six_iot_factory_reset();
	#endif
	six_nvs_init_storage();
	nvs_flash_init_partition(CREDENTIALS_PARTITION);
	s_iot_cfg.iam.device_guid = get_device_guid();
	s_iot_cfg.iot_product_id = get_device_product_id();
	s_device_tokens.access_token = NULL;
	s_device_tokens.id_token = NULL;
	six_log_init(&s_iot_cfg);
	run_six_iot_sdk_main_task();
}

void _sdk_timer_callback(void *arg) {
	s_sdk_timer_tick++;
	ESP_LOGD(TAG, "sdk timer is ticking: %lu", s_sdk_timer_tick);
	if (s_sdk_timer_tick % LOG_TIMER_TICKS == 0) {
		// esp_event_post_to(six_iot_sdk_event_loop_handle, SIX_IOT_EVENT, LOG_UPLOAD_REQ, NULL, 0,
		// 				 LOG_UPLOAD_REQ_EVENT_DELAY);

		// --- MODIFIED SECTION ---
        // Post to the Log Upload Task's queue instead of the Event Loop
		uint8_t msg = 1;
		UBaseType_t free_slots = uxQueueSpacesAvailable(log_upload_queue);
		if (free_slots > 0) {
			if (xQueueSend(log_upload_queue, &msg, 0) == pdPASS) {
				ESP_LOGD(TAG, "Queued log upload request, free slots after send: %u", (unsigned)(free_slots - 1));
			} else {
				ESP_LOGE(TAG, "Failed to queue log upload despite reported free slots: %u", (unsigned)free_slots);
			}
		} else {
			ESP_LOGW(TAG, "Log Upload queue is full (len=%d). Skipping upload tick.", LOG_UPLOAD_QUEUE_LENGTH);
		}
        // --- END MODIFIED SECTION ---
	}

	if (s_sdk_timer_tick % MQTT_CLIENT_TIMER_TICKS == 0) {
		ESP_LOGD(TAG, "Posting MQTT_CLIENT_WATCH_DOG event (tick %lu)", s_sdk_timer_tick);
		esp_err_t ret = esp_event_post_to(six_iot_sdk_event_loop_handle, SIX_IOT_EVENT, MQTT_CLIENT_WATCH_DOG, NULL, 0,
						  MQTT_CLIENT_WATCH_DOG_EVENT_DELAY);
		if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to post MQTT_CLIENT_WATCH_DOG event: %s", esp_err_to_name(ret));
        } else {
            ESP_LOGD(TAG, "MQTT_CLIENT_WATCH_DOG event posted successfully");
        }
	}
}

void _six_init_sdk_timer() {
	const esp_timer_create_args_t timer_args = {
		.callback = &_sdk_timer_callback, .arg = NULL, .name = "periodic_sdk_timer"};
	esp_timer_create(&timer_args, &s_sdk_timer);
	esp_timer_start_periodic(s_sdk_timer, SDK_TIMER_INTERVAL); // microseconds
}


void six_iot_factory_reset() {
    esp_err_t err;
    
    ESP_LOGW(TAG, "--- STARTING FACTORY RESET PROCEDURE ---");
    // 1. Initialize the target partition if it hasn't been already.
    // This is necessary to ensure the NVS driver can access the partition metadata.
    err = nvs_flash_init_partition(NVS_PARTITION_TO_WIPE);
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // If init fails, we attempt to erase anyway, assuming a configuration issue.
        ESP_LOGW(TAG, "Target partition failed initial integrity check. Proceeding with erase.");
    } else if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize target NVS partition (%s). Aborting reset.", esp_err_to_name(err));
        return;
    }

    // 2. Erase the ENTIRE content of the target NVS partition ('nvs')
    ESP_LOGW(TAG, "Erasing ALL data from partition: %s...", NVS_PARTITION_TO_WIPE);
    err = nvs_flash_erase_partition(NVS_PARTITION_TO_WIPE);
    
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Partition '%s' successfully erased.", NVS_PARTITION_TO_WIPE);
    } else {
        ESP_LOGE(TAG, "Failed to erase partition '%s' (Error: %s).", NVS_PARTITION_TO_WIPE, esp_err_to_name(err));
        // You might still want to reboot even if the erase failed, depending on the error.
    }

    // 3. Optional: Verify that the credentials partition (nvs_fact) is untouched.
    // This step is often skipped in production code but confirms isolation.
    err = nvs_flash_init_partition(CREDENTIALS_PARTITION);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Verified that credentials partition '%s' is intact.", CREDENTIALS_PARTITION);
        nvs_flash_deinit_partition(CREDENTIALS_PARTITION); // De-initialize the partition gracefully
    } else {
        ESP_LOGE(TAG, "Failed to initialize credentials partition '%s' for verification (Error: %s).", CREDENTIALS_PARTITION, esp_err_to_name(err));
    }
    
    // 4. De-initialize the erased partition
    nvs_flash_deinit_partition(NVS_PARTITION_TO_WIPE);
    
    // 5. Reboot the program
    ESP_LOGW(TAG, "NVS cleanup complete. Rebooting system now...");
    vTaskDelay(pdMS_TO_TICKS(100)); // Short delay to allow logs to flush
    //esp_restart();
}