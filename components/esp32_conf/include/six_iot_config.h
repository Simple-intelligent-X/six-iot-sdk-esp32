/*
 * six_iot_config.h
 *
 *  Created on: 2023年7月22日
 *      Author: Stephen Yu
 */

#ifndef __SIX_IAM_IOT_INCLUDE_H__
#define __SIX_IAM_IOT_INCLUDE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <mqtt_client.h>

#define TOPIC_PUBLISH 0
#define TOPIC_SUBSCRIBE 1

#define DEVICE_KEY_JWT_EXPIRE_IN_SECONDS 3600 * 24 * 365

typedef enum {
	PROVISION_STATUS_NOT_START = -1,

	// configure the device to provision in "softap" mode
	PROVISION_STATUS_START_DEVICE_IN_SOFTAP_MODE = 1,
	PROVISION_STATUS_INIT_DEVICE_IN_SOFTAP_SUCCEED,
	PROVISION_STATUS_WEB_SERVER_STARTED,
	PROVISION_STATUS_WEB_SERVER_START_FAIL,
	PROVISION_STATUS_STA_CONN_TO_SOFTAP,
	PROVISION_STATUS_STA_DIS_CONN_FROM_SOFTAP,

	// configure the device to provision in "blufi" mode
	PROVISION_STATUS_START_DEVICE_IN_BLUFI_MODE,
	// configure the device to provision in "smartconfig" mode
	PROVISOIN_STATUS_START_DEVICE_IN_SMART_CONFIG_MODE,

	// status after receive the AP credential and to connect to AP as STA
	PROVISION_STATUS_AP_CREDENTIALS_SUBMIT,
	PROVISION_STATUS_INIT_AS_STA_START,
	PROVISION_STATUS_AS_STA_CONN_TO_AP_START,
	PROVISION_STATUS_AS_STA_DISCONN_FROM_AP_AND_RETRY,
	PROVISION_STATUS_AS_STA_FAIL_CONN_TO_AP,
	PROVISION_STATUS_AS_STA_CONN_TO_AP_SUCCEED,
	PROVISION_STATUS_SNTP_SYNCED,

	// status for authentication
	PROVISION_STATUS_DEVICE_AUTH_OBTAIN_LOCAL_KEY,
	PROVISION_STATUS_DEVICE_AUTH_OBTAIN_LOCAL_KEY_SUCCEED,
	PROVISION_STATUS_DEVICE_AUTH_OBTAIN_LOCAL_KEY_FAIL,
	PROVISION_STATUS_DEVICE_AUTH_PROVISION_DEVICE_BY_IAM,
	PROVISION_STATUS_DEVICE_AUTH_PROVISION_DEVICE_SUCCEED,
	PROVISION_STATUS_DEVICE_AUTH_PROVISION_DEVICE_FAIL,
	PROVISION_STATUS_DEVICE_AUTH_GEN_JWT,
	PROVISION_STATUS_DEVICE_AUTH_EXG_ACCESS_TOKEN_REQ,
	PROVISION_STATUS_DEVICE_AUTH_EXG_ACCESS_TOKEN_REQ_SUCCEED,
	PROVISION_STATUS_DEVICE_AUTH_EXG_ACCESS_TOKEN_REQ_FAIL,
	PROVISION_STATUS_DEVICE_AUTH_EXG_TOKENS_SUCCEED,
	PROVISION_STATUS_DEVICE_AUTH_EXG_ID_TOKEN_SUCCEED,
	PROVISION_STATUS_DEVICE_AUTH_EXG_ACCESS_TOKEN_SUCCEED,

	// status for "bind device"
	PROVISION_STATUS_BIND_DEVICE_REC_CMD,
	PROVISION_STATUS_BIND_DEVICE_START,
	PROVISION_STATUS_BIND_DEVICE_REQ,
	PROVISION_STATUS_BIND_DEVICE_REQ_SUCCEED,
	PROVISION_STATUS_BIND_DEVICE_REQ_CHALLENGE_CMD,
	PROVISION_STATUS_BIND_DEVICE_REQ_FAIL,
	PROVISION_STATUS_BIND_DEVICE_RESULT_FAIL,

	// request to refresh the token
	REFRESH_DEVICE_TOKEN_INTENT,
	MQTT_CONN_ERR,
	MQTT_CLIENT_WATCH_DOG,

	LOG_UPLOAD_REQ,

	PROVISION_STATUS_BIND_DEVICE_OK = 200,
	PROVISION_STATUS_BIND_DEVICE_FAIL = 400
} six_iot_event_t;

typedef struct {
	char *msg;
	void *data;
} six_iot_event_data_t;

ESP_EVENT_DECLARE_BASE(SIX_IOT_EVENT);

#define SIX_IAM_DEVICE_JWT_ASSERTION                                                                                   \
	"grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer:six-device&"                                               \
	"assertion=%s"
#define SIX_IAM_BIND_DEVICE_BODY "deviceGuid=%s&targetPrincipalGuid=%s"
#define SIX_IAM_AUTH_HEADER_NAME "Authorization"
#define SIX_IAM_AUTH_HEADER_VALUE "Bearer %s"
#define SIX_LOG_BODY "deviceGuid=%s&log=%s"

typedef void (*six_iam_token_handler_t)(bool success, char *id_token, char *access_token);

typedef void (*six_iot_bind_device_result_handler_t)(char *result);

typedef void (*six_iot_provision_status_handler_t)(six_iot_event_t status);

typedef void (*six_iot_mqtt_event_handler_t)(esp_event_base_t base, int32_t event_id, esp_mqtt_event_handle_t event);

typedef struct {
	// char *rsa_pem_private_key;
	char *device_guid;
	char *token_endpoint;
} six_iam_config_t;

typedef struct {
	char *id_token;
	char *access_token;
} six_iam_tokens_t;

typedef struct {
	char *topic;
	int type;
} six_iot_topic_t;

typedef struct {
	//
} six_iot_smart_config_t;

typedef struct {
	char *mqtt_endpoint;
	char *mqtt_username;
	char *mqtt_password;
	char *mqtt_clientid;
	six_iam_config_t iam;
	char *iot_product_id;
	char *iot_bind_device_endpoint;
	char *iot_log_endpoint;
	six_iot_mqtt_event_handler_t mqtt_handler;
} six_iot_config_t;

typedef struct {
	char *principal_guid;
	char *bind_device_result;
} six_iot_bind_device_report_data_t;

#ifdef __cplusplus
}
#endif

#endif /* __SIX_IAM_IOT_INCLUDE_H__ */
