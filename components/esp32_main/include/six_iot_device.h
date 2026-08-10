/*
 * six_iot_prov_device.h
 *
 *  Created on: 2023年7月22日
 *      Author: Stephen Yu
 */

#ifndef __SIX_IOT_DEVICE_H__
#define __SIX_IOT_DEVICE_H__

#include "esp_event.h"
#include "six_iot_config.h"

#ifdef __cplusplus
extern "C" {
#endif

// void six_iot_bind_device(
// 	six_iot_config_t *iot_config, char *user_global_uuid, char *access_token,
// 	esp_event_loop_handle_t loop_handle);

// exchange the ID token and Access token for the device
void six_iam_exchange_device_tokens(
	six_iot_config_t *iot_config, esp_event_loop_handle_t loop_handle);

// send the event for the intent to refresh the device tokens
void six_iot_intent_refresh_device_tokens();

// send the request to refresh device tokens
void six_iot_refresh_device_tokens();

// send the request to refresh device tokens and call the handler when the operation is finished
void six_iot_refresh_device_tokens_with_handler(six_iam_token_handler_t handler);

/**
 * To facilitate the callback mechanism for the restful requests, encapsulate
 * the user_data buffer and callback handler in one struct.
 * */
typedef struct {
	char *user_data;
	int user_data_buffer_len;
	void *handler;
} six_rest_reqs_user_data_t;

#ifdef __cplusplus
}
#endif

#endif /* __SIX_IOT_DEVICE_H__ */
