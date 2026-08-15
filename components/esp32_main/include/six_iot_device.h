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

// exchange the ID token and Access token for the device
void six_iam_exchange_device_tokens(six_iot_config_t *iot_config, esp_event_loop_handle_t loop_handle);

// send the request to refresh device tokens and call the handler when the operation is finished
void six_iot_refresh_device_tokens_with_handler(six_iam_token_handler_t handler);

#ifdef __cplusplus
}
#endif

#endif /* __SIX_IOT_DEVICE_H__ */
