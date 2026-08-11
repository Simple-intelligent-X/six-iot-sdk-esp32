/*
 * six_iot_mqtt.h
 *
 *  Created on: 2023年7月23日
 *      Author: Stephen Yu
 */

#ifndef __SIX_IOT_MQTT_H__
#define __SIX_IOT_MQTT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "six_iot_config.h"
#include <cJson.h>

typedef enum { MQTT_STATE_READY, MQTT_STATE_RECONNECTING, MQTT_CREATE_CLIENT_FAIL } mqtt_client_state_t;

/**
 * Start the MQTT client
 *
 */
void six_iot_start_mqtt(six_iot_config_t *iot_config, char *mqtt_endpoint, char *mqtt_clientid, char *mqtt_username,
						char *mqtt_password, esp_event_loop_handle_t loop_handle, six_iot_mqtt_event_handler_t handler);

void six_iot_reconnect_mqtt();

void six_iot_watch_client();

void six_iot_handle_mqtt_conn_error();

bool six_iot_publish_conn_online_msg();

esp_err_t six_iot_publish_log_msg(char *log);

#ifdef __cplusplus
}
#endif

#endif /* __SIX_IOT_MQTT_H__ */
