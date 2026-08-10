#ifndef __SIX_IOT_SDK_H__
#define __SIX_IOT_SDK_H__

#include "mqtt_client.h"
#include "six_iot_config.h"
#include "six_iot_mqtt.h"

#ifdef __cplusplus
extern "C" {
#endif

void six_iot_run_sdk(void);

/**
 * When an MQTT event is triggered, will call this method to let the specific
 * firmware to handle the MQTT message
 */
void six_iot_handle_mqtt_event(const six_iot_config_t *iot_config, esp_event_base_t base, int32_t event_id,
							   esp_mqtt_event_handle_t event);

void six_iot_factory_reset();

#ifdef __cplusplus
}
#endif

#endif
