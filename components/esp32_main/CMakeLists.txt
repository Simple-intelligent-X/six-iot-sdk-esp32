# Define the component to interact with the IAM backend and to connect to with the MQTT Broker
set(COMPONENT_REQUIRES esp32_cred esp32_conf esp32_prov_npm esp32_util esp32_ota esp32_log esp_event esp_wifi esp_http_client json nvs_flash mbedtls mqtt)
set(COMPONENT_PRIV_REQUIRES) 


# Register the Component (COMPONENT_TARGET is defined here)
idf_component_register(SRCS "six_iot_sdk.c" "six_iot_shadow.c" "six_iot_init.c" "six_iam_jwt.c" "six_iot_device.c" "six_iot_mqtt.c"
                       INCLUDE_DIRS "include"
                       REQUIRES ${COMPONENT_REQUIRES}
                       #EMBED_TXTFILES ${project_dir}/device_certs/device_cert.pem
                       )

# Add binary data (These must also come after idf_component_register)
if(CONFIG_DEFAULT_ROOT_CA)
    target_add_binary_data(${COMPONENT_TARGET} "${project_dir}/ca_certs/six_ca.pem" TEXT)
endif()

if(CONFIG_AWS_ROOT_CA)
    target_add_binary_data(${COMPONENT_TARGET} "${project_dir}/ca_certs/aws_root_ca.pem" TEXT)
endif()