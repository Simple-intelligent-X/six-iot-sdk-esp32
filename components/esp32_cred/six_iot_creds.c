#include "six_iot_creds.h"
#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <cJson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "six_iot_creds";

const char *CREDENTIALS_PARTITION = "nvs_fact";

#define JSON_KEY_NAME "network_prov"

char *get_device_private_key() {
	esp_err_t err;
	nvs_handle_t my_handle;
	char *key_buf = NULL;

	// Open the "creds" namespace
	err = nvs_open_from_partition(CREDENTIALS_PARTITION, "creds", NVS_READONLY, &my_handle);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Error (%s) opening NVS handle for 'creds'", esp_err_to_name(err));
		return NULL;
	}

	size_t key_len = 0;

	// 1. Get required size
	err = nvs_get_str(my_handle, "device_key", NULL, &key_len);

	if (err == ESP_OK) {
		// 2. Allocate memory on the heap
		key_buf = (char *)malloc(key_len);
		if (key_buf) {
			// 3. Retrieve the string
			nvs_get_str(my_handle, "device_key", key_buf, &key_len);
			ESP_LOGI(TAG, "Private Key loaded (Size: %d bytes)", (int)key_len);
		} else {
			ESP_LOGE(TAG, "Failed to allocate memory for Private Key.");
		}
	} else {
		ESP_LOGE(TAG, "Failed to read device_key (Error: %s)", esp_err_to_name(err));
	}

	nvs_close(my_handle);
	return key_buf; // Returns NULL on failure, or a pointer to the key on success
}

char *get_device_guid() { return get_network_prov_field("deviceGuid"); }

char *get_device_product_id() { return get_network_prov_field("productId"); }

char *get_network_prov_field(const char *field_name) {
	esp_err_t err;
	nvs_handle_t my_handle;
	char *json_str = NULL;
	char *field_value = NULL;

	// 1. Open the "creds" namespace
	err = nvs_open_from_partition(CREDENTIALS_PARTITION, "creds", NVS_READONLY, &my_handle);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Error (%s) opening NVS handle for 'creds'", esp_err_to_name(err));
		return NULL;
	}

	size_t required_size = 0;
	cJSON *root = NULL;

	// --- STEP 1: Read the entire JSON string from NVS ---

	// 1a. Get required size for the JSON string
	err = nvs_get_str(my_handle, JSON_KEY_NAME, NULL, &required_size);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "Failed to read JSON key '%s' (Error: %s)", JSON_KEY_NAME, esp_err_to_name(err));
		goto cleanup;
	}

	// 1b. Allocate memory and retrieve the JSON string
	json_str = (char *)malloc(required_size);
	if (!json_str) {
		ESP_LOGE(TAG, "Failed to allocate memory for JSON string.");
		goto cleanup;
	}
	nvs_get_str(my_handle, JSON_KEY_NAME, json_str, &required_size);

	// --- STEP 2: Parse the JSON string ---

	root = cJSON_Parse(json_str);
	if (root == NULL) {
		ESP_LOGE(TAG, "Failed to parse JSON string from NVS.");
		goto cleanup;
	}

	// --- STEP 3: Extract the specific field ---

	cJSON *field = cJSON_GetObjectItemCaseSensitive(root, field_name);

	if (cJSON_IsString(field) && (field->valuestring != NULL)) {
		size_t value_len = strlen(field->valuestring) + 1;
		field_value = (char *)malloc(value_len);
		if (field_value) {
			strncpy(field_value, field->valuestring, value_len);
			ESP_LOGI(TAG, "Field '%s' loaded: %s", field_name, field_value);
		} else {
			ESP_LOGE(TAG, "Failed to allocate memory for field value.");
		}
	} else {
		ESP_LOGE(TAG, "Field '%s' not found or is not a string.", field_name);
	}

	// --- STEP 4: Cleanup and Return ---
cleanup:
	if (json_str) {
		free(json_str);
	}
	if (root) {
		cJSON_Delete(root);
	}
	nvs_close(my_handle);

	// field_value is either NULL or a heap-allocated string to be freed by the caller
	return field_value;
}