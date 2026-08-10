#include "six_iot_util.h"
#include "esp_system.h"
#include <esp_heap_caps.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <string.h>

static const char *TAG = "six_iot_util";

char *base64_encode_urlsafe(const unsigned char *input, size_t input_len) {
	// Calculate output size (with padding)
	size_t output_len = 4 * ((input_len + 2) / 3) + 1;
	char *output = malloc(output_len);
	if (!output) {
		ESP_LOGE(TAG, "Memory allocation failed");
		return NULL;
	}

	// Perform Base64 encoding
	size_t written = 0;
	int ret = mbedtls_base64_encode((unsigned char *)output, output_len, &written, input, input_len);

	if (ret != 0) {
		ESP_LOGE(TAG, "Base64 encode failed: -0x%04X", -ret);
		free(output);
		return NULL;
	}

	// Convert to URL-safe Base64 (replace '+' with '-', '/' with '_', remove
	// '=')
	for (size_t i = 0; i < written; i++) {
		if (output[i] == '+')
			output[i] = '-';
		else if (output[i] == '/')
			output[i] = '_';
	}

	// Remove padding if needed (optional for JWT)
	while (written > 0 && output[written - 1] == '=') {
		output[--written] = '\0';
	}

	return output;
}

/**
 * Parse String attribute from JSON
 */
char *six_parse_json_str_attr(cJSON *json, char *attrName) {
	// Validate inputs
	if (json == NULL || attrName == NULL) {
		return NULL;
	}

	// First try direct access
	cJSON *item = cJSON_GetObjectItemCaseSensitive(json, attrName);
	if (item != NULL && cJSON_IsString(item)) {
		return item->valuestring;
	}

	// Search through child objects if not found directly
	for (cJSON *child = json->child; child != NULL; child = child->next) {
		if (cJSON_IsObject(child)) {
			char *result = six_parse_json_str_attr(child, attrName);
			if (result != NULL) {
				return result;
			}
		}
	}

	return NULL;
}

/**
 * Parse Object attribute from the shadow JSON
 */
cJSON *six_parse_json_obj_attr(cJSON *json, char *attrName) {
	if (NULL == json || NULL == attrName) {
		return NULL;
	}

	// First try direct access
	cJSON *item = cJSON_GetObjectItemCaseSensitive(json, attrName);
	if (item != NULL) {
		return item;
	}

	// If not found, search through child objects
	cJSON *child = json->child;
	while (child != NULL) {
		if (cJSON_IsObject(child)) {
			item = cJSON_GetObjectItemCaseSensitive(child, attrName);
			if (item != NULL) {
				return item;
			}
		}
		child = child->next;
	}

	return NULL;
}

void six_check_wifi_quality(const char *tag) {
	// ESP_LOGD(tag, "Available sockets: %ld", esp_random() % 10);
	wifi_ap_record_t ap_info;
	if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
		ESP_LOGD(tag, "WiFi RSSI: %ddBm", ap_info.rssi);
		if (ap_info.rssi < -75) {
			ESP_LOGW(tag, "Weak WiFi signal may cause connection issues");
		}
	}
}

/**
 * Take the heap snapshot
 */
void six_memory_snapshot(const char *tag) {
	size_t free_heap = esp_get_free_heap_size();
	ESP_LOGD(tag, "Free heap: %d bytes, largest block heap size: %u bytes", free_heap,
			 heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));
}

/**
 * Defragment heap to consolidate the heap for some operation e.g. WSS connection.
 *
 */
void six_defregment_heap(const char *tag) {
	ESP_LOGD(TAG, "Performing gentle memory recovery");
	size_t before = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
	// Simple allocation/free pattern to encourage consolidation
	void *blocks[3];
	size_t sizes[] = {1024, 2048, 1024};

	for (int i = 0; i < 3; i++) {
		blocks[i] = heap_caps_malloc(sizes[i], MALLOC_CAP_8BIT);
		if (blocks[i]) {
			memset(blocks[i], 0, sizes[i]);
			vTaskDelay(pdMS_TO_TICKS(10)); // Small delay
		}
	}

	for (int i = 2; i >= 0; i--) {
		if (blocks[i]) {
			heap_caps_free(blocks[i]);
		}
	}
	// Force garbage collection
	heap_caps_free(heap_caps_malloc(1, MALLOC_CAP_8BIT));
	size_t after = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
	ESP_LOGD(tag, "Defrag result: %d -> %d bytes", before, after);
}

// mbedtlsError
char *_six_iam_mbedtls_error(int errnum) {
	static char buffer[200] = {0};
	mbedtls_strerror(errnum, buffer, sizeof(buffer));
	return buffer;
}

char *sign_data_with_rsa_private_key(char *base64_payload, char *private_key) {
	char *base64_signature = NULL;

	mbedtls_pk_context pk_context;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	// Initialize all contexts early
	mbedtls_pk_init(&pk_context);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	size_t length = strlen(private_key);

	char *p_rng = "random";
	// get the RSA private key from PEM string, the RNG function seems will not
	// be called, however the document said it need to pass a non NULL function
	// as parameter. seems pass NULL will not cause issue
	int rc = mbedtls_pk_parse_key(&pk_context, (const unsigned char *)private_key, length + 1, NULL, 0, NULL, p_rng);
	ESP_LOGD(TAG, "parse key result: %d\n", rc);
	if (rc != 0) {
		ESP_LOGE(TAG, "mbedtls_pk_parse_key fail : %d (-0x%x): %s\n", rc, -rc, _six_iam_mbedtls_error(rc));
		goto clean_up;
	}

	const char *pers = "entropy";
	// generate the hash seed
	rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
	if (rc != 0) {
		ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed fail: %d (-0x%x): %s\n", rc, -rc, _six_iam_mbedtls_error(rc));
		goto clean_up;
	}

	uint8_t digest[32];
	rc = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)base64_payload,
					strlen((char *)base64_payload), digest);
	if (rc != 0) {
		ESP_LOGE(TAG, "mbedtls_md fail: %d (-0x%x): %s\n", rc, -rc, _six_iam_mbedtls_error(rc));
		goto clean_up;
	}

	// the signature size will be 256.
	unsigned char sig[256];
	size_t sig_len;
	rc = mbedtls_pk_sign(&pk_context, MBEDTLS_MD_SHA256, digest, sizeof(digest), (unsigned char *)sig, sizeof(sig),
						 &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);
	if (rc != 0) {
		ESP_LOGE(TAG, "mbedtls_pk_sign fail: %d (-0x%x): %s\n", rc, -rc, _six_iam_mbedtls_error(rc));
		goto clean_up;
	}

	ESP_LOGD(TAG, "the signature length is: %d\n", sig_len);
	base64_signature = base64_encode_urlsafe((const unsigned char *)sig, sig_len);
	ESP_LOGD(TAG, "base64 encoded signature length is: %d\n", strlen((const char *)base64_signature));

clean_up:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_pk_free(&pk_context);
	ESP_LOGD(TAG, "release mbedtls_pk context\n");
	return base64_signature;
}

char *six_iot_parse_openid_from_jwt(const char *idtoken) {
	if (!idtoken) {
		ESP_LOGE(TAG, "Input token is NULL.");
		return NULL;
	}

	// 1. Locate the Payload (The string between the first and second dots)
	const char *payload_start = strchr(idtoken, '.');
	if (!payload_start) {
		ESP_LOGE(TAG, "JWT malformed: Missing first dot.");
		return NULL;
	}
	payload_start++; // Move past the first dot

	const char *payload_end = strchr(payload_start, '.');
	if (!payload_end) {
		ESP_LOGE(TAG, "JWT malformed: Missing second dot (Signature part).");
		return NULL;
	}

	size_t payload_len = payload_end - payload_start;
	if (payload_len == 0) {
		ESP_LOGE(TAG, "JWT payload is empty.");
		return NULL;
	}

	// --- NEW: PRE-PROCESS Base64URL PAYLOAD FOR MBEDTLS ---

	// Allocate temp buffer for Base64URL processing (max original length + 3 padding + 1 null)
	size_t temp_buffer_len = payload_len + 4;
	char *temp_payload = (char *)malloc(temp_buffer_len);
	if (!temp_payload) {
		ESP_LOGE(TAG, "Failed to allocate memory for temp payload.");
		return NULL;
	}
	memset(temp_payload, 0, temp_buffer_len);

	// Copy the payload segment
	strncpy(temp_payload, payload_start, payload_len);

	// Convert Base64URL characters to standard Base64
	for (size_t i = 0; i < payload_len; i++) {
		if (temp_payload[i] == '-') {
			temp_payload[i] = '+';
		} else if (temp_payload[i] == '_') {
			temp_payload[i] = '/';
		}
	}

	// Add padding to ensure length is a multiple of 4
	size_t padded_len = payload_len;
	while (padded_len % 4 != 0) {
		temp_payload[padded_len++] = '=';
	}
	temp_payload[padded_len] = '\0'; // Null-terminate the padded string

	// --- END PRE-PROCESSING ---

	// 2. Base64 Decode the Payload (using padded_len and temp_payload)
	size_t decoded_payload_len = 0;
	int ret = mbedtls_base64_decode(NULL, 0, &decoded_payload_len, (const unsigned char *)temp_payload, padded_len);

	// Check size calculation result
	if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL && ret != 0) {
		ESP_LOGE(TAG, "Base64 decode size calculation failed: %d", ret);
		free(temp_payload); // ⬅️ CLEANUP 1 (New)
		return NULL;
	}

	// Allocate buffer for the decoded JSON payload (+1 for null terminator)
	unsigned char *decoded_payload = (unsigned char *)malloc(decoded_payload_len + 1);
	if (!decoded_payload) {
		ESP_LOGE(TAG, "Failed to allocate memory for decoded payload.");
		free(temp_payload); // ⬅️ CLEANUP 1 (New)
		return NULL;
	}

	// Perform the actual decoding
	size_t actual_decoded_len = 0;
	ret = mbedtls_base64_decode(decoded_payload, decoded_payload_len, &actual_decoded_len,
								(const unsigned char *)temp_payload, padded_len);

	// ⬅️ CLEANUP 1: Free the temporary Base64 buffer immediately after use
	free(temp_payload);

	if (ret != 0) {
		ESP_LOGE(TAG, "Base64 decode failed: %d. Check the token source/signature.", ret);
		free(decoded_payload); // ⬅️ CLEANUP 2 (Original)
		return NULL;
	}

	// Ensure null termination for cJSON parsing
	decoded_payload[actual_decoded_len] = '\0';

	// 3. Parse the JSON
	cJSON *root = cJSON_Parse((const char *)decoded_payload);

	// ⬅️ CLEANUP 3: Free the decoded buffer immediately after parsing
	free(decoded_payload);

	if (!root) {
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL) {
			ESP_LOGE(TAG, "cJSON parsing error: before %s", error_ptr);
		}
		return NULL;
	}

	// 4. Extract the 'openId' Claim
	cJSON *openid_json = cJSON_GetObjectItemCaseSensitive(root, "openId");

	// Check if item exists and is a string
	if (!cJSON_IsString(openid_json) || (openid_json->valuestring == NULL)) {
		ESP_LOGE(TAG, "'openId' claim missing or not a string.");
		cJSON_Delete(root); // ⬅️ CLEANUP 4 (Original)
		return NULL;
	}

	// 5. Duplicate the result string for the caller
	char *openid_value = strdup(openid_json->valuestring);

	// ⬅️ CLEANUP 5: Delete the cJSON root structure
	cJSON_Delete(root);

	if (!openid_value) {
		ESP_LOGE(TAG, "Failed to allocate memory for final openId string.");
		return NULL;
	}

	return openid_value;
}

/*
void six_iot_set_time_zone() {
	time_t now;
	// get the current time
	time(&now);

	// set timezone to China Standard Time
	setenv("TZ", "CST-8", 1);
	tzset();

	// set the time to the timeinfo
	struct tm timeinfo;
	localtime_r(&now, &timeinfo);

	char strftime_buf[64];
	strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
	ESP_LOGD(TAG, "The current date/time in Shanghai is: %s", strftime_buf);
}
*/