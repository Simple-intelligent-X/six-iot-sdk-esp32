/*
 * six_iam_jwt.c
 *
 *  Created on: 2023年7月22日
 *      Author: Stephen Yu
 *
 */

#include <esp_log.h>
#include <inttypes.h>
#include <limits.h>
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "six_iam_jwt.h"
#include "six_iot_config.h"
#include "six_iot_nvs.h"
#include "six_iot_util.h"

static const char *TAG = "six_iam_jwt";

#define TOKEN_EXPIRATION_BUFFER_SECONDS 100

/* Sanity bound on device_guid length so the payload buffer size calc can't
 * be driven to something absurd by corrupted/unexpected input. */
#define DEVICE_GUID_MAX_LEN 128

/* {"exp":<up to 20 digits>,"sub":""}  -- fixed overhead; device_guid length
 * is added on top of this when sizing the payload buffer. */
#define JWT_PAYLOAD_OVERHEAD 48

#define JWT_HEADER_STR "{\"alg\":\"RS256\",\"typ\":\"JWT\"}"

/* Upper bound on the base64url JWT payload segment (header.payload.sig).
 * Our payload is always small ({"exp":...,"sub":"<guid>"}), so this lets
 * six_iam_token_expired use fixed stack buffers instead of heap churn on
 * every call. If DEVICE_GUID_MAX_LEN grows a lot, bump this too. */
#define MAX_JWT_PAYLOAD_B64_LEN 512

static char *_six_iam_create_jwt_content(const char *device_guid, const char *private_key);

static char *_six_iam_create_jwt_content(const char *device_guid, const char *private_key) {
	(void)private_key; /* not used directly in this step, kept for symmetry */

	const char *header = JWT_HEADER_STR;
	ESP_LOGD(TAG, "header is %s", header);

	char *base64_header = base64_encode_urlsafe((const unsigned char *)header, strlen(header));
	if (base64_header == NULL) {
		ESP_LOGE(TAG, "failed to base64-encode jwt header");
		return NULL;
	}
	ESP_LOGD(TAG, "base64_header after base64 encode is: %s", base64_header);

	size_t guid_len = strlen(device_guid);
	if (guid_len > DEVICE_GUID_MAX_LEN) {
		ESP_LOGE(TAG, "device_guid length %zu exceeds max %d", guid_len, DEVICE_GUID_MAX_LEN);
		free(base64_header);
		return NULL;
	}

	// build the payload (exp + sub) on the heap, sized + bounds-checked
	size_t payload_buf_len = guid_len + JWT_PAYLOAD_OVERHEAD;
	char *payload = (char *)malloc(payload_buf_len);
	if (payload == NULL) {
		ESP_LOGE(TAG, "failed to allocate jwt payload buffer");
		free(base64_header);
		return NULL;
	}

	struct timeval now;
	gettimeofday(&now, NULL);
	unsigned long long exp_time_ms = ((unsigned long long)now.tv_sec + DEVICE_KEY_JWT_EXPIRE_IN_SECONDS) * 1000ULL;

	int written = snprintf(payload, payload_buf_len, "{\"exp\":%llu,\"sub\":\"%s\"}", exp_time_ms, device_guid);
	if (written < 0 || (size_t)written >= payload_buf_len) {
		ESP_LOGE(TAG, "jwt payload truncated or encoding error");
		free(base64_header);
		free(payload);
		return NULL;
	}
	ESP_LOGD(TAG, "jwt payload is %s", payload);

	char *base64_payload = base64_encode_urlsafe((const unsigned char *)payload, strlen(payload));
	free(payload);
	if (base64_payload == NULL) {
		ESP_LOGE(TAG, "failed to base64-encode jwt payload");
		free(base64_header);
		return NULL;
	}
	ESP_LOGD(TAG, "base64_payload is %s", base64_payload);

	size_t combined_len = strlen(base64_header) + 1 /* '.' */ + strlen(base64_payload) + 1 /* '\0' */;
	char *header_and_payload = (char *)calloc(combined_len, sizeof(char));
	if (header_and_payload == NULL) {
		ESP_LOGE(TAG, "failed to allocate header.payload buffer");
		free(base64_header);
		free(base64_payload);
		return NULL;
	}
	snprintf(header_and_payload, combined_len, "%s.%s", base64_header, base64_payload);

	free(base64_header);
	free(base64_payload);

	return header_and_payload;
}

char *six_iam_create_jwt(const char *device_guid, const char *private_key) {
	if (NULL == device_guid) {
		ESP_LOGW(TAG, "device_guid is not provided");
		return NULL;
	}
	if (NULL == private_key) {
		ESP_LOGW(TAG, "private_key is not provided");
		return NULL;
	}

	// load jwt from NVS to avoid expensive mbedTLS operation
	char *jwt = six_nvs_read_device_jwt();
	if (NULL != jwt) {
		if (!six_iam_token_expired(jwt, MilliSecond)) {
			ESP_LOGD(TAG, "device JWT exists in nvs and valid, use it");
			return jwt;
		}
		// cached jwt is stale, discard it and fall through to regenerate
		free(jwt);
	}

	char *base64_header_and_payload = _six_iam_create_jwt_content(device_guid, private_key);
	if (base64_header_and_payload == NULL) {
		ESP_LOGW(TAG, "failed to build jwt content");
		return NULL;
	}

	char *base64_signature = sign_data_with_rsa_private_key(base64_header_and_payload, private_key);
	if (base64_signature == NULL) {
		free(base64_header_and_payload);
		ESP_LOGW(TAG, "fail to sign the jwt content");
		return NULL;
	}
	ESP_LOGD(TAG, "base64 encoded signature length is: %zu", strlen(base64_signature));

	size_t jwt_len = strlen(base64_header_and_payload) + 1 /* '.' */ + strlen(base64_signature) + 1 /* '\0' */;
	char *new_jwt = (char *)malloc(jwt_len);
	if (new_jwt == NULL) {
		ESP_LOGE(TAG, "failed to allocate jwt buffer");
		free(base64_header_and_payload);
		free(base64_signature);
		return NULL;
	}
	snprintf(new_jwt, jwt_len, "%s.%s", base64_header_and_payload, base64_signature);

	free(base64_header_and_payload);
	free(base64_signature);

	// save the jwt to the NVS (assumes six_nvs_save_device_jwt copies the
	// data internally rather than taking ownership of this pointer)
	six_nvs_save_device_jwt(new_jwt);

	return new_jwt;
}

bool six_iam_token_expired(const char *token, EXP_UNIT_T unit) {
	if (token == NULL) {
		ESP_LOGE(TAG, "Input token is NULL.");
		return true;
	}

	// Extract JWT payload
	const char *dot1 = strchr(token, '.');
	if (dot1 == NULL) {
		ESP_LOGE(TAG, "First dot not found in token.");
		return true;
	}

	const char *dot2 = strchr(dot1 + 1, '.');
	if (dot2 == NULL) {
		ESP_LOGE(TAG, "Second dot not found in token.");
		return true;
	}

	size_t payload_len = (size_t)(dot2 - dot1 - 1);
	if (payload_len == 0 || payload_len > MAX_JWT_PAYLOAD_B64_LEN) {
		ESP_LOGE(TAG, "Payload length %zu invalid.", payload_len);
		return true;
	}

	// Required padding for standard base64 (round up to multiple of 4)
	size_t padded_len = (payload_len + 3) & ~((size_t)3);

	// Fixed-size stack scratch buffers: payload_len is bounded above by
	// MAX_JWT_PAYLOAD_B64_LEN, so this avoids 3 malloc/free pairs (and the
	// heap fragmentation risk that comes with them) on every single call.
	char base64_standard[MAX_JWT_PAYLOAD_B64_LEN + 4];
	unsigned char decoded[(MAX_JWT_PAYLOAD_B64_LEN + 4) * 3 / 4 + 1];

	// Convert URL-safe base64 straight from the token into standard base64,
	// padded. (No need for an intermediate copy of the raw segment first.)
	for (size_t i = 0; i < payload_len; i++) {
		char c = dot1[1 + i];
		base64_standard[i] = (c == '-') ? '+' : (c == '_') ? '/' : c;
	}
	for (size_t i = payload_len; i < padded_len; i++) {
		base64_standard[i] = '=';
	}
	base64_standard[padded_len] = '\0';

	size_t output_len;
	int ret =
		mbedtls_base64_decode(decoded, sizeof(decoded), &output_len, (unsigned char *)base64_standard, padded_len);
	if (ret != 0) {
		ESP_LOGE(TAG, "Base64 decode failed with return code %d.", ret);
		return true;
	}
	decoded[output_len] = '\0';

	// Parse JSON with cJSON
	cJSON *json = cJSON_Parse((char *)decoded);
	if (json == NULL) {
		ESP_LOGE(TAG, "cJSON parsing failed, is the decoded payload valid JSON?");
		return true;
	}

	// Get expiration time
	cJSON *exp = cJSON_GetObjectItem(json, "exp");
	bool is_expired = true;

	if (cJSON_IsNumber(exp)) {
		time_t expiration = (time_t)exp->valuedouble;
		time_t now = time(NULL);
		long long now_time = (long long)now;
		long long expiration_time = ((long long)expiration) / (unit == MilliSecond ? 1000 : 1);
		ESP_LOGD(TAG, "Current time (raw): %lld", now_time);
		ESP_LOGD(TAG, "Expiration time (raw): %lld", expiration_time);
		ESP_LOGD(TAG, "Time difference: %lld seconds", (expiration_time - now_time));
		is_expired = (now_time >= expiration_time - TOKEN_EXPIRATION_BUFFER_SECONDS);
	}

	cJSON_Delete(json);
	return is_expired;
}