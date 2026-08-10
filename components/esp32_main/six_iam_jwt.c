/*
 * six_iam_jwt.c
 *
 *  Created on: 2023年7月22日
 *      Author: Stephen Yu
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
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "six_iam_jwt.h"
#include "six_iot_config.h"
#include "six_iot_nvs.h"
#include "six_iot_util.h"

static const char *TAG = "six_iam_jwt";

#define TOKEN_EXPIRATION_BUFFER_SECONDS 100

char *_six_iam_create_jwt_content(const char *device_guid, const char *private_key);

/*
int six_iam_f_rng(void *data, unsigned char *output, size_t len) {
	printf("data is %s\n", (char*) data);
	return 1;
}
*/

char *_six_iam_create_jwt_content(const char *device_guid, const char *private_key) {
	// define the header
	char *header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
	ESP_LOGD(TAG, "header is %s\n", header);

	char *base64_header = base64_encode_urlsafe((const unsigned char *)header, strlen(header));
	ESP_LOGD(TAG, "base64_header after base64 encode is: %s\n", base64_header);

	// set the expiration time of the deivce jwt
	char payload[strlen(device_guid) + 50];
	struct timeval now;
	gettimeofday(&now, NULL);
	unsigned long long current_time = now.tv_sec;
	unsigned long long exp_time = current_time + DEVICE_KEY_JWT_EXPIRE_IN_SECONDS;
	sprintf(payload, "{\"exp\":%lld,\"sub\":\"%s\"}", exp_time * 1000, device_guid);
	ESP_LOGD(TAG, "jwt payload is %s\n", payload);

	char *base64_payload = base64_encode_urlsafe((const unsigned char *)payload, strlen((const char *)payload));
	ESP_LOGD(TAG, "base64_payload is %s\n", base64_payload);

	char *header_and_payload =
		(char *)calloc(strlen((char *)base64_header) + 1 + strlen((char *)base64_payload) + 1, sizeof(char));
	sprintf((char *)header_and_payload, "%s.%s", base64_header, base64_payload);

	// free base64_header
	if (base64_header != NULL) {
		free(base64_header);
	}

	// free base64_payload
	if (base64_payload != NULL) {
		free(base64_payload);
	}
	return header_and_payload;
}

char *six_iam_create_jwt(const char *device_guid, const char *private_key) {
	if (NULL == device_guid) {
		ESP_LOGW(TAG, "divce_guid is not provided");
		return NULL;
	}
	if (NULL == private_key) {
		ESP_LOGW(TAG, "private_key is not provided");
		return NULL;
	}

	// load jwt from NVS to void expensive mBedTls operation
	char *jwt = six_nvs_read_device_jwt();
	if (NULL != jwt && !six_iam_token_expired(jwt, MilliSecond)) {
		ESP_LOGD(TAG, "device JWT exists in nvs and valid, use it");
		return jwt;
	}
	// free jwt found in nvs and generate new one
	free(jwt);

	char *base64_payload = _six_iam_create_jwt_content(device_guid, private_key);
	char *base64_signature = sign_data_with_rsa_private_key(base64_payload, private_key);
	if (base64_signature == NULL) {
		free(base64_payload);
		ESP_LOGW(TAG, "fail to sign the jwt content");
		return NULL;
	}

	ESP_LOGD(TAG, "base64 encoded signature length is: %d\n", strlen((const char *)base64_signature));

	// allocate the memory to hold the JWT content
	jwt = (char *)malloc(strlen((char *)base64_payload) + 1 + strlen((char *)base64_signature) + 1);
	sprintf(jwt, "%s.%s", base64_payload, base64_signature);

	free(base64_payload);
	free(base64_signature);

	// save the jwt to the NVS
	six_nvs_save_device_jwt(jwt);

	return jwt;
}

// char *six_iam_create_jwt(const char *device_guid, const char *private_key) {
// 	if (NULL == device_guid) {
// 		ESP_LOGW(TAG, "divce_guid is not provided");
// 		return NULL;
// 	}
// 	if (NULL == private_key) {
// 		ESP_LOGW(TAG, "private_key is not provided");
// 		return NULL;
// 	}

// 	// load jwt from NVS to void expensive mBedTls operation
// 	char *jwt = six_nvs_read_device_jwt();
// 	if (NULL != jwt && !six_iam_token_expired(jwt, MilliSecond)) {
// 		ESP_LOGD(TAG, "device JWT exists in nvs and valid, use it");
// 		return jwt;
// 	}
// 	// free jwt found in nvs and generate new one
// 	free(jwt);
// 	// just for test
// 	// char *jwt = NULL;

// 	// init the mbedtls_pk context
// 	mbedtls_pk_context pk_context;
// 	mbedtls_pk_init(&pk_context);
// 	size_t length = strlen(private_key);

// 	char *p_rng = "random";
// 	// get the RSA private key from PEM string, the RNG function seems will not
// 	// be called, however the document said it need to pass a non NULL function
// 	// as parameter. seems pass NULL will not cause issue
// 	int rc = mbedtls_pk_parse_key(&pk_context, (const unsigned char *)private_key, length + 1, NULL, 0, NULL, p_rng);
// 	ESP_LOGD(TAG, "parse key result: %d\n", rc);
// 	if (rc != 0) {
// 		ESP_LOGE(TAG, "mbedtls_pk_parse_key fail : %d (-0x%x): %s\n", rc, -rc, _six_iam_mbedtls_error(rc));
// 		return NULL;
// 	}

// 	mbedtls_entropy_context entropy;
// 	mbedtls_ctr_drbg_context ctr_drbg;
// 	mbedtls_entropy_init(&entropy);
// 	mbedtls_ctr_drbg_init(&ctr_drbg);

// 	const char *pers = "entropy";
// 	// generate the hash seed
// 	rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
// 	if (rc != 0) {
// 		ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed fail: %d (-0x%x): %s\n", rc, -rc, _six_iam_mbedtls_error(rc));
// 		return NULL;
// 	}

// 	char *base64_payload = _six_iam_create_jwt_content(device_guid, private_key);
// 	uint8_t digest[32];
// 	rc = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)base64_payload,
// 					strlen((char *)base64_payload), digest);
// 	if (rc != 0) {
// 		ESP_LOGE(TAG, "mbedtls_md fail: %d (-0x%x): %s\n", rc, -rc, _six_iam_mbedtls_error(rc));
// 		free(base64_payload);
// 		return NULL;
// 	}

// 	// the signature size will be 256.
// 	unsigned char sig[256];
// 	size_t sig_len;
// 	rc = mbedtls_pk_sign(&pk_context, MBEDTLS_MD_SHA256, digest, sizeof(digest), (unsigned char *)sig, sizeof(sig),
// 						 &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);
// 	if (rc != 0) {
// 		ESP_LOGE(TAG, "mbedtls_pk_sign fail: %d (-0x%x): %s\n", rc, -rc, _six_iam_mbedtls_error(rc));
// 		free(base64_payload);
// 		return NULL;
// 	}

// 	ESP_LOGD(TAG, "the signature length is: %d\n", sig_len);

// 	char *base64_signature = base64_encode_urlsafe((const unsigned char *)sig, sig_len);
// 	ESP_LOGD(TAG, "base64 encoded signature length is: %d\n", strlen((const char *)base64_signature));

// 	// allocate the memory to hold the JWT content
// 	jwt = (char *)malloc(strlen((char *)base64_payload) + 1 + strlen((char *)base64_signature) + 1);
// 	sprintf(jwt, "%s.%s", base64_payload, base64_signature);

// 	free(base64_payload);
// 	free(base64_signature);

// 	mbedtls_pk_free(&pk_context);
// 	ESP_LOGD(TAG, "release mbedtls_pk context\n");

// 	// save the jwt to the NVS
// 	six_nvs_save_device_jwt(jwt);

// 	return jwt;
// }

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

	size_t payload_len = dot2 - dot1 - 1;
	if (payload_len == 0) {
		ESP_LOGE(TAG, "Payload length is zero.");
		return true;
	}

	// Dynamically allocate a buffer for the URL-safe base64 string
	char *base64_urlsafe = (char *)malloc(payload_len + 1);
	if (base64_urlsafe == NULL) {
		ESP_LOGE(TAG, "Failed to allocate memory for URL-safe base64.");
		return true;
	}
	memcpy(base64_urlsafe, dot1 + 1, payload_len);
	base64_urlsafe[payload_len] = '\0';

	// Calculate required padding for standard base64
	size_t padded_len = payload_len;
	while (padded_len % 4 != 0) {
		padded_len++;
	}

	// free dot1 and dot2

	// Allocate buffer for padded and converted base64 string
	char *base64_standard = (char *)malloc(padded_len + 1);
	if (base64_standard == NULL) {
		free(base64_urlsafe);
		ESP_LOGE(TAG, "Failed to allocate memory for standard base64.");
		return true;
	}

	// Convert URL-safe base64 to standard base64 and add padding
	for (size_t i = 0; i < payload_len; i++) {
		char c = base64_urlsafe[i];
		base64_standard[i] = (c == '-') ? '+' : (c == '_') ? '/' : c;
	}
	// Add padding characters
	for (size_t i = payload_len; i < padded_len; i++) {
		base64_standard[i] = '=';
	}
	base64_standard[padded_len] = '\0';
	free(base64_urlsafe);

	// Decode base64
	size_t decoded_size = (padded_len * 3) / 4 + 1;
	unsigned char *decoded = (unsigned char *)malloc(decoded_size);
	if (decoded == NULL) {
		free(base64_standard);
		ESP_LOGE(TAG, "Failed to allocate memory for decoded payload.");
		return true;
	}

	size_t output_len;
	int ret = mbedtls_base64_decode(decoded, decoded_size, &output_len, (unsigned char *)base64_standard, padded_len);

	free(base64_standard);

	if (ret != 0) {
		free(decoded);
		ESP_LOGE(TAG, "Base64 decode failed with return code %d.", ret);
		return true;
	}
	decoded[output_len] = '\0';

	// Parse JSON with cJSON
	cJSON *json = cJSON_Parse((char *)decoded);
	free(decoded);

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