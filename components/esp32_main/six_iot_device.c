/*
 * six_iot_device.c
 *
 *  Created on: 2023年7月22日
 *      Author: Stephen Yu
 */
#include <ctype.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <esp_tls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
#include <esp_crt_bundle.h>
#endif
#include <cJson.h>
#include <esp_heap_caps.h>
#include <esp_http_client.h>
#include <esp_wifi.h>
#include <freertos/semphr.h>

#include "six_iam_jwt.h"
#include "six_iot_config.h"
#include "six_iot_device.h"
#include "six_iot_nvs.h"
#include "six_iot_util.h"
#include "six_iot_creds.h"

static const char *TAG = "six_iot_device";

#ifdef CONFIG_AWS_ROOT_CA
extern const uint8_t aws_root_ca_pem_start[] asm("_binary_aws_root_ca_pem_start");
extern const uint8_t aws_root_ca_pem_end[] asm("_binary_aws_root_ca_pem_end");
#endif

#ifdef CONFIG_DEFAULT_ROOT_CA
extern const uint8_t six_ca_pem_start[] asm("_binary_six_ca_pem_start");
extern const uint8_t six_ca_pem_end[] asm("_binary_six_ca_pem_end");
#endif

#define SIX_IOT_SDK_EVENT_TICK pdMS_TO_TICKS(100)

#define MAX_HTTP_REC_BUFFER 512

static six_iam_token_handler_t s_refresh_token_handler = NULL;

// Static config parameters
static esp_event_loop_handle_t s_six_iot_loop = NULL;
static six_iot_config_t *s_iot_cfg = NULL;
static char *s_user_global_uuid = NULL;

/**Inner methods definition start**/

char *_six_iot_obtain_key_from_local();

void _six_iam_exchange_device_tokens_with_local_key(char *private_key);

void _six_iam_refresh_device_tokens_with_local_key(char *private_key);

void _six_iot_provision_device_by_iam();

bool _six_is_tokens_valide_in_nvs(bool post_event);

void _six_iam_exchange_tokens(const char *token_endpoint, char *jwt, six_iam_token_handler_t token_handler_t);

/**Inner methods definition end**/

static void s_report_provision_status(six_iot_event_t status, char *msg, void *args) {
	ESP_LOGD(TAG, "s_report_provision_status.msg: %s", msg);
	if (s_six_iot_loop) {
		if (status == PROVISION_STATUS_BIND_DEVICE_OK) {
			six_iot_bind_device_report_data_t *report_data = args;
			char *data = report_data->principal_guid;
			int size = sizeof(char) * (strlen(data) + 1);
			ESP_LOGD(TAG, "PROVISION_STATUS_BIND_DEVICE_OK.data.size: %d", size);
			esp_event_post_to(s_six_iot_loop, SIX_IOT_EVENT, status, data, size, SIX_IOT_SDK_EVENT_TICK);
		} else if (status == PROVISION_STATUS_DEVICE_AUTH_EXG_TOKENS_SUCCEED) {
			six_iam_tokens_t *tokens = args;
			// report the id token
			char *data = tokens->id_token;
			int size = sizeof(char) * (strlen(data) + 1);
			ESP_LOGD(TAG, "PROVISION_STATUS_DEVICE_AUTH_EXG_TOKENS_SUCCEED.id_token.data.size: %d", size);
			esp_event_post_to(s_six_iot_loop, SIX_IOT_EVENT, PROVISION_STATUS_DEVICE_AUTH_EXG_ID_TOKEN_SUCCEED, data,
							  size, SIX_IOT_SDK_EVENT_TICK);

			// report the access token
			data = tokens->access_token;
			size = sizeof(char) * (strlen(data) + 1);
			ESP_LOGD(TAG, "PROVISION_STATUS_DEVICE_AUTH_EXG_TOKENS_SUCCEED.access_token.data.size: %d", size);
			esp_event_post_to(s_six_iot_loop, SIX_IOT_EVENT, PROVISION_STATUS_DEVICE_AUTH_EXG_ACCESS_TOKEN_SUCCEED,
							  data, size, SIX_IOT_SDK_EVENT_TICK);
		} else {
			ESP_LOGD(TAG, "s_report_provision_status.data.sizeof: %d", sizeof(*args));
			esp_event_post_to(s_six_iot_loop, SIX_IOT_EVENT, status, args, sizeof(*args), SIX_IOT_SDK_EVENT_TICK);
		}
	}
}

static void s_six_iam_token_handler(bool success, char *id_token, char *access_token) {
	if (success) {
		six_iam_tokens_t tokens;
		tokens.id_token = id_token;
		tokens.access_token = access_token;
		six_nvs_save_id_token(id_token);
		six_nvs_save_access_token(access_token);
		s_report_provision_status(PROVISION_STATUS_DEVICE_AUTH_EXG_TOKENS_SUCCEED,
								  "ID and Access Token for device is obtained successfully!", &tokens);
	}
}

static void s_six_iam_token_refresh_handler(bool success, char *id_token, char *access_token) {
	if (id_token != NULL) {
		six_nvs_save_id_token(id_token);
	}
	if (access_token != NULL) {
		six_nvs_save_access_token(access_token);
	}
	if (s_refresh_token_handler != NULL) {
		(*s_refresh_token_handler)(success, id_token, access_token);
	}
}

// parse the id token from JSON
static char *s_parse_id_token(cJSON *json) { return six_parse_json_str_attr(json, "id_token"); }

static char *s_parse_access_token(cJSON *json) { return six_parse_json_str_attr(json, "access_token"); }

esp_err_t _http_rest_for_tokens_event_handler(esp_http_client_event_t *evt) {
	static char *output_buffer = NULL; // Buffer to store response of http request from event handler
	static int output_len = 0;
	switch (evt->event_id) {
	case HTTP_EVENT_ERROR:
		ESP_LOGW(TAG, "HTTP_EVENT_ERROR");
		if (output_buffer != NULL) {
			free(output_buffer);
			output_buffer = NULL;
		}
		output_len = 0;
		break;
	case HTTP_EVENT_ON_CONNECTED:
		ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
		break;
	case HTTP_EVENT_HEADER_SENT:
		ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
		break;
	case HTTP_EVENT_ON_HEADER:
		ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
		break;
	case HTTP_EVENT_ON_DATA:
		ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len:%d", evt->data_len);
		s_report_provision_status(PROVISION_STATUS_DEVICE_AUTH_EXG_ACCESS_TOKEN_REQ_SUCCEED,
								  "The request to get the access token respond successfully!", NULL);
		/*
		 *  Check for chunked encoding is added as the URL for chunked encoding
		 * used in this example returns binary data. However, event handler can
		 * also be used in case chunked encoding is used.
		 */
		if (!esp_http_client_is_chunked_response(evt->client)) {
			// If user_data buffer is configured, copy the response into the
			// buffer
			if (evt->user_data) {
				char *user_data = (char *)(((six_rest_reqs_user_data_t *)evt->user_data)->user_data);
				int user_data_buffer_len = ((six_rest_reqs_user_data_t *)evt->user_data)->user_data_buffer_len;
				// if the buffer is too small
				while ((user_data_buffer_len - output_len) <= evt->data_len) {
					ESP_LOGD(TAG, "size of user_data is %d, output_len is %d, data_len is %d\n", user_data_buffer_len,
							 output_len, evt->data_len);
					int new_buffer_len = user_data_buffer_len + MAX_HTTP_REC_BUFFER;
					char *new_buffer = (char *)calloc(new_buffer_len + 1, sizeof(char));
					memcpy(new_buffer, user_data, output_len);
					if (user_data) {
						free(user_data);
					}
					user_data = ((six_rest_reqs_user_data_t *)evt->user_data)->user_data = new_buffer;
					user_data_buffer_len = ((six_rest_reqs_user_data_t *)evt->user_data)->user_data_buffer_len =
						new_buffer_len;
				}
				memcpy(user_data + output_len, evt->data, evt->data_len);
			} else {
				if (output_buffer == NULL) {
					output_buffer = (char *)calloc(esp_http_client_get_content_length(evt->client), sizeof(char));
					output_len = 0;
					if (output_buffer == NULL) {
						ESP_LOGE(TAG, "Failed to allocate memory for output buffer");
						return ESP_FAIL;
					}
				}
				ESP_LOGD(TAG, "use output_buffer");
				memcpy(output_buffer + output_len, evt->data, evt->data_len);
			}
			output_len += evt->data_len;
		}
		break;
	case HTTP_EVENT_ON_FINISH:
		char *user_data = (char *)(((six_rest_reqs_user_data_t *)evt->user_data)->user_data);
		ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH, finish response is:%s\n", user_data);

		// parse the access token and invoke the callback handler to transmit the access token to the handler
		cJSON *resp_json = cJSON_Parse(user_data);
		char *id_token = NULL;
		char *id_token_in_json = s_parse_id_token(resp_json);
		if (id_token_in_json != NULL) {
			id_token = strdup(id_token_in_json);
		}
		char *access_token = NULL;
		char *access_token_in_json = s_parse_access_token(resp_json);
		if (access_token_in_json != NULL) {
			access_token = strdup(access_token_in_json);
		}
		cJSON_Delete(resp_json);

		six_iam_token_handler_t id_token_handler =
			(six_iam_token_handler_t)(((six_rest_reqs_user_data_t *)evt->user_data)->handler);
		if (id_token != NULL) {
			(*id_token_handler)(true, id_token, access_token);
		} else {
			(*id_token_handler)(false, id_token, access_token);
		}

		if (id_token != NULL) {
			free(id_token);
			id_token = NULL;
		}

		if (access_token != NULL) {
			free(access_token);
			access_token = NULL;
		}

		if (output_buffer != NULL) {
			free(output_buffer);
			output_buffer = NULL;
		}
		output_len = 0;
		break;
	case HTTP_EVENT_DISCONNECTED:
		ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
		if (output_buffer != NULL) {
			free(output_buffer);
			output_buffer = NULL;
		}
		output_len = 0;
		break;
	case HTTP_EVENT_REDIRECT:
		ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
		// esp_http_client_set_header(evt->client, "From", "user@example.com");
		esp_http_client_set_header(evt->client, "Accept", "text/html");
		esp_http_client_set_redirection(evt->client);
		break;
	}
	return ESP_OK;
}

static void s_http_rest_for_tokens(const char *token_endpoint, char *jwt, six_iam_token_handler_t id_token_handler) {
	six_memory_snapshot(TAG);
	six_check_wifi_quality(TAG);
	ESP_LOGD(TAG, "Available sockets: %ld", esp_random() % 10);
	six_defregment_heap(TAG);

	char *local_response_buffer = (char *)calloc(MAX_HTTP_REC_BUFFER, sizeof(char));

	ESP_LOGD(TAG, "Largest block heap size before initialize restful request context: %u",
			 heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));
	/**
	 * NOTE: All the configuration parameters for http_client must be specified
	 * either in URL or as host and path parameters. If host and path parameters
	 * are not set, query parameter will be ignored. In such cases, query
	 * parameter should be specified in URL.
	 *
	 * If URL as well as host and path parameters are specified, values of host
	 * and path will be considered.
	 */
	six_rest_reqs_user_data_t user_data = {
		user_data : local_response_buffer,
		user_data_buffer_len : MAX_HTTP_REC_BUFFER,
		handler : id_token_handler
	};

	esp_http_client_config_t config = {
		.url = token_endpoint,
		.event_handler = _http_rest_for_tokens_event_handler,
#ifdef CONFIG_SDK_TOKEN_REQ_DEFAULT_CA
		.cert_pem = (const char *)six_ca_pem_start,
#endif
#ifdef CONFIG_SDK_TOKEN_REQ_AWS_CA
		.cert_pem = (const char *)aws_root_ca_pem_start,
#endif
		.user_data = &user_data, // Pass address of local buffer to get response
		//.is_async = true,
		.tls_version = ESP_HTTP_CLIENT_TLS_VER_TLS_1_2,
		.timeout_ms = 30000,
	};

	esp_http_client_handle_t client = esp_http_client_init(&config);

	int post_data_buffer_len = strlen(jwt) + strlen(SIX_IAM_DEVICE_JWT_ASSERTION) + 1;
	// char post_data[post_data_buffer_len];
	char *post_data = (char *)calloc(post_data_buffer_len, sizeof(char));
	// memset(post_data, 0, post_data_buffer_len * sizeof(char));
	ESP_LOGD(TAG, "post_data.length before populate: %d\n", strlen(post_data));
	sprintf(post_data, SIX_IAM_DEVICE_JWT_ASSERTION, jwt);
	ESP_LOGD(TAG, "post_data.length after populate: %d\n", strlen(post_data));

	ESP_LOGD(TAG, "Reuqest url is:%s\n", token_endpoint);
	//ESP_LOGD(TAG, "post_data:%s\n", post_data);
	ESP_LOGD(TAG, "Free heap size before send request: %ld", esp_get_free_heap_size());

	esp_http_client_set_method(client, HTTP_METHOD_POST);
	esp_http_client_set_header(client, "Content-Type", "application/x-www-form-urlencoded");
	// esp_http_client_set_header(client, "Content-Type", "application/json");
	esp_http_client_set_post_field(client, post_data, strlen(post_data));
	esp_err_t err = esp_http_client_perform(client);
	free(post_data);
	if (user_data.user_data != NULL) {
		free(user_data.user_data);
		user_data.user_data = NULL;
	}

	if (err == ESP_OK) {
		ESP_LOGD(TAG, "HTTP POST Status = %d, content_length = %lld", esp_http_client_get_status_code(client),
				 esp_http_client_get_content_length(client));
	} else {
		ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
		s_report_provision_status(PROVISION_STATUS_DEVICE_AUTH_EXG_ACCESS_TOKEN_REQ_FAIL,
								  "The request to get the access token fail!", NULL);
		if (id_token_handler) {
			(*id_token_handler)(false, NULL, NULL);
		}
	}

	err = esp_http_client_cleanup(client);
	client = NULL;
	if (err == ESP_OK) {
		ESP_LOGD(TAG, "Clean http client succeed!");
	} else {
		ESP_LOGE(TAG, "Clean http client fail: %s", esp_err_to_name(err));
	}
}

void _six_iam_exchange_tokens(const char *token_endpoint, char *jwt, six_iam_token_handler_t token_handler_t) {
	s_report_provision_status(PROVISION_STATUS_DEVICE_AUTH_EXG_ACCESS_TOKEN_REQ, "To exchange the tokens with JWT!",
							  NULL);
	s_http_rest_for_tokens(token_endpoint, jwt, token_handler_t);
}

esp_err_t _http_rest_for_bind_device_handler(esp_http_client_event_t *evt) {
	static char *output_buffer;
	static int output_len;
	switch (evt->event_id) {
	case HTTP_EVENT_ERROR:
		ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
		break;
	case HTTP_EVENT_ON_CONNECTED:
		ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
		break;
	case HTTP_EVENT_HEADER_SENT:
		ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
		break;
	case HTTP_EVENT_ON_HEADER:
		ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
		break;
	case HTTP_EVENT_ON_DATA:
		ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len:%d", evt->data_len);
		s_report_provision_status(PROVISION_STATUS_BIND_DEVICE_REQ_SUCCEED,
								  "the request to bind device respond successfully!", NULL);
		/*
		 *  Check for chunked encoding is added as the URL for chunked encoding
		 * used in this example returns binary data. However, event handler can
		 * also be used in case chunked encoding is used.
		 */
		if (evt->user_data) {
			char *user_data = (char *)(((six_rest_reqs_user_data_t *)evt->user_data)->user_data);
			int user_data_buffer_len = ((six_rest_reqs_user_data_t *)evt->user_data)->user_data_buffer_len;
			// if the buffer is too small
			while ((user_data_buffer_len - output_len) <= evt->data_len) {
				ESP_LOGD(TAG, "size of user_data is %d, output_len is %d, data_len is %d\n", user_data_buffer_len,
						 output_len, evt->data_len);
				int new_buffer_len = user_data_buffer_len + MAX_HTTP_REC_BUFFER;
				char *new_buffer = (char *)calloc(new_buffer_len + 1, sizeof(char));
				memcpy(new_buffer, user_data, output_len);
				if (user_data) {
					free(user_data);
				}
				user_data = ((six_rest_reqs_user_data_t *)evt->user_data)->user_data = new_buffer;
				user_data_buffer_len = ((six_rest_reqs_user_data_t *)evt->user_data)->user_data_buffer_len =
					new_buffer_len;
			}
			memcpy(user_data + output_len, evt->data, evt->data_len);
			// printf("user_data is %s\n", user_data);
		} else {
			if (output_buffer == NULL) {
				output_buffer = (char *)malloc(esp_http_client_get_content_length(evt->client));
				output_len = 0;
				if (output_buffer == NULL) {
					ESP_LOGE(TAG, "Failed to allocate memory for output buffer");
					return ESP_FAIL;
				}
			}
			memcpy(output_buffer + output_len, evt->data, evt->data_len);
		}
		output_len += evt->data_len;
		break;
	case HTTP_EVENT_ON_FINISH:
		char *user_data = (char *)(((six_rest_reqs_user_data_t *)evt->user_data)->user_data);
		ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH, user_data len: %d, bind_device_output_len: %d\n", strlen(user_data),
				 output_len);
		// cJSON * resJson = cJSON_Parse(user_data);
		// printf("parsed bind device result is:%s\n", bind_device_result);
		char *bind_device_result = calloc(output_len + 1, sizeof(char));
		memcpy(bind_device_result, user_data, output_len);

		if (output_buffer != NULL) {
			free(output_buffer);
			output_buffer = NULL;
		}
		output_len = 0;

		if (NULL != bind_device_result) {
			six_iot_bind_device_report_data_t report_data;
			report_data.principal_guid = s_user_global_uuid;
			report_data.bind_device_result = bind_device_result;
			s_report_provision_status(PROVISION_STATUS_BIND_DEVICE_OK, "bind device succeed!", &report_data);
			free(bind_device_result);
		} else {
			s_report_provision_status(PROVISION_STATUS_BIND_DEVICE_RESULT_FAIL, "bind device parse server result fail!",
									  NULL);
		}
		break;
	case HTTP_EVENT_DISCONNECTED:
		ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
		if (output_buffer != NULL) {
			free(output_buffer);
			output_buffer = NULL;
		}
		output_len = 0;
		break;
	case HTTP_EVENT_REDIRECT:
		ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
		// esp_http_client_set_header(evt->client, "From", "user@example.com");
		esp_http_client_set_header(evt->client, "Accept", "text/html");
		esp_http_client_set_redirection(evt->client);
		break;
	}
	return ESP_OK;
}

static void s_http_rest_for_bind_device(const char *bind_device_endpoint, char *access_token) {
	// char local_response_buffer[MAX_HTTP_REC_BUFFER] = {0};
	char *local_response_buffer = (char *)malloc(sizeof(char) * MAX_HTTP_REC_BUFFER);
	/**
	 * NOTE: All the configuration parameters for http_client must be specified
	 * either in URL or as host and path parameters. If host and path parameters
	 * are not set, query parameter will be ignored. In such cases, query
	 * parameter should be specified in URL.
	 *
	 * If URL as well as host and path parameters are specified, values of host
	 * and path will be considered.
	 */
	six_rest_reqs_user_data_t user_data = {
		user_data : local_response_buffer,
		user_data_buffer_len : MAX_HTTP_REC_BUFFER,
		// handler: id_token_handler
	};

	esp_http_client_config_t config = {//.url = bind_device_endpoint,
									   .event_handler = _http_rest_for_bind_device_handler,
									   .user_data = &user_data, // Pass address of local buffer to get response
									   .disable_auto_redirect = true,
									   .timeout_ms = 30000,
									   .buffer_size_tx = strlen(access_token) + 300,
#ifdef CONFIG_SDK_BIND_DEVICE_REQ_DEFAULT_CA
									   .cert_pem = (const char *)six_ca_pem_start,
#endif
#ifdef CONFIG_SDK_BIND_DEVICE_REQ_AWS_CA
									   .cert_pem = (const char *)aws_root_ca_pem_start,
#endif
									   .max_authorization_retries = 5,
									   .tls_version = ESP_HTTP_CLIENT_TLS_VER_TLS_1_2,
									   .transport_type = HTTP_TRANSPORT_OVER_SSL};

	int endpoint_len = strlen(s_iot_cfg->iot_bind_device_endpoint) + strlen(s_iot_cfg->iot_product_id) + 1;
	char endpoint[endpoint_len];
	memset(endpoint, 0, endpoint_len * sizeof(endpoint[0]));
	sprintf(endpoint, s_iot_cfg->iot_bind_device_endpoint, s_iot_cfg->iot_product_id);
	config.url = endpoint;
	ESP_LOGD(TAG, "the url is:%s\n", endpoint);

	esp_http_client_handle_t client = esp_http_client_init(&config);

	int post_data_len =
		strlen(SIX_IAM_BIND_DEVICE_BODY) + strlen(s_iot_cfg->iam.device_guid) + strlen(s_user_global_uuid) + 1;
	char post_data[post_data_len];
	memset(post_data, 0, post_data_len * sizeof(post_data[0]));
	sprintf(post_data, SIX_IAM_BIND_DEVICE_BODY, s_iot_cfg->iam.device_guid, s_user_global_uuid);
	ESP_LOGD(TAG, "the post data is %s\n", post_data);

	// char auth_header_data[strlen(access_token) +
	// strlen(SIX_IAM_AUTH_HEADER_VALUE)];
	char *auth_header_data = calloc(strlen(access_token) + strlen(SIX_IAM_AUTH_HEADER_VALUE) + 1, sizeof(char));
	sprintf(auth_header_data, SIX_IAM_AUTH_HEADER_VALUE, access_token);
	ESP_LOGD(TAG, "the header data is %s, len is %d\n", auth_header_data, strlen(auth_header_data));

	esp_http_client_set_method(client, HTTP_METHOD_POST);
	// esp_http_client_set_header(client, "Content-Type", "application/json");
	esp_http_client_set_post_field(client, post_data, strlen(post_data));
	// set the Authorization header
	esp_http_client_set_header(client, SIX_IAM_AUTH_HEADER_NAME, auth_header_data);

	esp_err_t err = esp_http_client_perform(client);
	if (err == ESP_OK) {
		ESP_LOGD(TAG, "HTTP POST Status = %d, content_length = %lld", esp_http_client_get_status_code(client),
				 esp_http_client_get_content_length(client));
		// s_report_provision_status(PROVISION_STATUS_DEVICE_AUTH_BIND_DEVICE_REQ_SUCCEED,
		// "the request to bind device respond successfully!", NULL);
	} else {
		ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
		s_report_provision_status(PROVISION_STATUS_BIND_DEVICE_REQ_FAIL, "the request to bind device fail!", NULL);
	}
	if (user_data.user_data != NULL) {
		free(user_data.user_data);
		user_data.user_data = NULL;
	}
	if (auth_header_data != NULL) {
		free(auth_header_data);
	}
	esp_http_client_cleanup(client);
	client = NULL;
}

void _six_iam_exchange_device_tokens_with_local_key(char *private_key) {
	s_report_provision_status(PROVISION_STATUS_DEVICE_AUTH_GEN_JWT, "generate JWT through private key!", NULL);
	char *jwt = six_iam_create_jwt(s_iot_cfg->iam.device_guid, private_key);
	// free(private_key);
	_six_iam_exchange_tokens(s_iot_cfg->iam.token_endpoint, jwt, s_six_iam_token_handler);
	// release the jwt which was allocated in heap
	if (NULL != jwt) {
		free(jwt);
		jwt = NULL;
	}
}

void _six_iam_refresh_device_tokens_with_local_key(char *private_key) {
	char *jwt = six_iam_create_jwt(s_iot_cfg->iam.device_guid, private_key);
	// free(private_key);
	_six_iam_exchange_tokens(s_iot_cfg->iam.token_endpoint, jwt, s_six_iam_token_refresh_handler);
	// release the jwt which was allocated in heap
	if (NULL != jwt) {
		free(jwt);
		jwt = NULL;
	}
}

void _six_iot_provision_device_by_iam() {
	// provision the device dynamically
}

char *_six_iot_obtain_key_from_local() { return get_device_private_key(); }

void six_iot_bind_device(six_iot_config_t *iot_config, char *user_global_uuid, char *access_token,
						 esp_event_loop_handle_t loop_handle) {
	if (!user_global_uuid) {
		ESP_LOGW(TAG, "Will not bind the device, user_global_uuid is NULL");
		return;
	}
	if (!access_token) {
		ESP_LOGW(TAG, "Will not bind the device, access_token is NULL");
		return;
	}
	ESP_LOGD(TAG, "Bind the device to principal id %s\n access_token is %s\n", user_global_uuid, access_token);
	s_six_iot_loop = loop_handle;
	s_iot_cfg = iot_config;
	s_user_global_uuid = user_global_uuid;
	s_http_rest_for_bind_device(s_iot_cfg->iot_bind_device_endpoint, access_token);
}

bool _six_is_tokens_valide_in_nvs(bool post_event) {
	char *id_token_in_nvs = six_nvs_read_id_token();
	char *access_token_in_nvs = six_nvs_read_access_token();
	if (id_token_in_nvs != NULL && !six_iam_token_expired(id_token_in_nvs, Second) && access_token_in_nvs != NULL &&
		!six_iam_token_expired(access_token_in_nvs, Second)) {
		if (post_event) {
			// report the id token
			char *data = id_token_in_nvs;
			int size = sizeof(char) * (strlen(data) + 1);
			ESP_LOGD(TAG,
					 "ID_Token in nvs is valid, post PROVISION_STATUS_DEVICE_AUTH_EXG_ID_TOKEN_SUCCEED directly, "
					 "token.size: %d",
					 size);
			esp_event_post_to(s_six_iot_loop, SIX_IOT_EVENT, PROVISION_STATUS_DEVICE_AUTH_EXG_ID_TOKEN_SUCCEED, data,
							  size, 10);

			vTaskDelay(pdMS_TO_TICKS(50)); // Delay for 50 milliseconds

			// report the access token
			data = access_token_in_nvs;
			size = sizeof(char) * (strlen(data) + 1);
			ESP_LOGD(
				TAG,
				"Access_Token in nvs is valid, post PROVISION_STATUS_DEVICE_AUTH_EXG_ACCESS_TOKEN_SUCCEED directly, "
				"token.size: %d",
				size);
			esp_event_post_to(s_six_iot_loop, SIX_IOT_EVENT, PROVISION_STATUS_DEVICE_AUTH_EXG_ACCESS_TOKEN_SUCCEED,
							  data, size, 10);
		} else {
			free(id_token_in_nvs);
			free(access_token_in_nvs);
		}
		return true;
	}
	if (id_token_in_nvs != NULL) {
		free(id_token_in_nvs);
	}
	if (access_token_in_nvs != NULL) {
		free(access_token_in_nvs);
	}
	return false;
}

void six_iam_exchange_device_tokens(six_iot_config_t *iot_config, esp_event_loop_handle_t loop_handle) {
	s_six_iot_loop = loop_handle;
	s_iot_cfg = iot_config;
	// if the tokens in nvs is valid, will directly use it, other than request it from IAM endpoint
	if (_six_is_tokens_valide_in_nvs(true)) {
		return;
	}
	char *private_key = _six_iot_obtain_key_from_local();
	s_report_provision_status(PROVISION_STATUS_DEVICE_AUTH_OBTAIN_LOCAL_KEY, "Obtain the device RSA key from local",
							  NULL);
	if (private_key) {
		s_report_provision_status(PROVISION_STATUS_DEVICE_AUTH_OBTAIN_LOCAL_KEY_SUCCEED,
								  "Obtain the device RSA key from local succeed!", NULL);
		_six_iam_exchange_device_tokens_with_local_key(private_key);
		free(private_key);
	} else {
		s_report_provision_status(PROVISION_STATUS_DEVICE_AUTH_OBTAIN_LOCAL_KEY_FAIL,
								  "Can't obtain the device RSA key from local!", NULL);
		_six_iot_provision_device_by_iam();
	}
}

void six_iot_intent_refresh_device_tokens() {
	if (s_iot_cfg == NULL) {
		ESP_LOGW(TAG, "Device service is not initialized, can't refresh the token");
		return;
	}
	ESP_LOGD(TAG, "Intent to refresh the token of device!");
	s_report_provision_status(REFRESH_DEVICE_TOKEN_INTENT, "Intent to refresh the token of device!", NULL);
}

static bool is_refreshing_token = false;
void six_iot_refresh_device_tokens() {
	ESP_LOGD(TAG, "six_refresh_device_tokens");
	if (is_refreshing_token) {
		ESP_LOGD(TAG, "is_refreshing_token, return");
		return;
	}
	is_refreshing_token = true;
	s_refresh_token_handler = NULL;
	char *private_key = _six_iot_obtain_key_from_local();
	if (private_key) {
		_six_iam_refresh_device_tokens_with_local_key(private_key);
	}
	is_refreshing_token = false;
}

void six_iot_refresh_device_tokens_with_handler(six_iam_token_handler_t handler) {
	ESP_LOGD(TAG, "six_refresh_device_tokens_with_handler");
	if (is_refreshing_token) {
		ESP_LOGD(TAG, "is_refreshing_token, return");
		return;
	}
	is_refreshing_token = true;
	s_refresh_token_handler = handler;
	char *private_key = _six_iot_obtain_key_from_local();
	if (private_key) {
		_six_iam_refresh_device_tokens_with_local_key(private_key);
	}
	is_refreshing_token = false;
}
