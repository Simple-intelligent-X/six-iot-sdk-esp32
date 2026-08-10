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
extern const uint8_t aws_root_ca_pem_start[]
    asm("_binary_aws_root_ca_pem_start");
extern const uint8_t aws_root_ca_pem_end[]
    asm("_binary_aws_root_ca_pem_end");
#endif

#ifdef CONFIG_DEFAULT_ROOT_CA
extern const uint8_t six_ca_pem_start[]
    asm("_binary_six_ca_pem_start");
extern const uint8_t six_ca_pem_end[]
    asm("_binary_six_ca_pem_end");
#endif

#define SIX_IOT_SDK_EVENT_TICK       pdMS_TO_TICKS(100)

#define HTTP_INITIAL_BUFFER_SIZE     512U
#define MAX_TOKEN_RESPONSE_SIZE     8192U
#define MAX_BIND_RESPONSE_SIZE      4096U
#define HTTP_TIMEOUT_MS             30000

static six_iam_token_handler_t s_refresh_token_handler = NULL;
static esp_event_loop_handle_t s_six_iot_loop = NULL;
static six_iot_config_t *s_iot_cfg = NULL;
static char *s_user_global_uuid = NULL;

/*
 * Refresh operations are synchronous today because esp_http_client_perform()
 * is used without async mode. The mutex also prevents two callers from
 * modifying s_refresh_token_handler at the same time.
 */
static SemaphoreHandle_t s_token_refresh_mutex = NULL;

/*
 * HTTP response state belongs to one HTTP client/request.
 * It must not be static inside an event handler.
 */
typedef struct {
    char *data;
    size_t length;
    size_t capacity;
    size_t max_size;
    six_iam_token_handler_t token_handler;
} six_http_response_ctx_t;

/** Inner methods definition start **/

char *_six_iot_obtain_key_from_local(void);

void _six_iam_exchange_device_tokens_with_local_key(const char *private_key);

void _six_iam_refresh_device_tokens_with_local_key(const char *private_key);

void _six_iot_provision_device_by_iam(void);

bool _six_is_tokens_valide_in_nvs(bool post_event);

void _six_iam_exchange_tokens(
    const char *token_endpoint,
    const char *jwt,
    six_iam_token_handler_t token_handler);

/** Inner methods definition end **/

static esp_err_t s_init_token_refresh_mutex(void) {
    if (s_token_refresh_mutex != NULL) {
        return ESP_OK;
    }

    s_token_refresh_mutex = xSemaphoreCreateMutex();

    if (s_token_refresh_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create token refresh mutex");
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

static void s_http_response_cleanup(six_http_response_ctx_t *ctx) {
    if (ctx == NULL) {
        return;
    }
    free(ctx->data);
    ctx->data = NULL;

    ctx->length = 0;
    ctx->capacity = 0;
    ctx->max_size = 0;
    ctx->token_handler = NULL;
}

static esp_err_t s_http_response_init(six_http_response_ctx_t *ctx,
    size_t initial_size, size_t max_size) {
    if (ctx == NULL || initial_size == 0 || max_size < initial_size) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(ctx, 0, sizeof(*ctx));

    ctx->data = calloc(initial_size + 1U, sizeof(char));

    if (ctx->data == NULL) {
        return ESP_ERR_NO_MEM;
    }

    ctx->capacity = initial_size;
    ctx->max_size = max_size;
    return ESP_OK;
}

static esp_err_t s_http_response_append(six_http_response_ctx_t *ctx,
    const void *data, size_t data_len) {
    if (ctx == NULL || data == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (data_len == 0) {
        return ESP_OK;
    }

    if (ctx->length > ctx->max_size || data_len > ctx->max_size - ctx->length) {
        ESP_LOGE(
            TAG,
            "HTTP response exceeds limit: current=%u incoming=%u max=%u",
            (unsigned)ctx->length,
            (unsigned)data_len,
            (unsigned)ctx->max_size);
        return ESP_ERR_NO_MEM;
    }

    size_t required = ctx->length + data_len + 1U;

    if (required > ctx->capacity) {
        size_t new_capacity = ctx->capacity;

        while (new_capacity < required) {
            if (new_capacity > ctx->max_size / 2U) {
                new_capacity = ctx->max_size;
                break;
            }

            new_capacity *= 2U;
        }

        if (new_capacity > ctx->max_size) {
            new_capacity = ctx->max_size;
        }

        char *new_data =
            realloc(ctx->data, new_capacity + 1U);

        if (new_data == NULL) {
            ESP_LOGE(
                TAG,
                "Failed to grow HTTP response buffer from %u to %u",
                (unsigned)ctx->capacity,
                (unsigned)new_capacity);

            return ESP_ERR_NO_MEM;
        }

        ctx->data = new_data;
        ctx->capacity = new_capacity;
    }

    memcpy(ctx->data + ctx->length, data, data_len);

    ctx->length += data_len;

    ctx->data[ctx->length] = '\0';

    return ESP_OK;
}

static void s_report_provision_status(
	six_iot_event_t status,
    char *msg, void *args) {
    if (msg != NULL) {
        ESP_LOGD(TAG, "%s", msg);
    }

    if (s_six_iot_loop == NULL) {
        return;
    }

    if (status == PROVISION_STATUS_DEVICE_AUTH_EXG_TOKENS_SUCCEED) {
        if (args == NULL) {
            ESP_LOGW(TAG, "Token success event has NULL data");
            return;
        }

        six_iam_tokens_t *tokens = args;

        if (tokens->id_token == NULL ||
            tokens->access_token == NULL) {
            ESP_LOGW(TAG, "Token success event contains NULL token");
            return;
        }

        char *data = tokens->id_token;
        size_t size = strlen(data) + 1U;

        esp_err_t err = esp_event_post_to(
            s_six_iot_loop,
            SIX_IOT_EVENT,
            PROVISION_STATUS_DEVICE_AUTH_EXG_ID_TOKEN_SUCCEED,
            data,
            size,
            SIX_IOT_SDK_EVENT_TICK);

        if (err != ESP_OK) {
            ESP_LOGW(
                TAG,
                "Failed to post ID-token event: %s",
                esp_err_to_name(err));
        }

        data = tokens->access_token;
        size = strlen(data) + 1U;

        err = esp_event_post_to(
            s_six_iot_loop,
            SIX_IOT_EVENT,
            PROVISION_STATUS_DEVICE_AUTH_EXG_ACCESS_TOKEN_SUCCEED,
            data,
            size,
            SIX_IOT_SDK_EVENT_TICK);

        if (err != ESP_OK) {
            ESP_LOGW(
                TAG,
                "Failed to post access-token event: %s",
                esp_err_to_name(err));
        }

        return;
    }

    /*
     * Preserve the original event behavior for status events whose
     * payload is a fixed/simple value. If args is NULL, post no payload.
     */
    size_t size = (args != NULL) ? sizeof(*args) : 0U;

    esp_err_t err = esp_event_post_to(
        s_six_iot_loop,
        SIX_IOT_EVENT,
        status,
        args,
        size,
        SIX_IOT_SDK_EVENT_TICK);

    if (err != ESP_OK) {
        ESP_LOGW(
            TAG,
            "Failed to post provisioning event %d: %s",
            (int)status,
            esp_err_to_name(err));
    }
}

static void s_six_iam_token_handler(
    bool success,
    char *id_token,
    char *access_token) {
    if (!success) {
        return;
    }

    if (id_token == NULL || access_token == NULL) {
        ESP_LOGE(TAG, "Token handler received incomplete token response");
        return;
    }

    six_iam_tokens_t tokens = {
        .id_token = id_token,
        .access_token = access_token,
    };

    six_nvs_save_id_token(id_token);
    six_nvs_save_access_token(access_token);

    s_report_provision_status(
        PROVISION_STATUS_DEVICE_AUTH_EXG_TOKENS_SUCCEED,
        "ID and Access Token for device is obtained successfully!",
        &tokens);
}

static void s_six_iam_token_refresh_handler(
    bool success,
    char *id_token,
    char *access_token) {
    if (id_token != NULL) {
        six_nvs_save_id_token(id_token);
    }

    if (access_token != NULL) {
        six_nvs_save_access_token(access_token);
    }

    if (s_refresh_token_handler != NULL) {
        s_refresh_token_handler(
            success,
            id_token,
            access_token);
    }
}

/* Parse the ID token from JSON. */
static char *s_parse_id_token(cJSON *json) {
    if (json == NULL) {
        return NULL;
    }

    return six_parse_json_str_attr(json, "id_token");
}

/* Parse the access token from JSON. */
static char *s_parse_access_token(cJSON *json) {
    if (json == NULL) {
        return NULL;
    }

    return six_parse_json_str_attr(json, "access_token");
}

esp_err_t _http_rest_for_tokens_event_handler(
    esp_http_client_event_t *evt) {
    if (evt == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    six_http_response_ctx_t *ctx =
        (six_http_response_ctx_t *)evt->user_data;

    switch (evt->event_id) {

    case HTTP_EVENT_ERROR:
        ESP_LOGW(TAG, "HTTP_EVENT_ERROR");
        break;

    case HTTP_EVENT_ON_CONNECTED:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
        break;

    case HTTP_EVENT_HEADER_SENT:
        ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
        break;

    case HTTP_EVENT_ON_HEADER:
        ESP_LOGD(
            TAG,
            "HTTP_EVENT_ON_HEADER, key=%s",
            evt->header_key != NULL ? evt->header_key : "<unknown>");
        break;

    case HTTP_EVENT_ON_DATA:
        if (ctx == NULL) {
            ESP_LOGE(TAG, "Token HTTP response context is NULL");
            return ESP_FAIL;
        }

        ESP_LOGD(
            TAG,
            "HTTP_EVENT_ON_DATA, len=%d",
            evt->data_len);

        if (evt->data_len < 0) {
            return ESP_FAIL;
        }

        esp_err_t err = s_http_response_append(
            ctx,
            evt->data,
            (size_t)evt->data_len);

        if (err != ESP_OK) {
            ESP_LOGE(
                TAG,
                "Unable to store token HTTP response");

            return err;
        }

        /*
         * This means response data was received, preserving the original
         * provisioning-status behavior.
         */
        s_report_provision_status(
            PROVISION_STATUS_DEVICE_AUTH_EXG_ACCESS_TOKEN_REQ_SUCCEED,
            "The request to get the access token respond successfully!",
            NULL);

        break;

    case HTTP_EVENT_ON_FINISH:
        if (ctx == NULL) {
            ESP_LOGE(TAG, "Token HTTP response context is NULL");
            return ESP_FAIL;
        }

        ESP_LOGD(
            TAG,
            "HTTP_EVENT_ON_FINISH, response length=%u",
            (unsigned)ctx->length);

        if (ctx->data == NULL || ctx->length == 0U) {
            ESP_LOGE(TAG, "Empty token response");

            if (ctx->token_handler != NULL) {
                ctx->token_handler(false, NULL, NULL);
            }

            return ESP_FAIL;
        }

        int status_code =
            esp_http_client_get_status_code(evt->client);

        if (status_code < 200 || status_code >= 300) {
            ESP_LOGW(
                TAG,
                "Token endpoint returned HTTP status %d",
                status_code);

            if (ctx->token_handler != NULL) {
                ctx->token_handler(false, NULL, NULL);
            }

            return ESP_FAIL;
        }

        cJSON *resp_json =
            cJSON_ParseWithLengthOpts(
                ctx->data,
                ctx->length,
                NULL,
                0);

        if (resp_json == NULL) {
            ESP_LOGE(TAG, "Invalid JSON returned by token endpoint");

            if (ctx->token_handler != NULL) {
                ctx->token_handler(false, NULL, NULL);
            }

            return ESP_FAIL;
        }

        char *id_token = NULL;
        char *access_token = NULL;

        char *id_token_in_json =
            s_parse_id_token(resp_json);

        if (id_token_in_json != NULL) {
            id_token = strdup(id_token_in_json);

            if (id_token == NULL) {
                ESP_LOGE(TAG, "Failed to allocate ID token");
                cJSON_Delete(resp_json);

                if (ctx->token_handler != NULL) {
                    ctx->token_handler(false, NULL, NULL);
                }

                return ESP_ERR_NO_MEM;
            }
        }

        char *access_token_in_json =
            s_parse_access_token(resp_json);

        if (access_token_in_json != NULL) {
            access_token = strdup(access_token_in_json);

            if (access_token == NULL) {
                ESP_LOGE(TAG, "Failed to allocate access token");

                free(id_token);
                cJSON_Delete(resp_json);

                if (ctx->token_handler != NULL) {
                    ctx->token_handler(false, NULL, NULL);
                }

                return ESP_ERR_NO_MEM;
            }
        }

        cJSON_Delete(resp_json);

        if (ctx->token_handler == NULL) {
            ESP_LOGE(TAG, "Token response handler is NULL");

            free(id_token);
            free(access_token);

            return ESP_ERR_INVALID_STATE;
        }

        bool success =
            (id_token != NULL && access_token != NULL);

        /*
         * The callback borrows these pointers for the duration of the call.
         * It must not retain them.
         */
        ctx->token_handler(
            success,
            id_token,
            access_token);

        free(id_token);
        free(access_token);

        break;

    case HTTP_EVENT_DISCONNECTED:
        ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
        break;

    case HTTP_EVENT_REDIRECT:
        ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");

        esp_http_client_set_header(
            evt->client,
            "Accept",
            "application/json");

        esp_http_client_set_redirection(evt->client);
        break;

    default:
        break;
    }

    return ESP_OK;
}

static void s_http_rest_for_tokens(
    const char *token_endpoint,
    const char *jwt,
    six_iam_token_handler_t token_handler) {

    if (token_endpoint == NULL || jwt == NULL) {
        ESP_LOGE(TAG, "Invalid token endpoint or JWT");

        if (token_handler != NULL) {
            token_handler(false, NULL, NULL);
        }

        return;
    }

    six_http_response_ctx_t response = {0};

    esp_err_t err = s_http_response_init(
        &response,
        HTTP_INITIAL_BUFFER_SIZE,
        MAX_TOKEN_RESPONSE_SIZE);

    if (err != ESP_OK) {
        ESP_LOGE(
            TAG,
            "Failed to allocate token response buffer");

        if (token_handler != NULL) {
            token_handler(false, NULL, NULL);
        }

        return;
    }

    response.token_handler = token_handler;

    int post_data_len = snprintf(
		NULL,
        0,
        SIX_IAM_DEVICE_JWT_ASSERTION,
        jwt);

    if (post_data_len < 0) {
        ESP_LOGE(TAG, "Failed to calculate token POST body length");

        s_http_response_cleanup(&response);

        if (token_handler != NULL) {
            token_handler(false, NULL, NULL);
        }

        return;
    }

    char *post_data =
        malloc((size_t)post_data_len + 1U);

    if (post_data == NULL) {
        ESP_LOGE(TAG, "Failed to allocate token POST body");

        s_http_response_cleanup(&response);

        if (token_handler != NULL) {
            token_handler(false, NULL, NULL);
        }

        return;
    }

    int written = snprintf(
        post_data,
        (size_t)post_data_len + 1U,
        SIX_IAM_DEVICE_JWT_ASSERTION,
        jwt);

    if (written != post_data_len) {
        ESP_LOGE(TAG, "Failed to construct token POST body");

        free(post_data);
        s_http_response_cleanup(&response);

        if (token_handler != NULL) {
            token_handler(false, NULL, NULL);
        }

        return;
    }

    esp_http_client_config_t config = {
        .url = token_endpoint,
        .event_handler = _http_rest_for_tokens_event_handler,
        .user_data = &response,
        .tls_version = ESP_HTTP_CLIENT_TLS_VER_TLS_1_2,
        .timeout_ms = HTTP_TIMEOUT_MS,

#ifdef CONFIG_SDK_TOKEN_REQ_DEFAULT_CA
        .cert_pem = (const char *)six_ca_pem_start,
#endif

#ifdef CONFIG_SDK_TOKEN_REQ_AWS_CA
        .cert_pem = (const char *)aws_root_ca_pem_start,
#endif
    };

    esp_http_client_handle_t client =
        esp_http_client_init(&config);

    if (client == NULL) {
        ESP_LOGE(TAG, "esp_http_client_init() failed");

        free(post_data);
        s_http_response_cleanup(&response);

        if (token_handler != NULL) {
            token_handler(false, NULL, NULL);
        }

        return;
    }

    err = esp_http_client_set_method(
        client,
        HTTP_METHOD_POST);

    if (err != ESP_OK) {
        ESP_LOGE(
            TAG,
            "Failed to set token HTTP method: %s",
            esp_err_to_name(err));

        goto cleanup;
    }

    err = esp_http_client_set_header(
        client,
        "Content-Type",
        "application/x-www-form-urlencoded");

    if (err != ESP_OK) {
        ESP_LOGE(
            TAG,
            "Failed to set token Content-Type: %s",
            esp_err_to_name(err));

        goto cleanup;
    }

    err = esp_http_client_set_post_field(
        client,
        post_data,
        (size_t)post_data_len);

    if (err != ESP_OK) {
        ESP_LOGE(
            TAG,
            "Failed to set token POST field: %s",
            esp_err_to_name(err));

        goto cleanup;
    }

    ESP_LOGD(
        TAG,
        "Sending token request to IAM endpoint");

    err = esp_http_client_perform(client);

    if (err != ESP_OK) {
        ESP_LOGE(
            TAG,
            "HTTP POST request failed: %s",
            esp_err_to_name(err));

        s_report_provision_status(
            PROVISION_STATUS_DEVICE_AUTH_EXG_ACCESS_TOKEN_REQ_FAIL,
            "The request to get the access token fail!",
            NULL);

        /*
         * The event handler may already have invoked the callback for some
         * response errors. Here it is only invoked if the perform operation
         * itself failed before a valid response was processed.
         */
        if (response.length == 0U &&
            response.token_handler != NULL) {
            response.token_handler(false, NULL, NULL);
        }

        goto cleanup;
    }

    ESP_LOGD(
        TAG,
        "HTTP POST Status=%d content_length=%lld response_length=%u",
        esp_http_client_get_status_code(client),
        esp_http_client_get_content_length(client),
        (unsigned)response.length);

cleanup:

    free(post_data);

    s_http_response_cleanup(&response);

    err = esp_http_client_cleanup(client);

    if (err != ESP_OK) {
        ESP_LOGW(
            TAG,
            "HTTP client cleanup failed: %s",
            esp_err_to_name(err));
    }
}


void _six_iam_exchange_tokens(
    const char *token_endpoint,
    const char *jwt,
    six_iam_token_handler_t token_handler) {
    if (token_endpoint == NULL || jwt == NULL) {
        ESP_LOGE(TAG, "Invalid token exchange parameters");

        if (token_handler != NULL) {
            token_handler(false, NULL, NULL);
        }

        return;
    }

    s_report_provision_status(
        PROVISION_STATUS_DEVICE_AUTH_EXG_ACCESS_TOKEN_REQ,
        "To exchange the tokens with JWT!",
        NULL);

    s_http_rest_for_tokens(
        token_endpoint,
        jwt,
        token_handler);
}


void _six_iam_exchange_device_tokens_with_local_key(
	const char *private_key) {
    if (private_key == NULL ||
        s_iot_cfg == NULL ||
        s_iot_cfg->iam.device_guid == NULL) {
        ESP_LOGE(TAG, "Invalid parameters for token exchange");
        return;
    }

    char *jwt = six_iam_create_jwt(
        s_iot_cfg->iam.device_guid,
        private_key);

    if (jwt == NULL) {
        ESP_LOGE(TAG, "Failed to create device JWT");
        return;
    }

	s_report_provision_status(
        PROVISION_STATUS_DEVICE_AUTH_GEN_JWT,
        "generate JWT through private key!",
        NULL);

    _six_iam_exchange_tokens(
        s_iot_cfg->iam.token_endpoint,
        jwt,
        s_six_iam_token_handler);

    free(jwt);
}

void _six_iam_refresh_device_tokens_with_local_key(
    const char *private_key) {
    if (private_key == NULL ||
        s_iot_cfg == NULL ||
        s_iot_cfg->iam.device_guid == NULL) {
        ESP_LOGE(TAG, "Invalid parameters for token refresh");
        return;
    }

    char *jwt = six_iam_create_jwt(
        s_iot_cfg->iam.device_guid,
        private_key);

    if (jwt == NULL) {
        ESP_LOGE(TAG, "Failed to create refresh JWT");
        return;
    }

    _six_iam_exchange_tokens(
        s_iot_cfg->iam.token_endpoint,
        jwt,
        s_six_iam_token_refresh_handler);

    free(jwt);
}

void _six_iot_provision_device_by_iam(void) {
    /*
     * Provision the device dynamically.
     *
     * This was intentionally empty in the original implementation.
     */
}

char *_six_iot_obtain_key_from_local(void) {
    return get_device_private_key();
}

bool _six_is_tokens_valide_in_nvs(bool post_event) {
    char *id_token_in_nvs =
        six_nvs_read_id_token();

    char *access_token_in_nvs =
        six_nvs_read_access_token();

    bool valid =
        id_token_in_nvs != NULL &&
        !six_iam_token_expired(
            id_token_in_nvs,
            Second) &&
        access_token_in_nvs != NULL &&
        !six_iam_token_expired(
            access_token_in_nvs,
            Second);

    if (!valid) {
        free(id_token_in_nvs);
        free(access_token_in_nvs);
        return false;
    }

    if (post_event && s_six_iot_loop != NULL) {
        char *data = id_token_in_nvs;
        size_t size = strlen(data) + 1U;

        esp_err_t err = esp_event_post_to(
            s_six_iot_loop,
            SIX_IOT_EVENT,
            PROVISION_STATUS_DEVICE_AUTH_EXG_ID_TOKEN_SUCCEED,
            data,
            size,
            SIX_IOT_SDK_EVENT_TICK);

        if (err != ESP_OK) {
            ESP_LOGW(
                TAG,
                "Failed to post cached ID token event: %s",
                esp_err_to_name(err));
        }

        data = access_token_in_nvs;
        size = strlen(data) + 1U;

        err = esp_event_post_to(
            s_six_iot_loop,
            SIX_IOT_EVENT,
            PROVISION_STATUS_DEVICE_AUTH_EXG_ACCESS_TOKEN_SUCCEED,
            data,
            size,
            SIX_IOT_SDK_EVENT_TICK);

        if (err != ESP_OK) {
            ESP_LOGW(
                TAG,
                "Failed to post cached access token event: %s",
                esp_err_to_name(err));
        }
    }

    /*
     * esp_event_post_to() copies event data. These NVS buffers are therefore
     * owned by this function and must always be released here.
     */
    free(id_token_in_nvs);
    free(access_token_in_nvs);

    return true;
}


void six_iam_exchange_device_tokens(
    six_iot_config_t *iot_config, 
	esp_event_loop_handle_t loop_handle) {
    if (iot_config == NULL) {
        ESP_LOGE(TAG, "iot_config is NULL");
        return;
    }

    s_six_iot_loop = loop_handle;
    s_iot_cfg = iot_config;

    /*
     * If valid tokens are already stored in NVS, use them directly.
     */
    if (_six_is_tokens_valide_in_nvs(true)) {
        return;
    }

    char *private_key = _six_iot_obtain_key_from_local();

    s_report_provision_status(
        PROVISION_STATUS_DEVICE_AUTH_OBTAIN_LOCAL_KEY,
        "Obtain the device RSA key from flash",
        NULL);

    if (private_key != NULL) {
        s_report_provision_status(
            PROVISION_STATUS_DEVICE_AUTH_OBTAIN_LOCAL_KEY_SUCCEED,
            "Obtain the device RSA key from flash succeed!",
            NULL);
        _six_iam_exchange_device_tokens_with_local_key(private_key);
        /*
         * get_device_private_key() returns heap memory.
         */
        free(private_key);
    } else {
        s_report_provision_status(
            PROVISION_STATUS_DEVICE_AUTH_OBTAIN_LOCAL_KEY_FAIL,
            "Can't obtain the device RSA key from flash!",
            NULL);

        _six_iot_provision_device_by_iam();
    }
}

void six_iot_intent_refresh_device_tokens(void) {
    if (s_iot_cfg == NULL) {
        ESP_LOGW(
            TAG,
            "Device service is not initialized, can't refresh the token");
        return;
    }

    ESP_LOGD(
        TAG,
        "Intent to refresh the token of device!");

    s_report_provision_status(
        REFRESH_DEVICE_TOKEN_INTENT,
        "Intent to refresh the token of device!",
        NULL);
}

void six_iot_refresh_device_tokens(void) {
    ESP_LOGD(
        TAG,
        "six_refresh_device_tokens");

    if (s_iot_cfg == NULL) {
        ESP_LOGW(
            TAG,
            "Device service is not initialized, can't refresh token");
        return;
    }

    if (s_init_token_refresh_mutex() != ESP_OK) {
        return;
    }

    if (xSemaphoreTake(
            s_token_refresh_mutex,
            0) != pdTRUE) {

        ESP_LOGD(
            TAG,
            "Token refresh already in progress");

        return;
    }

    s_refresh_token_handler = NULL;

    char *private_key =
        _six_iot_obtain_key_from_local();

    if (private_key != NULL) {
        _six_iam_refresh_device_tokens_with_local_key(
            private_key);

        free(private_key);
    } else {
        ESP_LOGW(
            TAG,
            "Unable to obtain private key for token refresh");
    }

    s_refresh_token_handler = NULL;

    xSemaphoreGive(s_token_refresh_mutex);
}

void six_iot_refresh_device_tokens_with_handler(
    six_iam_token_handler_t handler) {
    ESP_LOGD(
        TAG,
        "six_refresh_device_tokens_with_handler");

    if (s_iot_cfg == NULL) {
        ESP_LOGW(
            TAG,
            "Device service is not initialized, can't refresh token");
        return;
    }

    if (s_init_token_refresh_mutex() != ESP_OK) {
        return;
    }

    if (xSemaphoreTake(
            s_token_refresh_mutex,
            0) != pdTRUE) {

        ESP_LOGD(
            TAG,
            "Token refresh already in progress");

        return;
    }

    s_refresh_token_handler = handler;

    char *private_key =
        _six_iot_obtain_key_from_local();

    if (private_key != NULL) {
        _six_iam_refresh_device_tokens_with_local_key(
            private_key);

        free(private_key);
    } else {
        ESP_LOGW(
            TAG,
            "Unable to obtain private key for token refresh");

        s_refresh_token_handler = NULL;

        if (handler != NULL) {
            handler(false, NULL, NULL);
        }
    }

    s_refresh_token_handler = NULL;

    xSemaphoreGive(s_token_refresh_mutex);
}
