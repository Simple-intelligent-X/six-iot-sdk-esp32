#ifndef SIX_IOT_LOG_H
#define SIX_IOT_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include "six_iot_config.h"

typedef enum {
	LOG_WRITE_OK = 0,
	LOG_MUTEX_NOT_INIT,
	LOG_MUTEX_GET_FAIL,
	LOG_OPEN_WRITING_FILE_FAIL,
	LOG_QUEUE_FULL,
} six_iot_log_write_result_t;

/**
 * @brief Initializes the SPIFFS file system and prepares the log directory.
 * * This function must be called once at the start of the application.
 * It mounts SPIFFS, creates the `/spiffs/logs` directory, and initializes
 * a mutex for thread-safe logging.
 */
void six_log_init(six_iot_config_t *iot_config);

/**
 * @brief Writes a message to a log file on SPIFFS.
 * * This function is thread-safe and can be called from multiple tasks.
 * It automatically manages file rotation and space, deleting the oldest
 * logs if the occupied space exceeds a predefined threshold.
 * * @param message The string message to be written to the log file.
 */
six_iot_log_write_result_t six_log_message(const char *message);

/**
 * @brief Uploads all log files from SPIFFS to the cloud and deletes them.
 * This method is called from SDK task periodically.
 */
void six_log_upload();

#ifdef __cplusplus
}
#endif

#endif /* SIX_IOT_LOG_H */