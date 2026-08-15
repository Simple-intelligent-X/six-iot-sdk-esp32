#include <dirent.h>
#include <esp_http_client.h>
#include <esp_log.h>
#include <esp_spiffs.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <time.h>

#include "six_iam_jwt.h"
#include "six_iot_log.h"
#include "six_iot_mqtt.h"
#include "six_iot_nvs.h"

#define SINGLE_LOG_FILE_SIZE 1024
#define MAX_LOG_MSG_LENGTH 128
#define MAX_LOG_FILES 95
#define MAX_FILE_PATH_LEN 36
#define MAX_FILE_NAME_LEN 30
#define LOG_DIR_MODE 0755

// Async logging queue
#define LOG_QUEUE_LENGTH 20
#define LOG_WRITER_TASK_NAME "LogWriterTask"
#define LOG_WRITER_TASK_STACK_SIZE (1024 * 4)
#define LOG_WRITER_TASK_PRIORITY (configMAX_PRIORITIES - 4)

static QueueHandle_t s_log_queue = NULL;
static TaskHandle_t s_log_writer_task_handle = NULL;
static void s_log_writer_task(void *pvParameters);

static const char *TAG = "six_iot_log";
static const char *LOG_DIR = "/spiffs/logs";
static const int MAX_LOG_FILES_TO_CLEAN = 1;

static six_iot_config_t *s_iot_cfg = NULL;
static SemaphoreHandle_t s_log_mutex = NULL;

static FILE *s_open_log_file = NULL;
static char s_open_file_name[MAX_FILE_PATH_LEN] = {0};

static char s_uploading_file_buffer[SINGLE_LOG_FILE_SIZE + MAX_LOG_MSG_LENGTH + 1] = {0};

static void _get_timestamp(char *buffer, size_t buffer_len);
static void _monitor_spiff_space();
static int _get_next_log_idx();
static void _clean_open_file();
static void _six_log_upload();
static bool _is_file_path_ends_with_name(const char *file_path, const char *name);

// Initialize SPIFFS
void six_log_init(six_iot_config_t *iot_config) {
	ESP_LOGD(TAG, "Initializing SPIFFS");
	s_iot_cfg = iot_config;

	s_log_mutex = xSemaphoreCreateMutex();
	if (s_log_mutex == NULL) {
		ESP_LOGE(TAG, "Failed to create log mutex");
		return;
	}

	esp_vfs_spiffs_conf_t conf = {
		.base_path = "/spiffs", .partition_label = NULL, .max_files = MAX_LOG_FILES, .format_if_mount_failed = true};

	esp_err_t ret = esp_vfs_spiffs_register(&conf);
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "Failed to mount or format SPIFFS (%s)", esp_err_to_name(ret));
		return;
	}

	struct stat st;
	if (stat(LOG_DIR, &st) != 0) {
		ESP_LOGD(TAG, "Creating log directory: %s", LOG_DIR);
		mkdir(LOG_DIR, LOG_DIR_MODE);
	}

	ESP_LOGD(TAG, "SPIFFS initialized and log directory prepared.");

	// Create async log queue and writer task
	if (s_log_queue == NULL) {
		s_log_queue = xQueueCreate(LOG_QUEUE_LENGTH, MAX_LOG_MSG_LENGTH + 1);
		if (s_log_queue == NULL) {
			ESP_LOGE(TAG, "Failed to create log queue");
		}
	}

	if (s_log_writer_task_handle == NULL && s_log_queue != NULL) {
		if (xTaskCreate(s_log_writer_task, LOG_WRITER_TASK_NAME, LOG_WRITER_TASK_STACK_SIZE, NULL,
						LOG_WRITER_TASK_PRIORITY, &s_log_writer_task_handle) != pdPASS) {
			ESP_LOGE(TAG, "Failed to create log writer task");
			vQueueDelete(s_log_queue);
			s_log_queue = NULL;
		}
	}
}

void safe_fprintf_log(FILE *file, const char *timestamp, const char *message) {
	// Calculate maximum message length allowed
	int timestamp_len = strlen(timestamp);
	int overhead = 5; // "[", "]:", "\n" characters + null terminator consideration
	int max_message_len = MAX_LOG_MSG_LENGTH - timestamp_len - overhead;

	if (max_message_len < 0) {
		max_message_len = 0; // Handle extremely long timestamp
	}

	// Truncate message if necessary
	int message_len = strlen(message);
	if (message_len > max_message_len) {
		// Write truncated message with ellipsis
		fprintf(file, "[%s]:%.*s...\n", timestamp, max_message_len - 3, message);
	} else {
		// Write full message
		fprintf(file, "[%s]:%s\n", timestamp, message);
	}
}

// Main logging function to write a message to a file
six_iot_log_write_result_t six_log_message(const char *message) {
	if (s_log_queue == NULL) {
		ESP_LOGD(TAG, "Log queue not initialized, dropping log");
		return LOG_MUTEX_NOT_INIT;
	}

	if (message == NULL) {
		ESP_LOGW(TAG, "Attempted to log a NULL message, skipping");
		return LOG_WRITE_OK; // Consider NULL message as a no-op
	}

	char buf[MAX_LOG_MSG_LENGTH + 1];
	strncpy(buf, message, MAX_LOG_MSG_LENGTH);
	buf[MAX_LOG_MSG_LENGTH] = '\0';

	// Non-blocking enqueue: if queue is full, drop the message to avoid blocking caller
	if (xQueueSend(s_log_queue, buf, 0) != pdPASS) {
		ESP_LOGW(TAG, "Log queue full, dropping log message");
		return LOG_QUEUE_FULL;
	}
	return LOG_WRITE_OK;
}

// Helper to get a timestamp string
static void _get_timestamp(char *buffer, size_t buffer_len) {
	time_t now;
	struct tm timeinfo;
	time(&now);
	localtime_r(&now, &timeinfo);
	strftime(buffer, buffer_len, "%Y-%m-%dT%H:%M:%S", &timeinfo);
}

// Function to check SPIFFS usage and delete old files if necessary
static void _monitor_spiff_space() {
	size_t total = 0, used = 0;
	esp_err_t ret = esp_spiffs_info(NULL, &total, &used);
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "Failed to get SPIFFS info (%s)", esp_err_to_name(ret));
		return;
	}
	double usage = (double)used / total;
	ESP_LOGD(TAG, "SPIFFS usage: %.2f%% (%u/%u bytes)", usage * 100, used, total);
}

// Function to find the next available log file number
static int _get_next_log_idx() {
	int next_idx = 0;
	DIR *dir = opendir(LOG_DIR);
	if (!dir) {
		ESP_LOGE(TAG, "Failed to open log directory to find next file");
		return 0;
	}

	struct dirent *ent;
	while ((ent = readdir(dir)) != NULL) {
		if (ent->d_type == DT_REG && strstr(ent->d_name, "log_") == ent->d_name) {
			int file_idx;
			if (sscanf(ent->d_name, "log_%d.txt", &file_idx) == 1) {
				if (file_idx >= next_idx) {
					next_idx = file_idx + 1;
				}
			}
		}
	}
	closedir(dir);
	return next_idx;
}

static void _clean_open_file() {
	if (s_open_log_file) {
		fclose(s_open_log_file);
	}
	s_open_log_file = NULL;
	memset(s_open_file_name, 0, MAX_FILE_PATH_LEN);
}

static bool _is_file_path_ends_with_name(const char *file_path, const char *name) {
	if (file_path == NULL || name == NULL) {
		return false;
	}
	char temp[MAX_FILE_PATH_LEN] = {0};
	snprintf(temp, sizeof(temp), "%s/%s", LOG_DIR, name);
	return strcmp(file_path, temp) == 0;
}

void six_log_upload() {
	ESP_LOGD(TAG, "Upload log...");
	_six_log_upload();
	_monitor_spiff_space();
}

/**
 * @brief Uploads all log files from SPIFFS to the cloud and deletes them.
 * This method ensures thread-safe access to the log files. It iterates
 * through all files in the log directory, uploads their content one by
 * one, and deletes them upon successful upload.
 */
static void _six_log_upload() {
	if (NULL == s_log_mutex) {
		ESP_LOGD(TAG, "s_log_mutex is not initialized, return!");
		return;
	}
	if (xSemaphoreTake(s_log_mutex, portMAX_DELAY) == pdTRUE) {
		ESP_LOGD(TAG, "Starting log upload process...");
		DIR *dir = opendir(LOG_DIR);
		if (!dir) {
			ESP_LOGE(TAG, "Failed to open log directory");
			xSemaphoreGive(s_log_mutex);
			return;
		}

		struct dirent *ent;
		char file_path[MAX_FILE_PATH_LEN];
		int uploaded_files_count = 0;

		// Use an array to store file names to upload in a specific order
		char file_names[MAX_LOG_FILES_TO_CLEAN][MAX_FILE_NAME_LEN];
		int file_count = 0;

		// Read all file names into a list
		while ((ent = readdir(dir)) != NULL && file_count < MAX_LOG_FILES_TO_CLEAN) {
			if (ent->d_type == DT_REG && strstr(ent->d_name, "log_") == ent->d_name) {
				// Ensure filename doesn't exceed our buffer
				strncpy(file_names[file_count], ent->d_name, MAX_FILE_NAME_LEN - 1);
				file_names[file_count][MAX_FILE_NAME_LEN - 1] = '\0'; // Ensure null termination
				ESP_LOGD(TAG, "Read file: %s", file_names[file_count]);
				file_count++;
			}
		}
		closedir(dir);

		// Sort files by their number (bubble sort)
		for (int i = 0; i < file_count - 1; i++) {
			for (int j = 0; j < file_count - i - 1; j++) {
				int num_j, num_j1;
				sscanf(file_names[j], "log_%d.txt", &num_j);
				sscanf(file_names[j + 1], "log_%d.txt", &num_j1);

				if (num_j > num_j1) {
					// Swap the filenames
					char temp[MAX_FILE_NAME_LEN];
					strncpy(temp, file_names[j], MAX_FILE_NAME_LEN);
					strncpy(file_names[j], file_names[j + 1], MAX_FILE_NAME_LEN);
					strncpy(file_names[j + 1], temp, MAX_FILE_NAME_LEN);
				}
			}
		}

		ESP_LOGD(TAG, "file_count: %d", file_count);
		// Process sorted files
		for (int i = 0; i < file_count; i++) {
			const char *filename_to_upload = file_names[i];
			// Safe path construction with length checking
			int path_len = snprintf(file_path, sizeof(file_path), "%s/%s", LOG_DIR, filename_to_upload);
			ESP_LOGD(TAG, "file_path: %s, path_len: %d", file_path, path_len);
			if (path_len >= sizeof(file_path)) {
				ESP_LOGE(TAG, "File path too long: %s/%s", LOG_DIR, filename_to_upload);
				continue;
			}

			FILE *f = fopen(file_path, "r");
			if (f == NULL) {
				ESP_LOGE(TAG, "Failed to open file for reading: %s", file_path);
				continue;
			}

			// Get file size
			if (fseek(f, 0, SEEK_END) != 0) {
				ESP_LOGE(TAG, "Failed to seek to end of log file: %s", file_path);
				fclose(f);
				continue;
			}

			long fsize = ftell(f);

			if (fsize < 0) {
				ESP_LOGE(TAG, "Failed to get size of log file: %s", file_path);
				fclose(f);
				continue;
			}

			if (fseek(f, 0, SEEK_SET) != 0) {
				ESP_LOGE(TAG, "Failed to seek to beginning of log file: %s", file_path);
				fclose(f);
				continue;
			}

			if (fsize > 0) {
				size_t buffer_size = sizeof(s_uploading_file_buffer) - 1;
				memset(s_uploading_file_buffer, 0, sizeof(s_uploading_file_buffer));

				size_t read_size = fsize > buffer_size ? buffer_size : (size_t)fsize;
				size_t actual_read = fread(s_uploading_file_buffer, 1, read_size, f);
				if (actual_read != read_size) {
					ESP_LOGE(TAG, "Failed to read log file: %s", file_path);
					fclose(f);
					continue;
				}
				s_uploading_file_buffer[actual_read] = '\0';

				fclose(f);
				char *log_content = s_uploading_file_buffer;

				ESP_LOGD(TAG, "s_open_file_name: %s, filename_to_upload: %s", s_open_file_name, filename_to_upload);
				if (_is_file_path_ends_with_name(s_open_file_name, filename_to_upload)) {
					_clean_open_file();
				}
				// Upload the log content
				ESP_LOGD(TAG, "Uploading log file: %s, log_content: %s", filename_to_upload, log_content);
				// will leverage the mqttt to send the log to cloud, this is light weight solution
				esp_err_t err = six_iot_publish_log_msg(log_content);

				if (err == ESP_OK) {
					ESP_LOGD(TAG, "Successfully uploaded log file, deleting file: %s", filename_to_upload);
					if (unlink(file_path) != 0) {
						ESP_LOGE(TAG, "Failed to delete file: %s", file_path);
					} else {
						uploaded_files_count++;
					}
				} else {
					ESP_LOGE(TAG, "Failed to upload log file: %s, keeping file.", filename_to_upload);
				}
			} else {
				ESP_LOGW(TAG, "Skipping empty log file: %s", filename_to_upload);
				fclose(f);
				// Delete empty files immediately
				if (unlink(file_path) != 0) {
					ESP_LOGE(TAG, "Failed to delete empty file: %s", file_path);
				}
				if (_is_file_path_ends_with_name(s_open_file_name, filename_to_upload)) {
					_clean_open_file();
				}
			}
		}
		ESP_LOGD(TAG, "Log upload and cleanup finished. Uploaded %d files.", uploaded_files_count);
		xSemaphoreGive(s_log_mutex);
	} else {
		ESP_LOGD(TAG, "Can't get the log mutext, upload log in next timer tick!");
	}
}

// Log writer task: consume messages from s_log_queue and perform SPIFFS writes
static void s_log_writer_task(void *pvParameters) {
	char msg[MAX_LOG_MSG_LENGTH + 1];

	while (1) {
		if (xQueueReceive(s_log_queue, msg, portMAX_DELAY) == pdPASS) {
			if (NULL == s_log_mutex) {
				ESP_LOGD(TAG, "s_log_mutex is not initialized, skip writing");
				continue;
			}
			if (xSemaphoreTake(s_log_mutex, portMAX_DELAY) != pdTRUE) {
				ESP_LOGD(TAG, "Failed to take log mutex in writer task");
				continue;
			}

			// Open new file if needed
			if (s_open_log_file == NULL) {
				int next_idx = _get_next_log_idx();
				memset(s_open_file_name, 0, sizeof(s_open_file_name));
				snprintf(s_open_file_name, sizeof(s_open_file_name), "%s/log_%d.txt", LOG_DIR, next_idx);

				s_open_log_file = fopen(s_open_file_name, "a");
				if (s_open_log_file == NULL) {
					ESP_LOGE(TAG, "Failed to open file for writing log: %s", s_open_file_name);
					xSemaphoreGive(s_log_mutex);
					continue;
				}
			}

			char timestamp[32];
			_get_timestamp(timestamp, sizeof(timestamp));
			safe_fprintf_log(s_open_log_file, timestamp, msg);
			fflush(s_open_log_file);

			struct stat st;
			if (stat(s_open_file_name, &st) == 0) {
				if (st.st_size > SINGLE_LOG_FILE_SIZE) {
					fclose(s_open_log_file);
					_clean_open_file();
				}
			}
			_monitor_spiff_space();
			xSemaphoreGive(s_log_mutex);
		}
	}
}
