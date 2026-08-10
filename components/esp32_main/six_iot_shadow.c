#include <string.h>

#include "six_iot_shadow.h"
#include "six_iot_util.h"

/**
 * Parse the shadow status
 */
char *six_iot_parse_shadow_status(cJSON *json) { return six_iot_parse_shadow_str_attr(json, "status"); }

/**
 * Parse String attribute from the shadow JSON
 */
char *six_iot_parse_shadow_str_attr(cJSON *json, char *attrName) { return six_parse_json_str_attr(json, attrName); }

/**
 * Parse Object attribute from the shadow JSON
 */
cJSON *six_iot_parse_shadow_obj_attr(cJSON *json, char *attrName) { return six_parse_json_obj_attr(json, attrName); }

/**
 *
  shadowTopic: '+/+/shadow'
  shadowLwtTopic: '+/+/shadow/lwt'
  shadowUpdateTopic: '+/+/shadow/update'
  shadowDesiredTopic: '+/+/shadow/desired'
  shadowReportedTopic: '+/+/shadow/reported'
  shadowPingTopic: '+/+/shadow/ping'
  shadowGetTopic: '+/+/shadow/get'
  shadowOtaTopic: '+/+/shadow/ota'
  shadowUpdateAcceptedTopic: 'shadow/update/accepted'
  shadowDesiredAcceptedTopic: 'shadow/desired/accepted'
  shadowReportedAcceptedTopic: 'shadow/reported/accepted'
  shadowPingAcceptedTopic: 'shadow/ping/accepted'
  shadowGetAcceptedTopic: 'shadow/get/accepted'

  Shadow,
  Lwt,
  Update,
  Desired,
  Reported,
  Ping,
  Get,
  UpdateAccepted,
  DesiredAccepted,
  ReportedAccepted,
  PingAccepted,
  GetAccepted,
 */
char *six_iot_get_shadow_topic(char *productId, char *deviceGuid, six_iot_shadow_topic_t topicType) {
	int topicLength = 0;
	char *topicSeg1 = NULL;
	char *topicSeg2 = NULL;
	switch (topicType) {
	case Shadow:
		break;
	case Lwt:
		topicSeg1 = "lwt";
		break;
	case Update:
		topicSeg1 = "update";
		break;
	// case Desired:
	// 	topicSeg1 = "desired";
	// 	break;
	// case Reported:
	// 	topicSeg1 = "reported";
	// 	break;
	case Ping:
		topicSeg1 = "ping";
		break;
	case Get:
		topicSeg1 = "get";
		break;
	case Ota:
		topicSeg1 = "ota";
		break;
	case Log:
		topicSeg1 = "log";
		break;
	case UpdateAccepted:
		topicSeg1 = "update";
		topicSeg2 = "accepted";
		break;
	case UpdateDelta:
		topicSeg1 = "update";
		topicSeg2 = "delta";
		break;
	// case DesiredAccepted:
	// 	topicSeg1 = "desired";
	// 	topicSeg2 = "accepted";
	// 	break;
	// case ReportedAccepted:
	// 	topicSeg1 = "reported";
	// 	topicSeg2 = "accepted";
	// 	break;
	case PingAccepted:
		topicSeg1 = "ping";
		topicSeg2 = "accepted";
		break;
	case GetAccepted:
		topicSeg1 = "get";
		topicSeg2 = "accepted";
		break;
	default:
		break;
	}
	if (topicSeg1) {
		topicLength = strlen(topicSeg1) + 1;
	}
	if (topicSeg2) {
		topicLength += strlen(topicSeg2) + 1;
	}
	char *topic =
		calloc(strlen(productId) + 1 + strlen(deviceGuid) + 1 + strlen("shadow") + 1 + topicLength, sizeof(char));
	strcat(topic, productId);
	strcat(topic, "/");
	strcat(topic, deviceGuid);
	strcat(topic, "/");
	strcat(topic, "shadow");
	if (topicSeg1) {
		strcat(topic, "/");
		strcat(topic, topicSeg1);
	}
	if (topicSeg2) {
		strcat(topic, "/");
		strcat(topic, topicSeg2);
	}
	return topic;
}

char *six_iot_get_general_topic(char *productId, char *deviceGuid, char *subTopic) {
	int topicLength = strlen(subTopic) + 1;
	char *topic = calloc(strlen(productId) + 1 + strlen(deviceGuid) + 1 + topicLength, sizeof(char));
	strcat(topic, productId);
	strcat(topic, "/");
	strcat(topic, deviceGuid);
	strcat(topic, "/");
	strcat(topic, subTopic);
	return topic;
}