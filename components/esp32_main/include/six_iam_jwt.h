#ifndef __SIX_IAM_JWT_H__
#define __SIX_IAM_JWT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdio.h>

typedef enum { Second, MilliSecond } EXP_UNIT_T;

char *six_iam_create_jwt(const char *device_global_uuid, const char *private_key);

bool six_iam_token_expired(const char *token, EXP_UNIT_T unit);

#ifdef __cplusplus
}
#endif

#endif
