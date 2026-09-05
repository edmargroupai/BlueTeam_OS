#pragma once
/* Narrow ABI placeholder. No general service logic. */

#ifdef __cplusplus
extern "C" {
#endif

#define BTOS_NATIVE_ABI 1

struct btos_parse_result {
    int status;
    const char *error;
};

#ifdef __cplusplus
}
#endif
