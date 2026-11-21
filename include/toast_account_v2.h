#pragma once
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Windows account ABI v2. Inputs are bounded UTF-8 JSON, never NUL-terminated.
   All non-null pointers must denote valid caller-owned storage of the given size.
   On success release every returned ID exactly once. A null destination with
   capacity zero queries the result byte length. Calls may block on HTTPS. */
int32_t toast_account_v2_open(const uint8_t*, size_t, uint64_t* client);
int32_t toast_account_v2_call(uint64_t client,const uint8_t*,size_t,uint64_t* result);
int32_t toast_account_v2_copy(uint64_t result,uint8_t* destination,size_t capacity,size_t* size);
/* Offline deletion for exactly this origin and trust selection. No server revocation. */
int32_t toast_account_v2_forget_local(const uint8_t* options, size_t size);
int32_t toast_account_v2_release(uint64_t handle);
#ifdef __cplusplus
}
#endif
