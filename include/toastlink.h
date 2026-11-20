/* ToastRAM Connect C ABI (draft, not yet released).
 * Offline import only: parses CA certificate structure but performs no
 * TLS identity verification or enrollment.
 * Link to toastlink_ffi's platform-specific static or shared library.
 */
#ifndef TOASTLINK_H
#define TOASTLINK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ToastLinkHandle ToastLinkHandle;

enum {
    TOASTLINK_OK = 0,
    TOASTLINK_INVALID_ARGUMENT = 1,
    TOASTLINK_INVALID_FILE = 2,
    TOASTLINK_BUFFER_TOO_SMALL = 3,
    TOASTLINK_INTERNAL_ERROR = 4,
    TOASTLINK_EXPIRED = 5,           /* Request a fresh connection file. */
    TOASTLINK_UNSUPPORTED_FORMAT = 6 /* Unsupported version or format. */
};

/* The caller owns the returned handle. data must remain readable during call.
 * out_handle is set to NULL before parsing; no network operation is performed.
 */
int32_t toastlink_import_json(const uint8_t *data, size_t len,
                              ToastLinkHandle **out_handle);

/* Returns a NUL-terminated JSON string without enrollment secrets.
 * If buffer capacity is too small, sets *required (including trailing NUL)
 * and returns TOASTLINK_BUFFER_TOO_SMALL. Caller allocates the buffer.
 * status in returned JSON is ALWAYS "unverified" in this milestone.
 */
int32_t toastlink_metadata_json(const ToastLinkHandle *handle, char *buffer,
                                 size_t capacity, size_t *required);

/* NULL is accepted; all other pointers must be live, SDK-issued handles. */
void toastlink_free(ToastLinkHandle *handle);

#ifdef __cplusplus
}
#endif
#endif
