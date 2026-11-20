#pragma once
#include "toastlink.h"
#include <memory>
#include <string>
#include <vector>

namespace toastlink {
struct release_handle {
    void operator()(ToastLinkHandle* handle) const noexcept { toastlink_free(handle); }
};
using imported_file = std::unique_ptr<ToastLinkHandle, release_handle>;

// A failed replacement preserves the caller's previous import.
inline int32_t import_file(const uint8_t* bytes, size_t length, imported_file& output) {
    ToastLinkHandle* raw = nullptr;
    auto status = toastlink_import_json(bytes, length, &raw);
    imported_file next(raw);
    if (status == TOASTLINK_OK) output.swap(next);
    return status;
}

inline int32_t metadata(const imported_file& file, std::string& output) {
    size_t required = 0;
    auto status = toastlink_metadata_json(file.get(), nullptr, 0, &required);
    if (status != TOASTLINK_BUFFER_TOO_SMALL) return status;
    std::vector<char> buffer(required);
    status = toastlink_metadata_json(file.get(), buffer.data(), buffer.size(), &required);
    if (status == TOASTLINK_OK) output.assign(buffer.data(), required - 1);
    return status;
}
}
