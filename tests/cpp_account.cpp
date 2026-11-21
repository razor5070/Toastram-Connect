#include "toast_account_v2.h"
#include <cstring>
int main() {
    const char* invalid = R"({"origin":"http://localhost"})";
    uint64_t id = 99;
    if (toast_account_v2_open(reinterpret_cast<const uint8_t*>(invalid), std::strlen(invalid), &id) != 2 || id) return 1;
    if (toast_account_v2_call(42, nullptr, 0, &id) == 0 || id) return 2;
    size_t bytes = 1;
    if (toast_account_v2_copy(42,nullptr,0,&bytes) == 0 || bytes) return 3;
    return toast_account_v2_release(42) == 0 ? 4 : 0;
}
