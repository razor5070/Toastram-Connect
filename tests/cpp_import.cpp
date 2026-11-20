#include "toastlink.hpp"
#include <iostream>
#include <fstream>
#include <iterator>

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    std::ifstream input(argv[1], std::ios::binary);
    if (!input) return 2;
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input), {}};
    toastlink::imported_file file;
    if (toastlink::import_file(bytes.data(), bytes.size(), file) != TOASTLINK_OK) return 1;
    std::string metadata;
    if (toastlink::metadata(file, metadata) != TOASTLINK_OK) return 1;
    if (toastlink::import_file(nullptr, 0, file) != TOASTLINK_INVALID_ARGUMENT || !file) return 1;
    std::string again;
    if (toastlink::metadata(file, again) != TOASTLINK_OK || again != metadata) return 1;
    return 0;
}
