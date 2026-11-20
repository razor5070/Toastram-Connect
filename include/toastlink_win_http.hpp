#pragma once
#include <filesystem>
#include <fstream>
#include <httplib.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <wincred.h>
#include <windows.h>

namespace toastlink_win_http {
class Binding {
  std::shared_ptr<X509> ca;
  std::string bearer, origin;
  static std::string Hex(const unsigned char *bytes, size_t size) {
    constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < size; ++i) {
      out += digits[bytes[i] >> 4];
      out += digits[bytes[i] & 15];
    }
    return out;
  }

public:
  ~Binding() { SecureZeroMemory(bearer.data(), bearer.size()); }
  bool Available() const { return ca && !bearer.empty(); }
  // Null means no paired profile. An invalid profile returns an unusable
  // binding so the caller cannot silently switch to a legacy credential.
  static std::shared_ptr<Binding> Open(std::string url) {
    if (!url.starts_with("https://"))
      return {};
    if (url.ends_with(":443"))
      url.resize(url.size() - 4);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(url.data()), url.size(),
           hash);
    wchar_t local[32768];
    auto n = GetEnvironmentVariableW(L"LOCALAPPDATA", local, 32768);
    if (!n || n >= 32768)
      return {};
    auto path = std::filesystem::path(local) / L"ToastRAM Connect" /
                L"sessions" / (Hex(hash, sizeof(hash)) + ".json");
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) && !ec)
      return {};
    auto result = std::make_shared<Binding>();
    result->origin = url;
    try {
      std::ifstream input(path, std::ios::binary);
      std::string raw(32769, ' ');
      input.read(raw.data(), raw.size());
      if (!input.eof() || input.gcount() > 32768)
        return result;
      raw.resize(static_cast<size_t>(input.gcount()));
      auto doc = nlohmann::json::parse(raw);
      if (doc.at("version") != 1 || doc.at("origin") != url)
        return result;
      auto pem = doc.at("ca_pem").get<std::string>();
      std::unique_ptr<BIO, decltype(&BIO_free)> bio(
          BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
      if (!bio)
        return result;
      std::shared_ptr<X509> cert(
          PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free);
      unsigned int size = 0;
      if (!cert || !X509_digest(cert.get(), EVP_sha256(), hash, &size))
        return result;
      auto locator = doc.at("locator").get<std::string>();
      if (!locator.starts_with(url + "|") ||
          !locator.ends_with("|" + Hex(hash, size)) ||
          std::count(locator.begin(), locator.end(), '|') != 3 ||
          locator.find('\0') != std::string::npos)
        return result;
      std::wstring target(locator.begin(), locator.end());
      target += L".ToastRAM Connect v1";
      PCREDENTIALW entry = nullptr;
      if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &entry))
        return result;
      std::unique_ptr<void, decltype(&CredFree)> release(entry, CredFree);
      if (entry->CredentialBlobSize % 2 || entry->CredentialBlobSize < 86 ||
          entry->CredentialBlobSize > 512)
        return result;
      auto chars = reinterpret_cast<const wchar_t *>(entry->CredentialBlob);
      for (size_t i = 0; i < entry->CredentialBlobSize / 2; ++i) {
        wchar_t c = chars[i];
        if (!((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
              (c >= L'0' && c <= L'9') || c == L'_' || c == L'-'))
          return result;
      }
      for (size_t i = 0; i < entry->CredentialBlobSize / 2; ++i)
        result->bearer.push_back(static_cast<char>(chars[i]));
      result->ca = std::move(cert);
    } catch (const std::exception &) {
    }
    return result;
  }
  void Apply(httplib::Client &client, bool authenticated) const {
    std::string address = "https://" + client.host();
    if (client.port() != 443)
      address += ":" + std::to_string(client.port());
    if (!client.tls_context() || address != origin)
      throw std::runtime_error("Paired endpoint mismatch");
    auto store = X509_STORE_new();
    if (!store)
      throw std::bad_alloc();
    const bool pinned = ca && X509_STORE_add_cert(store, ca.get()) == 1;
    // Use only the paired CA. On builds with Schannel chain fallback,
    // route chain verification through the explicitly configured OpenSSL store.
#ifdef CPPHTTPLIB_WINDOWS_AUTOMATIC_ROOT_CERTIFICATES_UPDATE
    client.enable_windows_certificate_verification(false);
#endif
    client.enable_server_certificate_verification(true);
    client.enable_server_hostname_verification(true);
    client.enable_system_ca(false);
    client.set_follow_location(false);
    client.set_ca_cert_store(store);
    if (pinned && authenticated)
      client.set_bearer_token_auth(bearer);
  }
  void Redact(std::string &text) const {
    if (bearer.empty())
      return;
    size_t i = 0;
    while ((i = text.find(bearer, i)) != std::string::npos) {
      text.replace(i, bearer.size(), "[redacted]");
      i += 10;
    }
  }
};
} // namespace toastlink_win_http
