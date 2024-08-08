#include "certs.h"
#include <functional>
#include <stdexcept>
#include <wincrypt.h>

namespace WinExportCertificateAndKey {
namespace {

// Naive RAII cleanup helper.
struct Cleanup {
  std::function<void()> fn;
  Cleanup(std::function<void()> fn) : fn(fn) {}
  ~Cleanup() { fn(); }
};

// Throw an exception based on the last Windows error message.
void ThrowWindowsError(const char* call) {
  DWORD err = GetLastError();
  CHAR err_msg_buf[256] = {};

  FormatMessageA(
      FORMAT_MESSAGE_FROM_SYSTEM |
      FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr,
      err,
      0,
      err_msg_buf,
      sizeof(err_msg_buf),
      nullptr);
  err_msg_buf[sizeof(err_msg_buf) - 1] = '\0';
  size_t err_msg_len = strlen(err_msg_buf);
  if (err_msg_len > 0 && err_msg_buf[err_msg_len - 1] == '\n') {
    err_msg_buf[strlen(err_msg_buf) - 1] = '\0';
    if (err_msg_len > 1 && err_msg_buf[err_msg_len - 2] == '\r') {
      err_msg_buf[err_msg_len - 2] = '\0';
    }
  }

  char buf[384] = {};
  snprintf(buf,
           sizeof(buf),
           "%s failed with: %s (0x%lx)",
           call,
           err_msg_buf,
           static_cast<unsigned long>(err));
  throw std::runtime_error(buf);
}

// Create a temporary certificate store, add 'cert' to it, and then
// export it (using 'password' for encryption).
std::vector<BYTE> CertToBuffer(PCCERT_CONTEXT cert, LPCWSTR password, DWORD export_flags) {
  HCERTSTORE memstore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, 0);
  if (!memstore) {
    ThrowWindowsError("CertOpenStore(CERT_STORE_PROV_MEMORY)");
  }
  Cleanup cleanup([&]() { CertCloseStore(memstore, 0); });
  if (!CertAddCertificateContextToStore(memstore, cert, CERT_STORE_ADD_ALWAYS, nullptr)) {
    ThrowWindowsError("CertAddCertificateContextToStore()");
  }

  CRYPT_DATA_BLOB out = { 0, nullptr };
  if (!PFXExportCertStoreEx(memstore, &out, password, nullptr, export_flags)) {
    ThrowWindowsError("PFXExportCertStoreEx()");
  }
  std::vector<BYTE> outbuf(out.cbData);
  out.pbData = outbuf.data();
  if (!PFXExportCertStoreEx(memstore, &out, password, nullptr, export_flags)) {
    ThrowWindowsError("PFXExportCertStoreEx()");
  }

  return outbuf;
}

class CertStoreHandle {
 public:
  CertStoreHandle(HCERTSTORE store) : store_(store) {}
  ~CertStoreHandle() {
    CertCloseStore(store_, 0);
    if (current_cert_) {
      CertFreeCertificateContext(current_cert_);
    }
  }
  HCERTSTORE get() const { return store_; }
  operator boolean() const { return !!get(); }

  CertStoreHandle(CertStoreHandle&& other)
    : store_(other.store_), current_cert_(other.current_cert_) {
    other.store_ = nullptr;
    other.current_cert_ = nullptr;
  }
  CertStoreHandle& operator=(CertStoreHandle&& other) {
    this->~CertStoreHandle();
    return *new(this)CertStoreHandle(std::move(other));
  }

  PCCERT_CONTEXT next() {
    current_cert_ = CertEnumCertificatesInStore(store_, current_cert_);
    return current_cert_;
  }

 private:
  CertStoreHandle(const CertStoreHandle&) = delete;
  CertStoreHandle& operator=(const CertStoreHandle&) = delete;

  HCERTSTORE store_;
  PCCERT_CONTEXT current_cert_ = nullptr;
};

CertStoreHandle CertOpenStore(const std::wstring& name, DWORD type) {
  CertStoreHandle sys_cs = ::CertOpenStore(
    CERT_STORE_PROV_SYSTEM,
    0,
    NULL,
    type | CERT_STORE_READONLY_FLAG | CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG,
    name.data());
  if (!sys_cs) {
    ThrowWindowsError("CertOpenStore()");
  }
  return sys_cs;
}
} // anonymous namespace

std::vector<std::vector<BYTE>> ExportAllCertificates(
    const std::wstring& sys_store_name, DWORD store_type) {
  CertStoreHandle sys_cs = CertOpenStore(sys_store_name, store_type);

  PCCERT_CONTEXT cert;
  std::vector<std::vector<BYTE>> result;
  while (cert = sys_cs.next()) {
    result.emplace_back(cert->pbCertEncoded, cert->pbCertEncoded + cert->cbCertEncoded);
  }
  return result;
}

std::vector<BYTE> ExportCertificateAndKey(const ExportCertificateAndKeyArgs& args) {
  LPCWSTR password = args.password_buf.data();
  CertStoreHandle sys_cs = CertOpenStore(args.sys_store_name, args.store_type);
  PCCERT_CONTEXT cert = nullptr;

  if (args.use_thumbprint) {
    CRYPT_HASH_BLOB thumbprint_blob = {
      static_cast<DWORD>(args.thumbprint.size()),
      const_cast<BYTE*>(args.thumbprint.data())
    };
    cert = CertFindCertificateInStore(
        sys_cs.get(),
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_HASH,
        &thumbprint_blob,
        nullptr);
  } else {
    cert = CertFindCertificateInStore(
        sys_cs.get(),
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_STR,
        args.subject.data(),
        nullptr);
  } 
  
  if (!cert) {
    ThrowWindowsError("CertFindCertificateInStore()");
  }

  Cleanup cleanup_cert([&]() { CertFreeCertificateContext(cert); });

  DWORD export_flags = EXPORT_PRIVATE_KEYS;
  if (args.require_private_key) {
    export_flags |= REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY;
  }
  return CertToBuffer(cert, password, export_flags);
}

}  // namespace WinExportCertificateAndKey {