#define NOMINMAX // otherwise windows.h #defines min and max as macros
#include <limits>
#include <napi.h>
#include <windows.h>
#include <wincrypt.h>

using namespace Napi;

namespace {

// Naive RAII cleanup helper.
struct Cleanup {
  std::function<void()> fn;
  Cleanup(std::function<void()> fn) : fn(fn) {}
  ~Cleanup() { fn(); }
};

// Convert UTF-8 to a Windows UTF-16 wstring.
std::wstring MultiByteToWideChar(Value value) {
  static_assert(sizeof(std::wstring::value_type) == sizeof(std::u16string::value_type),
      "wstring and u16string have the same value type on Windows");
  std::u16string u16 = value.ToString();
  return std::wstring(u16.begin(), u16.end());
}

// Throw an exception based on the last Windows error message.
void ThrowWindowsError(const char* call) {
  DWORD err = GetLastError();
  CHAR err_msg_buf[128];

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

  char buf[256];
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

std::vector<BYTE> ExportCertificateAndKey(
    DWORD store_type,
    const std::wstring& sys_store_name,
    bool use_thumbprint,
    const std::vector<BYTE>& thumbprint,
    const std::wstring& subject,
    const std::wstring& password_buf,
    bool require_private_key) {
  LPCWSTR password = password_buf.data();
  CertStoreHandle sys_cs = CertOpenStore(sys_store_name, store_type);
  PCCERT_CONTEXT cert = nullptr;

  if (use_thumbprint) {
    CRYPT_HASH_BLOB thumbprint_blob = {
      static_cast<DWORD>(thumbprint.size()),
      const_cast<BYTE*>(thumbprint.data())
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
        subject.data(),
        nullptr);
  } 
  
  if (!cert) {
    ThrowWindowsError("CertFindCertificateInStore()");
  }

  Cleanup cleanup_cert([&]() { CertFreeCertificateContext(cert); });

  DWORD export_flags = EXPORT_PRIVATE_KEYS;
  if (require_private_key) {
    export_flags |= REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY;
  }
  return CertToBuffer(cert, password, export_flags);
}


Value ExportAllCertificatesSync(const CallbackInfo& args) {
  std::wstring sys_store_name = MultiByteToWideChar(args[0].ToString());
  DWORD store_type = args[1].ToNumber().Uint32Value();

  try {
    std::vector<std::vector<BYTE>> certs =
        ExportAllCertificates(sys_store_name, store_type);
    if (certs.size() > static_cast<uint32_t>(-1)) {
      throw std::runtime_error("result length exceeds uint32 max");
    }
    Array result = Array::New(args.Env());
    for (uint32_t i = 0; i < certs.size(); i++) {
      result[i] = Buffer<BYTE>::Copy(args.Env(), certs[i].data(), certs[i].size());
    }
    return result;
  } catch (const std::exception& e) {
    throw Error::New(args.Env(), e.what());
  }
}

// Export a given certificate from a system certificate store,
// identified either by its thumbprint or its subject line.
Value ExportCertificateAndKeySync(const CallbackInfo& args) {
  std::wstring password_buf = MultiByteToWideChar(args[0].ToString());
  std::wstring sys_store_name = MultiByteToWideChar(args[1].ToString());
  DWORD store_type = args[2].ToNumber().Uint32Value();
  bool use_thumbprint;
  std::vector<BYTE> thumbprint;
  std::wstring subject;
  bool require_private_key = args[4].ToBoolean();

  Object search_spec = args[3].ToObject();
  if (search_spec.HasOwnProperty("thumbprint")) {
    use_thumbprint = true;
    Buffer<BYTE> thumbprint_buf = search_spec.Get("thumbprint").As<Buffer<BYTE>>();
    thumbprint = {thumbprint_buf.Data(), thumbprint_buf.Data() + thumbprint_buf.Length()};
  } else if (search_spec.HasOwnProperty("subject")) {
    use_thumbprint = false;
    subject = MultiByteToWideChar(search_spec.Get("subject").ToString());
  } else {
    throw Error::New(args.Env(), "Need to specify either `thumbprint` or `subject`");
  }
  try {
    auto result = ExportCertificateAndKey(
        store_type, sys_store_name, use_thumbprint, thumbprint, subject, password_buf, require_private_key);
    return Buffer<BYTE>::Copy(args.Env(), result.data(), result.size());
  } catch (const std::exception& e) {
    throw Error::New(args.Env(), e.what());
  }
}

}

static Object InitWinExportCertAndKey(Env env, Object exports) {
  exports["exportCertificateAndKey"] = Function::New(env, ExportCertificateAndKeySync);
  exports["exportAllCertificates"] = Function::New(env, ExportAllCertificatesSync);
  Object storeTypes = Object::New(env);
  storeTypes["CERT_SYSTEM_STORE_CURRENT_SERVICE"] = Number::New(env, CERT_SYSTEM_STORE_CURRENT_SERVICE);
  storeTypes["CERT_SYSTEM_STORE_CURRENT_USER"] = Number::New(env, CERT_SYSTEM_STORE_CURRENT_USER);
  storeTypes["CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY"] = Number::New(env, CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY);
  storeTypes["CERT_SYSTEM_STORE_LOCAL_MACHINE"] = Number::New(env, CERT_SYSTEM_STORE_LOCAL_MACHINE);
  storeTypes["CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE"] = Number::New(env, CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE);
  storeTypes["CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY"] = Number::New(env, CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY);
  storeTypes["CERT_SYSTEM_STORE_SERVICES"] = Number::New(env, CERT_SYSTEM_STORE_SERVICES);
  storeTypes["CERT_SYSTEM_STORE_USERS"] = Number::New(env, CERT_SYSTEM_STORE_USERS);
  exports["storeTypes"] = storeTypes;
  return exports;
}

NODE_API_MODULE(win_export_cert, InitWinExportCertAndKey)