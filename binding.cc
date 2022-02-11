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
void ThrowWindowsError(Env env, const char* call) {
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
  throw Error::New(env, buf);
}

// Create a temporary certificate store, add 'cert' to it, and then
// export it (using 'password' for encryption).
Buffer<BYTE> CertToBuffer(Env env, PCCERT_CONTEXT cert, LPCWSTR password, bool require_priv_key) {
  HCERTSTORE memstore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, 0);
  if (!memstore) {
    ThrowWindowsError(env, "CertOpenStore(CERT_STORE_PROV_MEMORY)");
  }
  Cleanup cleanup([&]() { CertCloseStore(memstore, 0); });
  if (!CertAddCertificateContextToStore(memstore, cert, CERT_STORE_ADD_ALWAYS, nullptr)) {
    ThrowWindowsError(env, "CertAddCertificateContextToStore()");
  }

  CRYPT_DATA_BLOB out = { 0, nullptr };
  DWORD export_flags = EXPORT_PRIVATE_KEYS;
  if (require_priv_key) {
    export_flags |= REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY;
  }
  if (!PFXExportCertStoreEx(memstore, &out, password, nullptr, export_flags)) {
    ThrowWindowsError(env, "PFXExportCertStoreEx()");
  }
  Buffer<BYTE> outbuf = Buffer<BYTE>::New(env, out.cbData);
  out.pbData = outbuf.Data();
  if (!PFXExportCertStoreEx(memstore, &out, password, nullptr, export_flags)) {
    ThrowWindowsError(env, "PFXExportCertStoreEx()");
  }

  return outbuf;
}

// Export a given certificate from a system certificate store,
// identified either by its thumbprint or its subject line.
Value ExportCertificate(const CallbackInfo& args) {
  std::wstring password_buf = MultiByteToWideChar(args[0].ToString());
  LPCWSTR password = password_buf.data();
  std::wstring sys_store_name = MultiByteToWideChar(args[1].ToString());
  HCERTSTORE sys_cs = CertOpenSystemStoreW(0, sys_store_name.data());
  if (!sys_cs) {
    ThrowWindowsError(args.Env(), "CertOpenSystemStoreA()");
  }
  Cleanup cleanup_sys_cs([&]() { CertCloseStore(sys_cs, 0); });

  PCCERT_CONTEXT cert = nullptr;
  Object search_spec = args[2].ToObject();
  if (search_spec.HasOwnProperty("thumbprint")) {
    Buffer<BYTE> thumbprint = search_spec.Get("thumbprint").As<Buffer<BYTE>>();
    CRYPT_HASH_BLOB thumbprint_blob = {
      static_cast<DWORD>(thumbprint.Length()),
      thumbprint.Data()
    };
    cert = CertFindCertificateInStore(
        sys_cs,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_HASH,
        &thumbprint_blob,
        nullptr);
  } else if (search_spec.HasOwnProperty("subject")) {
    cert = CertFindCertificateInStore(
        sys_cs,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_STR,
        MultiByteToWideChar(search_spec.Get("subject").ToString()).data(),
        nullptr);
  } else {
    SetLastError(CRYPT_E_NOT_FOUND);
  }
  if (!cert) {
    ThrowWindowsError(args.Env(), "CertFindCertificateInStore()");
  }

  Cleanup cleanup_cert([&]() { CertFreeCertificateContext(cert); });

  return CertToBuffer(args.Env(), cert, password, args[3].ToBoolean());
}

}

static Object InitWinExportCertAndKey(Env env, Object exports) {
  exports["exportCertificate"] = Function::New(env, ExportCertificate);
  return exports;
}

NODE_API_MODULE(win_export_cert, InitWinExportCertAndKey)