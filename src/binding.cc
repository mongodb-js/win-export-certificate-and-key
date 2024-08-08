#include "certs.h"
#include <napi.h>

namespace {
using namespace Napi;
using namespace WinExportCertificateAndKey;

Array BufferListToArray(Env env, const std::vector<std::vector<BYTE>>& vec) {
  Array ret = Array::New(env);
  if (vec.size() > static_cast<uint32_t>(-1)) {
    throw std::runtime_error("result length exceeds uint32 max");
  }
  for (uint32_t i = 0; i < vec.size(); i++) {
    ret[i] = Buffer<BYTE>::Copy(env, vec[i].data(), vec[i].size());
  }
  return ret;
}

// Convert UTF-8 to a Windows UTF-16 wstring.
std::wstring MultiByteToWideChar(Value value) {
  static_assert(sizeof(std::wstring::value_type) == sizeof(std::u16string::value_type),
      "wstring and u16string have the same value type on Windows");
  std::u16string u16 = value.ToString();
  return std::wstring(u16.begin(), u16.end());
}

Value ExportAllCertificatesSync(const CallbackInfo& args) {
  std::wstring sys_store_name = MultiByteToWideChar(args[0].ToString());
  DWORD store_type = args[1].ToNumber().Uint32Value();

  try {
    return BufferListToArray(
        args.Env(), ExportAllCertificates(sys_store_name, store_type));
  } catch (const std::exception& e) {
    throw Error::New(args.Env(), e.what());
  }
}

// Export a given certificate from a system certificate store,
// identified either by its thumbprint or its subject line.
Value ExportCertificateAndKeySync(const CallbackInfo& args) {
  ExportCertificateAndKeyArgs exp_args;
  exp_args.password_buf = MultiByteToWideChar(args[0].ToString());
  exp_args.sys_store_name = MultiByteToWideChar(args[1].ToString());
  exp_args.store_type = args[2].ToNumber().Uint32Value();
  exp_args.require_private_key = args[4].ToBoolean();

  Object search_spec = args[3].ToObject();
  if (search_spec.HasOwnProperty("thumbprint")) {
    exp_args.use_thumbprint = true;
    Buffer<BYTE> thumbprint = search_spec.Get("thumbprint").As<Buffer<BYTE>>();
    exp_args.thumbprint = {thumbprint.Data(), thumbprint.Data() + thumbprint.Length()};
  } else if (search_spec.HasOwnProperty("subject")) {
    exp_args.use_thumbprint = false;
    exp_args.subject = MultiByteToWideChar(search_spec.Get("subject").ToString());
  } else {
    throw Error::New(args.Env(), "Need to specify either `thumbprint` or `subject`");
  }
  try {
    auto result = ExportCertificateAndKey(exp_args);
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