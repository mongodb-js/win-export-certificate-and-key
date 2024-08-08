#define NOMINMAX // otherwise windows.h #defines min and max as macros
#include <vector>
#include <string>
#include <windows.h>

namespace WinExportCertificateAndKey {
struct ExportCertificateAndKeyArgs {
  DWORD store_type;
  std::wstring sys_store_name;
  bool use_thumbprint;
  std::vector<BYTE> thumbprint;
  std::wstring subject;
  std::wstring password_buf;
  bool require_private_key;
};

std::vector<BYTE> ExportCertificateAndKey(const ExportCertificateAndKeyArgs& args);

std::vector<std::vector<BYTE>> ExportAllCertificates(
    const std::wstring& sys_store_name, DWORD store_type);
}
