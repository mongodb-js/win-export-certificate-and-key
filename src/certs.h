#define NOMINMAX // otherwise windows.h #defines min and max as macros
#include <vector>
#include <string>
#include <windows.h>

namespace WinExportCertificateAndKey {
std::vector<BYTE> ExportCertificateAndKey(
    DWORD store_type,
    const std::wstring& sys_store_name,
    bool use_thumbprint,
    const std::vector<BYTE>& thumbprint,
    const std::wstring& subject,
    const std::wstring& password_buf,
    bool require_private_key);

std::vector<std::vector<BYTE>> ExportAllCertificates(
    const std::wstring& sys_store_name, DWORD store_type);
}
