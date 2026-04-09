#pragma once

#include <string>

namespace antivirus::agent {

std::string WideToUtf8(const std::wstring& value);
std::wstring Utf8ToWide(const std::string& value);
std::wstring ReadEnvironmentVariable(const wchar_t* name);
std::string EscapeJsonString(const std::wstring& value);
std::string TrimCopy(std::string value);
std::wstring CurrentUtcTimestamp();
std::wstring GenerateGuidString();

}  // namespace antivirus::agent
