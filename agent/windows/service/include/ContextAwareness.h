#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace antivirus::agent {

struct OriginSignal {
  std::wstring code;
  std::wstring message;
  int score{0};
};

struct ContentOriginContext {
  std::wstring channel;
  std::wstring browserFamily;
  std::wstring sourceApplication;
  std::wstring parentApplication;
  std::wstring sourceDomain;
  std::wstring sourceUrl;
  std::wstring navigationType;
  std::wstring observedAt;
  bool browserOriginated{false};
  bool emailOriginated{false};
  bool webmailOriginated{false};
  bool attachmentOriginated{false};
  bool downloadOriginated{false};
  bool browserLaunchedFile{false};
  bool browserExtensionHost{false};
  bool abusivePermissionPrompt{false};
  bool suspiciousChildProcess{false};
  bool fakeUpdatePattern{false};
  bool suspiciousLureName{false};
  bool passwordProtectedArchivePattern{false};
  bool macroDocument{false};
};

std::wstring ToLowerContextCopy(std::wstring value);
bool IsBrowserImagePath(std::wstring_view imagePath);
bool IsEmailImagePath(std::wstring_view imagePath);
std::wstring DetectBrowserFamily(std::wstring_view imagePath, std::wstring_view parentImagePath,
                                 std::wstring_view commandLine);
std::wstring DetectSourceDomain(std::wstring_view sourceUrl, std::wstring_view commandLine);
ContentOriginContext BuildContentOriginContext(const std::filesystem::path& path, std::wstring_view processImagePath,
                                               std::wstring_view parentImagePath, std::wstring_view commandLine,
                                               std::wstring_view observedAt = {});
std::vector<OriginSignal> CollectContentOriginSignals(const ContentOriginContext& context,
                                                      const std::filesystem::path& path);
std::wstring BuildContentOriginLabel(const ContentOriginContext& context);
std::wstring SerializeContentOriginContext(const ContentOriginContext& context);

}  // namespace antivirus::agent
