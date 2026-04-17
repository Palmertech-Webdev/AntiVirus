#include "ContextAwareness.h"

#include <algorithm>
#include <array>
#include <cwctype>

#include "StringUtils.h"

namespace antivirus::agent {
namespace {

bool Contains(std::wstring_view haystack, std::wstring_view needle) {
  return haystack.find(needle) != std::wstring_view::npos;
}

bool ContainsAny(std::wstring_view haystack, std::initializer_list<std::wstring_view> needles) {
  return std::any_of(needles.begin(), needles.end(),
                     [&](const auto needle) { return Contains(haystack, needle); });
}

bool LooksLikeExecutableOrScript(const std::wstring& extension) {
  return extension == L".exe" || extension == L".msi" || extension == L".scr" || extension == L".dll" ||
         extension == L".ps1" || extension == L".bat" || extension == L".cmd" || extension == L".js" ||
         extension == L".jse" || extension == L".vbs" || extension == L".vbe" || extension == L".hta" ||
         extension == L".lnk";
}

bool LooksLikeArchive(const std::wstring& extension) {
  return extension == L".zip" || extension == L".rar" || extension == L".7z" || extension == L".iso";
}

bool LooksLikeMacroDocument(const std::wstring& extension) {
  return extension == L".docm" || extension == L".xlsm" || extension == L".pptm";
}

std::wstring ExtractHostFromUrl(std::wstring_view value) {
  auto lower = ToLowerContextCopy(std::wstring(value));
  const auto scheme = lower.find(L"://");
  if (scheme == std::wstring::npos) {
    return {};
  }

  auto hostStart = scheme + 3;
  auto hostEnd = lower.find_first_of(L"/\\? #\"", hostStart);
  if (hostEnd == std::wstring::npos) {
    hostEnd = lower.size();
  }

  auto host = lower.substr(hostStart, hostEnd - hostStart);
  const auto at = host.rfind(L'@');
  if (at != std::wstring::npos) {
    host = host.substr(at + 1);
  }
  const auto colon = host.find(L':');
  if (colon != std::wstring::npos) {
    host = host.substr(0, colon);
  }
  while (!host.empty() && (host.back() == L'.' || host.back() == L'/')) {
    host.pop_back();
  }
  return host;
}

std::wstring JsonEscape(const std::wstring& value) {
  return Utf8ToWide(EscapeJsonString(value));
}

}  // namespace

std::wstring ToLowerContextCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

bool IsBrowserImagePath(std::wstring_view imagePath) {
  const auto lower = ToLowerContextCopy(std::wstring(imagePath));
  return ContainsAny(lower, {L"\\chrome.exe", L"\\msedge.exe", L"\\firefox.exe", L"\\browser_broker.exe",
                             L"\\chrome_proxy.exe"});
}

bool IsEmailImagePath(std::wstring_view imagePath) {
  const auto lower = ToLowerContextCopy(std::wstring(imagePath));
  return ContainsAny(lower, {L"\\outlook.exe", L"\\thunderbird.exe"});
}

std::wstring DetectBrowserFamily(std::wstring_view imagePath, std::wstring_view parentImagePath,
                                 std::wstring_view commandLine) {
  const auto joined = ToLowerContextCopy(std::wstring(imagePath) + L" " + std::wstring(parentImagePath) + L" " +
                                         std::wstring(commandLine));
  if (Contains(joined, L"msedge")) {
    return L"edge";
  }
  if (Contains(joined, L"chrome")) {
    return L"chrome";
  }
  if (Contains(joined, L"firefox")) {
    return L"firefox";
  }
  return {};
}

std::wstring DetectSourceDomain(std::wstring_view sourceUrl, std::wstring_view commandLine) {
  const auto direct = ExtractHostFromUrl(sourceUrl);
  if (!direct.empty()) {
    return direct;
  }

  const auto command = ToLowerContextCopy(std::wstring(commandLine));
  const auto https = command.find(L"https://");
  const auto http = command.find(L"http://");
  const auto marker = https != std::wstring::npos ? https : http;
  if (marker == std::wstring::npos) {
    return {};
  }

  return ExtractHostFromUrl(command.substr(marker));
}

ContentOriginContext BuildContentOriginContext(const std::filesystem::path& path, std::wstring_view processImagePath,
                                               std::wstring_view parentImagePath, std::wstring_view commandLine,
                                               std::wstring_view observedAt) {
  ContentOriginContext context{};
  context.sourceApplication = std::wstring(processImagePath);
  context.parentApplication = std::wstring(parentImagePath);
  context.browserFamily = DetectBrowserFamily(processImagePath, parentImagePath, commandLine);
  context.browserOriginated = !context.browserFamily.empty() || IsBrowserImagePath(processImagePath) ||
                              IsBrowserImagePath(parentImagePath);
  context.emailOriginated = IsEmailImagePath(processImagePath) || IsEmailImagePath(parentImagePath);
  context.webmailOriginated = context.browserOriginated &&
                              ContainsAny(ToLowerContextCopy(std::wstring(commandLine)),
                                          {L"mail.google.com", L"outlook.office.com", L"outlook.live.com",
                                           L"mail.yahoo.com", L"proton.me/mail"});
  context.attachmentOriginated = context.emailOriginated || context.webmailOriginated;
  context.observedAt = std::wstring(observedAt);

  const auto lowerCommand = ToLowerContextCopy(std::wstring(commandLine));
  const auto lowerPath = ToLowerContextCopy(path.wstring());
  const auto extension = ToLowerContextCopy(path.extension().wstring());
  const auto fileName = ToLowerContextCopy(path.filename().wstring());

  context.browserExtensionHost =
      ContainsAny(lowerCommand, {L"--extension-process", L"--type=extension", L"extensionhost", L"moz-extension://"});
  context.abusivePermissionPrompt =
      ContainsAny(lowerCommand, {L"notification", L"push", L"permission", L"allow-notifications"});
  context.downloadOriginated =
      context.browserOriginated &&
      (ContainsAny(lowerPath, {L"\\downloads\\", L"\\desktop\\"}) || LooksLikeExecutableOrScript(extension) ||
       LooksLikeArchive(extension));
  context.browserLaunchedFile =
      context.browserOriginated && LooksLikeExecutableOrScript(extension) &&
      (ContainsAny(lowerCommand, {L"shellopen", L"open", L"launch"}) || ContainsAny(lowerPath, {L"\\downloads\\", L"\\desktop\\"}));
  context.suspiciousChildProcess =
      context.browserOriginated &&
      ContainsAny(ToLowerContextCopy(std::wstring(processImagePath)),
                  {L"\\powershell.exe", L"\\cmd.exe", L"\\wscript.exe", L"\\cscript.exe", L"\\mshta.exe",
                   L"\\rundll32.exe"});
  context.fakeUpdatePattern =
      context.browserOriginated && LooksLikeExecutableOrScript(extension) &&
      ContainsAny(fileName, {L"update", L"urgent", L"browser", L"chrome", L"edge", L"firefox", L"adobe",
                             L"flash", L"java", L"security_fix", L"plugin"});
  context.suspiciousLureName =
      ContainsAny(fileName, {L"invoice", L"payment", L"remittance", L"reset", L"verify", L"urgent", L"action_required",
                             L"payroll", L"benefits", L"delivery", L"parcel", L"voicemail"});
  context.passwordProtectedArchivePattern =
      LooksLikeArchive(extension) &&
      ContainsAny(fileName, {L"password", L"protected", L"secure", L"unlock", L"open_me"});
  context.macroDocument = LooksLikeMacroDocument(extension);

  if (context.browserExtensionHost) {
    context.navigationType = L"browser_extension_host";
  } else if (context.abusivePermissionPrompt) {
    context.navigationType = L"browser_permission_prompt";
  } else if (ContainsAny(lowerCommand, {L"redirect=", L"continue=", L"target=", L"return="})) {
    context.navigationType = L"redirect_navigation";
  } else if (context.downloadOriginated) {
    context.navigationType = L"download_initiation";
  } else if (context.browserLaunchedFile) {
    context.navigationType = L"browser_launched_file";
  } else if (context.browserOriginated) {
    context.navigationType = L"typed_or_clicked_navigation";
  } else if (context.attachmentOriginated) {
    context.navigationType = L"email_attachment";
  }

  context.sourceDomain = DetectSourceDomain(context.sourceUrl, commandLine);

  if (context.attachmentOriginated) {
    context.channel = L"email";
  } else if (context.browserOriginated) {
    context.channel = L"browser";
  } else {
    context.channel = L"system";
  }

  return context;
}

std::vector<OriginSignal> CollectContentOriginSignals(const ContentOriginContext& context,
                                                      const std::filesystem::path& path) {
  std::vector<OriginSignal> signals;
  const auto extension = ToLowerContextCopy(path.extension().wstring());

  if (context.downloadOriginated) {
    signals.push_back({L"BROWSER_DOWNLOAD_CONTEXT",
                       L"Fenrir preserved browser download context for this file.", 12});
  }
  if (context.browserLaunchedFile) {
    signals.push_back({L"BROWSER_LAUNCHED_FILE",
                       L"Fenrir saw a browser-origin file launch rather than a generic system open.", 14});
  }
  if (context.browserExtensionHost) {
    signals.push_back({L"BROWSER_EXTENSION_HOST",
                       L"Browser extension host context increased scrutiny for this activity.", 10});
  }
  if (context.abusivePermissionPrompt) {
    signals.push_back({L"ABUSIVE_NOTIFICATION_PROMPT",
                       L"Browser permission or notification prompt context matched a common scam delivery pattern.", 18});
  }
  if (context.suspiciousChildProcess) {
    signals.push_back({L"BROWSER_CHILD_PROCESS_ABUSE",
                       L"Browser context launched a script or proxy process associated with drive-by abuse.", 22});
  }
  if (context.fakeUpdatePattern) {
    signals.push_back({L"FAKE_UPDATE_DOWNLOAD_PATTERN",
                       L"Filename and browser context resemble a fake update or fake download lure.", 24});
  }
  if (context.attachmentOriginated) {
    signals.push_back({L"EMAIL_ATTACHMENT_CONTEXT",
                       L"Fenrir treated this artifact as email-origin content.", 16});
  }
  if (context.webmailOriginated) {
    signals.push_back({L"WEBMAIL_ATTACHMENT_CONTEXT",
                       L"Webmail browser context indicates this artifact likely arrived through email.", 10});
  }
  if (context.suspiciousLureName) {
    signals.push_back({L"EMAIL_LURE_FILENAME",
                       L"Filename wording matches common invoice, reset, delivery, or urgent-issue lures.", 14});
  }
  if (context.passwordProtectedArchivePattern) {
    signals.push_back({L"PASSWORD_PROTECTED_ARCHIVE_PATTERN",
                       L"Archive naming suggests a password-protected delivery pattern often used to evade inspection.", 18});
  }
  if (context.macroDocument) {
    signals.push_back({L"MACRO_DOCUMENT_CONTEXT",
                       L"Macro-capable Office content received extra scrutiny in the current delivery context.", 12});
  }

  if ((context.attachmentOriginated || context.downloadOriginated) &&
      (extension == L".lnk" || extension == L".hta" || extension == L".ps1" || extension == L".js" ||
       extension == L".vbs")) {
    signals.push_back({L"DELIVERED_SCRIPT_OR_SHORTCUT",
                       L"Delivered script or shortcut content is high risk in browser and email channels.", 20});
  }

  return signals;
}

std::wstring BuildContentOriginLabel(const ContentOriginContext& context) {
  if (context.attachmentOriginated) {
    if (!context.sourceApplication.empty()) {
      return L"Email attachment via " + std::filesystem::path(context.sourceApplication).filename().wstring();
    }
    return L"Email attachment";
  }

  if (context.browserOriginated) {
    std::wstring browser = context.browserFamily.empty() ? L"Browser" : context.browserFamily;
    if (!browser.empty()) {
      browser[0] = static_cast<wchar_t>(std::towupper(browser[0]));
    }
    if (context.browserLaunchedFile) {
      return browser + L" launched file";
    }
    if (context.downloadOriginated) {
      return browser + L" download";
    }
    return browser + L" web activity";
  }

  return L"Local file activity";
}

std::wstring SerializeContentOriginContext(const ContentOriginContext& context) {
  return std::wstring(L"{\"channel\":\"") + JsonEscape(context.channel) +
         L"\",\"browserFamily\":\"" + JsonEscape(context.browserFamily) +
         L"\",\"sourceApplication\":\"" + JsonEscape(context.sourceApplication) +
         L"\",\"parentApplication\":\"" + JsonEscape(context.parentApplication) +
         L"\",\"sourceDomain\":\"" + JsonEscape(context.sourceDomain) +
         L"\",\"sourceUrl\":\"" + JsonEscape(context.sourceUrl) +
         L"\",\"navigationType\":\"" + JsonEscape(context.navigationType) +
         L"\",\"observedAt\":\"" + JsonEscape(context.observedAt) +
         L"\",\"browserOriginated\":" + (context.browserOriginated ? std::wstring(L"true") : std::wstring(L"false")) +
         L",\"emailOriginated\":" + (context.emailOriginated ? std::wstring(L"true") : std::wstring(L"false")) +
         L",\"webmailOriginated\":" + (context.webmailOriginated ? std::wstring(L"true") : std::wstring(L"false")) +
         L",\"attachmentOriginated\":" + (context.attachmentOriginated ? std::wstring(L"true") : std::wstring(L"false")) +
         L",\"downloadOriginated\":" + (context.downloadOriginated ? std::wstring(L"true") : std::wstring(L"false")) +
         L",\"browserLaunchedFile\":" + (context.browserLaunchedFile ? std::wstring(L"true") : std::wstring(L"false")) +
         L",\"browserExtensionHost\":" + (context.browserExtensionHost ? std::wstring(L"true") : std::wstring(L"false")) +
         L",\"abusivePermissionPrompt\":" + (context.abusivePermissionPrompt ? std::wstring(L"true") : std::wstring(L"false")) +
         L",\"suspiciousChildProcess\":" + (context.suspiciousChildProcess ? std::wstring(L"true") : std::wstring(L"false")) +
         L",\"fakeUpdatePattern\":" + (context.fakeUpdatePattern ? std::wstring(L"true") : std::wstring(L"false")) +
         L",\"suspiciousLureName\":" + (context.suspiciousLureName ? std::wstring(L"true") : std::wstring(L"false")) +
         L",\"passwordProtectedArchivePattern\":" +
         (context.passwordProtectedArchivePattern ? std::wstring(L"true") : std::wstring(L"false")) +
         L",\"macroDocument\":" + (context.macroDocument ? std::wstring(L"true") : std::wstring(L"false")) +
         L"}";
}

}  // namespace antivirus::agent
