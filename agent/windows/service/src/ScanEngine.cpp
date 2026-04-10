#include "ScanEngine.h"

#include <Windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <mutex>
#include <optional>
#include <sstream>
#include <string_view>
#include <system_error>

#include "CryptoUtils.h"
#include "ReputationLookup.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

constexpr std::size_t kReadLimit = 1024 * 1024;
constexpr int kDetectThreshold = 45;
constexpr int kQuarantineThreshold = 70;

struct Hit {
  std::wstring code;
  std::wstring message;
  std::wstring tacticId;
  std::wstring techniqueId;
  int score{0};
};

struct Rule {
  std::wstring scope;
  std::wstring code;
  std::wstring message;
  std::wstring tacticId;
  std::wstring techniqueId;
  int score{0};
  std::vector<std::wstring> patterns;
};

struct FileData {
  std::filesystem::path path;
  std::uintmax_t sizeBytes{0};
  std::wstring extension;
  std::wstring fileNameLower;
  std::wstring contentType;
  std::wstring signer;
  std::wstring reputation;
  std::wstring sha256;
  std::wstring textLower;
  std::wstring asciiLower;
  std::wstring zipEntryNamesLower;
  std::vector<unsigned char> bytes;
  bool userPath{false};
  bool trustedPath{false};
  bool pe{false};
  bool zip{false};
  bool ole{false};
  bool lnk{false};
  double entropy{0.0};
  std::uint32_t archiveEntryCount{0};
};

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring TrimWide(std::wstring value) {
  const auto first = value.find_first_not_of(L" \t\r\n");
  if (first == std::wstring::npos) {
    return {};
  }

  const auto last = value.find_last_not_of(L" \t\r\n");
  return value.substr(first, last - first + 1);
}

bool Contains(std::wstring_view haystack, std::wstring_view needle) {
  return haystack.find(needle) != std::wstring_view::npos;
}

bool ContainsAny(std::wstring_view haystack, std::initializer_list<std::wstring_view> needles) {
  return std::any_of(needles.begin(), needles.end(),
                     [haystack](const auto needle) { return Contains(haystack, needle); });
}

bool UserPath(const std::filesystem::path& path) {
  const auto lower = ToLowerCopy(path.wstring());
  return Contains(lower, L"\\users\\") || Contains(lower, L"\\downloads\\") || Contains(lower, L"\\desktop\\") ||
         Contains(lower, L"\\temp\\") ||
         Contains(lower, L"\\appdata\\local\\temp\\") || Contains(lower, L"\\startup\\");
}

bool IsNoisyCachePath(const std::filesystem::path& path) {
  const auto lower = ToLowerCopy(path.wstring());
  return ContainsAny(lower, {L"\\node-compile-cache\\", L"\\v8-compile-cache\\", L"\\npm-cache\\",
                             L"\\pnpm-store\\", L"\\yarn\\cache\\", L"\\.cache\\",
                             L"\\appdata\\local\\temp\\node-compile-cache\\"});
}

bool ExecutableExt(const std::wstring& ext);
bool ScriptExt(const std::wstring& ext);

bool IsHighRiskExecutionSurface(const FileData& file) {
  return file.pe || file.zip || file.ole || file.lnk || ExecutableExt(file.extension) ||
         ScriptExt(file.extension) || file.extension == L".hta" || file.extension == L".url";
}

bool ContainsEicarMarker(const FileData& file) {
  return ContainsAny(file.fileNameLower, {L"eicar"}) ||
         ContainsAny(file.textLower, {L"eicar-standard-antivirus-test-file"}) ||
         ContainsAny(file.zipEntryNamesLower, {L"eicar"});
}

bool ShouldSuppressNoisyCacheFile(const FileData& file) {
  if (!IsNoisyCachePath(file.path) || ContainsEicarMarker(file)) {
    return false;
  }

  return !IsHighRiskExecutionSurface(file);
}

bool TrustedPath(const std::filesystem::path& path) {
  const auto lower = ToLowerCopy(path.wstring());
  return Contains(lower, L"\\windows\\") || Contains(lower, L"\\program files\\") ||
         Contains(lower, L"\\program files (x86)\\");
}

std::wstring NormalizePathForComparison(const std::filesystem::path& path) {
  if (path.empty()) {
    return {};
  }

  std::error_code error;
  auto normalized = std::filesystem::absolute(path, error);
  if (error) {
    normalized = path;
  }

  normalized = normalized.lexically_normal();
  auto value = ToLowerCopy(normalized.wstring());
  std::replace(value.begin(), value.end(), L'/', L'\\');
  while (value.size() > 1 && value.back() == L'\\') {
    if (value.size() == 3 && value[1] == L':') {
      break;
    }
    if (value.size() == 2 && value[0] == L'\\' && value[1] == L'\\') {
      break;
    }
    value.pop_back();
  }

  return value;
}

bool PathIsWithinRoot(const std::wstring& candidate, const std::wstring& root) {
  if (candidate.empty() || root.empty()) {
    return false;
  }

  if (candidate == root) {
    return true;
  }

  std::wstring rootPrefix = root;
  if (!rootPrefix.empty() && rootPrefix.back() != L'\\') {
    rootPrefix.push_back(L'\\');
  }

  return candidate.starts_with(rootPrefix);
}

bool IsExcludedPath(const std::filesystem::path& path, const std::vector<std::filesystem::path>& exclusions) {
  const auto normalizedPath = NormalizePathForComparison(path);
  if (normalizedPath.empty()) {
    return false;
  }

  for (const auto& exclusion : exclusions) {
    const auto normalizedExclusion = NormalizePathForComparison(exclusion);
    if (PathIsWithinRoot(normalizedPath, normalizedExclusion)) {
      return true;
    }
  }

  return false;
}

bool ExecutableExt(const std::wstring& ext) {
  return ext == L".exe" || ext == L".dll" || ext == L".scr" || ext == L".msi" || ext == L".com";
}

bool ScriptExt(const std::wstring& ext) {
  return ext == L".ps1" || ext == L".psm1" || ext == L".bat" || ext == L".cmd" || ext == L".js" ||
         ext == L".jse" || ext == L".vbs" || ext == L".vbe" || ext == L".hta";
}

std::wstring GetModuleDirectory() {
  std::wstring buffer(MAX_PATH, L'\0');
  const auto written = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (written == 0) {
    return {};
  }

  buffer.resize(written);
  const auto path = std::filesystem::path(buffer);
  return path.has_parent_path() ? path.parent_path().wstring() : std::filesystem::current_path().wstring();
}

std::filesystem::path ResolveSignatureBundlePath() {
  const auto envPath = ReadEnvironmentVariable(L"ANTIVIRUS_SIGNATURE_BUNDLE_PATH");
  if (!envPath.empty()) {
    return std::filesystem::path(envPath);
  }

  auto moduleDirectory = std::filesystem::path(GetModuleDirectory());
  for (int depth = 0; depth < 4 && !moduleDirectory.empty(); ++depth) {
    const auto directCandidate = moduleDirectory / L"signatures" / L"default-signatures.tsv";
    if (std::error_code error; std::filesystem::exists(directCandidate, error) && !error) {
      return directCandidate;
    }

    const auto repoCandidate = moduleDirectory / L"agent" / L"windows" / L"signatures" / L"default-signatures.tsv";
    if (std::error_code error; std::filesystem::exists(repoCandidate, error) && !error) {
      return repoCandidate;
    }

    moduleDirectory = moduleDirectory.parent_path();
  }

  const auto cwdCandidate = std::filesystem::current_path() / L"signatures" / L"default-signatures.tsv";
  if (std::error_code error; std::filesystem::exists(cwdCandidate, error) && !error) {
    return cwdCandidate;
  }

  return std::filesystem::current_path() / L"agent" / L"windows" / L"signatures" / L"default-signatures.tsv";
}

std::vector<std::wstring> SplitPatterns(const std::wstring& value, const wchar_t separator) {
  std::vector<std::wstring> parts;
  std::wstring current;
  for (const auto ch : value) {
    if (ch == separator) {
      const auto trimmed = TrimWide(current);
      if (!trimmed.empty()) {
        parts.push_back(ToLowerCopy(trimmed));
      }
      current.clear();
      continue;
    }
    current.push_back(ch);
  }

  const auto trailing = TrimWide(current);
  if (!trailing.empty()) {
    parts.push_back(ToLowerCopy(trailing));
  }
  return parts;
}

std::vector<std::wstring> SplitColumns(const std::wstring& value, const wchar_t separator) {
  std::vector<std::wstring> columns;
  std::wstring current;
  for (const auto ch : value) {
    if (ch == separator) {
      columns.push_back(TrimWide(current));
      current.clear();
      continue;
    }
    current.push_back(ch);
  }
  columns.push_back(TrimWide(current));
  return columns;
}

std::vector<unsigned char> ReadBytes(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    return {};
  }
  input.seekg(0, std::ios::end);
  const auto size = static_cast<std::size_t>(std::max<std::streamoff>(input.tellg(), 0));
  input.seekg(0, std::ios::beg);
  std::vector<unsigned char> bytes(std::min(size, kReadLimit));
  input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  bytes.resize(static_cast<std::size_t>(std::max<std::streamsize>(input.gcount(), 0)));
  return bytes;
}

std::wstring DecodeText(const std::vector<unsigned char>& bytes) {
  if (bytes.empty()) {
    return {};
  }
  if (bytes.size() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) {
    std::wstring text;
    for (std::size_t i = 2; i + 1 < bytes.size(); i += 2) {
      const auto ch = static_cast<wchar_t>(bytes[i] | (bytes[i + 1] << 8));
      if (ch != L'\0') {
        text.push_back(ch);
      }
    }
    return text;
  }
  const auto utf8 = Utf8ToWide(std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
  if (!utf8.empty()) {
    return utf8;
  }
  std::wstring text;
  text.reserve(bytes.size());
  for (const auto byte : bytes) {
    text.push_back(byte >= 0x20 && byte <= 0x7E ? static_cast<wchar_t>(byte) : L' ');
  }
  return text;
}

std::wstring ExtractAsciiLower(const std::vector<unsigned char>& bytes) {
  std::wstring text;
  text.reserve(bytes.size());
  for (const auto byte : bytes) {
    text.push_back(byte >= 0x20 && byte <= 0x7E ? static_cast<wchar_t>(std::towlower(static_cast<wchar_t>(byte)))
                                                : L' ');
  }
  return text;
}

double Entropy(const std::vector<unsigned char>& bytes) {
  if (bytes.empty()) {
    return 0.0;
  }
  std::array<std::size_t, 256> counts{};
  for (const auto byte : bytes) {
    ++counts[byte];
  }
  double entropy = 0.0;
  const auto total = static_cast<double>(bytes.size());
  for (const auto count : counts) {
    if (count == 0) {
      continue;
    }
    const auto p = static_cast<double>(count) / total;
    entropy -= p * std::log2(p);
  }
  return entropy;
}

std::uint32_t CountZipEntries(const std::vector<unsigned char>& bytes) {
  std::uint32_t count = 0;
  for (std::size_t index = 0; index + 3 < bytes.size(); ++index) {
    if (bytes[index] == 'P' && bytes[index + 1] == 'K' && bytes[index + 2] == 0x03 && bytes[index + 3] == 0x04) {
      ++count;
    }
  }
  return count;
}

std::wstring ExtractZipEntryNamesLower(const std::vector<unsigned char>& bytes) {
  std::wstring entryNames;
  for (std::size_t index = 0; index + 46 <= bytes.size(); ++index) {
    if (bytes[index] != 'P' || bytes[index + 1] != 'K' || bytes[index + 2] != 0x01 || bytes[index + 3] != 0x02) {
      continue;
    }

    const auto fileNameLength = static_cast<std::uint16_t>(bytes[index + 28] | (bytes[index + 29] << 8));
    const auto extraFieldLength = static_cast<std::uint16_t>(bytes[index + 30] | (bytes[index + 31] << 8));
    const auto commentLength = static_cast<std::uint16_t>(bytes[index + 32] | (bytes[index + 33] << 8));

    const auto fileNameOffset = index + 46;
    const auto fileNameEnd = fileNameOffset + fileNameLength;
    if (fileNameEnd > bytes.size()) {
      continue;
    }

    const auto decodedName = Utf8ToWide(std::string(reinterpret_cast<const char*>(bytes.data() + fileNameOffset),
                                                    fileNameLength));
    if (decodedName.empty()) {
      continue;
    }

    if (!entryNames.empty()) {
      entryNames.push_back(L' ');
    }
    entryNames += ToLowerCopy(decodedName);

    const auto skipTo = fileNameEnd + extraFieldLength + commentLength;
    if (skipTo > index) {
      index = skipTo > 0 ? skipTo - 1 : index;
    }
  }

  return entryNames;
}

bool LongBase64(std::wstring_view text) {
  std::size_t run = 0;
  for (const auto ch : text) {
    const auto ok = (ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z') || (ch >= L'0' && ch <= L'9') ||
                    ch == L'+' || ch == L'/' || ch == L'=';
    run = ok ? run + 1 : 0;
    if (run >= 96) {
      return true;
    }
  }
  return false;
}

bool LooksLikeRansomNoteName(std::wstring_view fileNameLower) {
  return ContainsAny(fileNameLower, {L"readme", L"decrypt", L"recover", L"restore", L"how_to", L"help", L"ransom"}) &&
         (ContainsAny(fileNameLower, {L".txt", L".html", L".hta", L".url"}) ||
          fileNameLower.find(L'_') != std::wstring_view::npos || fileNameLower.find(L'-') != std::wstring_view::npos);
}

bool ContainsRansomNoteLanguage(std::wstring_view textLower) {
  const auto mentionsEncryption =
      ContainsAny(textLower, {L"your files have been encrypted", L"all your files have been encrypted",
                              L"data encrypted", L"files are encrypted", L"encrypted with"});
  const auto mentionsRecovery =
      ContainsAny(textLower, {L"how to decrypt", L"recover your files", L"restore your files",
                              L"private key", L"decryptor", L"decryption key"});
  const auto mentionsPayment =
      ContainsAny(textLower, {L"bitcoin", L"monero", L"onion", L"tor browser", L"contact us", L"pay"});

  return (mentionsEncryption && mentionsRecovery) || (mentionsEncryption && mentionsPayment);
}

bool LooksLikeEncryptedArtifact(const FileData& file) {
  if (file.pe || file.zip || file.ole || file.lnk || ScriptExt(file.extension) || ExecutableExt(file.extension)) {
    return false;
  }

  const auto suspiciousExtension =
      ContainsAny(file.extension, {L".locked", L".lock", L".encrypted", L".enc", L".crypt", L".crypted", L".cry",
                                   L".lockbit", L".conti", L".akira", L".clop", L".ryuk", L".blackcat"});
  return suspiciousExtension && file.entropy >= 6.8;
}

bool ContainsRecoveryInhibitionCommands(std::wstring_view textLower) {
  return ContainsAny(textLower, {L"vssadmin delete shadows", L"wmic shadowcopy delete", L"wbadmin delete catalog",
                                 L"wbadmin delete backup", L"bcdedit /set {default} recoveryenabled no",
                                 L"bcdedit /set {current} recoveryenabled no",
                                 L"bcdedit /set {default} bootstatuspolicy ignoreallfailures",
                                 L"bcdedit /set {current} bootstatuspolicy ignoreallfailures", L"reagentc /disable"});
}

bool ContainsMassEncryptionScriptBehavior(std::wstring_view textLower) {
  const auto enumeratesFiles =
      ContainsAny(textLower, {L"get-childitem", L"enumeratefiles", L"directory.getfiles", L"findfirstfile",
                              L"forfiles", L"dir /s", L"walk("});
  const auto usesCrypto =
      ContainsAny(textLower, {L"aesmanaged", L"rijndaelmanaged", L"cryptostream", L"createencryptor",
                              L"transformfinalblock", L"encryptor", L"cryptoapi"});
  const auto rewritesContent =
      ContainsAny(textLower, {L"writeallbytes", L"set-content", L"writealltext", L"move-item", L"rename-item",
                              L"copyto(", L"filesystem::rename"});

  return enumeratesFiles && usesCrypto && rewritesContent;
}

std::wstring QuerySigner(const std::wstring& path) {
  HCERTSTORE store = nullptr;
  HCRYPTMSG message = nullptr;
  PCCERT_CONTEXT cert = nullptr;
  DWORD encoding = 0;
  DWORD contentType = 0;
  DWORD formatType = 0;
  if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                       CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                       CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &contentType, &formatType, &store, &message,
                       nullptr) == FALSE) {
    return {};
  }
  DWORD signerInfoSize = 0;
  if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize) == FALSE) {
    if (message) CryptMsgClose(message);
    if (store) CertCloseStore(store, 0);
    return {};
  }
  std::vector<BYTE> buffer(signerInfoSize);
  if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, buffer.data(), &signerInfoSize) == FALSE) {
    if (message) CryptMsgClose(message);
    if (store) CertCloseStore(store, 0);
    return {};
  }
  const auto* signerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(buffer.data());
  CERT_INFO info{};
  info.Issuer = signerInfo->Issuer;
  info.SerialNumber = signerInfo->SerialNumber;
  cert = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &info,
                                    nullptr);
  std::wstring subject;
  if (cert != nullptr) {
    const auto length = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
    if (length > 1) {
      subject.resize(length - 1);
      CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subject.data(), length);
    }
    CertFreeCertificateContext(cert);
  }
  if (message) CryptMsgClose(message);
  if (store) CertCloseStore(store, 0);
  return subject;
}

bool TrustedSigner(const std::wstring& signer) {
  const auto lower = ToLowerCopy(signer);
  static const std::array<const wchar_t*, 13> trusted = {
      L"microsoft", L"google",     L"adobe",     L"mozilla", L"intel",      L"nvidia", L"vmware",
      L"cisco",     L"oracle",     L"crowdstrike", L"eset",    L"bitdefender", L"kaspersky"};
  return std::any_of(trusted.begin(), trusted.end(),
                     [&lower](const auto* value) { return lower.find(value) != std::wstring::npos; });
}

void AddHit(std::vector<Hit>& hits, Hit hit) {
  const auto found =
      std::any_of(hits.begin(), hits.end(), [&hit](const auto& existing) { return existing.code == hit.code; });
  if (!found) {
    hits.push_back(std::move(hit));
  }
}

bool RuleApplies(const Rule& rule, const FileData& file) {
  if (rule.scope.empty() || rule.scope == L"any") {
    return true;
  }
  if (rule.scope == L"text") {
    return true;
  }
  if (rule.scope == L"ascii") {
    return true;
  }
  if (rule.scope == L"pe") {
    return file.pe || ExecutableExt(file.extension);
  }
  if (rule.scope == L"zip") {
    return file.zip;
  }
  if (rule.scope == L"script") {
    return ScriptExt(file.extension);
  }
  if (rule.scope == L"ole") {
    return file.ole;
  }
  if (rule.scope == L"lnk") {
    return file.lnk || file.extension == L".lnk";
  }
  if (rule.scope == L"office") {
    return file.ole || file.zip ||
           file.extension == L".doc" || file.extension == L".docm" || file.extension == L".docx" ||
           file.extension == L".xls" || file.extension == L".xlsm" || file.extension == L".xlsx" ||
           file.extension == L".ppt" || file.extension == L".pptm" || file.extension == L".pptx" ||
           file.extension == L".rtf";
  }
  return true;
}

std::wstring_view RuleHaystack(const Rule& rule, const FileData& file) {
  if (rule.scope == L"ascii" || rule.scope == L"pe" || rule.scope == L"zip" || rule.scope == L"lnk") {
    return file.asciiLower;
  }
  return file.textLower;
}

void AddRuleHits(const std::vector<Rule>& rules, const FileData& file, std::vector<Hit>& hits) {
  for (const auto& rule : rules) {
    if (!RuleApplies(rule, file)) {
      continue;
    }
    const auto haystack = RuleHaystack(rule, file);
    for (const auto& pattern : rule.patterns) {
      if (Contains(haystack, pattern)) {
        AddHit(hits, Hit{rule.code, rule.message, rule.tacticId, rule.techniqueId, rule.score});
        break;
      }
    }
  }
}

std::vector<Rule> LoadExternalRules() {
  static std::once_flag once;
  static std::vector<Rule> cachedRules;

  std::call_once(once, [] {
    const auto path = ResolveSignatureBundlePath();
    std::ifstream input(WideToUtf8(path.wstring()), std::ios::binary);
    if (!input.is_open()) {
      return;
    }

    std::string lineUtf8;
    while (std::getline(input, lineUtf8)) {
      const auto trimmed = TrimWide(Utf8ToWide(lineUtf8));
      if (trimmed.empty() || trimmed.starts_with(L"#") || trimmed.starts_with(L";")) {
        continue;
      }

      const auto columns = SplitColumns(trimmed, L'|');
      if (columns.size() < 7) {
        continue;
      }

      Rule rule;
      rule.scope = ToLowerCopy(columns[0]);
      rule.code = columns[1];
      rule.message = columns[2];
      rule.tacticId = columns[3];
      rule.techniqueId = columns[4];
      try {
        rule.score = std::stoi(columns[5]);
      } catch (...) {
        continue;
      }
      rule.patterns = SplitPatterns(columns[6], L';');
      if (!rule.code.empty() && !rule.patterns.empty()) {
        cachedRules.push_back(std::move(rule));
      }
    }
  });

  return cachedRules;
}

std::optional<FileData> LoadFileData(const std::filesystem::path& path) {
  std::error_code error;
  if (!std::filesystem::exists(path, error) || !std::filesystem::is_regular_file(path, error)) {
    return std::nullopt;
  }
  FileData file{};
  file.path = path;
  file.sizeBytes = std::filesystem::file_size(path, error);
  file.extension = ToLowerCopy(path.extension().wstring());
  file.fileNameLower = ToLowerCopy(path.filename().wstring());
  file.bytes = ReadBytes(path);
  file.pe = file.bytes.size() >= 2 && file.bytes[0] == 'M' && file.bytes[1] == 'Z';
  file.zip = file.bytes.size() >= 4 && file.bytes[0] == 'P' && file.bytes[1] == 'K';
  file.ole = file.bytes.size() >= 8 && file.bytes[0] == 0xD0 && file.bytes[1] == 0xCF;
  file.lnk = file.bytes.size() >= 4 && file.bytes[0] == 0x4C && file.bytes[1] == 0x00;
  file.userPath = UserPath(path);
  file.trustedPath = TrustedPath(path);
  file.textLower = ToLowerCopy(DecodeText(file.bytes));
  file.asciiLower = ExtractAsciiLower(file.bytes);
  file.zipEntryNamesLower = file.zip ? ExtractZipEntryNamesLower(file.bytes) : std::wstring{};
  file.entropy = Entropy(file.bytes);
  file.archiveEntryCount = file.zip ? CountZipEntries(file.bytes) : 0;
  file.contentType = file.pe ? L"portable-executable" : file.zip ? L"zip-archive" : file.ole ? L"ole-document"
                              : file.lnk ? L"windows-shortcut" : ScriptExt(file.extension) ? L"script" : L"binary";
  if (file.pe || ExecutableExt(file.extension)) {
    file.signer = QuerySigner(path.wstring());
  }
  file.reputation = !file.signer.empty() && TrustedSigner(file.signer) && file.trustedPath ? L"trusted-signed-system"
                    : !file.signer.empty() && TrustedSigner(file.signer)                    ? L"trusted-signed"
                    : file.trustedPath                                                     ? L"trusted-path"
                    : file.userPath && file.signer.empty()                                 ? L"user-writable-unsigned"
                                                                                           : L"unknown";
  try {
    file.sha256 = ComputeFileSha256(path);
  } catch (...) {
  }
  return file;
}

std::wstring BuildReportedReputation(const std::wstring& internalReputation,
                                     const ReputationLookupResult& reputationLookup) {
  if (!reputationLookup.attempted) {
    return internalReputation;
  }

  std::wstring reportedReputation = internalReputation;
  if (!reportedReputation.empty()) {
    reportedReputation += L";";
  }
  reportedReputation += DescribeReputationLookup(reputationLookup);
  return reportedReputation;
}

std::wstring GuessTechnique(const FileData& file) {
  if (file.extension == L".ps1" || file.extension == L".psm1") return L"T1059.001";
  if (file.extension == L".bat" || file.extension == L".cmd") return L"T1059.003";
  if (file.extension == L".js" || file.extension == L".jse") return L"T1059.007";
  if (file.extension == L".vbs" || file.extension == L".vbe" || file.ole) return L"T1059.005";
  if (file.extension == L".hta") return L"T1218.005";
  if (file.lnk || file.extension == L".lnk") return L"T1204.001";
  return L"T1204.002";
}

}  // namespace

std::optional<ScanFinding> ScanFile(const std::filesystem::path& path, const PolicySnapshot& policy,
                                    const std::vector<std::filesystem::path>& excludedPaths) {
  if (IsExcludedPath(path, excludedPaths)) {
    return std::nullopt;
  }

  const auto loaded = LoadFileData(path);
  if (!loaded.has_value()) {
    return std::nullopt;
  }

  const auto& file = *loaded;
  if (ShouldSuppressNoisyCacheFile(file)) {
    return std::nullopt;
  }

  std::vector<Hit> hits;
  const auto archiveText = file.zipEntryNamesLower.empty() ? file.asciiLower : file.zipEntryNamesLower + L" " + file.asciiLower;

  if (ContainsAny(file.fileNameLower, {L"eicar"}) ||
      ContainsAny(file.textLower, {L"eicar-standard-antivirus-test-file"}) ||
      ContainsAny(archiveText, {L"eicar-standard-antivirus-test-file", L"x5o!p%@ap", L"eicar.com", L"eicar.txt"})) {
    AddHit(hits, Hit{L"EICAR_TEST_SIGNATURE", L"A standard antivirus test signature was detected.", L"TA0002",
                     L"T1204.002", 99});
  }

  if ((file.pe || ExecutableExt(file.extension)) && file.userPath) {
    AddHit(hits, Hit{file.signer.empty() ? L"USER_PATH_UNSIGNED_EXECUTABLE" : L"USER_PATH_EXECUTABLE",
                     file.signer.empty() ? L"Unsigned portable executable was found in a user-controlled path."
                                         : L"Portable executable was found in a user-controlled path.",
                     L"TA0002", L"T1204.002", file.signer.empty() ? 52 : 18});
  }
  if (file.extension == L".hta") {
    AddHit(hits, Hit{L"HTA_EXECUTION_SURFACE", L"HTA content is a high-risk execution surface on Windows.", L"TA0005",
                     L"T1218.005", file.userPath ? 72 : 60});
  }
  if ((file.lnk || file.extension == L".lnk") && file.userPath) {
    AddHit(hits, Hit{L"USER_PATH_SHORTCUT", L"Shortcut content in a user-controlled path often serves as an execution lure.",
                     L"TA0002", L"T1204.001", 30});
  }
  if (file.zip && file.userPath) {
    AddHit(hits, Hit{L"USER_PATH_ARCHIVE", L"Archive content in a user-controlled path can stage payload delivery.",
                     L"TA0002", L"T1204.002", 12});
  }

  if (Contains(file.textLower, L"amsiutils")) {
    AddHit(hits, Hit{L"DEFENSE_EVASION_AMSI", L"Content contains AMSI bypass or defense-evasion patterns.",
                     L"TA0005", L"T1562.001", 55});
  }

  if (Contains(file.textLower, L"frombase64string") || Contains(file.textLower, L"encodedcommand") ||
      Contains(file.textLower, L"-enc ")) {
    AddHit(hits, Hit{L"ENCODED_PAYLOAD", L"Content contains encoded payload or decode routines.", L"TA0005",
                     L"T1027", 35});
  }
  if (Contains(file.textLower, L"downloadstring") || Contains(file.textLower, L"downloadfile") ||
      Contains(file.textLower, L"invoke-webrequest") || Contains(file.textLower, L"start-bitstransfer") ||
      Contains(file.textLower, L"net.webclient")) {
    AddHit(hits, Hit{L"DOWNLOAD_CRADLE", L"Content contains network download cradle behavior.", L"TA0011", L"T1105",
                     35});
  }
  if (Contains(file.textLower, L"invoke-expression") || Contains(file.textLower, L"iex ") ||
      Contains(file.textLower, L"iex(")) {
    AddHit(hits, Hit{L"DYNAMIC_EXECUTION", L"Content uses dynamic execution primitives.", L"TA0002", L"T1059.001",
                     30});
  }
  if (Contains(file.textLower, L"autoopen") || Contains(file.textLower, L"document_open") ||
      Contains(file.textLower, L"workbook_open") || Contains(file.textLower, L"createobject(\"wscript.shell\")")) {
    AddHit(hits, Hit{L"OFFICE_MACRO_LAUNCH", L"Macro auto-run or shell execution patterns were found.", L"TA0002",
                     L"T1059.005", 40});
  }
  if (Contains(file.textLower, L"schtasks /create") || Contains(file.textLower, L"register-scheduledtask") ||
      Contains(file.textLower, L"new-scheduledtaskaction")) {
    AddHit(hits, Hit{L"SCHEDULED_TASK_PERSISTENCE",
                     L"Content contains scheduled-task persistence commands or helper APIs.", L"TA0003",
                     L"T1053.005", 24});
  }
  if (Contains(file.textLower, L"currentversion\\run") || Contains(file.textLower, L"\\runonce") ||
      Contains(file.textLower, L"reg add hkcu\\software\\microsoft\\windows\\currentversion\\run") ||
      Contains(file.textLower, L"reg add hklm\\software\\microsoft\\windows\\currentversion\\run")) {
    AddHit(hits, Hit{L"RUN_KEY_PERSISTENCE",
                     L"Content contains run-key persistence commands or registry paths.", L"TA0003",
                     L"T1547.001", 24});
  }
  if (Contains(file.textLower, L"sc create") || Contains(file.textLower, L"new-service") ||
      Contains(file.textLower, L"createservice")) {
    AddHit(hits, Hit{L"SERVICE_PERSISTENCE", L"Content contains service-install persistence patterns.", L"TA0003",
                     L"T1543.003", 28});
  }
  if (Contains(file.textLower, L"virtualalloc") || Contains(file.textLower, L"writeprocessmemory") ||
      Contains(file.textLower, L"createremotethread") || Contains(file.textLower, L"queueuserapc")) {
    AddHit(hits, Hit{L"PROCESS_INJECTION_API", L"Content references in-memory injection APIs.", L"TA0005",
                     L"T1055", 45});
  }
  if (Contains(file.textLower, L"wscript.shell") || Contains(file.textLower, L"shell.application") ||
      Contains(file.textLower, L"regsvr32") || Contains(file.textLower, L"mshta") ||
      Contains(file.textLower, L"rundll32")) {
    AddHit(hits, Hit{L"SCRIPT_HOST_ABUSE", L"Script host abuse patterns were detected.", L"TA0002", L"T1059", 30});
  }
  if ((ScriptExt(file.extension) || file.extension == L".hta" || file.extension == L".txt" || file.extension == L".html") &&
      ContainsRecoveryInhibitionCommands(file.textLower)) {
    AddHit(hits, Hit{L"RECOVERY_INHIBITION",
                     L"Content attempts to delete shadow copies, backups, or recovery settings commonly targeted by ransomware.",
                     L"TA0040", L"T1490", 72});
  }
  if (ScriptExt(file.extension) && ContainsMassEncryptionScriptBehavior(file.textLower)) {
    AddHit(hits, Hit{L"MASS_ENCRYPTION_SCRIPT",
                     L"Script content combines file enumeration, cryptography, and rewrite operations consistent with ransomware.",
                     L"TA0040", L"T1486", 70});
  }
  if (LooksLikeRansomNoteName(file.fileNameLower) && ContainsRansomNoteLanguage(file.textLower)) {
    AddHit(hits, Hit{L"RANSOM_NOTE_ARTIFACT",
                     L"Content resembles a ransom note with file-recovery and payment instructions.", L"TA0040",
                     L"T1486", 68});
  }
  if (LongBase64(file.textLower)) {
    AddHit(hits, Hit{L"LONG_BASE64_BLOB", L"Content contains a long encoded payload blob.", L"TA0005", L"T1027", 30});
  }
  if (std::count(file.textLower.begin(), file.textLower.end(), L'^') >= 12 ||
      std::count(file.textLower.begin(), file.textLower.end(), L'`') >= 12) {
    AddHit(hits, Hit{L"SCRIPT_OBFUSCATION", L"Content uses common obfuscation markers.", L"TA0005", L"T1027", 28});
  }

  if (Contains(file.asciiLower, L"http://") || Contains(file.asciiLower, L"https://") ||
      Contains(file.asciiLower, L"urldownloadtofile") || Contains(file.asciiLower, L"winhttp") ||
      Contains(file.asciiLower, L"internetopenurl")) {
    AddHit(hits, Hit{L"PE_DOWNLOAD_AND_EXECUTE", L"Portable executable contains download-and-execute strings.",
                     L"TA0011", L"T1105", 35});
  }
  if (Contains(file.asciiLower, L"virtualalloc") || Contains(file.asciiLower, L"writeprocessmemory") ||
      Contains(file.asciiLower, L"createremotethread") || Contains(file.asciiLower, L"queueuserapc")) {
    AddHit(hits, Hit{L"PE_PROCESS_INJECTION", L"Portable executable contains process injection strings.", L"TA0005",
                     L"T1055", 45});
  }
  if (Contains(file.asciiLower, L"powershell") || Contains(file.asciiLower, L"rundll32") ||
      Contains(file.asciiLower, L"regsvr32") || Contains(file.asciiLower, L"mshta") ||
      Contains(file.asciiLower, L"cmd.exe") || Contains(file.asciiLower, L"wscript") ||
      Contains(file.asciiLower, L"cscript")) {
    AddHit(hits, Hit{L"PE_LOLBIN_PROXY", L"Portable executable references LOLBins often used for proxy execution.",
                     L"TA0005", L"T1218", 32});
  }
  if (file.pe && file.entropy >= 7.2 && file.signer.empty()) {
    AddHit(hits, Hit{L"PE_HIGH_ENTROPY_PACKED",
                     L"Unsigned portable executable has high entropy consistent with packing or encryption.", L"TA0005",
                     L"T1027.002", 28});
  }
  if (LooksLikeEncryptedArtifact(file)) {
    AddHit(hits, Hit{L"ENCRYPTED_IMPACT_ARTIFACT",
                     L"File resembles an encrypted-impact artifact based on extension and entropy.", L"TA0040",
                     L"T1486", 52});
  }

  if (file.zip && (Contains(archiveText, L".exe") || Contains(archiveText, L".dll") ||
                   Contains(archiveText, L".scr") || Contains(archiveText, L".msi"))) {
    AddHit(hits, Hit{L"ARCHIVE_EXECUTABLE_PAYLOAD", L"Archive contains executable payload content.", L"TA0002",
                     L"T1204.002", 48});
  }
  if (file.zip && (Contains(archiveText, L".ps1") || Contains(archiveText, L".js") ||
                   Contains(archiveText, L".vbs") || Contains(archiveText, L".hta") ||
                   Contains(archiveText, L".bat") || Contains(archiveText, L".cmd"))) {
    AddHit(hits, Hit{L"ARCHIVE_SCRIPT_PAYLOAD", L"Archive contains script payload content.", L"TA0002", L"T1059",
                     45});
  }
  if (file.zip && Contains(archiveText, L".lnk")) {
    AddHit(hits, Hit{L"ARCHIVE_SHORTCUT_PAYLOAD", L"Archive contains shortcut content that can proxy execution.",
                     L"TA0002", L"T1204.001", 42});
  }
  if (file.zip && (Contains(archiveText, L".pdf.exe") || Contains(archiveText, L".doc.exe") ||
                   Contains(archiveText, L".jpg.exe"))) {
    AddHit(hits, Hit{L"ARCHIVE_DOUBLE_EXTENSION", L"Archive contains a deceptive double-extension lure.", L"TA0001",
                     L"T1566", 40});
  }
  if (file.zip && (Contains(archiveText, L".docm") || Contains(archiveText, L".xlsm") ||
                   Contains(archiveText, L".pptm"))) {
    AddHit(hits, Hit{L"ARCHIVE_MACRO_DOCUMENT", L"Archive contains macro-capable Office content.", L"TA0002",
                     L"T1204.002", 36});
  }
  if ((file.lnk || file.extension == L".lnk") &&
      (Contains(file.asciiLower, L"powershell") || Contains(file.asciiLower, L"cmd.exe") ||
       Contains(file.asciiLower, L"mshta") || Contains(file.asciiLower, L"rundll32"))) {
    AddHit(hits, Hit{L"LNK_PROXY_EXECUTION",
                     L"Shortcut content references a high-risk command interpreter or proxy binary.", L"TA0002",
                     L"T1204.001", 45});
  }

  if (file.extension == L".rtf" &&
      (Contains(file.textLower, L"\\objdata") || Contains(file.textLower, L"\\object") ||
       Contains(file.textLower, L"\\objupdate"))) {
    AddHit(hits, Hit{L"RTF_EMBEDDED_OBJECT", L"RTF content contains embedded object markers often used for payload delivery.",
                     L"TA0001", L"T1204.002", 32});
  }

  if (file.extension == L".msi" &&
      (Contains(file.asciiLower, L"customaction") || Contains(file.asciiLower, L"installexecutesequence")) &&
      (Contains(file.asciiLower, L"powershell") || Contains(file.asciiLower, L"cmd.exe") ||
       Contains(file.asciiLower, L"rundll32") || Contains(file.asciiLower, L"mshta"))) {
    AddHit(hits, Hit{L"MSI_PROXY_EXECUTION",
                     L"MSI content appears to wire a custom action into a high-risk interpreter or proxy binary.",
                     L"TA0002", L"T1218.007", 42});
  }

  if (file.userPath && file.path.wstring().find(L':', 3) != std::wstring::npos) {
    AddHit(hits, Hit{L"ALTERNATE_DATA_STREAM_PATH",
                     L"The path resembles an alternate data stream, which attackers sometimes use to hide payloads.",
                     L"TA0005", L"T1564.004", 26});
  }

  AddRuleHits(LoadExternalRules(), file, hits);

  int score = 0;
  for (const auto& hit : hits) {
    score += hit.score;
  }
  const auto highSeverity =
      std::any_of(hits.begin(), hits.end(), [](const auto& hit) { return hit.score >= 45; });
  if (((file.reputation == L"trusted-signed-system" || file.reputation == L"trusted-signed") && !highSeverity &&
       score < 70) ||
      (file.reputation == L"trusted-path" && score < 80) || score < kDetectThreshold) {
    return std::nullopt;
  }

  const auto top =
      std::max_element(hits.begin(), hits.end(),
                       [](const auto& left, const auto& right) { return left.score < right.score; });
  const auto quarantineCandidate =
      file.pe || ExecutableExt(file.extension) || file.ole || file.zip || file.extension == L".hta";
  const auto reputationLookup = policy.cloudLookupEnabled && !file.sha256.empty() && score >= kDetectThreshold
                                    ? LookupPublicFileReputation(file.sha256)
                                    : ReputationLookupResult{};
  const auto verifiedKnownGood = reputationLookup.attempted && reputationLookup.knownGood;
  ScanFinding finding{
      .path = file.path,
      .sizeBytes = file.sizeBytes,
      .sha256 = file.sha256,
      .contentType = file.contentType,
      .reputation = BuildReportedReputation(file.reputation, reputationLookup),
      .signer = file.signer,
      .heuristicScore = static_cast<std::uint32_t>(std::clamp(score, 0, 99)),
      .archiveEntryCount = file.archiveEntryCount,
      .verdict =
          ScanVerdict{
              .disposition = verifiedKnownGood && score < kQuarantineThreshold
                                 ? VerdictDisposition::Allow
                                 : VerdictDisposition::Block,
              .confidence = static_cast<std::uint32_t>(std::clamp(score, 1, 99)),
              .tacticId = top != hits.end() ? top->tacticId : L"TA0002",
              .techniqueId = top != hits.end() ? top->techniqueId : GuessTechnique(file),
              .reasons = {}}};
  if (reputationLookup.attempted) {
    finding.verdict.reasons.push_back(
        {verifiedKnownGood ? L"REPUTATION_VERIFIED" : L"REPUTATION_LOOKUP", reputationLookup.summary});
  }
  for (const auto& hit : hits) {
    finding.verdict.reasons.push_back({hit.code, hit.message});
  }
  if (finding.sha256.empty()) {
    finding.verdict.reasons.push_back(
        {L"HASH_UNAVAILABLE", L"SHA-256 computation failed, so the finding is based on content and path heuristics."});
  }
  if (!file.signer.empty()) {
    finding.verdict.reasons.push_back({L"SIGNER_CONTEXT", L"Embedded signer: " + file.signer});
  }
  if (finding.verdict.disposition == VerdictDisposition::Block && quarantineCandidate) {
    finding.verdict.reasons.push_back({L"BLOCK_FIRST",
                                       L"Fenrir blocked this item immediately and can quarantine it during remediation."});
  }
  return finding;
}

std::optional<ScanFinding> ScanFile(const std::filesystem::path& path, const PolicySnapshot& policy) {
  return ScanFile(path, policy, {});
}

std::vector<ScanFinding> ScanTargets(const std::vector<std::filesystem::path>& targets, const PolicySnapshot& policy,
                                     const ScanProgressCallback& progressCallback) {
  return ScanTargets(targets, policy, progressCallback, {});
}

std::vector<ScanFinding> ScanTargets(const std::vector<std::filesystem::path>& targets, const PolicySnapshot& policy) {
  return ScanTargets(targets, policy, ScanProgressCallback{}, {});
}

std::vector<ScanFinding> ScanTargets(const std::vector<std::filesystem::path>& targets, const PolicySnapshot& policy,
                                     const ScanProgressCallback& progressCallback,
                                     const std::vector<std::filesystem::path>& excludedPaths) {
  std::vector<std::filesystem::path> files;
  for (const auto& target : targets) {
    std::error_code error;
    if (IsExcludedPath(target, excludedPaths)) {
      continue;
    }

    if (std::filesystem::is_regular_file(target, error)) {
      files.push_back(target);
      continue;
    }

    error.clear();
    if (!std::filesystem::is_directory(target, error)) {
      continue;
    }

    for (std::filesystem::recursive_directory_iterator iterator(
             target, std::filesystem::directory_options::skip_permission_denied, error);
         iterator != std::filesystem::recursive_directory_iterator(); iterator.increment(error)) {
      if (error) {
        error.clear();
        continue;
      }

      const auto entryPath = iterator->path();
      if (IsExcludedPath(entryPath, excludedPaths)) {
        if (iterator->is_directory(error)) {
          iterator.disable_recursion_pending();
        }
        if (error) {
          error.clear();
        }
        continue;
      }

      if (iterator->is_regular_file(error)) {
        files.push_back(entryPath);
      }

      if (error) {
        error.clear();
      }
    }
  }

  std::sort(files.begin(), files.end());
  files.erase(std::unique(files.begin(), files.end()), files.end());

  std::vector<ScanFinding> findings;
  for (std::size_t index = 0; index < files.size(); ++index) {
    const auto& file = files[index];
    if (progressCallback) {
      progressCallback(ScanProgressUpdate{
          .completedTargets = index,
          .totalTargets = files.size(),
          .findingCount = findings.size(),
          .currentPath = file,
      });
    }

    if (const auto finding = ScanFile(file, policy, excludedPaths); finding.has_value()) {
      findings.push_back(*finding);
    }
  }

  if (progressCallback) {
    progressCallback(ScanProgressUpdate{
        .completedTargets = files.size(),
        .totalTargets = files.size(),
        .findingCount = findings.size(),
        .currentPath = {},
    });
  }

  std::sort(findings.begin(), findings.end(),
            [](const ScanFinding& left, const ScanFinding& right) { return left.path < right.path; });
  return findings;
}

std::wstring VerdictDispositionToString(const VerdictDisposition disposition) {
  switch (disposition) {
    case VerdictDisposition::Allow:
      return L"allow";
    case VerdictDisposition::Block:
      return L"block";
    case VerdictDisposition::Quarantine:
      return L"quarantine";
    case VerdictDisposition::Unknown:
    default:
      return L"unknown";
  }
}

std::wstring RemediationStatusToString(const RemediationStatus status) {
  switch (status) {
    case RemediationStatus::Quarantined:
      return L"quarantined";
    case RemediationStatus::Failed:
      return L"failed";
    case RemediationStatus::None:
    default:
      return L"none";
  }
}

TelemetryRecord BuildScanFindingTelemetry(const ScanFinding& finding, const std::wstring& source) {
  const auto disposition = VerdictDispositionToString(finding.verdict.disposition);
  const auto techniqueId = finding.verdict.techniqueId.empty() ? L"unknown" : finding.verdict.techniqueId;
  const auto remediationStatus = RemediationStatusToString(finding.remediationStatus);

  std::wstring summary = finding.verdict.disposition == VerdictDisposition::Allow ? L"On-demand scan verified "
                                                                                  : L"On-demand scan flagged ";
  summary += finding.path.filename().wstring();
  if (finding.verdict.disposition == VerdictDisposition::Allow) {
    summary += L" after reputation verification.";
  } else {
    summary += L" for ";
    summary += disposition;
    if (finding.remediationStatus == RemediationStatus::Quarantined) {
      summary += L" and moved it into local quarantine.";
    } else if (finding.remediationStatus == RemediationStatus::Failed) {
      summary += L", but remediation failed locally.";
    } else {
      summary += L".";
    }
  }

  std::wstring payload = L"{\"path\":\"";
  payload += Utf8ToWide(EscapeJsonString(finding.path.wstring()));
  payload += L"\",\"sizeBytes\":";
  payload += std::to_wstring(finding.sizeBytes);
  payload += L",\"sha256\":\"";
  payload += finding.sha256;
  payload += L"\",\"contentType\":\"";
  payload += finding.contentType;
  payload += L"\",\"reputation\":\"";
  payload += finding.reputation;
  payload += L"\",\"signer\":\"";
  payload += Utf8ToWide(EscapeJsonString(finding.signer));
  payload += L"\",\"heuristicScore\":";
  payload += std::to_wstring(finding.heuristicScore);
  payload += L",\"archiveEntryCount\":";
  payload += std::to_wstring(finding.archiveEntryCount);
  payload += L",\"remediationStatus\":\"";
  payload += remediationStatus;
  payload += L"\"";
  payload += L",\"disposition\":\"";
  payload += disposition;
  payload += L"\",\"tacticId\":\"";
  payload += finding.verdict.tacticId;
  payload += L"\",\"techniqueId\":\"";
  payload += techniqueId;
  payload += L"\",\"quarantineRecordId\":\"";
  payload += finding.quarantineRecordId;
  payload += L"\",\"evidenceRecordId\":\"";
  payload += finding.evidenceRecordId;
  payload += L"\",\"quarantinedPath\":\"";
  payload += Utf8ToWide(EscapeJsonString(finding.quarantinedPath.wstring()));
  payload += L"\",\"remediationError\":\"";
  payload += Utf8ToWide(EscapeJsonString(finding.remediationError));
  payload += L"\"}";

  return TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = L"scan.finding",
      .source = source,
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payload};
}

TelemetryRecord BuildScanSummaryTelemetry(const std::size_t targetCount, const std::size_t findingCount,
                                          const PolicySnapshot& policy, const std::wstring& source) {
  std::wstring summary;
  if (findingCount == 0) {
    summary = L"On-demand scan completed without suspicious findings.";
  } else {
    summary = L"On-demand scan completed with ";
    summary += std::to_wstring(findingCount);
    summary += L" suspicious finding(s).";
  }

  std::wstring payload = L"{\"targetCount\":";
  payload += std::to_wstring(targetCount);
  payload += L",\"findingCount\":";
  payload += std::to_wstring(findingCount);
  payload += L",\"policyRevision\":\"";
  payload += policy.revision;
  payload += L"\"}";

  return TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = L"scan.completed",
      .source = source,
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payload};
}

}  // namespace antivirus::agent
