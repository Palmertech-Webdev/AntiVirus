#include "ReputationLookup.h"

#include <Windows.h>
#include <winhttp.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cwctype>
#include <mutex>
#include <optional>
#include <regex>
#include <string>
#include <iterator>
#include <unordered_map>

#include "StringUtils.h"

namespace antivirus::agent {
namespace {

struct ParsedBaseUrl {
  std::wstring host;
  INTERNET_PORT port{INTERNET_DEFAULT_HTTPS_PORT};
  bool secure{true};
  std::wstring pathPrefix;
};

struct CachedReputationEntry {
  ReputationLookupResult result;
  std::chrono::system_clock::time_point expiresAt;
};

constexpr auto kKnownGoodTtl = std::chrono::hours(24);
constexpr auto kUnknownTtl = std::chrono::hours(6);
constexpr auto kFailureTtl = std::chrono::minutes(30);

std::mutex gCacheMutex;
std::unordered_map<std::wstring, CachedReputationEntry> gCache;

std::wstring TrimCopy(std::wstring value) {
  const auto isTrimCharacter = [](const wchar_t ch) {
    return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n' || ch == L'/';
  };

  while (!value.empty() && isTrimCharacter(value.front())) {
    value.erase(value.begin());
  }
  while (!value.empty() && isTrimCharacter(value.back())) {
    value.pop_back();
  }
  return value;
}

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

bool IsHexSha256(const std::wstring& value) {
  if (value.size() != 64) {
    return false;
  }

  return std::all_of(value.begin(), value.end(), [](const wchar_t ch) {
    return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f');
  });
}

std::wstring ResolveBaseUrl() {
  wchar_t environmentValue[1024];
  const auto length = GetEnvironmentVariableW(L"FENRIR_HASHLOOKUP_BASE_URL", environmentValue,
                                              static_cast<DWORD>(std::size(environmentValue)));
  if (length > 0 && length < std::size(environmentValue)) {
    return TrimCopy(std::wstring(environmentValue, length));
  }

  return L"https://hashlookup.circl.lu";
}

ParsedBaseUrl ParseBaseUrl(std::wstring baseUrl) {
  ParsedBaseUrl parsed{};
  baseUrl = TrimCopy(std::move(baseUrl));

  if (baseUrl.starts_with(L"https://")) {
    baseUrl.erase(0, std::wstring(L"https://").size());
    parsed.secure = true;
    parsed.port = INTERNET_DEFAULT_HTTPS_PORT;
  } else if (baseUrl.starts_with(L"http://")) {
    baseUrl.erase(0, std::wstring(L"http://").size());
    parsed.secure = false;
    parsed.port = INTERNET_DEFAULT_HTTP_PORT;
  }

  const auto slashPosition = baseUrl.find(L'/');
  const auto hostPort = slashPosition == std::wstring::npos ? baseUrl : baseUrl.substr(0, slashPosition);
  parsed.pathPrefix = slashPosition == std::wstring::npos ? L"" : baseUrl.substr(slashPosition);

  const auto portPosition = hostPort.find(L':');
  if (portPosition == std::wstring::npos) {
    parsed.host = hostPort;
    return parsed;
  }

  parsed.host = hostPort.substr(0, portPosition);
  const auto portText = hostPort.substr(portPosition + 1);
  try {
    const auto parsedPort = std::stoi(portText);
    if (parsedPort > 0 && parsedPort <= 65535) {
      parsed.port = static_cast<INTERNET_PORT>(parsedPort);
    }
  } catch (...) {
  }

  return parsed;
}

struct HttpResponse {
  DWORD statusCode{0};
  std::string body;
};

std::optional<std::string> ExtractJsonString(const std::string& json, const std::string& key) {
  const std::regex pattern("\"" + key + "\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"");
  std::smatch match;
  if (!std::regex_search(json, match, pattern)) {
    return std::nullopt;
  }

  std::string result;
  result.reserve(match[1].str().size());

  bool escaping = false;
  for (const auto ch : match[1].str()) {
    if (!escaping) {
      if (ch == '\\') {
        escaping = true;
      } else {
        result.push_back(ch);
      }
      continue;
    }

    switch (ch) {
      case '\\':
        result.push_back('\\');
        break;
      case '"':
        result.push_back('"');
        break;
      case 'n':
        result.push_back('\n');
        break;
      case 'r':
        result.push_back('\r');
        break;
      case 't':
        result.push_back('\t');
        break;
      default:
        result.push_back(ch);
        break;
    }

    escaping = false;
  }

  if (escaping) {
    result.push_back('\\');
  }

  return result;
}

std::optional<std::uint32_t> ExtractJsonUInt(const std::string& json, const std::string& key) {
  const std::regex pattern("\"" + key + "\"\\s*:\\s*(\\d+)");
  std::smatch match;
  if (!std::regex_search(json, match, pattern)) {
    return std::nullopt;
  }

  try {
    return static_cast<std::uint32_t>(std::stoul(match[1].str()));
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<HttpResponse> ExecuteHttpGet(const std::wstring& path) {
  const auto parsedBaseUrl = ParseBaseUrl(ResolveBaseUrl());
  if (parsedBaseUrl.host.empty()) {
    return std::nullopt;
  }

  std::wstring requestPath = parsedBaseUrl.pathPrefix;
  if (requestPath.empty() || requestPath.back() != L'/') {
    requestPath.push_back(L'/');
  }
  if (!path.empty() && path.front() == L'/') {
    requestPath += path.substr(1);
  } else {
    requestPath += path;
  }

  const auto session = WinHttpOpen(L"Fenrir Hashlookup Reputation/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (session == nullptr) {
    return std::nullopt;
  }

  WinHttpSetTimeouts(session, 5000, 5000, 5000, 5000);

  const auto connection = WinHttpConnect(session, parsedBaseUrl.host.c_str(), parsedBaseUrl.port, 0);
  if (connection == nullptr) {
    WinHttpCloseHandle(session);
    return std::nullopt;
  }

  const auto request = WinHttpOpenRequest(connection, L"GET", requestPath.c_str(), nullptr, WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          parsedBaseUrl.secure ? WINHTTP_FLAG_SECURE : 0);
  if (request == nullptr) {
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return std::nullopt;
  }

  const auto headers = L"Accept: application/json\r\n";
  const auto sent = WinHttpSendRequest(request, headers, static_cast<DWORD>(-1), WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
  if (!sent || !WinHttpReceiveResponse(request, nullptr)) {
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return std::nullopt;
  }

  DWORD statusCode = 0;
  DWORD statusCodeSize = sizeof(statusCode);
  if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX)) {
    statusCode = 0;
  }

  std::string body;
  for (;;) {
    DWORD availableBytes = 0;
    if (!WinHttpQueryDataAvailable(request, &availableBytes) || availableBytes == 0) {
      break;
    }

    std::string chunk(availableBytes, '\0');
    DWORD bytesRead = 0;
    if (!WinHttpReadData(request, chunk.data(), availableBytes, &bytesRead)) {
      WinHttpCloseHandle(request);
      WinHttpCloseHandle(connection);
      WinHttpCloseHandle(session);
      return std::nullopt;
    }

    chunk.resize(bytesRead);
    body.append(chunk);
  }

  WinHttpCloseHandle(request);
  WinHttpCloseHandle(connection);
  WinHttpCloseHandle(session);

  return HttpResponse{.statusCode = statusCode, .body = std::move(body)};
}

CachedReputationEntry MakeCacheEntry(const ReputationLookupResult& result) {
  const auto now = std::chrono::system_clock::now();
  const auto ttl = result.lookupSucceeded ? (result.knownGood ? kKnownGoodTtl : kUnknownTtl) : kFailureTtl;
  return CachedReputationEntry{.result = result, .expiresAt = now + ttl};
}

ReputationLookupResult BuildResultForStatus(const std::wstring& sha256, const HttpResponse& response) {
  ReputationLookupResult result{};
  result.attempted = true;
  result.provider = L"CIRCL hashlookup";
  result.source = L"hashlookup";

  if (response.statusCode == 200) {
    result.lookupSucceeded = true;
    result.knownGood = true;
    result.trustScore = ExtractJsonUInt(response.body, "hashlookup:trust").value_or(100);

    const auto source = ExtractJsonString(response.body, "source");
    if (source.has_value()) {
      result.source = Utf8ToWide(*source);
    }

    result.summary = L"Verified known file in CIRCL hashlookup.";
    result.details = L"The SHA-256 hash matched the public hashlookup corpus.";
    if (result.trustScore > 0) {
      result.details += L" Trust score: " + std::to_wstring(result.trustScore) + L".";
    }
    if (!result.source.empty()) {
      result.details += L" Source: " + result.source + L".";
    }
    return result;
  }

  if (response.statusCode == 404) {
    result.lookupSucceeded = true;
    result.knownGood = false;
    result.summary = L"No public hashlookup match was found.";
    result.details = L"The SHA-256 hash was not present in the public hashlookup corpus.";
    return result;
  }

  result.lookupSucceeded = false;
  result.knownGood = false;
  result.summary = L"Public reputation lookup was unavailable.";
  result.details = L"CIRCL hashlookup could not be reached or returned an unexpected response for " + sha256 + L".";
  return result;
}

}  // namespace

ReputationLookupResult LookupPublicFileReputation(const std::wstring& sha256) {
  const auto normalizedSha256 = ToLowerCopy(TrimCopy(sha256));
  ReputationLookupResult invalidResult{};
  invalidResult.provider = L"CIRCL hashlookup";
  invalidResult.source = L"hashlookup";
  invalidResult.summary = L"SHA-256 reputation lookup was skipped.";
  invalidResult.details = L"A valid SHA-256 value is required before a hashlookup query can be made.";

  if (!IsHexSha256(normalizedSha256)) {
    return invalidResult;
  }

  const auto now = std::chrono::system_clock::now();
  {
    std::lock_guard lock(gCacheMutex);
    const auto cached = gCache.find(normalizedSha256);
    if (cached != gCache.end() && cached->second.expiresAt > now) {
      auto result = cached->second.result;
      result.fromCache = true;
      return result;
    }
  }

  const auto response = ExecuteHttpGet(L"/lookup/sha256/" + normalizedSha256);
  ReputationLookupResult result = response.has_value() ? BuildResultForStatus(normalizedSha256, *response)
                                                       : ReputationLookupResult{};
  if (!response.has_value()) {
    result.attempted = true;
    result.lookupSucceeded = false;
    result.knownGood = false;
    result.provider = L"CIRCL hashlookup";
    result.source = L"hashlookup";
    result.summary = L"Public reputation lookup was unavailable.";
    result.details = L"CIRCL hashlookup could not be contacted for " + normalizedSha256 + L".";
  }

  {
    std::lock_guard lock(gCacheMutex);
    gCache[normalizedSha256] = MakeCacheEntry(result);
  }

  return result;
}

std::wstring DescribeReputationLookup(const ReputationLookupResult& result) {
  if (!result.attempted) {
    return L"hashlookup-skipped";
  }

  if (result.knownGood) {
    return result.fromCache ? L"hashlookup-known-good-cache" : L"hashlookup-known-good";
  }

  if (result.lookupSucceeded) {
    return result.fromCache ? L"hashlookup-unknown-cache" : L"hashlookup-unknown";
  }

  return result.fromCache ? L"hashlookup-unavailable-cache" : L"hashlookup-unavailable";
}

}  // namespace antivirus::agent
