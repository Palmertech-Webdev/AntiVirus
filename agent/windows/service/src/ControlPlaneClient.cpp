#include "ControlPlaneClient.h"

#include <Windows.h>
#include <winhttp.h>

#include <algorithm>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>

#include "StringUtils.h"

namespace antivirus::agent {
namespace {

struct HttpResponse {
  DWORD statusCode{0};
  std::string body;
};

std::wstring JoinUrl(const std::wstring& baseUrl, const std::wstring& path) {
  if (baseUrl.empty()) {
    return path;
  }

  if (baseUrl.back() == L'/' && path.starts_with(L"/")) {
    return baseUrl.substr(0, baseUrl.size() - 1) + path;
  }

  if (baseUrl.back() != L'/' && !path.starts_with(L"/")) {
    return baseUrl + L"/" + path;
  }

  return baseUrl + path;
}

bool EndsWithInsensitive(const std::wstring& value, const std::wstring& suffix) {
  if (suffix.size() > value.size()) {
    return false;
  }

  const auto offset = value.size() - suffix.size();
  for (std::size_t index = 0; index < suffix.size(); ++index) {
    if (std::towlower(value[offset + index]) != std::towlower(suffix[index])) {
      return false;
    }
  }

  return true;
}

std::wstring NormalizeControlPlaneBaseUrl(std::wstring baseUrl) {
  while (!baseUrl.empty() && (baseUrl.back() == L' ' || baseUrl.back() == L'\t' || baseUrl.back() == L'\r' ||
                              baseUrl.back() == L'\n' || baseUrl.back() == L'/')) {
    baseUrl.pop_back();
  }

  if (EndsWithInsensitive(baseUrl, L"/api/v1")) {
    baseUrl.resize(baseUrl.size() - std::wstring(L"/api/v1").size());
  }

  return baseUrl;
}

std::string EscapeRegex(const std::string& value) {
  std::string escaped;
  escaped.reserve(value.size() * 2);

  for (const auto ch : value) {
    switch (ch) {
      case '\\':
      case '^':
      case '$':
      case '.':
      case '|':
      case '?':
      case '*':
      case '+':
      case '(':
      case ')':
      case '[':
      case ']':
      case '{':
      case '}':
        escaped.push_back('\\');
        break;
      default:
        break;
    }

    escaped.push_back(ch);
  }

  return escaped;
}

std::string UnescapeJsonString(const std::string& value) {
  std::string result;
  result.reserve(value.size());

  bool escaping = false;
  for (const auto ch : value) {
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

std::optional<std::string> ExtractJsonString(const std::string& json, const std::string& key) {
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"");
  std::smatch match;
  if (std::regex_search(json, match, pattern)) {
    return UnescapeJsonString(match[1].str());
  }

  return std::nullopt;
}

std::optional<bool> ExtractJsonBool(const std::string& json, const std::string& key) {
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*(true|false)");
  std::smatch match;
  if (std::regex_search(json, match, pattern)) {
    return match[1].str() == "true";
  }

  return std::nullopt;
}

std::optional<int> ExtractJsonInt(const std::string& json, const std::string& key) {
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*(\\d+)");
  std::smatch match;
  if (std::regex_search(json, match, pattern)) {
    return std::stoi(match[1].str());
  }

  return std::nullopt;
}

std::optional<std::string> ExtractJsonObject(const std::string& json, const std::string& key) {
  const auto keyToken = "\"" + key + "\"";
  const auto keyPosition = json.find(keyToken);
  if (keyPosition == std::string::npos) {
    return std::nullopt;
  }

  const auto objectStart = json.find('{', keyPosition);
  if (objectStart == std::string::npos) {
    return std::nullopt;
  }

  bool insideString = false;
  bool escaping = false;
  int depth = 0;

  for (std::size_t index = objectStart; index < json.size(); ++index) {
    const auto ch = json[index];

    if (insideString) {
      if (escaping) {
        escaping = false;
      } else if (ch == '\\') {
        escaping = true;
      } else if (ch == '"') {
        insideString = false;
      }

      continue;
    }

    if (ch == '"') {
      insideString = true;
      continue;
    }

    if (ch == '{') {
      ++depth;
      continue;
    }

    if (ch == '}') {
      --depth;
      if (depth == 0) {
        return json.substr(objectStart, index - objectStart + 1);
      }
    }
  }

  return std::nullopt;
}

std::vector<std::string> ExtractJsonObjectArray(const std::string& json, const std::string& key) {
  std::vector<std::string> objects;

  const auto keyToken = "\"" + key + "\"";
  const auto keyPosition = json.find(keyToken);
  if (keyPosition == std::string::npos) {
    return objects;
  }

  const auto arrayStart = json.find('[', keyPosition);
  if (arrayStart == std::string::npos) {
    return objects;
  }

  bool insideString = false;
  bool escaping = false;
  int objectDepth = 0;
  std::size_t objectStart = std::string::npos;

  for (std::size_t index = arrayStart + 1; index < json.size(); ++index) {
    const auto ch = json[index];

    if (insideString) {
      if (escaping) {
        escaping = false;
      } else if (ch == '\\') {
        escaping = true;
      } else if (ch == '"') {
        insideString = false;
      }

      continue;
    }

    if (ch == '"') {
      insideString = true;
      continue;
    }

    if (ch == ']') {
      break;
    }

    if (ch == '{') {
      if (objectDepth == 0) {
        objectStart = index;
      }

      ++objectDepth;
      continue;
    }

    if (ch == '}') {
      --objectDepth;
      if (objectDepth == 0 && objectStart != std::string::npos) {
        objects.push_back(json.substr(objectStart, index - objectStart + 1));
        objectStart = std::string::npos;
      }
    }
  }

  return objects;
}

std::vector<std::string> ExtractJsonStringArray(const std::string& json, const std::string& key) {
  std::vector<std::string> values;

  const auto keyToken = "\"" + key + "\"";
  const auto keyPosition = json.find(keyToken);
  if (keyPosition == std::string::npos) {
    return values;
  }

  const auto arrayStart = json.find('[', keyPosition);
  if (arrayStart == std::string::npos) {
    return values;
  }

  bool insideString = false;
  bool escaping = false;
  std::string current;

  for (std::size_t index = arrayStart + 1; index < json.size(); ++index) {
    const auto ch = json[index];

    if (!insideString) {
      if (ch == ']') {
        break;
      }

      if (ch == '"') {
        insideString = true;
        current.clear();
      }

      continue;
    }

    if (escaping) {
      current.push_back(ch);
      escaping = false;
      continue;
    }

    if (ch == '\\') {
      current.push_back(ch);
      escaping = true;
      continue;
    }

    if (ch == '"') {
      values.push_back(UnescapeJsonString(current));
      insideString = false;
      current.clear();
      continue;
    }

    current.push_back(ch);
  }

  return values;
}

std::wstring RequireString(const std::optional<std::string>& value, const char* fieldName) {
  if (!value.has_value()) {
    throw std::runtime_error(std::string("Missing JSON string field: ") + fieldName);
  }

  return Utf8ToWide(*value);
}

bool RequireBool(const std::optional<bool>& value, const char* fieldName) {
  if (!value.has_value()) {
    throw std::runtime_error(std::string("Missing JSON bool field: ") + fieldName);
  }

  return *value;
}

PolicySnapshot ParsePolicySnapshot(const std::string& json) {
  PolicySnapshot policy = CreateDefaultPolicySnapshot();
  policy.policyId = RequireString(ExtractJsonString(json, "id"), "id");
  policy.policyName = RequireString(ExtractJsonString(json, "name"), "name");
  policy.revision = RequireString(ExtractJsonString(json, "revision"), "revision");
  policy.realtimeProtectionEnabled = RequireBool(ExtractJsonBool(json, "realtimeProtection"), "realtimeProtection");
  policy.cloudLookupEnabled = RequireBool(ExtractJsonBool(json, "cloudLookup"), "cloudLookup");
  policy.scriptInspectionEnabled = RequireBool(ExtractJsonBool(json, "scriptInspection"), "scriptInspection");
  policy.networkContainmentEnabled = RequireBool(ExtractJsonBool(json, "networkContainment"), "networkContainment");
  policy.quarantineOnMalicious = RequireBool(ExtractJsonBool(json, "quarantineOnMalicious"), "quarantineOnMalicious");
  if (const auto value = ExtractJsonInt(json, "scanMaliciousBlockThreshold"); value.has_value()) {
    policy.scanMaliciousBlockThreshold = static_cast<std::uint32_t>(std::clamp(*value, 1, 99));
  }
  if (const auto value = ExtractJsonInt(json, "scanMaliciousQuarantineThreshold"); value.has_value()) {
    policy.scanMaliciousQuarantineThreshold =
        static_cast<std::uint32_t>(std::clamp(*value, static_cast<int>(policy.scanMaliciousBlockThreshold), 99));
  }
  if (const auto value = ExtractJsonInt(json, "scanBenignDampeningScore"); value.has_value()) {
    policy.scanBenignDampeningScore = static_cast<std::uint32_t>(std::clamp(*value, 0, 80));
  }
  if (const auto value = ExtractJsonInt(json, "genericRuleScoreScalePercent"); value.has_value()) {
    policy.genericRuleScoreScalePercent = static_cast<std::uint32_t>(std::clamp(*value, 20, 100));
  }
  if (const auto value = ExtractJsonInt(json, "realtimeExecuteBlockThreshold"); value.has_value()) {
    policy.realtimeExecuteBlockThreshold = static_cast<std::uint32_t>(std::clamp(*value, 40, 99));
  }
  if (const auto value = ExtractJsonInt(json, "realtimeNonExecuteBlockThreshold"); value.has_value()) {
    policy.realtimeNonExecuteBlockThreshold = static_cast<std::uint32_t>(std::clamp(*value, 50, 99));
  }
  if (const auto value = ExtractJsonInt(json, "realtimeQuarantineThreshold"); value.has_value()) {
    const auto minThreshold = std::max<int>(static_cast<int>(policy.realtimeExecuteBlockThreshold),
                                            static_cast<int>(policy.realtimeNonExecuteBlockThreshold));
    policy.realtimeQuarantineThreshold = static_cast<std::uint32_t>(std::clamp(*value, minThreshold, 99));
  }
  if (const auto value = ExtractJsonInt(json, "realtimeObserveTelemetryThreshold"); value.has_value()) {
    policy.realtimeObserveTelemetryThreshold = static_cast<std::uint32_t>(std::clamp(*value, 1, 95));
  }
  if (const auto value = ExtractJsonBool(json, "realtimeObserveOnlyForNonExecute"); value.has_value()) {
    policy.realtimeObserveOnlyForNonExecute = *value;
  }
  if (const auto value = ExtractJsonBool(json, "archiveObserveOnly"); value.has_value()) {
    policy.archiveObserveOnly = *value;
  }
  if (const auto value = ExtractJsonBool(json, "networkObserveOnly"); value.has_value()) {
    policy.networkObserveOnly = *value;
  }
  if (const auto value = ExtractJsonBool(json, "cloudLookupObserveOnly"); value.has_value()) {
    policy.cloudLookupObserveOnly = *value;
  }
  if (const auto value = ExtractJsonBool(json, "requireSignerForSuppression"); value.has_value()) {
    policy.requireSignerForSuppression = *value;
  }
  if (const auto value = ExtractJsonBool(json, "allowUnsignedSuppressionPathExecutables"); value.has_value()) {
    policy.allowUnsignedSuppressionPathExecutables = *value;
  }
  if (const auto value = ExtractJsonBool(json, "enableCleanwareSignerDampening"); value.has_value()) {
    policy.enableCleanwareSignerDampening = *value;
  }
  if (const auto value = ExtractJsonBool(json, "enableKnownGoodHashDampening"); value.has_value()) {
    policy.enableKnownGoodHashDampening = *value;
  }
  for (const auto& root : ExtractJsonStringArray(json, "suppressionPathRoots")) {
    const auto wide = Utf8ToWide(root);
    if (!wide.empty()) {
      policy.suppressionPathRoots.push_back(wide);
    }
  }
  for (const auto& sha256 : ExtractJsonStringArray(json, "suppressionSha256")) {
    const auto wide = Utf8ToWide(sha256);
    if (!wide.empty()) {
      policy.suppressionSha256.push_back(wide);
    }
  }
  for (const auto& signer : ExtractJsonStringArray(json, "suppressionSignerNames")) {
    const auto wide = Utf8ToWide(signer);
    if (!wide.empty()) {
      policy.suppressionSignerNames.push_back(wide);
    }
  }
  return policy;
}

std::wstring ExtractQueryParameter(const std::wstring& url, const std::wstring& name) {
  const auto queryStart = url.find(L'?');
  if (queryStart == std::wstring::npos) {
    return {};
  }

  const auto key = name + L"=";
  auto searchOffset = queryStart + 1;
  while (searchOffset < url.size()) {
    const auto keyOffset = url.find(key, searchOffset);
    if (keyOffset == std::wstring::npos) {
      return {};
    }

    if (keyOffset == queryStart + 1 || url[keyOffset - 1] == L'&') {
      const auto valueStart = keyOffset + key.size();
      const auto valueEnd = url.find(L'&', valueStart);
      return url.substr(valueStart, valueEnd == std::wstring::npos ? std::wstring::npos : valueEnd - valueStart);
    }

    searchOffset = keyOffset + key.size();
  }

  return {};
}

std::wstring ExtractDeviceApiKeyFromCommandChannelUrl(const std::wstring& commandChannelUrl) {
  return ExtractQueryParameter(commandChannelUrl, L"deviceApiKey");
}

HttpResponse RequestJson(const wchar_t* method, const std::wstring& url, const std::string& body = {},
                         const std::wstring& deviceApiKey = {}) {
  URL_COMPONENTS components{};
  components.dwStructSize = sizeof(components);
  components.dwSchemeLength = static_cast<DWORD>(-1);
  components.dwHostNameLength = static_cast<DWORD>(-1);
  components.dwUrlPathLength = static_cast<DWORD>(-1);
  components.dwExtraInfoLength = static_cast<DWORD>(-1);

  if (WinHttpCrackUrl(url.c_str(), 0, 0, &components) == FALSE) {
    throw std::runtime_error("WinHttpCrackUrl failed");
  }

  const std::wstring host(components.lpszHostName, components.dwHostNameLength);
  std::wstring path(components.lpszUrlPath, components.dwUrlPathLength);
  if (components.dwExtraInfoLength > 0) {
    path.append(components.lpszExtraInfo, components.dwExtraInfoLength);
  }

  const auto secure = components.nScheme == INTERNET_SCHEME_HTTPS;
  const auto* agentName = L"FenrirAgent/0.1";

  auto session = WinHttpOpen(agentName, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
                             WINHTTP_NO_PROXY_BYPASS, 0);
  if (session == nullptr) {
    throw std::runtime_error("WinHttpOpen failed");
  }

  auto connection = WinHttpConnect(session, host.c_str(), components.nPort, 0);
  if (connection == nullptr) {
    WinHttpCloseHandle(session);
    throw std::runtime_error("WinHttpConnect failed");
  }

  auto request = WinHttpOpenRequest(connection, method, path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                    WINHTTP_DEFAULT_ACCEPT_TYPES, secure ? WINHTTP_FLAG_SECURE : 0);
  if (request == nullptr) {
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    throw std::runtime_error("WinHttpOpenRequest failed");
  }

  const auto bodySize = static_cast<DWORD>(body.size());
  std::wstring headers = L"Content-Type: application/json\r\n";
  if (!deviceApiKey.empty()) {
    headers += L"X-Device-Api-Key: " + deviceApiKey + L"\r\n";
  }

  if (WinHttpSendRequest(request, headers.c_str(), static_cast<DWORD>(-1), body.empty() ? WINHTTP_NO_REQUEST_DATA
                                                                                          : const_cast<char*>(body.data()),
                         bodySize, bodySize, 0) == FALSE) {
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    throw std::runtime_error("WinHttpSendRequest failed");
  }

  if (WinHttpReceiveResponse(request, nullptr) == FALSE) {
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    throw std::runtime_error("WinHttpReceiveResponse failed");
  }

  DWORD statusCode = 0;
  DWORD statusCodeSize = sizeof(statusCode);
  if (WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                          &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX) == FALSE) {
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    throw std::runtime_error("WinHttpQueryHeaders failed");
  }

  std::string responseBody;
  for (;;) {
    DWORD availableBytes = 0;
    if (WinHttpQueryDataAvailable(request, &availableBytes) == FALSE) {
      WinHttpCloseHandle(request);
      WinHttpCloseHandle(connection);
      WinHttpCloseHandle(session);
      throw std::runtime_error("WinHttpQueryDataAvailable failed");
    }

    if (availableBytes == 0) {
      break;
    }

    std::string chunk(availableBytes, '\0');
    DWORD downloadedBytes = 0;
    if (WinHttpReadData(request, chunk.data(), availableBytes, &downloadedBytes) == FALSE) {
      WinHttpCloseHandle(request);
      WinHttpCloseHandle(connection);
      WinHttpCloseHandle(session);
      throw std::runtime_error("WinHttpReadData failed");
    }

    chunk.resize(downloadedBytes);
    responseBody += chunk;
  }

  WinHttpCloseHandle(request);
  WinHttpCloseHandle(connection);
  WinHttpCloseHandle(session);

  if (statusCode < 200 || statusCode >= 300) {
    if (statusCode == 404 && responseBody.find("\"error\":\"device_not_found\"") != std::string::npos) {
      std::ostringstream message;
      message << "Control-plane rejected the cached device identity: " << responseBody;
      throw DeviceIdentityRejectedError(message.str());
    }

    std::ostringstream message;
    message << "HTTP request failed with status " << statusCode << ": " << responseBody;
    throw std::runtime_error(message.str());
  }

  return HttpResponse{.statusCode = statusCode, .body = std::move(responseBody)};
}

RemoteCommand ParseRemoteCommand(const std::string& json) {
  return RemoteCommand{
      .commandId = RequireString(ExtractJsonString(json, "id"), "id"),
      .type = RequireString(ExtractJsonString(json, "type"), "type"),
      .issuedBy = RequireString(ExtractJsonString(json, "issuedBy"), "issuedBy"),
      .createdAt = RequireString(ExtractJsonString(json, "createdAt"), "createdAt"),
      .updatedAt = RequireString(ExtractJsonString(json, "updatedAt"), "updatedAt"),
      .targetPath = Utf8ToWide(ExtractJsonString(json, "targetPath").value_or("")),
      .recordId = Utf8ToWide(ExtractJsonString(json, "recordId").value_or("")),
      .payloadJson = Utf8ToWide(ExtractJsonString(json, "payloadJson").value_or(""))};
}

}  // namespace

ControlPlaneClient::ControlPlaneClient(std::wstring baseUrl) : baseUrl_(NormalizeControlPlaneBaseUrl(std::move(baseUrl))) {}

EnrollmentResult ControlPlaneClient::Enroll(const AgentState& state) const {
  std::ostringstream body;
  body << "{"
       << "\"hostname\":\"" << EscapeJsonString(state.hostname) << "\","
       << "\"osVersion\":\"" << EscapeJsonString(state.osVersion) << "\","
       << "\"serialNumber\":\"" << EscapeJsonString(state.serialNumber) << "\""
       << "}";

  const auto response = RequestJson(L"POST", JoinUrl(baseUrl_, L"/api/v1/enroll"), body.str());
  const auto policyObject = ExtractJsonObject(response.body, "policy");
  if (!policyObject.has_value()) {
    throw std::runtime_error("Enrollment response did not include a policy object");
  }

  return EnrollmentResult{
      .deviceId = RequireString(ExtractJsonString(response.body, "deviceId"), "deviceId"),
      .issuedAt = RequireString(ExtractJsonString(response.body, "issuedAt"), "issuedAt"),
      .commandChannelUrl = RequireString(ExtractJsonString(response.body, "commandChannelUrl"), "commandChannelUrl"),
      .policy = ParsePolicySnapshot(*policyObject)};
}

HeartbeatResult ControlPlaneClient::SendHeartbeat(const AgentState& state) const {
  if (state.deviceId.empty()) {
    throw std::runtime_error("Cannot send heartbeat without a device identifier");
  }

  const auto deviceApiKey = ExtractDeviceApiKeyFromCommandChannelUrl(state.commandChannelUrl);

  std::ostringstream body;
  body << "{"
       << "\"agentVersion\":\"" << EscapeJsonString(state.agentVersion) << "\","
       << "\"platformVersion\":\"" << EscapeJsonString(state.platformVersion) << "\","
       << "\"healthState\":\"" << EscapeJsonString(state.healthState) << "\","
       << "\"isolated\":" << (state.isolated ? "true" : "false")
       << "}";

  const auto response =
      RequestJson(L"POST", JoinUrl(baseUrl_, L"/api/v1/devices/" + state.deviceId + L"/heartbeat"), body.str(),
                  deviceApiKey);

  return HeartbeatResult{
      .receivedAt = RequireString(ExtractJsonString(response.body, "receivedAt"), "receivedAt"),
      .effectivePolicyRevision =
          RequireString(ExtractJsonString(response.body, "effectivePolicyRevision"), "effectivePolicyRevision"),
      .commandsPending = ExtractJsonInt(response.body, "commandsPending").value_or(0)};
}

PolicyCheckInResult ControlPlaneClient::CheckInPolicy(const AgentState& state) const {
  if (state.deviceId.empty()) {
    throw std::runtime_error("Cannot check in policy without a device identifier");
  }

  const auto deviceApiKey = ExtractDeviceApiKeyFromCommandChannelUrl(state.commandChannelUrl);

  std::ostringstream body;
  body << "{"
       << "\"currentPolicyRevision\":\"" << EscapeJsonString(state.policy.revision) << "\","
       << "\"agentVersion\":\"" << EscapeJsonString(state.agentVersion) << "\","
       << "\"platformVersion\":\"" << EscapeJsonString(state.platformVersion) << "\""
       << "}";

  const auto response =
      RequestJson(L"POST", JoinUrl(baseUrl_, L"/api/v1/devices/" + state.deviceId + L"/policy-check-in"), body.str(),
                  deviceApiKey);
  const auto policyObject = ExtractJsonObject(response.body, "policy");
  if (!policyObject.has_value()) {
    throw std::runtime_error("Policy check-in response did not include a policy object");
  }

  return PolicyCheckInResult{
      .retrievedAt = RequireString(ExtractJsonString(response.body, "retrievedAt"), "retrievedAt"),
      .changed = RequireBool(ExtractJsonBool(response.body, "changed"), "changed"),
      .policy = ParsePolicySnapshot(*policyObject)};
}

TelemetryBatchResult ControlPlaneClient::SendTelemetryBatch(const AgentState& state,
                                                            const std::vector<TelemetryRecord>& records) const {
  if (state.deviceId.empty()) {
    throw std::runtime_error("Cannot send telemetry without a device identifier");
  }

  const auto deviceApiKey = ExtractDeviceApiKeyFromCommandChannelUrl(state.commandChannelUrl);

  if (records.empty()) {
    return TelemetryBatchResult{};
  }

  std::ostringstream body;
  body << "{\"events\":[";
  for (std::size_t index = 0; index < records.size(); ++index) {
    const auto& record = records[index];
    if (index != 0) {
      body << ',';
    }

    body << "{"
         << "\"eventId\":\"" << EscapeJsonString(record.eventId) << "\","
         << "\"eventType\":\"" << EscapeJsonString(record.eventType) << "\","
         << "\"source\":\"" << EscapeJsonString(record.source) << "\","
         << "\"summary\":\"" << EscapeJsonString(record.summary) << "\","
         << "\"occurredAt\":\"" << EscapeJsonString(record.occurredAt) << "\","
         << "\"payloadJson\":\"" << EscapeJsonString(record.payloadJson) << "\""
         << "}";
  }
  body << "]}";

  const auto response =
      RequestJson(L"POST", JoinUrl(baseUrl_, L"/api/v1/devices/" + state.deviceId + L"/telemetry"), body.str(),
                  deviceApiKey);

  return TelemetryBatchResult{
      .receivedAt = RequireString(ExtractJsonString(response.body, "receivedAt"), "receivedAt"),
      .accepted = ExtractJsonInt(response.body, "accepted").value_or(0),
      .totalStored = ExtractJsonInt(response.body, "totalStored").value_or(0)};
}

CommandPollResult ControlPlaneClient::PollPendingCommands(const AgentState& state, const int limit) const {
  if (state.deviceId.empty()) {
    throw std::runtime_error("Cannot poll commands without a device identifier");
  }

  const auto deviceApiKey = ExtractDeviceApiKeyFromCommandChannelUrl(state.commandChannelUrl);

  const auto response = RequestJson(
      L"GET", JoinUrl(baseUrl_, L"/api/v1/devices/" + state.deviceId + L"/commands/pending?limit=" + std::to_wstring(limit)),
      {}, deviceApiKey);

  CommandPollResult result{
      .polledAt = RequireString(ExtractJsonString(response.body, "polledAt"), "polledAt"),
      .items = {}};

  for (const auto& itemJson : ExtractJsonObjectArray(response.body, "items")) {
    result.items.push_back(ParseRemoteCommand(itemJson));
  }

  return result;
}

void ControlPlaneClient::CompleteCommand(const AgentState& state, const std::wstring& commandId,
                                         const std::wstring& status, const std::wstring& resultJson) const {
  if (state.deviceId.empty()) {
    throw std::runtime_error("Cannot complete a command without a device identifier");
  }

  const auto deviceApiKey = ExtractDeviceApiKeyFromCommandChannelUrl(state.commandChannelUrl);

  std::ostringstream body;
  body << "{"
       << "\"status\":\"" << EscapeJsonString(status) << "\"";

  if (!resultJson.empty()) {
    body << ",\"resultJson\":\"" << EscapeJsonString(resultJson) << "\"";
  }

  body << "}";

  static_cast<void>(RequestJson(
      L"POST", JoinUrl(baseUrl_, L"/api/v1/devices/" + state.deviceId + L"/commands/" + commandId + L"/complete"),
      body.str(), deviceApiKey));
}

}  // namespace antivirus::agent
