#include "LocalControlChannel.h"

#include <Windows.h>
#include <sddl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <mutex>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "LocalSecurity.h"
#include "StringUtils.h"

namespace antivirus::agent {

namespace {

struct LocalPipeRequest {
  std::wstring type;
  std::wstring recordId;
  std::wstring targetPath;
  std::wstring payloadJson;
};

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

std::optional<std::wstring> ExtractPayloadString(const std::wstring& json, const std::string& key) {
  const auto utf8Json = WideToUtf8(json);
  const std::regex pattern("\"" + EscapeRegex(key) + "\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"");
  std::smatch match;
  if (!std::regex_search(utf8Json, match, pattern)) {
    return std::nullopt;
  }

  return Utf8ToWide(UnescapeJsonString(match[1].str()));
}

std::wstring EscapeJsonValue(const std::wstring& value) {
  return Utf8ToWide(EscapeJsonString(value));
}

std::wstring BuildResponseJson(const bool success, const int statusCode, const std::wstring& resultJson,
                               const std::wstring& errorMessage, const std::wstring& role = L"",
                               const std::wstring& requester = L"") {
  std::wstring json = L"{\"success\":";
  json += success ? L"true" : L"false";
  json += L",\"statusCode\":";
  json += std::to_wstring(statusCode);
  json += L",\"resultJson\":\"";
  json += EscapeJsonValue(resultJson);
  json += L"\",\"errorMessage\":\"";
  json += EscapeJsonValue(errorMessage);
  json += L"\"";
  if (!role.empty()) {
    json += L",\"role\":\"";
    json += EscapeJsonValue(role);
    json += L"\"";
  }
  if (!requester.empty()) {
    json += L",\"requester\":\"";
    json += EscapeJsonValue(requester);
    json += L"\"";
  }
  json += L"}";
  return json;
}

LocalAction ResolveActionForCommandType(const std::wstring& type) {
  if (type == L"quarantine.restore" || type == L"quarantine.delete") {
    return LocalAction::QuarantineMutate;
  }

  if (type == L"patch.software.install" || type == L"patch.windows.install" || type == L"patch.cycle.run") {
    return LocalAction::PatchInstall;
  }

  if (type == L"patch.scan" || type == L"software.update.search") {
    return LocalAction::PatchRefresh;
  }

  if (type == L"support.bundle.export" || type == L"support.bundle.export.full" || type == L"storage.maintenance.run") {
    return LocalAction::ExportSupportBundle;
  }

  return LocalAction::ViewStatus;
}

bool IsSupportedLocalCommand(const std::wstring& type) {
  static const std::array<const wchar_t*, 9> kSupportedTypes = {
      L"quarantine.restore",      L"quarantine.delete",    L"patch.scan",         L"patch.software.install",
      L"patch.windows.install",   L"patch.cycle.run",      L"support.bundle.export", L"support.bundle.export.full",
      L"storage.maintenance.run"};

  return std::any_of(kSupportedTypes.begin(), kSupportedTypes.end(),
                     [&type](const auto* candidate) { return type == candidate; });
}

bool ReadPipeMessage(const HANDLE pipe, std::wstring* message) {
  if (message == nullptr) {
    return false;
  }

  std::string buffer;
  std::array<char, 4096> chunk{};
  DWORD bytesRead = 0;

  for (;;) {
    if (ReadFile(pipe, chunk.data(), static_cast<DWORD>(chunk.size()), &bytesRead, nullptr) != FALSE) {
      buffer.append(chunk.data(), chunk.data() + bytesRead);
      break;
    }

    const auto error = GetLastError();
    if (error != ERROR_MORE_DATA) {
      return false;
    }

    buffer.append(chunk.data(), chunk.data() + bytesRead);
  }

  *message = Utf8ToWide(buffer);
  return true;
}

bool WritePipeMessage(const HANDLE pipe, const std::wstring& message) {
  const auto payload = WideToUtf8(message);
  DWORD bytesWritten = 0;
  return WriteFile(pipe, payload.data(), static_cast<DWORD>(payload.size()), &bytesWritten, nullptr) != FALSE;
}

bool ParsePipeRequest(const std::wstring& json, LocalPipeRequest* request, std::wstring* errorMessage) {
  if (request == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir local control did not receive a request target.";
    }
    return false;
  }

  const auto type = ExtractPayloadString(json, "type");
  if (!type.has_value() || type->empty()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Fenrir local control request is missing a command type.";
    }
    return false;
  }

  request->type = *type;
  request->recordId = ExtractPayloadString(json, "recordId").value_or(L"");
  request->targetPath = ExtractPayloadString(json, "targetPath").value_or(L"");
  request->payloadJson = ExtractPayloadString(json, "payloadJson").value_or(L"{}");
  return true;
}

std::wstring QueryImpersonatedUserName() {
  std::array<wchar_t, 256> buffer{};
  DWORD size = static_cast<DWORD>(buffer.size());
  if (GetUserNameW(buffer.data(), &size) == FALSE) {
    return L"unknown";
  }

  if (size > 0 && buffer[size - 1] == L'\0') {
    --size;
  }
  return std::wstring(buffer.data(), size);
}

HANDLE CreatePipeSecurityDescriptor() {
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)", SDDL_REVISION_1, &descriptor, nullptr) == FALSE) {
    return nullptr;
  }

  return descriptor;
}

std::wstring BuildLocalCommandId() {
  return L"local-" + CurrentUtcTimestamp() + L"-" + GenerateGuidString();
}

}  // namespace

class LocalControlChannelState {
 public:
  std::mutex lock;
  HANDLE activePipe{INVALID_HANDLE_VALUE};
  std::thread worker;
};

struct LocalControlChannel::State : public LocalControlChannelState {};

LocalControlChannel::LocalControlChannel(CommandExecutor executor, StopPredicate shouldStop)
    : executor_(std::move(executor)), shouldStop_(std::move(shouldStop)), state_(std::make_unique<State>()) {}

LocalControlChannel::~LocalControlChannel() { Stop(); }

void LocalControlChannel::Start() {
  auto* state = state_.get();
  if (state == nullptr || running_) {
    return;
  }

  stopRequested_ = false;
  running_ = true;
  state->worker = std::thread([this]() { Run(); });
}

void LocalControlChannel::Stop() {
  auto* state = state_.get();
  if (state == nullptr || !running_) {
    return;
  }

  stopRequested_ = true;
  {
    std::lock_guard guard(state->lock);
    if (state->activePipe != INVALID_HANDLE_VALUE) {
      CancelSynchronousIo(reinterpret_cast<HANDLE>(state->worker.native_handle()));
      CloseHandle(state->activePipe);
      state->activePipe = INVALID_HANDLE_VALUE;
    }
  }

  if (state->worker.joinable()) {
    state->worker.join();
  }
  running_ = false;
}

void LocalControlChannel::Run() {
  auto* state = state_.get();
  if (state == nullptr) {
    return;
  }

  while (!stopRequested_ && !(shouldStop_ && shouldStop_())) {
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = FALSE;
    attributes.lpSecurityDescriptor = CreatePipeSecurityDescriptor();

    const HANDLE pipe =
        CreateNamedPipeW(kFenrirLocalControlPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                         4, 16 * 1024, 16 * 1024, 1000, &attributes);
    if (attributes.lpSecurityDescriptor != nullptr) {
      LocalFree(attributes.lpSecurityDescriptor);
      attributes.lpSecurityDescriptor = nullptr;
    }

    if (pipe == INVALID_HANDLE_VALUE) {
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
      continue;
    }

    {
      std::lock_guard guard(state->lock);
      state->activePipe = pipe;
    }

    const auto connected = ConnectNamedPipe(pipe, nullptr) != FALSE || GetLastError() == ERROR_PIPE_CONNECTED;
    if (!connected) {
      {
        std::lock_guard guard(state->lock);
        if (state->activePipe == pipe) {
          state->activePipe = INVALID_HANDLE_VALUE;
        }
      }
      CloseHandle(pipe);
      if (stopRequested_ || (shouldStop_ && shouldStop_())) {
        break;
      }
      continue;
    }

    std::wstring requestMessage;
    if (!ReadPipeMessage(pipe, &requestMessage)) {
      WritePipeMessage(pipe, BuildResponseJson(false, 400, L"", L"Fenrir local control could not read the request payload."));
      FlushFileBuffers(pipe);
      DisconnectNamedPipe(pipe);
      {
        std::lock_guard guard(state->lock);
        if (state->activePipe == pipe) {
          state->activePipe = INVALID_HANDLE_VALUE;
        }
      }
      CloseHandle(pipe);
      continue;
    }

    LocalPipeRequest request{};
    std::wstring parseError;
    if (!ParsePipeRequest(requestMessage, &request, &parseError)) {
      WritePipeMessage(pipe, BuildResponseJson(false, 400, L"", parseError));
      FlushFileBuffers(pipe);
      DisconnectNamedPipe(pipe);
      {
        std::lock_guard guard(state->lock);
        if (state->activePipe == pipe) {
          state->activePipe = INVALID_HANDLE_VALUE;
        }
      }
      CloseHandle(pipe);
      continue;
    }

    if (!IsSupportedLocalCommand(request.type)) {
      WritePipeMessage(pipe, BuildResponseJson(false, 404, L"", L"Fenrir local control does not expose that command."));
      FlushFileBuffers(pipe);
      DisconnectNamedPipe(pipe);
      {
        std::lock_guard guard(state->lock);
        if (state->activePipe == pipe) {
          state->activePipe = INVALID_HANDLE_VALUE;
        }
      }
      CloseHandle(pipe);
      continue;
    }

    LocalActionAuthorization authorization{};
    std::wstring requester = L"unknown";
    if (ImpersonateNamedPipeClient(pipe) != FALSE) {
      authorization = AuthorizeCurrentUser(ResolveActionForCommandType(request.type));
      requester = QueryImpersonatedUserName();
      RevertToSelf();
    } else {
      authorization = LocalActionAuthorization{
          .role = LocalUserRole::Unknown,
          .allowed = false,
          .requestOnly = false,
          .reason = L"Fenrir could not verify the caller identity for this local action."};
    }

    if (!authorization.allowed) {
      WritePipeMessage(pipe, BuildResponseJson(false, 403, L"", authorization.reason, LocalUserRoleToString(authorization.role),
                                               requester));
      FlushFileBuffers(pipe);
      DisconnectNamedPipe(pipe);
      {
        std::lock_guard guard(state->lock);
        if (state->activePipe == pipe) {
          state->activePipe = INVALID_HANDLE_VALUE;
        }
      }
      CloseHandle(pipe);
      continue;
    }

    try {
      RemoteCommand command{};
      command.commandId = BuildLocalCommandId();
      command.type = request.type;
      command.issuedBy = L"local-dashboard:" + requester;
      command.createdAt = CurrentUtcTimestamp();
      command.updatedAt = command.createdAt;
      command.recordId = request.recordId;
      command.targetPath = request.targetPath;
      command.payloadJson = request.payloadJson;

      const auto resultJson = executor_(command);
      WritePipeMessage(pipe, BuildResponseJson(true, 200, resultJson, L"", LocalUserRoleToString(authorization.role),
                                               requester));
    } catch (const std::exception& error) {
      WritePipeMessage(pipe,
                       BuildResponseJson(false, 500, L"", Utf8ToWide(error.what()), LocalUserRoleToString(authorization.role),
                                         requester));
    }

    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    {
      std::lock_guard guard(state->lock);
      if (state->activePipe == pipe) {
        state->activePipe = INVALID_HANDLE_VALUE;
      }
    }
    CloseHandle(pipe);
  }
}

}  // namespace antivirus::agent
