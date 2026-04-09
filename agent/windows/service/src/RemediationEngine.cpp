#include "RemediationEngine.h"

#include <Windows.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <map>
#include <set>
#include <system_error>

#include "EvidenceRecorder.h"
#include "QuarantineStore.h"
#include "ScanEngine.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

struct ProcessRecord {
  DWORD processId{0};
  DWORD parentProcessId{0};
  std::filesystem::path imagePath;
};

std::wstring NormalizePath(const std::filesystem::path& path) {
  std::error_code error;
  auto normalized = std::filesystem::absolute(path, error);
  if (error) {
    normalized = path;
  }

  auto value = normalized.lexically_normal().wstring();
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring NormalizeString(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

bool PathMatches(const std::filesystem::path& candidate, const std::filesystem::path& subjectPath) {
  const auto normalizedCandidate = NormalizePath(candidate);
  const auto normalizedSubject = NormalizePath(subjectPath);
  if (normalizedCandidate == normalizedSubject) {
    return true;
  }

  const auto candidateFilename = NormalizeString(candidate.filename().wstring());
  const auto subjectFilename = NormalizeString(subjectPath.filename().wstring());
  return !candidateFilename.empty() && candidateFilename == subjectFilename;
}

std::vector<ProcessRecord> EnumerateProcesses() {
  std::vector<ProcessRecord> records;
  const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return records;
  }

  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot, &entry) == FALSE) {
    CloseHandle(snapshot);
    return records;
  }

  do {
    ProcessRecord record;
    record.processId = entry.th32ProcessID;
    record.parentProcessId = entry.th32ParentProcessID;

    const auto processHandle =
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
    if (processHandle != nullptr) {
      std::wstring imageBuffer(MAX_PATH, L'\0');
      DWORD bufferLength = static_cast<DWORD>(imageBuffer.size());
      if (QueryFullProcessImageNameW(processHandle, 0, imageBuffer.data(), &bufferLength) != FALSE) {
        imageBuffer.resize(bufferLength);
        record.imagePath = imageBuffer;
      }
      CloseHandle(processHandle);
    }

    records.push_back(std::move(record));
  } while (Process32NextW(snapshot, &entry) != FALSE);

  CloseHandle(snapshot);
  return records;
}

void CollectDescendants(const DWORD processId, const std::multimap<DWORD, DWORD>& childrenByParent,
                        std::vector<DWORD>& orderedIds) {
  const auto range = childrenByParent.equal_range(processId);
  for (auto it = range.first; it != range.second; ++it) {
    CollectDescendants(it->second, childrenByParent, orderedIds);
  }

  orderedIds.push_back(processId);
}

bool DeleteRegistryValueIfMatches(HKEY rootKey, const wchar_t* subKey, REGSAM wow64Flag,
                                  const std::filesystem::path& subjectPath, int* removedCount,
                                  std::vector<std::wstring>* removedArtifacts) {
  HKEY key = nullptr;
  if (RegOpenKeyExW(rootKey, subKey, 0, KEY_READ | KEY_WRITE | wow64Flag, &key) != ERROR_SUCCESS) {
    return true;
  }

  DWORD valueCount = 0;
  DWORD maxValueNameLength = 0;
  DWORD maxValueDataLength = 0;
  if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &valueCount, &maxValueNameLength,
                       &maxValueDataLength, nullptr, nullptr) != ERROR_SUCCESS) {
    RegCloseKey(key);
    return false;
  }

  std::vector<std::wstring> valuesToDelete;
  for (DWORD index = 0; index < valueCount; ++index) {
    std::wstring name(maxValueNameLength + 1, L'\0');
    std::vector<BYTE> data(maxValueDataLength + sizeof(wchar_t), 0);
    DWORD nameLength = static_cast<DWORD>(name.size());
    DWORD dataLength = static_cast<DWORD>(data.size());
    DWORD type = 0;
    if (RegEnumValueW(key, index, name.data(), &nameLength, nullptr, &type, data.data(), &dataLength) != ERROR_SUCCESS) {
      continue;
    }

    name.resize(nameLength);
    if (type != REG_SZ && type != REG_EXPAND_SZ) {
      continue;
    }

    std::wstring value(reinterpret_cast<wchar_t*>(data.data()), dataLength / sizeof(wchar_t));
    if (!value.empty() && value.back() == L'\0') {
      value.pop_back();
    }

    if (PathMatches(value, subjectPath) || NormalizeString(value).find(NormalizeString(subjectPath.filename().wstring())) !=
                                           std::wstring::npos) {
      valuesToDelete.push_back(name);
    }
  }

  for (const auto& name : valuesToDelete) {
    if (RegDeleteValueW(key, name.c_str()) == ERROR_SUCCESS) {
      ++(*removedCount);
      removedArtifacts->push_back(std::wstring(subKey) + L"\\" + name);
    }
  }

  RegCloseKey(key);
  return true;
}

std::wstring ResolveShortcutTarget(const std::filesystem::path& shortcutPath) {
  std::wstring target;
  const auto coInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  const bool coInitialized = SUCCEEDED(coInit);
  if (FAILED(coInit) && coInit != RPC_E_CHANGED_MODE) {
    return {};
  }

  IShellLinkW* shellLink = nullptr;
  if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
                                 reinterpret_cast<void**>(&shellLink))) &&
      shellLink != nullptr) {
    IPersistFile* persistFile = nullptr;
    if (SUCCEEDED(shellLink->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&persistFile))) &&
        persistFile != nullptr) {
      if (SUCCEEDED(persistFile->Load(shortcutPath.c_str(), STGM_READ))) {
        std::array<wchar_t, MAX_PATH> buffer{};
        WIN32_FIND_DATAW data{};
        if (SUCCEEDED(shellLink->GetPath(buffer.data(), static_cast<int>(buffer.size()), &data, SLGP_UNCPRIORITY))) {
          target = buffer.data();
        }
      }
      persistFile->Release();
    }
    shellLink->Release();
  }

  if (coInitialized) {
    CoUninitialize();
  }
  return target;
}

std::wstring ReadSmallText(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    return {};
  }

  std::string buffer(4096, '\0');
  input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
  buffer.resize(static_cast<std::size_t>(std::max<std::streamsize>(input.gcount(), 0)));
  return Utf8ToWide(buffer);
}

void AppendOutcome(RemediationOutcome& target, const RemediationOutcome& source) {
  target.processesTerminated += source.processesTerminated;
  target.registryValuesRemoved += source.registryValuesRemoved;
  target.startupArtifactsRemoved += source.startupArtifactsRemoved;
  target.quarantineApplied = target.quarantineApplied || source.quarantineApplied;
  if (!source.quarantineRecordId.empty()) {
    target.quarantineRecordId = source.quarantineRecordId;
  }
  if (!source.evidenceRecordId.empty()) {
    target.evidenceRecordId = source.evidenceRecordId;
  }
  target.removedArtifacts.insert(target.removedArtifacts.end(), source.removedArtifacts.begin(),
                                 source.removedArtifacts.end());
  if (!source.errorMessage.empty()) {
    if (!target.errorMessage.empty()) {
      target.errorMessage += L" ";
    }
    target.errorMessage += source.errorMessage;
  }
}

}  // namespace

RemediationEngine::RemediationEngine(const AgentConfig& config) : config_(config) {}

RemediationOutcome RemediationEngine::TerminateProcessesForPath(const std::filesystem::path& subjectPath,
                                                                const bool includeChildren) const {
  RemediationOutcome outcome;
  const auto processes = EnumerateProcesses();
  std::multimap<DWORD, DWORD> childrenByParent;
  std::set<DWORD> rootIds;

  for (const auto& process : processes) {
    childrenByParent.emplace(process.parentProcessId, process.processId);
    if (!process.imagePath.empty() && PathMatches(process.imagePath, subjectPath)) {
      rootIds.insert(process.processId);
    }
  }

  std::vector<DWORD> orderedIds;
  for (const auto rootId : rootIds) {
    if (includeChildren) {
      CollectDescendants(rootId, childrenByParent, orderedIds);
    } else {
      orderedIds.push_back(rootId);
    }
  }

  for (const auto processId : orderedIds) {
    const auto handle = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (handle == nullptr) {
      continue;
    }

    if (TerminateProcess(handle, 1) != FALSE) {
      ++outcome.processesTerminated;
    }
    CloseHandle(handle);
  }

  outcome.success = true;
  return outcome;
}

RemediationOutcome RemediationEngine::CleanupPersistenceForPath(const std::filesystem::path& subjectPath) const {
  RemediationOutcome outcome;
  DeleteRegistryValueIfMatches(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, subjectPath,
                               &outcome.registryValuesRemoved, &outcome.removedArtifacts);
  DeleteRegistryValueIfMatches(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0,
                               subjectPath, &outcome.registryValuesRemoved, &outcome.removedArtifacts);
  DeleteRegistryValueIfMatches(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_WOW64_64KEY,
                               subjectPath, &outcome.registryValuesRemoved, &outcome.removedArtifacts);
  DeleteRegistryValueIfMatches(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                               KEY_WOW64_64KEY, subjectPath, &outcome.registryValuesRemoved, &outcome.removedArtifacts);
  DeleteRegistryValueIfMatches(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                               KEY_WOW64_64KEY, subjectPath, &outcome.registryValuesRemoved, &outcome.removedArtifacts);

  PWSTR startupPath = nullptr;
  PWSTR commonStartupPath = nullptr;
  if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Startup, 0, nullptr, &startupPath))) {
    std::filesystem::path folder(startupPath);
    CoTaskMemFree(startupPath);
    if (std::filesystem::exists(folder)) {
      for (const auto& entry : std::filesystem::directory_iterator(folder)) {
        const auto candidate = entry.path();
        bool remove = PathMatches(candidate, subjectPath);
        if (!remove && candidate.extension() == L".lnk") {
          remove = PathMatches(ResolveShortcutTarget(candidate), subjectPath);
        }
        if (!remove) {
          const auto text = NormalizeString(ReadSmallText(candidate));
          const auto subject = NormalizeString(subjectPath.wstring());
          remove = !text.empty() && text.find(subject) != std::wstring::npos;
        }
        if (remove) {
          std::error_code error;
          std::filesystem::remove(candidate, error);
          if (!error) {
            ++outcome.startupArtifactsRemoved;
            outcome.removedArtifacts.push_back(candidate.wstring());
          }
        }
      }
    }
  }

  if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_CommonStartup, 0, nullptr, &commonStartupPath))) {
    std::filesystem::path folder(commonStartupPath);
    CoTaskMemFree(commonStartupPath);
    if (std::filesystem::exists(folder)) {
      for (const auto& entry : std::filesystem::directory_iterator(folder)) {
        const auto candidate = entry.path();
        bool remove = PathMatches(candidate, subjectPath);
        if (!remove && candidate.extension() == L".lnk") {
          remove = PathMatches(ResolveShortcutTarget(candidate), subjectPath);
        }
        if (!remove) {
          const auto text = NormalizeString(ReadSmallText(candidate));
          const auto subject = NormalizeString(subjectPath.wstring());
          remove = !text.empty() && text.find(subject) != std::wstring::npos;
        }
        if (remove) {
          std::error_code error;
          std::filesystem::remove(candidate, error);
          if (!error) {
            ++outcome.startupArtifactsRemoved;
            outcome.removedArtifacts.push_back(candidate.wstring());
          }
        }
      }
    }
  }

  outcome.success = true;
  return outcome;
}

RemediationOutcome RemediationEngine::RemediatePath(const std::filesystem::path& subjectPath,
                                                    const PolicySnapshot& policy) const {
  RemediationOutcome outcome;
  AppendOutcome(outcome, TerminateProcessesForPath(subjectPath, true));
  AppendOutcome(outcome, CleanupPersistenceForPath(subjectPath));

  std::error_code error;
  if (std::filesystem::exists(subjectPath, error)) {
    const auto finding = ScanFile(subjectPath, policy, config_.scanExcludedPaths);
    if (finding.has_value()) {
      auto mutableFinding = *finding;
      if (mutableFinding.verdict.disposition == VerdictDisposition::Quarantine ||
          mutableFinding.verdict.disposition == VerdictDisposition::Block) {
        QuarantineStore quarantineStore(config_.quarantineRootPath, config_.runtimeDatabasePath);
        const auto quarantineResult = quarantineStore.QuarantineFile(mutableFinding);
        if (quarantineResult.success) {
          mutableFinding.remediationStatus = RemediationStatus::Quarantined;
          mutableFinding.quarantineRecordId = quarantineResult.recordId;
          mutableFinding.quarantinedPath = quarantineResult.quarantinedPath;
          outcome.quarantineApplied = true;
          outcome.quarantineRecordId = quarantineResult.recordId;
        } else {
          mutableFinding.remediationStatus = RemediationStatus::Failed;
          mutableFinding.remediationError = quarantineResult.errorMessage;
        }
      }

      EvidenceRecorder evidenceRecorder(config_.evidenceRootPath, config_.runtimeDatabasePath);
      const auto evidence = evidenceRecorder.RecordScanFinding(mutableFinding, policy, L"remediation-engine");
      outcome.evidenceRecordId = evidence.recordId;
    }
  }

  outcome.success = outcome.errorMessage.empty();
  return outcome;
}

}  // namespace antivirus::agent
