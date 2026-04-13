#pragma once

#include <string>
#include <vector>

namespace antivirus::agent {

struct InstalledSoftwareInventoryItem {
  std::wstring softwareId;
  std::wstring displayName;
  std::wstring displayVersion;
  std::wstring publisher;
  std::wstring installLocation;
  std::wstring uninstallCommand;
  std::wstring quietUninstallCommand;
  std::wstring installDate;
  std::wstring displayIconPath;
  std::vector<std::wstring> executableNames;
  std::vector<std::wstring> executablePaths;
  bool blocked{false};
  std::wstring updateState{L"unknown"};
  std::wstring lastUpdateCheckAt;
  std::wstring updateSummary;
  std::wstring supportedPatchSource;
  bool manualPatchOnly{false};
  bool patchUnsupported{false};
};

struct DeviceInventorySnapshot {
  std::vector<std::wstring> privateIpAddresses;
  std::wstring lastLoggedOnUser;
  std::vector<InstalledSoftwareInventoryItem> installedSoftware;
};

DeviceInventorySnapshot CollectDeviceInventorySnapshot();
std::wstring BuildDeviceInventoryPayload(const DeviceInventorySnapshot& snapshot);

}  // namespace antivirus::agent
