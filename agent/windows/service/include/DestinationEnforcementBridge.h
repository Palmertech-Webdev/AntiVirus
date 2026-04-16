#pragma once

#include <string>
#include <vector>

namespace antivirus::agent {

struct DestinationEnforcementRequest {
  std::wstring displayDestination;
  std::vector<std::wstring> remoteAddresses;
  std::wstring sourceApplication;
  std::wstring summary;
  std::wstring reason;
};

using DestinationEnforcementHandler = bool (*)(void* context,
                                               const DestinationEnforcementRequest& request,
                                               std::wstring* errorMessage);

void RegisterDestinationEnforcementHandler(DestinationEnforcementHandler handler, void* context);
bool InvokeDestinationEnforcementHandler(const DestinationEnforcementRequest& request,
                                         std::wstring* errorMessage = nullptr);

}  // namespace antivirus::agent
