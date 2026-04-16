#include "DestinationEnforcementBridge.h"

#include <mutex>

namespace antivirus::agent {
namespace {
std::mutex g_mutex;
DestinationEnforcementHandler g_handler = nullptr;
void* g_context = nullptr;
}  // namespace

void RegisterDestinationEnforcementHandler(const DestinationEnforcementHandler handler, void* context) {
  const std::scoped_lock lock(g_mutex);
  g_handler = handler;
  g_context = context;
}

bool InvokeDestinationEnforcementHandler(const DestinationEnforcementRequest& request,
                                         std::wstring* errorMessage) {
  DestinationEnforcementHandler handler = nullptr;
  void* context = nullptr;
  {
    const std::scoped_lock lock(g_mutex);
    handler = g_handler;
    context = g_context;
  }

  if (handler == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Destination enforcement is unavailable.";
    }
    return false;
  }

  return handler(context, request, errorMessage);
}

}  // namespace antivirus::agent
