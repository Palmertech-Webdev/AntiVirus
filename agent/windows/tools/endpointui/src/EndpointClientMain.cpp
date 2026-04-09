#include <Windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <uxtheme.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "AgentConfig.h"
#include "EndpointClient.h"
#include "ProcessInventory.h"
#include "LocalScanRunner.h"
#include "LocalStateStore.h"
#include "ServiceInventory.h"
#include "StringUtils.h"

namespace {

using antivirus::agent::EndpointClientSnapshot;
using antivirus::agent::LocalServiceState;

constexpr wchar_t kWindowClassName[] = L"FenrirEndpointClientWindow";
constexpr wchar_t kWindowTitle[] = L"Fenrir Protection Center";
constexpr wchar_t kInstanceMutexName[] = L"Local\\FenrirEndpointClientSingleton";
constexpr wchar_t kRestoreWindowMessageName[] = L"FenrirEndpointClient.RestoreWindow";
constexpr UINT kTrayMessage = WM_APP + 1;
constexpr UINT kScanCompleteMessage = WM_APP + 2;
constexpr UINT kScanProgressMessage = WM_APP + 3;
constexpr UINT_PTR kRefreshTimerId = 100;
constexpr UINT kRefreshIntervalMs = 10000;

enum : int {
  IDC_BRAND_CARD = 1001,
  IDC_TITLE = 1002,
  IDC_SUBTITLE = 1003,
  IDC_STATUS_BADGE = 1004,
  IDC_PRIMARY_SECTION_TITLE = 1005,
  IDC_SECONDARY_SECTION_TITLE = 1006,
  IDC_SUMMARY_CARD = 1007,
  IDC_DETAILS_CARD = 1008,
  IDC_METRIC_THREATS = 1009,
  IDC_METRIC_QUARANTINE = 1010,
  IDC_METRIC_SERVICE = 1011,
  IDC_METRIC_SYNC = 1012,
  IDC_SCAN_STATUS = 1013,
  IDC_PROGRESS = 1014,
  IDC_THREATS_LIST = 1015,
  IDC_QUARANTINE_LIST = 1016,
  IDC_HISTORY_LIST = 1017,
  IDC_DETAIL_EDIT = 1018,
  IDC_BUTTON_REFRESH = 1101,
  IDC_BUTTON_QUICKSCAN = 1102,
  IDC_BUTTON_FULLSCAN = 1103,
  IDC_BUTTON_CUSTOMSCAN = 1104,
  IDC_BUTTON_STARTSERVICE = 1105,
  IDC_BUTTON_OPENQUARANTINE = 1106,
  IDC_BUTTON_RESTORE = 1107,
  IDC_BUTTON_DELETE = 1108,
  IDC_NAV_DASHBOARD = 1201,
  IDC_NAV_THREATS = 1202,
  IDC_NAV_QUARANTINE = 1203,
  IDC_NAV_SCANS = 1204,
  IDC_NAV_SERVICE = 1205,
  IDC_NAV_HISTORY = 1206,
  IDC_NAV_SETTINGS = 1207,
  IDM_TRAY_OPEN = 2001,
  IDM_TRAY_QUICKSCAN = 2002,
  IDM_TRAY_FULLSCAN = 2003,
  IDM_TRAY_QUARANTINE = 2004,
  IDM_TRAY_EXIT = 2005
};

enum class ScanPreset {
  Quick,
  Full,
  Folder
};

enum class ClientPage : int {
  Dashboard = 0,
  Threats = 1,
  Quarantine = 2,
  Scans = 3,
  Service = 4,
  History = 5,
  Settings = 6
};

struct ScanCompletePayload {
  std::wstring summary;
  bool success{true};
};

struct ScanProgressPayload {
  std::wstring status;
  std::uint32_t completedTargets{0};
  std::uint32_t totalTargets{0};
};

struct LaunchOptions {
  bool backgroundMode{false};
};

HANDLE g_instanceMutex = nullptr;

struct UiContext {
  antivirus::agent::AgentConfig config;
  EndpointClientSnapshot snapshot;
  NOTIFYICONDATAW trayIcon{};
  HWND hwnd{};
  HWND brandCard{};
  HWND titleLabel{};
  HWND subtitleLabel{};
  HWND statusBadge{};
  HWND primarySectionTitle{};
  HWND secondarySectionTitle{};
  HWND summaryCard{};
  HWND detailsCard{};
  HWND metricThreats{};
  HWND metricQuarantine{};
  HWND metricService{};
  HWND metricSync{};
  HWND scanStatusLabel{};
  HWND progressBar{};
  HWND threatsList{};
  HWND quarantineList{};
  HWND historyList{};
  HWND detailEdit{};
  HWND refreshButton{};
  HWND quickScanButton{};
  HWND fullScanButton{};
  HWND customScanButton{};
  HWND startServiceButton{};
  HWND openQuarantineButton{};
  HWND restoreButton{};
  HWND deleteButton{};
  HWND navDashboardButton{};
  HWND navThreatsButton{};
  HWND navQuarantineButton{};
  HWND navScansButton{};
  HWND navServiceButton{};
  HWND navHistoryButton{};
  HWND navSettingsButton{};
  HFONT titleFont{};
  HFONT headingFont{};
  HFONT bodyFont{};
  HBRUSH windowBrush{};
  HBRUSH surfaceBrush{};
  HBRUSH summarySafeBrush{};
  HBRUSH summaryWarningBrush{};
  HBRUSH summaryDangerBrush{};
  HBRUSH detailsBrush{};
  HBRUSH metricInfoBrush{};
  HBRUSH metricSuccessBrush{};
  HBRUSH metricWarningBrush{};
  HBRUSH metricDangerBrush{};
  HBRUSH detailBrush{};
  HBRUSH listBrush{};
  HICON iconNeutralSmall{};
  HICON iconNeutralLarge{};
  HICON iconSafeSmall{};
  HICON iconSafeLarge{};
  HICON iconWarningSmall{};
  HICON iconWarningLarge{};
  HICON iconDangerSmall{};
  HICON iconDangerLarge{};
  bool trayAdded{false};
  bool allowExit{false};
  bool backgroundMode{false};
  bool snapshotPrimed{false};
  std::size_t lastObservedThreatCount{0};
  LocalServiceState lastObservedServiceState{LocalServiceState::Unknown};
  std::wstring lastThreatFingerprint;
  std::atomic_bool scanRunning{false};
  std::wstring activeScanLabel;
  ClientPage currentPage{ClientPage::Dashboard};
};

UiContext* GetContext(HWND hwnd) {
  return reinterpret_cast<UiContext*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

void UpdateTrayIcon(UiContext& context);

std::wstring NullableText(const std::wstring& value, const wchar_t* fallback = L"(not available)") {
  return value.empty() ? std::wstring(fallback) : value;
}

UINT RestoreWindowMessageId() {
  static const UINT messageId = RegisterWindowMessageW(kRestoreWindowMessageName);
  return messageId;
}

bool HasSwitch(const std::vector<std::wstring>& arguments, const wchar_t* value) {
  return std::any_of(arguments.begin(), arguments.end(),
                     [value](const std::wstring& argument) { return _wcsicmp(argument.c_str(), value) == 0; });
}

bool IsCurrentUserAdmin() {
  return IsUserAnAdmin() != FALSE;
}

LaunchOptions ParseLaunchOptions() {
  LaunchOptions options;
  int argumentCount = 0;
  const auto argumentValues = CommandLineToArgvW(GetCommandLineW(), &argumentCount);
  if (argumentValues == nullptr) {
    return options;
  }

  std::vector<std::wstring> arguments;
  arguments.reserve(static_cast<std::size_t>(argumentCount));
  for (int index = 0; index < argumentCount; ++index) {
    arguments.emplace_back(argumentValues[index]);
  }
  LocalFree(argumentValues);

  options.backgroundMode =
      HasSwitch(arguments, L"--background") || HasSwitch(arguments, L"--tray") || HasSwitch(arguments, L"/background");
  return options;
}

bool IsWindowInteractive(const UiContext& context) {
  return IsWindowVisible(context.hwnd) != FALSE;
}

std::wstring ProtectionHeadline(const EndpointClientSnapshot& snapshot) {
  if (snapshot.openThreatCount != 0) {
    return L"Threats need attention";
  }

  if (snapshot.serviceState == LocalServiceState::Running &&
      _wcsicmp(snapshot.agentState.healthState.c_str(), L"healthy") == 0) {
    return L"Protected";
  }

  if (snapshot.serviceState == LocalServiceState::NotInstalled) {
    return L"Protection service is not installed";
  }

  if (snapshot.serviceState == LocalServiceState::Stopped) {
    return L"Protection service is stopped";
  }

  return L"Protection is degraded";
}

std::wstring ProtectionGuidance(const EndpointClientSnapshot& snapshot) {
  if (snapshot.serviceState == LocalServiceState::NotInstalled) {
    return L"Local scans are available, but always-on background protection will not run until the endpoint service is installed.";
  }

  if (snapshot.serviceState == LocalServiceState::Stopped) {
    return L"Start the protection service to restore continuous monitoring, telemetry upload, and command handling.";
  }

  if (snapshot.openThreatCount != 0) {
    return L"Recent malicious activity was detected locally. Review the Threats and Quarantine tabs, then decide whether anything should be restored or removed.";
  }

  if (_wcsicmp(snapshot.agentState.healthState.c_str(), L"healthy") != 0) {
    return L"The endpoint is still reporting a degraded runtime state. Review the service state and recent local findings to confirm what needs attention.";
  }

  return L"Background protection is running and no unresolved local threats are currently recorded.";
}

std::wstring BuildSummaryCardText(const EndpointClientSnapshot& snapshot) {
  std::wstringstream stream;
  stream << ProtectionHeadline(snapshot) << L"\r\n\r\n" << ProtectionGuidance(snapshot);
  return stream.str();
}

std::wstring BuildDetailsCardText(const EndpointClientSnapshot& snapshot) {
  std::wstringstream stream;
  stream << L"Device: " << NullableText(snapshot.agentState.hostname) << L"\r\n"
         << L"Service: " << antivirus::agent::LocalServiceStateToString(snapshot.serviceState) << L"\r\n"
         << L"Policy: " << NullableText(snapshot.agentState.policy.policyName) << L" ("
         << NullableText(snapshot.agentState.policy.revision, L"n/a") << L")\r\n"
         << L"Last heartbeat: " << NullableText(snapshot.agentState.lastHeartbeatAt, L"(never)") << L"\r\n"
         << L"Last policy sync: " << NullableText(snapshot.agentState.lastPolicySyncAt, L"(never)") << L"\r\n"
         << L"Queued uploads: " << snapshot.queuedTelemetryCount;
  return stream.str();
}

std::wstring BuildMetricCardText(const std::wstring& label, const std::wstring& value, const std::wstring& detail = L"") {
  std::wstringstream stream;
  stream << label << L"\r\n" << value;
  if (!detail.empty()) {
    stream << L"\r\n" << detail;
  }
  return stream.str();
}

std::wstring BuildSubtitleText() {
  return L"Local threat response, quarantine, and on-demand scanning for this device.";
}

bool IsScanSessionRecord(const antivirus::agent::ScanHistoryRecord& record) {
  return _wcsicmp(record.contentType.c_str(), L"scan-session") == 0;
}

std::wstring OverallStatusChip(const EndpointClientSnapshot& snapshot) {
  if (snapshot.serviceState == LocalServiceState::NotInstalled || snapshot.serviceState == LocalServiceState::Stopped) {
    return L"Protection off";
  }
  if (snapshot.openThreatCount != 0 || _wcsicmp(snapshot.agentState.healthState.c_str(), L"healthy") != 0) {
    return L"Attention needed";
  }
  return L"Protected";
}

std::wstring BuildBrandCardText(const EndpointClientSnapshot& snapshot) {
  std::wstringstream stream;
  stream << L"FENRIR ENDPOINT\r\n"
         << NullableText(snapshot.agentState.hostname, L"Local device") << L"\r\n"
         << OverallStatusChip(snapshot) << L"\r\n"
         << L"Policy " << NullableText(snapshot.agentState.policy.revision, L"n/a");
  return stream.str();
}

std::wstring PageTitle(const ClientPage page) {
  switch (page) {
    case ClientPage::Threats:
      return L"Threats";
    case ClientPage::Quarantine:
      return L"Quarantine";
    case ClientPage::Scans:
      return L"Scans";
    case ClientPage::Service:
      return L"Service";
    case ClientPage::History:
      return L"History";
    case ClientPage::Settings:
      return L"Settings";
    case ClientPage::Dashboard:
    default:
      return L"Dashboard";
  }
}

std::wstring PageSubtitle(const ClientPage page, const EndpointClientSnapshot& snapshot) {
  switch (page) {
    case ClientPage::Threats:
      return L"Investigate active detections, review evidence, and decide what needs action.";
    case ClientPage::Quarantine:
      return L"Review contained items, confirm whether anything should be restored, and keep the device clean.";
    case ClientPage::Scans:
      return L"Launch quick, full, or targeted scans and follow the latest scan activity from this device.";
    case ClientPage::Service:
      return L"Runtime health, upload queue, service posture, and local protection readiness.";
    case ClientPage::History:
      return L"Historical detections, scan sessions, and local agent actions for this endpoint.";
    case ClientPage::Settings:
      return L"Local configuration, runtime paths, and endpoint client preferences for this device.";
    case ClientPage::Dashboard:
    default:
      if (snapshot.serviceState == LocalServiceState::NotInstalled) {
        return L"Background protection is off because the endpoint service is not installed. Local scans are still available.";
      }
      return L"See protection status, recent activity, and the next action to take on this endpoint.";
  }
}

std::wstring PrimarySectionTitle(const ClientPage page) {
  switch (page) {
    case ClientPage::Threats:
      return L"Threat queue";
    case ClientPage::Quarantine:
      return L"Quarantine inventory";
    case ClientPage::Scans:
      return L"Recent scans";
    case ClientPage::History:
      return L"Activity timeline";
    case ClientPage::Service:
      return L"Protection overview";
    case ClientPage::Settings:
      return L"Local preferences";
    case ClientPage::Dashboard:
    default:
      return L"Recent activity";
  }
}

std::wstring SecondarySectionTitle(const ClientPage page) {
  switch (page) {
    case ClientPage::Quarantine:
      return L"Item detail";
    case ClientPage::Threats:
      return L"Threat detail";
    case ClientPage::Service:
      return L"Runtime detail";
    case ClientPage::Settings:
      return L"Configuration detail";
    case ClientPage::Dashboard:
    case ClientPage::Scans:
    case ClientPage::History:
    default:
      return L"Detail";
  }
}

int NavButtonIdForPage(const ClientPage page) {
  switch (page) {
    case ClientPage::Dashboard:
      return IDC_NAV_DASHBOARD;
    case ClientPage::Threats:
      return IDC_NAV_THREATS;
    case ClientPage::Quarantine:
      return IDC_NAV_QUARANTINE;
    case ClientPage::Scans:
      return IDC_NAV_SCANS;
    case ClientPage::Service:
      return IDC_NAV_SERVICE;
    case ClientPage::History:
      return IDC_NAV_HISTORY;
    case ClientPage::Settings:
    default:
      return IDC_NAV_SETTINGS;
  }
}

std::optional<ClientPage> PageForNavButtonId(const int controlId) {
  switch (controlId) {
    case IDC_NAV_DASHBOARD:
      return ClientPage::Dashboard;
    case IDC_NAV_THREATS:
      return ClientPage::Threats;
    case IDC_NAV_QUARANTINE:
      return ClientPage::Quarantine;
    case IDC_NAV_SCANS:
      return ClientPage::Scans;
    case IDC_NAV_SERVICE:
      return ClientPage::Service;
    case IDC_NAV_HISTORY:
      return ClientPage::History;
    case IDC_NAV_SETTINGS:
      return ClientPage::Settings;
    default:
      return std::nullopt;
  }
}

bool IsNavigationButton(const int controlId) {
  return PageForNavButtonId(controlId).has_value();
}

std::wstring FriendlyScanLabel(const ScanPreset preset) {
  switch (preset) {
    case ScanPreset::Quick:
      return L"Quick scan";
    case ScanPreset::Full:
      return L"Full scan";
    case ScanPreset::Folder:
    default:
      return L"Folder scan";
  }
}

std::wstring LowercaseCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring CompactPathForStatus(const std::filesystem::path& path) {
  if (path.empty()) {
    return {};
  }

  const auto fileName = path.filename().wstring();
  if (!fileName.empty()) {
    return fileName;
  }

  return path.wstring();
}

void SetWindowTextSafe(HWND control, const std::wstring& text) {
  if (control != nullptr) {
    SetWindowTextW(control, text.c_str());
  }
}

COLORREF DarkTextColor() { return RGB(235, 241, 252); }
COLORREF MutedTextColor() { return RGB(145, 159, 185); }
COLORREF AccentBlue() { return RGB(49, 123, 242); }
COLORREF AccentBlueDark() { return RGB(153, 206, 255); }
COLORREF AccentGreen() { return RGB(31, 182, 123); }
COLORREF AccentGreenDark() { return RGB(173, 247, 213); }
COLORREF AccentAmber() { return RGB(224, 151, 39); }
COLORREF AccentAmberDark() { return RGB(255, 218, 158); }
COLORREF AccentRed() { return RGB(214, 72, 112); }
COLORREF AccentRedDark() { return RGB(255, 193, 206); }
COLORREF WindowBackgroundColor() { return RGB(6, 11, 22); }
COLORREF SurfaceColor() { return RGB(13, 22, 40); }
COLORREF SummarySafeColor() { return RGB(12, 40, 33); }
COLORREF SummaryWarningColor() { return RGB(48, 36, 12); }
COLORREF SummaryDangerColor() { return RGB(52, 20, 29); }
COLORREF DetailsCardColor() { return RGB(18, 29, 52); }
COLORREF MetricInfoColor() { return RGB(16, 27, 48); }
COLORREF MetricSuccessColor() { return RGB(12, 38, 31); }
COLORREF MetricWarningColor() { return RGB(48, 36, 12); }
COLORREF MetricDangerColor() { return RGB(52, 20, 29); }
COLORREF DetailColor() { return RGB(9, 17, 32); }
COLORREF ListBackColor() { return RGB(11, 19, 35); }
COLORREF ListAltBackColor() { return RGB(8, 15, 28); }
COLORREF BrandBaseColor() { return RGB(11, 22, 39); }
COLORREF BrandFrameColor() { return RGB(72, 122, 185); }
COLORREF BrandShieldColor() { return RGB(236, 243, 255); }
COLORREF BrandNeutralColor() { return RGB(104, 193, 255); }

COLORREF AdjustColor(const COLORREF color, const int delta) {
  const auto clampChannel = [delta](const BYTE channel) {
    return static_cast<BYTE>(std::clamp(static_cast<int>(channel) + delta, 0, 255));
  };

  return RGB(clampChannel(GetRValue(color)), clampChannel(GetGValue(color)), clampChannel(GetBValue(color)));
}

enum class BrandIconTone {
  Neutral,
  Safe,
  Warning,
  Danger
};

COLORREF ResolveBrandToneColor(BrandIconTone tone) {
  switch (tone) {
    case BrandIconTone::Safe:
      return AccentGreen();
    case BrandIconTone::Warning:
      return AccentAmber();
    case BrandIconTone::Danger:
      return AccentRed();
    case BrandIconTone::Neutral:
    default:
      return BrandNeutralColor();
  }
}

BrandIconTone ResolveBrandIconTone(const EndpointClientSnapshot& snapshot) {
  if (snapshot.openThreatCount != 0) {
    return BrandIconTone::Danger;
  }

  if (snapshot.serviceState == LocalServiceState::Running &&
      _wcsicmp(snapshot.agentState.healthState.c_str(), L"healthy") == 0) {
    return BrandIconTone::Safe;
  }

  if (snapshot.serviceState == LocalServiceState::NotInstalled ||
      snapshot.serviceState == LocalServiceState::Stopped) {
    return BrandIconTone::Danger;
  }

  return BrandIconTone::Warning;
}

HICON CreateBrandIcon(int size, BrandIconTone tone) {
  HDC screen = GetDC(nullptr);
  HDC canvas = CreateCompatibleDC(screen);

  BITMAPV5HEADER header{};
  header.bV5Size = sizeof(header);
  header.bV5Width = size;
  header.bV5Height = -size;
  header.bV5Planes = 1;
  header.bV5BitCount = 32;
  header.bV5Compression = BI_BITFIELDS;
  header.bV5RedMask = 0x00FF0000;
  header.bV5GreenMask = 0x0000FF00;
  header.bV5BlueMask = 0x000000FF;
  header.bV5AlphaMask = 0xFF000000;

  void* pixels = nullptr;
  HBITMAP colorBitmap = CreateDIBSection(canvas, reinterpret_cast<BITMAPINFO*>(&header), DIB_RGB_COLORS, &pixels, nullptr, 0);
  std::vector<std::uint8_t> maskBits(static_cast<std::size_t>(((size + 15) / 16) * 2 * size), 0);
  HBITMAP maskBitmap = CreateBitmap(size, size, 1, 1, maskBits.data());
  HGDIOBJ previousBitmap = SelectObject(canvas, colorBitmap);

  const RECT bounds{0, 0, size, size};
  HBRUSH baseBrush = CreateSolidBrush(BrandBaseColor());
  FillRect(canvas, &bounds, baseBrush);
  DeleteObject(baseBrush);

  HPEN framePen = CreatePen(PS_SOLID, std::max(1, size / 18), BrandFrameColor());
  HGDIOBJ previousPen = SelectObject(canvas, framePen);
  HBRUSH bodyBrush = CreateSolidBrush(BrandBaseColor());
  HGDIOBJ previousBrush = SelectObject(canvas, bodyBrush);
  const int inset = std::max(2, size / 10);
  const int radius = std::max(4, size / 4);
  RoundRect(canvas, inset, inset, size - inset, size - inset, radius, radius);
  SelectObject(canvas, previousBrush);
  DeleteObject(bodyBrush);
  SelectObject(canvas, previousPen);
  DeleteObject(framePen);

  HBRUSH shieldBrush = CreateSolidBrush(BrandShieldColor());
  previousBrush = SelectObject(canvas, shieldBrush);
  HPEN shieldPen = CreatePen(PS_SOLID, 1, BrandShieldColor());
  previousPen = SelectObject(canvas, shieldPen);
  POINT shield[6]{
    {size / 2, static_cast<LONG>(size * 0.21f)},
    {static_cast<LONG>(size * 0.70f), static_cast<LONG>(size * 0.31f)},
    {static_cast<LONG>(size * 0.70f), static_cast<LONG>(size * 0.47f)},
    {static_cast<LONG>(size * 0.66f), static_cast<LONG>(size * 0.63f)},
    {size / 2, static_cast<LONG>(size * 0.80f)},
    {static_cast<LONG>(size * 0.34f), static_cast<LONG>(size * 0.63f)}
  };
  Polygon(canvas, shield, 6);
  SelectObject(canvas, previousBrush);
  DeleteObject(shieldBrush);
  SelectObject(canvas, previousPen);
  DeleteObject(shieldPen);

  HPEN signalPen = CreatePen(PS_SOLID, std::max(2, size / 10), ResolveBrandToneColor(tone));
  previousPen = SelectObject(canvas, signalPen);
  MoveToEx(canvas, static_cast<int>(size * 0.37f), static_cast<int>(size * 0.52f), nullptr);
  LineTo(canvas, static_cast<int>(size * 0.45f), static_cast<int>(size * 0.52f));
  LineTo(canvas, static_cast<int>(size * 0.49f), static_cast<int>(size * 0.43f));
  LineTo(canvas, static_cast<int>(size * 0.54f), static_cast<int>(size * 0.60f));
  LineTo(canvas, static_cast<int>(size * 0.59f), static_cast<int>(size * 0.48f));
  LineTo(canvas, static_cast<int>(size * 0.66f), static_cast<int>(size * 0.48f));
  SelectObject(canvas, previousPen);
  DeleteObject(signalPen);

  HBRUSH signalBrush = CreateSolidBrush(ResolveBrandToneColor(tone));
  previousBrush = SelectObject(canvas, signalBrush);
  previousPen = SelectObject(canvas, GetStockObject(NULL_PEN));
  const int dotRadius = std::max(2, size / 12);
  const int dotX = static_cast<int>(size * 0.64f);
  const int dotY = static_cast<int>(size * 0.35f);
  Ellipse(canvas, dotX - dotRadius, dotY - dotRadius, dotX + dotRadius, dotY + dotRadius);
  SelectObject(canvas, previousBrush);
  DeleteObject(signalBrush);
  SelectObject(canvas, previousPen);

  ICONINFO iconInfo{};
  iconInfo.fIcon = TRUE;
  iconInfo.hbmMask = maskBitmap;
  iconInfo.hbmColor = colorBitmap;
  HICON icon = CreateIconIndirect(&iconInfo);

  SelectObject(canvas, previousBitmap);
  DeleteObject(maskBitmap);
  DeleteObject(colorBitmap);
  DeleteDC(canvas);
  ReleaseDC(nullptr, screen);
  return icon;
}

HICON LoadFenrirIcon(const int size) {
  return static_cast<HICON>(LoadImageW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(100), IMAGE_ICON, size, size,
                                       LR_DEFAULTCOLOR));
}

void CreateBrandIcons(UiContext& context) {
  context.iconNeutralSmall = LoadFenrirIcon(16);
  context.iconNeutralLarge = LoadFenrirIcon(32);
  context.iconSafeSmall = LoadFenrirIcon(16);
  context.iconSafeLarge = LoadFenrirIcon(32);
  context.iconWarningSmall = LoadFenrirIcon(16);
  context.iconWarningLarge = LoadFenrirIcon(32);
  context.iconDangerSmall = LoadFenrirIcon(16);
  context.iconDangerLarge = LoadFenrirIcon(32);
}

void DestroyBrandIcons(UiContext& context) {
  if (context.iconNeutralSmall != nullptr) {
    DestroyIcon(context.iconNeutralSmall);
  }
  if (context.iconNeutralLarge != nullptr) {
    DestroyIcon(context.iconNeutralLarge);
  }
  if (context.iconSafeSmall != nullptr) {
    DestroyIcon(context.iconSafeSmall);
  }
  if (context.iconSafeLarge != nullptr) {
    DestroyIcon(context.iconSafeLarge);
  }
  if (context.iconWarningSmall != nullptr) {
    DestroyIcon(context.iconWarningSmall);
  }
  if (context.iconWarningLarge != nullptr) {
    DestroyIcon(context.iconWarningLarge);
  }
  if (context.iconDangerSmall != nullptr) {
    DestroyIcon(context.iconDangerSmall);
  }
  if (context.iconDangerLarge != nullptr) {
    DestroyIcon(context.iconDangerLarge);
  }
}

HICON SelectTrayIcon(UiContext& context) {
  switch (ResolveBrandIconTone(context.snapshot)) {
    case BrandIconTone::Safe:
      return context.iconSafeSmall != nullptr ? context.iconSafeSmall : context.iconNeutralSmall;
    case BrandIconTone::Danger:
      return context.iconDangerSmall != nullptr ? context.iconDangerSmall : context.iconNeutralSmall;
    case BrandIconTone::Warning:
      return context.iconWarningSmall != nullptr ? context.iconWarningSmall : context.iconNeutralSmall;
    case BrandIconTone::Neutral:
    default:
      return context.iconNeutralSmall;
  }
}

HICON SelectWindowIcon(UiContext& context, bool large) {
  switch (ResolveBrandIconTone(context.snapshot)) {
    case BrandIconTone::Safe:
      return large ? context.iconSafeLarge : context.iconSafeSmall;
    case BrandIconTone::Danger:
      return large ? context.iconDangerLarge : context.iconDangerSmall;
    case BrandIconTone::Warning:
      return large ? context.iconWarningLarge : context.iconWarningSmall;
    case BrandIconTone::Neutral:
    default:
      return large ? context.iconNeutralLarge : context.iconNeutralSmall;
  }
}

void CreateThemeResources(UiContext& context) {
  context.windowBrush = CreateSolidBrush(WindowBackgroundColor());
  context.surfaceBrush = CreateSolidBrush(SurfaceColor());
  context.summarySafeBrush = CreateSolidBrush(SummarySafeColor());
  context.summaryWarningBrush = CreateSolidBrush(SummaryWarningColor());
  context.summaryDangerBrush = CreateSolidBrush(SummaryDangerColor());
  context.detailsBrush = CreateSolidBrush(DetailsCardColor());
  context.metricInfoBrush = CreateSolidBrush(MetricInfoColor());
  context.metricSuccessBrush = CreateSolidBrush(MetricSuccessColor());
  context.metricWarningBrush = CreateSolidBrush(MetricWarningColor());
  context.metricDangerBrush = CreateSolidBrush(MetricDangerColor());
  context.detailBrush = CreateSolidBrush(DetailColor());
  context.listBrush = CreateSolidBrush(ListBackColor());
}

void DestroyBrush(HBRUSH& brush) {
  if (brush != nullptr) {
    DeleteObject(brush);
    brush = nullptr;
  }
}

void DestroyThemeResources(UiContext& context) {
  DestroyBrush(context.windowBrush);
  DestroyBrush(context.surfaceBrush);
  DestroyBrush(context.summarySafeBrush);
  DestroyBrush(context.summaryWarningBrush);
  DestroyBrush(context.summaryDangerBrush);
  DestroyBrush(context.detailsBrush);
  DestroyBrush(context.metricInfoBrush);
  DestroyBrush(context.metricSuccessBrush);
  DestroyBrush(context.metricWarningBrush);
  DestroyBrush(context.metricDangerBrush);
  DestroyBrush(context.detailBrush);
  DestroyBrush(context.listBrush);
}

void ConfigureListViewColumns(HWND listView, const std::vector<std::pair<std::wstring, int>>& columns) {
  while (Header_GetItemCount(ListView_GetHeader(listView)) > 0) {
    ListView_DeleteColumn(listView, 0);
  }

  for (int index = 0; index < static_cast<int>(columns.size()); ++index) {
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    column.pszText = const_cast<LPWSTR>(columns[static_cast<std::size_t>(index)].first.c_str());
    column.cx = columns[static_cast<std::size_t>(index)].second;
    column.iSubItem = index;
    ListView_InsertColumn(listView, index, &column);
  }
}

void InsertListViewRow(HWND listView, const int rowIndex, const std::vector<std::wstring>& values) {
  for (int subItem = 0; subItem < static_cast<int>(values.size()); ++subItem) {
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iItem = rowIndex;
    item.iSubItem = subItem;
    item.pszText = const_cast<LPWSTR>(values[static_cast<std::size_t>(subItem)].c_str());
    if (subItem == 0) {
      ListView_InsertItem(listView, &item);
    } else {
      ListView_SetItem(listView, &item);
    }
  }
}

std::wstring ThreatDisplayPath(const antivirus::agent::ScanHistoryRecord& record) {
  if (_wcsicmp(record.contentType.c_str(), L"scan-session") == 0) {
    return record.subjectPath.empty() ? std::wstring(L"[Scan session]") : record.subjectPath.wstring();
  }

  return record.subjectPath.empty() ? std::wstring(L"(memory or script content)") : record.subjectPath.wstring();
}

std::wstring HistorySourceLabel(const std::wstring& source) {
  if (_wcsicmp(source.c_str(), L"endpoint-ui.quick-scan") == 0) {
    return L"Quick scan";
  }
  if (_wcsicmp(source.c_str(), L"endpoint-ui.full-scan") == 0) {
    return L"Full scan";
  }
  if (_wcsicmp(source.c_str(), L"endpoint-ui.custom-scan") == 0) {
    return L"Folder scan";
  }
  return source.empty() ? std::wstring(L"(unknown)") : source;
}

std::wstring HistoryDispositionLabel(const antivirus::agent::ScanHistoryRecord& record) {
  if (_wcsicmp(record.contentType.c_str(), L"scan-session") != 0) {
    return record.disposition.empty() ? std::wstring(L"(unknown)") : record.disposition;
  }

  if (_wcsicmp(record.disposition.c_str(), L"completed-clean") == 0) {
    return L"clean";
  }
  if (_wcsicmp(record.disposition.c_str(), L"completed-with-findings") == 0) {
    return L"findings";
  }
  return record.disposition.empty() ? std::wstring(L"completed") : record.disposition;
}

std::wstring BuildThreatDetailText(const antivirus::agent::ScanHistoryRecord& record) {
  std::wstringstream stream;
  stream << L"Threat detail\r\n\r\n"
         << L"Detected: " << NullableText(record.recordedAt) << L"\r\n"
         << L"Item: " << ThreatDisplayPath(record) << L"\r\n"
         << L"Disposition: " << NullableText(record.disposition) << L"\r\n"
         << L"Confidence: " << record.confidence << L"\r\n"
         << L"Tactic / Technique: " << NullableText(record.tacticId, L"(n/a)") << L" / "
         << NullableText(record.techniqueId, L"(n/a)") << L"\r\n"
         << L"Remediation: " << NullableText(record.remediationStatus, L"(none)") << L"\r\n"
         << L"SHA-256: " << NullableText(record.sha256, L"(unavailable)") << L"\r\n"
         << L"Evidence ID: " << NullableText(record.evidenceRecordId, L"(none)") << L"\r\n"
         << L"Quarantine ID: " << NullableText(record.quarantineRecordId, L"(none)");
  return stream.str();
}

std::wstring BuildQuarantineDetailText(const antivirus::agent::QuarantineIndexRecord& record) {
  std::wstringstream stream;
  stream << L"Quarantine detail\r\n\r\n"
         << L"Captured: " << NullableText(record.capturedAt) << L"\r\n"
         << L"Original path: " << record.originalPath.wstring() << L"\r\n"
         << L"Quarantined path: " << NullableText(record.quarantinedPath.wstring(), L"(removed from quarantine)") << L"\r\n"
         << L"Status: " << NullableText(record.localStatus) << L"\r\n"
         << L"Technique: " << NullableText(record.techniqueId, L"(n/a)") << L"\r\n"
         << L"Size: " << record.sizeBytes << L" bytes\r\n"
         << L"SHA-256: " << NullableText(record.sha256, L"(unavailable)") << L"\r\n"
         << L"Record ID: " << NullableText(record.recordId);
  return stream.str();
}

std::wstring BuildHistoryDetailText(const antivirus::agent::ScanHistoryRecord& record) {
  if (_wcsicmp(record.contentType.c_str(), L"scan-session") == 0) {
    std::wstringstream stream;
    stream << L"Scan activity\r\n\r\n"
           << L"Recorded: " << NullableText(record.recordedAt) << L"\r\n"
           << L"Scan type: " << HistorySourceLabel(record.source) << L"\r\n"
           << L"Scope: " << ThreatDisplayPath(record) << L"\r\n"
           << L"Result: " << HistoryDispositionLabel(record) << L"\r\n"
           << L"Summary: " << NullableText(record.reputation, L"(no summary available)") << L"\r\n"
           << L"Remediation: " << NullableText(record.remediationStatus, L"(none)");
    return stream.str();
  }

  std::wstringstream stream;
  stream << L"Detection history\r\n\r\n"
         << L"Recorded: " << NullableText(record.recordedAt) << L"\r\n"
         << L"Source: " << HistorySourceLabel(record.source) << L"\r\n"
         << L"Item: " << ThreatDisplayPath(record) << L"\r\n"
         << L"Disposition: " << HistoryDispositionLabel(record) << L"\r\n"
         << L"Reputation: " << NullableText(record.reputation, L"(unknown)") << L"\r\n"
         << L"Content type: " << NullableText(record.contentType, L"(unknown)") << L"\r\n"
         << L"Tactic / Technique: " << NullableText(record.tacticId, L"(n/a)") << L" / "
         << NullableText(record.techniqueId, L"(n/a)") << L"\r\n"
         << L"Remediation: " << NullableText(record.remediationStatus, L"(none)");
  return stream.str();
}

std::wstring BuildServiceOverviewText(const UiContext& context) {
  const auto processes = antivirus::agent::CollectProcessInventory(6);
  const auto services = antivirus::agent::CollectServiceInventory(6);
  const auto prioritizedProcessCount = std::count_if(processes.begin(), processes.end(), [](const auto& process) {
    return process.prioritized;
  });
  const auto riskyServiceCount = std::count_if(services.begin(), services.end(), [](const auto& service) {
    return service.risky;
  });

  std::wstringstream stream;
  stream << L"Runtime posture\r\n\r\n"
         << L"Device ID: " << NullableText(context.snapshot.agentState.deviceId, L"(not enrolled)") << L"\r\n"
         << L"Service state: " << antivirus::agent::LocalServiceStateToString(context.snapshot.serviceState) << L"\r\n"
         << L"Health state: " << NullableText(context.snapshot.agentState.healthState, L"(unknown)") << L"\r\n"
         << L"Policy: " << NullableText(context.snapshot.agentState.policy.policyName) << L" ("
         << NullableText(context.snapshot.agentState.policy.revision, L"n/a") << L")\r\n"
         << L"Last heartbeat: " << NullableText(context.snapshot.agentState.lastHeartbeatAt, L"(never)") << L"\r\n"
         << L"Last policy sync: " << NullableText(context.snapshot.agentState.lastPolicySyncAt, L"(never)") << L"\r\n"
         << L"Queued telemetry: " << context.snapshot.queuedTelemetryCount << L"\r\n"
          << L"Processes observed: " << processes.size() << L" (" << prioritizedProcessCount << L" prioritized)\r\n"
          << L"Services observed: " << services.size() << L" (" << riskyServiceCount << L" flagged)\r\n"
         << L"Agent version: " << NullableText(context.config.agentVersion) << L"\r\n"
         << L"Platform version: " << NullableText(context.config.platformVersion) << L"\r\n"
         << L"Command channel: " << NullableText(context.snapshot.agentState.commandChannelUrl, L"(not assigned)");

        if (!processes.empty()) {
          const auto& process = processes.front();
          stream << L"\r\n\r\nHighlighted process\r\n"
            << L"Name: " << NullableText(process.imageName, L"(unknown)") << L"\r\n"
            << L"Path: " << NullableText(process.imagePath, L"(unknown)") << L"\r\n"
            << L"PID: " << process.pid;
        }

        if (!services.empty()) {
          const auto& service = services.front();
          stream << L"\r\n\r\nHighlighted service\r\n"
            << L"Name: " << NullableText(service.displayName, L"(unknown)") << L"\r\n"
            << L"Service: " << NullableText(service.serviceName, L"(unknown)") << L"\r\n"
            << L"Binary: " << NullableText(service.binaryPath, L"(unknown)") << L"\r\n"
            << L"State: " << NullableText(service.currentState, L"(unknown)") << L"\r\n"
            << L"Account: " << NullableText(service.accountName, L"(unknown)");
        }

  if (!context.snapshot.updateJournal.empty()) {
    const auto& latest = context.snapshot.updateJournal.front();
    stream << L"\r\n\r\nLatest update\r\n"
           << L"Package: " << NullableText(latest.packageId, L"(unknown)") << L"\r\n"
           << L"Target version: " << NullableText(latest.targetVersion, L"(unknown)") << L"\r\n"
           << L"Status: " << NullableText(latest.status, L"(unknown)") << L"\r\n"
           << L"Started: " << NullableText(latest.startedAt, L"(unknown)");
  }

  return stream.str();
}

std::wstring BuildSettingsOverviewText(const UiContext& context) {
  std::wstringstream stream;
  stream << L"Local configuration\r\n\r\n"
         << L"Control plane: " << NullableText(context.config.controlPlaneBaseUrl) << L"\r\n"
         << L"Runtime database: " << context.config.runtimeDatabasePath.wstring() << L"\r\n"
         << L"State file: " << context.config.stateFilePath.wstring() << L"\r\n"
         << L"Telemetry queue: " << context.config.telemetryQueuePath.wstring() << L"\r\n"
         << L"Quarantine root: " << context.config.quarantineRootPath.wstring() << L"\r\n"
         << L"Evidence root: " << context.config.evidenceRootPath.wstring() << L"\r\n"
         << L"Realtime port: " << NullableText(context.config.realtimeProtectionPortName) << L"\r\n"
         << L"Sync interval: " << context.config.syncIntervalSeconds << L" seconds\r\n"
         << L"Telemetry batch size: " << context.config.telemetryBatchSize << L"\r\n"
         << L"Isolation loopback: " << (context.config.isolationAllowLoopback ? L"allowed" : L"blocked");
  return stream.str();
}

std::wstring DefaultDetailText(const UiContext& context) {
  switch (context.currentPage) {
    case ClientPage::Threats:
      if (context.snapshot.recentThreats.empty()) {
        return L"Threat detail\r\n\r\nNo unresolved local threats are currently recorded on this device.";
      }
      return L"Threat detail\r\n\r\nSelect a threat to see its path, ATT&CK mapping, confidence, and remediation state.";
    case ClientPage::Quarantine:
      if (context.snapshot.quarantineItems.empty()) {
        return L"Quarantine detail\r\n\r\nNo items are currently being held in local quarantine.";
      }
      return L"Quarantine detail\r\n\r\nSelect a quarantined item to review where it came from and decide whether to restore or delete it.";
    case ClientPage::Service:
      return BuildServiceOverviewText(context);
    case ClientPage::Settings:
      return BuildSettingsOverviewText(context);
    case ClientPage::Dashboard:
      if (context.snapshot.recentFindings.empty()) {
        return L"Recent activity\r\n\r\nNo recent scans or detections are recorded yet. Use Quick scan to verify the device now.";
      }
      return L"Recent activity\r\n\r\nSelect an item to review what happened recently on this endpoint and what the agent did next.";
    case ClientPage::Scans:
      return L"Scan detail\r\n\r\nSelect a scan session to review its scope, outcome, and remediation summary.";
    case ClientPage::History:
    default:
      if (context.snapshot.recentFindings.empty()) {
        return L"Detection history\r\n\r\nNo local scans or detections have been recorded yet.";
      }
      return L"Detection history\r\n\r\nSelect a scan or historical finding to review what ran and how the agent handled it.";
  }
}

void PopulateThreatsList(UiContext& context) {
  ListView_DeleteAllItems(context.threatsList);
  int row = 0;
  for (const auto& record : context.snapshot.recentThreats) {
    const auto attack = record.techniqueId.empty() ? record.tacticId : record.tacticId + L" / " + record.techniqueId;
    InsertListViewRow(context.threatsList, row++,
                      {record.recordedAt,
                       ThreatDisplayPath(record),
                       record.disposition,
                       std::to_wstring(record.confidence),
                       attack.empty() ? std::wstring(L"(n/a)") : attack,
                       record.remediationStatus.empty() ? std::wstring(L"(none)") : record.remediationStatus});
  }
}

void PopulateQuarantineList(UiContext& context) {
  ListView_DeleteAllItems(context.quarantineList);
  int row = 0;
  for (const auto& record : context.snapshot.quarantineItems) {
    InsertListViewRow(context.quarantineList, row++,
                      {record.capturedAt,
                       record.originalPath.wstring(),
                       record.localStatus,
                       record.techniqueId.empty() ? std::wstring(L"(n/a)") : record.techniqueId,
                       record.sha256.empty() ? std::wstring(L"(unavailable)") : record.sha256});
  }
}

void PopulateHistoryList(UiContext& context) {
  ListView_DeleteAllItems(context.historyList);
  int row = 0;
  for (const auto& record : context.snapshot.recentFindings) {
    if (context.currentPage == ClientPage::Scans && !IsScanSessionRecord(record)) {
      continue;
    }

    InsertListViewRow(context.historyList, row++,
                      {record.recordedAt,
                       HistoryDispositionLabel(record),
                      ThreatDisplayPath(record),
                      HistorySourceLabel(record.source),
                      record.techniqueId.empty() ? std::wstring(L"(n/a)") : record.techniqueId,
                      record.remediationStatus.empty() ? std::wstring(L"(none)") : record.remediationStatus});
  }
}

std::wstring BuildThreatFingerprint(const EndpointClientSnapshot& snapshot) {
  if (snapshot.recentThreats.empty()) {
    return {};
  }

  const auto& record = snapshot.recentThreats.front();
  return record.recordedAt + L"|" + record.subjectPath.wstring() + L"|" + record.disposition + L"|" +
         record.techniqueId + L"|" + record.sha256;
}

bool ServiceStateNeedsNotification(const LocalServiceState state) {
  switch (state) {
    case LocalServiceState::Running:
    case LocalServiceState::StartPending:
      return false;
    case LocalServiceState::NotInstalled:
    case LocalServiceState::Stopped:
    case LocalServiceState::StopPending:
    case LocalServiceState::Paused:
    case LocalServiceState::Unknown:
    default:
      return true;
  }
}

std::wstring BuildThreatNotificationBody(const EndpointClientSnapshot& snapshot) {
  if (snapshot.recentThreats.empty()) {
    if (!snapshot.recentThreats.empty()) {
      const auto& threat = snapshot.recentThreats.front();
      const auto displayPath = ThreatDisplayPath(threat);
      const auto fileName = std::filesystem::path(displayPath).filename().wstring();
      std::wstringstream stream;
      stream << (fileName.empty() ? L"A local threat" : fileName) << L" was blocked.";
      if (!displayPath.empty()) {
        stream << L" Path: " << displayPath;
      }
      return stream.str();
    }

    return L"The endpoint has local detections that need attention.";
  }

  const auto& record = snapshot.recentThreats.front();
  std::wstringstream stream;
  const auto displayTarget = record.subjectPath.filename().empty() ? record.subjectPath.wstring()
                                                                   : record.subjectPath.filename().wstring();
  stream << NullableText(displayTarget, L"Suspicious content") << L" was " << NullableText(record.disposition, L"blocked")
         << L".";
  if (snapshot.openThreatCount > 1) {
    stream << L" " << snapshot.openThreatCount << L" unresolved local threats need review.";
  }
  return stream.str();
}

std::wstring BuildServiceNotificationBody(const EndpointClientSnapshot& snapshot) {
  std::wstringstream stream;
  stream << L"Background protection changed to "
         << antivirus::agent::LocalServiceStateToString(snapshot.serviceState) << L".";
  if (!snapshot.agentState.healthState.empty()) {
    stream << L" Runtime health is " << snapshot.agentState.healthState << L".";
  }
  return stream.str();
}

void ShowTrayNotification(UiContext& context, const std::wstring& title, const std::wstring& body,
                          const DWORD infoFlags) {
  UpdateTrayIcon(context);
  context.trayIcon.uFlags = NIF_MESSAGE | NIF_TIP | NIF_ICON | NIF_INFO;
  wcsncpy_s(context.trayIcon.szInfoTitle, title.c_str(), _TRUNCATE);
  wcsncpy_s(context.trayIcon.szInfo, body.c_str(), _TRUNCATE);
  context.trayIcon.dwInfoFlags = infoFlags | NIIF_LARGE_ICON;
  context.trayIcon.uTimeout = 10000;
  Shell_NotifyIconW(NIM_MODIFY, &context.trayIcon);
}

void UpdateNotificationBaseline(UiContext& context, const EndpointClientSnapshot& snapshot) {
  context.lastObservedThreatCount = snapshot.openThreatCount;
  context.lastObservedServiceState = snapshot.serviceState;
  context.lastThreatFingerprint = BuildThreatFingerprint(snapshot);
  context.snapshotPrimed = true;
}

void EvaluateNotifications(UiContext& context, const EndpointClientSnapshot& snapshot) {
  const auto notificationsVisible = !IsWindowInteractive(context);
  const auto threatFingerprint = BuildThreatFingerprint(snapshot);

  bool notifyThreats = false;
  bool notifyService = false;
  if (!context.snapshotPrimed) {
    notifyThreats = context.backgroundMode && snapshot.openThreatCount != 0;
    notifyService = context.backgroundMode && ServiceStateNeedsNotification(snapshot.serviceState);
  } else if (notificationsVisible) {
    notifyThreats = snapshot.openThreatCount != 0 &&
                    (snapshot.openThreatCount > context.lastObservedThreatCount ||
                     (!threatFingerprint.empty() && threatFingerprint != context.lastThreatFingerprint));
    notifyService = snapshot.serviceState != context.lastObservedServiceState &&
                    ServiceStateNeedsNotification(snapshot.serviceState);
  }

  if (notifyThreats) {
    ShowTrayNotification(context,
                         snapshot.openThreatCount == 1 ? L"Threat found on this device" : L"Multiple threats detected",
                         BuildThreatNotificationBody(snapshot), NIIF_WARNING);
  } else if (notifyService) {
    ShowTrayNotification(context, L"Protection service needs attention", BuildServiceNotificationBody(snapshot),
                         NIIF_WARNING);
  }

  UpdateNotificationBaseline(context, snapshot);
}

void UpdateTrayIcon(UiContext& context) {
  context.trayIcon.cbSize = sizeof(context.trayIcon);
  context.trayIcon.hWnd = context.hwnd;
  context.trayIcon.uID = 1;
  context.trayIcon.uFlags = NIF_MESSAGE | NIF_TIP | NIF_ICON;
  context.trayIcon.uCallbackMessage = kTrayMessage;
  context.trayIcon.hIcon = SelectTrayIcon(context);

  const auto tooltip = ProtectionHeadline(context.snapshot) + L" | " + NullableText(context.snapshot.agentState.hostname);
  wcsncpy_s(context.trayIcon.szTip, tooltip.c_str(), _TRUNCATE);

  Shell_NotifyIconW(context.trayAdded ? NIM_MODIFY : NIM_ADD, &context.trayIcon);
  if (!context.trayAdded) {
    context.trayIcon.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &context.trayIcon);
  }
  context.trayAdded = true;
  SendMessageW(context.hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(SelectWindowIcon(context, false)));
  SendMessageW(context.hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(SelectWindowIcon(context, true)));
}

void UpdatePageChrome(UiContext& context) {
  SetWindowTextSafe(context.brandCard, BuildBrandCardText(context.snapshot));
  SetWindowTextSafe(context.titleLabel, PageTitle(context.currentPage));
  SetWindowTextSafe(context.subtitleLabel, PageSubtitle(context.currentPage, context.snapshot));
  SetWindowTextSafe(context.statusBadge, OverallStatusChip(context.snapshot));
  SetWindowTextSafe(context.primarySectionTitle, PrimarySectionTitle(context.currentPage));
  SetWindowTextSafe(context.secondarySectionTitle, SecondarySectionTitle(context.currentPage));

  const std::array<HWND, 7> navButtons{
      context.navDashboardButton, context.navThreatsButton,  context.navQuarantineButton, context.navScansButton,
      context.navServiceButton,   context.navHistoryButton,  context.navSettingsButton};
  for (const auto button : navButtons) {
    if (button != nullptr) {
      InvalidateRect(button, nullptr, TRUE);
    }
  }
}

COLORREF ResolveMetricThreatFill(const UiContext& context) {
  return context.snapshot.openThreatCount == 0 ? MetricSuccessColor() : MetricDangerColor();
}

COLORREF ResolveServiceFill(const UiContext& context) {
  if (context.snapshot.serviceState == LocalServiceState::Running &&
      _wcsicmp(context.snapshot.agentState.healthState.c_str(), L"healthy") == 0) {
    return MetricSuccessColor();
  }

  if (context.snapshot.serviceState == LocalServiceState::NotInstalled ||
      context.snapshot.serviceState == LocalServiceState::Stopped) {
    return MetricDangerColor();
  }

  return MetricWarningColor();
}

HBRUSH ResolveStaticBrush(UiContext& context, HWND control) {
  if (control == context.titleLabel || control == context.subtitleLabel) {
    return context.windowBrush;
  }

  if (control == context.primarySectionTitle || control == context.secondarySectionTitle) {
    return context.windowBrush;
  }

  if (control == context.statusBadge) {
    if (context.snapshot.serviceState == LocalServiceState::NotInstalled ||
        context.snapshot.serviceState == LocalServiceState::Stopped) {
      return context.metricDangerBrush;
    }
    if (context.snapshot.openThreatCount != 0 || _wcsicmp(context.snapshot.agentState.healthState.c_str(), L"healthy") != 0) {
      return context.metricWarningBrush;
    }
    return context.metricSuccessBrush;
  }

  if (control == context.brandCard) {
    return context.detailsBrush;
  }

  if (control == context.summaryCard) {
    return context.surfaceBrush;
  }

  if (control == context.detailsCard) {
    return context.detailsBrush;
  }

  if (control == context.metricThreats) {
    return ResolveMetricThreatFill(context) == MetricDangerColor() ? context.metricDangerBrush : context.metricSuccessBrush;
  }

  if (control == context.metricQuarantine) {
    return context.snapshot.activeQuarantineCount == 0 ? context.metricInfoBrush : context.metricWarningBrush;
  }

  if (control == context.metricService) {
    const auto fill = ResolveServiceFill(context);
    if (fill == MetricSuccessColor()) {
      return context.metricSuccessBrush;
    }
    if (fill == MetricDangerColor()) {
      return context.metricDangerBrush;
    }
    return context.metricWarningBrush;
  }

  if (control == context.metricSync) {
    return context.metricInfoBrush;
  }

  if (control == context.scanStatusLabel) {
    return context.windowBrush;
  }

  return context.surfaceBrush;
}

COLORREF ResolveStaticTextColor(UiContext& context, HWND control) {
  if (control == context.subtitleLabel) {
    return MutedTextColor();
  }

  if (control == context.primarySectionTitle || control == context.secondarySectionTitle) {
    return MutedTextColor();
  }

  if (control == context.statusBadge) {
    if (context.snapshot.serviceState == LocalServiceState::NotInstalled ||
        context.snapshot.serviceState == LocalServiceState::Stopped) {
      return AccentRedDark();
    }
    if (context.snapshot.openThreatCount != 0 || _wcsicmp(context.snapshot.agentState.healthState.c_str(), L"healthy") != 0) {
      return AccentAmberDark();
    }
    return AccentGreenDark();
  }

  if (control == context.brandCard) {
    return DarkTextColor();
  }

  if (control == context.summaryCard) {
    return DarkTextColor();
  }

  if (control == context.metricThreats) {
    return context.snapshot.openThreatCount == 0 ? AccentGreenDark() : AccentRedDark();
  }

  if (control == context.metricQuarantine) {
    return context.snapshot.activeQuarantineCount == 0 ? AccentBlueDark() : AccentAmberDark();
  }

  if (control == context.metricService) {
    if (context.snapshot.serviceState == LocalServiceState::Running &&
        _wcsicmp(context.snapshot.agentState.healthState.c_str(), L"healthy") == 0) {
      return AccentGreenDark();
    }
    if (context.snapshot.serviceState == LocalServiceState::NotInstalled ||
        context.snapshot.serviceState == LocalServiceState::Stopped) {
      return AccentRedDark();
    }
    return AccentAmberDark();
  }

  if (control == context.metricSync) {
    return AccentBlueDark();
  }

  if (control == context.scanStatusLabel) {
    return context.scanRunning ? AccentBlueDark() : MutedTextColor();
  }

  if (control == context.titleLabel) {
    return AccentBlueDark();
  }

  return DarkTextColor();
}

COLORREF ResolveButtonFill(const UiContext& context, const int controlId, const UINT itemState) {
  const auto disabled = (itemState & ODS_DISABLED) != 0;
  const auto pressed = (itemState & ODS_SELECTED) != 0;

  if (IsNavigationButton(controlId)) {
    const auto selectedPage = PageForNavButtonId(controlId);
    const auto selected = selectedPage.has_value() && selectedPage.value() == context.currentPage;
    if (disabled) {
      return RGB(25, 36, 57);
    }
    if (selected) {
      return pressed ? RGB(31, 52, 88) : RGB(22, 42, 76);
    }
    return pressed ? RGB(18, 28, 46) : WindowBackgroundColor();
  }

  COLORREF base = AccentBlue();
  switch (controlId) {
    case IDC_BUTTON_QUICKSCAN:
      base = AccentBlue();
      break;
    case IDC_BUTTON_FULLSCAN:
      base = RGB(88, 91, 214);
      break;
    case IDC_BUTTON_CUSTOMSCAN:
      base = RGB(74, 159, 192);
      break;
    case IDC_BUTTON_REFRESH:
      base = RGB(124, 136, 160);
      break;
    case IDC_BUTTON_STARTSERVICE:
      base = AccentGreen();
      break;
    case IDC_BUTTON_OPENQUARANTINE:
      base = AccentAmber();
      break;
    case IDC_BUTTON_RESTORE:
      base = AccentGreen();
      break;
    case IDC_BUTTON_DELETE:
      base = AccentRed();
      break;
    default:
      break;
  }

  if (disabled) {
    return RGB(203, 212, 226);
  }

  if (pressed) {
    return RGB(std::max(0, static_cast<int>(GetRValue(base)) - 25),
               std::max(0, static_cast<int>(GetGValue(base)) - 25),
               std::max(0, static_cast<int>(GetBValue(base)) - 25));
  }

  return base;
}

COLORREF ResolveButtonTextColor(const UINT itemState) {
  return (itemState & ODS_DISABLED) != 0 ? RGB(112, 124, 144) : RGB(244, 247, 255);
}

void DrawOwnerButton(const DRAWITEMSTRUCT* draw, UiContext& context) {
  RECT rect = draw->rcItem;
  if (IsNavigationButton(static_cast<int>(draw->CtlID))) {
    const auto fillColor = ResolveButtonFill(context, static_cast<int>(draw->CtlID), draw->itemState);
    HBRUSH brush = CreateSolidBrush(fillColor);
    FillRect(draw->hDC, &rect, brush);
    DeleteObject(brush);

    const auto selectedPage = PageForNavButtonId(static_cast<int>(draw->CtlID));
    const auto selected = selectedPage.has_value() && selectedPage.value() == context.currentPage;
    if (selected) {
      RECT accentRect{rect.left + 2, rect.top + 8, rect.left + 7, rect.bottom - 8};
      HBRUSH accentBrush = CreateSolidBrush(AccentBlue());
      FillRect(draw->hDC, &accentRect, accentBrush);
      DeleteObject(accentBrush);
    }

    wchar_t text[128]{};
    GetWindowTextW(draw->hwndItem, text, static_cast<int>(std::size(text)));
    SetBkMode(draw->hDC, TRANSPARENT);
    SetTextColor(draw->hDC, selected ? DarkTextColor() : MutedTextColor());
    SelectObject(draw->hDC, context.bodyFont);
    RECT textRect = rect;
    textRect.left += 18;
    DrawTextW(draw->hDC, text, -1, &textRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    return;
  }

  const auto fillColor = ResolveButtonFill(context, static_cast<int>(draw->CtlID), draw->itemState);
  const auto borderColor = AdjustColor(fillColor, 26);
  const auto highlightColor = AdjustColor(fillColor, 18);
  const auto shadowColor = AdjustColor(fillColor, -22);

  HBRUSH brush = CreateSolidBrush(fillColor);
  HPEN pen = CreatePen(PS_SOLID, 1, borderColor);
  HGDIOBJ oldPen = SelectObject(draw->hDC, pen);
  HGDIOBJ oldBrush = SelectObject(draw->hDC, brush);
  RoundRect(draw->hDC, rect.left, rect.top, rect.right, rect.bottom, 14, 14);
  SelectObject(draw->hDC, oldBrush);
  SelectObject(draw->hDC, oldPen);
  DeleteObject(brush);
  DeleteObject(pen);

  RECT highlightRect = rect;
  highlightRect.left += 2;
  highlightRect.top += 2;
  highlightRect.right -= 2;
  highlightRect.bottom = rect.top + ((rect.bottom - rect.top) / 2);
  HBRUSH highlightBrush = CreateSolidBrush(highlightColor);
  FillRect(draw->hDC, &highlightRect, highlightBrush);
  DeleteObject(highlightBrush);

  HPEN shadowPen = CreatePen(PS_SOLID, 1, shadowColor);
  oldPen = SelectObject(draw->hDC, shadowPen);
  MoveToEx(draw->hDC, rect.left + 8, rect.bottom - 2, nullptr);
  LineTo(draw->hDC, rect.right - 8, rect.bottom - 2);
  SelectObject(draw->hDC, oldPen);
  DeleteObject(shadowPen);

  RECT accentRect{
      rect.left + 10,
      rect.top + 9,
      rect.left + 16,
      rect.bottom - 9,
  };
  HBRUSH accentBrush = CreateSolidBrush(AdjustColor(fillColor, 34));
  FillRect(draw->hDC, &accentRect, accentBrush);
  DeleteObject(accentBrush);

  wchar_t text[128]{};
  GetWindowTextW(draw->hwndItem, text, static_cast<int>(std::size(text)));
  SetBkMode(draw->hDC, TRANSPARENT);
  SetTextColor(draw->hDC, ResolveButtonTextColor(draw->itemState));
  SelectObject(draw->hDC, context.bodyFont);
  RECT textRect = rect;
  textRect.left += 24;
  DrawTextW(draw->hDC, text, -1, &textRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

  if ((draw->itemState & ODS_FOCUS) != 0) {
    RECT focusRect = rect;
    InflateRect(&focusRect, -4, -4);
    DrawFocusRect(draw->hDC, &focusRect);
  }
}

void UpdateActionButtons(UiContext& context) {
  EnableWindow(context.startServiceButton, context.snapshot.serviceState == LocalServiceState::Stopped);
  const auto dashboardMode = context.currentPage == ClientPage::Dashboard;
  const auto threatsMode = context.currentPage == ClientPage::Threats;
  const auto quarantineMode = context.currentPage == ClientPage::Quarantine;
  const auto scansMode = context.currentPage == ClientPage::Scans;
  const auto serviceMode = context.currentPage == ClientPage::Service;
  const auto historyMode = context.currentPage == ClientPage::History;

  ShowWindow(context.quickScanButton, (dashboardMode || threatsMode || scansMode || historyMode) ? SW_SHOW : SW_HIDE);
  ShowWindow(context.fullScanButton, (dashboardMode || threatsMode || scansMode || historyMode) ? SW_SHOW : SW_HIDE);
  ShowWindow(context.customScanButton, (dashboardMode || threatsMode || scansMode || historyMode) ? SW_SHOW : SW_HIDE);
  ShowWindow(context.refreshButton, (dashboardMode || threatsMode || quarantineMode || scansMode || serviceMode || historyMode ||
                                     context.currentPage == ClientPage::Settings)
                                        ? SW_SHOW
                                        : SW_HIDE);
  ShowWindow(context.startServiceButton, (dashboardMode || serviceMode) ? SW_SHOW : SW_HIDE);
  ShowWindow(context.openQuarantineButton, (dashboardMode || quarantineMode || threatsMode) ? SW_SHOW : SW_HIDE);
  ShowWindow(context.restoreButton, quarantineMode ? SW_SHOW : SW_HIDE);
  ShowWindow(context.deleteButton, quarantineMode ? SW_SHOW : SW_HIDE);
  EnableWindow(context.restoreButton, quarantineMode && IsCurrentUserAdmin());
}

void UpdateDetailPane(UiContext& context) {
  std::wstring detailText = DefaultDetailText(context);

  if (context.currentPage == ClientPage::Threats) {
    const auto index = ListView_GetNextItem(context.threatsList, -1, LVNI_SELECTED);
    if (index >= 0 && static_cast<std::size_t>(index) < context.snapshot.recentThreats.size()) {
      detailText = BuildThreatDetailText(context.snapshot.recentThreats[static_cast<std::size_t>(index)]);
    }
  } else if (context.currentPage == ClientPage::Quarantine) {
    const auto index = ListView_GetNextItem(context.quarantineList, -1, LVNI_SELECTED);
    if (index >= 0 && static_cast<std::size_t>(index) < context.snapshot.quarantineItems.size()) {
      detailText = BuildQuarantineDetailText(context.snapshot.quarantineItems[static_cast<std::size_t>(index)]);
    }
  } else if (context.currentPage == ClientPage::Dashboard || context.currentPage == ClientPage::Scans ||
             context.currentPage == ClientPage::History) {
    const auto index = ListView_GetNextItem(context.historyList, -1, LVNI_SELECTED);
    if (index >= 0 && static_cast<std::size_t>(index) < context.snapshot.recentFindings.size()) {
      std::size_t visibleIndex = 0;
      for (const auto& record : context.snapshot.recentFindings) {
        if (context.currentPage == ClientPage::Scans && !IsScanSessionRecord(record)) {
          continue;
        }
        if (visibleIndex == static_cast<std::size_t>(index)) {
          detailText = BuildHistoryDetailText(record);
          break;
        }
        ++visibleIndex;
      }
    }
  }

  SetWindowTextSafe(context.detailEdit, detailText);
  UpdateActionButtons(context);
}

void UpdateVisibleList(UiContext& context) {
  const auto showThreats = context.currentPage == ClientPage::Threats;
  const auto showQuarantine = context.currentPage == ClientPage::Quarantine;
  const auto showHistory = context.currentPage == ClientPage::Dashboard || context.currentPage == ClientPage::Scans ||
                           context.currentPage == ClientPage::History;
  ShowWindow(context.threatsList, showThreats ? SW_SHOW : SW_HIDE);
  ShowWindow(context.quarantineList, showQuarantine ? SW_SHOW : SW_HIDE);
  ShowWindow(context.historyList, showHistory ? SW_SHOW : SW_HIDE);
  UpdateDetailPane(context);
}

void RefreshSnapshot(UiContext& context) {
  try {
    const auto refreshedSnapshot = antivirus::agent::LoadEndpointClientSnapshot(context.config);
    context.snapshot = refreshedSnapshot;

    UpdatePageChrome(context);
    SetWindowTextSafe(context.summaryCard, BuildSummaryCardText(context.snapshot));
    SetWindowTextSafe(context.detailsCard, BuildDetailsCardText(context.snapshot));
    SetWindowTextSafe(context.metricThreats,
                      BuildMetricCardText(L"Open threats", std::to_wstring(context.snapshot.openThreatCount),
                                          context.snapshot.openThreatCount == 1 ? L"1 unresolved detection"
                                                                               : std::to_wstring(context.snapshot.openThreatCount) + L" unresolved detections"));
    SetWindowTextSafe(context.metricQuarantine,
                      BuildMetricCardText(L"Quarantine", std::to_wstring(context.snapshot.activeQuarantineCount),
                                          context.snapshot.activeQuarantineCount == 1 ? L"1 item contained"
                                                                                      : std::to_wstring(context.snapshot.activeQuarantineCount) + L" items contained"));
    SetWindowTextSafe(context.metricService,
                      BuildMetricCardText(L"Protection service",
                                          antivirus::agent::LocalServiceStateToString(context.snapshot.serviceState),
                                          NullableText(context.snapshot.agentState.healthState, L"(unknown)")));
    SetWindowTextSafe(context.metricSync,
                      BuildMetricCardText(L"Last check-in",
                                          NullableText(context.snapshot.agentState.lastHeartbeatAt, L"(never)"),
                                          std::to_wstring(context.snapshot.queuedTelemetryCount) + L" upload(s) queued"));

    PopulateThreatsList(context);
    PopulateQuarantineList(context);
    PopulateHistoryList(context);
    UpdateVisibleList(context);
    UpdateTrayIcon(context);
    EvaluateNotifications(context, refreshedSnapshot);
  } catch (const std::exception& error) {
    UpdatePageChrome(context);
    SetWindowTextSafe(context.summaryCard, L"Unable to load local protection state.");
    SetWindowTextSafe(context.detailsCard, antivirus::agent::Utf8ToWide(error.what()));
    SetWindowTextSafe(context.metricThreats, BuildMetricCardText(L"Open threats", L"unavailable"));
    SetWindowTextSafe(context.metricQuarantine, BuildMetricCardText(L"Quarantine", L"unavailable"));
    SetWindowTextSafe(context.metricService, BuildMetricCardText(L"Protection service", L"unknown"));
    SetWindowTextSafe(context.metricSync, BuildMetricCardText(L"Last check-in", L"unknown"));
    ListView_DeleteAllItems(context.threatsList);
    ListView_DeleteAllItems(context.quarantineList);
    ListView_DeleteAllItems(context.historyList);
    SetWindowTextSafe(context.detailEdit, L"Local protection details could not be loaded.");
    UpdateTrayIcon(context);
  }
}

void UpdateScanProgress(UiContext& context, const std::wstring& statusText, const std::uint32_t completedTargets,
                        const std::uint32_t totalTargets) {
  SetWindowTextSafe(context.scanStatusLabel, statusText);
  ShowWindow(context.progressBar, SW_SHOW);

  const auto total = std::max<std::uint32_t>(totalTargets, 1);
  SendMessageW(context.progressBar, PBM_SETRANGE32, 0, total);
  SendMessageW(context.progressBar, PBM_SETPOS, std::min(completedTargets, total), 0);
}

void SetScanRunning(UiContext& context, const bool running, const std::wstring& statusText) {
  SetWindowTextSafe(context.scanStatusLabel, statusText);
  ShowWindow(context.progressBar, running ? SW_SHOW : SW_HIDE);
  if (running) {
    SendMessageW(context.progressBar, PBM_SETSTATE, PBST_NORMAL, 0);
    SendMessageW(context.progressBar, PBM_SETRANGE32, 0, 100);
    SendMessageW(context.progressBar, PBM_SETPOS, 0, 0);
  } else {
    SendMessageW(context.progressBar, PBM_SETPOS, 0, 0);
  }

  EnableWindow(context.quickScanButton, !running);
  EnableWindow(context.fullScanButton, !running);
  EnableWindow(context.customScanButton, !running);
  EnableWindow(context.refreshButton, !running);
}

std::optional<std::wstring> PickFolder(HWND owner) {
  BROWSEINFOW browseInfo{};
  browseInfo.hwndOwner = owner;
  browseInfo.lpszTitle = L"Choose a folder to scan";
  browseInfo.ulFlags = BIF_RETURNONLYFSDIRS | BIF_USENEWUI | BIF_NEWDIALOGSTYLE;

  const auto pidl = SHBrowseForFolderW(&browseInfo);
  if (pidl == nullptr) {
    return std::nullopt;
  }

  std::wstring selected(MAX_PATH, L'\0');
  const auto ok = SHGetPathFromIDListW(pidl, selected.data());
  CoTaskMemFree(pidl);
  if (!ok) {
    return std::nullopt;
  }

  selected.resize(wcslen(selected.c_str()));
  return selected;
}

void RunScanAsync(HWND hwnd, UiContext& context, const ScanPreset preset, const std::optional<std::filesystem::path>& customPath) {
  if (context.scanRunning.exchange(true)) {
    return;
  }

  context.activeScanLabel = FriendlyScanLabel(preset);
  const auto statusText = L"Preparing " + LowercaseCopy(context.activeScanLabel) + L" scope...";

  SetScanRunning(context, true, statusText);
  const auto config = context.config;
  const auto scanLabel = context.activeScanLabel;

  std::thread([hwnd, config, preset, customPath, scanLabel]() {
    auto* payload = new ScanCompletePayload{};
    try {
      antivirus::agent::LocalStateStore stateStore(config.runtimeDatabasePath, config.stateFilePath);
      const auto state = stateStore.LoadOrCreate();

      std::vector<std::filesystem::path> targets;
      std::wstring source;
      switch (preset) {
        case ScanPreset::Quick:
          targets = antivirus::agent::BuildQuickScanTargets();
          source = L"endpoint-ui.quick-scan";
          break;
        case ScanPreset::Full:
          targets = antivirus::agent::BuildFullScanTargets();
          source = L"endpoint-ui.full-scan";
          break;
        case ScanPreset::Folder:
          targets = customPath.has_value() ? std::vector<std::filesystem::path>{*customPath} : std::vector<std::filesystem::path>{};
          source = L"endpoint-ui.custom-scan";
          break;
      }

      const auto result = antivirus::agent::ExecuteLocalScan(
          config, state, targets,
          antivirus::agent::LocalScanExecutionOptions{.queueTelemetry = true, .applyRemediation = true, .source = source},
          [hwnd, scanLabel](const antivirus::agent::LocalScanProgressUpdate& progress) {
            auto* progressPayload = new ScanProgressPayload{};
            std::wstringstream status;
            if (progress.totalTargets == 0) {
              status << scanLabel << L": no scannable files were discovered.";
            } else if (progress.completedTargets >= progress.totalTargets) {
              status << scanLabel << L": finalizing results...";
            } else {
              status << scanLabel << L": scanning " << (progress.completedTargets + 1) << L" of " << progress.totalTargets;
              const auto displayTarget = CompactPathForStatus(progress.currentTarget);
              if (!displayTarget.empty()) {
                status << L"  " << displayTarget;
              }
              if (progress.findingCount != 0) {
                status << L"  " << progress.findingCount << L" finding(s)";
              }
            }

            progressPayload->status = status.str();
            progressPayload->completedTargets = static_cast<std::uint32_t>(progress.completedTargets);
            progressPayload->totalTargets = static_cast<std::uint32_t>(progress.totalTargets);
            if (IsWindow(hwnd)) {
              PostMessageW(hwnd, kScanProgressMessage, 0, reinterpret_cast<LPARAM>(progressPayload));
            } else {
              delete progressPayload;
            }
          });

      std::wstringstream summary;
      summary << scanLabel << L" complete. " << result.targetCount << L" target(s) checked and " << result.findings.size()
              << L" suspicious item(s) detected.";
      if (!result.findings.empty() && result.remediationFailed) {
        summary << L" Some remediation actions failed and need review.";
      } else if (!result.findings.empty()) {
        summary << L" Local remediation was applied where policy allowed it.";
      }

      payload->summary = summary.str();
      payload->success = !result.remediationFailed;
    } catch (const std::exception& error) {
      payload->summary = std::wstring(L"Scan failed: ") + antivirus::agent::Utf8ToWide(error.what());
      payload->success = false;
    }

    if (IsWindow(hwnd)) {
      PostMessageW(hwnd, kScanCompleteMessage, 0, reinterpret_cast<LPARAM>(payload));
    } else {
      delete payload;
    }
  }).detach();
}

void HideToTray(HWND hwnd) {
  ShowWindow(hwnd, SW_HIDE);
}

void RestoreFromTray(HWND hwnd) {
  ShowWindow(hwnd, SW_SHOW);
  ShowWindow(hwnd, SW_RESTORE);
  SetForegroundWindow(hwnd);
}

void SelectPage(UiContext& context, const ClientPage page) {
  context.currentPage = page;
  UpdatePageChrome(context);
  PopulateHistoryList(context);
  UpdateVisibleList(context);
}

void OpenQuarantineFolder(const UiContext& context) {
  std::filesystem::create_directories(context.config.quarantineRootPath);
  ShellExecuteW(context.hwnd, L"open", context.config.quarantineRootPath.wstring().c_str(), nullptr, nullptr, SW_SHOWDEFAULT);
}

void ShowTrayMenu(UiContext& context) {
  HMENU menu = CreatePopupMenu();
  if (menu == nullptr) {
    return;
  }

  AppendMenuW(menu, MF_STRING, IDM_TRAY_OPEN, L"Open Fenrir");
  AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(menu, MF_STRING, IDM_TRAY_QUICKSCAN, L"Run quick scan");
  AppendMenuW(menu, MF_STRING, IDM_TRAY_FULLSCAN, L"Run full scan");
  AppendMenuW(menu, MF_STRING, IDM_TRAY_QUARANTINE, L"Open quarantine");
  AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(menu, MF_STRING, IDM_TRAY_EXIT, L"Exit Fenrir");
  AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(menu, MF_STRING, IDM_TRAY_EXIT, L"Exit Fenrir");

  POINT cursor{};
  GetCursorPos(&cursor);
  SetForegroundWindow(context.hwnd);
  TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN, cursor.x, cursor.y, 0, context.hwnd, nullptr);
  DestroyMenu(menu);
}

void UpdateListColumnWidths(HWND listView, const std::vector<int>& widths) {
  for (int index = 0; index < static_cast<int>(widths.size()); ++index) {
    ListView_SetColumnWidth(listView, index, widths[static_cast<std::size_t>(index)]);
  }
}

void LayoutControls(UiContext& context) {
  RECT client{};
  GetClientRect(context.hwnd, &client);

  const int padding = 20;
  const int width = client.right - client.left;
  const int height = client.bottom - client.top;
  const int railWidth = 236;
  const int railGap = 22;
  const int railX = padding;
  const int railY = padding;
  const int railHeight = height - (padding * 2);
  const int contentX = railX + railWidth + railGap;
  const int contentWidth = width - contentX - padding;

  const int brandHeight = 116;
  const int navButtonHeight = 42;
  const int navGap = 8;
  const int navTop = railY + brandHeight + 18;

  MoveWindow(context.brandCard, railX, railY, railWidth, brandHeight, TRUE);
  MoveWindow(context.navDashboardButton, railX, navTop, railWidth, navButtonHeight, TRUE);
  MoveWindow(context.navThreatsButton, railX, navTop + (navButtonHeight + navGap) * 1, railWidth, navButtonHeight, TRUE);
  MoveWindow(context.navQuarantineButton, railX, navTop + (navButtonHeight + navGap) * 2, railWidth, navButtonHeight, TRUE);
  MoveWindow(context.navScansButton, railX, navTop + (navButtonHeight + navGap) * 3, railWidth, navButtonHeight, TRUE);
  MoveWindow(context.navServiceButton, railX, navTop + (navButtonHeight + navGap) * 4, railWidth, navButtonHeight, TRUE);
  MoveWindow(context.navHistoryButton, railX, navTop + (navButtonHeight + navGap) * 5, railWidth, navButtonHeight, TRUE);
  MoveWindow(context.navSettingsButton, railX, navTop + (navButtonHeight + navGap) * 6, railWidth, navButtonHeight, TRUE);

  const int titleHeight = 42;
  const int subtitleHeight = 26;
  MoveWindow(context.titleLabel, contentX, padding, contentWidth - 170, titleHeight, TRUE);
  MoveWindow(context.subtitleLabel, contentX, padding + titleHeight + 2, contentWidth - 200, subtitleHeight, TRUE);
  MoveWindow(context.statusBadge, contentX + contentWidth - 164, padding + 8, 164, 36, TRUE);

  const bool dashboardPage = context.currentPage == ClientPage::Dashboard;
  const bool threatsPage = context.currentPage == ClientPage::Threats;
  const bool quarantinePage = context.currentPage == ClientPage::Quarantine;
  const bool scansPage = context.currentPage == ClientPage::Scans;
  const bool servicePage = context.currentPage == ClientPage::Service;
  const bool historyPage = context.currentPage == ClientPage::History;
  const bool settingsPage = context.currentPage == ClientPage::Settings;

  const bool showHero = dashboardPage || scansPage || servicePage || settingsPage;
  const bool showMetrics = dashboardPage || scansPage || servicePage;
  const bool showSummary = showHero;
  const bool showDetails = showHero;
  const bool showLists = dashboardPage || threatsPage || quarantinePage || scansPage || historyPage;
  const bool showPrimaryList = threatsPage || quarantinePage || historyPage || scansPage || dashboardPage;
  const bool showDetailPane = showLists || servicePage || settingsPage;

  ShowWindow(context.summaryCard, showSummary ? SW_SHOW : SW_HIDE);
  ShowWindow(context.detailsCard, showDetails ? SW_SHOW : SW_HIDE);
  ShowWindow(context.metricThreats, showMetrics ? SW_SHOW : SW_HIDE);
  ShowWindow(context.metricQuarantine, showMetrics ? SW_SHOW : SW_HIDE);
  ShowWindow(context.metricService, showMetrics ? SW_SHOW : SW_HIDE);
  ShowWindow(context.metricSync, showMetrics ? SW_SHOW : SW_HIDE);
  ShowWindow(context.primarySectionTitle, showPrimaryList ? SW_SHOW : SW_HIDE);
  ShowWindow(context.secondarySectionTitle, showDetailPane ? SW_SHOW : SW_HIDE);

  int currentTop = padding + titleHeight + subtitleHeight + 24;
  const int heroGap = 16;
  const int heroHeight = showHero ? (dashboardPage ? 132 : 120) : 0;
  if (showHero) {
    const int heroLeftWidth = dashboardPage ? static_cast<int>(contentWidth * 0.58) : static_cast<int>(contentWidth * 0.52);
    const int heroRightWidth = contentWidth - heroLeftWidth - heroGap;
    MoveWindow(context.summaryCard, contentX, currentTop, heroLeftWidth, heroHeight, TRUE);
    MoveWindow(context.detailsCard, contentX + heroLeftWidth + heroGap, currentTop, heroRightWidth, heroHeight, TRUE);
    currentTop += heroHeight + 16;
  }

  if (showMetrics) {
    const int metricGap = 12;
    const int metricHeight = 84;
    const int metricWidth = (contentWidth - (metricGap * 3)) / 4;
    MoveWindow(context.metricThreats, contentX, currentTop, metricWidth, metricHeight, TRUE);
    MoveWindow(context.metricQuarantine, contentX + metricWidth + metricGap, currentTop, metricWidth, metricHeight, TRUE);
    MoveWindow(context.metricService, contentX + ((metricWidth + metricGap) * 2), currentTop, metricWidth, metricHeight, TRUE);
    MoveWindow(context.metricSync, contentX + ((metricWidth + metricGap) * 3), currentTop, metricWidth, metricHeight, TRUE);
    currentTop += metricHeight + 16;
  }

  const int buttonWidth = 138;
  const int buttonHeight = 40;
  const int actionGap = 10;
  const int rightActionWidth = 196;
  MoveWindow(context.quickScanButton, contentX, currentTop, buttonWidth, buttonHeight, TRUE);
  MoveWindow(context.fullScanButton, contentX + (buttonWidth + actionGap), currentTop, buttonWidth, buttonHeight, TRUE);
  MoveWindow(context.customScanButton, contentX + ((buttonWidth + actionGap) * 2), currentTop, buttonWidth, buttonHeight, TRUE);
  MoveWindow(context.refreshButton, contentX + ((buttonWidth + actionGap) * 3), currentTop, buttonWidth, buttonHeight, TRUE);
  MoveWindow(context.startServiceButton, contentX + ((buttonWidth + actionGap) * 4), currentTop, 160, buttonHeight, TRUE);
  MoveWindow(context.openQuarantineButton, contentX + contentWidth - rightActionWidth, currentTop, rightActionWidth, buttonHeight, TRUE);

  currentTop += buttonHeight + 12;
  MoveWindow(context.scanStatusLabel, contentX, currentTop, contentWidth - 260, 24, TRUE);
  MoveWindow(context.progressBar, contentX + contentWidth - 240, currentTop + 3, 240, 16, TRUE);

  currentTop += 34;
  const bool showProgressArea = dashboardPage || scansPage || context.scanRunning;
  ShowWindow(context.scanStatusLabel, showProgressArea ? SW_SHOW : SW_HIDE);
  ShowWindow(context.progressBar, showProgressArea ? SW_SHOW : SW_HIDE);

  if (showLists) {
    const int panelGap = 18;
    const int sectionTitleHeight = 22;
    const int contentBottom = height - padding;
    MoveWindow(context.primarySectionTitle, contentX, currentTop, contentWidth / 2, sectionTitleHeight, TRUE);
    MoveWindow(context.secondarySectionTitle, contentX + static_cast<int>(contentWidth * 0.62), currentTop,
               static_cast<int>(contentWidth * 0.38), sectionTitleHeight, TRUE);
    currentTop += sectionTitleHeight + 8;

    const int listWidth = static_cast<int>(contentWidth * 0.60);
    const int detailWidth = contentWidth - listWidth - panelGap;
    const int listHeight = contentBottom - currentTop;
    MoveWindow(context.threatsList, contentX, currentTop, listWidth, listHeight, TRUE);
    MoveWindow(context.quarantineList, contentX, currentTop, listWidth, listHeight, TRUE);
    MoveWindow(context.historyList, contentX, currentTop, listWidth, listHeight, TRUE);
    MoveWindow(context.detailEdit, contentX + listWidth + panelGap, currentTop, detailWidth, listHeight - 46, TRUE);
    MoveWindow(context.restoreButton, contentX + listWidth + panelGap + detailWidth - 254, currentTop + listHeight - 38, 120, 36, TRUE);
    MoveWindow(context.deleteButton, contentX + listWidth + panelGap + detailWidth - 124, currentTop + listHeight - 38, 120, 36, TRUE);

    UpdateListColumnWidths(context.threatsList, {170, listWidth - 690, 110, 100, 180, 130});
    UpdateListColumnWidths(context.quarantineList, {170, listWidth - 740, 120, 160, 270});
    UpdateListColumnWidths(context.historyList, {170, 110, listWidth - 710, 150, 140, 130});
  } else {
    ShowWindow(context.threatsList, SW_HIDE);
    ShowWindow(context.quarantineList, SW_HIDE);
    ShowWindow(context.historyList, SW_HIDE);
    if (showDetailPane) {
      MoveWindow(context.secondarySectionTitle, contentX, currentTop, contentWidth, 22, TRUE);
      MoveWindow(context.detailEdit, contentX, currentTop + 30, contentWidth, height - (currentTop + 30) - padding, TRUE);
    }
  }
}

void PerformQuarantineAction(UiContext& context, const bool restore) {
  const auto index = ListView_GetNextItem(context.quarantineList, -1, LVNI_SELECTED);
  if (index < 0 || static_cast<std::size_t>(index) >= context.snapshot.quarantineItems.size()) {
    MessageBoxW(context.hwnd, L"Select a quarantined item first.", kWindowTitle, MB_OK | MB_ICONINFORMATION);
    return;
  }

  if (restore && !IsCurrentUserAdmin()) {
    MessageBoxW(context.hwnd, L"Restoring quarantined files requires an elevated administrator session.",
                kWindowTitle, MB_OK | MB_ICONWARNING);
    return;
  }

  const auto& item = context.snapshot.quarantineItems[static_cast<std::size_t>(index)];
  const auto result = restore ? antivirus::agent::RestoreQuarantinedItem(context.config, item.recordId)
                              : antivirus::agent::DeleteQuarantinedItem(context.config, item.recordId);
  if (!result.success) {
    const auto heading = restore ? L"Unable to restore the selected item." : L"Unable to delete the selected item.";
    MessageBoxW(context.hwnd,
                (std::wstring(heading) + L"\r\n\r\n" + (result.errorMessage.empty() ? L"Unknown error" : result.errorMessage))
                    .c_str(),
                kWindowTitle, MB_OK | MB_ICONERROR);
    return;
  }

  RefreshSnapshot(context);
}

void InitializeListView(HWND listView) {
  SendMessageW(listView, CCM_SETUNICODEFORMAT, TRUE, 0);
  ListView_SetExtendedListViewStyle(listView, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
}

HWND CreateCard(HWND parent, const int id) {
  return CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
                         0, 0, 0, 0, parent, reinterpret_cast<HMENU>(id), nullptr, nullptr);
}

LRESULT HandleListCustomDraw(const NMLVCUSTOMDRAW* customDraw) {
  switch (customDraw->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
      return CDRF_NOTIFYITEMDRAW;
    case CDDS_ITEMPREPAINT: {
      auto* mutableDraw = const_cast<NMLVCUSTOMDRAW*>(customDraw);
      const bool selected = (customDraw->nmcd.uItemState & CDIS_SELECTED) != 0;
      mutableDraw->clrText = selected ? RGB(255, 255, 255) : DarkTextColor();
      mutableDraw->clrTextBk = selected ? AccentBlue() : ((customDraw->nmcd.dwItemSpec % 2 == 0) ? ListBackColor() : ListAltBackColor());
      return CDRF_NEWFONT;
    }
    default:
      return CDRF_DODEFAULT;
  }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
  if (message == RestoreWindowMessageId()) {
    if (auto* context = GetContext(hwnd)) {
      RestoreFromTray(hwnd);
      SelectPage(*context, ClientPage::Dashboard);
      LayoutControls(*context);
    }
    return 0;
  }

  switch (message) {
    case kTrayMessage: {
      auto* context = GetContext(hwnd);
      if (lParam == WM_LBUTTONUP || lParam == WM_LBUTTONDBLCLK || lParam == NIN_BALLOONUSERCLICK ||
          lParam == NIN_SELECT || lParam == NIN_KEYSELECT) {
        RestoreFromTray(hwnd);
        if (context != nullptr) {
          SelectPage(*context, ClientPage::Dashboard);
          LayoutControls(*context);
        }
        return 0;
      }
      if (lParam == WM_RBUTTONUP || lParam == WM_CONTEXTMENU) {
        if (context != nullptr) {
          ShowTrayMenu(*context);
        }
        return 0;
      }
      break;
    }
    case WM_ERASEBKGND: {
      RECT client{};
      GetClientRect(hwnd, &client);
      auto* context = GetContext(hwnd);
      FillRect(reinterpret_cast<HDC>(wParam), &client, context != nullptr ? context->windowBrush : GetSysColorBrush(COLOR_WINDOW));
      return 1;
    }

    case WM_CTLCOLORSTATIC: {
      auto* context = GetContext(hwnd);
      auto* control = reinterpret_cast<HWND>(lParam);
      auto hdc = reinterpret_cast<HDC>(wParam);
      if (context == nullptr || control == nullptr) {
        break;
      }

      SetBkMode(hdc, OPAQUE);
      SetTextColor(hdc, ResolveStaticTextColor(*context, control));
      const auto brush = ResolveStaticBrush(*context, control);
      if (brush == context->windowBrush) {
        SetBkColor(hdc, WindowBackgroundColor());
      } else if (brush == context->detailsBrush) {
        SetBkColor(hdc, DetailsCardColor());
      } else if (brush == context->summarySafeBrush) {
        SetBkColor(hdc, SummarySafeColor());
      } else if (brush == context->summaryWarningBrush) {
        SetBkColor(hdc, SummaryWarningColor());
      } else if (brush == context->summaryDangerBrush) {
        SetBkColor(hdc, SummaryDangerColor());
      } else if (brush == context->metricInfoBrush) {
        SetBkColor(hdc, MetricInfoColor());
      } else if (brush == context->metricSuccessBrush) {
        SetBkColor(hdc, MetricSuccessColor());
      } else if (brush == context->metricWarningBrush) {
        SetBkColor(hdc, MetricWarningColor());
      } else if (brush == context->metricDangerBrush) {
        SetBkColor(hdc, MetricDangerColor());
      } else {
        SetBkColor(hdc, SurfaceColor());
      }
      return reinterpret_cast<INT_PTR>(brush);
    }

    case WM_CTLCOLOREDIT: {
      auto* context = GetContext(hwnd);
      auto* control = reinterpret_cast<HWND>(lParam);
      auto hdc = reinterpret_cast<HDC>(wParam);
      if (context == nullptr || control != context->detailEdit) {
        break;
      }

      SetBkMode(hdc, OPAQUE);
      SetBkColor(hdc, DetailColor());
      SetTextColor(hdc, DarkTextColor());
      return reinterpret_cast<INT_PTR>(context->detailBrush);
    }

    case WM_DRAWITEM: {
      auto* context = GetContext(hwnd);
      auto* draw = reinterpret_cast<DRAWITEMSTRUCT*>(lParam);
      if (context == nullptr || draw == nullptr || draw->CtlType != ODT_BUTTON) {
        break;
      }

      DrawOwnerButton(draw, *context);
      return TRUE;
    }

    case WM_CREATE: {
      auto* context = new UiContext{};
      context->config = antivirus::agent::LoadAgentConfigForModule(nullptr);
      context->hwnd = hwnd;
      const auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
      const auto* launchOptions = create != nullptr ? reinterpret_cast<LaunchOptions*>(create->lpCreateParams) : nullptr;
      context->backgroundMode = launchOptions != nullptr && launchOptions->backgroundMode;
      SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(context));

      NONCLIENTMETRICSW metrics{};
      metrics.cbSize = sizeof(metrics);
      SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0);
      wcscpy_s(metrics.lfMessageFont.lfFaceName, L"Segoe UI");
      context->bodyFont = CreateFontIndirectW(&metrics.lfMessageFont);
      auto titleFont = metrics.lfMessageFont;
      titleFont.lfHeight = 30;
      titleFont.lfWeight = FW_BOLD;
      wcscpy_s(titleFont.lfFaceName, L"Segoe UI Semibold");
      context->titleFont = CreateFontIndirectW(&titleFont);
      auto headingFont = metrics.lfMessageFont;
      headingFont.lfHeight = 18;
      headingFont.lfWeight = FW_SEMIBOLD;
      wcscpy_s(headingFont.lfFaceName, L"Segoe UI Semibold");
      context->headingFont = CreateFontIndirectW(&headingFont);
      CreateThemeResources(*context);
      CreateBrandIcons(*context);
      SendMessageW(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(context->iconNeutralSmall));
      SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(context->iconNeutralLarge));

      context->brandCard = CreateCard(hwnd, IDC_BRAND_CARD);
      context->titleLabel = CreateWindowW(L"STATIC", kWindowTitle, WS_CHILD | WS_VISIBLE,
                                          0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_TITLE), nullptr, nullptr);
      context->subtitleLabel = CreateWindowW(L"STATIC", BuildSubtitleText().c_str(), WS_CHILD | WS_VISIBLE,
                                             0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SUBTITLE), nullptr, nullptr);
      context->statusBadge = CreateCard(hwnd, IDC_STATUS_BADGE);
      context->primarySectionTitle = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
                                                   0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_PRIMARY_SECTION_TITLE), nullptr, nullptr);
      context->secondarySectionTitle = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
                                                     0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SECONDARY_SECTION_TITLE), nullptr, nullptr);
      context->summaryCard = CreateCard(hwnd, IDC_SUMMARY_CARD);
      context->detailsCard = CreateCard(hwnd, IDC_DETAILS_CARD);
      context->metricThreats = CreateCard(hwnd, IDC_METRIC_THREATS);
      context->metricQuarantine = CreateCard(hwnd, IDC_METRIC_QUARANTINE);
      context->metricService = CreateCard(hwnd, IDC_METRIC_SERVICE);
      context->metricSync = CreateCard(hwnd, IDC_METRIC_SYNC);
      context->navDashboardButton = CreateWindowW(L"BUTTON", L"Dashboard", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                                  0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_NAV_DASHBOARD), nullptr, nullptr);
      context->navThreatsButton = CreateWindowW(L"BUTTON", L"Threats", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                                0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_NAV_THREATS), nullptr, nullptr);
      context->navQuarantineButton = CreateWindowW(L"BUTTON", L"Quarantine", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                                   0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_NAV_QUARANTINE), nullptr, nullptr);
      context->navScansButton = CreateWindowW(L"BUTTON", L"Scans", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                              0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_NAV_SCANS), nullptr, nullptr);
      context->navServiceButton = CreateWindowW(L"BUTTON", L"Service", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                                0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_NAV_SERVICE), nullptr, nullptr);
      context->navHistoryButton = CreateWindowW(L"BUTTON", L"History", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                                0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_NAV_HISTORY), nullptr, nullptr);
      context->navSettingsButton = CreateWindowW(L"BUTTON", L"Settings", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                                 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_NAV_SETTINGS), nullptr, nullptr);
      context->quickScanButton = CreateWindowW(L"BUTTON", L"Quick scan", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                               0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BUTTON_QUICKSCAN), nullptr, nullptr);
      context->fullScanButton = CreateWindowW(L"BUTTON", L"Full scan", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                              0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BUTTON_FULLSCAN), nullptr, nullptr);
      context->customScanButton = CreateWindowW(L"BUTTON", L"Scan folder", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                                0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BUTTON_CUSTOMSCAN), nullptr, nullptr);
      context->refreshButton = CreateWindowW(L"BUTTON", L"Refresh status", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                             0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BUTTON_REFRESH), nullptr, nullptr);
      context->startServiceButton = CreateWindowW(L"BUTTON", L"Start protection", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                                  0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BUTTON_STARTSERVICE), nullptr, nullptr);
      context->openQuarantineButton = CreateWindowW(L"BUTTON", L"Open quarantine folder", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                                    0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BUTTON_OPENQUARANTINE), nullptr, nullptr);
      context->scanStatusLabel = CreateWindowW(L"STATIC", L"Ready.", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                               0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SCAN_STATUS), nullptr, nullptr);
      context->progressBar = CreateWindowExW(0, PROGRESS_CLASSW, nullptr, WS_CHILD | PBS_SMOOTH,
                                              0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_PROGRESS), nullptr, nullptr);
      context->threatsList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, nullptr,
                                              WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                              0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_THREATS_LIST), nullptr, nullptr);
      context->quarantineList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, nullptr,
                                                WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                                0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_QUARANTINE_LIST), nullptr, nullptr);
      context->historyList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, nullptr,
                                              WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                              0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_HISTORY_LIST), nullptr, nullptr);
      context->detailEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE |
                                                                 ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                                            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_DETAIL_EDIT), nullptr, nullptr);
      context->restoreButton = CreateWindowW(L"BUTTON", L"Restore", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                             0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BUTTON_RESTORE), nullptr, nullptr);
      context->deleteButton = CreateWindowW(L"BUTTON", L"Delete", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                                            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BUTTON_DELETE), nullptr, nullptr);

      const std::vector<HWND> bodyControls = {
          context->brandCard,         context->subtitleLabel,    context->statusBadge,      context->primarySectionTitle,
          context->secondarySectionTitle, context->summaryCard,  context->detailsCard,      context->metricThreats,
          context->metricQuarantine,  context->metricService,    context->metricSync,       context->navDashboardButton,
          context->navThreatsButton,  context->navQuarantineButton, context->navScansButton, context->navServiceButton,
          context->navHistoryButton,  context->navSettingsButton, context->quickScanButton, context->fullScanButton,
          context->customScanButton,  context->refreshButton,    context->startServiceButton, context->openQuarantineButton,
          context->scanStatusLabel,   context->detailEdit,       context->restoreButton,    context->deleteButton};
      for (const auto control : bodyControls) {
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(context->bodyFont), TRUE);
      }
      SendMessageW(context->titleLabel, WM_SETFONT, reinterpret_cast<WPARAM>(context->titleFont), TRUE);
      SendMessageW(context->subtitleLabel, WM_SETFONT, reinterpret_cast<WPARAM>(context->headingFont), TRUE);

      InitializeListView(context->threatsList);
      InitializeListView(context->quarantineList);
      InitializeListView(context->historyList);
      SetWindowTheme(context->threatsList, L"Explorer", nullptr);
      SetWindowTheme(context->quarantineList, L"Explorer", nullptr);
      SetWindowTheme(context->historyList, L"Explorer", nullptr);
      ListView_SetBkColor(context->threatsList, ListBackColor());
      ListView_SetTextBkColor(context->threatsList, ListBackColor());
      ListView_SetTextColor(context->threatsList, DarkTextColor());
      ListView_SetBkColor(context->quarantineList, ListBackColor());
      ListView_SetTextBkColor(context->quarantineList, ListBackColor());
      ListView_SetTextColor(context->quarantineList, DarkTextColor());
      ListView_SetBkColor(context->historyList, ListBackColor());
      ListView_SetTextBkColor(context->historyList, ListBackColor());
      ListView_SetTextColor(context->historyList, DarkTextColor());
      SendMessageW(context->progressBar, PBM_SETBKCOLOR, 0, static_cast<LPARAM>(DetailsCardColor()));
      SendMessageW(context->progressBar, PBM_SETBARCOLOR, 0, static_cast<LPARAM>(AccentBlue()));

      ConfigureListViewColumns(context->threatsList,
                               {{L"Detected", 170}, {L"Item", 360}, {L"Action", 110},
                                {L"Confidence", 100}, {L"ATT&CK", 180}, {L"Remediation", 130}});
      ConfigureListViewColumns(context->quarantineList,
                               {{L"Captured", 170}, {L"Original path", 380}, {L"Status", 120},
                                {L"Technique", 160}, {L"SHA-256", 260}});
      ConfigureListViewColumns(context->historyList,
                               {{L"Recorded", 170}, {L"Result", 110}, {L"Item", 360},
                                {L"Source", 150}, {L"Technique", 140}, {L"Remediation", 130}});

      SetScanRunning(*context, false, L"Ready.");
      RefreshSnapshot(*context);
      SelectPage(*context, ClientPage::Dashboard);
      LayoutControls(*context);
      SetTimer(hwnd, kRefreshTimerId, kRefreshIntervalMs, nullptr);
      return 0;
    }

    case WM_SIZE: {
      if (auto* context = GetContext(hwnd)) {
        LayoutControls(*context);
      }
      return 0;
    }

    case WM_TIMER: {
      if (wParam == kRefreshTimerId) {
        if (auto* context = GetContext(hwnd)) {
          RefreshSnapshot(*context);
        }
      }
      return 0;
    }

    case WM_NOTIFY: {
      auto* context = GetContext(hwnd);
      if (context == nullptr) {
        break;
      }

      const auto* header = reinterpret_cast<NMHDR*>(lParam);
      if (header == nullptr) {
        break;
      }

      if ((header->hwndFrom == context->threatsList || header->hwndFrom == context->quarantineList ||
           header->hwndFrom == context->historyList) &&
          header->code == NM_CUSTOMDRAW) {
        return HandleListCustomDraw(reinterpret_cast<NMLVCUSTOMDRAW*>(lParam));
      }

      if ((header->hwndFrom == context->threatsList || header->hwndFrom == context->quarantineList ||
           header->hwndFrom == context->historyList) &&
          header->code == LVN_ITEMCHANGED) {
        UpdateDetailPane(*context);
        return 0;
      }
      break;
    }

    case WM_COMMAND: {
      auto* context = GetContext(hwnd);
      if (context == nullptr) {
        return 0;
      }

      switch (LOWORD(wParam)) {
        case IDC_NAV_DASHBOARD:
          SelectPage(*context, ClientPage::Dashboard);
          LayoutControls(*context);
          return 0;
        case IDC_NAV_THREATS:
          SelectPage(*context, ClientPage::Threats);
          LayoutControls(*context);
          return 0;
        case IDC_NAV_QUARANTINE:
          SelectPage(*context, ClientPage::Quarantine);
          LayoutControls(*context);
          return 0;
        case IDC_NAV_SCANS:
          SelectPage(*context, ClientPage::Scans);
          LayoutControls(*context);
          return 0;
        case IDC_NAV_SERVICE:
          SelectPage(*context, ClientPage::Service);
          LayoutControls(*context);
          return 0;
        case IDC_NAV_HISTORY:
          SelectPage(*context, ClientPage::History);
          LayoutControls(*context);
          return 0;
        case IDC_NAV_SETTINGS:
          SelectPage(*context, ClientPage::Settings);
          LayoutControls(*context);
          return 0;
        case IDC_BUTTON_REFRESH:
          RefreshSnapshot(*context);
          return 0;
        case IDC_BUTTON_QUICKSCAN:
          RunScanAsync(hwnd, *context, ScanPreset::Quick, std::nullopt);
          return 0;
        case IDC_BUTTON_FULLSCAN:
          RunScanAsync(hwnd, *context, ScanPreset::Full, std::nullopt);
          return 0;
        case IDC_BUTTON_CUSTOMSCAN: {
          const auto folder = PickFolder(hwnd);
          if (folder.has_value()) {
            RunScanAsync(hwnd, *context, ScanPreset::Folder, std::filesystem::path(*folder));
          }
          return 0;
        }
        case IDC_BUTTON_STARTSERVICE:
          if (!antivirus::agent::StartAgentService()) {
            MessageBoxW(hwnd, L"Unable to start the protection service from the local client.",
                        kWindowTitle, MB_OK | MB_ICONWARNING);
          }
          RefreshSnapshot(*context);
          return 0;
        case IDC_BUTTON_OPENQUARANTINE:
          SelectPage(*context, ClientPage::Quarantine);
          LayoutControls(*context);
          OpenQuarantineFolder(*context);
          return 0;
        case IDC_BUTTON_RESTORE:
          PerformQuarantineAction(*context, true);
          return 0;
        case IDC_BUTTON_DELETE:
          PerformQuarantineAction(*context, false);
          return 0;
        case IDM_TRAY_OPEN:
          RestoreFromTray(hwnd);
          SelectPage(*context, ClientPage::Dashboard);
          LayoutControls(*context);
          return 0;
        case IDM_TRAY_QUICKSCAN:
          RunScanAsync(hwnd, *context, ScanPreset::Quick, std::nullopt);
          return 0;
        case IDM_TRAY_FULLSCAN:
          RunScanAsync(hwnd, *context, ScanPreset::Full, std::nullopt);
          return 0;
        case IDM_TRAY_QUARANTINE:
          RestoreFromTray(hwnd);
          SelectPage(*context, ClientPage::Quarantine);
          LayoutControls(*context);
          return 0;
        case IDM_TRAY_EXIT:
          context->allowExit = true;
          DestroyWindow(hwnd);
          return 0;
        default:
          return 0;
      }
    }

    case kScanCompleteMessage: {
      auto* context = GetContext(hwnd);
      auto* payload = reinterpret_cast<ScanCompletePayload*>(lParam);
      if (context != nullptr && payload != nullptr) {
        context->scanRunning = false;
        context->activeScanLabel.clear();
        SetScanRunning(*context, false, payload->summary);
        RefreshSnapshot(*context);
        SelectPage(*context, context->snapshot.openThreatCount != 0 ? ClientPage::Threats : ClientPage::Scans);
        LayoutControls(*context);
        if (IsWindowInteractive(*context)) {
          MessageBoxW(hwnd, payload->summary.c_str(), kWindowTitle,
                      MB_OK | (payload->success ? MB_ICONINFORMATION : MB_ICONWARNING));
        } else {
          ShowTrayNotification(*context, payload->success ? L"Scan completed" : L"Scan needs attention",
                               payload->summary, payload->success ? NIIF_INFO : NIIF_WARNING);
        }
      }
      delete payload;
      return 0;
    }

    case kScanProgressMessage: {
      auto* context = GetContext(hwnd);
      auto* payload = reinterpret_cast<ScanProgressPayload*>(lParam);
      if (context != nullptr && payload != nullptr && context->scanRunning) {
        UpdateScanProgress(*context, payload->status, payload->completedTargets, payload->totalTargets);
      }
      delete payload;
      return 0;
    }

    case WM_CLOSE: {
      auto* context = GetContext(hwnd);
      if (context != nullptr && !context->allowExit) {
        HideToTray(hwnd);
        return 0;
      }

      DestroyWindow(hwnd);
      return 0;
    }

    case WM_DESTROY: {
      auto* context = GetContext(hwnd);
      if (context != nullptr) {
        KillTimer(hwnd, kRefreshTimerId);
        if (context->trayAdded) {
          Shell_NotifyIconW(NIM_DELETE, &context->trayIcon);
        }
        if (context->titleFont != nullptr) {
          DeleteObject(context->titleFont);
        }
        if (context->headingFont != nullptr) {
          DeleteObject(context->headingFont);
        }
        if (context->bodyFont != nullptr) {
          DeleteObject(context->bodyFont);
        }
        DestroyBrandIcons(*context);
        DestroyThemeResources(*context);
        delete context;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
      }

      if (g_instanceMutex != nullptr) {
        CloseHandle(g_instanceMutex);
        g_instanceMutex = nullptr;
      }

      PostQuitMessage(0);
      return 0;
    }
  }

  return DefWindowProcW(hwnd, message, wParam, lParam);
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
  INITCOMMONCONTROLSEX controls{};
  controls.dwSize = sizeof(controls);
  controls.dwICC = ICC_STANDARD_CLASSES | ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_TAB_CLASSES;
  InitCommonControlsEx(&controls);
  OleInitialize(nullptr);
  const auto launchOptions = ParseLaunchOptions();

  g_instanceMutex = CreateMutexW(nullptr, FALSE, kInstanceMutexName);
  if (g_instanceMutex != nullptr && GetLastError() == ERROR_ALREADY_EXISTS) {
    if (!launchOptions.backgroundMode) {
      PostMessageW(HWND_BROADCAST, RestoreWindowMessageId(), 0, 0);
    }
    CloseHandle(g_instanceMutex);
    g_instanceMutex = nullptr;
    OleUninitialize();
    return 0;
  }

  HICON classLargeIcon = CreateBrandIcon(32, BrandIconTone::Neutral);
  HICON classSmallIcon = CreateBrandIcon(16, BrandIconTone::Neutral);

  WNDCLASSEXW windowClass{};
  windowClass.cbSize = sizeof(windowClass);
  windowClass.lpfnWndProc = WindowProc;
  windowClass.hInstance = instance;
  windowClass.lpszClassName = kWindowClassName;
  windowClass.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
  windowClass.hIcon = classLargeIcon;
  windowClass.hIconSm = classSmallIcon;
  windowClass.hbrBackground = nullptr;
  RegisterClassExW(&windowClass);

  HWND hwnd = CreateWindowExW(0, kWindowClassName, kWindowTitle, WS_OVERLAPPEDWINDOW,
                              CW_USEDEFAULT, CW_USEDEFAULT, 1440, 980,
                              nullptr, nullptr, instance, const_cast<LaunchOptions*>(&launchOptions));
  if (hwnd == nullptr) {
    DestroyIcon(classLargeIcon);
    DestroyIcon(classSmallIcon);
    if (g_instanceMutex != nullptr) {
      CloseHandle(g_instanceMutex);
      g_instanceMutex = nullptr;
    }
    OleUninitialize();
    return 1;
  }

  ShowWindow(hwnd, launchOptions.backgroundMode ? SW_HIDE : (showCommand == 0 ? SW_SHOWDEFAULT : showCommand));
  UpdateWindow(hwnd);

  MSG message{};
  while (GetMessageW(&message, nullptr, 0, 0) > 0) {
    TranslateMessage(&message);
    DispatchMessageW(&message);
  }

  DestroyIcon(classLargeIcon);
  DestroyIcon(classSmallIcon);
  OleUninitialize();
  return static_cast<int>(message.wParam);
}
