#include <fltKernel.h>
#include <dontuse.h>
#include <ntstrsafe.h>
#include <suppress.h>

#include "../../shared/include/RealtimeProtectionProtocol.h"

PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT gServerPort = NULL;
PFLT_PORT gClientPort = NULL;
FAST_MUTEX gClientPortLock;

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

NTSTATUS
AntivirusUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS
AntivirusInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                       _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

FLT_PREOP_CALLBACK_STATUS
AntivirusPreCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                   _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS
AntivirusPreWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                  _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS
AntivirusPreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                           _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS
AntivirusPreAcquireForSectionSynchronization(_Inout_ PFLT_CALLBACK_DATA Data,
                                             _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                             _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

NTSTATUS
AntivirusPortConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie, _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
                     _In_ ULONG SizeOfContext, _Outptr_result_maybenull_ PVOID* ConnectionPortCookie);

VOID
AntivirusPortDisconnect(_In_opt_ PVOID ConnectionCookie);

static NTSTATUS
AntivirusInspectFileOperation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                              _In_ ANTIVIRUS_REALTIME_FILE_OPERATION Operation);

static NTSTATUS
AntivirusBuildRequest(_Inout_ PFLT_CALLBACK_DATA Data, _In_ ANTIVIRUS_REALTIME_FILE_OPERATION Operation,
                      _Out_ ANTIVIRUS_REALTIME_SCAN_REQUEST* Request);

static BOOLEAN
AntivirusShouldScanCreate(_In_ PFLT_CALLBACK_DATA Data, _Out_ ANTIVIRUS_REALTIME_FILE_OPERATION* Operation);

static BOOLEAN
AntivirusHasConnectedBroker(VOID);

static BOOLEAN
AntivirusShouldFailClosed(_In_ ANTIVIRUS_REALTIME_FILE_OPERATION Operation);

static BOOLEAN
AntivirusShouldFailClosedForContext(_Inout_ PFLT_CALLBACK_DATA Data, _In_ ANTIVIRUS_REALTIME_FILE_OPERATION Operation,
                                    _In_opt_ const ANTIVIRUS_REALTIME_SCAN_REQUEST* Request,
                                    _In_ PCFLT_RELATED_OBJECTS FltObjects);

static BOOLEAN
AntivirusIsHighRiskPath(_In_z_ const WCHAR* Path);

static BOOLEAN
AntivirusIsSensitiveSetInformationClass(_In_ FILE_INFORMATION_CLASS informationClass);

static BOOLEAN
AntivirusIsSectionSyncHighRisk(_Inout_ PFLT_CALLBACK_DATA Data);

static BOOLEAN
AntivirusVolumeIsRemoteOrRemovable(_In_ PCFLT_RELATED_OBJECTS FltObjects);

static BOOLEAN
AntivirusPathHasCloudSyncMarker(_In_z_ const WCHAR* Path);

static BOOLEAN
AntivirusPathHasTraversalSequence(_In_z_ const WCHAR* Path);

static BOOLEAN
AntivirusPathContainsInsensitive(_In_z_ const WCHAR* Path, _In_z_ const WCHAR* Needle);

static BOOLEAN
AntivirusPathContainsAlternateDataStream(_In_z_ const WCHAR* Path);

static BOOLEAN
AntivirusPathHasPrefixInsensitive(_In_z_ const WCHAR* Path, _In_z_ const WCHAR* Prefix);

const FLT_OPERATION_REGISTRATION gCallbacks[] = {
    {IRP_MJ_CREATE, 0, AntivirusPreCreate, NULL},
    {IRP_MJ_WRITE, 0, AntivirusPreWrite, NULL},
  {IRP_MJ_SET_INFORMATION, 0, AntivirusPreSetInformation, NULL},
  {IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, AntivirusPreAcquireForSectionSynchronization, NULL},
    {IRP_MJ_OPERATION_END}};

const FLT_REGISTRATION gRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    gCallbacks,
    AntivirusUnload,
    AntivirusInstanceSetup,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL};

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
  NTSTATUS status;
  OBJECT_ATTRIBUTES objectAttributes;
  UNICODE_STRING portName;
  PSECURITY_DESCRIPTOR securityDescriptor = NULL;

  UNREFERENCED_PARAMETER(RegistryPath);

  ExInitializeFastMutex(&gClientPortLock);

  status = FltRegisterFilter(DriverObject, &gRegistration, &gFilterHandle);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  RtlInitUnicodeString(&portName, ANTIVIRUS_REALTIME_PORT_NAME);
  status = FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);
  if (!NT_SUCCESS(status)) {
    FltUnregisterFilter(gFilterHandle);
    gFilterHandle = NULL;
    return status;
  }

  InitializeObjectAttributes(&objectAttributes, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL,
                             securityDescriptor);

  status = FltCreateCommunicationPort(gFilterHandle, &gServerPort, &objectAttributes, NULL, AntivirusPortConnect,
                                      AntivirusPortDisconnect, NULL, 1);

  FltFreeSecurityDescriptor(securityDescriptor);
  securityDescriptor = NULL;

  if (!NT_SUCCESS(status)) {
    FltUnregisterFilter(gFilterHandle);
    gFilterHandle = NULL;
    return status;
  }

  status = FltStartFiltering(gFilterHandle);
  if (!NT_SUCCESS(status)) {
    if (gServerPort != NULL) {
      FltCloseCommunicationPort(gServerPort);
      gServerPort = NULL;
    }

    FltUnregisterFilter(gFilterHandle);
    gFilterHandle = NULL;
  }

  return status;
}

NTSTATUS
AntivirusUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
  UNREFERENCED_PARAMETER(Flags);

  ExAcquireFastMutex(&gClientPortLock);
  if (gClientPort != NULL) {
    FltCloseClientPort(gFilterHandle, &gClientPort);
    gClientPort = NULL;
  }
  ExReleaseFastMutex(&gClientPortLock);

  if (gServerPort != NULL) {
    FltCloseCommunicationPort(gServerPort);
    gServerPort = NULL;
  }

  if (gFilterHandle != NULL) {
    FltUnregisterFilter(gFilterHandle);
    gFilterHandle = NULL;
  }

  return STATUS_SUCCESS;
}

NTSTATUS
AntivirusInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                       _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType) {
  UNREFERENCED_PARAMETER(FltObjects);
  UNREFERENCED_PARAMETER(Flags);
  UNREFERENCED_PARAMETER(VolumeDeviceType);
  UNREFERENCED_PARAMETER(VolumeFilesystemType);
  return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
AntivirusPreCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                   _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
  ANTIVIRUS_REALTIME_FILE_OPERATION operation;
  NTSTATUS status;

  UNREFERENCED_PARAMETER(CompletionContext);

  if (!AntivirusShouldScanCreate(Data, &operation)) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  status = AntivirusInspectFileOperation(Data, FltObjects, operation);
  if (status == STATUS_ACCESS_DENIED) {
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
  }

  return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
AntivirusPreWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                  _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
  NTSTATUS status;

  UNREFERENCED_PARAMETER(CompletionContext);

  if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  status = AntivirusInspectFileOperation(Data, FltObjects, ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE);
  if (status == STATUS_ACCESS_DENIED) {
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
  }

  return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
AntivirusPreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                           _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
  NTSTATUS status;

  UNREFERENCED_PARAMETER(CompletionContext);

  if (Data->Iopb == NULL ||
      !AntivirusIsSensitiveSetInformationClass(Data->Iopb->Parameters.SetFileInformation.FileInformationClass)) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  status = AntivirusInspectFileOperation(Data, FltObjects, ANTIVIRUS_REALTIME_FILE_OPERATION_RENAME);
  if (status == STATUS_ACCESS_DENIED) {
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
  }

  return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
AntivirusPreAcquireForSectionSynchronization(_Inout_ PFLT_CALLBACK_DATA Data,
                                             _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                             _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
  NTSTATUS status;
  ANTIVIRUS_REALTIME_FILE_OPERATION operation;

  UNREFERENCED_PARAMETER(CompletionContext);

  if (!AntivirusIsSectionSyncHighRisk(Data)) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  operation = ANTIVIRUS_REALTIME_FILE_OPERATION_SECTION_MAP;
  if (Data->Iopb != NULL) {
    const ULONG pageProtection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
    const ULONG executeMask = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (!FlagOn(pageProtection, executeMask)) {
      operation = ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE;
    }
  }

  status = AntivirusInspectFileOperation(Data, FltObjects, operation);
  if (status == STATUS_ACCESS_DENIED) {
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
  }

  return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS
AntivirusPortConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie,
                     _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext, _In_ ULONG SizeOfContext,
                     _Outptr_result_maybenull_ PVOID* ConnectionPortCookie) {
  UNREFERENCED_PARAMETER(ServerPortCookie);
  UNREFERENCED_PARAMETER(ConnectionContext);
  UNREFERENCED_PARAMETER(SizeOfContext);
  UNREFERENCED_PARAMETER(ConnectionPortCookie);

  ExAcquireFastMutex(&gClientPortLock);
  gClientPort = ClientPort;
  ExReleaseFastMutex(&gClientPortLock);

  return STATUS_SUCCESS;
}

VOID
AntivirusPortDisconnect(_In_opt_ PVOID ConnectionCookie) {
  UNREFERENCED_PARAMETER(ConnectionCookie);

  ExAcquireFastMutex(&gClientPortLock);
  if (gClientPort != NULL) {
    FltCloseClientPort(gFilterHandle, &gClientPort);
    gClientPort = NULL;
  }
  ExReleaseFastMutex(&gClientPortLock);
}

static NTSTATUS
AntivirusInspectFileOperation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                              _In_ ANTIVIRUS_REALTIME_FILE_OPERATION Operation) {
  NTSTATUS status;
  ANTIVIRUS_REALTIME_SCAN_REQUEST request;
  ANTIVIRUS_REALTIME_SCAN_REPLY reply;
  ULONG replyLength;
  LARGE_INTEGER timeout;
  PFLT_PORT clientPort = NULL;
  BOOLEAN strictFailClosed;

  UNREFERENCED_PARAMETER(FltObjects);

  if (Data == NULL || Data->Iopb == NULL) {
    return AntivirusShouldFailClosed(Operation) ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
  }

  RtlZeroMemory(&request, sizeof(request));
  RtlZeroMemory(&reply, sizeof(reply));

  status = AntivirusBuildRequest(Data, Operation, &request);
  strictFailClosed = AntivirusShouldFailClosedForContext(Data, Operation, NT_SUCCESS(status) ? &request : NULL,
                                                         FltObjects);
  if (!NT_SUCCESS(status)) {
    return strictFailClosed ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
  }

  if (!AntivirusHasConnectedBroker()) {
    return strictFailClosed ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
  }

  ExAcquireFastMutex(&gClientPortLock);
  clientPort = gClientPort;
  ExReleaseFastMutex(&gClientPortLock);

  if (clientPort == NULL) {
    return strictFailClosed ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
  }

  request.protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
  request.requestSize = sizeof(request);
  request.requestId = (uint64_t)(ULONG_PTR)Data;
  request.operation = Operation;
  request.processId = HandleToULong(PsGetCurrentProcessId());
  request.threadId = HandleToULong(PsGetCurrentThreadId());

  timeout.QuadPart = -((strictFailClosed ? 2500 : 1000) * 10 * 1000);
  replyLength = sizeof(reply);

  status = FltSendMessage(gFilterHandle, &clientPort, &request, sizeof(request), &reply, &replyLength, &timeout);
  if (!NT_SUCCESS(status)) {
    return strictFailClosed ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
  }

  if (replyLength < sizeof(reply) || reply.protocolVersion != ANTIVIRUS_REALTIME_PROTOCOL_VERSION) {
    return strictFailClosed ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
  }

  if (reply.action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK) {
    return STATUS_ACCESS_DENIED;
  }

  if (reply.action != ANTIVIRUS_REALTIME_RESPONSE_ACTION_ALLOW) {
    return strictFailClosed ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
  }

  return STATUS_SUCCESS;
}

static NTSTATUS
AntivirusBuildRequest(_Inout_ PFLT_CALLBACK_DATA Data, _In_ ANTIVIRUS_REALTIME_FILE_OPERATION Operation,
                      _Out_ ANTIVIRUS_REALTIME_SCAN_REQUEST* Request) {
  NTSTATUS status;
  PFLT_FILE_NAME_INFORMATION fileNameInformation = NULL;
  CHAR processImageName[16] = {0};

  UNREFERENCED_PARAMETER(Operation);

  if (Data == NULL || Data->Iopb == NULL || Request == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &fileNameInformation);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = FltParseFileNameInformation(fileNameInformation);
  if (!NT_SUCCESS(status)) {
    FltReleaseFileNameInformation(fileNameInformation);
    return status;
  }

  if (fileNameInformation->Name.Length == 0 || fileNameInformation->Name.Buffer == NULL) {
    FltReleaseFileNameInformation(fileNameInformation);
    return STATUS_INVALID_PARAMETER;
  }

  if ((fileNameInformation->Name.Length / sizeof(WCHAR)) >= ANTIVIRUS_REALTIME_PATH_CAPACITY) {
    FltReleaseFileNameInformation(fileNameInformation);
    return STATUS_NAME_TOO_LONG;
  }

  status = RtlStringCchCopyNW(Request->path, ANTIVIRUS_REALTIME_PATH_CAPACITY, fileNameInformation->Name.Buffer,
                              fileNameInformation->Name.Length / sizeof(WCHAR));
  if (!NT_SUCCESS(status) || Request->path[0] == L'\0') {
    FltReleaseFileNameInformation(fileNameInformation);
    return NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status;
  }

  RtlStringCchPrintfW(Request->correlationId, ANTIVIRUS_REALTIME_CORRELATION_CAPACITY, L"%p", Data);

  RtlZeroMemory(processImageName, sizeof(processImageName));
  RtlCopyMemory(processImageName, PsGetProcessImageFileName(PsGetCurrentProcess()),
                min(sizeof(processImageName) - 1, sizeof(processImageName)));
  RtlStringCchPrintfW(Request->processImage, ANTIVIRUS_REALTIME_IMAGE_CAPACITY, L"%S", processImageName);

  FltReleaseFileNameInformation(fileNameInformation);
  return STATUS_SUCCESS;
}

static BOOLEAN
AntivirusShouldScanCreate(_In_ PFLT_CALLBACK_DATA Data, _Out_ ANTIVIRUS_REALTIME_FILE_OPERATION* Operation) {
  const ACCESS_MASK desiredAccess =
    (Data != NULL && Data->Iopb != NULL && Data->Iopb->Parameters.Create.SecurityContext != NULL)
      ? Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess
      : 0;
  const BOOLEAN executeIntent = FlagOn(desiredAccess, FILE_EXECUTE);
  const BOOLEAN writeIntent =
    FlagOn(desiredAccess,
       FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC |
         WRITE_OWNER);
  const BOOLEAN createDisposition =
      (Data->Iopb->Parameters.Create.Options >> 24) == FILE_CREATE ||
      (Data->Iopb->Parameters.Create.Options >> 24) == FILE_SUPERSEDE ||
      (Data->Iopb->Parameters.Create.Options >> 24) == FILE_OVERWRITE ||
      (Data->Iopb->Parameters.Create.Options >> 24) == FILE_OVERWRITE_IF;

  if (Data == NULL || Data->Iopb == NULL || Operation == NULL) {
    return FALSE;
  }

  if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
    return FALSE;
  }

  if (executeIntent) {
    *Operation = ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE;
    return TRUE;
  }

  if (createDisposition) {
    *Operation = ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE;
    return TRUE;
  }

  if (writeIntent) {
    *Operation = ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE;
    return TRUE;
  }

  *Operation = ANTIVIRUS_REALTIME_FILE_OPERATION_OPEN;
  return TRUE;
}

static BOOLEAN
AntivirusHasConnectedBroker(VOID) {
  BOOLEAN hasClientPort;

  ExAcquireFastMutex(&gClientPortLock);
  hasClientPort = (gClientPort != NULL);
  ExReleaseFastMutex(&gClientPortLock);

  return hasClientPort;
}

static BOOLEAN
AntivirusShouldFailClosed(_In_ ANTIVIRUS_REALTIME_FILE_OPERATION Operation) {
  return Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE ||
         Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE ||
         Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE ||
         Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_RENAME ||
         Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_SECTION_MAP;
}

static BOOLEAN
AntivirusShouldFailClosedForContext(_Inout_ PFLT_CALLBACK_DATA Data, _In_ ANTIVIRUS_REALTIME_FILE_OPERATION Operation,
                                    _In_opt_ const ANTIVIRUS_REALTIME_SCAN_REQUEST* Request,
                                    _In_ PCFLT_RELATED_OBJECTS FltObjects) {
  BOOLEAN isCreateReparseOpen = FALSE;
  BOOLEAN isSensitiveSetInformation = FALSE;
  BOOLEAN isSectionSyncHighRisk = FALSE;

  if (Data->Iopb != NULL && Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
    isCreateReparseOpen = FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_REPARSE_POINT);
  }

  if (Data->Iopb != NULL && Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
    isSensitiveSetInformation = AntivirusIsSensitiveSetInformationClass(
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass);
  }

  if (Data->Iopb != NULL && Data->Iopb->MajorFunction == IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION) {
    isSectionSyncHighRisk = AntivirusIsSectionSyncHighRisk(Data);
  }

  if (AntivirusShouldFailClosed(Operation) || isCreateReparseOpen || isSensitiveSetInformation ||
      isSectionSyncHighRisk || AntivirusVolumeIsRemoteOrRemovable(FltObjects)) {
    return TRUE;
  }

  if (Request != NULL &&
      (AntivirusIsHighRiskPath(Request->path) || AntivirusPathHasCloudSyncMarker(Request->path))) {
    return TRUE;
  }

  return FALSE;
}

static BOOLEAN
AntivirusIsSensitiveSetInformationClass(_In_ FILE_INFORMATION_CLASS informationClass) {
  if (informationClass == FileRenameInformation || informationClass == FileLinkInformation ||
      informationClass == FileDispositionInformation || informationClass == FileAllocationInformation ||
      informationClass == FileEndOfFileInformation) {
    return TRUE;
  }

#ifdef FileRenameInformationEx
  if (informationClass == FileRenameInformationEx) {
    return TRUE;
  }
#endif

#ifdef FileLinkInformationEx
  if (informationClass == FileLinkInformationEx) {
    return TRUE;
  }
#endif

#ifdef FileDispositionInformationEx
  if (informationClass == FileDispositionInformationEx) {
    return TRUE;
  }
#endif

  return FALSE;
}

static BOOLEAN
AntivirusIsSectionSyncHighRisk(_Inout_ PFLT_CALLBACK_DATA Data) {
  ULONG pageProtection;
  ULONG executeMask;
  ULONG writableMask;

  if (Data == NULL || Data->Iopb == NULL ||
      Data->Iopb->MajorFunction != IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION) {
    return FALSE;
  }

  if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) {
    return FALSE;
  }

  pageProtection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
  executeMask = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
  writableMask = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

  return FlagOn(pageProtection, executeMask) || FlagOn(pageProtection, writableMask);
}

static BOOLEAN
AntivirusIsHighRiskPath(_In_z_ const WCHAR* Path) {
  if (Path == NULL || Path[0] == L'\0') {
    return FALSE;
  }

  if (AntivirusPathHasTraversalSequence(Path)) {
    return TRUE;
  }

  if (AntivirusPathContainsAlternateDataStream(Path)) {
    return TRUE;
  }

  if (AntivirusPathHasPrefixInsensitive(Path, L"\\Device\\Mup\\") ||
      AntivirusPathHasPrefixInsensitive(Path, L"\\Device\\LanmanRedirector\\") ||
      AntivirusPathHasPrefixInsensitive(Path, L"\\Device\\WebDavRedirector\\") ||
      AntivirusPathHasPrefixInsensitive(Path, L"\\??\\UNC\\") ||
      AntivirusPathHasPrefixInsensitive(Path, L"\\??\\GLOBALROOT\\Device\\Mup\\") ||
      AntivirusPathHasPrefixInsensitive(Path, L"\\Device\\CdRom")) {
    return TRUE;
  }

  if (AntivirusPathHasCloudSyncMarker(Path)) {
    return TRUE;
  }

  return FALSE;
}

static BOOLEAN
AntivirusVolumeIsRemoteOrRemovable(_In_ PCFLT_RELATED_OBJECTS FltObjects) {
  NTSTATUS status;
  ULONG bytesReturned = 0;
  UCHAR volumePropertiesBuffer[sizeof(FLT_VOLUME_PROPERTIES) + 512] = {0};
  PFLT_VOLUME_PROPERTIES volumeProperties;

  if (FltObjects == NULL || FltObjects->Volume == NULL) {
    return FALSE;
  }

  volumeProperties = (PFLT_VOLUME_PROPERTIES)volumePropertiesBuffer;
  status = FltGetVolumeProperties(FltObjects->Volume, volumeProperties, sizeof(volumePropertiesBuffer),
                                  &bytesReturned);
  if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
    return FALSE;
  }

  return FlagOn(volumeProperties->DeviceCharacteristics, FILE_REMOTE_DEVICE) ||
         FlagOn(volumeProperties->DeviceCharacteristics, FILE_REMOVABLE_MEDIA);
}

static BOOLEAN
AntivirusPathHasCloudSyncMarker(_In_z_ const WCHAR* Path) {
  return AntivirusPathContainsInsensitive(Path, L"\\onedrive\\") ||
         AntivirusPathContainsInsensitive(Path, L"\\dropbox\\") ||
         AntivirusPathContainsInsensitive(Path, L"\\google drive\\") ||
         AntivirusPathContainsInsensitive(Path, L"\\googledrive\\") ||
         AntivirusPathContainsInsensitive(Path, L"\\icloud drive\\") ||
         AntivirusPathContainsInsensitive(Path, L"\\box\\") ||
         AntivirusPathContainsInsensitive(Path, L"\\syncthing\\");
}

static BOOLEAN
AntivirusPathHasTraversalSequence(_In_z_ const WCHAR* Path) {
  return AntivirusPathContainsInsensitive(Path, L"\\..\\") ||
         AntivirusPathContainsInsensitive(Path, L"/../") ||
         AntivirusPathContainsInsensitive(Path, L"\\.\\") ||
         AntivirusPathContainsInsensitive(Path, L"/./");
}

static BOOLEAN
AntivirusPathContainsInsensitive(_In_z_ const WCHAR* Path, _In_z_ const WCHAR* Needle) {
  SIZE_T pathIndex;
  SIZE_T needleLength = 0;

  if (Path == NULL || Needle == NULL || Needle[0] == L'\0') {
    return FALSE;
  }

  while (Needle[needleLength] != L'\0') {
    ++needleLength;
  }

  for (pathIndex = 0; Path[pathIndex] != L'\0'; ++pathIndex) {
    SIZE_T offset = 0;
    while (offset < needleLength && Path[pathIndex + offset] != L'\0' &&
           RtlDowncaseUnicodeChar(Path[pathIndex + offset]) == RtlDowncaseUnicodeChar(Needle[offset])) {
      ++offset;
    }

    if (offset == needleLength) {
      return TRUE;
    }

    if (Path[pathIndex + offset] == L'\0') {
      break;
    }
  }

  return FALSE;
}

static BOOLEAN
AntivirusPathContainsAlternateDataStream(_In_z_ const WCHAR* Path) {
  SIZE_T index;
  WCHAR previous = L'\0';

  if (Path == NULL) {
    return FALSE;
  }

  for (index = 0; Path[index] != L'\0'; ++index) {
    if (Path[index] != L':') {
      previous = Path[index];
      continue;
    }

    if (index == 1 && ((Path[0] >= L'A' && Path[0] <= L'Z') || (Path[0] >= L'a' && Path[0] <= L'z'))) {
      previous = Path[index];
      continue;
    }

    if (previous != L'\\') {
      return TRUE;
    }

    previous = Path[index];
  }

  return FALSE;
}

static BOOLEAN
AntivirusPathHasPrefixInsensitive(_In_z_ const WCHAR* Path, _In_z_ const WCHAR* Prefix) {
  UNICODE_STRING pathString;
  UNICODE_STRING prefixString;

  if (Path == NULL || Prefix == NULL) {
    return FALSE;
  }

  RtlInitUnicodeString(&pathString, Path);
  RtlInitUnicodeString(&prefixString, Prefix);
  return RtlPrefixUnicodeString(&prefixString, &pathString, TRUE);
}
