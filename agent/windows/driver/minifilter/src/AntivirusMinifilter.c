#include <fltKernel.h>
#include <dontuse.h>
#include <ntstrsafe.h>
#include <suppress.h>

#include "../../../shared/include/RealtimeProtectionProtocol.h"

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

FLT_POSTOP_CALLBACK_STATUS
AntivirusPostWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                   _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

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
AntivirusBuildRequest(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                      _In_ ANTIVIRUS_REALTIME_FILE_OPERATION Operation,
                      _Out_ ANTIVIRUS_REALTIME_SCAN_REQUEST* Request);

static VOID
AntivirusPopulateProcessImage(_Out_ ANTIVIRUS_REALTIME_SCAN_REQUEST* Request);

static ULONG
AntivirusGetParentProcessId(VOID);

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

static ULONG
AntivirusBuildRequestFlags(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                           _In_ ANTIVIRUS_REALTIME_FILE_OPERATION Operation,
                           _In_opt_ const ANTIVIRUS_REALTIME_SCAN_REQUEST* Request);

static ULONG
AntivirusBuildPathRiskFlags(_In_z_ const WCHAR* Path, _In_ ANTIVIRUS_REALTIME_FILE_OPERATION Operation);

static ULONG
AntivirusClassifySignerTrustLevel(_In_z_ const WCHAR* ProcessImagePath);

static BOOLEAN
AntivirusPathHasExtensionInsensitive(_In_z_ const WCHAR* Path, _In_z_ const WCHAR* Extension);

static BOOLEAN
AntivirusPathIsUserControlled(_In_z_ const WCHAR* Path);

const FLT_OPERATION_REGISTRATION gCallbacks[] = {
    {IRP_MJ_CREATE, 0, AntivirusPreCreate, NULL},
    {IRP_MJ_WRITE, 0, AntivirusPreWrite, AntivirusPostWrite},
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

FLT_POSTOP_CALLBACK_STATUS
AntivirusPostWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                   _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags) {
  UNREFERENCED_PARAMETER(CompletionContext);

  if (Data == NULL || Data->Iopb == NULL || !NT_SUCCESS(Data->IoStatus.Status)) {
    return FLT_POSTOP_FINISHED_PROCESSING;
  }

  if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) || FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
    return FLT_POSTOP_FINISHED_PROCESSING;
  }

  if (KeGetCurrentIrql() > APC_LEVEL) {
    return FLT_POSTOP_FINISHED_PROCESSING;
  }

  // A pre-write scan often sees the old file contents. Post-write lets the
  // broker inspect completed browser downloads and quarantine malicious bytes.
  (void)AntivirusInspectFileOperation(Data, FltObjects, ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE);
  return FLT_POSTOP_FINISHED_PROCESSING;
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

  status = AntivirusBuildRequest(Data, FltObjects, Operation, &request);
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
  request.parentProcessId = AntivirusGetParentProcessId();
  if (request.requestFlags == 0) {
    request.requestFlags = AntivirusBuildRequestFlags(Data, FltObjects, Operation, &request);
  }
  if (request.pathRiskFlags == 0) {
    request.pathRiskFlags = AntivirusBuildPathRiskFlags(request.path, Operation);
  }

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
AntivirusBuildRequest(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                      _In_ ANTIVIRUS_REALTIME_FILE_OPERATION Operation,
                      _Out_ ANTIVIRUS_REALTIME_SCAN_REQUEST* Request) {
  NTSTATUS status;
  PFLT_FILE_NAME_INFORMATION fileNameInformation = NULL;

  if (Data == NULL || Data->Iopb == NULL || Request == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  Request->desiredAccess = 0;
  Request->createDisposition = 0;
  Request->requestFlags = 0;
  Request->pathRiskFlags = 0;
  Request->signerTrustLevel = ANTIVIRUS_REALTIME_SIGNER_TRUST_UNKNOWN;

  if (Data->Iopb->MajorFunction == IRP_MJ_CREATE && Data->Iopb->Parameters.Create.SecurityContext != NULL) {
    Request->desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    Request->createDisposition = (Data->Iopb->Parameters.Create.Options >> 24);
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
  AntivirusPopulateProcessImage(Request);
  Request->signerTrustLevel = AntivirusClassifySignerTrustLevel(Request->processImage);
  Request->pathRiskFlags = AntivirusBuildPathRiskFlags(Request->path, Operation);
  Request->requestFlags = AntivirusBuildRequestFlags(Data, FltObjects, Operation, Request);

  FltReleaseFileNameInformation(fileNameInformation);
  return STATUS_SUCCESS;
}

static VOID
AntivirusPopulateProcessImage(_Out_ ANTIVIRUS_REALTIME_SCAN_REQUEST* Request) {
  NTSTATUS status;
  PUNICODE_STRING processImage = NULL;

  if (Request == NULL) {
    return;
  }

  Request->processImage[0] = L'\0';

  status = SeLocateProcessImageName(PsGetCurrentProcess(), &processImage);
  if (!NT_SUCCESS(status) || processImage == NULL || processImage->Buffer == NULL || processImage->Length == 0) {
    return;
  }

  RtlStringCchCopyNW(Request->processImage, ANTIVIRUS_REALTIME_IMAGE_CAPACITY, processImage->Buffer,
                     processImage->Length / sizeof(WCHAR));
  ExFreePool(processImage);
}

static ULONG
AntivirusGetParentProcessId(VOID) {
  typedef HANDLE (*PANTIVIRUS_GET_PARENT_PROCESS_ID)(_In_ PEPROCESS Process);

  UNICODE_STRING routineName;
  PANTIVIRUS_GET_PARENT_PROCESS_ID getParentProcessId = NULL;
  HANDLE parentProcessId = NULL;

  RtlInitUnicodeString(&routineName, L"PsGetProcessInheritedFromUniqueProcessId");
  getParentProcessId = (PANTIVIRUS_GET_PARENT_PROCESS_ID)(ULONG_PTR)MmGetSystemRoutineAddress(&routineName);
  if (getParentProcessId != NULL) {
    parentProcessId = getParentProcessId(PsGetCurrentProcess());
  }

  return HandleToULong(parentProcessId);
}

static BOOLEAN
AntivirusShouldScanCreate(_In_ PFLT_CALLBACK_DATA Data, _Out_ ANTIVIRUS_REALTIME_FILE_OPERATION* Operation) {
  ACCESS_MASK desiredAccess = 0;
  ULONG createDispositionValue = 0;
  BOOLEAN executeIntent;
  BOOLEAN writeIntent;
  BOOLEAN createDisposition;

  if (Data == NULL || Data->Iopb == NULL || Operation == NULL) {
    return FALSE;
  }

  if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
    desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
  }
  createDispositionValue = (Data->Iopb->Parameters.Create.Options >> 24);
  executeIntent = FlagOn(desiredAccess, FILE_EXECUTE | GENERIC_EXECUTE);
  writeIntent =
      FlagOn(desiredAccess,
             FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC |
                 WRITE_OWNER | GENERIC_WRITE);
  createDisposition = createDispositionValue == FILE_CREATE || createDispositionValue == FILE_SUPERSEDE ||
                      createDispositionValue == FILE_OVERWRITE || createDispositionValue == FILE_OVERWRITE_IF;

  if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
    return FALSE;
  }

  if (executeIntent) {
    *Operation = ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE;
    return TRUE;
  }

  if (createDisposition && writeIntent) {
    *Operation = ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE;
    return TRUE;
  }

  if (writeIntent) {
    *Operation = ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE;
    return TRUE;
  }

  if (createDisposition) {
    *Operation = ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE;
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
  return Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE ||
         Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_SECTION_MAP;
}

static BOOLEAN
AntivirusShouldFailClosedForContext(_Inout_ PFLT_CALLBACK_DATA Data, _In_ ANTIVIRUS_REALTIME_FILE_OPERATION Operation,
                                    _In_opt_ const ANTIVIRUS_REALTIME_SCAN_REQUEST* Request,
                                    _In_ PCFLT_RELATED_OBJECTS FltObjects) {
  const ULONG highRiskExtensionMask = ANTIVIRUS_REALTIME_PATH_RISK_EXECUTABLE_EXTENSION |
                                      ANTIVIRUS_REALTIME_PATH_RISK_SCRIPT_EXTENSION |
                                      ANTIVIRUS_REALTIME_PATH_RISK_CONTAINER_EXTENSION;
  BOOLEAN isCreateReparseOpen = FALSE;
  BOOLEAN isSensitiveSetInformation = FALSE;
  BOOLEAN isSectionSyncHighRisk = FALSE;
  BOOLEAN createHighRiskUserPath = FALSE;
  BOOLEAN renameHighRiskExtension = FALSE;

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

  if (Request != NULL) {
    createHighRiskUserPath =
        Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE &&
        FlagOn(Request->pathRiskFlags, ANTIVIRUS_REALTIME_PATH_RISK_USER_CONTROLLED) &&
        FlagOn(Request->pathRiskFlags, highRiskExtensionMask);
    renameHighRiskExtension =
        Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_RENAME &&
        FlagOn(Request->pathRiskFlags, highRiskExtensionMask);
  }

  if (AntivirusShouldFailClosed(Operation) || isSectionSyncHighRisk || createHighRiskUserPath ||
      renameHighRiskExtension) {
    return TRUE;
  }

  if (Request != NULL) {
    if (isCreateReparseOpen && FlagOn(Request->requestFlags, ANTIVIRUS_REALTIME_REQUEST_FLAG_REPARSE_PATH)) {
      return TRUE;
    }

    if (FlagOn(Request->requestFlags, ANTIVIRUS_REALTIME_REQUEST_FLAG_ADS_PATH) &&
        (Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE ||
         Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_SECTION_MAP ||
         Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_RENAME ||
         Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE)) {
      return TRUE;
    }

    if (isSensitiveSetInformation && renameHighRiskExtension) {
      return TRUE;
    }

    if (AntivirusVolumeIsRemoteOrRemovable(FltObjects) &&
        (Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE ||
         Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_SECTION_MAP || createHighRiskUserPath ||
         renameHighRiskExtension)) {
      return TRUE;
    }

    if (FlagOn(Request->pathRiskFlags, ANTIVIRUS_REALTIME_PATH_RISK_HIGH_RISK_PATH) &&
        (Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE ||
         Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_SECTION_MAP || createHighRiskUserPath ||
         renameHighRiskExtension)) {
      return TRUE;
    }

    if (AntivirusPathHasCloudSyncMarker(Request->path) &&
        (Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE ||
         Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_SECTION_MAP || createHighRiskUserPath ||
         renameHighRiskExtension)) {
      return TRUE;
    }
  }

  if (isCreateReparseOpen && (Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE ||
                              Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_SECTION_MAP)) {
    return TRUE;
  }

  return FALSE;
}

static ULONG
AntivirusBuildRequestFlags(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                           _In_ ANTIVIRUS_REALTIME_FILE_OPERATION Operation,
                           _In_opt_ const ANTIVIRUS_REALTIME_SCAN_REQUEST* Request) {
  ULONG flags = 0;

  if (Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE ||
      Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_SECTION_MAP) {
    flags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_EXECUTE_INTENT;
  }

  if (Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE ||
      Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_CREATE) {
    flags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_WRITE_INTENT;
  }

  if (Operation == ANTIVIRUS_REALTIME_FILE_OPERATION_RENAME) {
    flags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_RENAME_INTENT;
  }

  if (Data != NULL && Data->Iopb != NULL && Data->Iopb->MajorFunction == IRP_MJ_CREATE &&
      FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_REPARSE_POINT)) {
    flags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_REPARSE_PATH;
  }

  if (Data != NULL && Data->Iopb != NULL &&
      Data->Iopb->MajorFunction == IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION) {
    const ULONG pageProtection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
    const ULONG executeMask = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    const ULONG writeMask = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (FlagOn(pageProtection, executeMask)) {
      flags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_SECTION_MAP_EXECUTE;
    }
    if (FlagOn(pageProtection, writeMask)) {
      flags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_SECTION_MAP_WRITE;
    }
  }

  if (AntivirusVolumeIsRemoteOrRemovable(FltObjects)) {
    flags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_REMOTE_VOLUME;
    flags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_REMOVABLE_VOLUME;
  }

  if (Request != NULL) {
    if (AntivirusPathHasCloudSyncMarker(Request->path)) {
      flags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_CLOUD_SYNC_PATH;
    }
    if (AntivirusPathContainsAlternateDataStream(Request->path)) {
      flags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_ADS_PATH;
    }
    if (AntivirusPathHasTraversalSequence(Request->path)) {
      flags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_REPARSE_PATH;
    }
  }

  return flags;
}

static ULONG
AntivirusBuildPathRiskFlags(_In_z_ const WCHAR* Path, _In_ ANTIVIRUS_REALTIME_FILE_OPERATION Operation) {
  ULONG flags = 0;

  UNREFERENCED_PARAMETER(Operation);

  if (Path == NULL || Path[0] == L'\0') {
    return flags;
  }

  if (AntivirusIsHighRiskPath(Path)) {
    flags |= ANTIVIRUS_REALTIME_PATH_RISK_HIGH_RISK_PATH;
  }
  if (AntivirusPathIsUserControlled(Path)) {
    flags |= ANTIVIRUS_REALTIME_PATH_RISK_USER_CONTROLLED;
  }
  if (AntivirusPathHasExtensionInsensitive(Path, L".exe") ||
      AntivirusPathHasExtensionInsensitive(Path, L".dll") ||
      AntivirusPathHasExtensionInsensitive(Path, L".scr") ||
      AntivirusPathHasExtensionInsensitive(Path, L".com") ||
      AntivirusPathHasExtensionInsensitive(Path, L".msi")) {
    flags |= ANTIVIRUS_REALTIME_PATH_RISK_EXECUTABLE_EXTENSION;
  }
  if (AntivirusPathHasExtensionInsensitive(Path, L".ps1") ||
      AntivirusPathHasExtensionInsensitive(Path, L".psm1") ||
      AntivirusPathHasExtensionInsensitive(Path, L".cmd") ||
      AntivirusPathHasExtensionInsensitive(Path, L".bat") ||
      AntivirusPathHasExtensionInsensitive(Path, L".js") ||
      AntivirusPathHasExtensionInsensitive(Path, L".jse") ||
      AntivirusPathHasExtensionInsensitive(Path, L".vbs") ||
      AntivirusPathHasExtensionInsensitive(Path, L".vbe") ||
      AntivirusPathHasExtensionInsensitive(Path, L".hta")) {
    flags |= ANTIVIRUS_REALTIME_PATH_RISK_SCRIPT_EXTENSION;
  }
  if (AntivirusPathHasExtensionInsensitive(Path, L".zip") ||
      AntivirusPathHasExtensionInsensitive(Path, L".7z") ||
      AntivirusPathHasExtensionInsensitive(Path, L".rar") ||
      AntivirusPathHasExtensionInsensitive(Path, L".lnk") ||
      AntivirusPathHasExtensionInsensitive(Path, L".iso")) {
    flags |= ANTIVIRUS_REALTIME_PATH_RISK_CONTAINER_EXTENSION;
  }
  if (AntivirusPathHasTraversalSequence(Path)) {
    flags |= ANTIVIRUS_REALTIME_PATH_RISK_TRAVERSAL_SEQUENCE;
  }
  if (AntivirusPathContainsAlternateDataStream(Path)) {
    flags |= ANTIVIRUS_REALTIME_PATH_RISK_ADS_PATH;
  }

  return flags;
}

static ULONG
AntivirusClassifySignerTrustLevel(_In_z_ const WCHAR* ProcessImagePath) {
  if (ProcessImagePath == NULL || ProcessImagePath[0] == L'\0') {
    return ANTIVIRUS_REALTIME_SIGNER_TRUST_UNKNOWN;
  }

  if (AntivirusPathHasPrefixInsensitive(ProcessImagePath, L"\\SystemRoot\\") ||
      AntivirusPathContainsInsensitive(ProcessImagePath, L"\\Windows\\System32\\")) {
    return ANTIVIRUS_REALTIME_SIGNER_TRUST_SYSTEM;
  }

  if (AntivirusPathContainsInsensitive(ProcessImagePath, L"\\Program Files\\") ||
      AntivirusPathContainsInsensitive(ProcessImagePath, L"\\Program Files (x86)\\")) {
    return ANTIVIRUS_REALTIME_SIGNER_TRUST_PROGRAM_FILES;
  }

  if (AntivirusPathIsUserControlled(ProcessImagePath)) {
    return ANTIVIRUS_REALTIME_SIGNER_TRUST_USER_PATH;
  }

  return ANTIVIRUS_REALTIME_SIGNER_TRUST_UNKNOWN;
}

static BOOLEAN
AntivirusPathHasExtensionInsensitive(_In_z_ const WCHAR* Path, _In_z_ const WCHAR* Extension) {
  SIZE_T pathLength = 0;
  SIZE_T extensionLength = 0;
  SIZE_T index;

  if (Path == NULL || Extension == NULL || Extension[0] == L'\0') {
    return FALSE;
  }

  while (Path[pathLength] != L'\0') {
    ++pathLength;
  }
  while (Extension[extensionLength] != L'\0') {
    ++extensionLength;
  }

  if (pathLength < extensionLength) {
    return FALSE;
  }

  index = pathLength - extensionLength;
  while (index < pathLength) {
    if (RtlDowncaseUnicodeChar(Path[index]) != RtlDowncaseUnicodeChar(Extension[index - (pathLength - extensionLength)])) {
      return FALSE;
    }
    ++index;
  }

  return TRUE;
}

static BOOLEAN
AntivirusPathIsUserControlled(_In_z_ const WCHAR* Path) {
  if (Path == NULL || Path[0] == L'\0') {
    return FALSE;
  }

  return AntivirusPathContainsInsensitive(Path, L"\\Users\\") ||
         AntivirusPathContainsInsensitive(Path, L"\\ProgramData\\") ||
         AntivirusPathContainsInsensitive(Path, L"\\AppData\\") ||
         AntivirusPathContainsInsensitive(Path, L"\\Downloads\\") ||
         AntivirusPathContainsInsensitive(Path, L"\\Desktop\\") ||
         AntivirusPathContainsInsensitive(Path, L"\\Temp\\");
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
