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

const FLT_OPERATION_REGISTRATION gCallbacks[] = {
    {IRP_MJ_CREATE, 0, AntivirusPreCreate, NULL},
    {IRP_MJ_WRITE, 0, AntivirusPreWrite, NULL},
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

  UNREFERENCED_PARAMETER(FltObjects);

  if (!AntivirusHasConnectedBroker()) {
    return STATUS_SUCCESS;
  }

  RtlZeroMemory(&request, sizeof(request));
  RtlZeroMemory(&reply, sizeof(reply));

  status = AntivirusBuildRequest(Data, Operation, &request);
  if (!NT_SUCCESS(status)) {
    return STATUS_SUCCESS;
  }

  ExAcquireFastMutex(&gClientPortLock);
  clientPort = gClientPort;
  ExReleaseFastMutex(&gClientPortLock);

  if (clientPort == NULL) {
    return STATUS_SUCCESS;
  }

  request.protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
  request.requestSize = sizeof(request);
  request.requestId = (uint64_t)(ULONG_PTR)Data;
  request.operation = Operation;
  request.processId = HandleToULong(PsGetCurrentProcessId());
  request.threadId = HandleToULong(PsGetCurrentThreadId());

  timeout.QuadPart = -(10 * 1000 * 1000);
  replyLength = sizeof(reply);

  status = FltSendMessage(gFilterHandle, &clientPort, &request, sizeof(request), &reply, &replyLength, &timeout);
  if (!NT_SUCCESS(status)) {
    return STATUS_SUCCESS;
  }

  if (reply.action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK) {
    return STATUS_ACCESS_DENIED;
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

  status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &fileNameInformation);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = FltParseFileNameInformation(fileNameInformation);
  if (!NT_SUCCESS(status)) {
    FltReleaseFileNameInformation(fileNameInformation);
    return status;
  }

  RtlStringCchCopyNW(Request->path, ANTIVIRUS_REALTIME_PATH_CAPACITY, fileNameInformation->Name.Buffer,
                     fileNameInformation->Name.Length / sizeof(WCHAR));

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
  const BOOLEAN executeIntent =
      FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess, FILE_EXECUTE);
  const BOOLEAN createDisposition =
      (Data->Iopb->Parameters.Create.Options >> 24) == FILE_CREATE ||
      (Data->Iopb->Parameters.Create.Options >> 24) == FILE_SUPERSEDE ||
      (Data->Iopb->Parameters.Create.Options >> 24) == FILE_OVERWRITE ||
      (Data->Iopb->Parameters.Create.Options >> 24) == FILE_OVERWRITE_IF;

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
