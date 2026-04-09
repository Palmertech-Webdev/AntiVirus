cmake_minimum_required(VERSION 3.24)

project(AntiVirusAgentService LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

function(antivirus_apply_portable_runtime target_name)
  if(MINGW)
    target_link_options(${target_name} PRIVATE -static-libgcc -static-libstdc++)
    if(NOT "${target_name}" STREQUAL "antivirus-sqlite3")
      target_link_libraries(${target_name} PRIVATE -Wl,-Bstatic winpthread -Wl,-Bdynamic)
    endif()
  endif()
endfunction()

add_library(antivirus-sqlite3 STATIC
  ../../../third_party/sqlite/sqlite-amalgamation-3510300/sqlite3.c
)

target_include_directories(antivirus-sqlite3 PUBLIC
  ../../../third_party/sqlite/sqlite-amalgamation-3510300
)
target_compile_definitions(antivirus-sqlite3 PRIVATE
  SQLITE_DQS=0
  SQLITE_THREADSAFE=1
  SQLITE_OMIT_LOAD_EXTENSION
)

add_library(antivirus-agent-core STATIC
  ../sensor/etw/src/ProcessEtwSensor.cpp
  ../sensor/wfp/src/NetworkIsolationManager.cpp
  src/AmsiEvidenceRecorder.cpp
  src/AmsiScanEngine.cpp
  src/AgentConfig.cpp
  src/AgentService.cpp
  src/CommandJournalStore.cpp
  src/ControlPlaneClient.cpp
  src/CryptoUtils.cpp
  src/EndpointClient.cpp
  src/EvidenceRecorder.cpp
  src/FileDeltaTracker.cpp
  src/FileInventory.cpp
  src/FileSnapshotCollector.cpp
  src/HardeningManager.cpp
  src/LocalScanRunner.cpp
  src/LocalStateStore.cpp
  src/ProcessDeltaTracker.cpp
  src/ProcessInventory.cpp
  src/ProcessSnapshotCollector.cpp
  src/QuarantineStore.cpp
  src/RealtimeProtectionBroker.cpp
  src/RemediationEngine.cpp
  src/RuntimeDatabase.cpp
  src/ScanEngine.cpp
  src/SelfTestRunner.cpp
  src/StringUtils.cpp
  src/TelemetryQueueStore.cpp
  src/UpdaterService.cpp
  src/WscCoexistenceManager.cpp
)

target_include_directories(antivirus-agent-core PUBLIC include ../shared/include ../sensor/etw/include ../sensor/wfp/include)
target_link_libraries(antivirus-agent-core PUBLIC antivirus-sqlite3 winhttp ole32 oleaut32 bcrypt advapi32 tdh crypt32 wintrust fwpuclnt iphlpapi shell32 ws2_32)
antivirus_apply_portable_runtime(antivirus-agent-core)

add_library(antivirus-amsi-provider-core STATIC
  ../provider/amsi/src/AntiVirusAmsiProvider.cpp
)

target_include_directories(antivirus-amsi-provider-core PRIVATE
  include
  ../provider/amsi/include
)
target_link_libraries(antivirus-amsi-provider-core PRIVATE antivirus-agent-core ole32 advapi32)
antivirus_apply_portable_runtime(antivirus-amsi-provider-core)

add_library(antivirus-amsi-provider SHARED
  ../provider/amsi/src/AntiVirusAmsiProviderDll.cpp
)

target_include_directories(antivirus-amsi-provider PRIVATE
  include
  ../provider/amsi/include
)
target_link_libraries(antivirus-amsi-provider PRIVATE antivirus-amsi-provider-core antivirus-agent-core ole32 advapi32)
set_target_properties(antivirus-amsi-provider PROPERTIES OUTPUT_NAME "antivirus-amsi-provider" PREFIX "")
antivirus_apply_portable_runtime(antivirus-amsi-provider)

add_executable(antivirus-agent-service
  src/ServiceMain.cpp
)

target_link_libraries(antivirus-agent-service PRIVATE antivirus-agent-core advapi32)
target_link_options(antivirus-agent-service PRIVATE -municode)
antivirus_apply_portable_runtime(antivirus-agent-service)

add_executable(antivirus-endpoint-client WIN32
  ../tools/endpointui/src/endpointui.rc
  ../tools/endpointui/src/EndpointClientMain.cpp
)

target_include_directories(antivirus-endpoint-client PRIVATE include)
target_link_libraries(antivirus-endpoint-client PRIVATE antivirus-agent-core comctl32 ole32 uxtheme)
target_compile_definitions(antivirus-endpoint-client PRIVATE UNICODE _UNICODE)
target_link_options(antivirus-endpoint-client PRIVATE -municode)
antivirus_apply_portable_runtime(antivirus-endpoint-client)

add_executable(antivirus-scannercli
  ../tools/scannercli/src/ScannerCliMain.cpp
)

target_include_directories(antivirus-scannercli PRIVATE include)
target_link_libraries(antivirus-scannercli PRIVATE antivirus-agent-core)
target_link_options(antivirus-scannercli PRIVATE -municode)
antivirus_apply_portable_runtime(antivirus-scannercli)

add_executable(antivirus-amsitestcli
  ../tools/amsitestcli/src/AmsiTestCliMain.cpp
)

target_include_directories(antivirus-amsitestcli PRIVATE
  include
  ../provider/amsi/include
)
target_link_libraries(antivirus-amsitestcli PRIVATE antivirus-amsi-provider-core antivirus-agent-core ole32)
target_link_options(antivirus-amsitestcli PRIVATE -municode)
antivirus_apply_portable_runtime(antivirus-amsitestcli)

add_executable(antivirus-etwtestcli
  ../tools/etwtestcli/src/EtwTestCliMain.cpp
)

target_include_directories(antivirus-etwtestcli PRIVATE
  include
  ../sensor/etw/include
)
target_link_libraries(antivirus-etwtestcli PRIVATE antivirus-agent-core)
target_link_options(antivirus-etwtestcli PRIVATE -municode)
antivirus_apply_portable_runtime(antivirus-etwtestcli)

add_executable(antivirus-wfptestcli
  ../tools/wfptestcli/src/WfpTestCliMain.cpp
)

target_include_directories(antivirus-wfptestcli PRIVATE
  include
  ../sensor/wfp/include
)
target_link_libraries(antivirus-wfptestcli PRIVATE antivirus-agent-core)
target_link_options(antivirus-wfptestcli PRIVATE -municode)
antivirus_apply_portable_runtime(antivirus-wfptestcli)

set(INSTALLER_NATIVE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../installer/native)
set(INSTALLER_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/installer-generated)
file(MAKE_DIRECTORY ${INSTALLER_GENERATED_DIR})

get_filename_component(ANTIVIRUS_CXX_COMPILER_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
find_file(SETUP_WINPTHREAD_DLL
  NAMES libwinpthread-1.dll
  PATHS
    "${ANTIVIRUS_CXX_COMPILER_DIR}"
    "${ANTIVIRUS_CXX_COMPILER_DIR}/../bin"
  NO_DEFAULT_PATH
)

if(MINGW AND NOT SETUP_WINPTHREAD_DLL)
  message(FATAL_ERROR "Could not locate libwinpthread-1.dll next to the configured MinGW compiler.")
endif()

file(TO_CMAKE_PATH "${INSTALLER_NATIVE_DIR}/include/SetupResourceIds.h" SETUP_RESOURCE_HEADER)
file(TO_CMAKE_PATH "${CMAKE_CURRENT_BINARY_DIR}/antivirus-agent-service.exe" SETUP_SERVICE_EXE)
file(TO_CMAKE_PATH "${CMAKE_CURRENT_BINARY_DIR}/antivirus-endpoint-client.exe" SETUP_ENDPOINT_CLIENT_EXE)
file(TO_CMAKE_PATH "${CMAKE_CURRENT_BINARY_DIR}/antivirus-amsi-provider.dll" SETUP_AMSI_PROVIDER_DLL)
file(TO_CMAKE_PATH "${CMAKE_CURRENT_BINARY_DIR}/antivirus-scannercli.exe" SETUP_SCANNERCLI_EXE)
file(TO_CMAKE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../signatures/default-signatures.tsv" SETUP_SIGNATURES_FILE)
file(TO_CMAKE_PATH "${SETUP_WINPTHREAD_DLL}" SETUP_WINPTHREAD_DLL_CMAKE)

file(GENERATE OUTPUT ${INSTALLER_GENERATED_DIR}/SetupPayload.rc CONTENT
"#include \"${SETUP_RESOURCE_HEADER}\"\n\
IDR_PAYLOAD_SERVICE RCDATA \"${SETUP_SERVICE_EXE}\"\n\
IDR_PAYLOAD_ENDPOINT_CLIENT RCDATA \"${SETUP_ENDPOINT_CLIENT_EXE}\"\n\
IDR_PAYLOAD_AMSI_PROVIDER RCDATA \"${SETUP_AMSI_PROVIDER_DLL}\"\n\
IDR_PAYLOAD_SCANNERCLI RCDATA \"${SETUP_SCANNERCLI_EXE}\"\n\
IDR_PAYLOAD_SIGNATURES RCDATA \"${SETUP_SIGNATURES_FILE}\"\n\
IDR_PAYLOAD_WINPTHREAD RCDATA \"${SETUP_WINPTHREAD_DLL_CMAKE}\"\n")

add_executable(antivirus-setup WIN32
  ${INSTALLER_NATIVE_DIR}/src/setup.rc
  ${INSTALLER_NATIVE_DIR}/src/SetupMain.cpp
  ${INSTALLER_GENERATED_DIR}/SetupPayload.rc
)

add_dependencies(antivirus-setup
  antivirus-agent-service
  antivirus-endpoint-client
  antivirus-amsi-provider
  antivirus-scannercli
)

target_include_directories(antivirus-setup PRIVATE
  ${INSTALLER_NATIVE_DIR}/include
)
target_link_libraries(antivirus-setup PRIVATE comctl32 ole32 shell32 advapi32)
if(MINGW)
  target_link_libraries(antivirus-setup PRIVATE -Wl,-Bstatic stdc++ -Wl,-Bdynamic)
endif()
target_compile_definitions(antivirus-setup PRIVATE UNICODE _UNICODE)
target_link_options(antivirus-setup PRIVATE -municode -static)
antivirus_apply_portable_runtime(antivirus-setup)
