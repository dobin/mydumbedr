#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>

// Needs to be set on the project properties as well
#pragma comment(lib, "FltMgr.lib")

// Maximum size of the buffers used to communicate via Named Pipes
#define MESSAGE_SIZE 2048

UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\MyDumbEDR"); // Internal driver device name, cannot be used userland
UNICODE_STRING SYM_LINK = RTL_CONSTANT_STRING(L"\\??\\MyDumbEDR");        // Symlink used to reach the driver, can be used userland

HANDLE hPipe = NULL;                     // Handle that we will use to communicate with the named pipe


int log_event(wchar_t* message) {
    if (hPipe == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            cannot log as pipe is closed");
        return 1;
    }
    NTSTATUS status;
    IO_STATUS_BLOCK io_stat_block;    // IO status block used to specify the state of a I/O request

    // Now we'll send the data path the userland agent
    status = ZwWriteFile(
        hPipe,            // Handle to the named pipe
        NULL,             // Optionally a handle on an even object
        NULL,             // Always NULL
        NULL,             // Always NULL
        &io_stat_block,   // Structure containing the I/O queue
        message, // Buffer in which is stored the binary path
        MESSAGE_SIZE,     // Maximum size of the buffer
        NULL,             // Bytes offset (optional)
        NULL              // Always NULL
    );
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWriteFile: Error ZwWriteFile: 0x%0.8x\n", status);
        hPipe = NULL;
        return 0;
    }

    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            log_event(): %zW", message);
    status = ZwWaitForSingleObject(
        hPipe, // Handle the named pipe
        FALSE, // Whether or not we want the wait to be alertable
        NULL   // An optional timeout
    );
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWriteFile: Error ZwWaitForSingleObject: 0x%0.8x\n", status);
        hPipe = NULL;
        return 0;
    }

    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWaitForSingleObject: 0x%0.8x\n", status);

    return 1;
}


int open_pipe() {
    UNICODE_STRING pipeName; // String containing the name of the named
    // Initialize a UNICODE_STRING structure containing the name of the named pipe
    RtlInitUnicodeString(
        &pipeName,                      // Variable in which we will store the UNICODE_STRING structure
        L"\\??\\pipe\\dumbedr-analyzer" // Wide string containing the name of the named pipe
    );

    OBJECT_ATTRIBUTES fattrs = { 0 }; // Objects Attributes used to store information when calling ZwCreateFile
    IO_STATUS_BLOCK io_stat_block;    // IO status block used to specify the state of a I/O request

    // Initialize an OBJECT_ATTRIBUTE structure pointing to our named pipe
    InitializeObjectAttributes(&fattrs, &pipeName, OBJ_CASE_INSENSITIVE | 0x0200, 0, NULL);

    // Reads from the named pipe
    NTSTATUS status = ZwCreateFile(
        &hPipe,                                         // Handle to the named pipe
        FILE_WRITE_DATA | FILE_READ_DATA | SYNCHRONIZE, // File attribute (we need both read and write)
        &fattrs,                                        // Structure containing the file attribute
        &io_stat_block,                                 // Structure containing the I/O queue
        NULL,                                           // Allocation size, not needed in that case
        0,                                              // Specific files attributes (not needed as well
        FILE_SHARE_READ | FILE_SHARE_WRITE,             // File sharing access
        FILE_OPEN,                                      // Specify the action we want to do on the file 
        FILE_NON_DIRECTORY_FILE,                        // Specifying that the file is not a directory
        NULL,                                           // Always NULL
        0                                               // Always zero
    );

    // If we can obtain a handle on the named pipe then 
    if (NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            PIPE: OK.\n");
        return 1;
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            PIPE: ERROR, Daemon not running?.\n");
        hPipe = NULL;
        return 0;
    }
}


int inject_dll(int pid) {
    UNICODE_STRING pipeName; // String containing the name of the named
    // Initialize a UNICODE_STRING structure containing the name of the named pipe
    RtlInitUnicodeString(
        &pipeName,                      // Variable in which we will store the UNICODE_STRING structure
        L"\\??\\pipe\\dumbedr-injector" // Wide string containing the name of the named pipe
    );

    HANDLE hPipe2;                     // Handle that we will use to communicate with the named pipe
    OBJECT_ATTRIBUTES fattrs = { 0 }; // Objects Attributes used to store information when calling ZwCreateFile
    IO_STATUS_BLOCK io_stat_block;    // IO status block used to specify the state of a I/O request

    // Initialize an OBJECT_ATTRIBUTE structure pointing to our named pipe
    InitializeObjectAttributes(&fattrs, &pipeName, OBJ_CASE_INSENSITIVE | 0x0200, 0, NULL);

    NTSTATUS status = ZwCreateFile(
        &hPipe2,                                         // Handle to the named pipe
        FILE_WRITE_DATA | FILE_READ_DATA | SYNCHRONIZE, // File attribute (we need both read and write)
        &fattrs,                                        // Structure containing the file attribute
        &io_stat_block,                                 // Structure containing the I/O queue
        NULL,                                           // Allocation size, not needed in that case
        0,                                              // Specific files attributes (not needed as well
        FILE_SHARE_READ | FILE_SHARE_WRITE,             // File sharing access
        FILE_OPEN,                                      // Specify the action we want to do on the file 
        FILE_NON_DIRECTORY_FILE,                        // Specifying that the file is not a directory
        NULL,                                           // Always NULL
        0                                               // Always zero
    );

    // If we can obtain a handle on the named pipe then 
    if (NT_SUCCESS(status)) {

        wchar_t pid_to_inject[MESSAGE_SIZE] = { 0 };
        swprintf_s(pid_to_inject, MESSAGE_SIZE, L"%d\0", pid);
        // Now we'll send the binary path to the userland agent
        status = ZwWriteFile(
            hPipe2,          // Handle to the named pipe
            NULL,           // Optionally a handle on an even object
            NULL,           // Always NULL
            NULL,           // Always NULL
            &io_stat_block, // Structure containing the I/O queue
            pid_to_inject,  // Buffer in which is stored the binary path
            MESSAGE_SIZE,   // Maximum size of the buffer
            NULL,           // Bytes offset (optional)
            NULL            // Always NULL
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWriteFile: 0x%0.8x\n", status);

        /*
        This function is needed when you are running read/write files operation so that the kernel driver
        makes sure that the reading/writing phase is done and you can keep running the code
        */

        status = ZwWaitForSingleObject(
            hPipe2, // Handle the named pipe
            FALSE, // Whether or not we want the wait to be alertable
            NULL   // An optional timeout
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWaitForSingleObject: 0x%0.8x\n", status);
        
        wchar_t response[MESSAGE_SIZE] = { 0 };
        // Reading the response from the named pipe (ie: if the binary is malicious or not based on static analysis)
        status = ZwReadFile(
            hPipe2,          // Handle to the named pipe
            NULL,           // Optionally a handle on an even object
            NULL,           // Always NULL
            NULL,           // Always NULL
            &io_stat_block, // Structure containing the I/O queue
            &response,      // Buffer in which to store the answer
            MESSAGE_SIZE,   // Maximum size of the buffer
            NULL,           // Bytes offset (optional)
            NULL            // Always NULL
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwReadFile: 0x%0.8x\n", status);

        // Waiting again for the operation to be completed
        status = ZwWaitForSingleObject(
            hPipe2,
            FALSE,
            NULL
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWaitForSingleObject: 0x%0.8x\n", status);
        
        // Used to close a connection to the named pipe
        ZwClose(
            hPipe2 // Handle to the named pipe
        );
        
        if (wcscmp(response, L"OK\0") == 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            RemoteInjector: OK\n", response);
            return 0;
        }
        else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            RemoteInjector: KO\n", response);
            return 1;
        }
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            RemoteInjector unreachable. Allowing.\n");
        return 0;
    }
}

#define MESSAGE_SIZE 2048


void CreateProcessNotifyRoutine(PEPROCESS parent_process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo) {
    UNREFERENCED_PARAMETER(parent_process);

    PEPROCESS process = NULL;
    PUNICODE_STRING processName = NULL;

    PsLookupProcessByProcessId(pid, &process);
    SeLocateProcessImageName(process, &processName);

    wchar_t line[MESSAGE_SIZE] = { 0 };

    // Never forget this if check because if you don't, you'll end up crashing your Windows system ;P
    if (createInfo != NULL) {
        createInfo->CreationStatus = STATUS_SUCCESS;

        // Retrieve parent process ID and process name
        PsLookupProcessByProcessId(createInfo->ParentProcessId, &parent_process);
        PUNICODE_STRING parent_processName = NULL;
        SeLocateProcessImageName(parent_process, &parent_processName);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Process %wZ created\n", processName);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            PID: %d\n", pid);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            Created by: %wZ\n", parent_processName);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ImageBase: %ws\n", createInfo->ImageFileName->Buffer);

        POBJECT_NAME_INFORMATION objFileDosDeviceName;
        IoQueryFileDosDeviceName(createInfo->FileObject, &objFileDosDeviceName);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            DOS path: %ws\n", objFileDosDeviceName->Name.Buffer);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            CommandLine: %ws\n", createInfo->CommandLine->Buffer);

        swprintf(line, L"process:%llu;%wZ;%llu;%wZ",
            (unsigned __int64) pid, processName,
            (unsigned __int64) createInfo->ParentProcessId, parent_processName);
        log_event(line);
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Process %wZ killed\n", processName);
    }
}


void CreateThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
    wchar_t line[MESSAGE_SIZE] = { 0 };
    swprintf(line, L"thread:%llu;%llu;%d",
        (unsigned __int64)ProcessId, 
        (unsigned __int64)ThreadId,
        Create);
    log_event(line);

    if ( (uintptr_t) ProcessId == 700) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Thread %d created\n", ThreadId);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            PID: %d  %d\n", ProcessId, Create);
    }
}

void LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
    wchar_t line[MESSAGE_SIZE] = { 0 };
    swprintf(line, L"image:%llu;%wZ",
        (unsigned __int64)ProcessId,
        FullImageName);
    log_event(line);

    if ((uintptr_t)ProcessId == 700) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Image %wZ created\n", FullImageName);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            PID: %d\n", ProcessId);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            Image Info: %d\n", ImageInfo);
    }
}


/** For ObRegisterCallbacks **/
typedef struct _TD_CALLBACK_PARAMETERS {
    ACCESS_MASK AccessBitsToClear;
    ACCESS_MASK AccessBitsToSet;
}
TD_CALLBACK_PARAMETERS, * PTD_CALLBACK_PARAMETERS;
typedef struct _TD_CALLBACK_REGISTRATION {
    // Handle returned by ObRegisterCallbacks.
    PVOID RegistrationHandle;

    // If not NULL, filter only requests to open/duplicate handles to this
    // process (or one of its threads).
    PVOID TargetProcess;
    HANDLE TargetProcessId;

    // Currently each TD_CALLBACK_REGISTRATION has at most one process and one
    // thread callback. That is, we can't register more than one callback for
    // the same object type with a single ObRegisterCallbacks call.
    TD_CALLBACK_PARAMETERS ProcessParams;
    TD_CALLBACK_PARAMETERS ThreadParams;

    // Index in the global TdCallbacks array.
    ULONG RegistrationId;        
}
TD_CALLBACK_REGISTRATION, *PTD_CALLBACK_REGISTRATION;
OB_PREOP_CALLBACK_STATUS
CBTdPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo
)
{
    // https://github.com/microsoft/Windows-driver-samples/blob/main/general/obcallback/driver/callback.c
    if (0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] OperationCallBack %p %p\n",
            RegistrationContext, PreInfo);
    }

    return OB_PREOP_SUCCESS;
}
PVOID pCBRegistrationHandle = NULL;


void UnloadMyDumbEDR(_In_ PDRIVER_OBJECT DriverObject) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[MyDumbEDR] Unloading routine called\n");

    // Handle to the named pipe
    ZwClose(hPipe);
    
    // Unset the callback
    PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
    PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
    PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    ObUnRegisterCallbacks(pCBRegistrationHandle);

    // Delete the driver device 
    IoDeleteDevice(DriverObject->DeviceObject);
    // Delete the symbolic link
    IoDeleteSymbolicLink(&SYM_LINK);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    // Prevent compiler error such as unreferenced parameter (error 4)
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Initializing the EDR's driver\n");

    // Variable that will store the output of WinAPI functions
    NTSTATUS status;

    // Setting the unload routine to execute
    DriverObject->DriverUnload = UnloadMyDumbEDR;

    // Initializing a device object and creating it
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING deviceName = DEVICE_NAME;
    UNICODE_STRING symlinkName = SYM_LINK;
    status = IoCreateDevice(
        DriverObject,		   // our driver object,
        0,					   // no need for extra bytes,
        &deviceName,           // the device name,
        FILE_DEVICE_UNKNOWN,   // device type,
        0,					   // characteristics flags,
        FALSE,				   // not exclusive,
        &DeviceObject		   // the resulting pointer
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Device creation failed\n");
        return status;
    }

    // Creating the symlink that we will use to contact our driver
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Symlink creation failed\n");
        IoDeleteDevice(DeviceObject);
        return status;
    }

    open_pipe();

    NTSTATUS ret;
    // Process
    ret = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, FALSE);
    if (ret == STATUS_SUCCESS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] CreateProcessNotifyRoutine launched successfully\n");
    }
    else if (ret == STATUS_INVALID_PARAMETER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] CreateProcessNotifyRoutine Invalid parameter\n");
    }
    else if (ret == STATUS_ACCESS_DENIED) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] CreateProcessNotifyRoutine Access denied\n");
    }

    // Thread
    ret = PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
    if (ret == STATUS_SUCCESS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] CreateThreadNotifyRoutine launched successfully\n");
    }
    else if (ret == STATUS_INVALID_PARAMETER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] CreateThreadNotifyRoutine Invalid parameter\n");
    }
    else if (ret == STATUS_ACCESS_DENIED) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] CreateThreadNotifyRoutine Access denied\n");
    }

    // Image
    ret = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    if (ret == STATUS_SUCCESS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] LoadImageNotifyRoutine launched successfully\n");
    }
    else if (ret == STATUS_INVALID_PARAMETER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] LoadImageNotifyRoutine Invalid parameter\n");
    }
    else if (ret == STATUS_ACCESS_DENIED) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] LoadImageNotifyRoutine Access denied\n");
    }

    // Open
    // https://github.com/microsoft/Windows-driver-samples/blob/main/general/obcallback/driver/callback.c
    OB_CALLBACK_REGISTRATION  CBObRegistration = { 0 };
    UNICODE_STRING CBAltitude = { 0 };
    RtlInitUnicodeString(&CBAltitude, L"1000");
    TD_CALLBACK_REGISTRATION CBCallbackRegistration = { 0 };

    OB_OPERATION_REGISTRATION CBOperationRegistrations[2] = { { 0 }, { 0 } };
    CBOperationRegistrations[0].ObjectType = PsProcessType;
    CBOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
    CBOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
    CBOperationRegistrations[0].PreOperation = CBTdPreOperationCallback;
    //CBOperationRegistrations[0].PostOperation = CBTdPostOperationCallback;

    CBOperationRegistrations[1].ObjectType = PsThreadType;
    CBOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_CREATE;
    CBOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
    CBOperationRegistrations[1].PreOperation = CBTdPreOperationCallback;
    //CBOperationRegistrations[1].PostOperation = CBTdPostOperationCallback;

    CBObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    CBObRegistration.OperationRegistrationCount = 2;
    CBObRegistration.Altitude = CBAltitude;
    CBObRegistration.RegistrationContext = &CBCallbackRegistration;
    CBObRegistration.OperationRegistration = CBOperationRegistrations;
    ret = ObRegisterCallbacks(&CBObRegistration, &pCBRegistrationHandle);
    if (ret == STATUS_SUCCESS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] ObRegister launched successfully\n");
    }
    else if (ret == STATUS_INVALID_PARAMETER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] ObRegister Invalid parameter\n");
    }
    else if (ret == STATUS_ACCESS_DENIED) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] ObRegister Access denied\n");
    }


    return 0;
}