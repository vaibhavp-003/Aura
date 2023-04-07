#include "SDActMon.h"
#include <wdmsec.h>

#define DbgPrint

#define FSCTL_REQUEST_OPLOCK	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 144, METHOD_BUFFERED, FILE_ANY_ACCESS)

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, SDActMonInstanceSetup)
#pragma alloc_text(PAGE, ActMonPreCreate)
#pragma alloc_text(PAGE, ActMonPostCreate)
#pragma alloc_text(PAGE, ActMonPreCleanup)
#pragma alloc_text(PAGE, ActMonPostCleanup)
#pragma alloc_text(PAGE, ActMonPreWrite)
#pragma alloc_text(PAGE, ActMonPreSetInfo)
#pragma alloc_text(PAGE, ActMonPortConnect)
#pragma alloc_text(PAGE, ActMonPortDisconnect)
#pragma alloc_text(PAGE, ContextCleanup)
#pragma alloc_text(PAGE, SendEntryToUI)
#pragma alloc_text(PAGE, SDActMonInstanceTeardownStart)
#pragma alloc_text(PAGE, SDActMonInstanceTeardownComplete)
#pragma alloc_text(PAGE, ActMonUnload)
#pragma alloc_text(PAGE, SDActMonQueryTeardown)
#pragma alloc_text(PAGE, GetProcessNameEx)
#pragma alloc_text(PAGE, DriverDeviceControlHandler)
#endif

BOOLEAN		gbIsProtectionOn = TRUE;

SDACTMON_DATA SDActMonData = { 0 };


const UNICODE_STRING OurPathFiles[] =
{
	RTL_CONSTANT_STRING(L"\\ULTRAAV\\"),
	{0, 0, NULL}
};

const UNICODE_STRING OurProcessesFiles[] =
{
	RTL_CONSTANT_STRING(L"ULTRAAV\\*.EXE"),
	RTL_CONSTANT_STRING(L"ULTRAAV\\AUWATCHDOGSERVICE.EXE"),
	RTL_CONSTANT_STRING(L"ULTRAAV\\AUACTMON.EXE"),
	RTL_CONSTANT_STRING(L"ULTRAAV\\AUTRAY.EXE"),
	RTL_CONSTANT_STRING(L"ULTRAAV\\AUSCANNER.EXE"),
	RTL_CONSTANT_STRING(L"ULTRAAV\\AULIVEUPDATE.EXE"),
	RTL_CONSTANT_STRING(L"ULTRAAV\\AUSRVOPT.EXE"),
	RTL_CONSTANT_STRING(L"ULTRAAV\\AUMAINUI.EXE"),
	RTL_CONSTANT_STRING(L"ULTRAAV\\AUUSB.EXE"),
	RTL_CONSTANT_STRING(L"ULTRAAV\\AUDBSERVER.EXE"),
	RTL_CONSTANT_STRING(L"ULTRAAV\\AUMAILPROXY.EXE"),
	RTL_CONSTANT_STRING(L"ULTRAAV\\AUFIREWALLSRV.EXE"),
	RTL_CONSTANT_STRING(L"ULTRAAV\\AUWSRMSG.EXE"),
	RTL_CONSTANT_STRING(L"ULTRAAV\\AUNOTIFICATIONS.EXE"),
	RTL_CONSTANT_STRING(L"ULTRAAV\\AUUNINSTALLER.EXE"),

	RTL_CONSTANT_STRING(L"\\AUDRIVERMGR.EXE"),
	RTL_CONSTANT_STRING(L"\\NFREGDRV.EXE"),
	RTL_CONSTANT_STRING(L"\\ULTRAAV.EXE"),
	RTL_CONSTANT_STRING(L"\\ULTRAAV.TMP"),
	RTL_CONSTANT_STRING(L"\\ULTRAAVX64.EXE"),
	RTL_CONSTANT_STRING(L"\\ULTRAAVX64.TMP"),

	RTL_CONSTANT_STRING(L"\\ULPROX64.EXE"),
	RTL_CONSTANT_STRING(L"\\ULPROX64.TMP"),

	RTL_CONSTANT_STRING(L"\\ULPRO.EXE"),
	RTL_CONSTANT_STRING(L"\\ULPRO.TMP"),

	RTL_CONSTANT_STRING(L"\\ULVIR.EXE"),
	RTL_CONSTANT_STRING(L"\\ULVIR.TMP"),

	RTL_CONSTANT_STRING(L"\\ULVIRX64.EXE"),
	RTL_CONSTANT_STRING(L"\\ULVIRX64.TMP"),

	RTL_CONSTANT_STRING(L"\\AUFDB.EXE"),
	RTL_CONSTANT_STRING(L"\\AUFDB.TMP"),

	RTL_CONSTANT_STRING(L"\\UPD_*.EXE"),
	RTL_CONSTANT_STRING(L"\\UPD_*.TMP"),

	RTL_CONSTANT_STRING(L"\\AUFWS.EXE"),
	RTL_CONSTANT_STRING(L"\\AUFWS.TMP"),

	RTL_CONSTANT_STRING(L"\\AUFWSX64.EXE"),
	RTL_CONSTANT_STRING(L"\\AUFWSX64.TMP"),

	RTL_CONSTANT_STRING(L"\\AUUNINSTALLER.EXE"),
	RTL_CONSTANT_STRING(L"\\ULTRAAVDRV.EXE"),
	RTL_CONSTANT_STRING(L"\\ULTRAAVDRV.TMP"),
	RTL_CONSTANT_STRING(L"\\ULTRAAVDRVX64.EXE"),
	RTL_CONSTANT_STRING(L"\\ULTRAAVDRVX64.TMP"),
	/*************************************************************************************************/
	{0, 0, NULL}
	
};

const FLT_OPERATION_REGISTRATION Callbacks[] =
{	
	/*
	{IRP_MJ_CREATE,0,ActMonPreCreate,ActMonPostCreate},
	{IRP_MJ_CLEANUP, 0, ActMonPreCleanup, ActMonPostCleanup},
	{IRP_MJ_WRITE, 0, ActMonPreWrite, NULL},
	{IRP_MJ_OPERATION_END}
	*/
	{IRP_MJ_CREATE,0,ActMonPreCreate,ActMonPostCreate},
	{IRP_MJ_CLEANUP, 0, ActMonPreCleanup, ActMonPostCleanup},
	{IRP_MJ_WRITE, 0, ActMonPreWrite, NULL},
	{IRP_MJ_SET_INFORMATION, 0, ActMonPreSetInfo, NULL},
	{IRP_MJ_OPERATION_END}
	
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] =
{
	{ FLT_STREAMHANDLE_CONTEXT, 0, NULL, sizeof(SDACTMON_STREAM_HANDLE_CONTEXT), MAXSYSMON_POOL_POOL_TAG },
	{ FLT_INSTANCE_CONTEXT, 0, ContextCleanup, sizeof(INSTANCE_CONTEXT), MAXSYSMON_POOL_POOL_TAG },
	{ FLT_CONTEXT_END }
};

const FLT_REGISTRATION FilterRegistration =
{
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	0,
	ContextRegistration,
	Callbacks,
	ActMonUnload,
	SDActMonInstanceSetup,              //  InstanceSetup
	SDActMonQueryTeardown,              //  InstanceQueryTeardown
	SDActMonInstanceTeardownStart,		//  InstanceTeardownStart
	SDActMonInstanceTeardownComplete,	//  InstanceTeardownComplete
	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent
};

NTSTATUS ActMonUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	//DbgPrint("[SWAPNIL] SDActMon.sys Unload\n");
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	FltCloseCommunicationPort(SDActMonData.ServerPort);
	
	FltUnregisterFilter(SDActMonData.Filter);

	ExDeleteNPagedLookasideList(&SDActMonData.QueueContextLookaside);

	return STATUS_SUCCESS;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	//DbgPrint("[SWAPNIL] Inside DriverEntry\n");
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;
	PSECURITY_DESCRIPTOR sd;
	NTSTATUS status;
	GUID MAX_CLASS_GUID = { 0 };
	PDEVICE_OBJECT devobject = 0;

	UNREFERENCED_PARAMETER(RegistryPath);
	PAGED_CODE();

	//DbgPrint("[SWAPNIL] DriverEntry : Inside\n");

	SDActMonData.UserProcess = NULL;
	SDActMonData.ClientPort = 0;
	SDActMonData.PendingRequests = 0;

	//DbgPrint("[SWAPNIL] DriverEntry : LEVEL 1\n");

	//ExInitializeNPagedLookasideList(&SDActMonData.QueueContextLookaside, NULL, NULL, 0, sizeof(QUEUE_CONTEXT), MAXSYSMON_POOL_POOL_TAG, 0);
	IoCreateDeviceSecure(DriverObject, MAX_PATH, &DEVICENAME, FILE_DEVICE_FILE_SYSTEM, FILE_DEVICE_SECURE_OPEN, FALSE, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RWX_RES_RWX, (struct _GUID*)&MAX_CLASS_GUID, &devobject);
	IoCreateSymbolicLink(&DEVICELINK, &DEVICENAME);

	//DbgPrint("[SWAPNIL] DriverEntry : LEVEL 2\n");

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControlHandler;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateCloseHandler;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateCloseHandler;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = DriverCleanupHandler;
	DriverObject->DriverUnload = DriverUnloadHandler;
	
	//DbgPrint("[SWAPNIL] DriverEntry : LEVEL 3\n");

	ExInitializeNPagedLookasideList(&SDActMonData.QueueContextLookaside, NULL, NULL, 0, sizeof(QUEUE_CONTEXT), MAXSYSMON_POOL_POOL_TAG, 0);

	//DbgPrint("[SWAPNIL] DriverEntry : LEVEL 4\n");

	g_bReadBlock = GetUsbSettingsData(RegistryPath, &USB_READ_VALUE);
	g_bWriteBlock = GetUsbSettingsData(RegistryPath, &USB_WRITE_VALUE);
	g_bExecuteBlock = GetUsbSettingsData(RegistryPath, &USB_EXECUTE_VALUE);
	g_bActivityLog = GetUsbSettingsData(RegistryPath, &USB_ACTIVITY_MON_VALUE);

	status = FltRegisterFilter(DriverObject, &FilterRegistration, &SDActMonData.Filter);
	if (!NT_SUCCESS(status)) 
	{
		//DbgPrint("[SWAPNIL] DriverEntry : LEVEL 5 FAILED\n");
		return status;
	}

	//DbgPrint("[SWAPNIL] DriverEntry : LEVEL 5\n");

	//Create Communication Port
	RtlInitUnicodeString(&uniString, SDActMonPortName);

	//  We secure the port so only ADMINs & SYSTEM can acecss it.
	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

	//DbgPrint("[SWAPNIL] DriverEntry : LEVEL 6\n");

	if (NT_SUCCESS(status))
	{
		//DbgPrint("[SWAPNIL] DriverEntry : LEVEL 6.1\n");
		InitializeObjectAttributes(&oa, &uniString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);

		//DbgPrint("[SWAPNIL] DriverEntry : LEVEL 6.2\n");

		status = FltCreateCommunicationPort(SDActMonData.Filter, &SDActMonData.ServerPort, &oa, NULL, ActMonPortConnect, ActMonPortDisconnect, NULL, 1);
		FltFreeSecurityDescriptor(sd);

		//DbgPrint("[SWAPNIL] DriverEntry : LEVEL 6.3\n");

		if (NT_SUCCESS(status))
		{
			//  Start filtering I/O.
			//DbgPrint("[SWAPNIL] DriverEntry : LEVEL 6.4\n");
			status = FltStartFiltering(SDActMonData.Filter);
			if (NT_SUCCESS(status))
			{
				//DbgPrint("[SWAPNIL] DriverEntry : LEVEL 6.5 SUCCESS\n");
				return STATUS_SUCCESS;
			}
			//DbgPrint("[SWAPNIL] DriverEntry : LEVEL 6.5 FAIED\n");
			FltCloseCommunicationPort(SDActMonData.ServerPort);
		}
	}

	//DbgPrint("[SWAPNIL] DriverEntry : LEVEL 7\n");

	FltUnregisterFilter(SDActMonData.Filter);
	return status;

}

BOOLEAN GetProcessNameEx(PUNICODE_STRING ProcessImageName)
{
	NTSTATUS		status = STATUS_ACCESS_DENIED;
	PUNICODE_STRING imageName = NULL;
	ULONG			returnedLength = 0;
	ULONG			bufferLength = 0;
	PVOID			buffer = NULL;

	PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process

	if (PsGetCurrentProcessId() == (HANDLE)4)
	{
		if (ProcessImageName->MaximumLength < SYSTEM_PROCESS_NAME.MaximumLength)
		{
			return FALSE;
		}
		RtlCopyUnicodeString(ProcessImageName, &SYSTEM_PROCESS_NAME);
		return TRUE;
	}

	if (ZwQueryInformationProcess == NULL)
	{
		UNICODE_STRING routineName = { 0 };
		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
		ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
		if (NULL == ZwQueryInformationProcess)
		{
			return FALSE;
		}
	}
	// get the size we need
	status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessImageFileName, NULL, 0, &returnedLength);

	if (STATUS_INFO_LENGTH_MISMATCH != status)
	{
		return FALSE;
	}

	//check the buffer size
	bufferLength = returnedLength - sizeof(UNICODE_STRING);
	if (ProcessImageName->MaximumLength < bufferLength)
	{
		return FALSE;
	}

	buffer = ExAllocatePoolWithTag(NonPagedPool, returnedLength, MAXSYSMON_POOL_POOL_TAG);
	if (NULL == buffer || !buffer)
	{
		return FALSE;
	}

	status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessImageFileName, buffer, returnedLength, &returnedLength);

	if (NT_SUCCESS(status))
	{
		imageName = (PUNICODE_STRING)buffer;
		RtlCopyUnicodeString(ProcessImageName, imageName);
	}

	if (buffer)
	{
		ExFreePoolWithTag(buffer, MAXSYSMON_POOL_POOL_TAG);
	}

	return TRUE;
}

BOOLEAN GetImageNameByID(HANDLE ProcessId, PUNICODE_STRING pusImageFileName)
{
	UNICODE_STRING		ProcImgName = { 0 };
	HANDLE				hProcessHandle = NULL;
	NTSTATUS			status = STATUS_ACCESS_DENIED;
	PEPROCESS			eProcess = NULL;
	//int iEntryIndex = -1;

	//get process handle for given PID
	status = PsLookupProcessByProcessId(ProcessId, &eProcess);
	if ((!NT_SUCCESS(status)) || (!eProcess))
	{
		return FALSE;
	}

	status = ObOpenObjectByPointer(eProcess, 0, NULL, 0, 0, KernelMode, &hProcessHandle);
	if ((!NT_SUCCESS(status)) || (!hProcessHandle))
	{
		ObDereferenceObject(eProcess);
		eProcess = NULL;
		return FALSE;
	}

	//Find out name of process
	ProcImgName.Length = 0;
	ProcImgName.MaximumLength = 1024;
	ProcImgName.Buffer = ExAllocatePoolWithTag(NonPagedPool, ProcImgName.MaximumLength, MAXSYSMON_POOL_POOL_TAG);

	if (ProcImgName.Buffer == NULL)
	{
		ZwClose(hProcessHandle);
		ObDereferenceObject(eProcess);
		eProcess = NULL;
		return FALSE;
	}
	RtlZeroMemory(ProcImgName.Buffer, ProcImgName.MaximumLength);

	status = GetProcessImageName(hProcessHandle, &ProcImgName);

	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(ProcImgName.Buffer, MAXSYSMON_POOL_POOL_TAG);
		ZwClose(hProcessHandle);
		ObDereferenceObject(eProcess);
		eProcess = NULL;
		return FALSE;
	}

	if (pusImageFileName)
	{
		RtlCopyUnicodeString(pusImageFileName, &ProcImgName);
	}

	ExFreePoolWithTag(ProcImgName.Buffer, MAXSYSMON_POOL_POOL_TAG);
	ZwClose(hProcessHandle);
	ObDereferenceObject(eProcess);
	eProcess = NULL;
	return TRUE;
}

NTSTATUS GetProcessImageName(HANDLE ProcessHandle, PUNICODE_STRING ProcessImageName)
{
	NTSTATUS			status = STATUS_ACCESS_DENIED;
	PUNICODE_STRING		imageName = NULL;
	ULONG				returnedLength = 0;
	ULONG				bufferLength = 0;
	PVOID				buffer = NULL;

	if (ZwQueryInformationProcess == NULL)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
		ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
		if (NULL == ZwQueryInformationProcess)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}
	// get the size we need
	status = ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, NULL,
		0, &returnedLength);

	if (STATUS_INFO_LENGTH_MISMATCH != status)
	{
		return status;
	}

	//check the buffer size
	bufferLength = returnedLength - sizeof(UNICODE_STRING);
	if (ProcessImageName->MaximumLength < bufferLength)
	{
		ProcessImageName->Length = (USHORT)bufferLength;
		return STATUS_BUFFER_OVERFLOW;
	}

	buffer = ExAllocatePoolWithTag(NonPagedPool, returnedLength, MAXSYSMON_POOL_POOL_TAG);
	if (NULL == buffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, buffer,returnedLength, &returnedLength);

	if (NT_SUCCESS(status))
	{
		imageName = (PUNICODE_STRING)buffer;
		RtlCopyUnicodeString(ProcessImageName, imageName);
	}

	ExFreePoolWithTag(buffer, MAXSYSMON_POOL_POOL_TAG);
	return status;
}

USHORT GetMaxLen(PUNICODE_STRING pStr)
{
	return (pStr->MaximumLength >= pStr->Length ? pStr->MaximumLength : pStr->Length);
}

BOOLEAN IsOurPathFile(PUNICODE_STRING FileBeingAccessed)
{
	const UNICODE_STRING* pusEntry = 0;
	UNICODE_STRING	FileBeingAccessedTemp;
	if (!FileBeingAccessed || !FileBeingAccessed->Buffer || FileBeingAccessed->Length <= 0)
	{
		return FALSE;
	}


	RtlUpcaseUnicodeString(&FileBeingAccessedTemp, FileBeingAccessed, TRUE);

	if (!FileBeingAccessedTemp.Buffer || FileBeingAccessedTemp.Length <= 0)
	{
		return FALSE;
	}

	pusEntry = OurPathFiles;
	while (pusEntry->Buffer != NULL)
	{
		if (MatchUnicodeString(pusEntry, &FileBeingAccessedTemp))
		{
			RtlFreeUnicodeString(&FileBeingAccessedTemp);
			return TRUE;
		}
		pusEntry++;
	}

	RtlFreeUnicodeString(&FileBeingAccessedTemp);
	return FALSE;
}

BOOLEAN IsOurProcessFile(PUNICODE_STRING ProcessPath)
{
	const UNICODE_STRING* pusEntry = 0;
	UNICODE_STRING	FileBeingAccessedTemp;
	if (!ProcessPath || !ProcessPath->Buffer || ProcessPath->Length <= 0)
	{
		return FALSE;
	}


	RtlUpcaseUnicodeString(&FileBeingAccessedTemp, ProcessPath, TRUE);

	if (!FileBeingAccessedTemp.Buffer || FileBeingAccessedTemp.Length <= 0)
	{
		return FALSE;
	}

	pusEntry = OurProcessesFiles;
	while (pusEntry->Buffer != NULL)
	{
		if (MatchUnicodeString(pusEntry, &FileBeingAccessedTemp))
		{
			RtlFreeUnicodeString(&FileBeingAccessedTemp);
			return TRUE;
		}
		pusEntry++;
	}
	RtlFreeUnicodeString(&FileBeingAccessedTemp);
	return FALSE;
}

BOOLEAN MatchUnicodeString(UNICODE_STRING const* pusLeftString, UNICODE_STRING const* pusRightString)
{
	BOOLEAN bReturnVal = FALSE;
	bReturnVal = MatchWCHARString((pusLeftString->Length / 2), pusLeftString->Buffer, (pusRightString->Length / 2), pusRightString->Buffer);
	return bReturnVal;
}

BOOLEAN MatchWCHARString(int iwLen, PWCHAR w, int isLen, PWCHAR s)
{
	int iw = 0, is = 0;
	int iwPieceOff = 0, iwPieceLen = 0;
	BOOLEAN bFlag = FALSE;
	for (iw = 0; iw < iwLen;)
	{
		bFlag = FALSE;
		for (iwPieceOff = iw; iw < iwLen && !bFlag; iw++)
		{
			bFlag = L'*' == w[iw];
		}
		iwPieceLen = iw - iwPieceOff;
		iwPieceLen -= bFlag;
		if (iwPieceLen <= 0)
		{
			continue;
		}
		bFlag = FALSE;
		for (; is + (iwPieceLen - 1) < isLen && !bFlag; is++)
		{
			bFlag = !memcmp(w + iwPieceOff, s + is, iwPieceLen * sizeof(WCHAR));
		}
		if (!bFlag)
		{
			break;
		}
	}
	return bFlag;
}

NTSTATUS GetMaxFileInfo(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject, _Out_ PBOOLEAN IsDir, _Out_ PLONGLONG FileSize)
{
	NTSTATUS status = STATUS_SUCCESS;
	FILE_STANDARD_INFORMATION standardInfo;

	status = FltQueryInformationFile(Instance,FileObject,&standardInfo,sizeof(FILE_STANDARD_INFORMATION),FileStandardInformation,NULL);

	if (NT_SUCCESS(status))
	{
		*IsDir = standardInfo.Directory;
		*FileSize = standardInfo.EndOfFile.QuadPart;
	}
	return status;

}

NTSTATUS ActMonPortConnect(__in PFLT_PORT ClientPort, __in_opt PVOID ServerPortCookie,__in_bcount_opt(SizeOfContext) PVOID ConnectionContext,__in ULONG SizeOfContext, __deref_out_opt PVOID* ConnectionCookie)
{
	PAGED_CODE();

	//DbgPrint("Inside ActMonPortConnect");

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie = NULL);

	ASSERT(SDActMonData.ClientPort == NULL);
	ASSERT(SDActMonData.UserProcess == NULL);

	SDActMonData.UserProcess = PsGetCurrentProcess();
	SDActMonData.ClientPort = ClientPort;
	SDActMonData.ControlPid = (ULONG)PsGetCurrentProcessId();

	//DbgPrint("[%05d] !!! SDActMon.sys --- connected, port=0x%p\n", PsGetCurrentProcessId(), ClientPort );
	return STATUS_SUCCESS;

}

VOID ActMonPortDisconnect(__in_opt PVOID ConnectionCookie)
{
	UNREFERENCED_PARAMETER(ConnectionCookie);

	PAGED_CODE();

	//DbgPrint("[%05d] !!! SDActMon.sys --- disconnected, port=0x%p\n", PsGetCurrentProcessId(), SDActMonData.ClientPort );

	FltCloseClientPort(SDActMonData.Filter, &SDActMonData.ClientPort);
	SDActMonData.UserProcess = NULL;
	SDActMonData.ClientPort = 0;
}

VOID ContextCleanup(__in PFLT_CONTEXT Context, __in FLT_CONTEXT_TYPE ContextType)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(ContextType);

	PAGED_CODE();
}

BOOLEAN SendEntryToUI(ULONG ulTypeOfCall, PUNICODE_STRING pusProcessName, PUNICODE_STRING pAccessed_1, PUNICODE_STRING pAccessed_2)
{
	NTSTATUS status;
	PSDACTMON_NOTIFICATION notification = NULL;
	ULONG replyLength;
	BOOLEAN bAllowEntry = TRUE;
	LARGE_INTEGER Timeout;

	PAGED_CODE();

	
	Timeout.QuadPart = -(LONGLONG)1 * 30 * 10 * 1000 * 1000;		// 30 Seconds

	if (SDActMonData.ClientPort == 0)
	{
		//DbgPrint("SDActMonData.ClientPort == 0\n");
		return bAllowEntry;
	}

	notification = ExAllocatePoolWithTag(NonPagedPool, sizeof(SDACTMON_NOTIFICATION), MAXSYSMON_POOL_POOL_TAG);

	if (NULL == notification)
	{
		return bAllowEntry;
	}

	notification->ProcessID = PsGetCurrentProcessId();

	notification->TypeOfCall = ulTypeOfCall;
	notification->TypeOfReplication = 0;

	RtlZeroMemory(&notification->ProcessName, sizeof(notification->ProcessName));
	RtlZeroMemory(&notification->Accessed_1, sizeof(notification->Accessed_1));
	RtlZeroMemory(&notification->Accessed_2, sizeof(notification->Accessed_2));

	//  Copy only as much as the buffer can hold
	RtlCopyMemory(&notification->ProcessName, pusProcessName->Buffer, min(pusProcessName->Length, SDACTMON_READ_BUFFER_SIZE));
	RtlCopyMemory(&notification->Accessed_1, pAccessed_1->Buffer, min(pAccessed_1->Length, SDACTMON_READ_BUFFER_SIZE));
	//RtlCopyMemory(&notification->ProcessName, pusProcessName, min(pusProcessName->Length, SDACTMON_READ_BUFFER_SIZE));
	//RtlCopyMemory(&notification->Accessed_1, pAccessed_1, min(pAccessed_1->Length, SDACTMON_READ_BUFFER_SIZE));
	

	if (pAccessed_2)
	{
		RtlCopyMemory(&notification->Accessed_2, pAccessed_2->Buffer, min(pAccessed_2->Length, SDACTMON_READ_BUFFER_SIZE));
	}

	replyLength = sizeof(SDACTMON_REPLY);

	//DbgPrint("notification->ProcessName : %wZ\n", &notification->ProcessName);
	//DbgPrint("notification->Accessed_1 : %wZ\n", &notification->Accessed_1);
	//DbgPrint("notification->ProcessID : %05d\n", notification->ProcessID);

	
	//DbgPrint("notification->Accessed_2 : %wZ", &notification->Accessed_2);
	status = FltSendMessage(SDActMonData.Filter, &SDActMonData.ClientPort, notification,sizeof(SDACTMON_NOTIFICATION), notification, &replyLength, &Timeout);

	if (STATUS_SUCCESS == status)
	{
		bAllowEntry = ((PSDACTMON_REPLY)notification)->SafeToOpen;

	}
	if (notification)
	{
		ExFreePoolWithTag(notification, MAXSYSMON_POOL_POOL_TAG);
	}
	return bAllowEntry;

}

FLT_PREOP_CALLBACK_STATUS ActMonPreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
	NTSTATUS					RetStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PFLT_FILE_NAME_INFORMATION	nameInfo;
	HANDLE						hCurrentProcID = NULL;
	ULONG						dwCurProcessID = 0x00;
	UNICODE_STRING				usDriveLetter = { 0 }, usFullFileName = { 0 }, usProcessName = { 0 };
	PFILE_OBJECT				pFileObject = NULL;
	PUNICODE_STRING				pParentFolderName = NULL, pFileName = NULL;
	
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();

	if (!gbIsProtectionOn)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (SDActMonData.ClientPort == 0)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if ((!SDActMonData.UserProcess) || (IoThreadToProcess(Data->Thread) == SDActMonData.UserProcess))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* If this is a callback for a FS Filter driver then we ignore the event */
	if (FLT_IS_FS_FILTER_OPERATION(Data))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (!FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_COMPLETE_IF_OPLOCKED))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (!NT_SUCCESS(Data->IoStatus.Status) ||
		(STATUS_REPARSE == Data->IoStatus.Status) ||
		FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE) /* ||
		IsAllowedStateCreate(FltObjects, 0)*/)
	{

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	hCurrentProcID = PsGetCurrentProcessId();
	if (hCurrentProcID == NULL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	dwCurProcessID = (ULONG)hCurrentProcID;
	if (dwCurProcessID == 0 || dwCurProcessID == 8)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (IsOurProcessByID(hCurrentProcID))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	usProcessName.Length = 0;
	usProcessName.MaximumLength = 512;
	usProcessName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usProcessName.MaximumLength, MAXSYSMON_POOL_POOL_TAG);

	if (usProcessName.Buffer == NULL || !usProcessName.Buffer)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	
	//if (GetImageNameByID(hCurrentProcID, &usProcessName) == FALSE)
	if (GetProcessNameEx(&usProcessName) == FALSE)
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
		}
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (IsOurProcessFile(&usProcessName))
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
		}
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	pFileObject = FltObjects->FileObject;

	if (!pFileObject)
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
		}
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	pFileName = &pFileObject->FileName;
	if ((!pFileName) || (pFileName->Length <= 0))
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
		}
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (!pFileName->Buffer)
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
		}
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if ((pFileObject->RelatedFileObject) && (pFileObject->FileName.Buffer[0] != L'\\'))
	{
		pParentFolderName = &pFileObject->RelatedFileObject->FileName;
	}

	if ((Data->Iopb->TargetFileObject != NULL) && Data->Iopb->TargetFileObject && Data->Iopb->TargetFileObject->FileName.Buffer && (Data->Iopb->TargetFileObject->FileName.Buffer != NULL))
	{
		if (dwCurProcessID == 4)
		{
			if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == 0x04)
			{
				if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
				{
					if (NT_SUCCESS(FltParseFileNameInformation(nameInfo)))
					{
						if (RtlCompareUnicodeString(&nameInfo->Extension, &TMP_FILE, TRUE) == 0)
						{
							FltReleaseFileNameInformation(nameInfo);
							if (usProcessName.Buffer)
							{
								ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
							}
							return FLT_PREOP_SUCCESS_WITH_CALLBACK;
						}
					}

					if (nameInfo->Name.Length > 512)
					{
						if (usProcessName.Buffer)
						{
							ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
						}
						FltReleaseFileNameInformation(nameInfo);
						return FLT_PREOP_SUCCESS_WITH_CALLBACK;
					}

					if ((CheckIsWinDll(&nameInfo->Name) == -1))
					{
						RtlInitUnicodeString(&usDriveLetter, NULL);
						if ((!NT_SUCCESS(IoVolumeDeviceToDosName(Data->Iopb->TargetFileObject->DeviceObject, &usDriveLetter))) || (!usDriveLetter.Buffer))
						{
							if (usProcessName.Buffer)
							{
								ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
							}
							return FLT_PREOP_SUCCESS_WITH_CALLBACK;
						}

						usFullFileName.Length = 0;
						if (pParentFolderName)
							usFullFileName.MaximumLength = GetMaxLen(&usDriveLetter) + GetMaxLen(pParentFolderName) + GetMaxLen(pFileName) + 4;
						else
							usFullFileName.MaximumLength = GetMaxLen(&usDriveLetter) + GetMaxLen(pFileName) + 2;
						usFullFileName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usFullFileName.MaximumLength, MAXSYSMON_POOL_POOL_TAG);

						if (!usFullFileName.Buffer)
						{
							if (usProcessName.Buffer)
							{
								ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
							}
							if (usDriveLetter.Buffer)
							{
								ExFreePool(usDriveLetter.Buffer);
							}

							return FLT_PREOP_SUCCESS_WITH_CALLBACK;
						}

						if (usFullFileName.Length > 512)
						{
							if (usProcessName.Buffer)
							{
								ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
							}
							if (usFullFileName.Buffer)
							{
								ExFreePoolWithTag(usFullFileName.Buffer, MAXSYSMON_POOL_POOL_TAG);
							}
							if (usDriveLetter.Buffer)
							{
								ExFreePool(usDriveLetter.Buffer);
							}
							return FLT_PREOP_SUCCESS_WITH_CALLBACK;
						}

						RtlUnicodeStringCatEx(&usFullFileName, &usDriveLetter, NULL, STRSAFE_IGNORE_NULLS);
						if (pParentFolderName)
						{
							RtlUnicodeStringCatEx(&usFullFileName, pParentFolderName, NULL, STRSAFE_IGNORE_NULLS);
							RtlUnicodeStringCatEx(&usFullFileName, &BACKSLASH, NULL, STRSAFE_IGNORE_NULLS);
						}
						RtlUnicodeStringCatEx(&usFullFileName, pFileName, NULL, STRSAFE_IGNORE_NULLS);

						SendEntryToUI(CALL_TYPE_N_CREATE, &usProcessName, &usFullFileName, NULL);//CALL_TYPE_F_CREATE
						
					}

					FltReleaseFileNameInformation(nameInfo);
				}
				else
				{
					if (usProcessName.Buffer)
					{
						ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
					}
					return FLT_PREOP_SUCCESS_NO_CALLBACK;
				}
			}
			else
			{
				if (usProcessName.Buffer)
				{
					ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
				}
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
		}
		if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation ||
			Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation)
		{
			if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
			{
				if (IsOurPathFile(&nameInfo->Name))
				{
					if (usProcessName.Buffer)
					{
						ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
					}
					//DbgPrint("[SWAPNIL PRE CREATE] SKIP FILE = %wZ\n", &nameInfo->Name);
					FltReleaseFileNameInformation(nameInfo);
					return FLT_PREOP_SUCCESS_NO_CALLBACK;
				}

				if (NT_SUCCESS(FltParseFileNameInformation(nameInfo)))
				{
					//if (nameInfo->Extension.Buffer != NULL)
					{
						if (nameInfo->Name.Length > 512)
						{
							if (usProcessName.Buffer)
							{
								ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
							}
							FltReleaseFileNameInformation(nameInfo);
							return FLT_PREOP_SUCCESS_NO_CALLBACK;
						}
						if (nameInfo->Name.Buffer != NULL)
						{
							RtlInitUnicodeString(&usDriveLetter, NULL);

							if ((!NT_SUCCESS(IoVolumeDeviceToDosName(Data->Iopb->TargetFileObject->DeviceObject, &usDriveLetter))) || (!usDriveLetter.Buffer))
							{
								if (usProcessName.Buffer)
								{
									ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
								}
								FltReleaseFileNameInformation(nameInfo);
								return FLT_PREOP_SUCCESS_NO_CALLBACK;
							}

							usFullFileName.Length = 0;
							if (pParentFolderName)
							{
								usFullFileName.MaximumLength = GetMaxLen(&usDriveLetter) + GetMaxLen(pParentFolderName) + GetMaxLen(pFileName) + 4;
							}
							else
							{
								usFullFileName.MaximumLength = GetMaxLen(&usDriveLetter) + GetMaxLen(pFileName) + 2;
							}
							usFullFileName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usFullFileName.MaximumLength, MAXSYSMON_POOL_POOL_TAG);

							if (!usFullFileName.Buffer)
							{
								if (usProcessName.Buffer)
								{
									ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
								}
								if (usDriveLetter.Buffer)
								{
									ExFreePool(usDriveLetter.Buffer);
								}
								FltReleaseFileNameInformation(nameInfo);
								return FLT_PREOP_SUCCESS_NO_CALLBACK;
							}

							if (usFullFileName.Length > 512)
							{
								if (usProcessName.Buffer)
								{
									ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
								}
								if (usFullFileName.Buffer)
								{
									ExFreePoolWithTag(usFullFileName.Buffer, MAXSYSMON_POOL_POOL_TAG);
								}
								if (usDriveLetter.Buffer)
								{
									ExFreePool(usDriveLetter.Buffer);
								}
								FltReleaseFileNameInformation(nameInfo);
								return FLT_PREOP_SUCCESS_NO_CALLBACK;
							}

							RtlUnicodeStringCatEx(&usFullFileName, &usDriveLetter, NULL, STRSAFE_IGNORE_NULLS);
							if (pParentFolderName)
							{
								RtlUnicodeStringCatEx(&usFullFileName, pParentFolderName, NULL, STRSAFE_IGNORE_NULLS);
								RtlUnicodeStringCatEx(&usFullFileName, &BACKSLASH, NULL, STRSAFE_IGNORE_NULLS);
							}
							RtlUnicodeStringCatEx(&usFullFileName, pFileName, NULL, STRSAFE_IGNORE_NULLS);
						}
					}
				}
				FltReleaseFileNameInformation(nameInfo);
				if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation)
				{
					if ((IsNeedToCheckEncryption(&usFullFileName, &nameInfo->Extension) != -1))
					{
						SendEntryToUI(CALL_TYPE_C_CREATE, &usProcessName, &nameInfo->Extension, &usFullFileName);
					}
				}
				else
				{
					RetStatus = AddInQue(Data, FltObjects, CALL_TYPE_F_EXECUTE, &usProcessName, &usFullFileName);
				}
			}
		}
	}


	if (usProcessName.Buffer)
	{
		ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
	}
	if (usFullFileName.Buffer)
	{
		ExFreePoolWithTag(usFullFileName.Buffer, MAXSYSMON_POOL_POOL_TAG);
	}
	if (usDriveLetter.Buffer)
	{
		ExFreePool(usDriveLetter.Buffer);
	}

	return RetStatus;
}

FLT_PREOP_CALLBACK_STATUS ActMonPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
	PFLT_FILE_NAME_INFORMATION	nameInfo;
	PFILE_OBJECT				pFileObject = 0;
	PUNICODE_STRING				pParentFolderName = NULL, pFileName = NULL;
	UNICODE_STRING				usProcessName = { 0 }, usDriveLetter = { 0 }, usFullFileName = { 0 };
	HANDLE						hCurrentProcID = NULL;
	BOOLEAN						bIsExecutable = FALSE;
	//BOOLEAN						bIsWriteCall = FALSE;
	ULONG						dwCurProcessID = 0x00;
	NTSTATUS					RetStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	BOOLEAN						bIsUSBCall = FALSE;

	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();

	if (!gbIsProtectionOn)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (SDActMonData.ClientPort == 0)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if ((!SDActMonData.UserProcess) || (IoThreadToProcess(Data->Thread) == SDActMonData.UserProcess))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* If this is a callback for a FS Filter driver then we ignore the event */
	if (FLT_IS_FS_FILTER_OPERATION(Data))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (!FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_COMPLETE_IF_OPLOCKED))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (!NT_SUCCESS(Data->IoStatus.Status) ||
		(STATUS_REPARSE == Data->IoStatus.Status) ||
		FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)  ||
		IsAllowedStateCreate(FltObjects, 0))
	{

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	hCurrentProcID = PsGetCurrentProcessId();
	if (hCurrentProcID == NULL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	dwCurProcessID = (ULONG)hCurrentProcID;
	if (dwCurProcessID == 0 || dwCurProcessID == 4 || dwCurProcessID == 8)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (IsOurProcessByID(hCurrentProcID))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	
	usProcessName.Length = 0;
	usProcessName.MaximumLength = 512;
	usProcessName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usProcessName.MaximumLength, MAXSYSMON_POOL_POOL_TAG);

	if (usProcessName.Buffer == NULL || !usProcessName.Buffer)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (GetImageNameByID(hCurrentProcID, &usProcessName) == FALSE)
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
		}
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	
	if (IsOurProcessFile(&usProcessName))
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
		}
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	
	pFileObject = FltObjects->FileObject;

	if (!pFileObject)
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
		}
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	pFileName = &pFileObject->FileName;
	if ((!pFileName) || (pFileName->Length <= 0))
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
		}
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (!pFileName->Buffer)
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
		}
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if ((pFileObject->RelatedFileObject) && (pFileObject->FileName.Buffer[0] != L'\\'))
	{
		pParentFolderName = &pFileObject->RelatedFileObject->FileName;
	}

	if ((Data->Iopb->TargetFileObject != NULL) && Data->Iopb->TargetFileObject && Data->Iopb->TargetFileObject->FileName.Buffer && (Data->Iopb->TargetFileObject->FileName.Buffer != NULL))
	{
		if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
		{
			if (IsOurPathFile(&nameInfo->Name))
			{
				if (usProcessName.Buffer)
				{
					ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
				}
				//DbgPrint("[SWAPNIL PRE CREATE] SKIP FILE = %wZ\n", &nameInfo->Name);

				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
			
			if (NT_SUCCESS(FltParseFileNameInformation(nameInfo)))
			{
				//if (nameInfo->Extension.Buffer != NULL)
				{
					if (nameInfo->Name.Length > 512)
					{
						if (usProcessName.Buffer)
						{
							ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
						}
						FltReleaseFileNameInformation(nameInfo);
						return FLT_PREOP_SUCCESS_NO_CALLBACK;
					}
					if (nameInfo->Name.Buffer != NULL)
					{
						RtlInitUnicodeString(&usDriveLetter, NULL);

						if ((!NT_SUCCESS(IoVolumeDeviceToDosName(Data->Iopb->TargetFileObject->DeviceObject, &usDriveLetter))) || (!usDriveLetter.Buffer))
						{
							if (usProcessName.Buffer)
							{
								ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
							}
							return FLT_PREOP_SUCCESS_NO_CALLBACK;
						}

						usFullFileName.Length = 0;
						if (pParentFolderName)
						{
							usFullFileName.MaximumLength = GetMaxLen(&usDriveLetter) + GetMaxLen(pParentFolderName) + GetMaxLen(pFileName) + 4;
						}
						else
						{
							usFullFileName.MaximumLength = GetMaxLen(&usDriveLetter) + GetMaxLen(pFileName) + 2;
						}
						usFullFileName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usFullFileName.MaximumLength, MAXSYSMON_POOL_POOL_TAG);

						if (!usFullFileName.Buffer)
						{
							if (usProcessName.Buffer)
							{
								ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
							}
							if (usDriveLetter.Buffer)
							{
								ExFreePool(usDriveLetter.Buffer);
							}
							return FLT_PREOP_SUCCESS_NO_CALLBACK;
						}

						if (usFullFileName.Length > 512)
						{
							if (usProcessName.Buffer)
							{
								ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
							}
							if (usFullFileName.Buffer)
							{
								ExFreePoolWithTag(usFullFileName.Buffer, MAXSYSMON_POOL_POOL_TAG);
							}
							if (usDriveLetter.Buffer)
							{
								ExFreePool(usDriveLetter.Buffer);
							}
							return FLT_PREOP_SUCCESS_NO_CALLBACK;
						}

						RtlUnicodeStringCatEx(&usFullFileName, &usDriveLetter, NULL, STRSAFE_IGNORE_NULLS);
						if (pParentFolderName)
						{
							RtlUnicodeStringCatEx(&usFullFileName, pParentFolderName, NULL, STRSAFE_IGNORE_NULLS);
							RtlUnicodeStringCatEx(&usFullFileName, &BACKSLASH, NULL, STRSAFE_IGNORE_NULLS);
						}
						RtlUnicodeStringCatEx(&usFullFileName, pFileName, NULL, STRSAFE_IGNORE_NULLS);

						//DbgPrint("[SWAPNIL PRE CREATE] usFullFileName = %wZ\n", &usFullFileName);
						//GENERIC_ALL
						
						/*
						if (IsFileWriteCall(Data))
						{
							bIsWriteCall = TRUE;
						}
						if (bIsWriteCall == TRUE)
						{
							//SendEntryToUI(CALL_TYPE_F_NEW_FILE, &usProcessName, &usFullFileName, NULL);
							DbgPrint("[SWAPNIL PRE_CREATE_WRITE] usProcessName = %wZ [%wZ]\n", &usProcessName, &usFullFileName);
						}
						*/
						if (g_bMonitorUSB == 0x01)
						{
							if (IsRemovableMedia(Data, FltObjects, CompletionContext) == 0x01)
							{
								BOOLEAN		bIsBlockUsbCall = FALSE;
								int			iRetVal = 0x00;

								bIsUSBCall = TRUE;

								if (g_bTotalBlock)
								{
									bIsBlockUsbCall = TRUE;
								}
								
								if (!bIsBlockUsbCall)
								{
									iRetVal = IsUSBReadCall(Data, FltObjects, CompletionContext);
									if (iRetVal > 0x00)
									{
										if (iRetVal == 1)
										{
											bIsBlockUsbCall = TRUE;
										}
										if (iRetVal == 2 || iRetVal == 3)
										{
											SendEntryToUI(CALL_TYPE_U_CREATE, &usProcessName, &nameInfo->Name, NULL);
											if (iRetVal == 3)
											{
												bIsBlockUsbCall = TRUE;
											}
										}
									}
								}

								if (!bIsBlockUsbCall)
								{
									//DbgPrint("[%05d] ##### USB ACTIVITY_EXECUTE CHECK : %wZ, %wZ!\n", PsGetCurrentProcessId(), &usProcessName, &nameInfo->Name);
									iRetVal = IsUSBExecuteCall(Data, FltObjects, CompletionContext);
									if (iRetVal > 0x00)
									{
										DbgPrint("[%05d] ##### USB ACTIVITY_EXECUTE : %wZ, %wZ!\n", PsGetCurrentProcessId(), &usProcessName, &nameInfo->Name);
										if (iRetVal == 1)
										{
											DbgPrint("[%05d] ##### USB ACTIVITY_EXECUTE BLOCK : %wZ, %wZ!\n", PsGetCurrentProcessId(), &usProcessName, &nameInfo->Name);
											bIsBlockUsbCall = TRUE;
										}
										if (iRetVal == 2 || iRetVal == 3)
										{
											SendEntryToUI(CALL_TYPE_U_EXECUTE, &usProcessName, &nameInfo->Name, NULL);
											if (iRetVal == 3)
											{
												DbgPrint("[%05d] ##### USB ACTIVITY_EXECUTE BLOCK 2 : %wZ, %wZ!\n", PsGetCurrentProcessId(), &usProcessName, &nameInfo->Name);
												bIsBlockUsbCall = TRUE;
											}
										}
									}
								}

								if (!bIsBlockUsbCall)
								{
									iRetVal = IsUSBWriteCall(Data, FltObjects, CompletionContext);
									if (iRetVal > 0x00)
									{
										if (iRetVal == 1)
										{
											bIsBlockUsbCall = TRUE;
										}
										if (iRetVal == 2 || iRetVal == 3)
										{
											SendEntryToUI(CALL_TYPE_U_WRITE, &usProcessName, &nameInfo->Name, NULL);
											if (iRetVal == 3)
											{
												bIsBlockUsbCall = TRUE;
											}
										}
									}
								}
								if (bIsBlockUsbCall)
								{
									DbgPrint("[%05d] ##### BLOCKED 4: %wZ, %wZ!\n", PsGetCurrentProcessId(), &usProcessName, &nameInfo->Name);
									Data->IoStatus.Status = STATUS_ACCESS_DENIED;
									Data->IoStatus.Information = 0;
									if (usProcessName.Buffer)
									{
										ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
									}
									if (usFullFileName.Buffer)
									{
										ExFreePoolWithTag(usFullFileName.Buffer, MAXSYSMON_POOL_POOL_TAG);
									}
									if (usDriveLetter.Buffer)
									{
										ExFreePool(usDriveLetter.Buffer);
									}
									FltReleaseFileNameInformation(nameInfo);
									return FLT_PREOP_COMPLETE;
								}
							}
						}
						if ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_EXECUTE) == FILE_EXECUTE)
						{
							if (nameInfo->Extension.Buffer != NULL)
							{
								if ((RtlCompareUnicodeString(&nameInfo->Extension, &EXE_FILE, TRUE) == 0))
								{
									bIsExecutable = TRUE;
								}
							}
						}
						if (bIsExecutable == TRUE)
						{
							RetStatus = AddInQue(Data, FltObjects, CALL_TYPE_F_EXECUTE, &usProcessName, &usFullFileName);
							//SendEntryToUI(CALL_TYPE_F_EXECUTE, &usProcessName, &usFullFileName, NULL);
							DbgPrint("[SWAPNIL PRE_EXECUTE] usProcessName = %wZ [%wZ]\n", &usProcessName, &usFullFileName);
						}
						/*
						else if (bIsUSBCall == FALSE)
						{
							//Handling for CryptMon calls
							if (nameInfo->Extension.Buffer != NULL)
							{
								if ((IsNeedToCheckEncryption(&usFullFileName, &nameInfo->Extension) != -1))
								{
									SendEntryToUI(CALL_TYPE_C_CREATE, &usProcessName, &nameInfo->Extension, &usFullFileName);
								}
							}
						}
						*/
					}
				}
			}
			FltReleaseFileNameInformation(nameInfo);
		}
	}

	if (usProcessName.Buffer)
	{
		ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
	}
	if (usFullFileName.Buffer)
	{
		ExFreePoolWithTag(usFullFileName.Buffer, MAXSYSMON_POOL_POOL_TAG);
	}
	if (usDriveLetter.Buffer)
	{
		ExFreePool(usDriveLetter.Buffer);
	}
	/*if (bIsExecutable == TRUE)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}*/
	return RetStatus;
}

FLT_POSTOP_CALLBACK_STATUS ActMonPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	PFLT_FILE_NAME_INFORMATION			nameInfo;
	PFILE_OBJECT						pFileObject = 0;
	PUNICODE_STRING						pParentFolderName = NULL, pFileName = NULL;
	UNICODE_STRING						usProcessName = { 0 }, usDriveLetter = { 0 }, usFullFileName = { 0 };
	HANDLE								hCurrentProcID = NULL;
	BOOLEAN								bIsDir = FALSE;
	LONGLONG							FileSize = 0;
	//BOOLEAN								bIsExecutable = FALSE;
	ULONG								dwCurProcessID = 0x00;
	NTSTATUS							status;
	PSDACTMON_STREAM_HANDLE_CONTEXT		pSDActMonContext = NULL;

	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);
	PAGED_CODE();

	if (!gbIsProtectionOn)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (!Data)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (!Data->Thread)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (SDActMonData.ClientPort == 0)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (IsPostCreateSkip(Data, FltObjects, Flags))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if ((!SDActMonData.UserProcess) || (IoThreadToProcess(Data->Thread) == SDActMonData.UserProcess))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	/* If this is a callback for a FS Filter driver then we ignore the event */
	if (FLT_IS_FS_FILTER_OPERATION(Data))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (!FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_COMPLETE_IF_OPLOCKED))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (!NT_SUCCESS(Data->IoStatus.Status) ||
		(STATUS_REPARSE == Data->IoStatus.Status) ||
		FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE) /* ||
		IsAllowedStateCreate(FltObjects, 0)*/)
	{

		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (KeGetCurrentIrql() > APC_LEVEL)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	pFileObject = FltObjects->FileObject;

	if (!pFileObject)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (FltObjects->FileObject->WriteAccess != 0x1)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	pFileName = &pFileObject->FileName;
	if ((!pFileName) || (pFileName->Length <= 0))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	if (!pFileName->Buffer)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if ((pFileObject->RelatedFileObject) && (pFileObject->FileName.Buffer[0] != L'\\'))
	{
		pParentFolderName = &pFileObject->RelatedFileObject->FileName;
	}

	hCurrentProcID = PsGetCurrentProcessId();
	if (hCurrentProcID == NULL)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	dwCurProcessID = (ULONG)hCurrentProcID;
	if (dwCurProcessID == 0 || dwCurProcessID == 4 || dwCurProcessID == 8)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	if (IsOurProcessByID(hCurrentProcID))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	usProcessName.Length = 0;
	usProcessName.MaximumLength = 512;
	usProcessName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usProcessName.MaximumLength, MAXSYSMON_POOL_POOL_TAG);

	if (usProcessName.Buffer == NULL || !usProcessName.Buffer)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (GetImageNameByID(hCurrentProcID, &usProcessName) == FALSE)
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
		}
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (IsOurProcessFile(&usProcessName))
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
		}
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if ((Data->Iopb->TargetFileObject != NULL) && Data->Iopb->TargetFileObject && Data->Iopb->TargetFileObject->FileName.Buffer && (Data->Iopb->TargetFileObject->FileName.Buffer != NULL))
	{
		if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
		{
			if (NT_SUCCESS(FltParseFileNameInformation(nameInfo)))
			{
				//if (nameInfo->Extension.Buffer != NULL)
				{
					if (nameInfo->Name.Length > 512)
					{
						if (usProcessName.Buffer)
						{
							ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
						}
						FltReleaseFileNameInformation(nameInfo);
						return FLT_POSTOP_FINISHED_PROCESSING;
					}
					if (nameInfo->Name.Buffer != NULL)
					{
						RtlInitUnicodeString(&usDriveLetter, NULL);

						if ((!NT_SUCCESS(IoVolumeDeviceToDosName(Data->Iopb->TargetFileObject->DeviceObject, &usDriveLetter))) || (!usDriveLetter.Buffer))
						{
							if (usProcessName.Buffer)
							{
								ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
							}
							return FLT_POSTOP_FINISHED_PROCESSING;
						}

						usFullFileName.Length = 0;
						if (pParentFolderName)
						{
							usFullFileName.MaximumLength = GetMaxLen(&usDriveLetter) + GetMaxLen(pParentFolderName) + GetMaxLen(pFileName) + 4;
						}
						else
						{
							usFullFileName.MaximumLength = GetMaxLen(&usDriveLetter) + GetMaxLen(pFileName) + 2;
						}
						usFullFileName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usFullFileName.MaximumLength, MAXSYSMON_POOL_POOL_TAG);

						if (!usFullFileName.Buffer)
						{
							if (usProcessName.Buffer)
							{
								ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
							}
							if (usDriveLetter.Buffer)
							{
								ExFreePool(usDriveLetter.Buffer);
							}
							return FLT_POSTOP_FINISHED_PROCESSING;
						}

						if (usFullFileName.Length > 512)
						{
							if (usProcessName.Buffer)
							{
								ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
							}
							if (usFullFileName.Buffer)
							{
								ExFreePoolWithTag(usFullFileName.Buffer, MAXSYSMON_POOL_POOL_TAG);
							}
							if (usDriveLetter.Buffer)
							{
								ExFreePool(usDriveLetter.Buffer);
							}
							return FLT_POSTOP_FINISHED_PROCESSING;
						}

						RtlUnicodeStringCatEx(&usFullFileName, &usDriveLetter, NULL, STRSAFE_IGNORE_NULLS);
						if (pParentFolderName)
						{
							RtlUnicodeStringCatEx(&usFullFileName, pParentFolderName, NULL, STRSAFE_IGNORE_NULLS);
							RtlUnicodeStringCatEx(&usFullFileName, &BACKSLASH, NULL, STRSAFE_IGNORE_NULLS);
						}
						RtlUnicodeStringCatEx(&usFullFileName, pFileName, NULL, STRSAFE_IGNORE_NULLS);

						NTSTATUS STATUS = GetMaxFileInfo(FltObjects->Instance, FltObjects->FileObject, &bIsDir, &FileSize);
						
						/*
						if (NT_SUCCESS(STATUS) && (FileSize == 0))
						{
							//DbgPrint("[POST SWAPNIL] SKIP EMPTY FILE = %wZ\n", &usFullFileName);
							return FLT_POSTOP_FINISHED_PROCESSING;
						}
						*/
						if (NT_SUCCESS(STATUS) && (bIsDir == TRUE))
						{
							if (usProcessName.Buffer)
							{
								ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
							}
							if (usFullFileName.Buffer)
							{
								ExFreePoolWithTag(usFullFileName.Buffer, MAXSYSMON_POOL_POOL_TAG);
							}
							if (usDriveLetter.Buffer)
							{
								ExFreePool(usDriveLetter.Buffer);
							}

							return FLT_POSTOP_FINISHED_PROCESSING;
						}

						/*
						if (IsFileWriteCall(Data))
						{
							SendEntryToUI(CALL_TYPE_F_EXECUTE, &usProcessName, &usFullFileName, NULL);
						}
						else
						{
						*/
						//SendEntryToUI(CALL_TYPE_F_NEW_FILE, &usProcessName, &usFullFileName, NULL);
						//}

						{
							status = FltAllocateContext(SDActMonData.Filter, FLT_STREAMHANDLE_CONTEXT, sizeof(SDACTMON_STREAM_HANDLE_CONTEXT), NonPagedPool, &pSDActMonContext);
							if (NT_SUCCESS(status))
							{
								pSDActMonContext->OurFile = FALSE;
								pSDActMonContext->RescanRequired = FALSE;
								pSDActMonContext->BlockWriteAccess = FALSE;

								RtlZeroMemory(&pSDActMonContext->usProcessName, sizeof(pSDActMonContext->usProcessName));
								RtlZeroMemory(&pSDActMonContext->szProcessName, sizeof(pSDActMonContext->szProcessName));
								pSDActMonContext->usProcessName.Length = usProcessName.Length;
								pSDActMonContext->usProcessName.MaximumLength = usProcessName.MaximumLength;
								RtlCopyMemory(&pSDActMonContext->szProcessName, usProcessName.Buffer, usProcessName.Length);
								pSDActMonContext->usProcessName.Buffer = pSDActMonContext->szProcessName;
								//RtlCopyUnicodeString(&pSDActMonContext->usProcessName, &usProcessName);

								RtlZeroMemory(&pSDActMonContext->usFullFileName, sizeof(pSDActMonContext->usFullFileName));
								RtlZeroMemory(&pSDActMonContext->szFullFileName, sizeof(pSDActMonContext->szFullFileName));
								pSDActMonContext->usFullFileName.Length = usFullFileName.Length;
								pSDActMonContext->usFullFileName.MaximumLength = usFullFileName.MaximumLength;
								RtlCopyMemory(&pSDActMonContext->szFullFileName, usFullFileName.Buffer, usFullFileName.Length);
								pSDActMonContext->usFullFileName.Buffer = pSDActMonContext->szFullFileName;
								//RtlCopyUnicodeString(&pSDActMonContext->usFullFileName, &usFullFileName);

								status = FltSetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject,FLT_SET_CONTEXT_KEEP_IF_EXISTS, pSDActMonContext, NULL);

								FltReleaseContext(pSDActMonContext);

								//DbgPrint("[SWAPNIL POST CREATE] Set Context = %wZ [%wZ]\n", &usProcessName, &usFullFileName);

							}
						}
						
						//DbgPrint("[POST CREATE] usProcessName = %wZ [%wZ]\n", &usProcessName, &usFullFileName);

						//DbgPrint("[SWAPNIL POST CREATE] usFullFileName = %wZ\n", &usFullFileName);
					}
				}
			}
			FltReleaseFileNameInformation(nameInfo);
		}
	}

	if (usProcessName.Buffer)
	{
		ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
	}
	if (usFullFileName.Buffer)
	{
		ExFreePoolWithTag(usFullFileName.Buffer, MAXSYSMON_POOL_POOL_TAG);
	}
	if (usDriveLetter.Buffer)
	{
		ExFreePool(usDriveLetter.Buffer);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS ActMonPreCleanup(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS ActMonPostCleanup(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	NTSTATUS							status;
	NTSTATUS							Retstatus = FLT_POSTOP_FINISHED_PROCESSING;
	PSDACTMON_STREAM_HANDLE_CONTEXT		pSDActMonContext = NULL;
	HANDLE								hCurrentProcID = NULL;
	ULONG								dwCurProcessID = 0;
	UNICODE_STRING						usProcessName = { 0 };
	

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	if (!gbIsProtectionOn)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	//DbgPrint("[SWAPNIL POST CLEANUP] INSIDE\n");
	
	
	if (!NT_SUCCESS(Data->IoStatus.Status) || (STATUS_REPARSE == Data->IoStatus.Status))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	
	if ((!SDActMonData.UserProcess) || (IoThreadToProcess(Data->Thread) == SDActMonData.UserProcess))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (KeGetCurrentIrql() > APC_LEVEL)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	hCurrentProcID = PsGetCurrentProcessId();
	if (hCurrentProcID == NULL)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	dwCurProcessID = (ULONG)hCurrentProcID;
	if (dwCurProcessID == 0 || dwCurProcessID == 4 || dwCurProcessID == 8)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (IsOurProcessByID(hCurrentProcID))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	usProcessName.Length = 0;
	usProcessName.MaximumLength = 512;
	usProcessName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usProcessName.MaximumLength, MAXSYSMON_POOL_POOL_TAG);

	if (usProcessName.Buffer == NULL || !usProcessName.Buffer)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (GetImageNameByID(hCurrentProcID, &usProcessName) == FALSE)
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
		}
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (IsOurProcessFile(&usProcessName))
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
		}
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (FltObjects)
	{
		if (!FltObjects->FileObject)
		{
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, &pSDActMonContext);
		if (NT_SUCCESS(status))
		{
			if (pSDActMonContext->RescanRequired)
			{
				if (pSDActMonContext->usFullFileName.Buffer && pSDActMonContext->usProcessName.Buffer)
				{
					//SendEntryToUI(CALL_TYPE_F_NEW_FILE, &pSDActMonContext->usProcessName, &pSDActMonContext->usFullFileName, NULL);
					//DbgPrint("[POST CLEANUP] SendEntryToUI : %wZ\n", &pSDActMonContext->usFullFileName);
					Retstatus = AddInQue(Data, FltObjects, CALL_TYPE_F_NEW_FILE, &pSDActMonContext->usProcessName, &pSDActMonContext->usFullFileName);
				}
			}
			FltDeleteContext(pSDActMonContext);
			FltReleaseContext(pSDActMonContext);
		}
	}

	//DbgPrint("[SWAPNIL POST CLEANUP] BYE BYE\n");
	
	return Retstatus;
}


FLT_PREOP_CALLBACK_STATUS ActMonPreWrite(_Inout_ PFLT_CALLBACK_DATA Data,_In_ PCFLT_RELATED_OBJECTS FltObjects,_Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
	NTSTATUS							status;
	PSDACTMON_STREAM_HANDLE_CONTEXT		pSDActMonContext = NULL;
	//PFLT_FILE_NAME_INFORMATION			nameInfo;
	HANDLE								hCurrentProcID = NULL;
	ULONG								dwCurProcessID = 0;
	//UNICODE_STRING						usProcessName = { 0 };

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(CompletionContext);
	
	PAGED_CODE();
	
	if (!gbIsProtectionOn)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	
	if ((!SDActMonData.UserProcess) || (IoThreadToProcess(Data->Thread) == SDActMonData.UserProcess))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (!FltObjects->Instance || !FltObjects->FileObject || (FlagOn(FltObjects->FileObject->Flags, FO_NAMED_PIPE)))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	/*
	if (KeGetCurrentIrql() > APC_LEVEL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	*/
	hCurrentProcID = PsGetCurrentProcessId();
	if (hCurrentProcID == NULL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	dwCurProcessID = (ULONG)hCurrentProcID;
	if (dwCurProcessID == 0 || dwCurProcessID == 4 || dwCurProcessID == 8)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (IsOurProcessByID(hCurrentProcID))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	/*
	usProcessName.Length = 0;
	usProcessName.MaximumLength = 512;
	usProcessName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usProcessName.MaximumLength, MAXSYSMON_POOL_POOL_TAG);

	
	if (usProcessName.Buffer == NULL || !usProcessName.Buffer)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (GetImageNameByID(hCurrentProcID, &usProcessName) == FALSE)
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
		}
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (usProcessName.Buffer)
	{
		ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
	}
	if (IsOurProcessFile(&usProcessName))
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
		}
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (usProcessName.Buffer)
	{
		ExFreePoolWithTag(usProcessName.Buffer, MAXSYSMON_POOL_POOL_TAG);
	}
	*/
	/*
	
	if ((Data->Iopb->TargetFileObject != NULL) && Data->Iopb->TargetFileObject && Data->Iopb->TargetFileObject->FileName.Buffer && (Data->Iopb->TargetFileObject->FileName.Buffer != NULL))
	{
		if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
		{
			if (NT_SUCCESS(FltParseFileNameInformation(nameInfo)))
			{
				FltReleaseFileNameInformation(nameInfo);
			}
		}
	}

	if (IsOurProcessByID(0))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	*/

	status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, &pSDActMonContext);
	if (NT_SUCCESS(status))
	{
		if (pSDActMonContext->usProcessName.Buffer)
		{
			if (IsOurProcessFile(&pSDActMonContext->usProcessName))
			{
				FltReleaseContext(pSDActMonContext);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
		}
		
		pSDActMonContext->RescanRequired = TRUE;
		FltReleaseContext(pSDActMonContext);
	}
	
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/*-------------------------------------------------------------------------------------
	Function		: DriverCreateCloseHandler
	In Parameters	: IN PDEVICE_OBJECT device, IN PIRP Irp
	Out Parameters	: NTSTATUS
	Purpose			: This handler is required to process the Create and Close IRP
					  without this hanlder the driver will not load.
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
NTSTATUS DriverCreateCloseHandler(IN PDEVICE_OBJECT device, IN PIRP Irp)
{
	UNREFERENCED_PARAMETER(device);

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: DriverCreateCloseHandler
	In Parameters	: IN PDEVICE_OBJECT device, IN PIRP Irp
	Out Parameters	: NTSTATUS
	Purpose			: This handler is required to handle the clean up process
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
NTSTATUS DriverCleanupHandler(IN PDEVICE_OBJECT device, IN PIRP Irp)
{
	UNREFERENCED_PARAMETER(device);

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: DriverUnloadHandler
	In Parameters	: IN PDRIVER_OBJECT driver
	Out Parameters	: NTSTATUS
	Purpose			: This handler unloades the driver
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void DriverUnloadHandler(IN PDRIVER_OBJECT driver)
{
	UNREFERENCED_PARAMETER(driver);
	return;
}

BOOLEAN IsFileWriteCall(__inout PFLT_CALLBACK_DATA Data)
{
	ULONG	CreateDisposition = 0x00;

	CreateDisposition = ((Data->Iopb->Parameters.Create.Options >> 24) & 0xFF);
	
	if (CreateDisposition == FILE_OPEN_IF)
	{
		return TRUE;
	}
	
	if (((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_DATA) == FILE_WRITE_DATA)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_EA) == FILE_WRITE_EA)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_APPEND_DATA) == FILE_APPEND_DATA)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & GENERIC_WRITE) == GENERIC_WRITE)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & GENERIC_ALL) == GENERIC_ALL)
		|| (((Data->Iopb->Parameters.Create.Options & 0xFF000000) == 0x02000000) &&
			((Data->Iopb->Parameters.Create.Options & 0x00000040) == 0x00000040))
		|| ((Data->Iopb->Parameters.Create.Options & 0xFF000000) == 0x00000000)
		|| ((Data->Iopb->Parameters.Create.Options & 0xFF000000) == 0x04000000)
		|| ((Data->Iopb->Parameters.Create.Options & 0xFF000000) == 0x05000000))
	{
		return TRUE;
	}
	else if (((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_DATA) == FILE_WRITE_DATA)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_EA) == FILE_WRITE_EA)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_APPEND_DATA) == FILE_APPEND_DATA)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & GENERIC_WRITE) == GENERIC_WRITE)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & GENERIC_ALL) == GENERIC_ALL))
	{
		return TRUE;
	}

	return FALSE;
}


/***************************************************************************
Routine Description:
	This routine is called by the filter manager when a new instance is created.
	We specified in the registry that we only want for manual attachments,
	so that is all we should receive here.
Arguments:
	FltObjects - Describes the instance and volume which we are being asked to
		setup.
	Flags - Flags describing the type of attachment this is.
	VolumeDeviceType - The DEVICE_TYPE for the volume to which this instance
		will attach.
	VolumeFileSystemType - The file system formatted on this volume.
Return Value:
  FLT_NOTIFY_STATUS_ATTACH              - we wish to attach to the volume
  FLT_NOTIFY_STATUS_DO_NOT_ATTACH       - no, thank you
***************************************************************************/
NTSTATUS SDActMonInstanceSetup(__in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_INSTANCE_SETUP_FLAGS Flags,
	__in DEVICE_TYPE VolumeDeviceType, __in FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
	PINSTANCE_CONTEXT InstCtx = NULL;
	NTSTATUS Status = STATUS_SUCCESS;

	//UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	ASSERT(FltObjects->Filter == SDActMonData.Filter);
	if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
	{
		return STATUS_FLT_DO_NOT_ATTACH;
	}
	//
	//  Allocate and initialize the instance context.
	//
	Status = FltAllocateContext(FltObjects->Filter, FLT_INSTANCE_CONTEXT, sizeof(INSTANCE_CONTEXT), NonPagedPool, &InstCtx);

	if (!NT_SUCCESS(Status))
	{
		
		goto InstanceSetupCleanup;
	}

	Status = FltCbdqInitialize(FltObjects->Instance,
		&InstCtx->Cbdq,
		CsqInsertIo,
		CsqRemoveIo,
		CsqPeekNextIo,
		CsqAcquire,
		CsqRelease,
		CsqCompleteCanceledIo);

	if (!NT_SUCCESS(Status))
	{
		goto InstanceSetupCleanup;
	}

	//
	//  Initialize the internal queue head and lock of the cancel safe queue.
	//
	InitializeListHead(&InstCtx->QueueHead);
	ExInitializeFastMutex(&InstCtx->Lock);

	//
	//  Initialize other members of the instance context.
	//
	InstCtx->Instance = FltObjects->Instance;
	InstCtx->WorkerThreadFlag = 0;
	KeInitializeEvent(&InstCtx->TeardownEvent, NotificationEvent, FALSE);

	//
	//  Set the instance context.
	//
	Status = FltSetInstanceContext(FltObjects->Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, InstCtx, NULL);

	if (!NT_SUCCESS(Status))
	{
		goto InstanceSetupCleanup;
	}

InstanceSetupCleanup:

	if (InstCtx != NULL)
	{
		FltReleaseContext(InstCtx);
	}

	return Status;
}

/***************************************************************************
***************************************************************************/
NTSTATUS AddInQue(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, ULONG ulTypeOfCall, PUNICODE_STRING pusProcessName, PUNICODE_STRING pusFullFileName)
{
	PINSTANCE_CONTEXT InstCtx = NULL;
	PQUEUE_CONTEXT QueueCtx = NULL;
	NTSTATUS CbStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	NTSTATUS Status;

	if (!gbIsProtectionOn)
	{
		goto JustCleanup;
	}

	if (ulTypeOfCall == CALL_TYPE_F_NEW_FILE)
	{
		CbStatus = FLT_POSTOP_FINISHED_PROCESSING;
	}

	
	
	if (SDActMonData.ClientPort == 0)
	{
		goto JustCleanup;
	}

	QueueCtx = ExAllocateFromNPagedLookasideList(&SDActMonData.QueueContextLookaside);
	if (QueueCtx == NULL)
	{
		goto JustCleanup;
	}

	RtlZeroMemory(QueueCtx, sizeof(QUEUE_CONTEXT));

	QueueCtx->ScanContext.Type_Of_Call = ulTypeOfCall;
	QueueCtx->ScanContext.usProcessName.Length = pusProcessName->Length;
	QueueCtx->ScanContext.usProcessName.MaximumLength = pusProcessName->MaximumLength;
	RtlCopyMemory(&QueueCtx->ScanContext.szProcessName, pusProcessName->Buffer, pusProcessName->Length);
	QueueCtx->ScanContext.usProcessName.Buffer = QueueCtx->ScanContext.szProcessName;
	//RtlCopyUnicodeString(&QueueCtx->ScanContext.usProcessName, pusProcessName);

	QueueCtx->ScanContext.usFullFileName.Length = pusFullFileName->Length;
	QueueCtx->ScanContext.usFullFileName.MaximumLength = pusFullFileName->MaximumLength;
	RtlCopyMemory(&QueueCtx->ScanContext.szFullFileName, pusFullFileName->Buffer, pusFullFileName->Length);
	QueueCtx->ScanContext.usFullFileName.Buffer = QueueCtx->ScanContext.szFullFileName;
	//RtlCopyUnicodeString(&QueueCtx->ScanContext.usFullFileName, pusFullFileName);
	//
	//  Get the instance context.
	//

	Status = FltGetInstanceContext(FltObjects->Instance, &InstCtx);

	if (!NT_SUCCESS(Status))
	{
		goto JustCleanup;
	}

	//
	//  Set the queue context
	//

	Data->QueueContext[0] = (PVOID)QueueCtx;
	Data->QueueContext[1] = NULL;

	//
	//  Insert the callback data into the cancel safe queue
	//

	Status = FltCbdqInsertIo(&InstCtx->Cbdq, Data, &QueueCtx->CbdqIoContext, 0);

	if (NT_SUCCESS(Status))
	{
		//
		//  In general, we can create a worker thread here as long as we can
		//  correctly handle the insert/remove race conditions b/w multi threads.
		//  In this sample, the worker thread creation is done in CsqInsertIo.
		//  This is a simpler solution because CsqInsertIo is atomic with 
		//  respect to other CsqXxxIo callback routines.
		//
		if (ulTypeOfCall == CALL_TYPE_F_NEW_FILE)
			CbStatus = FLT_POSTOP_MORE_PROCESSING_REQUIRED;
		else
			CbStatus = FLT_PREOP_PENDING;
	}
	//else
	//{
	//	//DbgPrint("[Csq]: Failed to insert into cbdq (Status = 0x%x) %d : %wZ : %wZ\n", Status, ulTypeOfCall, pusProcessName, pusFullFileName);
	//}

JustCleanup:

	//
	//  Clean up
	//

	if (QueueCtx && CbStatus != FLT_PREOP_PENDING && CbStatus != FLT_POSTOP_MORE_PROCESSING_REQUIRED)
	{
		ExFreeToNPagedLookasideList(&SDActMonData.QueueContextLookaside, QueueCtx);
	}

	if (InstCtx)
	{
		FltReleaseContext(InstCtx);
	}

	return CbStatus;
}

/***************************************************************************
Routine Description:
This routine is called at the start of instance teardown.
Arguments:
FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.
Flags - Reason why this instance is been deleted.
Return Value:
None.
***************************************************************************/
VOID SDActMonInstanceTeardownStart(__in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
	PINSTANCE_CONTEXT InstCtx = 0;
	NTSTATUS Status;

	//UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	Status = FltGetInstanceContext(FltObjects->Instance, &InstCtx);

	if (!NT_SUCCESS(Status))
	{
		return;
	}

	FltCbdqDisable(&InstCtx->Cbdq);
	
	EmptyQueueAndComplete(InstCtx);

	KeSetEvent(&InstCtx->TeardownEvent, 0, FALSE);

	//
	//  Cleanup
	//
	FltReleaseContext(InstCtx);
}

/***************************************************************************
Routine Description:
This routine is called at the end of instance teardown.
Arguments:
FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.
Flags - Reason why this instance is been deleted.
Return Value:
None.
***************************************************************************/
VOID SDActMonInstanceTeardownComplete(__in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();
	
}

/***************************************************************************
//  Cbdq callback routines.
***************************************************************************/
/***************************************************************************
Routine Description:
FltMgr calls this routine to acquire the lock protecting the queue.
Arguments:
DataQueue - Supplies a pointer to the queue itself.
Irql - Returns the previous IRQL if a spinlock is acquired.  We do not use
any spinlocks, so we ignore this.
Return Value:
None.
***************************************************************************/
VOID __drv_maxIRQL(APC_LEVEL) __drv_setsIRQL(APC_LEVEL) CsqAcquire(__in PFLT_CALLBACK_DATA_QUEUE DataQueue, __out PKIRQL Irql)
{
	PINSTANCE_CONTEXT InstCtx;

	UNREFERENCED_PARAMETER(Irql);

	//
	//  Get a pointer to the instance context.
	//
	InstCtx = CONTAINING_RECORD(DataQueue, INSTANCE_CONTEXT, Cbdq);

	//
	//  Acquire the lock.
	//
	ExAcquireFastMutex(&InstCtx->Lock);

}

/***************************************************************************
Routine Description:
FltMgr calls this routine to release the lock protecting the queue.
Arguments:
DataQueue - Supplies a pointer to the queue itself.
Irql - Supplies the previous IRQL if a spinlock is acquired.  We do not use
any spinlocks, so we ignore this.
Return Value:
None.
***************************************************************************/
VOID __drv_maxIRQL(APC_LEVEL) __drv_minIRQL(APC_LEVEL) __drv_setsIRQL(PASSIVE_LEVEL) CsqRelease(__in PFLT_CALLBACK_DATA_QUEUE DataQueue, __in KIRQL Irql)
{
	PINSTANCE_CONTEXT InstCtx;

	UNREFERENCED_PARAMETER(Irql);

	//
	//  Get a pointer to the instance context.
	//
	InstCtx = CONTAINING_RECORD(DataQueue, INSTANCE_CONTEXT, Cbdq);

	//
	//  Release the lock.
	//
	ExReleaseFastMutex(&InstCtx->Lock);

}

/***************************************************************************
Routine Description:
FltMgr calls this routine to insert an entry into our pending I/O queue.
The queue is already locked before this routine is called.
Arguments:
DataQueue - Supplies a pointer to the queue itself.
Data - Supplies the callback data for the operation that is being
inserted into the queue.
Context - Supplies user-defined context information.
Return Value:
STATUS_SUCCESS if the function completes successfully.  Otherwise a valid
NTSTATUS code is returned.
***************************************************************************/
NTSTATUS CsqInsertIo(__in PFLT_CALLBACK_DATA_QUEUE DataQueue, __in PFLT_CALLBACK_DATA Data, __in_opt PVOID Context)
{
	PINSTANCE_CONTEXT InstCtx;
	PFLT_GENERIC_WORKITEM WorkItem = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	BOOLEAN WasQueueEmpty;

	UNREFERENCED_PARAMETER(Context);

	
	//
	//  Get a pointer to the instance context.
	//
	InstCtx = CONTAINING_RECORD(DataQueue, INSTANCE_CONTEXT, Cbdq);

	//
	//  Save the queue state before inserting to it.
	//
	WasQueueEmpty = IsListEmpty(&InstCtx->QueueHead);

	//
	//  Insert the callback data entry into the queue.
	//
	InsertTailList(&InstCtx->QueueHead, &Data->QueueLinks);

	/*{
		if((PQUEUE_CONTEXT)Data->QueueContext[0])
		{
			PSDACTMON_STREAM_HANDLE_CONTEXT pScanContext = &((PQUEUE_CONTEXT)Data->QueueContext[0])->ScanContext;
		}
	}*/

	//
	//  Queue a work item if no worker thread present.
	//
	if (WasQueueEmpty && InterlockedIncrement(&InstCtx->WorkerThreadFlag) == 1)
	{
		WorkItem = FltAllocateGenericWorkItem();

		if (WorkItem)
		{
			Status = FltQueueGenericWorkItem(WorkItem,
				InstCtx->Instance,
				WorkItemRoutine,
				DelayedWorkQueue,
				InstCtx->Instance);
			if (!NT_SUCCESS(Status))
			{
				FltFreeGenericWorkItem(WorkItem);
			}
		}
		else
		{
			Status = STATUS_INSUFFICIENT_RESOURCES;
		}

		if (!NT_SUCCESS(Status))
		{
			//
			//  Remove the callback data that was inserted into the queue.
			//
			RemoveTailList(&InstCtx->QueueHead);
		}
	}
	return Status;
}

/***************************************************************************
Routine Description:
FltMgr calls this routine to remove an entry from our pending I/O queue.
The queue is already locked before this routine is called.
Arguments:
DataQueue - Supplies a pointer to the queue itself.
Data - Supplies the callback data that is to be removed.
Return Value:
None.
***************************************************************************/
VOID CsqRemoveIo(__in PFLT_CALLBACK_DATA_QUEUE DataQueue, __in PFLT_CALLBACK_DATA Data)
{
	UNREFERENCED_PARAMETER(DataQueue);

	
	/*{
		if((PQUEUE_CONTEXT)Data->QueueContext[0])
		{
			PSDACTMON_STREAM_HANDLE_CONTEXT pScanContext = &((PQUEUE_CONTEXT)Data->QueueContext[0])->ScanContext;
		}
	}*/

	//
	//  Remove the callback data entry from the queue.
	//
	RemoveEntryList(&Data->QueueLinks);
}

/***************************************************************************
Routine Description:
FltMgr calls this routine to look for an entry on our pending I/O queue.
The queue is already locked before this routine is called.
Arguments:
DataQueue - Supplies a pointer to the queue itself.
Data - Supplies the callback data we should start our search from.
If this is NULL, we start at the beginning of the list.
PeekContext - Supplies user-defined context information.
Return Value:
A pointer to the next callback data structure, or NULL.
***************************************************************************/
PFLT_CALLBACK_DATA CsqPeekNextIo(__in PFLT_CALLBACK_DATA_QUEUE DataQueue, __in_opt PFLT_CALLBACK_DATA Data, __in_opt PVOID PeekContext)
{
	PINSTANCE_CONTEXT InstCtx;
	PLIST_ENTRY NextEntry;
	PFLT_CALLBACK_DATA NextData;

	UNREFERENCED_PARAMETER(PeekContext);

	//
	//  Get a pointer to the instance context.
	//
	InstCtx = CONTAINING_RECORD(DataQueue, INSTANCE_CONTEXT, Cbdq);

	//
	//  If the supplied callback "Data" is NULL, the "NextIo" is the first entry
	//  in the queue; or it is the next list entry in the queue.
	//
	if (Data == NULL)
	{
		NextEntry = InstCtx->QueueHead.Flink;

	}
	else
	{
		NextEntry = Data->QueueLinks.Flink;
	}

	//
	//  Return NULL if we hit the end of the queue or the queue is empty.
	//
	if (NextEntry == &InstCtx->QueueHead)
	{
		//DbgPrint("[Csq]: Out CsqPeekNextIo\n");
		return NULL;
	}

	NextData = CONTAINING_RECORD(NextEntry, FLT_CALLBACK_DATA, QueueLinks);

	//DbgPrint("[Csq]: Out CsqPeekNextIo\n");
	return NextData;
}

/***************************************************************************
Routine Description:
FltMgr calls this routine to complete an operation as cancelled that was
previously pended. The queue is already locked before this routine is called.
Arguments:
DataQueue - Supplies a pointer to the queue itself.
Data - Supplies the callback data that is to be canceled.
Return Value:
None.
***************************************************************************/
VOID CsqCompleteCanceledIo(__in PFLT_CALLBACK_DATA_QUEUE DataQueue, __inout PFLT_CALLBACK_DATA Data)
{
	PQUEUE_CONTEXT QueueCtx;

	UNREFERENCED_PARAMETER(DataQueue);

	//DbgPrint("[Csq]: In CsqCompleteCanceledIo\n");

	QueueCtx = (PQUEUE_CONTEXT)Data->QueueContext[0];
	if (QueueCtx)
	{
		PSDACTMON_STREAM_HANDLE_CONTEXT pScanContext = &QueueCtx->ScanContext;
		if (pScanContext)
		{
			if (pScanContext->Type_Of_Call == CALL_TYPE_F_EXECUTE)
			{
				//
				//  Just complete the operation as canceled.
				//
				Data->IoStatus.Status = STATUS_CANCELLED;
				Data->IoStatus.Information = 0;
				FltCompletePendedPreOperation(Data, FLT_PREOP_COMPLETE, 0);
			}
			else
			{
				FltCompletePendedPostOperation(Data);
			}
		}
		//
		//  Free the extra storage that was allocated for this canceled I/O.
		//
		ExFreeToNPagedLookasideList(&SDActMonData.QueueContextLookaside, QueueCtx);
	}

	//DbgPrint("[Csq]: Out CsqCompleteCanceledIo\n");
}

/***************************************************************************
Routine Description:
This routine empties the cancel safe queue and complete all the
pended IO operations.
Arguments:
InstanceContext - Supplies a pointer to the instance context.
Return Value:
None.
***************************************************************************/
VOID EmptyQueueAndComplete(__in PINSTANCE_CONTEXT InstanceContext)
{
	//NTSTATUS status;
	PFLT_CALLBACK_DATA Data;

	//DbgPrint("[Csq]: In EmptyQueueAndComplete\n");
	if (InstanceContext)
	{

		do
		{
			Data = FltCbdqRemoveNextIo(&InstanceContext->Cbdq, NULL);
			if (Data)
			{
				PQUEUE_CONTEXT QueueCtx = (PQUEUE_CONTEXT)Data->QueueContext[0];
				if (QueueCtx)
				{
					PSDACTMON_STREAM_HANDLE_CONTEXT pScanContext = &QueueCtx->ScanContext;
					if (pScanContext)
					{
						if (pScanContext->Type_Of_Call == CALL_TYPE_F_EXECUTE)
							FltCompletePendedPreOperation(Data, FLT_PREOP_SUCCESS_NO_CALLBACK, NULL);
						else
							FltCompletePendedPostOperation(Data);
					}
					ExFreeToNPagedLookasideList(&SDActMonData.QueueContextLookaside, QueueCtx);
				}
			}
		} while (Data);
	}

	//DbgPrint("[Csq]: Out EmptyQueueAndComplete\n");
}

/***************************************************************************
Routine Description:
This WorkItem routine is called in the system thread context to process
all the pended I/O in this mini filter's cancel safe queue. For each I/O
in the queue, it completes the I/O after pending the operation for a
period of time. The thread exits when the queue is empty.
Arguments:
WorkItem - Unused.
Filter - Unused.
Context - Context information.
Return Value:
None.
***************************************************************************/
VOID WorkItemRoutine(__in PFLT_GENERIC_WORKITEM WorkItem, __in PFLT_FILTER Filter, __in PVOID Context)
{
	PINSTANCE_CONTEXT InstCtx = NULL;
	PFLT_CALLBACK_DATA Data;
	PFLT_INSTANCE Instance = (PFLT_INSTANCE)Context;
	NTSTATUS Status;

	UNREFERENCED_PARAMETER(WorkItem);
	UNREFERENCED_PARAMETER(Filter);

	//DbgPrint("[Csq]: In WorkItemRoutine\n");

	//
	//  Get a pointer to the instance context.
	//
	Status = FltGetInstanceContext(Instance, &InstCtx);

	if (!NT_SUCCESS(Status))
	{
		//DbgPrint("[Csq]: In WorkItemRoutine: Instance Context is missing\n");
		return;
	}

	//
	//  Process all the pended I/O in the cancel safe queue
	//
	for (;;)
	{
		//DbgPrint("[Csq]: Get Entry IN WorkItemRoutine!\n");

		//
		//  WorkerThreadFlag >= 1;
		//  Here we reduce it to 1.
		//
		InterlockedExchange(&InstCtx->WorkerThreadFlag, 1);

		//
		//  Remove an I/O from the cancel safe queue.
		//
		Data = FltCbdqRemoveNextIo(&InstCtx->Cbdq, NULL);

		if (Data)
		{
			PQUEUE_CONTEXT QueueCtx = (PQUEUE_CONTEXT)Data->QueueContext[0];
			if (QueueCtx)
			{
				PSDACTMON_STREAM_HANDLE_CONTEXT pScanContext = &QueueCtx->ScanContext;
				if (pScanContext)
				{
					BOOLEAN bAllowEntry = TRUE;

					//DbgPrint("[Csq]: [SEND TO UI] Type of Call: %d, WorkItemRoutine: %wZ : %wZ\n", pScanContext->Type_Of_Call, &pScanContext->usProcessName, &pScanContext->usFullFileName);
					bAllowEntry = SendEntryToUI(pScanContext->Type_Of_Call, &pScanContext->usProcessName, &pScanContext->usFullFileName, NULL);

					if (pScanContext->Type_Of_Call == CALL_TYPE_F_EXECUTE)
					{
						FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
						//DbgPrint("[Csq]: [CALL_TYPE_F_EXECUTE] WorkItemRoutine: %wZ : %wZ\n", &pScanContext->usProcessName, &pScanContext->usFullFileName);
						if (!bAllowEntry)
						{
							Data->IoStatus.Status = STATUS_ACCESS_DENIED;
							Data->IoStatus.Information = 0;
							callbackStatus = FLT_PREOP_COMPLETE;
							//DbgPrint("[Csq]: ##### BLOCKED 18: %wZ : %wZ\n", &pScanContext->usProcessName, &pScanContext->usFullFileName);
						}
						//  Complete the I/O
						FltCompletePendedPreOperation(Data, callbackStatus, NULL);
					}
					else if (pScanContext->Type_Of_Call == CALL_TYPE_F_NEW_FILE)
					{
						//DbgPrint("[Csq]: [CALL_TYPE_F_NEW_FILE] WorkItemRoutine: %wZ : %wZ\n", &pScanContext->usProcessName, &pScanContext->usFullFileName);
						//  Complete the I/O
						FltCompletePendedPostOperation(Data);
					}
					else
					{
						//DbgPrint("[Csq]: [UNKNOWN: %d] WorkItemRoutine: %wZ : %wZ\n", pScanContext->Type_Of_Call, &pScanContext->usProcessName, &pScanContext->usFullFileName);
					}
				}
				else
				{
					//DbgPrint("[Csq]: XXXXX WorkItemRoutine: pScanContext IS NULL!\n");
				}

				//
				//  Free the extra storage that was allocated for this I/O.
				//
				ExFreeToNPagedLookasideList(&SDActMonData.QueueContextLookaside, QueueCtx);
			}
		}
		else
		{
			//DbgPrint("[Csq]: XXXXX WorkItemRoutine: Data IS NULL!\n");

			//
			//  At this moment it is possible that a new IO is being inserted
			//  into the queue in the CsqInsertIo routine. Now that the queue is
			//  empty, CsqInsertIo needs to make a decision on whether to create
			//  a new worker thread. The decision is based on the race between
			//  the InterlockedIncrement in CsqInsertIo and the
			//  InterlockedDecrement as below. There are two situations:
			//
			//  (1) If the decrement executes earlier before the increment,
			//      the flag will be decremented to 0 so this worker thread
			//      will return. Then CsqInsertIo will increment the flag
			//      from 0 to 1, and therefore create a new worker thread.
			//  (2) If the increment executes earlier before the decrement,
			//      the flag will be first incremented to 2 in CsqInsertIo
			//      so a new worker thread will not be satisfied. Then the
			//      decrement as below will lower the flag down to 1, and
			//      therefore continue this worker thread.
			//
			if (InterlockedDecrement(&InstCtx->WorkerThreadFlag) == 0)
			{
				break;
			}
		}
	}

	//
	//  Clean up
	//

	FltReleaseContext(InstCtx);
	FltFreeGenericWorkItem(WorkItem);

	//DbgPrint("[Csq]: Out WorkItemRoutine\n");
}

/***************************************************************************
Routine Description:
	This is the instance detach routine for the filter. This
	routine is called by filter manager when a user initiates a manual instance
	detach. This is a 'query' routine: if the filter does not want to support
	manual detach, it can return a failure status
Arguments:
	FltObjects - Describes the instance and volume for which we are receiving
		this query teardown request.
	Flags - Unused
Return Value:
	STATUS_SUCCESS - we allow instance detach to happen
***************************************************************************/
NTSTATUS SDActMonQueryTeardown(__in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	//DbgPrint("In SDActMonQueryTeardown\n");

	return STATUS_SUCCESS;
}


/*-------------------------------------------------------------------------------------
	Function		: DriverDeviceControlHandler
	In Parameters	: IN PDEVICE_OBJECT device, IN PIRP Irp
	Out Parameters	: NTSTATUS
	Purpose			: This handler is used to communicate with the User Interface
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
NTSTATUS DriverDeviceControlHandler(IN PDEVICE_OBJECT device, IN PIRP Irp)
{
	/*
	PVOID inputBuffer = NULL;
	ULONG inputLength = 0x00;
	PVOID outputBuffer = NULL;
	ULONG outputLength= 0x00;
	*/
	UNREFERENCED_PARAMETER(device);
	PAGED_CODE();

	PIO_STACK_LOCATION loc = NULL;
	loc = IoGetCurrentIrpStackLocation(Irp);

	if (!loc)
	{
		Irp->IoStatus.Status = 0;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	if (loc->Parameters.DeviceIoControl.IoControlCode < (ULONG)IOCTL_PAUSE_PROTECTION && loc->Parameters.DeviceIoControl.IoControlCode > (ULONG)IOCTL_USB_ACTIVITY_LOG)
	{
		Irp->IoStatus.Status = 0;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	
	
	//inputLength = loc->Parameters.DeviceIoControl.InputBufferLength;
	//outputLength = loc->Parameters.DeviceIoControl.OutputBufferLength;
	//outputBuffer = Irp->AssociatedIrp.SystemBuffer;
	//inputBuffer = outputBuffer;

	if (loc->Parameters.DeviceIoControl.IoControlCode == (ULONG)IOCTL_PAUSE_PROTECTION)
	{
		gbIsProtectionOn = FALSE;
		DbgPrint("##### Pause Protection Event Received!\n");
	}
	if (loc->Parameters.DeviceIoControl.IoControlCode == (ULONG)IOCTL_RESUME_PROTECTION)
	{
		gbIsProtectionOn = TRUE;
		//DbgPrint("##### Resume Protection Event Received!\n");
	}

	if (loc->Parameters.DeviceIoControl.IoControlCode == (ULONG)IOCTL_REGISTER_PROCESSID)
	{
		DWORD* pdwProcessName = 0;
		pdwProcessName = (DWORD*)Irp->AssociatedIrp.SystemBuffer;
		if (*pdwProcessName < MAX_PROC_MAX_PROC_LAST_ENTRY)
		{
			dwProcessIDList[*pdwProcessName] = (DWORD)PsGetCurrentProcessId();
		}
	}
	
	if (loc->Parameters.DeviceIoControl.IoControlCode == (ULONG)IOCTL_USB_TOTAL_BLOCK)
	{
		PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
		if (inputBuffer)
		{
			g_bTotalBlock = *(ULONG*)inputBuffer;
			DbgPrint("IOCTL_USB_TOTAL_BLOCK = %d\n", g_bTotalBlock);
		}
	}
	
	if (loc->Parameters.DeviceIoControl.IoControlCode == (ULONG)IOCTL_USB_WRITE_BLOCK)
	{
		PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
		if (inputBuffer)
		{
			g_bWriteBlock = *(ULONG*)inputBuffer;
			DbgPrint("IOCTL_USB_WRITE_BLOCK = %d\n", g_bWriteBlock);
		}
	}

	if (loc->Parameters.DeviceIoControl.IoControlCode == (ULONG)IOCTL_USB_EXECUTE_BLOCK)
	{
		PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
		if (inputBuffer)
		{
			g_bExecuteBlock = *(ULONG*)inputBuffer;
			DbgPrint("IOCTL_USB_EXECUTE_BLOCK = %d\n", g_bExecuteBlock);
		}
	}

	if (loc->Parameters.DeviceIoControl.IoControlCode == (ULONG)IOCTL_USB_READ_BLOCK)
	{
		PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
		if (inputBuffer)
		{
			g_bReadBlock = *(ULONG*)inputBuffer;
			DbgPrint("IOCTL_USB_READ_BLOCK = %d\n", g_bReadBlock);
		}
	}

	if (loc->Parameters.DeviceIoControl.IoControlCode == (ULONG)IOCTL_USB_ACTIVITY_LOG)
	{
		PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
		if (inputBuffer)
		{
			g_bActivityLog = *(ULONG*)inputBuffer;
			DbgPrint("IOCTL_USB_ACTIVITY_LOG = %d\n", g_bActivityLog);
		}
	}
	
	//Tushar Kadam : This Part is Added to reduce removable media checking unneccesary call
	if (g_bReadBlock != 0x00 || g_bExecuteBlock != 0x00 || g_bWriteBlock != 0x00 || g_bTotalBlock != 0x00 || g_bActivityLog != 0x00 || g_bActivityDLP != 0x00)
	{
		g_bMonitorUSB = 0x01;
	}
	
	Irp->IoStatus.Status = 0;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: IsAllowedState
	In Parameters	:  __in PFLT_CALLBACK_DATA Data,__in PCFLT_RELATED_OBJECTS FltObjects,__in FLT_POST_OPERATION_FLAGS Flags
	Out Parameters	: BOOLEAN
	Purpose			: To filter out FltObject flags
	Author			: Himanshu Sonkar
--------------------------------------------------------------------------------------*/

BOOLEAN IsAllowedStateCreate(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_POST_OPERATION_FLAGS Flags
)
{
	PIRP pGetIrp;
	if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) ||
		!FltObjects->Instance || !FltObjects->FileObject ||
		FlagOn(FltObjects->FileObject->Flags, FO_NAMED_PIPE)
		)
	{
		return TRUE;
	}

	//Check if pGetIrp return Non Null value, if yes then skip it. It may cause deadlocks.
	pGetIrp = IoGetTopLevelIrp();
	if (pGetIrp)
	{
		return TRUE;
	}

	return FALSE;
}

BOOLEAN GetUsbSettingsData(PUNICODE_STRING pusRegistryPath, const PUNICODE_STRING pusValueName)
{
	BOOLEAN bStatus = FALSE;
	HANDLE   handle = NULL;
	NTSTATUS ntstatus = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES  objRegPath = { 0 };
	PKEY_VALUE_PARTIAL_INFORMATION pValueInfo = NULL;
	ULONG ulResultLength = 0;

	InitializeObjectAttributes(&objRegPath, pusRegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	ntstatus = ZwOpenKey(&handle, KEY_READ, &objRegPath);
	if ((!NT_SUCCESS(ntstatus)) || (!handle))
	{
		return bStatus;
	}

	pValueInfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + MAX_PATH, MAXSYSMON_POOL_POOL_TAG);
	if (pValueInfo)
	{
		memset(pValueInfo, 0, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + MAX_PATH);
		ntstatus = ZwQueryValueKey(handle, pusValueName, KeyValuePartialInformation, pValueInfo,
			sizeof(KEY_VALUE_PARTIAL_INFORMATION) + MAX_PATH, &ulResultLength);
		if (!NT_SUCCESS(ntstatus))
		{
			if (pValueInfo)
			{
				ExFreePoolWithTag(pValueInfo, MAXSYSMON_POOL_POOL_TAG);
			}
			ZwClose(handle);
			return bStatus;
		}

		{
			PULONG pdwData = (PULONG)pValueInfo->Data;
			if (*pdwData == 1)
				bStatus = TRUE;
			else
				bStatus = FALSE;
		}
		if (pValueInfo)
		{
			ExFreePoolWithTag(pValueInfo, MAXSYSMON_POOL_POOL_TAG);
		}
	}
	ZwClose(handle);

	return bStatus;
}

//0 : Not a Removable Media
//1 : USB Media
//2 : CD / DVD Media
int IsRemovableMedia(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
	ULONG						ReturnedLength = 0;
	int							iRetValue = 0x00;
	NTSTATUS					status = STATUS_SUCCESS;
	UCHAR						RMBuffer[sizeof(FLT_VOLUME_PROPERTIES) + 512];
	PFLT_VOLUME_PROPERTIES		VmProperties = (PFLT_VOLUME_PROPERTIES)RMBuffer;

	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Data);

	status = FltGetVolumeProperties(FltObjects->Volume,
		VmProperties,
		sizeof(RMBuffer),
		&ReturnedLength);

	if (NT_SUCCESS(status))
	{
		// DbgPrint("Get Volume properties successful\n");
		if (VmProperties->DeviceType == FILE_DEVICE_MASS_STORAGE)
		{
			DbgPrint("FILE_DEVICE_MASS_STORAGE\n");
		}

		if (VmProperties->DeviceType == FILE_DEVICE_CD_ROM)
		{
			DbgPrint("FILE_DEVICE_CD_ROM\n");
			iRetValue = 0x02;
		}

		if (VmProperties->DeviceType == FILE_DEVICE_DISK)
		{
			DbgPrint("FILE_DEVICE_DISK\n");
		}

		if (VmProperties->DeviceType == FILE_DEVICE_DVD)
		{
			DbgPrint("FILE_DEVICE_DVD\n");
			iRetValue = 0x02;
		}

		if (VmProperties->DeviceType == FILE_DEVICE_NETWORK)
		{
			DbgPrint("FILE_DEVICE_NETWORK\n");
		}

		if (VmProperties->DeviceType == FILE_DEVICE_VIRTUAL_DISK)
		{
			DbgPrint("FILE_DEVICE_VIRTUAL_DISK\n");
		}

		if (VmProperties->DeviceType == FILE_DEVICE_DISK_FILE_SYSTEM)
		{
			PDEVICE_OBJECT  pDevObj;
			if (NT_SUCCESS(FltGetDiskDeviceObject(FltObjects->Volume, &pDevObj)))
			{
				if (pDevObj)
				{
					if (pDevObj->Characteristics & FILE_REMOVABLE_MEDIA)
					{
						iRetValue = 0x01;
					}
				}
			}
		}
	}
	return iRetValue;
}

int IsUSBExecuteCall(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
	int	 iExecCall = 0;

	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(FltObjects);


	if (g_bExecuteBlock == 1 || g_bActivityLog == 1 || g_bActivityDLP == 1)
	{
		if (((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_READ_DATA) == FILE_READ_DATA)
			|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES)
			|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_READ_EA) == FILE_READ_EA)
			|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & GENERIC_READ) == GENERIC_READ)
			|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & SYNCHRONIZE) == SYNCHRONIZE))
		{
			if ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_EXECUTE) == FILE_EXECUTE)
			{
				//DbgPrint("Read call coming\n");
				if (g_bExecuteBlock == 1 && (g_bActivityLog == 1 || g_bActivityDLP == 1))
				{
					iExecCall = 0x03;
				}
				else if (g_bExecuteBlock == 1)
				{
					iExecCall = 0x01;
				}
				else if ((g_bActivityLog == 1 || g_bActivityDLP == 1))
				{
					iExecCall = 0x02;
				}
			}
		}
	}

	return iExecCall;
}


int IsUSBReadCall(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
	//BOOLEAN bReadCall = FALSE;
	int iReadCall = 0x00;

	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(FltObjects);

	if (g_bReadBlock == 1 || g_bActivityLog == 1 || g_bActivityDLP == 1)
	{
		if (((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_READ_DATA) == FILE_READ_DATA)
			|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES)
			|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_READ_EA) == FILE_READ_EA)
			|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & GENERIC_READ) == GENERIC_READ))
		{
			//DbgPrint("Read call coming\n");
			if (g_bReadBlock == 1 && (g_bActivityLog == 1 || g_bActivityDLP == 1))
			{
				iReadCall = 0x03;
			}
			else if (g_bReadBlock == 1)
			{
				iReadCall = 0x01;
			}
			else if ((g_bActivityLog == 1 || g_bActivityDLP == 1))
			{
				iReadCall = 0x02;
			}
		}
	}
	
	return iReadCall;
}

int IsUSBWriteCall(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
	int		iWriteCall = 0x00;
	ULONG	CreateDisposition;

	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(FltObjects);

	if (g_bWriteBlock == 1 || g_bActivityLog == 1 || g_bActivityDLP == 1)
	{
		if (IsFileWriteCall(Data))
		{
			if (g_bWriteBlock == 1 && (g_bActivityLog == 1 || g_bActivityDLP == 1))
			{
				iWriteCall = 0x03;
			}
			else if (g_bWriteBlock == 1)
			{
				iWriteCall = 0x01;
			}
			else if ((g_bActivityLog == 1 || g_bActivityDLP == 1))
			{
				iWriteCall = 0x02;
			}
		}
		CreateDisposition = ((Data->Iopb->Parameters.Create.Options >> 24) & 0xFF);
		if (CreateDisposition == FILE_OPEN_IF)
		{
			//DbgPrint("Write call coming\n");
			if (g_bWriteBlock == 1 && (g_bActivityLog == 1 || g_bActivityDLP == 1))
			{
				iWriteCall = 0x03;
			}
			else if (g_bWriteBlock == 1)
			{
				iWriteCall = 0x01;
			}
			else if ((g_bActivityLog == 1 || g_bActivityDLP == 1))
			{
				iWriteCall = 0x02;
			}
		}

	}

	return iWriteCall;
}

/*-------------------------------------------------------------------------------------
	Function		: SkipInPostCreate
	In Parameters	:  __in PFLT_CALLBACK_DATA Data,__in PCFLT_RELATED_OBJECTS FltObjects,__in FLT_POST_OPERATION_FLAGS Flags
	Out Parameters	: BOOLEAN
	Purpose			: To filter out Post create Flags
	Author			: Himanshu Sonkar
--------------------------------------------------------------------------------------*/

BOOLEAN IsPostCreateSkip(
	__in PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_POST_OPERATION_FLAGS Flags
)
{
	if (!NT_SUCCESS(Data->IoStatus.Status) ||
		(Data->IoStatus.Status == STATUS_REPARSE) ||
		FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN) ||
		IsAllowedStateCreate(FltObjects, Flags))
	{
		return TRUE;
	}

	return FALSE;
}

BOOLEAN IsOurProcessByID(HANDLE dwProcessID)
{
	int		iNoOfProcessID = 0;
	if (dwProcessID == 0)
	{
		dwProcessID = PsGetCurrentProcessId();
	}
	if (dwProcessID == 0)
	{
		return TRUE;
	}
	for (; iNoOfProcessID < MAX_PROC_MAX_PROC_LAST_ENTRY; iNoOfProcessID++)
	{
		if (dwProcessIDList[iNoOfProcessID] == (DWORD)dwProcessID)
		{
			return TRUE;
		}
	}
	return FALSE;
}

int CheckIsWinDll(PUNICODE_STRING pEntryPath)
{
	BOOLEAN			bFoundMax = FALSE;
	UNICODE_STRING	usUpperPath = { 0 };
	int				iIndex = 0;

	int iFullLen = (pEntryPath->Length / 2); //unicode string len

	if (!pEntryPath->Buffer) //check for NULL
	{
		return -1;
	}

	if (iFullLen <= 17)
	{
		return -1;
	}

	RtlUpcaseUnicodeString(&usUpperPath, pEntryPath, TRUE);
	if (!usUpperPath.Buffer) //check for NULL
	{
		return -1;
	}

	if (usUpperPath.Length <= 11) //check for len
	{
		RtlFreeUnicodeString(&usUpperPath);
		return -1;
	}

	while (iIndex < (iFullLen - 11))
	{
		if (usUpperPath.Buffer[iIndex] == '\\')
		{
			if ((RtlCompareMemory(&usUpperPath.Buffer[iIndex], L"\\WINDOWS\\", 9) == 9) ||
				(RtlCompareMemory(&usUpperPath.Buffer[iIndex], L"\\PROGRAM FILES", 14) == 14))
			{

				iIndex++;
				bFoundMax = TRUE;
				break;
			}
		}
		iIndex++;
	}
	if (bFoundMax == TRUE)
	{
		RtlFreeUnicodeString(&usUpperPath);
		return iIndex;
	}

	RtlFreeUnicodeString(&usUpperPath);
	return -1;
}

int IsNeedToCheckEncryption(PUNICODE_STRING pEntryPath, PUNICODE_STRING pFileExt)
{
	BOOLEAN			bFoundMax = FALSE;
	UNICODE_STRING	usUpperPath = { 0 };
	UNICODE_STRING	usUpperExt = { 0 };
	int				iIndex = 0;

	int iFullLen = (pEntryPath->Length / 2); //unicode string len

	if (!pEntryPath->Buffer) //check for NULL
	{
		return -1;
	}

	if (iFullLen == 6)
	{
		if (RtlCompareMemory(&pEntryPath->Buffer[0x00], L"System", 6) == 6)
		{
			return 0;
		}
	}

	if (iFullLen <= 17) //should atleast have \Device\HarddiskVolume1 or \Registry\Machine (considering the smaller len)
	{
		return -1;
	}

	RtlUpcaseUnicodeString(&usUpperPath, pEntryPath, TRUE);
	if (!usUpperPath.Buffer) //check for NULL
	{
		return -1;
	}

	RtlUpcaseUnicodeString(&usUpperExt, pFileExt, TRUE);
	if (!usUpperExt.Buffer) //check for NULL
	{
		return -1;
	}

	if ((RtlCompareMemory(&usUpperExt.Buffer[0x00], L"EXE", 6) == 6) || (RtlCompareMemory(&usUpperExt.Buffer[0x00], L"DLL", 6) == 6))
	{
		RtlFreeUnicodeString(&usUpperPath);
		RtlFreeUnicodeString(&usUpperExt);
		return -1;
	}

	//DbgPrint("##### CheckIsWinProgDir Name: %wZ\n", usUpperPath);
	while (iIndex < (iFullLen - 4))
	{
		if (usUpperPath.Buffer[iIndex] == '\\') // we are only interested in path containing '\MAX ' in them
		{
			// break if found '\MAX ' in the path
			if ((RtlCompareMemory(&usUpperPath.Buffer[iIndex], L"\\!-\\", 8) == 8))
			{
				iIndex++;
				bFoundMax = TRUE;
				break;
			}
			if ((RtlCompareMemory(&usUpperPath.Buffer[iIndex], L"\\~!-\\", 10) == 10))
			{
				iIndex++;
				bFoundMax = TRUE;
				break;
			}
			if ((RtlCompareMemory(&usUpperPath.Buffer[iIndex], L"\\!-SCPGT", 16) == 16))
			{
				iIndex++;
				bFoundMax = TRUE;
				break;
			}
			if ((RtlCompareMemory(&usUpperPath.Buffer[iIndex], L"\\DESKTOP\\", 18) == 18))
			{
				iIndex++;
				bFoundMax = TRUE;
				break;
			}
			if ((RtlCompareMemory(&usUpperPath.Buffer[iIndex], L"\\DOCUMENTS\\", 22) == 22))
			{
				iIndex++;
				bFoundMax = TRUE;
				break;
			}
			if ((RtlCompareMemory(&usUpperPath.Buffer[iIndex], L"\\PICTURES\\", 20) == 20))
			{
				iIndex++;
				bFoundMax = TRUE;
				break;
			}
			if ((RtlCompareMemory(&usUpperPath.Buffer[iIndex], L"\\VIDEOS\\", 16) == 16))
			{
				iIndex++;
				bFoundMax = TRUE;
				break;
			}
			if ((RtlCompareMemory(&usUpperPath.Buffer[iIndex], L"\\MUSIC\\", 14) == 14))
			{
				iIndex++;
				bFoundMax = TRUE;
				break;
			}
		}
		iIndex++;
	}
	if (bFoundMax == TRUE)
	{
		RtlFreeUnicodeString(&usUpperPath);
		RtlFreeUnicodeString(&usUpperExt);
		//DbgPrint("##### IGNORING WINDOWS DLL, Name: %wZ\n", pEntryPath);
		return iIndex;
	}

	RtlFreeUnicodeString(&usUpperPath);
	RtlFreeUnicodeString(&usUpperExt);
	return -1;
}