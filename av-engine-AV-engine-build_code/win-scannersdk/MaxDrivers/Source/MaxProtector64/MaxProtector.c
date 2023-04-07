#include "MaxProtector.h"
#include <fltKernel.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include "MaxCommon.h"
//#ifndef __MAXPROTECTOR_COMMON_H__
//	#include "MaxCommon.h"
//#endif 

#define DbgPrint
//#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

typedef struct _MAXPROTECTOR_DATA
{
	PDRIVER_OBJECT DriverObject;
	PFLT_FILTER Filter;
} MAXPROTECTOR_DATA, * PMAXPROTECTOR_DATA;

MAXPROTECTOR_DATA MaxProtectorData = { 0 };
LARGE_INTEGER iMaxProtectorRegistryFilter = { 0 };

BOOLEAN gbIsProtectionOn = FALSE;
BOOLEAN gbIsProdInstallation = FALSE;
BOOLEAN bIsUSBMonOn = FALSE;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, RegistryCallback)
#pragma alloc_text(PAGE, MaxProtectorUnload)
#pragma alloc_text(PAGE, MaxProtectorInstanceSetup)
#pragma alloc_text(PAGE, MaxProtectorPreCreate)
#pragma alloc_text(PAGE, MaxProtectorPostCreate)
#pragma alloc_text(PAGE,MaxObjectPreCallback)
#endif

const FLT_OPERATION_REGISTRATION Callbacks[] =
{
	{IRP_MJ_CREATE,				0, MaxProtectorPreCreate, NULL},
	{IRP_MJ_SET_INFORMATION,	0, MaxProtectorPreCreate, MaxProtectorPostCreate},
	{IRP_MJ_OPERATION_END}
};

const FLT_REGISTRATION FilterRegistration =
{
	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags
	0,									//  Context Registration.
	Callbacks,                          //  Operation callbacks
	MaxProtectorUnload,                 //  FilterUnload
	MaxProtectorInstanceSetup,          //  InstanceSetup
	MaxProtectorQueryTeardown,          //  InstanceQueryTeardown
	NULL,                               //  InstanceTeardownStart
	NULL,                               //  InstanceTeardownComplete
	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent
};

/*-------------------------------------------------------------------------------------
	Function		: DriverEntry
	In Parameters	: IN PDRIVER_OBJECT driver, IN PUNICODE_STRING path
	Out Parameters	: NTSTATUS
	Purpose			: The entry point for our Driver. Setup the IRP handlers.
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
NTSTATUS DriverEntry(__in PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	PDEVICE_OBJECT devobject = 0;
	GUID MAX_CLASS_GUID = { 0 };

	//UNREFERENCED_PARAMETER( RegistryPath );
	gbIsProtectionOn = FALSE;
	gbIsProcProtectionOn = FALSE;
	g_hProcCreateHandle = NULL;
	/*
	bRestrictAutorun = FALSE;
	bRestrictUSBWrite = FALSE;
	bRestrictUSBExecute = FALSE;
	bProtectSystemRegistry = FALSE;
	*/

	//IoCreateDevice(DriverObject, MAX_PATH, &PROTECTORDEVICENAME, FILE_DEVICE_FILE_SYSTEM, 0, FALSE, &devobject);
	IoCreateDeviceSecure(DriverObject, MAX_PATH, &PROTECTORDEVICENAME, FILE_DEVICE_FILE_SYSTEM, FILE_DEVICE_SECURE_OPEN, FALSE, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RWX_RES_RWX, (struct _GUID*)&MAX_CLASS_GUID, &devobject);

	IoCreateSymbolicLink(&PROTECTORDEVICELINK, &PROTECTORDEVICENAME);

	/*
	usDriverRegistryEntry.Length = 0;
	usDriverRegistryEntry.MaximumLength = GetMaxLen(RegistryPath);
	usDriverRegistryEntry.Buffer = ExAllocatePoolWithTag(NonPagedPool, usDriverRegistryEntry.MaximumLength, BLOCKTROJAN_POOL_POOL_TAG);

	if (usDriverRegistryEntry.Buffer)
	{
		RtlUnicodeStringCopy(&usDriverRegistryEntry, RegistryPath);
		LoadTrojanList(&usDriverRegistryEntry);

	}

	m_usFolSecINIPath.Length = 0;
	m_usFolSecINIPath.MaximumLength = GetMaxLen(RegistryPath);
	m_usFolSecINIPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, m_usFolSecINIPath.MaximumLength, BLOCKTROJAN_POOL_POOL_TAG);

	if (m_usFolSecINIPath.Buffer)
	{
		RtlUnicodeStringCopy(&m_usFolSecINIPath, RegistryPath);
	}
	*/

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControlHandler;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateCloseHandler;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateCloseHandler;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = DriverCleanupHandler;
	DriverObject->DriverUnload = DriverUnloadHandler;

	bRestrictAutorun = ShouldWeBlock(RegistryPath, &AUTORUN_REG_VALUE);
	bProtectSystemRegistry = ShouldWeBlock(RegistryPath, &PROTECT_SYS_REG_VALUE);
	//bRestrictUSBWrite = ShouldWeBlock(RegistryPath, &USB_WRITE_REG_VALUE);				// Not in use
	//bRestrictUSBExecute = ShouldWeBlock(RegistryPath, &USB_EXECUTE_REG_VALUE);			// Not in use
	
	MaxProtectorData.DriverObject = DriverObject;
	status = FltRegisterFilter(DriverObject, &FilterRegistration, &MaxProtectorData.Filter);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	else
	{
		RegisteCallbackFunction();
	}

	status = FltStartFiltering(MaxProtectorData.Filter);
	if (NT_SUCCESS(status))
	{
		if (RegisterProtectionFilterDriver(DriverObject))
		{
			ResetAllDrivesProtection();
			gbIsProtectionOn = TRUE;

			return STATUS_SUCCESS;
		}
	}
	FltUnregisterFilter(MaxProtectorData.Filter);
	return status;
}


/***************************************************************************
Routine Description:
	Pre create callback.  We need to remember whether this file has been
	opened for write access.  If it has, we'll want to rescan it in cleanup.
	This scheme results in extra scans in at least two cases:
	-- if the create fails (perhaps for access denied)
	-- the file is opened for write access but never actually written to
	The assumption is that writes are more common than creates, and checking
	or setting the context in the write path would be less efficient than
	taking a good guess before the create.
Arguments:
	Data - The structure which describes the operation parameters.
	FltObject - The structure which describes the objects affected by this
		operation.
	CompletionContext - Output parameter which can be used to pass a context
		from this pre-create callback to the post-create callback.
Return Value:
   FLT_PREOP_SUCCESS_WITH_CALLBACK - If this is not our user-mode process.
   FLT_PREOP_SUCCESS_NO_CALLBACK - All other threads.
***************************************************************************/
FLT_PREOP_CALLBACK_STATUS MaxProtectorPreCreate(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID* CompletionContext)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

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
		FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)/* ||
		IsAllowedStateCreate(FltObjects, 0)*/)
	{

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (Data->RequestorMode == KernelMode)
	{
		//DbgPrint("[%05d] ##### Requestor is a kernel driver!\n", PsGetCurrentProcessId());
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (!CheckFileEntry(Data, FltObjects)) // Block file access!
	{
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}
	
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/***************************************************************************
Routine Description:
	Post create callback.  We can't scan the file until after the create has
	gone to the filesystem, since otherwise the filesystem wouldn't be ready
	to read the file for us.
Arguments:
	Data - The structure which describes the operation parameters.
	FltObject - The structure which describes the objects affected by this
		operation.
	CompletionContext - The operation context passed fron the pre-create
		callback.
	Flags - Flags to say why we are getting this post-operation callback.
Return Value:
	FLT_POSTOP_FINISHED_PROCESSING - ok to open the file or we wish to deny
									 access to this file, hence undo the open
***************************************************************************/
FLT_POSTOP_CALLBACK_STATUS MaxProtectorPostCreate(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Data);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

/*-------------------------------------------------------------------------------------
	Function		: DriverUnloadHandler
	In Parameters	: IN PDRIVER_OBJECT driver
	Out Parameters	: NTSTATUS
	Purpose			: This handler helps in unhooking the server dispatch table (SDT)
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void DriverUnloadHandler(IN PDRIVER_OBJECT driver)
{
	gbIsProtectionOn = FALSE;
	gbIsProcProtectionOn = FALSE;
	ResetAllDrivesProtection();
	UnRegisteCallbackFunction();
	CleanUpDriver();
	/*
	UnLoadTrojanList();

	if (usDriverRegistryEntry.Buffer)
	{
		ExFreePoolWithTag(usDriverRegistryEntry.Buffer, BLOCKTROJAN_POOL_POOL_TAG);
	}

	if (m_usFolSecINIPath.Buffer)
	{
		ExFreePoolWithTag(m_usFolSecINIPath.Buffer, BLOCKTROJAN_POOL_POOL_TAG);
	}
	*/
	
	IoDeleteSymbolicLink(&PROTECTORDEVICELINK);
	IoDeleteDevice(driver->DeviceObject);
	
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
	Function		: DriverCleanupHandler
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
	Function		: DriverDeviceControlHandler
	In Parameters	: IN PDEVICE_OBJECT device, IN PIRP Irp
	Out Parameters	: NTSTATUS
	Purpose			: This handler helps in hooking the server dispatch table (SDT)
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
NTSTATUS DriverDeviceControlHandler(IN PDEVICE_OBJECT device, IN PIRP Irp)
{
	UNREFERENCED_PARAMETER(device);

	PIO_STACK_LOCATION loc = IoGetCurrentIrpStackLocation(Irp);

	if (loc->Parameters.DeviceIoControl.IoControlCode == (ULONG)IOCTL_PAUSE_PROTECTION)
	{
		gbIsProtectionOn = FALSE;
		//DbgPrint("##### Pause Protection Event Received!\n");
	}
	else if (loc->Parameters.DeviceIoControl.IoControlCode == (ULONG)IOCTL_RESUME_PROTECTION)
	{
		gbIsProtectionOn = TRUE;
		//DbgPrint("##### Resume Protection Event Received!\n");
	}
	else if (loc->Parameters.DeviceIoControl.IoControlCode == (ULONG)IOCTL_BLOCK_USB_DRIVE)
	{
		int iPos = 0;
		WCHAR* wDriveLetter = 0;
		wDriveLetter = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;
		iPos = ((int)wDriveLetter[0] - 0x41);
		if (iPos > -1 && iPos < 26)
		{
			SetTotalBlock(iPos, TRUE);
			SetWriteBlock(iPos, bRestrictUSBWrite);
			SetExecuteBlock(iPos, bRestrictUSBExecute);
			bIsUSBMonOn = TRUE;
			//DbgPrint("Total Block Event Received For Drive: %S\n", wDriveLetter);
		}
	}
	else if ((loc->Parameters.DeviceIoControl.IoControlCode == (ULONG)IOCTL_UNBLOCK_USB_DRIVE)
		|| (loc->Parameters.DeviceIoControl.IoControlCode == (ULONG)IOCTL_DISCONNECT_USB_DRIVE))
	{
		int iPos = 0;
		WCHAR* wDriveLetter = 0;
		wDriveLetter = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;
		iPos = ((int)wDriveLetter[0] - 0x41);

		//DbgPrint("Inside Disconnect Event Received For Drive: %S\n", wDriveLetter);

		if (iPos > -1 && iPos < 26)
		{
			SetTotalBlock(iPos, FALSE);
			if (loc->Parameters.DeviceIoControl.IoControlCode == (ULONG)IOCTL_DISCONNECT_USB_DRIVE)
			{
				SetWriteBlock(iPos, FALSE);
				SetExecuteBlock(iPos, FALSE);
				//DbgPrint("Disconnect Event Received For Drive: %S\n", wDriveLetter);
			}
			bIsUSBMonOn = IsUSBProtectionOn();
		}
		else if (wDriveLetter[0] == L'-')
		{
			ResetAllDrivesProtection();
			bIsUSBMonOn = FALSE;
			//DbgPrint("Disconnect Event Received For Drive: %S (ALL DRIVES)\n", wDriveLetter);
		}
	}
	else if (loc->Parameters.DeviceIoControl.IoControlCode == IOCTL_REGISTER_PROCESSID)
	{
		DWORD* pdwProcessName = 0;
		pdwProcessName = (DWORD*)Irp->AssociatedIrp.SystemBuffer;
		if ((*pdwProcessName < MAX_PROC_MAX_PROC_LAST_ENTRY) && (*pdwProcessName != MAX_PROC_OUTLOOK))
		{
			dwProcessIDList[*pdwProcessName] = (DWORD)PsGetCurrentProcessId();
			//DbgPrint(">>>>>> (1) Registered ProcessID: %d, Array Location: %d\n", dwProcessIDList[*pdwProcessName], *pdwProcessName);
		}
	}
	else if(loc->Parameters.DeviceIoControl.IoControlCode == IOCTL_INSTALL_PROTECTION)
	{
		gbIsProdInstallation = TRUE;
	}
	else if (loc->Parameters.DeviceIoControl.IoControlCode == IOCTL_STOP_INSTALL_PROTECTION)
	{
		gbIsProdInstallation = FALSE;
	}
	/*
	else if (loc->Parameters.DeviceIoControl.IoControlCode == IOCTL_RELOAD_INI)
	{
		//DbgPrint(">>>>>> Reload Ini event received: %wZ\n", &m_usFolSecINIPath);
		UnLoadTrojanList();
		//if(usDriverRegistryEntry.Buffer)
		if (m_usFolSecINIPath.Buffer)
		{
			bIsFolderSecOn = TRUE;
			LoadTrojanList(&m_usFolSecINIPath);
		}
	}
	else if (loc->Parameters.DeviceIoControl.IoControlCode == IOCTL_STOP_FOLDER_SECURE)
	{
		//DbgPrint(">>>>>> STOP Folder Secure event received\n");
		bIsFolderSecOn = FALSE;
	}
	*/
	Irp->IoStatus.Status = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return 0;
}


/*-------------------------------------------------------------------------------------
	Function		: RegisterProtectionFilterDriver
	In Parameters	: PDRIVER_OBJECT DriverObject
	Out Parameters	: BOOLEAN
	Purpose			: Registers the Mini-Filter Drive and the Callback Registry function
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
BOOLEAN RegisterProtectionFilterDriver(PDRIVER_OBJECT DriverObject)
{
	//OBJECT_ATTRIBUTES oa;
	//UNICODE_STRING uniString = { 0 };
	//PSECURITY_DESCRIPTOR sd;
	NTSTATUS status;

	//  Start Filtering Registry.
	status = CmRegisterCallback(RegistryCallback, DriverObject->DriverExtension, &iMaxProtectorRegistryFilter);
	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}
	return TRUE;
}


/*-------------------------------------------------------------------------------------
	Function		: RegistryCallback
	In Parameters	: PVOID CallbackContext,
					  PVOID Argument1,
					  PVOID Argument2
	Out Parameters	: NTSTATUS
					  STATUS_SUCCESS - ok to allow the registry entry
					  STATUS_ACCESS_DENIED - we wish to deny access
	Purpose			: Registry callback.  Is called for every createkey and setvalue
					  function call
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
NTSTATUS RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
	NTSTATUS							status = STATUS_SUCCESS;
	UNICODE_STRING						usProcessName = { 0 };
	REG_NOTIFY_CLASS					TypeOfNotification = (REG_NOTIFY_CLASS)Argument1;
	BOOLEAN								bIsOurMainUI = FALSE;
	BOOLEAN								bIsOurProcess = FALSE;
	HANDLE								pKeyHandle = NULL;
	OBJECT_ATTRIBUTES					objectAttributes;
	KEY_VALUE_PARTIAL_INFORMATION		valueinfo;
	ULONG								resultLength;
	NTSTATUS							KeyOpenStatus = STATUS_SUCCESS;
	ULONG								dwCurProcessID = 0x00;
	HANDLE								hCurrentProcID = NULL;
	static BOOLEAN						bLastCallBlocked = FALSE;

	UNREFERENCED_PARAMETER(CallbackContext);
	PAGED_CODE();

	if (gbIsProtectionOn == FALSE)
	{
		return STATUS_SUCCESS;
	}

	if ((!MmIsAddressValid(Argument2)) || (Argument2 == NULL))
	{
		return STATUS_SUCCESS;
	}

	hCurrentProcID = PsGetCurrentProcessId();
	if (hCurrentProcID == NULL)
	{
		return STATUS_SUCCESS;
	}


	dwCurProcessID = (ULONG)hCurrentProcID;
	if (dwCurProcessID == 0 || dwCurProcessID == 8 || dwCurProcessID == 4)
	{
		//DbgPrint("[SKIP]*************** PsGetCurrentProcessId(%d)!\n", dwCurProcessID);
		return STATUS_SUCCESS;
	}

	//DbgPrint("[%05d] INSIDE RegistryCallback!\n", PsGetCurrentProcessId());

	if (TypeOfNotification != RegNtPreCreateKey &&
		TypeOfNotification != RegNtPreCreateKeyEx &&
		TypeOfNotification != RegNtRenameKey &&
		TypeOfNotification != RegNtPreSetValueKey &&
		TypeOfNotification != RegNtDeleteKey &&
		TypeOfNotification != RegNtDeleteValueKey)
	{
		return STATUS_SUCCESS;
	}

	if (IsOurProcessByID(hCurrentProcID))
	{
		bIsOurProcess = TRUE;
		if (TypeOfNotification == RegNtPreSetValueKey)
		{
			bIsOurMainUI = TRUE;
		}
		else
		{
			return STATUS_SUCCESS;
		}
	}

	usProcessName.Length = 0;
	usProcessName.MaximumLength = 512;
	usProcessName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usProcessName.MaximumLength, MAXPROTECTOR_POOL_POOL_TAG);

	if (usProcessName.Buffer == NULL || !usProcessName.Buffer)
	{
		return STATUS_SUCCESS;
	}

	//if (GetImageNameByID(hCurrentProcID, &usProcessName) == FALSE)
	if (GetProcessNameEx(&usProcessName) == FALSE)
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
		}
		return STATUS_SUCCESS;
	}

	if (IsOurProcessFile(&usProcessName))
	{
		bIsOurProcess = TRUE;
		if (TypeOfNotification == RegNtPreSetValueKey)
		{
			bIsOurMainUI = TRUE;
		}
		else
		{
			return STATUS_SUCCESS;
		}
	}
	else if (gbIsProdInstallation)
	{
		if (IsOurInstallationProcessFile(&usProcessName))
		{
			if (usProcessName.Buffer)
			{
				ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
			}
			return STATUS_SUCCESS;
		}
	}

	
	switch (TypeOfNotification)
	{
		case RegNtPreCreateKey:		// Windows XP 32bit Only
		{
			PREG_PRE_CREATE_KEY_INFORMATION pInfo = (PREG_PRE_CREATE_KEY_INFORMATION)Argument2;
			if (pInfo)
			{
				if (bLastCallBlocked)
				{
					DbgPrint("Blocked: %5d, Key: (bLastCallBlocked)\n", dwCurProcessID);
					status = STATUS_ACCESS_DENIED;
					bLastCallBlocked = FALSE;
				}
				else
				{
					PUNICODE_STRING pKeyPath = pInfo->CompleteName;
					if ((pKeyPath) && (pKeyPath->Length > 0))
					{
						if (IsProtectedRegistry(NULL, pKeyPath))
						{
							if (!bIsOurProcess)
							{
								DbgPrint("Blocked: %5d, Key: %wZ\n", hCurrentProcID, pKeyPath);
								status = STATUS_ACCESS_DENIED;
							}
							InitializeObjectAttributes(&objectAttributes, pKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
							KeyOpenStatus = ZwOpenKey(pKeyHandle, KEY_ALL_ACCESS, &objectAttributes);
							if (!NT_SUCCESS(KeyOpenStatus))
							{
								//DbgPrint("ZwOpenKey failed for key name = %S with status = %X\n",pKeyPath->Buffer,status);
								//DbgPrint("@@@@@@@ Allow for the first time NtOpenKey : %wZ : %wZ : %wZ\n", PsGetCurrentProcessId(), &usImageName, Parent, ObjectAttributes->ObjectName);
								status = STATUS_SUCCESS;
							}
								//ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
						}
					}
					if (status == STATUS_ACCESS_DENIED)
					{
						bLastCallBlocked = TRUE;
					}
					else
					{
						bLastCallBlocked = FALSE;
					}
				}
			}
		}
		break;
		case RegNtPreCreateKeyEx:			// Windows XP 64 Bit && Windows 2003 && Vista 32 & 64 Bit
		{
			PREG_CREATE_KEY_INFORMATION pInfo = (PREG_CREATE_KEY_INFORMATION)Argument2;
			//pInfo
			if (pInfo)
			{
				//static BOOLEAN bLastCallBlocked = FALSE;
				if (bLastCallBlocked)
				{
					DbgPrint("Blocked: %5d, Key: (bLastCallBlocked)\n", hCurrentProcID);
					status = STATUS_ACCESS_DENIED;
					bLastCallBlocked = FALSE;
				}
				else
				{
					PUNICODE_STRING pKeyPath = pInfo->CompleteName;
					if ((pKeyPath) && (pKeyPath->Length > 0))
					{
						if (pKeyPath->Buffer[0] == '\\')
						{
							if (IsProtectedRegistry(NULL, pKeyPath))
							{
								if (!bIsOurProcess)
								{
									DbgPrint("Blocked 2: %5d, Key: %wZ\n", hCurrentProcID, pKeyPath);
									status = STATUS_ACCESS_DENIED;
								}
								InitializeObjectAttributes(&objectAttributes, pKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
								KeyOpenStatus = ZwOpenKey(pKeyHandle, KEY_ALL_ACCESS, &objectAttributes);
								//DbgPrint("ZwOpenKey Outside for key name = %S with status = %X\n",pKeyPath->Buffer,status);
								if (!NT_SUCCESS(KeyOpenStatus))
								{
									//DbgPrint("ZwOpenKey failed for key name = %S with status = %X\n",pKeyPath->Buffer,status);
									//DbgPrint("@@@@@@@ Allow for the first time NtOpenKey : %wZ : %wZ : %wZ\n", PsGetCurrentProcessId(), &usImageName, Parent, ObjectAttributes->ObjectName);
									status = STATUS_SUCCESS;
								}
								//ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
							}
						}
						else
						{
							PVOID pRegistryObject = pInfo->RootObject;
							if ((MmIsAddressValid(pRegistryObject)) && (pRegistryObject != NULL))
							{
								POBJECT_NAME_INFORMATION pObjectName = GetObjectCompleteName(pRegistryObject);
								if (pObjectName)
								{
									if (IsProtectedRegistry(&pObjectName->Name, pKeyPath))
									{
										if (!bIsOurProcess)
										{
											DbgPrint("Blocked: %5d, Key: %wZ\n", hCurrentProcID, pKeyPath);
											status = STATUS_ACCESS_DENIED;
										}
										InitializeObjectAttributes(&objectAttributes, pKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
										//DbgPrint("ZwOpenKey Outside for key name = %S with status = %X\n",pKeyPath->Buffer,status);
										KeyOpenStatus = ZwOpenKey(pKeyHandle, KEY_ALL_ACCESS, &objectAttributes);
										if (!NT_SUCCESS(KeyOpenStatus))
										{
											//DbgPrint("ZwOpenKey failed for key name = %S with status = %X\n",pKeyPath->Buffer,status);
											//DbgPrint("@@@@@@@ Allow for the first time NtOpenKey : %wZ : %wZ : %wZ\n", PsGetCurrentProcessId(), &usImageName, Parent, ObjectAttributes->ObjectName);
											status = STATUS_SUCCESS;
										}
										//ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
									}
									ExFreePoolWithTag(pObjectName, MAXPROTECTOR_POOL_POOL_TAG);
								}
							}
						}
					}
					if (status == STATUS_ACCESS_DENIED)
					{
						bLastCallBlocked = TRUE;
					}
					else
					{
						bLastCallBlocked = FALSE;
					}
				}
			}
		}
		break;
		case RegNtRenameKey:
		{
			PREG_RENAME_KEY_INFORMATION pInfo = (PREG_RENAME_KEY_INFORMATION)Argument2;
			if (pInfo)
			{
				PVOID pRegistryObject = pInfo->Object;
				if ((MmIsAddressValid(pRegistryObject)) && (pRegistryObject != NULL))
				{
					POBJECT_NAME_INFORMATION pObjectName = GetObjectCompleteName(pRegistryObject);
					if (pObjectName)
					{
						if ((IsProtectedRegistry(NULL, &pObjectName->Name)) ||
							(IsProtectedRegistry(NULL, pInfo->NewName)))
						{
							if (!bIsOurProcess)
							{
								DbgPrint("Blocked: %5d, Rename Key: %wZ, NewKey: %wZ\n", hCurrentProcID, &pObjectName->Name, pInfo->NewName);
								status = STATUS_ACCESS_DENIED;
							}
								//ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
						}
						ExFreePoolWithTag(pObjectName, MAXPROTECTOR_POOL_POOL_TAG);
					}
				}
			}
		}
		break;
		case RegNtPreSetValueKey:
		{
			PREG_SET_VALUE_KEY_INFORMATION pInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
			if (pInfo)
			{
				ULONG lTypeOfData = (ULONG)pInfo->Type;
				if ((lTypeOfData == REG_SZ) || (lTypeOfData == REG_EXPAND_SZ) || (lTypeOfData == REG_MULTI_SZ)
					|| (lTypeOfData == REG_DWORD) || (lTypeOfData == REG_QWORD) || (lTypeOfData == REG_BINARY))
				{
					PVOID pRegistryObject = pInfo->Object;
					if ((MmIsAddressValid(pRegistryObject)) && (pRegistryObject != NULL))
					{
						POBJECT_NAME_INFORMATION pObjectName = GetObjectCompleteName(pRegistryObject);
						if (pObjectName)
						{
							PUNICODE_STRING pValueName = pInfo->ValueName;
							PUNICODE_STRING pKeyPath = &(pObjectName->Name);
							if (IsProtectedRegistry(&pObjectName->Name, pValueName))
							{
								//BOOLEAN bIsOurProcess = FALSE;
								if (!bIsOurMainUI)
								{
									if (!bIsOurProcess)
									{
										DbgPrint("Blocked: %5d, SetValue Key: %wZ, Value: %wZ\n", hCurrentProcID, &pObjectName->Name, pValueName);
										status = STATUS_ACCESS_DENIED;
									}

									InitializeObjectAttributes(&objectAttributes, pKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
									KeyOpenStatus = ZwOpenKey(pKeyHandle, KEY_ALL_ACCESS, &objectAttributes);
									if (NT_SUCCESS(KeyOpenStatus))
									{
										KeyOpenStatus = ZwQueryValueKey(pKeyHandle, pValueName, KeyValuePartialInformation, &valueinfo, sizeof(KEY_VALUE_PARTIAL_INFORMATION), &resultLength);
										//DbgPrint("pValueName outside for key name = %S with status = %X\n",pValueName->Buffer,status);
										if (!NT_SUCCESS(KeyOpenStatus) && KeyOpenStatus != STATUS_BUFFER_OVERFLOW && KeyOpenStatus != STATUS_BUFFER_TOO_SMALL)
										{
											//DbgPrint("pValueName failed for key name = %S with status = %X\n",pValueName->Buffer,status);
											status = STATUS_SUCCESS;
										}
									}
									else
									{
										//DbgPrint("Else condition of ZwOpen Key = %S with status = %X and with Process Name = %S\n",pKeyPath->Buffer,status,usProcessName.Buffer);
										if (IsWOW64RegFile(&usProcessName))
										{
											//DbgPrint("Process comparison success  =%X",status);
											status = STATUS_SUCCESS;
										}
									}
									//ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
								}
								if ((lTypeOfData == REG_DWORD) && (bIsOurProcess || bIsOurMainUI))
								{
									PUNICODE_STRING pValueName = pInfo->ValueName;
									if (RtlCompareUnicodeString(pValueName, &PROTECT_SYS_REG_VALUE, TRUE) == 0)
									{
										PULONG pdwData = (PULONG)pInfo->Data;
										if (*pdwData == 1)
											bProtectSystemRegistry = TRUE;
										else
											bProtectSystemRegistry = FALSE;
									}
									else if (RtlCompareUnicodeString(pValueName, &AUTORUN_REG_VALUE, TRUE) == 0)
									{
										PULONG pdwData = (PULONG)pInfo->Data;
										if (*pdwData == 1)
											bRestrictAutorun = TRUE;
										else
											bRestrictAutorun = FALSE;
									}
									else if (RtlCompareUnicodeString(pValueName, &USB_WRITE_REG_VALUE, TRUE) == 0)
									{
										PULONG pdwData = (PULONG)pInfo->Data;
										if (*pdwData == 1)
											bRestrictUSBWrite = TRUE;
										else
											bRestrictUSBWrite = FALSE;
									}
									else if (RtlCompareUnicodeString(pValueName, &USB_EXECUTE_REG_VALUE, TRUE) == 0)
									{
										PULONG pdwData = (PULONG)pInfo->Data;
										if (*pdwData == 1)
											bRestrictUSBExecute = TRUE;
										else
											bRestrictUSBExecute = FALSE;
									}
								}
							}
							ExFreePoolWithTag(pObjectName, MAXPROTECTOR_POOL_POOL_TAG);
						}
					}
				}
			}
		}
		break;
		case RegNtDeleteKey:
		{
			PREG_DELETE_KEY_INFORMATION pInfo = (PREG_DELETE_KEY_INFORMATION)Argument2;
			if (pInfo)
			{
				PVOID pRegistryObject = pInfo->Object;
				if ((MmIsAddressValid(pRegistryObject)) && (pRegistryObject != NULL))
				{
					POBJECT_NAME_INFORMATION pObjectName = GetObjectCompleteName(pRegistryObject);
					if (pObjectName)
					{
						if (IsProtectedRegistry(NULL, &pObjectName->Name))
						{
							if (!bIsOurProcess)
							{
								DbgPrint("Blocked: %5d, Delete Key: %wZ\n", hCurrentProcID, &pObjectName->Name);
								status = STATUS_ACCESS_DENIED;
							}
							//ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
						}
						ExFreePoolWithTag(pObjectName, MAXPROTECTOR_POOL_POOL_TAG);
					}
				}
			}
		}
		break;
		case RegNtDeleteValueKey:
		{
			PREG_DELETE_VALUE_KEY_INFORMATION pInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
			if (pInfo)
			{
				PVOID pRegistryObject = pInfo->Object;
				if ((MmIsAddressValid(pRegistryObject)) && (pRegistryObject != NULL))
				{
					POBJECT_NAME_INFORMATION pObjectName = GetObjectCompleteName(pRegistryObject);
					if (pObjectName)
					{
						PUNICODE_STRING pValueName = pInfo->ValueName;
						if (IsProtectedRegistry(&pObjectName->Name, pValueName))
						{
							if (!bIsOurProcess)
							{
								DbgPrint("Blocked: %5d, Delete Key: %wZ, Value: %wZ\n", hCurrentProcID, &pObjectName->Name, pValueName);
								status = STATUS_ACCESS_DENIED;
							}
							//ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
						}
						ExFreePoolWithTag(pObjectName, MAXPROTECTOR_POOL_POOL_TAG);
					}
				}
			}
		}
		break;
	}
	
	if (usProcessName.Buffer)
	{
		ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
	}
	return status;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckFileEntry
	In Parameters	: __inout PFLT_CALLBACK_DATA Data,
					  __in PCFLT_RELATED_OBJECTS FltObjects
	Out Parameters	: FLT_PREOP_CALLBACK_STATUS
						FLT_PREOP_SUCCESS_WITH_CALLBACK - If this is not our user-mode process.
						FLT_PREOP_SUCCESS_NO_CALLBACK - All other threads.
	Purpose			: Pre create callback.  We need to remember whether this file has been
					  opened for write access.  If it has, we'll want to rescan it in cleanup.
					  This scheme results in extra scans in at least two cases:
					  -- if the create fails (perhaps for access denied)
					  -- the file is opened for write access but never actually written to
					  The assumption is that writes are more common than creates, and checking
					  or setting the context in the write path would be less efficient than
					  taking a good guess before the create.
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
BOOLEAN CheckFileEntry(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects)
{
	PUNICODE_STRING			pFileName = NULL;
	PFILE_OBJECT			pFileObject = 0;
	//PFLT_FILE_NAME_INFORMATION nameInfo;
	BOOLEAN					bAllowEntry = TRUE;
	//int iEntryIndex = -1;
	ULONG					ulTypeOfCall = CALL_TYPE_UNKNOWN;
	UNICODE_STRING			usProcessName = { 0 };
	//BOOLEAN					bIsAutoRun = FALSE;
	UNICODE_STRING			usDriveLetter = { 0 };
	ULONG					dwCurProcessID = 0;
	HANDLE					hCurrentProcID = NULL;
	int						iDriveLetter = 0x00;

	if (gbIsProtectionOn == FALSE)
	{
		return bAllowEntry;
	}

	//  If this create was failing anyway, don't bother scanning now.
	if (!NT_SUCCESS(Data->IoStatus.Status) || (STATUS_REPARSE == Data->IoStatus.Status))
	{
		return bAllowEntry;
	}

	pFileObject = FltObjects->FileObject;
	if (!pFileObject)
	{
		return bAllowEntry;
	}

	//Full File Name except the drive letter!
	pFileName = &pFileObject->FileName;
	if ((!pFileName) || (pFileName->Length <= 0))
	{
		return bAllowEntry;
	}
	if (!pFileName->Buffer)
	{
		return bAllowEntry;
	}

	if (pFileName->Buffer[0] != L'\\')
	{
		return bAllowEntry;
	}

	/*
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return bAllowEntry;
	}

	if (IsOurProcessByID(0))	// Current Process is Our Process
	{
		//DbgPrint("[%05d] OURPROCESS (CheckEntry) pFilePath: %wZ\n", PsGetCurrentProcessId(), pFileName);
		return bAllowEntry;
	}
	*/

	hCurrentProcID = PsGetCurrentProcessId();
	if (hCurrentProcID == NULL)
	{
		return bAllowEntry;
	}

	dwCurProcessID = (ULONG)hCurrentProcID;
	if (dwCurProcessID == 0 || dwCurProcessID == 4 || dwCurProcessID == 8)
	{
		return bAllowEntry;
	}

	if (IsOurProcessByID(hCurrentProcID))
	{
		return bAllowEntry;
	}

	usProcessName.Length = 0;
	usProcessName.MaximumLength = 512;
	usProcessName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usProcessName.MaximumLength, MAXPROTECTOR_POOL_POOL_TAG);

	if (usProcessName.Buffer == NULL || !usProcessName.Buffer)
	{
		return bAllowEntry;
	}

	if (GetImageNameByID(hCurrentProcID, &usProcessName) == FALSE)
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
		}
		return bAllowEntry;
	}

	if (IsOurProcessFile(&usProcessName))
	{
		if (usProcessName.Buffer)
		{
			ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
		}
		return bAllowEntry;
	}
	else if (gbIsProdInstallation)
	{
		if (IsOurInstallationProcessFile(&usProcessName))
		{
			if (usProcessName.Buffer)
			{
				ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
			}
			return bAllowEntry;
		}
	}


	if (Data->Iopb->MajorFunction == IRP_MJ_CREATE)
	{
		if (bRestrictAutorun == TRUE)
		{
			if (IsAutornINFCall(&usProcessName,pFileName))
			{
				if (usProcessName.Buffer)
				{
					ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
				}
				return FALSE;
			}
		}
		if (bIsUSBMonOn == TRUE)
		{
			//Retrieve the drive letter
			RtlInitUnicodeString(&usDriveLetter, NULL);
			if (!NT_SUCCESS(IoVolumeDeviceToDosName(pFileObject->DeviceObject, &usDriveLetter)))
			{
				return bAllowEntry;
			}

			if (usDriveLetter.Length < 2)
			{
				return bAllowEntry;
			}

			iDriveLetter = (usDriveLetter.Buffer[0x00] - 0x41);
			if (iDriveLetter < 0 || iDriveLetter > 26)
			{
				return bAllowEntry;
			}
			if (USB_TOTAL_BLOCK[iDriveLetter] == FALSE && USB_WRITE_BLOCK[iDriveLetter] == FALSE && USB_EXECUTE_BLOCK[iDriveLetter] == FALSE)
			{
				//DbgPrint("[%05d] No Need to go for USB check: %wZ\n", iDriveLetter, &usDriveLetter);
				return bAllowEntry;
			}

			if ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_EXECUTE) == FILE_EXECUTE)
			{
				ulTypeOfCall = CALL_TYPE_F_EXECUTE;
			}

			if (((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_DATA) == FILE_WRITE_DATA)
				|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES)
				|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_EA) == FILE_WRITE_EA)
				|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_APPEND_DATA) == FILE_APPEND_DATA))
			{
				ulTypeOfCall = CALL_TYPE_F_CREATE;
			}
			if (BlockUSBFileAccess(&usDriveLetter, (ulTypeOfCall == CALL_TYPE_F_EXECUTE), (ulTypeOfCall == CALL_TYPE_F_CREATE)))
			{
				//DbgPrint("[%05d] BLOCKED USB FilePath: %wZ\n", PsGetCurrentProcessId(), &usDriveLetter);
				ExFreePool(usDriveLetter.Buffer);
				return FALSE;
			}
			ExFreePool(usDriveLetter.Buffer);
		}
	}

	/*
	usProcessName.Length = 0;
	usProcessName.MaximumLength = MAX_BUFFER_SIZE;
	usProcessName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usProcessName.MaximumLength, MAXPROTECTOR_POOL_POOL_TAG);
	if (!usProcessName.Buffer)
	{
		//DbgPrint("[%05d] FAILED to allocate Process Buffer\n", PsGetCurrentProcessId());
		return bAllowEntry;
	}

	RtlZeroMemory(usProcessName.Buffer, usProcessName.MaximumLength);

	if (IsOurProcessByHandle(INVALID_HANDLE_VALUE, &usProcessName) || IsOurSetupFile(&usProcessName))
	{
		//DbgPrint("[%05d] SKIPPING our PROCESS\n", PsGetCurrentProcessId());
		ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
		return bAllowEntry;
	}

	if (usProcessName.Length == 0)
	{
		//DbgPrint("[%05d] FAILED to allocate Process Buffer Length\n", PsGetCurrentProcessId());
		ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
		return bAllowEntry;
	}
	*/
	if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION)
	{
		if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation)
		{
			ulTypeOfCall = CALL_TYPE_F_DELETE;
			if (IsProtectedFile(NULL, pFileName))
			{
				//DbgPrint("[%05d] BLOCKED DELETE ProcessName: %wZ, FilePath: %wZ\n", PsGetCurrentProcessId(), &usProcessName, pFileName);
				ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
				return FALSE;
			}
		}
		else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation)
		{
			PFILE_RENAME_INFORMATION pFileInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
			UNICODE_STRING usNewFileName = { 0 };

			//DbgPrint("CheckFileEntry 12");
			if (pFileInfo)
			{
				if ((pFileInfo->FileName[1] == '?') && (pFileInfo->FileName[2] == '?'))
				{
					usNewFileName.Length = (USHORT)pFileInfo->FileNameLength - 8;
					usNewFileName.MaximumLength = usNewFileName.Length;
					usNewFileName.Buffer = &pFileInfo->FileName[4];
				}
				else
				{
					usNewFileName.Length = (USHORT)pFileInfo->FileNameLength;// - 4;
					usNewFileName.MaximumLength = usNewFileName.Length;
					usNewFileName.Buffer = &pFileInfo->FileName[0];
				}
			}
			ulTypeOfCall = CALL_TYPE_F_RENAME;

			if (IsProtectedFile(NULL, &usNewFileName))
			{
				//DbgPrint("[%05d] BLOCKED RENAME ProcessName: %wZ, FilePath: %wZ: %wZ\n", PsGetCurrentProcessId(), &usProcessName, pFileName, &usNewFileName);
				ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
				return FALSE;
			}
			if (IsProtectedFile(NULL, pFileName))
			{
				//DbgPrint("[%05d] BLOCKED RENAME ProcessName: %wZ, FilePath: %wZ: %wZ\n", PsGetCurrentProcessId(), &usProcessName, pFileName, &usNewFileName);
				ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
				return FALSE;
			}
		}
	}
	else if (Data->Iopb->MajorFunction == IRP_MJ_CREATE)
	{
		if ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & DELETE) == DELETE)
		{
			if (IsProtectedFile(NULL, pFileName))
			{
				//DbgPrint("[%05d] BLOCKED DELETE ProcessName: %wZ, FilePath: %wZ\n", PsGetCurrentProcessId(), &usProcessName, pFileName);
				ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
				return FALSE;
			}
		}
		if (IsWriteCall(Data) == TRUE)
		{
			if (IsProtectedFile(NULL, pFileName))
			{
				//DbgPrint("[%05d] BLOCKED WRITE OURFILE ProcessName: %wZ, FilePath: %wZ\n", PsGetCurrentProcessId(), &usProcessName, pFileName);
				ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
				return FALSE;
			}
		}
	}

	//DbgPrint("[%05d] ALLOWED ProcessName: %wZ, FilePath: %wZ\n", PsGetCurrentProcessId(), &usProcessName, pFileName);
	ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
	return bAllowEntry;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanUpDriver
	In Parameters	: NONE
	Out Parameters	: NONE
	Purpose			: Dereferences all user communication events
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CleanUpDriver()
{
	if (MaxProtectorData.Filter != 0)
	{
		FltUnregisterFilter(MaxProtectorData.Filter);
		MaxProtectorData.Filter = 0;
	}

	/*
	//  Unregister the Registry filter
	if (iMaxProtectorRegistryFilter.QuadPart != 0)
	{
		CmUnRegisterCallback(iMaxProtectorRegistryFilter);
		iMaxProtectorRegistryFilter.QuadPart = 0;
	}
	*/
}

BOOLEAN IsWOW64RegFile(PUNICODE_STRING FileBeingAccessed)
{
	const UNICODE_STRING* pusEntry = 0;
	if (!FileBeingAccessed || !FileBeingAccessed->Buffer)
		return FALSE;

	RtlUpcaseUnicodeString(FileBeingAccessed, FileBeingAccessed, FALSE);

	pusEntry = ExeToAllow64;
	while (pusEntry->Buffer != NULL)
	{
		if (MatchUnicodeString(pusEntry, FileBeingAccessed))
		{
			return TRUE;
		}
		pusEntry++;
	}
	return FALSE;
}

BOOLEAN ShouldWeBlock(PUNICODE_STRING pusRegistryPath, const PUNICODE_STRING pusValueName)
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

	pValueInfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + MAX_PATH, MAXPROTECTOR_POOL_POOL_TAG);
	if (pValueInfo)
	{
		memset(pValueInfo, 0, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + MAX_PATH);
		ntstatus = ZwQueryValueKey(handle, pusValueName, KeyValuePartialInformation, pValueInfo,
			sizeof(KEY_VALUE_PARTIAL_INFORMATION) + MAX_PATH, &ulResultLength);
		if (!NT_SUCCESS(ntstatus))
		{
			ExFreePoolWithTag(pValueInfo, MAXPROTECTOR_POOL_POOL_TAG);
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

		ExFreePoolWithTag(pValueInfo, MAXPROTECTOR_POOL_POOL_TAG);
	}
	ZwClose(handle);

	return bStatus;
}

BOOLEAN IsUSBProtectionOn()
{
	BOOLEAN bRetValue = FALSE;
	int		iDriveNo = 0;

	for (; iDriveNo < 26; iDriveNo++)
	{
		if (USB_TOTAL_BLOCK[iDriveNo] == TRUE || USB_WRITE_BLOCK[iDriveNo] == TRUE || USB_EXECUTE_BLOCK[iDriveNo] == TRUE)
		{
			bRetValue = TRUE;
			break;
		}
	}

	return bRetValue;
}

void ResetAllDrivesProtection()
{
	int iDriveNo = 0;
	for (; iDriveNo < 26; iDriveNo++)
	{
		USB_TOTAL_BLOCK[iDriveNo] = FALSE;
		USB_WRITE_BLOCK[iDriveNo] = FALSE;
		USB_EXECUTE_BLOCK[iDriveNo] = FALSE;
	}
}

void SetTotalBlock(int iDriveLetter, BOOLEAN bBlock)
{
	USB_TOTAL_BLOCK[iDriveLetter] = bBlock;
}

void SetWriteBlock(int iDriveLetter, BOOLEAN bBlock)
{
	USB_WRITE_BLOCK[iDriveLetter] = bBlock;
}

void SetExecuteBlock(int iDriveLetter, BOOLEAN bBlock)
{
	USB_EXECUTE_BLOCK[iDriveLetter] = bBlock;
}


BOOLEAN GetImageNameByID(HANDLE ProcessId, PUNICODE_STRING pusImageFileName)
{
	UNICODE_STRING ProcImgName = { 0 };
	HANDLE hProcessHandle = NULL;
	NTSTATUS status = STATUS_ACCESS_DENIED;
	PEPROCESS eProcess = NULL;
	//int iEntryIndex = -1;

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		//DbgPrint("[%05d] Not running at PASSIVE_LEVEL pFilePath: %wZ\n", PsGetCurrentProcessId(), pFileName);
		return FALSE;
	}

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
	ProcImgName.Buffer = ExAllocatePoolWithTag(NonPagedPool, ProcImgName.MaximumLength, MAXPROTECTOR_POOL_POOL_TAG);

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
		ExFreePoolWithTag(ProcImgName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
		ZwClose(hProcessHandle);
		ObDereferenceObject(eProcess);
		eProcess = NULL;
		return FALSE;
	}

	if (pusImageFileName)
	{
		RtlCopyUnicodeString(pusImageFileName, &ProcImgName);
	}

	ExFreePoolWithTag(ProcImgName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
	ZwClose(hProcessHandle);
	ObDereferenceObject(eProcess);
	eProcess = NULL;
	return TRUE;
}

NTSTATUS GetProcessImageName(HANDLE ProcessHandle, PUNICODE_STRING ProcessImageName)
{
	NTSTATUS status = STATUS_ACCESS_DENIED;
	PUNICODE_STRING imageName = NULL;
	ULONG returnedLength = 0;
	ULONG bufferLength = 0;
	PVOID buffer = NULL;

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

	buffer = ExAllocatePoolWithTag(PagedPool, returnedLength, MAXPROTECTOR_POOL_POOL_TAG);
	if (NULL == buffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, buffer,
		returnedLength, &returnedLength);

	if (NT_SUCCESS(status))
	{
		imageName = (PUNICODE_STRING)buffer;
		RtlCopyUnicodeString(ProcessImageName, imageName);
	}

	ExFreePool(buffer);
	return status;
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
			return TRUE;
		}
		pusEntry++;
	}

	return FALSE;
}

BOOLEAN IsOurInstallationProcessFile(PUNICODE_STRING ProcessPath)
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

	pusEntry = InstallAllowProcess;
	while (pusEntry->Buffer != NULL)
	{
		if (MatchUnicodeString(pusEntry, &FileBeingAccessedTemp))
		{
			return TRUE;
		}
		pusEntry++;
	}

	return FALSE;
}

BOOLEAN IsOurProcess2Protect(PUNICODE_STRING ProcessPath)
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

	pusEntry = OurProcesses2Protect;
	while (pusEntry->Buffer != NULL)
	{
		if (MatchUnicodeString(pusEntry, &FileBeingAccessedTemp))
		{
			return TRUE;
		}
		pusEntry++;
	}

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

BOOLEAN IsProtectedRegistry(PUNICODE_STRING ParentRegistryPath, PUNICODE_STRING RegistryPath)
{
	int iEntryIndex = -1;
	//BOOLEAN bReturnValue = FALSE;
	UNICODE_STRING usFullRegKeyPath = { 0 };

	usFullRegKeyPath.Length = 0;

	if ((!RegistryPath) || (RegistryPath->Length <= 0))
	{
		return FALSE;
	}

	if ((ParentRegistryPath) && (ParentRegistryPath->Length > 0))
	{
		usFullRegKeyPath.MaximumLength = GetMaxLen(ParentRegistryPath) + GetMaxLen(RegistryPath) + 4;
	}
	else
	{
		usFullRegKeyPath.MaximumLength = GetMaxLen(RegistryPath) + 4;
	}

	usFullRegKeyPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, usFullRegKeyPath.MaximumLength, MAXPROTECTOR_POOL_POOL_TAG);
	if (!usFullRegKeyPath.Buffer)
	{
		return FALSE;
	}

	RtlZeroMemory(usFullRegKeyPath.Buffer, usFullRegKeyPath.MaximumLength);
	if ((ParentRegistryPath) && (ParentRegistryPath->Length > 0))
	{
		NTSTATUS st;
		st = RtlUnicodeStringCopy(&usFullRegKeyPath, ParentRegistryPath);
		st = RtlUnicodeStringCat(&usFullRegKeyPath, &BACKSLASH);
		st = RtlUnicodeStringCat(&usFullRegKeyPath, RegistryPath);
	}
	else
	{
		RtlUnicodeStringCopy(&usFullRegKeyPath, RegistryPath);
	}

	RtlUpcaseUnicodeString(&usFullRegKeyPath, &usFullRegKeyPath, FALSE);
	//DbgPrint("[%05d] ----- FullPath: %wZ\n", PsGetCurrentProcessId(), &usFullRegKeyPath);
	iEntryIndex = CheckIfProtectedRegistry(&usFullRegKeyPath);
	if (iEntryIndex != -1)
	{
		ExFreePoolWithTag(usFullRegKeyPath.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
		return TRUE;
	}

	ExFreePoolWithTag(usFullRegKeyPath.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
	return FALSE;
}

int CheckIfProtectedRegistry(PUNICODE_STRING RegistryBeingAccessed)
{
	int iEntryIndex = 0;
	const UNICODE_STRING* pusEntry = 0;


	if ((!RegistryBeingAccessed) || (RegistryBeingAccessed->Length <= 0))
	{
		return -1;
	}

	pusEntry = RegistryToProtect;
	while (pusEntry->Buffer != NULL)
	{
		if (MatchUnicodeString(pusEntry, RegistryBeingAccessed))
		{
			return iEntryIndex;
		}
		pusEntry++;
		iEntryIndex++;
	}

	if (bProtectSystemRegistry)
	{
		pusEntry = SystemRegistryToProtect;
		while (pusEntry->Buffer != NULL)
		{
			if (MatchUnicodeString(pusEntry, RegistryBeingAccessed))
			{
				return iEntryIndex;
			}
			pusEntry++;
			iEntryIndex++;
		}
	}
	return -1;
}

USHORT GetMaxLen(PUNICODE_STRING pStr)
{
	return (pStr->MaximumLength >= pStr->Length ? pStr->MaximumLength : pStr->Length);
}

POBJECT_NAME_INFORMATION GetObjectCompleteName(PVOID pObject)
{
	NTSTATUS status;
	ULONG returnedLength = 0;
	POBJECT_NAME_INFORMATION pObjectName = NULL;

	if ((!MmIsAddressValid(pObject)) || (pObject == NULL))
	{
		return NULL;
	}
	status = ObQueryNameString(pObject, 0, 0, &returnedLength);
	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (returnedLength == 0)
			returnedLength = 512;

		returnedLength += 4;	// ensure null terminated unicode string!
		pObjectName = ExAllocatePoolWithTag(NonPagedPool, returnedLength, MAXPROTECTOR_POOL_POOL_TAG);
		if (pObjectName)
		{
			RtlZeroMemory(pObjectName, returnedLength);
			status = ObQueryNameString(pObject, pObjectName, (returnedLength - 4), &returnedLength);
			if (NT_SUCCESS(status))
			{
				return pObjectName;
			}
			ExFreePoolWithTag(pObjectName, MAXPROTECTOR_POOL_POOL_TAG);
		}
	}
	return NULL;
}

BOOLEAN BlockUSBFileAccess(PUNICODE_STRING FileBeingAccessed, BOOLEAN bOpenForExecute, BOOLEAN bOpenForWrite)
{
	int iDriveNo = 0;
	UNICODE_STRING usImageName = { 0 };
	UNICODE_STRING usUSBDrive = { 0 };
	BOOLEAN bCheckNeeded = FALSE;

	if (!FileBeingAccessed)
		return FALSE;

	if (FileBeingAccessed->Length < 2)
		return FALSE;

	for (; iDriveNo < 26; iDriveNo++)
	{
		if ((USB_TOTAL_BLOCK[iDriveNo]) || ((USB_WRITE_BLOCK[iDriveNo]) && bOpenForWrite) || ((USB_EXECUTE_BLOCK[iDriveNo]) && bOpenForExecute))
		{
			//DbgPrint("#####Driver Block Setting FOUND\n");
			bCheckNeeded = TRUE;
		}
	}

	if (bCheckNeeded == FALSE)
	{
		//DbgPrint("##### NO Driver Block Setting Found\n");
		return FALSE;
	}

	usImageName.Length = GetMaxLen(FileBeingAccessed) + 2;
	usImageName.MaximumLength = usImageName.Length;
	usImageName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usImageName.MaximumLength, MAXPROTECTOR_POOL_POOL_TAG);
	RtlZeroMemory(usImageName.Buffer, usImageName.MaximumLength);
	RtlUnicodeStringCopy(&usImageName, FileBeingAccessed);
	RtlUpcaseUnicodeString(&usImageName, &usImageName, FALSE);

	usUSBDrive.Length = USB_DRIVE_LETTER.Length;
	usUSBDrive.MaximumLength = USB_DRIVE_LETTER.MaximumLength;
	usUSBDrive.Buffer = ExAllocatePoolWithTag(NonPagedPool, usUSBDrive.MaximumLength, MAXPROTECTOR_POOL_POOL_TAG);
	RtlZeroMemory(usUSBDrive.Buffer, usUSBDrive.MaximumLength);
	RtlUnicodeStringCopy(&usUSBDrive, &USB_DRIVE_LETTER);

	iDriveNo = 0;
	for (; iDriveNo < 26; iDriveNo++)
	{
		if ((USB_TOTAL_BLOCK[iDriveNo]) || ((USB_WRITE_BLOCK[iDriveNo]) && bOpenForWrite) || ((USB_EXECUTE_BLOCK[iDriveNo]) && bOpenForExecute))
		{
			usUSBDrive.Buffer[1] = (WCHAR)(iDriveNo + 0x41);
			if (((usUSBDrive.Buffer[1] == usImageName.Buffer[0]) && (usImageName.Buffer[1] == L':'))
				|| (MatchUnicodeString(&usUSBDrive, &usImageName)))
			{
				//DbgPrint("[%05d] ##### USB BLOCKED: %wZ\n", PsGetCurrentProcessId(), &usImageName);
				ExFreePoolWithTag(usImageName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
				ExFreePoolWithTag(usUSBDrive.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
				return TRUE;
			}
		}
	}

	ExFreePoolWithTag(usImageName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
	ExFreePoolWithTag(usUSBDrive.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
	return FALSE;
}

BOOLEAN IsAutornINFCall(PUNICODE_STRING pParentProcPath, PUNICODE_STRING pFileBeingAccessed)
{
	BOOLEAN					bReturn = FALSE;
	BOOLEAN					bAutorun = FALSE;
	UNICODE_STRING			usFileName = { 0 };
	UNICODE_STRING			usProcName = { 0 };

	if ((!pFileBeingAccessed) || (pFileBeingAccessed->Length <= 0) || (!pParentProcPath) || (pParentProcPath->Length <= 0))
	{
		return FALSE;
	}

		usFileName.MaximumLength = GetMaxLen(pFileBeingAccessed) + 4;
	usFileName.Length = 0;
	usFileName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usFileName.MaximumLength, MAXPROTECTOR_POOL_POOL_TAG);
	if (!usFileName.Buffer)
	{
		return FALSE;
	}

	RtlZeroMemory(usFileName.Buffer, usFileName.MaximumLength);
	
	RtlUnicodeStringCopy(&usFileName, pFileBeingAccessed);
	RtlUpcaseUnicodeString(&usFileName, &usFileName, FALSE);

	if (MatchUnicodeString(&AUTORUN_FILE_NAME, &usFileName))
	{
		bAutorun = TRUE;
	}
	else
	{
		ExFreePoolWithTag(usFileName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
		return FALSE;	// allow infection into these files
	}

	
	
	usProcName.MaximumLength = GetMaxLen(pParentProcPath) + 4;
	usProcName.Length = 0;
	usProcName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usProcName.MaximumLength, MAXPROTECTOR_POOL_POOL_TAG);
	if (!usProcName.Buffer)
	{
		return FALSE;
	}

	RtlZeroMemory(usProcName.Buffer, usProcName.MaximumLength);

	RtlUnicodeStringCopy(&usProcName, pParentProcPath);
	RtlUpcaseUnicodeString(&usProcName, &usProcName, FALSE);

	
	if (MatchUnicodeString(&EXPLORER_FILE_NAME, &usProcName))
	{
		bReturn = TRUE;
	}
	else if (MatchUnicodeString(&SVCHOST_FILE_NAME, &usProcName))
	{
		bReturn = TRUE;
	}
	else if(MatchUnicodeString(&SVCHOST_WOW_FILE_NAME, &usProcName))
	{
		bReturn = TRUE;
	}

	ExFreePoolWithTag(usFileName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
	ExFreePoolWithTag(usProcName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
	
	return bReturn;
}

BOOLEAN IsProtectedFile(PUNICODE_STRING ParentFolderPath, PUNICODE_STRING FileBeingAccessed)
{
	BOOLEAN bReturn = FALSE;
	const UNICODE_STRING* pusEntry = 0;
	UNICODE_STRING usFileName = { 0 };
	if ((!FileBeingAccessed) || (FileBeingAccessed->Length <= 0))
	{
		return FALSE;
	}

	if ((ParentFolderPath) && (ParentFolderPath->Length > 0))
	{
		usFileName.MaximumLength = GetMaxLen(ParentFolderPath) + GetMaxLen(FileBeingAccessed) + 4;
	}
	else
	{
		usFileName.MaximumLength = GetMaxLen(FileBeingAccessed) + 4;
	}

	usFileName.Length = 0;
	usFileName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usFileName.MaximumLength, MAXPROTECTOR_POOL_POOL_TAG);
	if (!usFileName.Buffer)
	{
		return FALSE;
	}

	RtlZeroMemory(usFileName.Buffer, usFileName.MaximumLength);
	if ((ParentFolderPath) && (ParentFolderPath->Length > 0))
	{
		NTSTATUS st;
		st = RtlUnicodeStringCopy(&usFileName, ParentFolderPath);
		st = RtlUnicodeStringCat(&usFileName, &BACKSLASH);
		st = RtlUnicodeStringCat(&usFileName, FileBeingAccessed);
	}
	else
	{
		RtlUnicodeStringCopy(&usFileName, FileBeingAccessed);
	}

	RtlUpcaseUnicodeString(&usFileName, &usFileName, FALSE);

	pusEntry = FilesToAllowInfection;
	while (pusEntry->Buffer != NULL)
	{
		if (MatchUnicodeString(pusEntry, &usFileName))
		{
			ExFreePoolWithTag(usFileName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
			return FALSE;	// allow infection into these files
		}
		pusEntry++;
	}

	pusEntry = FilesToProtect;
	//pusEntry = MaxSrvToProtect;
	while (pusEntry->Buffer != NULL)
	{
		if (MatchUnicodeString(pusEntry, &usFileName))
		{
			ExFreePoolWithTag(usFileName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
			return TRUE;
		}
		pusEntry++;
	}

	//bReturn = IsBlockTrojanFile(&usFileName);

	ExFreePoolWithTag(usFileName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
	return bReturn;
}

BOOLEAN IsWriteCall(__inout PFLT_CALLBACK_DATA Data)
{
	BOOLEAN		IsWriteCall = FALSE;
	ULONG		CreateDisposition;

	CreateDisposition = ((Data->Iopb->Parameters.Create.Options >> 24) & 0xFF);
	if (CreateDisposition == FILE_OPEN_IF)
	{
		IsWriteCall = TRUE;
		//DbgPrint("##### IsWriteCall Already Handled(1)! Create Options = 0x%08X, Createdi = 0x%08X\n", Data->Iopb->Parameters.Create.Options, CreateDisposition);
	}
	else if (((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_DATA) == FILE_WRITE_DATA)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_EA) == FILE_WRITE_EA)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_APPEND_DATA) == FILE_APPEND_DATA)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & GENERIC_WRITE) == GENERIC_WRITE))
	{
		IsWriteCall = TRUE;
		//DbgPrint("##### IsWriteCall Handled (NOW)! Create Options = 0x%08X, Createdi = 0x%08X\n", Data->Iopb->Parameters.Create.Options, CreateDisposition);
	}
	else if (((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_DATA) == FILE_WRITE_DATA)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_EA) == FILE_WRITE_EA)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_APPEND_DATA) == FILE_APPEND_DATA)
		|| ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & GENERIC_WRITE) == GENERIC_WRITE)
		|| (((Data->Iopb->Parameters.Create.Options & 0xFF000000) == 0x02000000) &&
			((Data->Iopb->Parameters.Create.Options & 0x00000040) == 0x00000040))
		|| ((Data->Iopb->Parameters.Create.Options & 0xFF000000) == 0x00000000)
		|| ((Data->Iopb->Parameters.Create.Options & 0xFF000000) == 0x04000000)
		|| ((Data->Iopb->Parameters.Create.Options & 0xFF000000) == 0x05000000))
	{
		IsWriteCall = TRUE;
	}

	return IsWriteCall;
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
NTSTATUS MaxProtectorInstanceSetup(__in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_INSTANCE_SETUP_FLAGS Flags,
	__in DEVICE_TYPE VolumeDeviceType, __in FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	//PAGED_CODE();

	ASSERT(FltObjects->Filter == MaxProtectorData.Filter);
	if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
	{
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	return STATUS_SUCCESS;
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
NTSTATUS MaxProtectorQueryTeardown(__in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	return STATUS_SUCCESS;
}

NTSTATUS UnRegisteCallbackFunction()
{
	//DbgPrint("[%05d] >>>>> In UnRegisteCallbackFunction()!\n", PsGetCurrentProcessId());
	if (NULL != g_hProcCreateHandle)
	{
		gbIsProcProtectionOn = FALSE;
		ObUnRegisterCallbacks(g_hProcCreateHandle);
		g_hProcCreateHandle = NULL;
	}
	return STATUS_SUCCESS;
}
OB_PREOP_CALLBACK_STATUS MaxObjectPreCallback(__in PVOID RegistrationContext, __in POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	HANDLE			hCurrentProcID = NULL;
	ULONG			dwCurProcessID = 0x00;
	
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (gbIsProcProtectionOn == FALSE || gbIsProtectionOn == FALSE)
	{
		return OB_PREOP_SUCCESS;
	}

	hCurrentProcID = PsGetCurrentProcessId();
	if (hCurrentProcID == NULL)
	{
		return OB_PREOP_SUCCESS;
	}

	dwCurProcessID = (ULONG)hCurrentProcID;
	if (dwCurProcessID == 0 || dwCurProcessID == 4 || dwCurProcessID == 8)
	{
		return OB_PREOP_SUCCESS;
	}

	if (IsOurProcessByID(hCurrentProcID))
	{
		return OB_PREOP_SUCCESS;
	}
	
	//if(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess == 5120 || (OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
	if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE ||
		(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION ||
		(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_SUSPEND_RESUME) == PROCESS_SUSPEND_RESUME ||
		(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
	{

		HANDLE hProcessID = PsGetProcessId((PEPROCESS)OperationInformation->Object);

		if (hProcessID == NULL || (ULONG)hProcessID == 0 || (ULONG)hProcessID == 4 || (ULONG)hProcessID == 8)
		{
			return OB_PREOP_SUCCESS;
		}

		if (hCurrentProcID == hProcessID)
		{
			DbgPrint("[%05d] >>>>> ALLOWED Self Termination: ProcID: %d\n", hCurrentProcID, hProcessID);
		}
		//else if(IsOurProcessByID(hProcessID) && !IsOurProcessByID(0))	// match found by processid
		else
		{
			UNICODE_STRING	usParentProcName = { 0 }; //Current Process
			UNICODE_STRING	usProcessName = { 0 }; //Process Being Accessed
			BOOLEAN			bOurProcess = FALSE;
			BOOLEAN			bOurCurProcess = FALSE;
			BOOLEAN			bProtectionBreached = FALSE;
			BOOLEAN			bIgnoreVMOperation = FALSE;

			usProcessName.Length = 0;
			usProcessName.MaximumLength = 512;
			usProcessName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usProcessName.MaximumLength, MAXPROTECTOR_POOL_POOL_TAG);

			if (usProcessName.Buffer == NULL || !usProcessName.Buffer)
			{
				return OB_PREOP_SUCCESS;
			}

			if (GetImageNameByID(hProcessID, &usProcessName) == FALSE)
			{
				if (usProcessName.Buffer)
				{
					ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
				}
				return OB_PREOP_SUCCESS;
			}

			//if (IsOurProcessFile(&usProcessName))
			if (IsOurProcess2Protect(&usProcessName))
			{
				bOurProcess = TRUE;
			}
			
			usParentProcName.Length = 0;
			usParentProcName.MaximumLength = 512;
			usParentProcName.Buffer = ExAllocatePoolWithTag(NonPagedPool, usParentProcName.MaximumLength, MAXPROTECTOR_POOL_POOL_TAG);

			if (usParentProcName.Buffer == NULL || !usParentProcName.Buffer)
			{
				if (usProcessName.Buffer)
				{
					ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
				}
				return OB_PREOP_SUCCESS;
			}

			if (GetImageNameByID(hCurrentProcID, &usParentProcName) == FALSE)
			{
				if (usProcessName.Buffer)
				{
					ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
				}
				if (usParentProcName.Buffer)
				{
					ExFreePoolWithTag(usParentProcName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
				}
				return OB_PREOP_SUCCESS;
			}

			if (IsOurProcessFile(&usParentProcName))
			{
				bOurCurProcess = TRUE;
			}

			if (bOurProcess == TRUE && !bOurCurProcess)
			{
				if (IsOurPathFile(&usProcessName))
				{
					bProtectionBreached = TRUE;
					if (CheckHTTPSOperation(&usParentProcName) >= 0x00)
					{
						bIgnoreVMOperation = TRUE;
					}
				}
			}

			if (usProcessName.Buffer)
			{
				ExFreePoolWithTag(usProcessName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
			}
			if (usParentProcName.Buffer)
			{
				ExFreePoolWithTag(usParentProcName.Buffer, MAXPROTECTOR_POOL_POOL_TAG);
			}

			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_CREATE_PROCESS) == PROCESS_CREATE_PROCESS)
			{
				bProtectionBreached = FALSE;
				//OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
			}

			if (bProtectionBreached == TRUE)
			{
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_CREATE_PROCESS) == PROCESS_CREATE_PROCESS)
				{
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
				}
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
				{
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
				}

				//if (iIndex != MAX_PROC_LIVEUPDATE)
				if (bIgnoreVMOperation == FALSE)
				{
					if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
					{
						OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
					}
					if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
					{
						OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
					}
				}

				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_SUSPEND_RESUME) == PROCESS_SUSPEND_RESUME)
				{
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
				}

			}
		}
	}

	return OB_PREOP_SUCCESS;
}

VOID MaxObjectPostCallback(__in PVOID  RegistrationContext, __in POB_POST_OPERATION_INFORMATION  OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);
	/*
	if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
	{
		DbgPrint("[%05d] ##### GRANTED ACCESS = 0x%X !\n", PsGetCurrentProcessId(),OperationInformation->Parameters->CreateHandleInformation.GrantedAccess);
	}
	else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
	{
		DbgPrint("[%05d] ##### GRANTED (DUPLICATE) ACCESS = 0x%X !\n", PsGetCurrentProcessId(),OperationInformation->Parameters->CreateHandleInformation.GrantedAccess);
	}
	*/
	return;
}

NTSTATUS RegisteCallbackFunction()
{
	NTSTATUS					ntStatus = STATUS_SUCCESS;
	USHORT						registrationCount = 1;
	OB_OPERATION_REGISTRATION	RegisterOperation;
	USHORT						filterVersion = ObGetFilterVersion();
	OB_CALLBACK_REGISTRATION	RegisterCallBack;
	REG_CONTEXT					RegistrationContext;
	//OB_OPERATION_REGISTRATION RegisterOperation[1] = { { 0 }, { 0 } };
	
	memset(&RegisterOperation, 0, sizeof(OB_OPERATION_REGISTRATION));
	memset(&RegisterCallBack, 0, sizeof(OB_CALLBACK_REGISTRATION));
	memset(&RegistrationContext, 0, sizeof(REG_CONTEXT));

	RegistrationContext.ulIndex = 1;
	RegistrationContext.Version = 120;

	if (filterVersion == OB_FLT_REGISTRATION_VERSION)
	{
		/*
		RegisterOperation[0].ObjectType = PsProcessType;
		RegisterOperation[0].Operations |= OB_OPERATION_HANDLE_CREATE;
		RegisterOperation[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
		RegisterOperation[0].PreOperation = MaxObjectPreCallback;
		RegisterOperation[0].PostOperation = MaxObjectPostCallback;

		RegisterOperation[1].ObjectType = PsThreadType;
		RegisterOperation[1].Operations |= OB_OPERATION_HANDLE_CREATE;
		RegisterOperation[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
		RegisterOperation[1].PreOperation = MaxObjectPreCallback;
		RegisterOperation[1].PostOperation = MaxObjectPostCallback;
		*/

		RegisterOperation.ObjectType = PsProcessType;
		RegisterOperation.Operations = OB_OPERATION_HANDLE_CREATE;
		RegisterOperation.PreOperation = MaxObjectPreCallback;
		RegisterOperation.PostOperation = MaxObjectPostCallback;

		RegisterCallBack.Version = OB_FLT_REGISTRATION_VERSION;
		RegisterCallBack.OperationRegistrationCount = registrationCount;
		RtlInitUnicodeString(&RegisterCallBack.Altitude, L"328610");
		RegisterCallBack.RegistrationContext = &RegistrationContext;
		RegisterCallBack.OperationRegistration = &RegisterOperation;

		ntStatus = ObRegisterCallbacks(&RegisterCallBack, &g_hProcCreateHandle);
		if (ntStatus == STATUS_SUCCESS)
		{
			gbIsProcProtectionOn = TRUE;
		}
		else
		{
			if (ntStatus == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION)
			{
				//DbgPrint("[%05d] >>>>> Status Filter Instance Altitude Collision!\n", PsGetCurrentProcessId());
			}
			if (ntStatus == STATUS_INVALID_PARAMETER)
			{
				//DbgPrint("[%05d] >>>>> Status Invalid Parameter!\n", PsGetCurrentProcessId());
			}
			if (ntStatus == STATUS_INSUFFICIENT_RESOURCES)
			{
				//DbgPrint("[%05d] >>>>> Status Allocate Memory Failed!\n", PsGetCurrentProcessId());
			}
			//DbgPrint("[%05d] >>>>> Register Callback Function Failed with 0x%08x!\n", PsGetCurrentProcessId(), ntStatus);
		}
	}
	/*else
	{
		DbgPrint("Filter Version is not supported.\n");
	}*/
	return ntStatus;
}

int CheckHTTPSOperation(PUNICODE_STRING pEntryPath)
{
	BOOLEAN			bFoundMax = FALSE;
	UNICODE_STRING	usUpperPath = { 0 };
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

	while (iIndex < (iFullLen - 11))
	{
		if (usUpperPath.Buffer[iIndex] == '\\') 
		{
			if ((RtlCompareMemory(&usUpperPath.Buffer[iIndex], L"\\SYSTEM32\\LSASS.EXE", 19) == 19))
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

/***************************************************************************
Routine Description:
	This is the unload routine for the Filter driver.  This unregisters the
	Filter with the filter manager and frees any allocated global data
	structures.
Arguments:
	None.
Return Value:
	Returns the final status of the deallocation routines.
***************************************************************************/
NTSTATUS MaxProtectorUnload(__in FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);
	PAGED_CODE();

	gbIsProcProtectionOn = FALSE;
	gbIsProtectionOn = FALSE;

	//UnRegisteCallbackFunction();

	CleanUpDriver();

	return STATUS_SUCCESS;
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

	buffer = ExAllocatePoolWithTag(NonPagedPool, returnedLength, MAXPROTECTOR_POOL_POOL_TAG);
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
		ExFreePoolWithTag(buffer, MAXPROTECTOR_POOL_POOL_TAG);
	}

	return TRUE;
}