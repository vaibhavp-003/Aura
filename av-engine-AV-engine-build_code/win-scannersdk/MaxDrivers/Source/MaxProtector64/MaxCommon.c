#include <fltKernel.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include "MaxCommon.h"
//#ifndef __MAXPROTECTOR_COMMON_H__
//	#include "MaxCommon.h"
//#endif 

/*
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

BOOLEAN GetImageNameByID(HANDLE ProcessId, PUNICODE_STRING pusImageFileName)
{
	UNICODE_STRING ProcImgName = { 0 };
	HANDLE hProcessHandle = NULL;
	NTSTATUS status = STATUS_ACCESS_DENIED;
	PEPROCESS eProcess = NULL;
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


*/