#include "pch.h"
#include "MaxDeviceInfoManager.h"

BOOL GetDriveTypeAndCharacteristics (HANDLE hDevice, DEVICE_TYPE *pDeviceType, ULONG *pCharacteristics)
{
	HMODULE hNtDll;
	LPFN_NT_QUERY_VOLUME_INFORMATION_FILE lpfnNtQueryVolumeInformationFile;
	NTSTATUS ntStatus;
	IO_STATUS_BLOCK IoStatusBlock;
	FILE_FS_DEVICE_INFORMATION FileFsDeviceInfo;
	BOOL bSuccess = FALSE;

	hNtDll = GetModuleHandle (TEXT("ntdll.dll"));
	if (hNtDll == NULL)
		return FALSE;

	lpfnNtQueryVolumeInformationFile = (LPFN_NT_QUERY_VOLUME_INFORMATION_FILE)GetProcAddress (hNtDll, "NtQueryVolumeInformationFile");
	if (lpfnNtQueryVolumeInformationFile == NULL)
		return FALSE;

	ntStatus = lpfnNtQueryVolumeInformationFile (hDevice, &IoStatusBlock,
		&FileFsDeviceInfo, sizeof(FileFsDeviceInfo),
		FileFsDeviceInformation);
	if (ntStatus == NO_ERROR) {
		bSuccess = TRUE;
		*pDeviceType = FileFsDeviceInfo.DeviceType;
		*pCharacteristics = FileFsDeviceInfo.Characteristics;
	}

	return bSuccess;
}

void FildVolumeName (LPCTSTR pszDeviceName)
{
	TCHAR szVolumeName[MAX_PATH] = TEXT("");
	TCHAR szDeviceName[MAX_PATH] = TEXT("");
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD dwCharCount;
	BOOL bSuccess;

	hFind = FindFirstVolume (szVolumeName, ARRAYSIZE(szVolumeName));
	if (hFind == INVALID_HANDLE_VALUE) return;

	while(TRUE) {
		//  Skip the \\?\ prefix and remove the trailing backslash.
		size_t Index = lstrlen(szVolumeName) - 1;
		if (szVolumeName[0]     != TEXT('\\') ||
			szVolumeName[1]     != TEXT('\\') ||
			szVolumeName[2]     != TEXT('?')  ||
			szVolumeName[3]     != TEXT('\\') ||
			szVolumeName[Index] != TEXT('\\')) return; // error

		//  QueryDosDeviceW doesn't allow a trailing backslash,
		//  so temporarily remove it.
		szVolumeName[Index] = TEXT('\0');
		dwCharCount = QueryDosDevice (&szVolumeName[4], szDeviceName, ARRAYSIZE(szDeviceName));
		szVolumeName[Index] = TEXT('\\');
		if (dwCharCount == 0) return; // error

		if (lstrcmp (pszDeviceName, szDeviceName) == 0) {
			_tprintf (TEXT("    Volume Device Name: %s\n"), szVolumeName);
			return;
		}

		bSuccess = FindNextVolume (hFind, szVolumeName, ARRAYSIZE(szVolumeName));
		if (!bSuccess) {
			DWORD dwErrorCode = GetLastError();
			if (dwErrorCode == ERROR_NO_MORE_ITEMS)
				break;
			else 
				break;  // ERROR!!!
		}
	}
}

void DumpVidPidMi (LPCTSTR pszDeviceInstanceId)
{
	TCHAR szDeviceInstanceId[MAX_DEVICE_ID_LEN];
	const static LPCTSTR arPrefix[3] = {TEXT("VID_"), TEXT("PID_"), TEXT("MI_")};
	LPTSTR pszToken, pszNextToken;
	int j;

	lstrcpy (szDeviceInstanceId, pszDeviceInstanceId);

	pszToken = _tcstok_s (szDeviceInstanceId , TEXT("\\#&"), &pszNextToken);
	while(pszToken != NULL) {
		for (j = 0; j < 3; j++) {
			if (_tcsncmp(pszToken, arPrefix[j], lstrlen(arPrefix[j])) == 0) {
				switch(j) {
					case 0:
						_tprintf (TEXT("        vid: \"%s\"\n"), pszToken + lstrlen(arPrefix[j]));
						break;
					case 1:
						_tprintf (TEXT("        pid: \"%s\"\n"), pszToken + lstrlen(arPrefix[j]));
						break;
					case 2:
						_tprintf (TEXT("        mi: \"%s\"\n"), pszToken + lstrlen(arPrefix[j]));
						break;
					default:
						break;
				}
			}
		}
		pszToken = _tcstok_s (NULL, TEXT("\\#&"), &pszNextToken);
	}
}

BOOL FindDiInfos (LPCGUID pGuidInferface, LPCGUID pGuidClass, LPCTSTR pszEnumerator,
				  DEVICE_TYPE DeviceType, DWORD DeviceNumber,
				  DWORD dwDeviceInstanceIdSize,     // MAX_DEVICE_ID_LEN
				  OUT LPTSTR pszDeviceInstanceId,
				  OUT PDWORD pdwRemovalPolicy)
				  //#define CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL             1
				  //#define CM_REMOVAL_POLICY_EXPECT_ORDERLY_REMOVAL        2
				  //#define CM_REMOVAL_POLICY_EXPECT_SURPRISE_REMOVAL       3
{
	HDEVINFO hIntDevInfo = NULL;
	DWORD dwIndex;
	BOOL bFound = FALSE; 
	HANDLE hDev = INVALID_HANDLE_VALUE;
	PSP_DEVICE_INTERFACE_DETAIL_DATA pInterfaceDetailData = NULL;

	// set defaults
	*pdwRemovalPolicy = 0;
	pszDeviceInstanceId[0] = TEXT('\0');

	__try {
		hIntDevInfo = SetupDiGetClassDevs (pGuidInferface, pszEnumerator, NULL,
			pGuidInferface != NULL? DIGCF_PRESENT | DIGCF_DEVICEINTERFACE:
			DIGCF_ALLCLASSES | DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
		if (hIntDevInfo == INVALID_HANDLE_VALUE)
			__leave;

		for (dwIndex = 0; ;dwIndex ++) {
			SP_DEVICE_INTERFACE_DATA interfaceData;
			SP_DEVINFO_DATA deviceInfoData;
			DWORD dwDataType, dwRequiredSize;
			BOOL bSuccess;

			ZeroMemory (&interfaceData, sizeof(interfaceData));
			interfaceData.cbSize = sizeof(interfaceData);
			bSuccess = SetupDiEnumDeviceInterfaces (hIntDevInfo, NULL, pGuidInferface, dwIndex, &interfaceData);
			if (!bSuccess) {
				DWORD dwErrorCode = GetLastError();
				if (dwErrorCode == ERROR_NO_MORE_ITEMS)
					break;
				else 
					break;  // ERROR!!!
			}

			dwRequiredSize = 0;
			bSuccess = SetupDiGetDeviceInterfaceDetail (hIntDevInfo, &interfaceData, NULL, 0, &dwRequiredSize, NULL);
			if ((!bSuccess && GetLastError() != ERROR_INSUFFICIENT_BUFFER) || dwRequiredSize == 0)
				continue;  // ERROR!!!

			if (pInterfaceDetailData)
				pInterfaceDetailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA) LocalFree (pInterfaceDetailData);

			pInterfaceDetailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA) LocalAlloc (LPTR, dwRequiredSize);
			pInterfaceDetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
			ZeroMemory (&deviceInfoData, sizeof(deviceInfoData));
			deviceInfoData.cbSize = sizeof(deviceInfoData);
			bSuccess = SetupDiGetDeviceInterfaceDetail (hIntDevInfo, &interfaceData,
				pInterfaceDetailData, dwRequiredSize, &dwRequiredSize, &deviceInfoData);
			if (!bSuccess)
				continue;

			hDev = CreateFile (pInterfaceDetailData->DevicePath, 
				0,                                   // no access to the drive
				FILE_SHARE_READ | FILE_SHARE_WRITE,  // share mode
				NULL,                                // default security attributes
				OPEN_EXISTING,                       // disposition
				0,                                   // file attributes
				NULL);                               // do not copy file attributes
			if (hDev != INVALID_HANDLE_VALUE) {
				STORAGE_DEVICE_NUMBER sdn;
				DWORD cbBytesReturned;
				bSuccess = DeviceIoControl (hDev,                           // device to be queried
					IOCTL_STORAGE_GET_DEVICE_NUMBER, 
					NULL, 0,                        // no input buffer
					(LPVOID)&sdn, sizeof(sdn),	    // output buffer
					&cbBytesReturned,               // # bytes returned
					(LPOVERLAPPED) NULL);           // synchronous I/O
				if (bSuccess) {
					if (sdn.DeviceType == DeviceType &&
						sdn.DeviceNumber == DeviceNumber) {

							DEVINST dnDevInstParent, dnDevInstParentParent;
							CONFIGRET ret;
							// device found !!!
							TCHAR szBuffer[4096];

							_tprintf (TEXT("    DevicePath: %s\n"), pInterfaceDetailData->DevicePath);

							bSuccess = SetupDiGetDeviceInstanceId (hIntDevInfo, &deviceInfoData, pszDeviceInstanceId,
								dwDeviceInstanceIdSize, &dwRequiredSize);
							if (dwRequiredSize > MAX_DEVICE_ID_LEN)
								continue;

							bSuccess = SetupDiGetDeviceRegistryProperty (hIntDevInfo, &deviceInfoData, SPDRP_REMOVAL_POLICY, &dwDataType,
								(PBYTE)pdwRemovalPolicy, sizeof(DWORD), &dwRequiredSize);
							// SPDRP_CHARACTERISTICS - Device characteristics
							//         FILE_FLOPPY_DISKETTE, FILE_REMOVABLE_MEDIA, and FILE_WRITE_ONCE_MEDIA characteristics 
							//         FILE_READ_ONLY_DEVICE
							bSuccess = SetupDiGetDeviceRegistryProperty (hIntDevInfo, &deviceInfoData, SPDRP_CLASS, &dwDataType,
								(PBYTE)szBuffer, sizeof(szBuffer), &dwRequiredSize);
							if (bSuccess)
								_tprintf (TEXT("    Class: \"%s\"\n"), szBuffer);
							bSuccess = SetupDiGetDeviceRegistryProperty (hIntDevInfo, &deviceInfoData, SPDRP_HARDWAREID, &dwDataType,
								(PBYTE)szBuffer, sizeof(szBuffer), &dwRequiredSize);
							if (bSuccess) {
								LPCTSTR pszId;
								_tprintf (TEXT("    Hardware IDs:\n"));
								for (pszId=szBuffer;
									*pszId != TEXT('\0') && pszId + dwRequiredSize/sizeof(TCHAR) <= szBuffer + ARRAYSIZE(szBuffer);
									pszId += lstrlen(pszId)+1) {

										_tprintf (TEXT("        \"%s\"\n"), pszId);
								}
							}
							bSuccess = SetupDiGetDeviceRegistryProperty (hIntDevInfo, &deviceInfoData, SPDRP_FRIENDLYNAME, &dwDataType,
								(PBYTE)szBuffer, sizeof(szBuffer), &dwRequiredSize);
							if (bSuccess)
								_tprintf (TEXT("    Friendly Name: \"%s\"\n"), szBuffer);

							bSuccess = SetupDiGetDeviceRegistryProperty (hIntDevInfo, &deviceInfoData, SPDRP_PHYSICAL_DEVICE_OBJECT_NAME, &dwDataType,
								(PBYTE)szBuffer, sizeof(szBuffer), &dwRequiredSize);
							if (bSuccess)
								_tprintf (TEXT("    Physical Device Object Name: \"%s\"\n"), szBuffer);

							bSuccess = SetupDiGetDeviceRegistryProperty (hIntDevInfo, &deviceInfoData, SPDRP_DEVICEDESC, &dwDataType,
								(PBYTE)szBuffer, sizeof(szBuffer), &dwRequiredSize);
							if (bSuccess)
								_tprintf (TEXT("    Device Description: \"%s\"\n"), szBuffer);
							bFound = TRUE;

							ret = CM_Get_Parent (&dnDevInstParent, deviceInfoData.DevInst, 0);
							if (ret == CR_SUCCESS) {
								TCHAR szDeviceInstanceID[MAX_DEVICE_ID_LEN];
								ret = CM_Get_Device_ID (dnDevInstParent, szDeviceInstanceID, ARRAY_SIZE(szDeviceInstanceID), 0);
								if (ret == CR_SUCCESS) {
									_tprintf (TEXT("    Parent Device Instance ID: %s\n"), szDeviceInstanceID);
									DumpVidPidMi (szDeviceInstanceID);
									ret = CM_Get_Parent (&dnDevInstParentParent, dnDevInstParent, 0);
									if (ret == CR_SUCCESS) {
										ret = CM_Get_Device_ID (dnDevInstParentParent, szDeviceInstanceID, ARRAY_SIZE(szDeviceInstanceID), 0);
										if (ret == CR_SUCCESS)
											_tprintf (TEXT("    Parent of Parent Device Instance ID: %s\n"), szDeviceInstanceID);
									}
								}
							}
							break;
					}
				}

				CloseHandle (hDev);
				hDev = INVALID_HANDLE_VALUE;
			}
		}
	}
	__finally {
		if (pInterfaceDetailData)
			pInterfaceDetailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA) LocalFree (pInterfaceDetailData);

		if (hDev != INVALID_HANDLE_VALUE)
			CloseHandle (hDev);

		if (hIntDevInfo)
			SetupDiDestroyDeviceInfoList (hIntDevInfo);
	}

	return bFound;
}

LPCTSTR DumpBusTypeAsString (STORAGE_BUS_TYPE type)
{
	const static LPCTSTR arStorageBusTypeNames[] = {
		TEXT("Unknown"),					// BusTypeUnknown = 0
		TEXT("SCSI"),						// BusTypeScsi = 1
		TEXT("ATAPI"),						// BusTypeAtapi = 2
		TEXT("ATA"),						// BusTypeAta = 3
		TEXT("IEEE-1394"),					// BusType1394 = 4
		TEXT("SSA"),						// BusTypeSsa = 5
		TEXT("Fibre Channel"),				// BusTypeFibre = 6
		TEXT("USB"),						// BusTypeUsb = 7
		TEXT("RAID"),						// BusTypeRAID = 8
		TEXT("iSCSI"),						// BusTypeiScsi = 9
		TEXT("Serial Attached SCSI (SAS)"),	// BusTypeSas = 10
		TEXT("SATA"),						// BusTypeSata = 11
		TEXT("SD"),							// BusTypeSd = 12
		TEXT("MMC"),						// BusTypeMmc = 13
		TEXT("Virtual"),					// BusTypeVirtual = 14
		TEXT("FileBackedVirtual")			// BusTypeFileBackedVirtual = 15
	};

	//if (type <= BusTypeFileBackedVirtual)
	if (type <= 15)
		return arStorageBusTypeNames[type];
	else
		return NULL;
}

CMaxDeviceInfoManager::CMaxDeviceInfoManager(void)
{
}

CMaxDeviceInfoManager::~CMaxDeviceInfoManager(void)
{
}

BOOL CMaxDeviceInfoManager::GetDeviceDetails(LPCTSTR pszDriveLetter, LPTSTR pszDeviceIdentifier)
{
	BOOL					bIsRemoveable = FALSE;
	TCHAR					szDeviceName[7] = TEXT("\\\\.\\");
	DWORD					dwRemovalPolicy;
	STORAGE_PROPERTY_QUERY	spq;
	BYTE					byBuffer[4096] = {0x00};
	TCHAR					szDeviceInstanceId[MAX_DEVICE_ID_LEN] = {0x00};
	GUID					*pGuidInferface = NULL, *pGuidClass = NULL;
	LPCTSTR					pszEnumerator = NULL;
	TCHAR					szVolumeName[MAX_PATH+1] = {0x00}, szFileSystemName[MAX_PATH+1] = {0x00}, szNtDeviceName[MAX_PATH+1] = {0x00};
	DWORD					dwVolumeSerialNumber, dwMaximumComponentLength, dwFileSystemFlags;
	HANDLE					hDevice; 
	DWORD					cbBytesReturned;
	STORAGE_DEVICE_NUMBER	sdn;
	BOOL					bSuccess;
	LPTSTR					pszDriveRoot;
	TCHAR					szLogLine[1024] = {0x00};

	//HMODULE hm = LoadLibrary (TEXT("C:\\Program Files\\Microsoft Office\\Office14\\OUTLOOK.EXE"));
	
	szDeviceName[4] = pszDriveLetter[0];
	szDeviceName[5] = TEXT(':');
	szDeviceName[6] = TEXT('\0');
	
	//_stprintf(szLogLine,L"Drive %c:\n",pszDriveRoot[0]);
	//AddLogEntry(szLogLine);

	// how to find Volume name: \\?\Volume{4c1b02c1-d990-11dc-99ae-806e6f6e6963}\
	// for the Paths:  C:\
	// or device name like \Device\HarddiskVolume2 or \Device\CdRom0
	cbBytesReturned = QueryDosDevice (&szDeviceName[4], szNtDeviceName, ARRAYSIZE(szNtDeviceName));
	if (cbBytesReturned) 
	{
		//_stprintf(szLogLine,L"    Dos Device Name: %s\n",szNtDeviceName);
		//AddLogEntry(szLogLine);
		FildVolumeName(szNtDeviceName);
	}

	pszDriveRoot = (LPTSTR)pszDriveLetter;
	bSuccess = GetVolumeInformation (pszDriveRoot, szVolumeName, ARRAYSIZE(szVolumeName),&dwVolumeSerialNumber, &dwMaximumComponentLength, &dwFileSystemFlags, szFileSystemName, ARRAYSIZE(szFileSystemName));
	if (bSuccess) 
	{
		//_stprintf(szLogLine,L"    Volume Name: \"%s\"\n",szVolumeName);
		//AddLogEntry(szLogLine);
	}

	hDevice = CreateFile( szDeviceName,
						  //FILE_READ_DATA, //0 - no access to the drive, for IOCTL_STORAGE_CHECK_VERIFY is FILE_READ_DATA needed
						  FILE_READ_ATTRIBUTES, // for IOCTL_STORAGE_CHECK_VERIFY2
						  FILE_SHARE_READ | FILE_SHARE_WRITE,	// share mode
						  NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		//__leave;
		return bIsRemoveable;
	}

	spq.PropertyId = StorageDeviceProperty;
	spq.QueryType = PropertyStandardQuery;
	spq.AdditionalParameters[0] = 0;

	bSuccess = DeviceIoControl( hDevice,                         // device to be queried
							    IOCTL_STORAGE_QUERY_PROPERTY,    // operation to perform
							    &spq, sizeof(spq),               // input buffer
								&byBuffer, sizeof(byBuffer),	 // output buffer
								&cbBytesReturned,                // # bytes returned
								(LPOVERLAPPED) NULL);            // synchronous I/O

	if (bSuccess) 
	{
		STORAGE_DEVICE_DESCRIPTOR *psdp = (STORAGE_DEVICE_DESCRIPTOR *)byBuffer;
		
		/*
		LPCTSTR pszBusType = DumpBusTypeAsString(psdp->BusType);
		
		if (pszBusType)
			//_tprintf (TEXT("    Bus Type: %s\n"), pszBusType);
			_stprintf(szLogLine,L"    Bus Type: %s\n",pszBusType);
		else
			//_tprintf (TEXT("    Bus Type: Unknown (%d)\n"), psdp->BusType);
			_stprintf(szLogLine,L"    Bus Type: Unknown (%d)\n",psdp->BusType);
		if (psdp->VendorIdOffset)
			//_tprintf (TEXT("    VendorId: \"%hs\"\n"), (LPCSTR)((PBYTE)psdp + psdp->VendorIdOffset));
			_stprintf(szLogLine,L"    VendorId: \"%hs\"\n",(LPCSTR)((PBYTE)psdp + psdp->VendorIdOffset));
		if (psdp->ProductIdOffset)
			//_tprintf (TEXT("    ProductId: \"%hs\"\n"), (LPCSTR)((PBYTE)psdp + psdp->ProductIdOffset));
			_stprintf(szLogLine,L"    ProductId: \"%hs\"\n",(LPCSTR)((PBYTE)psdp + psdp->ProductIdOffset));
		if (psdp->ProductRevisionOffset)
			//_tprintf (TEXT("    ProductRevision: \"%hs\"\n"), (LPCSTR)((PBYTE)psdp + psdp->ProductRevisionOffset));
			_stprintf(szLogLine,L"    ProductRevision: \"%hs\"\n",(LPCSTR)((PBYTE)psdp + psdp->ProductRevisionOffset));

		//_stprintf(szLogLine,L"    Volume Name: \"%s\"\n",szVolumeName);
		AddLogEntry(szLogLine);
		*/
		if (psdp->RemovableMedia)
		{
			bIsRemoveable = TRUE;
		}
	}

	cbBytesReturned = 0;
	bSuccess = DeviceIoControl( hDevice,                     // device to be queried
								IOCTL_STORAGE_CHECK_VERIFY2,
								NULL, 0,                     // no input buffer
								NULL, 0,					 // no output buffer
								&cbBytesReturned,            // # bytes returned
								(LPOVERLAPPED) NULL);        // synchronous I/O

	if (bSuccess)
	{
		//_stprintf(szLogLine,L"    the device media are accessible\n");
	}
	else if (GetLastError() == ERROR_NOT_READY)
	{
		//_stprintf(szLogLine,L"    the device media are not accessible\n");
	}
	//AddLogEntry(szLogLine);

	bSuccess = DeviceIoControl( hDevice,                         // device to be queried
								IOCTL_STORAGE_GET_DEVICE_NUMBER, 
								NULL, 0,                         // no input buffer
								(LPVOID)&sdn, sizeof(sdn),	     // output buffer
								&cbBytesReturned,                // # bytes returned
								(LPOVERLAPPED) NULL);            // synchronous I/O

	// GetLastError of ERROR_MORE_DATA indicates to the caller that the buffer was not large enough to accommodate the data requested
	if (!bSuccess)
	{
		//__leave;
		return bIsRemoveable;
	}

	//_stprintf(szLogLine,L"    DeviceType: %d, DeviceNumber: %d, PartitionNumber: %d\n", sdn.DeviceType, sdn.DeviceNumber, sdn.PartitionNumber);
	//AddLogEntry(szLogLine);

	pGuidInferface = NULL;
	pGuidClass = NULL;

	if (sdn.DeviceType == FILE_DEVICE_CD_ROM || sdn.DeviceType == FILE_DEVICE_DVD) 
	{
		pGuidInferface = (GUID*)&GUID_DEVINTERFACE_CDROM;
		pGuidClass = (GUID*)&GUID_DEVCLASS_CDROM;
	}
	else if (sdn.DeviceType == FILE_DEVICE_DISK) 
	{
		DEVICE_TYPE		DeviceType;
		ULONG			ulCharacteristics;
		bSuccess = GetDriveTypeAndCharacteristics (hDevice, &DeviceType, &ulCharacteristics);
		if (bSuccess) 
		{
			if ((ulCharacteristics & FILE_FLOPPY_DISKETTE) == FILE_FLOPPY_DISKETTE) 
			{
				pGuidInferface = (GUID*)&GUID_DEVINTERFACE_FLOPPY;
				pGuidClass = (GUID*)&GUID_DEVCLASS_FLOPPYDISK;
			}
			else 
			{
				pGuidInferface = (GUID*)&GUID_DEVINTERFACE_DISK;
				pGuidClass = (GUID*)&GUID_DEVCLASS_DISKDRIVE;
			}

			if ((ulCharacteristics & FILE_REMOVABLE_MEDIA) == FILE_REMOVABLE_MEDIA)
			{
				bIsRemoveable = TRUE;
			}
		}
	}
	// GUID_DEVCLASS_MEDIUM_CHANGER

	if (CloseHandle (hDevice))
	{
		hDevice = INVALID_HANDLE_VALUE;
	}

	bSuccess = FindDiInfos (pGuidInferface, pGuidClass, pszEnumerator, sdn.DeviceType, sdn.DeviceNumber,ARRAY_SIZE(szDeviceInstanceId), szDeviceInstanceId, &dwRemovalPolicy);
	
	if (bSuccess) 
	{
		if (dwRemovalPolicy == CM_REMOVAL_POLICY_EXPECT_SURPRISE_REMOVAL || dwRemovalPolicy == CM_REMOVAL_POLICY_EXPECT_ORDERLY_REMOVAL)
		{
			bIsRemoveable = TRUE;
		}
		
		if (pszDeviceIdentifier != NULL)
		{
			if (_tcslen(szDeviceInstanceId) > 0x00)
			{
				TCHAR	*pTemp = NULL;
				TCHAR	szDummy[1024] = {0x00};
				_tcscpy(szDummy,szDeviceInstanceId);
				pTemp = _tcsrchr(szDummy,'\\');
				if (pTemp != NULL)
				{
					pTemp++;
					if (pTemp != NULL)
					{
						_tcscpy(szDeviceInstanceId,pTemp);
					}
				}
				pTemp = _tcsrchr(szDeviceInstanceId,'&');
				if (pTemp != NULL)
				{
					*pTemp = '\0';
					pTemp = NULL;
				}

			}
			_tcscpy(pszDeviceIdentifier,szDeviceInstanceId);
		}

		/*
		_stprintf(szLogLine,L"    DeviceInstanceId: %s\n", szDeviceInstanceId);
		AddLogEntry(szLogLine);
		if (bIsRemoveable)
		{
			_stprintf(szLogLine,L"    Drive %c: is removeable\n", pszDriveRoot[0]);
			AddLogEntry(szLogLine);
		}
		*/
	}

	return bIsRemoveable;
}

BOOL CMaxDeviceInfoManager::IsPlugNPlayDevice(LPCTSTR pszDriveLetter, LPTSTR pszDeviceIdentifier)
{
	BOOL	bRetValue = FALSE;

	if (pszDriveLetter == NULL)
	{
		return bRetValue;
	}

	bRetValue = GetDeviceDetails(pszDriveLetter,pszDeviceIdentifier);

	return bRetValue;
}