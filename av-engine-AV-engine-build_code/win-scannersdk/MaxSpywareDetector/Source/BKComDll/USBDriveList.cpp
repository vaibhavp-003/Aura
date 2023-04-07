#include "pch.h"
#include "USBDriveList.h"
#include "USBDbOperations.h"
#include "MaxDeviceInfoManager.h"

CUSBDriveList::CUSBDriveList()
{

}

CUSBDriveList::~CUSBDriveList()
{

}


int CUSBDriveList::GetUSBCount()
{
	CUSBDbOperations	objUSBDbOperations;
	objUSBDbOperations.LoadDB();

	TCHAR		szDriveStrings[MAX_PATH] = { 0x00 };
	DWORD		dwBuffLen = MAX_PATH;
	TCHAR* pDummy = NULL;
	TCHAR		szDrive[0x10] = { 0x00 };
	CString		csDrive = L"";
	CString		csUSBSerialNumber = L"";

	GetLogicalDriveStrings(dwBuffLen, szDriveStrings);
	pDummy = szDriveStrings;

	int		iCount = 0;
	DWORD	dwData = 0;
	int		iUSBCount = 0;
	bool	bUsbFound = false;

	while (pDummy)
	{
		bUsbFound = false;
		csUSBSerialNumber.Format(L"");

		_stprintf_s(szDrive, 0x10, L"%s", pDummy);
		if (_tcslen(szDrive) == 0x00)
		{
			break;
		}
		csDrive.Format(_T("%s"), szDrive);
		CString csDebug;
		csDebug.Format(L"####Received Drive Type : %d for: %s ", GetDriveType(csDrive), csDrive);
		AddLogEntry(csDebug, 0, 0, true, LOG_DEBUG);
		if (GetDriveType(csDrive) == 2)
		{
			csDrive.Replace(L"\\", L"");
			csUSBSerialNumber = objUSBInfo.ExtractRemovableDrivesInfo(csDrive);
			csUSBSerialNumber.Trim();
			csUSBSerialNumber = L"";//always call IsPlugNPlayDevice
			AddLogEntry(L"####Got Drive Type 2:%s", csUSBSerialNumber, 0, true, LOG_DEBUG);
			if (csUSBSerialNumber.GetLength() > 0x4)//temp changes to get Serial ID
			{
				bUsbFound = true;
			}
			else
			{
				TCHAR					szDeviceID[512] = { 0x00 };
				CMaxDeviceInfoManager	objDeviceInfo;

				if (objDeviceInfo.IsPlugNPlayDevice(szDrive, szDeviceID))
				{
					bUsbFound = true;
					csUSBSerialNumber.Format(L"%s", szDeviceID);
					csUSBSerialNumber.Trim();
				}
			}

		}
		else
		{
			TCHAR					szDeviceID[512] = { 0x00 };
			CMaxDeviceInfoManager	objDeviceInfo;

			if (objDeviceInfo.IsPlugNPlayDevice(szDrive, szDeviceID))
			{
				bUsbFound = true;
				csUSBSerialNumber.Format(L"%s", szDeviceID);
				csUSBSerialNumber.Trim();
				AddLogEntry(L"####Got Drive Type other than 2:%s", csUSBSerialNumber, 0, true, LOG_DEBUG);
			}
		}

		//if(csUSBSerialNumber.GetLength() > 0x00) //2 for removable drive	
		if (bUsbFound == true)
		{
			if (csUSBSerialNumber.GetLength() >= 4)
			{
				if (!objUSBDbOperations.SearchSerialNo(csUSBSerialNumber))//if(!m_pUSBWhiteDb->SearchItem(csUSBSerialNumber,&dwData))
				{
					//
					//int index = m_lstAttachedUSBList.InsertItem(iCount, csDrive);
					//m_lstAttachedUSBList.SetItemText(index, 1, csUSBSerialNumber);
				}
			}
			else
			{
				csUSBSerialNumber = L"USB Serial not available";
				
				//int index = m_lstAttachedUSBList.InsertItem(iCount, csDrive);
				//m_lstAttachedUSBList.SetItemText(index, 1, csUSBSerialNumber);
			}
			iUSBCount++;
		}
		iCount++;
		pDummy += (_tcslen(szDriveStrings) + 0x01);
	}

	return iUSBCount;
}

int CUSBDriveList::LoadListControl(AttachedUSB* pAttachedUSB, int ipAttachedUSBCnt)
{
	CUSBDbOperations	objUSBDbOperations;
	objUSBDbOperations.LoadDB();

	TCHAR		szDriveStrings[MAX_PATH] = { 0x00 };
	DWORD		dwBuffLen = MAX_PATH;
	TCHAR* pDummy = NULL;
	TCHAR		szDrive[0x10] = { 0x00 };
	CString		csDrive = L"";
	CString		csUSBSerialNumber = L"";

	GetLogicalDriveStrings(dwBuffLen, szDriveStrings);
	pDummy = szDriveStrings;

	int		iCount = 0;
	DWORD	dwData = 0;
	int		iUSBCount = 0;
	bool	bUsbFound = false;

	while (pDummy)
	{
		bUsbFound = false;
		csUSBSerialNumber.Format(L"");

		_stprintf_s(szDrive, 0x10, L"%s", pDummy);
		if (_tcslen(szDrive) == 0x00)
		{
			break;
		}
		csDrive.Format(_T("%s"), szDrive);
		CString csDebug;
		csDebug.Format(L"####Received Drive Type : %d for: %s ", GetDriveType(csDrive), csDrive);
		AddLogEntry(csDebug, 0, 0, true, LOG_DEBUG);
		if (GetDriveType(csDrive) == 2)
		{
			csDrive.Replace(L"\\", L"");
			csUSBSerialNumber = objUSBInfo.ExtractRemovableDrivesInfo(csDrive);
			csUSBSerialNumber.Trim();
			csUSBSerialNumber = L"";//always call IsPlugNPlayDevice
			AddLogEntry(L"####Got Drive Type 2:%s", csUSBSerialNumber, 0, true, LOG_DEBUG);
			if (csUSBSerialNumber.GetLength() > 0x4)//temp changes to get Serial ID
			{
				bUsbFound = true;
			}
			else
			{
				TCHAR					szDeviceID[512] = { 0x00 };
				CMaxDeviceInfoManager	objDeviceInfo;

				if (objDeviceInfo.IsPlugNPlayDevice(szDrive, szDeviceID))
				{
					bUsbFound = true;
					csUSBSerialNumber.Format(L"%s", szDeviceID);
					csUSBSerialNumber.Trim();
				}
			}

		}
		else
		{
			TCHAR					szDeviceID[512] = { 0x00 };
			CMaxDeviceInfoManager	objDeviceInfo;

			if (objDeviceInfo.IsPlugNPlayDevice(szDrive, szDeviceID))
			{
				bUsbFound = true;
				csUSBSerialNumber.Format(L"%s", szDeviceID);
				csUSBSerialNumber.Trim();
				AddLogEntry(L"####Got Drive Type other than 2:%s", csUSBSerialNumber, 0, true, LOG_DEBUG);
			}
		}

		//if(csUSBSerialNumber.GetLength() > 0x00) //2 for removable drive	
		if (bUsbFound == true)
		{
			if (csUSBSerialNumber.GetLength() >= 4)
			{
				if (!objUSBDbOperations.SearchSerialNo(csUSBSerialNumber))//if(!m_pUSBWhiteDb->SearchItem(csUSBSerialNumber,&dwData))
				{
					wcscpy_s(pAttachedUSB[iUSBCount].szUSBDrive, csDrive);
					wcscpy_s(pAttachedUSB[iUSBCount].szUSBSerialNumber, csUSBSerialNumber);
					//
					//int index = m_lstAttachedUSBList.InsertItem(iCount, csDrive);
					//m_lstAttachedUSBList.SetItemText(index, 1, csUSBSerialNumber);
				}
			}
			else
			{
				csUSBSerialNumber = L"USB Serial not available";
				wcscpy_s(pAttachedUSB[iUSBCount].szUSBDrive, csDrive);
				wcscpy_s(pAttachedUSB[iUSBCount].szUSBSerialNumber, csUSBSerialNumber);
				//int index = m_lstAttachedUSBList.InsertItem(iCount, csDrive);
				//m_lstAttachedUSBList.SetItemText(index, 1, csUSBSerialNumber);
			}
			iUSBCount++;
		}
		iCount++;
		pDummy += (_tcslen(szDriveStrings) + 0x01);
	}

	return iUSBCount;
}

void CUSBDriveList::WhiteListUSB(AttachedUSB* pAttachedUSB, TCHAR* szName)
{
	CUSBDbOperations objUSBDbOperations;
	objUSBDbOperations.LoadDB();
	CString csSerialNumber = pAttachedUSB->szUSBSerialNumber;
	if (csSerialNumber.CompareNoCase(_T("USB Serial not available")) == 0)
	{
		return;
	}
	if (csSerialNumber.GetLength() <= 4)
	{
		return;
	}

	if (objUSBDbOperations.SearchSerialNo(csSerialNumber))
	{
		return;
	}
	objUSBDbOperations.AddSerialNo(csSerialNumber, szName);
	objUSBDbOperations.SaveDB();
}