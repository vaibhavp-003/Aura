#pragma once
#include "pch.h"
#include "USBInfo.h"

typedef struct _AttachedUSB
{
	wchar_t szUSBDrive[MAX_PATH];
	wchar_t szUSBSerialNumber[MAX_PATH];
	
} AttachedUSB;

class CUSBDriveList
{
public:
	CUSBDriveList();
	~CUSBDriveList();

public:
	int LoadListControl(AttachedUSB* pAttachedUSB, int ipAttachedUSBCnt);
	int GetUSBCount();
	CUSBInfo objUSBInfo;

	void WhiteListUSB(AttachedUSB* pAttachedUSB, TCHAR* szName);
};