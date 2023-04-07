#pragma once
#include "pch.h"
#include "S2S.h"
#include "USBDriveList.h"

const static int IOCTL_USB_TOTAL_BLOCK = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8009, METHOD_BUFFERED, FILE_ANY_ACCESS);
const static int IOCTL_USB_WRITE_BLOCK = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8010, METHOD_BUFFERED, FILE_ANY_ACCESS);
const static int IOCTL_USB_EXECUTE_BLOCK = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8011, METHOD_BUFFERED, FILE_ANY_ACCESS);
const static int IOCTL_USB_READ_BLOCK = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8012, METHOD_BUFFERED, FILE_ANY_ACCESS);
const static int IOCTL_USB_ACTIVITY_LOG = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8015, METHOD_BUFFERED, FILE_ANY_ACCESS);
/*
enum USBSetting
{
	ScanRemovable,
	AutoManual,
	TotalBlock,
	AutoRunINFBlock,
	ReadBlock,
	WriteBlock,
	ExecuteBlock,
	ActivityLog,
	BlockPhoneDevices,
	USBWhiteList,
	DontAskPassword
};
*/

typedef struct _USBSetting
{
	int iScanRemovable;
	int iAutoManualScan;
	int iTotalBlock;
	int iAutoRunINFBlock;
	int iReadBlock;
	int iWriteBlock;
	int iExecuteBlock;
	int iActivityLog;
	int iBlockPhoneDevices;
	int iUSBWhiteList;
	int iDontAskPassword;
	int iAskPhoneRestart;
} USBSetting;

class CUSBManager
{
public:
	CUSBManager();
	~CUSBManager();

public:
	CRegistry objReg;
	void GetInitialStatus();
	void GetUSBSettings(USBSetting* pUSBSetting);
	void SetUSBSettings(USBSetting* pUSBSetting);
	int ReadUsbRegistrySettings(ULONG ulTypeOfKey);
	void WriteUSBSettings(USBSetting* pUSBSetting);
	void SendDataToDriver(ULONG ulIoCode, ULONG data);
	void WriteUsbRegistrySettings(int iType, ULONG ulUsbSettings);
	void LoadUSBList(AttachedUSB * pAttachedUSB, int iAttachedUSBCnt);
	int LoadUSBListCnt();
	void DeleteUSBList(AttachedUSB* pAttachedUSB, int iAttachedUSBCnt);
	bool ViewUSBActivityLog();

public:
	bool m_bScanDevice;
	bool m_bAutoScanUsb;
	bool m_bManualScan;

	bool m_bReadButton;
	bool m_bWriteButton;
	bool m_bExecuteButton;
	bool m_bUSBLogButton;
	bool m_bUSBWhitelist;
	bool m_bAskForRestart;
	bool m_bBlockPhones;
	bool m_bUSBPWD;
	bool m_bTotalBlock;
	bool m_bBlockAutorun;
};

