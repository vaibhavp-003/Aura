/*=============================================================================
   FILE			: CPUInfo.h
   ABSTRACT		: This class provides methods to get details of CPU
   DOCUMENTS	: 
   AUTHOR		: Nupur Aggarwal 
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 21/11/2006
   NOTES		:
VERSION HISTORY	:				
============================================================================*/
#ifndef _CPUINFO_H_
#define _CPUINFO_H_


#include <winioctl.h>
#include "Registry.h"
#include <IPTypes.h>

class CCPUInfo
{
	LPOSVERSIONINFOEXW lpOSVersionInfo;

public:
	CCPUInfo(void);
	~CCPUInfo(void);
	CString		GetOSVersion();
	CString		GetServicePack();
	CString		GetOSVerTag();
	CString     GetOSVerTagFromRegistry();
	CString		GetProcessorName();
	CString		GetProcessorsCount();
	CString		GetProcessorSpeed();
	CString		GetProcessorIdentifier();
	CString		GetPCName();
	CString		GetVolumeSerialNo();
	CString		GetHardwareGUID();
	CString		GetHardWareProfileName();
	CString		GetIPAddress();
	CString		GetDiskSerialNo();
	CString		GetUserLocaleInfo();
	CString		GetRAMStatus();
	CString		GetHardDiskStatus();
	CString		GetDate(void);
	CString		GetMonthName(int iMonth);
	CString		GetProgramFilesDir();
	CString		GetProgramFilesDirX64();
	CString		GetSystemDir();
	CString		GetSystemWow64Dir();
	CString		GetWindowsDir();
	CString     GetTempDir();
	CString		GetEnvVariable();
	double		GetFreeSystemDiskSpace();
	DWORD		GetDpiValue();
	BOOL		CheckForAdminRights();
	CString		GetRootDrive();
	SYSTEMTIME  GetCurrSystemTime();
	BOOL		isOS64bit();
	CString		GetVendorID();
	CString		GetAPPDataPath();
	CString		GetAllUsersPath(void);
	CString		GetAllUserAppDataPath(void);
	CString		GetLocalAPPDataPath();
	CString		GetProdInstallPath();
	CString		GetMotherBoardSerialNumber(CString csMachineID);
	CString		GetOldMotherBoardSerialNumber(CString csMachineID);
	CString		GetProcessorSerialNumber();
	CString     GetVolumeSerialNumber();
	bool		FirewallXPCheck();
	bool		GetAllEnvVariable(CStringArray &csEnvVarArr);
	static		CString GetDirectoryPath(DWORD CSIDL_ID);
	bool		IsVistaServiceRequired();
	bool		GetMACaddress(CStringArray &arrMacAddress, CString &csAllAddress);
	PIP_ADAPTER_INFO GetAllAdapterInfo();

	DWORD		GetMajorOSVersion();
	bool		GetMajorAndMinorOSVersion(DWORD &dwMajorVersion, DWORD &dwMinorVersion);
	CString		GetRawMotherBoardID();
    bool		flagforuniqueid;
    bool		GetFlagForUniqueId();//true only if we get motherboard serialnumber or mac id  properly
	CString     GetRawNetworkMacID();
	CStringArray m_csarrMACAddresses;
private:
	CRegistry		m_objRegistry;
	CString			m_csDiskSerialNo;
	CString			m_chHardDriveSerialNumber;
	TCHAR			m_szMotherBoardID[MAX_PATH];
	TCHAR           m_szNetworkMacID[MAX_PATH];
	
	BOOL	_GetMotherBoardSerialNumberSEH();
	BOOL	_GetMotherBoardSerialNumber();
	BOOL    _GetNetworkMacIDSEH();
	BOOL    _GetNetworkMacID();
	
	INT		_GetHardDriveComputerID();
	INT		_ReadPhysicalDriveInNT ();
	INT		_ReadIdeDriveAsScsiDriveInNT (void);
	void	_PrintIdeInfo (int iDrive, DWORD diskdata [MAX_PATH]);
	BOOL	_DoIDENTIFY (HANDLE hPhysicalDriveIOCTL, PSENDCMDINPARAMS pSCIP,PSENDCMDOUTPARAMS pSCOP,
		BYTE bIDCmd, BYTE bDriveNum, PDWORD lpcbBytesReturned);
	CString	_ConvertToString (DWORD diskdata [MAX_PATH], int firstIndex, int lastIndex);
	void	CheckCharSet(CString &csMotherBoardNo);
	bool IsSafeBoot();
	

};

#endif //_CPUINFO_H_