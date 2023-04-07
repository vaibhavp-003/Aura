/*=============================================================================
   FILE			: CPUInfo.cpp
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
VERSION HISTORY	:16 Aug 2007 : Avinash B
				 Unicode Supported.
                 23-Oct-2009 : Sandip Sanap
                 Add the function GetOSVerTagFromRegistry().
				
============================================================================*/
#include "pch.h"
#include <winsock.h>
#include <winioctl.h>
#include <direct.h>
#include <atlcomtime.h>
//#include <shfolder.h>
#include <shlobj.h>//avinash
#include "HardDiskManager.h"
#include "CPUInfo.h"
#include "MaxExceptionFilter.h"
#include <Iphlpapi.h>
#include "MaxConstant.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma warning(disable : 4996)

extern "C" IMAGE_DOS_HEADER __ImageBase;
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


#define _WIN32_DCOM
//#include <iostream>
using namespace std;
#include <comdef.h>
#include <Wbemidl.h>

# pragma comment(lib, "wbemuuid.lib")

#define  MAX_IDE_DRIVES  4    //  Max number of drives assuming primary/secondary, master/slave topology
#define  SENDIDLENGTH  sizeof (SENDCMDOUTPARAMS) + MAX_BUFFER

typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);

//  GETVERSIONOUTPARAMS contains the data returned from the GetDriverVersion function.
typedef struct _GETVERSIONOUTPARAMS
{
	BYTE bVersion;      // Binary driver version.
	BYTE bRevision;     // Binary driver revision.
	BYTE bReserved;     // Not used.
	BYTE bIDEDeviceMap; // Bit map of IDE devices.
	DWORD fCapabilities; // Bit mask of driver capabilities.
	DWORD dwReserved[4]; // For future use.
} GETVERSIONOUTPARAMS, *PGETVERSIONOUTPARAMS, *LPGETVERSIONOUTPARAMS;

// The following struct defines the interesting part of the IDENTIFY
// buffer:
typedef struct _IDSECTOR
{
	USHORT  wGenConfig;
	USHORT  wNumCyls;
	USHORT  wReserved;
	USHORT  wNumHeads;
	USHORT  wBytesPerTrack;
	USHORT  wBytesPerSector;
	USHORT  wSectorsPerTrack;
	USHORT  wVendorUnique[3];
	CHAR    sSerialNumber[20];
	USHORT  wBufferType;
	USHORT  wBufferSize;
	USHORT  wECCSize;
	CHAR    sFirmwareRev[8];
	CHAR    sModelNumber[40];
	USHORT  wMoreVendorUnique;
	USHORT  wDoubleWordIO;
	USHORT  wCapabilities;
	USHORT  wReserved1;
	USHORT  wPIOTiming;
	USHORT  wDMATiming;
	USHORT  wBS;
	USHORT  wNumCurrentCyls;
	USHORT  wNumCurrentHeads;
	USHORT  wNumCurrentSectorsPerTrack;
	ULONG   ulCurrentSectorCapacity;
	USHORT  wMultSectorStuff;
	ULONG   ulTotalAddressableSectors;
	USHORT  wSingleWordDMA;
	USHORT  wMultiWordDMA;
	BYTE    bReserved[128];
} IDSECTOR, *PIDSECTOR;

typedef struct _SRB_IO_CONTROL
{
	ULONG HeaderLength;
	UCHAR Signature[9];
	ULONG Timeout;
	ULONG ControlCode;
	ULONG ReturnCode;
	ULONG Length;
} SRB_IO_CONTROL, *PSRB_IO_CONTROL;

//  IOCTL commands
#define  DFP_GET_VERSION          0x00074080
#define  DFP_SEND_DRIVE_COMMAND   0x0007c084
#define  DFP_RECEIVE_DRIVE_DATA   0x0007c088

#define  FILE_DEVICE_SCSI              0x0000001b
#define  IOCTL_SCSI_MINIPORT_IDENTIFY  ((FILE_DEVICE_SCSI << 16) + 0x0501)
#define  IOCTL_SCSI_MINIPORT 0x0004D008  //  see NTDDSCSI.H for definition


//  Valid values for the bCommandReg member of IDEREGS.
#define  IDE_ATAPI_IDENTIFY  0xA1  //  Returns ID sector for ATAPI.
#define  IDE_ATA_IDENTIFY    0xEC  //  Returns ID sector for ATA.

BYTE IdOutCmd [sizeof (SENDCMDOUTPARAMS) + MAX_BUFFER - 1] = {0};

/*-------------------------------------------------------------------------------------
Function		: CCPUInfo(Constructor)
In Parameters	: -
Out Parameters	: -
Purpose			: This Function  Initilaize CCPUInfo class
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CCPUInfo::CCPUInfo()
{

}
/*-------------------------------------------------------------------------------------
Function		: ~CCPUInfo (Destructor)
In Parameters	: -
Out Parameters	: -
Purpose			: This Function Destruct CCPUInfo class.
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CCPUInfo::~CCPUInfo()
{

}
/*-------------------------------------------------------------------------------------
Function		: GetOSVersion
In Parameters	: -
Out Parameters	: CString
Purpose			: This Function retrives Os Version on local system
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetOSVersion()
{
	try
	{
		CString csOperatingSystem;
		CString csServicePack;
		m_objRegistry.Get(OS_VERSION_REG,_T("ProductName"), csOperatingSystem, HKEY_LOCAL_MACHINE);
		m_objRegistry.Get(OS_VERSION_REG, _T("CSDVersion"), csServicePack, HKEY_LOCAL_MACHINE);
		csOperatingSystem = csOperatingSystem + _T(" ") + csServicePack;
		return csOperatingSystem.Trim();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetOSVersion"));
	}
	return CString("");
}
/*-------------------------------------------------------------------------------------
Function		: GetServicePack
In Parameters	: -
Out Parameters	: CString :  string Containg name of service pack
Purpose			: This function retrives name of service pack
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetServicePack()
{
	try
	{
		CString csServicePack = _T("");
		if(m_objRegistry.ValueExists(OS_VERSION_REG, _T("CSDVersion"), HKEY_LOCAL_MACHINE))
		{
			m_objRegistry.Get(OS_VERSION_REG, _T("CSDVersion"), csServicePack, HKEY_LOCAL_MACHINE);
			return csServicePack.Trim();
		}
		else
			return csServicePack;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetServicePack"));
	}
	return CString("");
}

/*-------------------------------------------------------------------------------------
Function		: GetOSVerTagFromRegistry
In Parameters	: -
Out Parameters	: CString :Os Version tag
Purpose			: This Function retrives Os Version TAG from registry path
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetOSVerTagFromRegistry()
{
	try
	{
		CString csVerTag = _T("");
		if(m_objRegistry.ValueExists(OS_VERSION_REG, _T("ProductName"), HKEY_LOCAL_MACHINE))
		{
			m_objRegistry.Get(OS_VERSION_REG, _T("ProductName"), csVerTag, HKEY_LOCAL_MACHINE);
			return csVerTag.Trim();
		}
		else
			return csVerTag;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetOSVerTagFromRegistry"));
	}
	return CString(_T(""));

}

/*-------------------------------------------------------------------------------------
Function		: _DoIDENTIFY
In Parameters	: -
Out Parameters	: CString :Os Version tag
Purpose			: This Function retrives Os Version TAG
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetOSVerTag()
{
	try
	{
		// Darshan
		// Made this CString object static to simply return the last found os version
		static CString WinVer = _T("");
		if(WinVer != _T(""))
			return WinVer;

		CRegistry objReg;
		CString csValue;

		if(objReg.KeyExists(OSVER_PATH_WIN98,HKEY_LOCAL_MACHINE))
		{
			objReg.Get(OSVER_PATH_WIN98,_T("Version"),csValue,HKEY_LOCAL_MACHINE);
			if(csValue.Find(_T("98")) != -1)
				return W98;
		}

		PGNSI pGNSI = NULL;
		SYSTEM_INFO objSysInfo;
		ZeroMemory(&objSysInfo, sizeof(SYSTEM_INFO));

		lpOSVersionInfo = new OSVERSIONINFOEX;
		ZeroMemory(lpOSVersionInfo, sizeof(OSVERSIONINFOEX));
		lpOSVersionInfo->dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

		//To get extended information about the version of the operating system that currently running
		if(GetVersionEx((OSVERSIONINFO *)lpOSVersionInfo) == 0)
		{
			//this api fails in case of windows 98 first version so taking the os version from registry.
			delete lpOSVersionInfo;
			return WinVer;
		}

		HMODULE hModule = NULL;
		hModule = GetModuleHandle(TEXT("kernel32.dll"));

		if(NULL != hModule)
		{
			pGNSI = (PGNSI)GetProcAddress(hModule, "GetNativeSystemInfo");
		}

		if(NULL != pGNSI)
		{
			pGNSI(&objSysInfo);
		}
		else
		{
			GetSystemInfo(&objSysInfo);
		}

		hModule = NULL;
		/*if(hModule != NULL)
		{
			FreeLibrary(hModule);
		}*/

		if(lpOSVersionInfo->dwPlatformId == VER_PLATFORM_WIN32_NT)
		{
			if(lpOSVersionInfo->wProductType == VER_NT_WORKSTATION)//Workingstation version
			{
				if(lpOSVersionInfo->dwMajorVersion == 6)
				{
					if(lpOSVersionInfo->dwMinorVersion == 0)
					{
						WinVer = WVISTA; //Windows Vista

					}
					else if(lpOSVersionInfo->dwMinorVersion == 1)
					{
						WinVer = WWIN7; //Windows 7 ultimate
					}
					else if(lpOSVersionInfo->dwMinorVersion == 2)
					{
						WinVer = WWIN8; //Windows 8 ultimate
					}
					if(objSysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
						WinVer += X64;
				}
				else if(lpOSVersionInfo->dwMajorVersion == 5)
				{
					if(lpOSVersionInfo->dwMinorVersion == 2)
					{
						WinVer = WXP64; //Windows XP 64

					}
					else if(lpOSVersionInfo->dwMinorVersion == 1)
					{
						WinVer = WXP; //Windows XP

						if(lpOSVersionInfo->wSuiteMask & VER_SUITE_PERSONAL)
							WinVer+= HED; //Windows XP Home Edtion
						else
							WinVer+= PED; //Windows XP Professional Edtion
					}
					else if(lpOSVersionInfo->dwMinorVersion == 0)
						WinVer = W2K; //Windows 2000 Professtiona
				}
				else
					WinVer = WNT4; //Windows NT 4.0 Workstation
			}
			else if(lpOSVersionInfo->wProductType == VER_NT_SERVER)
			{
				if(lpOSVersionInfo->dwMajorVersion >= 6)
				{
					if(lpOSVersionInfo->dwMinorVersion == 0)
						WinVer = WVISTA; //Windows 2008 Server (considering 2008 as a vista setup)
					if(lpOSVersionInfo->dwMinorVersion == 2)
						WinVer = WWIN8; //Windows 2012 Multipoint Server (considering 2012 as a Win 8)
				}
				else if(lpOSVersionInfo->dwMajorVersion >= 5)
				{
					if(lpOSVersionInfo->dwMinorVersion == 2)
						WinVer = WNE; //Windows.Net
					else
						WinVer = W2K; //Windows 2000

					if(lpOSVersionInfo->wSuiteMask & VER_SUITE_DATACENTER)
						WinVer+= DCS; //DataCenter Server
					else if(lpOSVersionInfo->wSuiteMask & VER_SUITE_ENTERPRISE)
					{
						if(lpOSVersionInfo->dwMajorVersion == 4)
							WinVer+= ADS; //Advanced Server
						else
							WinVer+= ENS; //Enterprise Server
					}
					else if(lpOSVersionInfo->wSuiteMask == VER_SUITE_BLADE)
						WinVer+= WES; //Web Server
					else
						WinVer+= SER; //Server
				}
				else
				{
					WinVer = WNT4; //Window NT 4.0
					WinVer+= SER; //Server
				}
				if(objSysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
					WinVer += X64;
			}
		}
		else
		{
			if(lpOSVersionInfo->dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)
			{
				if(lpOSVersionInfo->dwMinorVersion < 10)
					WinVer = W95; //Windows 95
				else if(lpOSVersionInfo->dwMinorVersion < 90)
					WinVer = W98; //Windows 98
				else
					WinVer = WME; //Windows ME
			}
		}
		delete lpOSVersionInfo;
		return WinVer.Trim();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetOSVerTag"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
Function		: GetProcessorName
In Parameters	: -
Out Parameters	: CString : String containg processor name
Purpose			: This Functionr retrives processor name on local system.
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetProcessorName()
{
	try
	{
		SYSTEM_INFO Sysinfo;
		CString processorType;

		// Copy the hardware information to the SYSTEM_INFO structure.
		GetSystemInfo(&Sysinfo);

		// for Windows 98 and Me
		switch(Sysinfo.dwProcessorType)
		{
		case PROCESSOR_INTEL_386	:	processorType = "Intel 80386";break;
		case PROCESSOR_INTEL_486	:	processorType = "Intel 80486";break;
		case PROCESSOR_INTEL_PENTIUM:	processorType = "Intel Pentium";break;
		case PROCESSOR_MIPS_R4000	:	processorType = "MIPS R4000";break;
		case PROCESSOR_ALPHA_21064	:	processorType = "ALPHA 21064";break;
		case PROCESSOR_PPC_601		:	processorType = "PPC 601";break;
		case PROCESSOR_PPC_603		:	processorType = "PPC 603";break;
		case PROCESSOR_PPC_604		:	processorType = "PPC 604";break;
		case PROCESSOR_PPC_620		:	processorType = "PPC 620";break;
		case PROCESSOR_HITACHI_SH3	:	processorType = "HITACHI SH3";break;
		case PROCESSOR_HITACHI_SH3E	:	processorType = "HITACHI SH3E";break;
		case PROCESSOR_HITACHI_SH4	:	processorType = "HITACHI SH4";break;
		case PROCESSOR_MOTOROLA_821	:	processorType = "MOTOROLA 821";break;
		case PROCESSOR_SHx_SH3		:	processorType = "SHx SH3";break;
		case PROCESSOR_SHx_SH4		:	processorType = "SHx SH4";break;
		case PROCESSOR_STRONGARM	:	processorType = "STRONGARM";break;
		case PROCESSOR_ARM720		:	processorType = "ARM 720";break;
		case PROCESSOR_ARM820		:	processorType = "ARM 820";break;
		case PROCESSOR_ARM920		:	processorType = "ARM 920";break;
		case PROCESSOR_ARM_7TDMI	:	processorType = "ARM 7TDMI";break;
		default						:	processorType = "Unknown -";break;
		}

		//for above ME
		CString processorArchitecture;
		switch(Sysinfo.wProcessorArchitecture)
		{
		case PROCESSOR_ARCHITECTURE_INTEL:
			processorArchitecture = "Intel ";
			break;
		case PROCESSOR_ARCHITECTURE_MIPS:
			processorArchitecture = "MIPS ";
			break;
		case PROCESSOR_ARCHITECTURE_ALPHA:
			processorArchitecture = "ALPHA";
			break;
		case PROCESSOR_ARCHITECTURE_PPC:
			processorArchitecture = "PPC ";
			break;
		case PROCESSOR_ARCHITECTURE_SHX:
			processorArchitecture = "SHx ";
			break;
		case PROCESSOR_ARCHITECTURE_ARM:
			processorArchitecture = "ARM ";
			break;
		case PROCESSOR_ARCHITECTURE_IA64:
			processorArchitecture = "IA 64";
			break;
		case PROCESSOR_ARCHITECTURE_ALPHA64:
			processorArchitecture = "ALPHA 64";
			break;
		case PROCESSOR_ARCHITECTURE_MSIL:
			processorArchitecture = "MSIL ";
			break;
		case PROCESSOR_ARCHITECTURE_AMD64:
			processorArchitecture = "AMD 64";
			break;
		case PROCESSOR_ARCHITECTURE_IA32_ON_WIN64:
			processorArchitecture = "IA32 on WIN64";
			break;
		case PROCESSOR_ARCHITECTURE_UNKNOWN :
			processorArchitecture = "Unknown";
			break;
		}
		CString processorLevel("");
		processorLevel.Format(_T("%u"), Sysinfo.wProcessorLevel);
		CString processorRevision("");
		processorRevision.Format(_T("%u"), Sysinfo.wProcessorRevision);
		processorType = processorArchitecture + _T("Level = ") + processorLevel + _T(" Revision = ") + processorRevision;

		return processorType;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetProcessorName"));
	}
	return CString("");
}

/*-------------------------------------------------------------------------------------
Function		: GetProcessorsCount
In Parameters	: -
Out Parameters	: CString : string containg count of processor
Purpose			: This  Function retrives no of processor on local machine.
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetProcessorsCount()
{
	try
	{
		SYSTEM_INFO SystemInfo;
		//char processorCount[MAX_PATH];
		TCHAR processorCount[MAX_PATH];
		GetSystemInfo(&SystemInfo);
		_itow_s (SystemInfo.dwNumberOfProcessors, processorCount, MAX_PATH, 10);
		return CString (processorCount).Trim();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetProcessorsCount"));
	}
	return CString("");
}
/*-------------------------------------------------------------------------------------
Function		: GetProcessorSpeed
In Parameters	: -
Out Parameters	: CString : string containg speed of processor
Purpose			: This Fucntion obtains the speed of processor
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetProcessorSpeed()
{
	try
	{
		TCHAR processorSpeed[MAX_PATH];
		DWORD procMHz;
		m_objRegistry.Get(SYSTEM_INFO_REG, _T("~MHz"), procMHz, HKEY_LOCAL_MACHINE);
		_itow_s(procMHz, processorSpeed, MAX_PATH, 10);
		wcscat_s(processorSpeed, MAX_PATH, _T(" MHz"));
		return CString(processorSpeed).Trim();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetProcessorSpeed"));
	}
	return CString("");
}
/*-------------------------------------------------------------------------------------
Function		: GetProcessorIdentifier
In Parameters	: -
Out Parameters	: CString : string containg processor Identifier
Purpose			: This Function obtain processor Identifier
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetProcessorIdentifier()
{
	try
	{
		CString processorIdentifier;
		m_objRegistry.Get(SYSTEM_INFO_REG,_T("Identifier"), processorIdentifier, HKEY_LOCAL_MACHINE);
		return processorIdentifier.Trim();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetProcessorIdentifier"));
	}
	return CString("");
}
/*-------------------------------------------------------------------------------------
Function		: GetPCName
In Parameters	: -
Out Parameters	: CString : string containg machine name
Purpose			: This Function obtain local machine name
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetPCName()
{
	try
	{
		CString csPCName;
		TCHAR    szComputerName[ MAX_PATH +1];
		DWORD   dwCompNameBufferSize = MAX_PATH;
		GetComputerName(szComputerName, &dwCompNameBufferSize);
		szComputerName[MAX_PATH] = _T('\0');
		csPCName = szComputerName;
		return csPCName.Trim();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetPCName"));
	}
	return CString("");
}

/*-------------------------------------------------------------------------------------
Function		: GetVolumeSerialNo
In Parameters	: -
Out Parameters	: CString : string containg Volume serial number
Purpose			: This Function obtain Volume serial No.on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetVolumeSerialNo()
{
	try
	{
		DWORD dwVolumeSerialNum;
		long lRetVal;
		CString csHexSN("");
		CString strWinDir("");
		CString csSerialNum("");

		lRetVal = GetWindowsDirectory(strWinDir.GetBuffer(MAX_PATH), MAX_PATH);
		strWinDir.ReleaseBuffer();
		strWinDir = strWinDir.Left(1);
		strWinDir = strWinDir + _T(":\\");
		GetVolumeInformation(strWinDir, NULL, NULL,&dwVolumeSerialNum, NULL, NULL, NULL, NULL);
		csHexSN.Format(_T("%X"),dwVolumeSerialNum);
		if(csHexSN.GetLength()<= 8)
		{
			csSerialNum = _T("");
			csSerialNum = _T("[") + csHexSN.Left(4) + _T("-") + csHexSN.Right(4) + _T("]");
		}
		return csSerialNum.Trim();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetVolumeSerialNo"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
Function		: GetHardwareGUID
In Parameters	: -
Out Parameters	: CString : string containg Volume serial number
Purpose			: This Function obtain Volume serial No.on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetHardwareGUID()
{
	try
	{
		HW_PROFILE_INFO   hwProfInfo;
		CString strHardwareGUID(_T(""));
		if(GetCurrentHwProfile(&hwProfInfo))
			strHardwareGUID.Format(_T("%s"), hwProfInfo.szHwProfileGuid);
		return strHardwareGUID;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetHardwareGUID"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
Function		: GetHardWareProfileName
In Parameters	: -
Out Parameters	: CString : string containg Hardware Profile Name
Purpose			: This Function obtain Hardware Profile Name local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetHardWareProfileName()
{
	try
	{
		HW_PROFILE_INFO   hwProfInfo;
		CString strHwProfileName(_T(""));
		if(GetCurrentHwProfile(&hwProfInfo))
			strHwProfileName.Format(_T("%s"), hwProfInfo.szHwProfileName);
		return strHwProfileName.Trim();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetHardWareProfileName"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
Function		: GetIPAddress
In Parameters	: -
Out Parameters	: CString : string containg IP Address
Purpose			: This Function obtain IP Address on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetIPAddress()
{
	try
	{
		CString	szIPAddress;
		char hostname[MAX_PATH]={0};
		WORD wVer;
		WSADATA	wData;
		PHOSTENT hostinfo;
		wVer = MAKEWORD(2,	0);
		// Get IP Address
		if(WSAStartup(wVer, &wData) == 0)
		{
			if(gethostname(hostname, sizeof(hostname)) == 0)
			{
				if(strcmp(hostname,"") == 0)
				{
					WSACleanup();
					szIPAddress = _T("0.0.0.0");
					return szIPAddress;
				}
				else
				{
					if((hostinfo = gethostbyname(hostname)) != NULL)
					{
						szIPAddress	= inet_ntoa	(*(struct in_addr *)*hostinfo->h_addr_list);
					}
				}
			}
			WSACleanup(	);
			if(szIPAddress == "")
				szIPAddress	= _T("0.0.0.0");
			return szIPAddress;
		}
		else
		{
			szIPAddress	= _T("0.0.0.0");
			return szIPAddress;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetIPAddress"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
Function		: GetUserLocaleInfo
In Parameters	: -
Out Parameters	: CString : string containg user information
Purpose			: This Function obtain user information on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetUserLocaleInfo()
{
	try
	{
		TCHAR strLocale[MAX_PATH] = {0};
		GetLocaleInfo(GetSystemDefaultLCID(), LOCALE_SLANGUAGE, strLocale, MAX_PATH);
		return CString(strLocale);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetUserLocaleInfo"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
Function		: GetRAMStatus
In Parameters	: -
Out Parameters	: CString : string containg Ram Status
Purpose			: This Function obtain Ram Status on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetRAMStatus()
{
	try
	{
		CString csRamInfo; //Hold information of Ram
		MEMORYSTATUS memoryStatus;
		ZeroMemory(&memoryStatus,sizeof(MEMORYSTATUS));
		memoryStatus.dwLength = sizeof (MEMORYSTATUS);
		::GlobalMemoryStatus (&memoryStatus);
		CString Temp;
		Temp.Format(_T("\nInstalled RAM:\t %ldMB"),(DWORD)(memoryStatus.dwTotalPhys/1024/1024)); //Value of installed Ram
		csRamInfo=Temp;
		Temp.Format(_T("\nMemory Available:\t %ldKB"),(DWORD)(memoryStatus.dwAvailPhys/1024));//Value of available memory
		csRamInfo+=Temp;
		Temp.Format(_T("\nPercent of used RAM:\t %%%ld \n"),memoryStatus.dwMemoryLoad);//Value of percent of Ram
		csRamInfo+=Temp;
		return csRamInfo; //return information about ram to GetHardWareInfo function
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetRAMStatus"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
Function		: GetHardDiskStatus
In Parameters	: -
Out Parameters	: CString : string containg Hard Drive Status
Purpose			: This Function obtain Hard Drive Status on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetHardDiskStatus()
{
	try
	{
		TCHAR tcDriveName[] = _T("\tA:");
		ULONG ulDriveMask = _getdrives();
		CString csDrv,csFreeSpace,csTemp,csTotalInfo;
		try
		{
			if(ulDriveMask == 0)
				AfxMessageBox(_T("_getdrives()failed to detect drive name"));

			else
			{
				while (ulDriveMask)
				{	csTotalInfo+=csFreeSpace;
				if(ulDriveMask & 1)
				{
					tcDriveName;	   
					csDrv=tcDriveName;
					csDrv = csDrv.Mid(1);
					CHardDiskManager objHDManager;
					if(objHDManager.CheckFreeSpace(csDrv))
					{
						csTemp = _T("Drive - ") + csDrv;

						csFreeSpace.Format(_T("%s\nFreeBytesAvailable :\t %f GBytes"),
							static_cast<LPCTSTR>(csTemp),
							objHDManager.GetFreeGBytesAvailable());

						csTemp = csFreeSpace;

						csFreeSpace.Format(_T("%s\nTotalNumberOfBytes :\t %f GBytes"),
							static_cast<LPCTSTR>(csTemp),
							objHDManager.GetTotalNumberOfGBytes());

						csTemp = csFreeSpace;

						csFreeSpace.Format(_T("%s\nTotalNumberOfFreeBytes :\t %f GBytes."),
							static_cast<LPCTSTR>(csTemp),
							objHDManager.GetTotalNumberOfFreeGBytes());

						csFreeSpace += _T("\n");
					}
				}
				++tcDriveName[1];
				ulDriveMask >>= 1;
				}
				csTotalInfo+=csFreeSpace;
			}
		}
		catch(...)
		{}
		return csTotalInfo;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetHardDiskStatus"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
Function		: GetDate
In Parameters	: -
Out Parameters	: CString : string containg Current Time
Purpose			: This Function obtain Current Time on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetDate()
{
	try
	{
		COleDateTime objOleDateTime; //take object of the COleDateTime
		objOleDateTime = objOleDateTime.GetCurrentTime();
		CString csDate; //hold system date
		csDate.Format(_T("[%d/%d/%d %s]"),
			objOleDateTime.GetMonth(),
			objOleDateTime.GetDay(),
			objOleDateTime.GetYear(),
			static_cast<LPCTSTR>(objOleDateTime.Format(_T("%H-%M-%S"))));
		return csDate; //return the system Date to the GetSystemInfo function
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetDate"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
Function		: GetMonthName
In Parameters	: -
Out Parameters	: CString : string containg Current Month Name
Purpose			: This Function obtain Current Month Name on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetMonthName(int iMonth)
{
	try
	{
		switch(iMonth)
		{
		case 1:
			return (_T("January"));
		case 2:
			return (_T("February"));
		case 3:
			return (_T("March"));
		case 4:
			return (_T("April"));
		case 5:
			return (_T("May"));
		case 6:
			return (_T("June"));
		case 7:
			return (_T("July"));
		case 8:
			return (_T("August"));
		case 9:
			return (_T("September"));
		case 10:
			return (_T("October"));
		case 11:
			return (_T("November"));
		case 12:
			return (_T("December"));
		}
		return _T("");
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetMonthName"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
Function		: GetProgramFilesDir
In Parameters	: -
Out Parameters	: CString : string containg fullpath of programme files
Purpose			: This Function obtain fullpath of programme files on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetProgramFilesDir()
{
	try
	{
		TCHAR lpszPath[MAX_PATH]={0};

		SHGetFolderPath(NULL,CSIDL_PROGRAM_FILES, NULL, 0, lpszPath);
		return lpszPath;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetProgramFilesDir"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
Function		: GetProgramFilesDirX86
In Parameters	: -
Out Parameters	: CString : string containg fullpath of programme files
Purpose			: This Function obtain fullpath of programme files on local  x64 machine
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
CString	CCPUInfo::GetProgramFilesDirX64()
{
	try
	{
		TCHAR lpszPath[MAX_PATH]={0};

		SHGetFolderPath(NULL,CSIDL_PROGRAM_FILESX86, NULL, 0, lpszPath);
		return lpszPath;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetProgramFilesDir"));
	}
	return CString(_T(""));
}
/*-------------------------------------------------------------------------------------
Function		: GetSystemDir
In Parameters	: -
Out Parameters	: CString : string containg Path of system directory
Purpose			: This Function obtain Path of system directory on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetSystemDir()
{
	try
	{
		TCHAR lpszPath[MAX_PATH + 1]={0};

		GetSystemDirectory (lpszPath,MAX_PATH + 1);
		return lpszPath;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetSystemDir"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
Function		: GetSystemWow64Dir
In Parameters	: -
Out Parameters	: CString : string containg Path of 64 system directory
Purpose			: This Function obtain Path of 64 system directory on local machine
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
CString	CCPUInfo::GetSystemWow64Dir(void)
{
	TCHAR szWowSysPath[MAX_PATH] = {0};
	try
	{
		typedef UINT (WINAPI * GETSYSTEMWOW64DIRECTORY)(LPTSTR lpBuffer,UINT uSize);
		GETSYSTEMWOW64DIRECTORY pSysWow64Dir = NULL;

		HMODULE hModule = NULL;
		hModule = GetModuleHandle(_T("kernel32.dll"));

		if(hModule)
		{
			pSysWow64Dir = (GETSYSTEMWOW64DIRECTORY)GetProcAddress(hModule, "GetSystemWow64DirectoryW");
		}

		if(pSysWow64Dir)
		{
			pSysWow64Dir(szWowSysPath, _countof(szWowSysPath));
		}

		/*if(hModule != NULL)
		{
			FreeLibrary(hModule);
		}*/
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetSystemWow64Dir"));
	}
	return szWowSysPath;
}

/*-------------------------------------------------------------------------------------
Function		: GetWindowsDir
In Parameters	: -
Out Parameters	: CString : string containg path to Windows Folder
Purpose			: This Function obtain path to Windows Folder on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetWindowsDir()
{
	try
	{
		TCHAR lpszPath[MAX_PATH + 1]={0};

		if(GetWindowsDirectory(lpszPath,MAX_PATH + 1))
		{
			return lpszPath;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetWindowsDir"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
Function		: GetTempDir
In Parameters	: -
Out Parameters	: CString : string containing Temp folder path
Purpose			: This Function obtain Temp folder path on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetTempDir()
{
	try
	{
		TCHAR lpszPath[MAX_PATH + 1]={0};

		GetTempPath(MAX_PATH + 1, lpszPath);
		return lpszPath;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetTempDir"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
Function		: GetEnvVariable
In Parameters	: -
Out Parameters	: CString : string containg environment variable
Purpose			: This Function obtain environment variable on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetEnvVariable()
{
	try
	{
		CString csEnvVari("");
		DWORD dwSize = 32767;	//Max size of environment variable
		if(GetEnvironmentVariable(_T("PATH"),csEnvVari.GetBuffer(dwSize),dwSize) != 0)
		{
			csEnvVari.ReleaseBuffer();
			CString csToken;
			int iCurPos= 0;
			csToken = csEnvVari.Tokenize(_T(";"), iCurPos);
			while(csToken != "")
			{
				csToken.Replace(_T("\\."),_T(""));
				csEnvVari += csToken;
				csToken = csEnvVari.Tokenize(_T(";"), iCurPos);
			}
			return csEnvVari;
		}
		csEnvVari.ReleaseBuffer();
		return csEnvVari;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetEnvVariable"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
Function		: GetDpiValue
In Parameters	: -
Out Parameters	: CString : string containg Dpi value
Purpose			: This Function obtain Dpi value
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
DWORD CCPUInfo::GetDpiValue()
{

	try
	{
		CRegistry	objReg;
		CString		strOSVersion;
		DWORD		dwValue;
		strOSVersion = GetOSVerTag(); //GetOSVersion();
		if(strOSVersion.Find(_T("Windows 8")) != -1)
		{
			strOSVersion = WWIN8;
		}
		if(strOSVersion.Find(_T("Windows 7")) != -1)
		{
			strOSVersion = WWIN7;
		}
		

		if(wcscmp(strOSVersion,_T("Windows 7")) ==0)//for windows 7 Ravindra
		{
			if(!objReg.Get(_T("Control Panel\\Desktop"),_T("LogPixels"),dwValue,HKEY_CURRENT_USER))
				dwValue = 96;
		}
		else if(wcscmp(strOSVersion,_T("Windows 8")) ==0)//for windows 8.1 Ravindra
		{
			if(!objReg.Get(_T("Control Panel\\Desktop"),_T("LogPixels"),dwValue,HKEY_CURRENT_USER))
				dwValue = 96;
		}
		else if(wcscmp(strOSVersion,_T("Windows 98")) !=0 && wcscmp(strOSVersion,_T("Windows ME")) !=0)//for windows 2000
		{
			if(!objReg.Get(DPI2KREG_KEY,_T("LogPixels"),dwValue,HKEY_LOCAL_MACHINE))
				dwValue = 96;

		}
		else
		{
			CString strDPIValue;
			if(!objReg.Get(DPI98REG_KEY,_T("DPIPhysicalX"),strDPIValue,HKEY_CURRENT_CONFIG))
			{
				dwValue = 96;

			}
			else
			{
				dwValue = _wtoi(strDPIValue);
				if(wcscmp(strDPIValue,_T("120")) == 0)
					dwValue = 98120;
			}
		}
		/*if(dwValue < 96)
			dwValue = 96;
		if(dwValue > 96 && dwValue != 98120)
			dwValue = 120;*/
		return dwValue;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetDpiValue"));
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: GetCurrSystemTime
In Parameters	: -
Out Parameters	: CString : string containg Current System Time
Purpose			: This Function obtain Current System Time on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
SYSTEMTIME CCPUInfo::GetCurrSystemTime()
{
	try
	{
		SYSTEMTIME stCurrent;
		CTime timeCurrent(CTime::GetCurrentTime());
		timeCurrent.GetAsSystemTime (stCurrent);
		return stCurrent;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetCurrSystemTime"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: CheckForAdminRights
In Parameters	: -
Out Parameters	: BOOL  : TRUE - Caller has Administrators local group.
FALSE - Caller does not have Administrators local group.
Purpose			: This routine returns TRUE if the caller's process is a member of the
Administrators local group.Caller is NOT expected to be impersonating
anyone and is expected to be able to open its own process and process
token.
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
BOOL CCPUInfo::CheckForAdminRights()
{
	BOOL bIsUserAdmin = FALSE;
	try
	{
		if(GetOSVerTag() == W98 || GetOSVerTag() == WME)
		{
			return TRUE;
		}

		SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
		PSID AdministratorsGroup;

		bIsUserAdmin = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
							DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup);
		if(bIsUserAdmin)
		{
			bIsUserAdmin = FALSE;
			CheckTokenMembership(NULL, AdministratorsGroup, &bIsUserAdmin);
			FreeSid(AdministratorsGroup);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::CheckForAdminRights"));
	}
	return bIsUserAdmin;
}

/*-------------------------------------------------------------------------------------
Function		: GetRootDrive
In Parameters	: -
Out Parameters	: CString : string containg Root Drive name
Purpose			: This Function obtain Root Drive name on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetRootDrive()
{
	try
	{
		CString csSystemDir = GetSystemDir();
		csSystemDir.Trim();

		CString csRootDrive = _T("");
		csRootDrive = csSystemDir[0];
		csRootDrive = csRootDrive + _T(":");
		return csRootDrive;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetRootDrive"));
	}
	return CString("");
}

/*-------------------------------------------------------------------------------------
Function		: GetFreeSystemDiskSpace
In Parameters	: -
Out Parameters	: double :  Free System Disk Space
Purpose			: This Function obtain Free System Disk Space on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
double  CCPUInfo::GetFreeSystemDiskSpace()
{
	try
	{
		CHardDiskManager objHDManager;
		double dFreeSpace = 0;

		CString csDrv = GetRootDrive();
		csDrv = csDrv + BACK_SLASH;

		if(objHDManager.CheckFreeSpace(csDrv))
		{
			dFreeSpace = objHDManager.GetTotalNumberOfFreeGBytes();
		}
		return dFreeSpace;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetFreeSystemDiskSpace"));
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: isOS64bit
In Parameters	: -
Out Parameters	: BOOL  : TRUE if current system is 64 bit OS
Purpose			: This Function obtain current version of OS on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
BOOL CCPUInfo::isOS64bit()
{
	try
	{
#ifdef WIN64
		return TRUE;
#else
		typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);

		LPFN_ISWOW64PROCESS fnIsWow64Process = NULL;

		HMODULE hModule = NULL;
		hModule = GetModuleHandle(_T("kernel32.dll"));

		if(hModule)
		{
			fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(hModule, "IsWow64Process");
		}

		BOOL bIsWow64 = FALSE;
		if(fnIsWow64Process)
		{
			if(!fnIsWow64Process(GetCurrentProcess(),&bIsWow64))
			{
				bIsWow64 = FALSE;
			}
		}

		/*if(hModule != NULL)
		{
			FreeLibrary(hModule);
		}*/

		return bIsWow64;
#endif
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::isOS64bit"));
	}
	return FALSE;
}

/*-------------------------------------------------------------------------------------
Function		: GetAPPDataPath
In Parameters	: -
Out Parameters	: CString
Purpose			: Get application data path
Author			: Avinash Shendage
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetAPPDataPath(void)
{
	CString csReturn;
	try
	{
		HRESULT hResult	= 0;
		LPITEMIDLIST pidlRoot = NULL;

		TCHAR* lpszPath = NULL;
		lpszPath = new TCHAR[MAX_FILE_PATH];

		if(lpszPath)
		{
			SecureZeroMemory(lpszPath, MAX_FILE_PATH*sizeof(TCHAR));

			hResult	= SHGetSpecialFolderLocation(NULL, CSIDL_APPDATA, &pidlRoot);
			if(NOERROR == hResult)
			{
				SHGetPathFromIDList(pidlRoot, lpszPath);
				csReturn.Format(_T("%s"), lpszPath);
			}

			delete[] lpszPath;
			lpszPath = NULL;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetAPPDataPath"));
	}
	return csReturn;
}

/*-------------------------------------------------------------------------------------
Function		: GetAllUsersPath
In Parameters	: -
Out Parameters	: CString
Purpose			: Get all users path
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetAllUsersPath(void)
{
	CString csReturn;
	try
	{
		CString csReplacementPath;
		CString  csPath;
		if(m_objRegistry.Get(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList" , L"ProfilesDirectory" ,
			csPath ,HKEY_LOCAL_MACHINE) && csPath.GetLength() > 0)
		{
			csReplacementPath = csPath;
			csReplacementPath.MakeLower();
			csReplacementPath.Replace(L"%systemdrive%\\", GetRootDrive() + L"\\");
		}
		CString osVersion = GetOSVerTag();
		if(osVersion.Find(WVISTA) != -1 || osVersion.Find(WWIN7) != -1 || osVersion.Find(WWIN8) != -1)//Vista/win7 32, 64 bit
		{
			if(m_objRegistry.Get(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList" ,
				L"Public" , csPath ,HKEY_LOCAL_MACHINE) && csPath.GetLength() > 0)
			{
				csPath.MakeLower();
				csPath.Replace(L"%systemdrive%\\", GetRootDrive() + L"\\");
				csReturn = csPath;
			}
		}
		else
		{
			if(m_objRegistry.Get(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList" ,L"AllUsersProfile" ,
				csPath ,HKEY_LOCAL_MACHINE) && csPath.GetLength() > 0)
			{
				csReturn = csReplacementPath + L"\\" + csPath;
			}
			else	//Required for Server 2008
				csReturn = csReplacementPath + L"\\All Users";
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetAPPDataPath"));
	}
	return csReturn;
}

/*-------------------------------------------------------------------------------------
Function		: GetAllUserAppDataPath
In Parameters	: -
Out Parameters	: CString
Purpose			: Get All User Application Data path
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetAllUserAppDataPath(void)
{
	CString csReturn;

	try
	{
		HRESULT hResult	= 0;
		LPITEMIDLIST pidlRoot = NULL;
		TCHAR *lpszPath = NULL;

		lpszPath = new TCHAR[MAX_FILE_PATH];

		if(lpszPath)
		{
			SecureZeroMemory(lpszPath, MAX_FILE_PATH*sizeof(TCHAR));

			hResult	= SHGetSpecialFolderLocation(NULL, CSIDL_COMMON_APPDATA, &pidlRoot);

			if(NOERROR == hResult)
			{
				SHGetPathFromIDList(pidlRoot, lpszPath);
				csReturn.Format(_T("%s"), lpszPath);
			}
			delete [] lpszPath;
			lpszPath = NULL;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetAllUserAppDataPath"));
	}

	return csReturn;
}

/*-------------------------------------------------------------------------------------
Function		: GetVendorID
In Parameters	: -
Out Parameters	: CString : string containg System Vendor Id (eg:Intel)
Purpose			: This Function obtain Vendor Id on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetVendorID()
{
	try
	{
		CString vendorIdentifier;
		m_objRegistry.Get(SYSTEM_INFO_REG, _T("VendorIdentifier"), vendorIdentifier, HKEY_LOCAL_MACHINE);
		return vendorIdentifier.Trim();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetVendorID"));
	}
	return CString(_T(""));
}

/*-------------------------------------------------------------------------------------
Function		: GetLocalAPPDataPath
In Parameters	: -
Out Parameters	: CString
Purpose			: Get application data path
Author			: Avinash Shendage
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetLocalAPPDataPath()
{
	CString csReturn;

	try
	{
		HRESULT hResult	= 0;
		LPITEMIDLIST pidlRoot = NULL;
		TCHAR *lpszPath = NULL;

		lpszPath = new TCHAR[MAX_FILE_PATH];

		if(lpszPath)
		{
			SecureZeroMemory(lpszPath, MAX_FILE_PATH*sizeof(TCHAR));

			hResult	= SHGetSpecialFolderLocation(NULL, CSIDL_LOCAL_APPDATA, &pidlRoot);

			if(NOERROR == hResult)
			{
				SHGetPathFromIDList(pidlRoot, lpszPath);
				csReturn.Format(_T("%s"), lpszPath);
			}
			delete[] lpszPath;
			lpszPath = NULL;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetLocalAPPDataPath"));
	}

	return csReturn;
}

BOOL CCPUInfo::_GetMotherBoardSerialNumberSEH()
{
	__try
	{
		_GetMotherBoardSerialNumber();
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("_GetMotherBoardSerialNumber"), false))
	{
	}
	return TRUE;
}

BOOL CCPUInfo::_GetMotherBoardSerialNumber()
{
	try
	{
		HRESULT hres;
		//Initialize COM.
		hres = CoInitialize(0);
		COINITIALIZE_OUTPUTDEBUGSTRING(hres);
		if (FAILED(hres))
		{
			//AddLogEntry(L"Failed to initialize COM library. Error code");// = 0x" << hex << hres << endl;
			//return csMotherBoardNo;
			goto END;
		}

		{
			hres =  CoInitializeSecurity(
										NULL, 
										0,							 // COM authentication
										NULL,                        // Authentication services
										NULL,                        // Reserved
										RPC_C_AUTHN_LEVEL_NONE,		 // Default authentication 
										RPC_C_IMP_LEVEL_IDENTIFY,	 // Default Impersonation  
										NULL,                        // Authentication info
										0,							 // Additional capabilities 
										NULL                         // Reserved
										);
			COCREATE_OUTPUTDEBUGSTRING(hres);
			if (FAILED(hres))
			{
				//AddLogEntry(L"Failed to initialize security. Error code = 0x");// << hex << hres << endl;
				if(hres == E_OUTOFMEMORY)
				{
					goto END;
					//return csMotherBoardNo;
				}
			}
		    
			IWbemLocator *pLoc = NULL;
			hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &pLoc);
			COCREATE_OUTPUTDEBUGSTRING(hres);
			if (FAILED(hres))
			{
				//AddLogEntry(L"Failed to create IWbemLocator object.");// << " Err code = 0x"  << hex << hres << endl;
				goto END;
				//return csMotherBoardNo;
			}

			IWbemServices *pSvc = NULL;
			hres = pLoc->ConnectServer(
									 _bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
									 NULL,                    // User name. NULL = current user
									 NULL,                    // User password. NULL = current
									 0,                       // Locale. NULL indicates current
									 NULL,                    // Security flags.
									 0,                       // Authority (e.g. Kerberos)
									 0,                       // Context object 
									 &pSvc                    // pointer to IWbemServices proxy
									 );
		    
			if (FAILED(hres))
			{
				//AddLogEntry(L"Could not connect. Error code = 0x");// << hex << hres << endl;
				pLoc->Release();     
				goto END;
				//return csMotherBoardNo;
			}
			hres = CoSetProxyBlanket(
								   pSvc,                        // Indicates the proxy to set
								   RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
								   RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
								   NULL,                        // Server principal name 
								   RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
								   RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
								   NULL,                        // client identity
								   EOAC_NONE                    // proxy capabilities 
								);

			if (FAILED(hres))
			{
				//AddLogEntry(L"Could not set proxy blanket. Error code = 0x");// << hex << hres << endl;
				pSvc->Release();
				pLoc->Release();     
				goto END;
				//return csMotherBoardNo;
			}

			// For example, get the name of the operating system
			IEnumWbemClassObject* pEnumerator = NULL;
			hres = pSvc->ExecQuery(
								bstr_t("WQL"), 
								bstr_t("SELECT * FROM Win32_BaseBoard"),
								WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
								NULL,
								&pEnumerator);
		    
			if (FAILED(hres))
			{
				//AddLogEntry(L"Query for operating system name failed.");//<< " Error code = 0x" << hex << hres << endl;
				pSvc->Release();
				pLoc->Release();
				goto END;
				//return csMotherBoardNo;
			}

			IWbemClassObject *pclsObj =  NULL;
			ULONG uReturn = 0;
		   
			while (pEnumerator)
			{
				HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

				if(0 == uReturn)
				{
					break;
				}

				VARIANT vtProp;

				// Get the value of the Name property
				hr = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
				//wcout << " SerialNumber : " << vtProp.bstrVal << endl;
				//AfxMessageBox((CString)vtProp.bstrVal);
				_tcscpy_s(m_szMotherBoardID, (LPCTSTR)vtProp.bstrVal);
				VariantClear(&vtProp);
			}

			AddLogEntry(L">> MotherBoardID");
			AddLogEntry(m_szMotherBoardID);
			AddLogEntry(L">> MotherBoardID");

			//AddLogEntry(_T("1. ******: >") + csMotherBoardNo + _T("<"));
			if(pSvc)
			{
				pSvc->Release();
			}
			if(pLoc)
			{
				pLoc->Release();
			}
			if(pEnumerator)
			{
				pEnumerator->Release();
			}

			if(pclsObj)
			{
				pclsObj->Release();
			}
		}
	}
	catch(_com_error &e)
	{
		_bstr_t bstr = _com_error(e).ErrorMessage();
		AddLogEntry(bstr);	
		AddLogEntry(L"_GetMotherBoardSerialNumber..._com_error: %s",(LPCTSTR)bstr);
	}
	catch(...)
	{
	}

END:

	CoUninitialize();

	return TRUE;
}

/*-------------------------------------------------------------------------------------
Function		: GetMotherBoardSerialNumber
In Parameters	: -
Out Parameters	: CString : string containg Motherboard serial number
Purpose			: This Function obtain Motherboard serial No.on local machine
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CString	CCPUInfo::GetMotherBoardSerialNumber(CString csMachineID)
{
	wmemset(m_szMotherBoardID, 0, MAX_PATH);
    wmemset(m_szNetworkMacID, 0, MAX_PATH);
	CString csMotherBoardNo = _T(""),csNetworkMacId = _T("");


	_GetMotherBoardSerialNumberSEH();

	csMotherBoardNo = m_szMotherBoardID;
	
	flagforuniqueid = TRUE;
	CheckCharSet(csMotherBoardNo);
	

	if(csMotherBoardNo.Trim().GetLength() > 0)
	{
		csMotherBoardNo.Replace(_T(" "), _T(""));
		csMotherBoardNo.Replace(_T(":"), _T(""));
		csMotherBoardNo.Replace(_T("-"), _T(""));
		csMotherBoardNo.Replace(_T("_"), _T(""));
		csMotherBoardNo.Replace(_T("."), _T(""));
		if(csMotherBoardNo == _T("000000000000"))
		{
			csMotherBoardNo = _T("");
            flagforuniqueid = FALSE;
		}
	}

	if(csMotherBoardNo == _T(""))	//Temporary handling for guest user!
	{
		csMotherBoardNo = csMachineID;
	}

	csMotherBoardNo.MakeUpper();
	//Some motherboard returs this string, in this case use hdd serial no!
	if((csMotherBoardNo == _T("TOBEFILLEDBYOEM")) || (csMotherBoardNo == _T("MB1234567890"))
		|| (csMotherBoardNo == _T("BASEBOARDSERIALNUMBER")) || (csMotherBoardNo == _T("0123456789AB"))
		|| (csMotherBoardNo == _T("123456789000")) || (csMotherBoardNo == _T("BSN12345678901234567"))
		|| (csMotherBoardNo == _T("XXXXXXXXXXXX")) || (csMotherBoardNo == _T("SERIALNUMBERXXXXXX"))
		|| (csMotherBoardNo == _T("0000000000000000000000")) || (csMotherBoardNo == _T("NOTAPPLICABLE"))
		|| (csMotherBoardNo == _T("123490EN400015")) || (csMotherBoardNo == _T("TOBEFILLEDBY"))
		|| (csMotherBoardNo == _T("NONE")) || (csMotherBoardNo.Find(_T("ÿ")) != -1)
		|| (csMotherBoardNo == _T("BTWW12100RDA")) || (csMotherBoardNo == _T("NB1234567890"))
		|| (csMotherBoardNo == _T("ZT0000020110101")))
	{
		csMotherBoardNo = _T("");
        flagforuniqueid = FALSE;
	}

    //for some motherboard we are getting DEFAULTSTRING.
	if(csMotherBoardNo.Find(_T("DEFAULT")) !=-1)
	{
		csMotherBoardNo = _T("");
        flagforuniqueid = FALSE;
	}

	if(csMotherBoardNo == _T("") || csMotherBoardNo.GetLength() < 12)
	{
		//if motherboard serial number invalid , go for mac id
		_GetNetworkMacIDSEH();
         flagforuniqueid = TRUE;

        csNetworkMacId=m_szNetworkMacID;

		CheckCharSet(csNetworkMacId);
       
		   if(csNetworkMacId == _T("000000000000"))
		   {
			 csNetworkMacId = _T("");
             flagforuniqueid = FALSE;

		   }
        csMotherBoardNo=csNetworkMacId;
	}

	if(csMotherBoardNo == _T("") || csMotherBoardNo.GetLength() < 12)
	{   //if mac id too invalid then go for random
		CString csVolumeSerial = GetVolumeSerialNo();

		csVolumeSerial.Replace(L"[", L"");
		csVolumeSerial.Replace(L"]", L"");
		csVolumeSerial.Replace(L"-", L"");
		csVolumeSerial.Replace(L"_", L"");
		CString csOs = GetOSVerTag();
		AddLogEntry(L"Os: >%s<", csOs);
		csOs.Replace(_T(" "), _T(""));
		
		CString csPCName = GetPCName();
		csPCName.Replace(L"[", L"");
		csPCName.Replace(L"]", L"");
		csPCName.Replace(L"-", L"");
		csPCName.Replace(L"_", L"");
		csPCName.Replace(_T(" "), _T(""));
		csPCName.Replace(_T(":"), _T(""));
		if(csPCName.GetLength() < 2)
		{
			csPCName = csPCName + _T("PCN");		//PC Name
		}
		csMotherBoardNo.Format(_T("%s%s%s"), csVolumeSerial, csPCName.Left(2), csOs.Right(2));
		AddLogEntry(L"MotherBoardNo: >%s<", csMotherBoardNo);
		if(csMotherBoardNo.GetLength() < 12)
		{
			csMotherBoardNo += csMotherBoardNo;
		}
        flagforuniqueid = FALSE;//since random
	}

	csMotherBoardNo.MakeUpper();

	return csMotherBoardNo;
}

CString	CCPUInfo::GetOldMotherBoardSerialNumber(CString csMachineID)
{
	wmemset(m_szMotherBoardID, 0, MAX_PATH);

	CString csMotherBoardNo = _T("");

	_GetMotherBoardSerialNumberSEH();

	csMotherBoardNo = m_szMotherBoardID;
	AddLogEntry(_T("OLD Raw ID: >%s<"), csMotherBoardNo);
	CheckCharSet(csMotherBoardNo);
	AddLogEntry(L"OLD After CheckCharSet: >%s<", csMotherBoardNo);

	if(csMotherBoardNo.Trim().GetLength() > 0)
	{
		csMotherBoardNo.Replace(_T(" "), _T(""));
		csMotherBoardNo.Replace(_T(":"), _T(""));
		csMotherBoardNo.Replace(_T("-"), _T(""));
		csMotherBoardNo.Replace(_T("_"), _T(""));
		csMotherBoardNo.Replace(_T("."), _T(""));
		if(csMotherBoardNo == _T("000000000000"))
		{
			csMotherBoardNo = _T("");
		}
	}

	AddLogEntry(_T("OLD Modified ID: >%s<"), csMotherBoardNo);

	if(csMotherBoardNo == _T(""))	//Temporary handling for guest user!
	{
		csMotherBoardNo = csMachineID;
	}

	csMotherBoardNo.MakeUpper();
	//Some motherboard returs this string, in this case use hdd serial no!
	if((csMotherBoardNo == _T("TOBEFILLEDBYOEM")) || (csMotherBoardNo == _T("MB1234567890"))
		|| (csMotherBoardNo == _T("BASEBOARDSERIALNUMBER")) || (csMotherBoardNo == _T("0123456789AB"))
		|| (csMotherBoardNo == _T("123456789000")) || (csMotherBoardNo == _T("BSN12345678901234567"))
		|| (csMotherBoardNo == _T("XXXXXXXXXXXX")) || (csMotherBoardNo == _T("SERIALNUMBERXXXXXX"))
		|| (csMotherBoardNo == _T("0000000000000000000000")) || (csMotherBoardNo == _T("NOTAPPLICABLE"))
		|| (csMotherBoardNo == _T("123490EN400015")) || (csMotherBoardNo == _T("TOBEFILLEDBY"))
		|| (csMotherBoardNo == _T("NONE")) || (csMotherBoardNo.Find(_T("ÿ")) != -1)
		|| (csMotherBoardNo == _T("BTWW12100RDA"))
		)
	{
		csMotherBoardNo = _T("");
	}

	if(csMotherBoardNo == _T("") || csMotherBoardNo.GetLength() < 12)
	{   //if mac id too invalid then go for random
		CString csVolumeSerial = GetVolumeSerialNo();
		AddLogEntry(L"OLD VolumeSerial: >%s<", csVolumeSerial);
		csVolumeSerial.Replace(L"[", L"");
		csVolumeSerial.Replace(L"]", L"");
		csVolumeSerial.Replace(L"-", L"");
		csVolumeSerial.Replace(L"_", L"");
		CString csOs = GetOSVerTag();
		AddLogEntry(L"Os: >%s<", csOs);
		csOs.Replace(_T(" "), _T(""));
		
		CString csPCName = GetPCName();
		AddLogEntry(L"OLD PCName: >%s<", csPCName);
		csPCName.Replace(L"[", L"");
		csPCName.Replace(L"]", L"");
		csPCName.Replace(L"-", L"");
		csPCName.Replace(L"_", L"");
		csPCName.Replace(_T(" "), _T(""));
		csPCName.Replace(_T(":"), _T(""));
		if(csPCName.GetLength() < 2)
		{
			csPCName = csPCName + _T("PCN");		//PC Name
		}
		csMotherBoardNo.Format(_T("%s%s%s"), csVolumeSerial, csPCName.Left(2), csOs.Right(2));
		AddLogEntry(L"OLD MotherBoardNo: >%s<", csMotherBoardNo);
		if(csMotherBoardNo.GetLength() < 12)
		{
			csMotherBoardNo += csMotherBoardNo;
			AddLogEntry(L"OLD Double MotherBoardNo: >%s<", csMotherBoardNo);
		}
	}

	csMotherBoardNo.MakeUpper();
	AddLogEntry(_T("OLD Final Motherboard ID: ") + csMotherBoardNo);
	return csMotherBoardNo;
}

void CCPUInfo::CheckCharSet(CString &csMotherBoardNo)
{
	CString csFinalSerial(L"");
	int iLen = csMotherBoardNo.GetLength();
	csMotherBoardNo.MakeUpper();
	for(int iCtr = 0; iCtr < iLen; iCtr++)
	{
		if(((csMotherBoardNo.GetAt(iCtr) >= 'A') && (csMotherBoardNo.GetAt(iCtr) <= 'Z')) ||
			((csMotherBoardNo.GetAt(iCtr) >= '0') && (csMotherBoardNo.GetAt(iCtr) <= '9')))
		{
			csFinalSerial += csMotherBoardNo.GetAt(iCtr);
		}
	}
	csMotherBoardNo = csFinalSerial;
}
BOOL CCPUInfo::_GetNetworkMacID()
{
	try
	{
		m_csarrMACAddresses.RemoveAll();
		HRESULT hres;
		//Initialize COM.
		hres = CoInitialize(0);
		COINITIALIZE_OUTPUTDEBUGSTRING(hres);
		if (FAILED(hres))
		{
			//AddLogEntry(L"Failed to initialize COM library. Error code");// = 0x" << hex << hres << endl;
			goto END;
		}

		{
			hres =  CoInitializeSecurity(
				NULL, 
				0,							 // COM authentication
				NULL,                        // Authentication services
				NULL,                        // Reserved
				RPC_C_AUTHN_LEVEL_NONE,		 // Default authentication 
				RPC_C_IMP_LEVEL_IDENTIFY,	 // Default Impersonation  
				NULL,                        // Authentication info
				0,							 // Additional capabilities 
				NULL                         // Reserved
				);
			COCREATE_OUTPUTDEBUGSTRING(hres);
			if (FAILED(hres))
			{
				//AddLogEntry(L"Failed to initialize security. Error code = 0x");// << hex << hres << endl;
				if(hres == E_OUTOFMEMORY)
				{
					goto END;

				}
			}

			IWbemLocator *pLoc = NULL;
			hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &pLoc);
			COCREATE_OUTPUTDEBUGSTRING(hres);
			if (FAILED(hres))
			{
				//AddLogEntry(L"Failed to create IWbemLocator object.");// << " Err code = 0x"  << hex << hres << endl;
				goto END;

			}

			IWbemServices *pSvc = NULL;
			hres = pLoc->ConnectServer(
				_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
				NULL,                    // User name. NULL = current user
				NULL,                    // User password. NULL = current
				0,                       // Locale. NULL indicates current
				NULL,                    // Security flags.
				0,                       // Authority (e.g. Kerberos)
				0,                       // Context object 
				&pSvc                    // pointer to IWbemServices proxy
				);

			if (FAILED(hres))
			{
				//AddLogEntry(L"Could not connect. Error code = 0x");// << hex << hres << endl;
				pLoc->Release();     
				goto END;

			}

			hres = CoSetProxyBlanket(
				pSvc,                        // Indicates the proxy to set
				RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
				RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
				NULL,                        // Server principal name 
				RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
				RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
				NULL,                        // client identity
				EOAC_NONE                    // proxy capabilities 
				);

			if (FAILED(hres))
			{
				//AddLogEntry(L"Could not set proxy blanket. Error code = 0x");// << hex << hres << endl;
				pSvc->Release();
				pLoc->Release();     
				goto END;

			}

			// For example, get the name of the operating system
			IEnumWbemClassObject* pEnumerator = NULL;
			hres= pSvc->ExecQuery(
				L"WQL",L"SELECT * FROM Win32_NetworkAdapter",
				WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
				NULL,
				&pEnumerator);

			if (FAILED(hres))
			{
				//AddLogEntry(L"Query for operating system name failed.");//<< " Error code = 0x" << hex << hres << endl;
				pSvc->Release();
				pLoc->Release();
				goto END;

			}

			IWbemClassObject *pclsObj = NULL;         

			ULONG uReturn = 0;

			while (hres != WBEM_S_FALSE)
			{
				hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

				if(0 == uReturn)
				{
					break;
				}

				VARIANT vtProp;

				CString mac,PnpDeviceId,Manufacturer, csProductName;

				// Get the value of the Name property
				hres=pclsObj->Get(L"MACAddress", 0,&vtProp, 0, 0);
				//check the HRESULT to see if the action succeeded.

				if(SUCCEEDED(hres) && (V_VT(&vtProp) == VT_BSTR))
				{  
					mac=(CString)vtProp.bstrVal;
					hres=pclsObj->Get(L"PNPDeviceID", 0,&vtProp, 0, 0);

					if(SUCCEEDED(hres) && (V_VT(&vtProp) == VT_BSTR))
					{   
						PnpDeviceId=(CString)vtProp.bstrVal;
						hres=pclsObj->Get(L"Manufacturer", 0,&vtProp, 0, 0);
						//AddLogEntry(L">> PNPDeviceID:");
						//AddLogEntry(PnpDeviceId);

						if(SUCCEEDED(hres) && (V_VT(&vtProp) == VT_BSTR))
						{ 
							Manufacturer=(CString)vtProp.bstrVal;
							//AddLogEntry(L">> Manufacturer:");
							//AddLogEntry(Manufacturer);
							hres=pclsObj->Get(L"ProductName", 0,&vtProp, 0, 0);
					
							if(SUCCEEDED(hres) && (V_VT(&vtProp) == VT_BSTR))
							{ 
								csProductName=(CString)vtProp.bstrVal;
								bool bSkip = false;
								if(csProductName.Find(L"HUAWEI") != -1)
								{
									bSkip = true;									
								}

							//display mac only if  PNPdevice id not root and manufacturer not microsoft 
							if(!bSkip && (PnpDeviceId.Find(L"ROOT\\")==-1)&&(Manufacturer.Find(L"Microsoft")==-1))
							{	 
								if(m_csarrMACAddresses.GetCount() == 3)
								{
									break;//added to take three mac id's only
								}
								if(m_csarrMACAddresses.GetCount() < 1)
								{
									_tcscpy_s(m_szNetworkMacID,(LPCTSTR)mac);
								}
								m_csarrMACAddresses.Add((LPCTSTR)mac);
							}
								VariantClear(&vtProp);
							}
						}
					}			
				}
			}
			if(pSvc)
			{
				pSvc->Release();
			}
			if(pLoc)
			{
				pLoc->Release();
			}
			if(pEnumerator)
			{
				pEnumerator->Release();
			}

			if(pclsObj)
			{
				pclsObj->Release();
			}
		}
	}
	catch(_com_error &e)
	{
		_bstr_t bstr = _com_error(e).ErrorMessage();
		AddLogEntry(bstr);	
		AddLogEntry(L"_GetNetworkMacID..._com_error: %s",(LPCTSTR)bstr);
	}
	catch(...)
	{
		AddLogEntry(L"_GetNetworkMacID...default exception!");
	}
END:
	CoUninitialize();
	return TRUE;
}

BOOL CCPUInfo::_GetNetworkMacIDSEH()
{
    __try
	{
		_GetNetworkMacID();
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("_GetNetworkMacIDSEH"), false))
	{
	}
	return TRUE;
}

/*-------------------------------------------------------------------------------------
Function		: GetProcessorSerialNumber
In Parameters	: -
Out Parameters	: CString : string containg Processor serial number
Purpose			: This Function obtain Processor serial No.on local machine
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CString	CCPUInfo::GetProcessorSerialNumber()
{
	CString csProcessorID = _T("");
	HRESULT hres;
    //Initialize COM.

	hres =  CoInitialize(0); 
	COINITIALIZE_OUTPUTDEBUGSTRING(hres);
    hres =  CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
	COCREATE_OUTPUTDEBUGSTRING(hres);
    if (FAILED(hres))
    {
		if(hres == E_OUTOFMEMORY)
		{
			CoUninitialize();
			return csProcessorID;
		}
    }
    
    IWbemLocator *pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &pLoc);
	COCREATE_OUTPUTDEBUGSTRING(hres);
    if (FAILED(hres))
    {
        CoUninitialize();
        return csProcessorID;
    }

    IWbemServices *pSvc = NULL;
    hres = pLoc->ConnectServer(
							 _bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
							 NULL,                    // User name. NULL = current user
							 NULL,                    // User password. NULL = current
							 0,                       // Locale. NULL indicates current
							 NULL,                    // Security flags.
							 0,                       // Authority (e.g. Kerberos)
							 0,                       // Context object 
							 &pSvc                    // pointer to IWbemServices proxy
							 );
    
    if(FAILED(hres))
    {
        pLoc->Release();     
        CoUninitialize();
        return csProcessorID;
    }
    hres = CoSetProxyBlanket(
						   pSvc,                        // Indicates the proxy to set
						   RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
						   RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
						   NULL,                        // Server principal name 
						   RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
						   RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
						   NULL,                        // client identity
						   EOAC_NONE                    // proxy capabilities 
						);

    if (FAILED(hres))
    {
        pSvc->Release();
        pLoc->Release();     
        CoUninitialize();
        return csProcessorID;
    }

    // For example, get the name of the operating system
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
						bstr_t("WQL"), 
						bstr_t("SELECT * FROM Win32_Processor"),
						WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
						NULL,
						&pEnumerator);
    
    if (FAILED(hres))
    {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return csProcessorID;
    }

    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;
   
    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if(0 == uReturn)
        {
            break;
        }

        VARIANT vtProp;

        // Get the value of the Name property
        hr = pclsObj->Get(L"ProcessorId", 0, &vtProp, 0, 0);
		csProcessorID = (CString)vtProp.bstrVal;
        VariantClear(&vtProp);
    }

	pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    pclsObj->Release();
    CoUninitialize();
	return csProcessorID;

}

/*-------------------------------------------------------------------------------------
Function		: GetDiskSerialNo
In Parameters	: -
Out Parameters	: CString : string containg Disk serial number
Purpose			: This Function obtain Disk serial No.on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetDiskSerialNo()
{
	try
	{
		m_csDiskSerialNo.Empty();

		_GetHardDriveComputerID();

		if(m_csDiskSerialNo == "$")
			m_csDiskSerialNo.Empty();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetDiskSerialNo"));
		m_csDiskSerialNo.Empty();
	}
	return m_csDiskSerialNo;
}

/*-------------------------------------------------------------------------------------
Function		: _GetHardDriveComputerID
In Parameters	: -
Out Parameters	: INT : containg Hard Drive Id
Purpose			: This function obtains Hard Drive Id on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
INT CCPUInfo::_GetHardDriveComputerID()
{
	try
	{
		INT iRetVal = FALSE;

		m_chHardDriveSerialNumber.Empty();

		//  this works under WinNT4 or Win2K if you have admin rights
		iRetVal = _ReadPhysicalDriveInNT (); 

		//  this should work in WinNT or Win2K if previous did not work this is kind of
		//  back door via the SCSI mini port driver into  the IDE drives
		if(!iRetVal)
			iRetVal = _ReadIdeDriveAsScsiDriveInNT ();

		return iRetVal;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::_GetHardDriveComputerID"));
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: _ReadPhysicalDriveInNT
In Parameters	: -
Out Parameters	: INT : contain Physical drive on NT
Purpose			: This Function obtain Physical drive on NT machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
INT CCPUInfo::_ReadPhysicalDriveInNT ()
{
	try
	{
		INT iRetVal = FALSE;
		INT iDrive = 0;

		for (iDrive = 0; iDrive < MAX_IDE_DRIVES; iDrive++)
		{
			HANDLE hPhysicalDriveIOCTL = 0;

			//  Try to get a handle to PhysicalDrive IOCTL, report failure and exit if can't.
			TCHAR driveName [MAX_PATH] = {0};

			swprintf_s(driveName, _countof(driveName), _T("\\\\.\\PhysicalDrive%d"), iDrive);

			//  Windows NT, Windows 2000, must have admin rights
			hPhysicalDriveIOCTL = CreateFile (driveName, GENERIC_READ | GENERIC_WRITE,
				FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
				OPEN_EXISTING, 0, NULL);

			if(hPhysicalDriveIOCTL != INVALID_HANDLE_VALUE)
			{
				GETVERSIONOUTPARAMS VersionParams = {0};
				DWORD               cbBytesReturned = 0;

				// Get the version, etc of PhysicalDrive IOCTL
				if(!DeviceIoControl (hPhysicalDriveIOCTL, DFP_GET_VERSION,
					NULL, 0, &VersionParams, sizeof(VersionParams), &cbBytesReturned, NULL))
				{
					CString csErr;
					csErr.Format(_T("DFP_GET_VERSION failed for drive %d and errorcode = %d"), iDrive,::GetLastError());
					AddLogEntry(csErr);
					//	continue;
				}

				// If there is a IDE device at number "i" issue commands to the device
				if(VersionParams.bIDEDeviceMap > 0)
				{
					BYTE             bIDCmd = 0;   // IDE or ATAPI IDENTIFY cmd
					SENDCMDINPARAMS  scip = {0};

					// Now, get the ID sector for all IDE devices in the system.
					// If the device is ATAPI use the IDE_ATAPI_IDENTIFY command,
					// otherwise use the IDE_ATA_IDENTIFY command
					bIDCmd =(VersionParams.bIDEDeviceMap >> iDrive & 0x10)? IDE_ATAPI_IDENTIFY : IDE_ATA_IDENTIFY;

					memset(IdOutCmd, 0, sizeof(IdOutCmd));

					if(_DoIDENTIFY (hPhysicalDriveIOCTL, &scip, (PSENDCMDOUTPARAMS)&IdOutCmd,
						(BYTE)bIDCmd, (BYTE)iDrive, &cbBytesReturned))
					{
						DWORD diskdata [MAX_PATH];
						USHORT *pIdSector = (USHORT *)((PSENDCMDOUTPARAMS)IdOutCmd) ->bBuffer;

						for (int idx = 0; idx < MAX_PATH; idx++)
							diskdata [idx] = pIdSector [idx];

						_PrintIdeInfo (iDrive, diskdata);
						iRetVal = TRUE;
					}
				}
				CloseHandle (hPhysicalDriveIOCTL);
			}
		}
		return iRetVal;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::_ReadPhysicalDriveInNT"));
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: _ReadIdeDriveAsScsiDriveInNT
In Parameters	: -
Out Parameters	: INT :
Purpose			: This Function obtain Volume serial No.on local machine
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
INT CCPUInfo::_ReadIdeDriveAsScsiDriveInNT (void)
{
	try
	{
		int iRetVal = FALSE;
		int controller = 0;

		for (controller = 0; controller < 2; controller++)
		{
			HANDLE hScsiDriveIOCTL = 0;
			TCHAR   driveName [MAX_PATH] = {0};

			//Try to get a handle to PhysicalDrive IOCTL, report failure and exit if can't.
			swprintf_s(driveName, _countof(driveName), _T("\\\\.\\Scsi%d:"), controller);

			//  Windows NT, Windows 2000, any rights should do
			hScsiDriveIOCTL = CreateFile(driveName, GENERIC_READ | GENERIC_WRITE,
				FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
				OPEN_EXISTING, 0, NULL);

			if(hScsiDriveIOCTL != INVALID_HANDLE_VALUE)
			{
				int drive = 0;

				for (drive = 0; drive < 2; drive++)
				{
					TCHAR buffer [sizeof (SRB_IO_CONTROL) + SENDIDLENGTH] = {0};
					SRB_IO_CONTROL *p = (SRB_IO_CONTROL *)buffer;
					SENDCMDINPARAMS *pin =
						(SENDCMDINPARAMS *)(buffer + sizeof (SRB_IO_CONTROL));
					DWORD dummy;

					//memset (buffer, 0, sizeof (buffer));
					p->HeaderLength = sizeof (SRB_IO_CONTROL);
					p->Timeout = 10000;
					p->Length = SENDIDLENGTH;
					p->ControlCode = IOCTL_SCSI_MINIPORT_IDENTIFY;

					//wcscpy cannot be used here
					//wcscpy_s((TCHAR *)p->Signature, _countof(p->Signature),_T("SCSIDISK"));
					strncpy_s((char *)p->Signature, sizeof(p->Signature), (char *)"SCSIDISK", 8);
					pin->irDriveRegs.bCommandReg = IDE_ATA_IDENTIFY;
					pin->bDriveNumber = (BYTE)drive;

					if(DeviceIoControl (hScsiDriveIOCTL, IOCTL_SCSI_MINIPORT,
						buffer,
						sizeof (SRB_IO_CONTROL) +
						sizeof (SENDCMDINPARAMS) - 1,
						buffer,
						sizeof (SRB_IO_CONTROL) + SENDIDLENGTH,
						&dummy, NULL))
					{

						SENDCMDOUTPARAMS *pOut =
							(SENDCMDOUTPARAMS *)(buffer + sizeof (SRB_IO_CONTROL));
						IDSECTOR *pId = (IDSECTOR *)(pOut->bBuffer);
						if(pId->sModelNumber [0])
						{
							DWORD diskdata[MAX_PATH]={0};
							int ijk = 0;
							USHORT *pIdSector = (USHORT *)pId;
							for (ijk = 0; ijk < MAX_PATH; ijk++)
								diskdata [ijk] = pIdSector [ijk];

							_PrintIdeInfo (controller * 2 + drive, diskdata);
							iRetVal = TRUE;
						}
					}
				}
				CloseHandle (hScsiDriveIOCTL);
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::_ReadIdeDriveAsScsiDriveInNT"));
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: _PrintIdeInfo
In Parameters	: int - drive
DWORD - diskdata
Out Parameters	: void
Purpose			: to get Hard Drive Serial number
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
void CCPUInfo::_PrintIdeInfo (int iDrive, DWORD diskdata [MAX_PATH])
{
	try
	{
		// copy the hard driver serial number to the buffer
		m_chHardDriveSerialNumber = _ConvertToString(diskdata, 10, 19);

		CString csTemp;
		csTemp = m_csDiskSerialNo;
		if(!csTemp.IsEmpty())
			m_csDiskSerialNo += "$";

		CString csTempHDDNo;
		csTempHDDNo.Format(_T("%s"), static_cast<LPCTSTR>(m_chHardDriveSerialNumber));
		m_csDiskSerialNo += csTempHDDNo.Trim();// HardDriveSerialNumber; 
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::_PrintIdeInfo"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: _ConvertToString
In Parameters	: DWORD - disk data
int - first index
int - last index
Out Parameters	: char * - pointer to string
Purpose			: to convert diskdata to string
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
CString CCPUInfo::_ConvertToString (DWORD diskdata [MAX_PATH], int firstIndex, int lastIndex)
{
	try
	{
		TCHAR string [MAX_BUFFER];
		int index = 0;
		int position = 0;

		//  each integer has two characters stored in it backwards
		for (index = firstIndex; index <= lastIndex; index++)
		{
			//  get high byte for 1st character
			string [position] = (TCHAR)(diskdata [index] / 256);
			position++;

			//  get low byte for 2nd character
			string [position] = (TCHAR)(diskdata [index] % 256);
			position++;
		}

		//  end the string
		string [position] = '\0';

		//  cut off the trailing blanks
		for (index = position - 1; index > 0 && ' ' == string [index]; index--)
			string [index] = '\0';

		return string;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::_ConvertToString"));
	}
	return _T("");
}

/*-------------------------------------------------------------------------------------
Function		: _DoIDENTIFY
In Parameters	: HANDLE - PhysicalDriveIOCTL handle
PSENDCMDINPARAMS - in param struct
PSENDCMDOUTPARAMS - out param struct
BYTE - ID
BYTE - drive number
PDWORD - return bytes
Out Parameters	: bool
Purpose			: to identify the command
Author			: Nupur Aggarwal
--------------------------------------------------------------------------------------*/
BOOL CCPUInfo::_DoIDENTIFY (HANDLE hPhysicalDriveIOCTL, PSENDCMDINPARAMS pSCIP,
							PSENDCMDOUTPARAMS pSCOP, BYTE bIDCmd, BYTE bDriveNum,
							PDWORD lpcbBytesReturned)
{
	try
	{
		// Set up data structures for IDENTIFY command.
		pSCIP->cBufferSize = MAX_BUFFER;
		pSCIP->irDriveRegs.bFeaturesReg = 0;
		pSCIP->irDriveRegs.bSectorCountReg = 1;
		pSCIP->irDriveRegs.bSectorNumberReg = 1;
		pSCIP->irDriveRegs.bCylLowReg = 0;
		pSCIP->irDriveRegs.bCylHighReg = 0;

		// Compute the drive number.
		pSCIP->irDriveRegs.bDriveHeadReg = 0xA0 | ((bDriveNum & 1)<< 4);

		// The command can either be IDE identify or ATAPI identify.
		pSCIP->irDriveRegs.bCommandReg = bIDCmd;
		pSCIP->bDriveNumber = bDriveNum;
		pSCIP->cBufferSize = MAX_BUFFER;

		return (DeviceIoControl (hPhysicalDriveIOCTL, DFP_RECEIVE_DRIVE_DATA,
			(LPVOID)pSCIP, sizeof(SENDCMDINPARAMS) - 1, (LPVOID)pSCOP,
			sizeof(SENDCMDOUTPARAMS) + MAX_BUFFER - 1, lpcbBytesReturned, NULL));
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::_DoIDENTIFY"));
	}
	return false;
};


/*-------------------------------------------------------------------------------------
Function		: GetAllEnvVariable
In Parameters	: -
Out Parameters	: bool : true / false
Purpose			: Get all environment path in an array
:
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/

bool CCPUInfo::GetAllEnvVariable(CStringArray &csEnvVarArr)
{
	CString csEnvVari;
	DWORD dwSize = 32767;//Max size of environment variable
	if(GetEnvironmentVariable(_T("PATH"),csEnvVari.GetBuffer(dwSize),dwSize) != 0)
	{
		csEnvVari.ReleaseBuffer();
		CString csToken;
		int iCurPos= 0;
		csToken = csEnvVari.Tokenize(_T(";"), iCurPos);
		while(csToken != _T(""))
		{
			csToken.Replace(_T("\\."),_T(""));
			csEnvVarArr.Add(csToken);
			csToken = csEnvVari.Tokenize(_T(";"), iCurPos);
		}
		return true;
	}
	csEnvVari.ReleaseBuffer();
	return false;
}
/*-------------------------------------------------------------------------------------
Function		: GetDirectoryPath
In Parameters	: CSIDL_ID - CSIDL ID
Out Parameters	: CString : Folder path
Purpose			: Get Directory path by CSIDL ID
:
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetDirectoryPath(DWORD CSIDL_ID)
{
	if(CSIDL_ID != 0)
	{
		TCHAR lpszPath[MAX_PATH] = {0};

		typedef HMODULE  (__stdcall *SHGETFOLDERPATH)(HWND, int, HANDLE, DWORD, LPTSTR);

		HMODULE hModule = LoadLibrary(_T("SHFOLDER.DLL"));
		if(hModule != NULL)
		{
			SHGETFOLDERPATH fnShGetFolderPath = (SHGETFOLDERPATH)GetProcAddress(hModule, "SHGetFolderPathW");

			if(fnShGetFolderPath != NULL)
			{
				fnShGetFolderPath(0,CSIDL_ID,NULL,	0,lpszPath);
			}
			FreeLibrary(hModule);
		}

		return lpszPath;
	}
	else
		return _T("");
}

/*-------------------------------------------------------------------------------------
Function		: GetProdInstallPath
In Parameters	: -
Out Parameters	: CString : Folder path
Purpose			: Get GetProdInstallPath path
:
Author			:
--------------------------------------------------------------------------------------*/
CString CCPUInfo::GetProdInstallPath()
{
	CString csReturn;
	try
	{
		TCHAR *lpszExeFileName = NULL;

		lpszExeFileName = new TCHAR[MAX_FILE_PATH];

		if(lpszExeFileName)
		{
			SecureZeroMemory(lpszExeFileName, MAX_FILE_PATH*sizeof(TCHAR)); 

			GetModuleFileName((HINSTANCE)&__ImageBase, lpszExeFileName, MAX_FILE_PATH);

			csReturn = lpszExeFileName;
			delete[] lpszExeFileName;
			lpszExeFileName = NULL;

			int iPos = 0;
			iPos = csReturn.ReverseFind('\\');

			if(-1 == iPos)
			{
				csReturn = csReturn + BACK_SLASH;
			}
			else
			{
				csReturn = csReturn.Mid(0, iPos);
				csReturn = csReturn + BACK_SLASH;
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CCPUInfo::GetProdInstallPath"));
	}

	return csReturn;
}

bool CCPUInfo::IsSafeBoot()
{
	//    0           Normal boot
	//    1           Fail-safe boot
	//    2           Fail-safe with network boot

	if(GetSystemMetrics(SM_CLEANBOOT))
	{
		return true;
	}
	else
	{
		return false;
	}
}
bool CCPUInfo::GetFlagForUniqueId()
{
	return flagforuniqueid;
}
bool CCPUInfo::IsVistaServiceRequired()
{
	bool bVistaServiceRequired = false;
	//Check for Windows Vista
	CString osVersion = GetOSVerTag();
	if(osVersion.Find(WVISTA) != -1 || osVersion.Find(WWIN7) != -1 || osVersion.Find(WWIN8) != -1)//Vista/win7 32, 64 bit
	{
		//Check for Windows Running in Normal Mode i.e.not in safe mode
		//In Safe Mode, Windows is running using admin rights so Service is not required.
		//Otherwise in Normal mode, service is required.
		if(!IsSafeBoot())
			bVistaServiceRequired = true;
	}
	return bVistaServiceRequired;
}

bool CCPUInfo::GetMACaddress(CStringArray &arrMacAddress, CString &csAllAddress)
{
	bool bAddressFound = false;
	IP_ADAPTER_INFO AdapterInfo[16] = {0};			// Allocate information for up to 16 NICs
	DWORD dwBufLen = sizeof(AdapterInfo);			// Save memory size of buffer

	csAllAddress = L"";
	arrMacAddress.RemoveAll();
	DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
	if(dwStatus != ERROR_SUCCESS)
		return bAddressFound;

	PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;	// Contains pointer to current adapter info
	do
	{
		CString csAddress;
		csAddress.Format(L"%02X-%02X-%02X-%02X-%02X-%02X", 
			pAdapterInfo->Address[0], pAdapterInfo->Address[1], pAdapterInfo->Address[2], 
			pAdapterInfo->Address[3], pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
		arrMacAddress.Add(csAddress);
		csAllAddress += csAddress += L":";
		bAddressFound = true;
		pAdapterInfo = pAdapterInfo->Next;			// Progress through linked list
	}
	while(pAdapterInfo);							// Terminate if last adapter
	return bAddressFound;
}

PIP_ADAPTER_INFO CCPUInfo::GetAllAdapterInfo()
{							
	PIP_ADAPTER_INFO pAdaptersInfo = NULL;
	CString csAdapterInfo;
	ULONG ulOutBufLen = 0;	
	DWORD dwError = GetAdaptersInfo( pAdaptersInfo, &ulOutBufLen);
	if (dwError == ERROR_BUFFER_OVERFLOW) 
	{
		free(pAdaptersInfo);
		pAdaptersInfo = NULL;
		pAdaptersInfo = (IP_ADAPTER_INFO *) malloc (ulOutBufLen); 
		memset(pAdaptersInfo,0x00,sizeof(IP_ADAPTER_INFO));
		dwError = GetAdaptersInfo( pAdaptersInfo, &ulOutBufLen);
	}
	else if(dwError == ERROR_NO_DATA)
		AfxMessageBox(L"No adapter information exists for the local computer");
	else if(dwError == ERROR_NOT_SUPPORTED)
		AfxMessageBox(L"GetAdaptersInfo is not supported by the operating system running on the local computer");

	return pAdaptersInfo;
}

DWORD CCPUInfo::GetMajorOSVersion()
{
	static DWORD dwReturnVal = 0;
	if(dwReturnVal == 0)
	{
		lpOSVersionInfo = new OSVERSIONINFOEX;
		ZeroMemory(lpOSVersionInfo, sizeof(OSVERSIONINFOEX));
		lpOSVersionInfo->dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

		//To get extended information about the version of the operating system that currently running
		if(GetVersionEx((OSVERSIONINFO *)lpOSVersionInfo) == 0)
		{
			//this api fails in case of windows 98 first version so taking the os version from registry.
			delete lpOSVersionInfo;
			return dwReturnVal;
		}
		dwReturnVal = lpOSVersionInfo->dwMajorVersion;

		delete lpOSVersionInfo;
		lpOSVersionInfo = NULL;
	}
	return dwReturnVal;
}

bool CCPUInfo::GetMajorAndMinorOSVersion(DWORD &dwMajorVersion, DWORD &dwMinorVersion)
{
	static DWORD dwMajor = 0;
	static DWORD dwMinor = 0;
	dwMajorVersion = dwMinorVersion = 0;
	if(dwMajor == 0)
	{
		lpOSVersionInfo = new OSVERSIONINFOEX;
		ZeroMemory(lpOSVersionInfo, sizeof(OSVERSIONINFOEX));
		lpOSVersionInfo->dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

		//To get extended information about the version of the operating system that currently running
		if(GetVersionEx((OSVERSIONINFO *)lpOSVersionInfo) == 0)
		{
			//this api fails in case of windows 98 first version so taking the os version from registry.
			delete lpOSVersionInfo;
			return false;
		}
	
		dwMajor = lpOSVersionInfo->dwMajorVersion;
		dwMinor = lpOSVersionInfo->dwMinorVersion;

		delete lpOSVersionInfo;
		lpOSVersionInfo = NULL;
	}
	dwMajorVersion = dwMajor;
	dwMinorVersion = dwMinor;
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: GetMotherBoardSerialNumber
In Parameters	: -
Out Parameters	: CString : string containg  Raw Motherboard serial number
Purpose			: This Function obtain Raw Motherboard serial No.on local machine
Author			: Siddharam Pujari
--------------------------------------------------------------------------------------*/
CString	CCPUInfo::GetRawMotherBoardID()
{
	wmemset(m_szMotherBoardID, 0, MAX_PATH);
	CString csMotherBoardNo = _T("");

	_GetMotherBoardSerialNumberSEH();

	csMotherBoardNo = m_szMotherBoardID;
	AddLogEntry(_T("Raw Motherboard ID: %s"), csMotherBoardNo);
	return csMotherBoardNo;
}

CString	CCPUInfo::GetRawNetworkMacID()
{
	wmemset(m_szNetworkMacID, 0, MAX_PATH);
	CString csMacAddresses;
	_GetNetworkMacIDSEH();
	csMacAddresses = m_szNetworkMacID;
	csMacAddresses.Replace(L":", L"-");
	return csMacAddresses;
}
CString CCPUInfo::GetVolumeSerialNumber()
{
	CString csMotherBoardNo = _T("");
	CString csVolumeSerial = GetVolumeSerialNo();
	AddLogEntry(L"VolumeSerial: >%s<", csVolumeSerial);
	csVolumeSerial.Replace(L"[", L"");
	csVolumeSerial.Replace(L"]", L"");
	csVolumeSerial.Replace(L"-", L"");
	csVolumeSerial.Replace(L"_", L"");
	CString csOs = GetOSVerTag();
	AddLogEntry(L"Os: >%s<", csOs);
	csOs.Replace(_T(" "), _T(""));
		
	CString csPCName = GetPCName();
	AddLogEntry(L"PCName: >%s<", csPCName);
	csPCName.Replace(L"[", L"");
	csPCName.Replace(L"]", L"");
	csPCName.Replace(L"-", L"");
	csPCName.Replace(L"_", L"");
	csPCName.Replace(_T(" "), _T(""));
	csPCName.Replace(_T(":"), _T(""));
	if(csPCName.GetLength() < 2)
	{
		csPCName = csPCName + _T("PCN");			//PC Name
	}
	csMotherBoardNo.Format(_T("%s%s%s"), csVolumeSerial, csPCName.Left(2), csOs.Right(2));
	AddLogEntry(L"MotherBoardNo: >%s<", csMotherBoardNo);
	if(csMotherBoardNo.GetLength() < 12)
	{
		csMotherBoardNo += csMotherBoardNo;
		AddLogEntry(L"Double MotherBoardNo: >%s<", csMotherBoardNo);
	}

	return csMotherBoardNo;

}

/*-----------------------------------------------------------------------------------------------
Function		: FirewallXPCheck
In Parameters	: -
Out Parameters	: boolean: OS is XP or not....
Purpose			: To block or unblock the features of firewall for XP... In future we return false
				  when XP is no longer in use.
				  if true :install NetFilter driver
				  else not
Author			: XP
--------------------------------------------------------------------------------------------------*/
bool CCPUInfo::FirewallXPCheck()
{
	DWORD dwMajorVersion = 0;
	DWORD dwMinorVersion = 0;
	GetMajorAndMinorOSVersion(dwMajorVersion, dwMinorVersion);
	if(dwMajorVersion ==5)
		return true;
	return false;
}