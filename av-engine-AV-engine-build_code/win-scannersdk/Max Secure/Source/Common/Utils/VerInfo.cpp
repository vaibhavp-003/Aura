/*======================================================================================
FILE             : VerInfo.h
ABSTRACT         : 
DOCUMENTS        : 
AUTHOR           : Darshan Singh Virdi
COMPANY          : Aura 
COPYRIGHT(NOTICE): (C) Aura
                   Created as an unpublished copyright work.  All rights reserved.
                   This document and the information it contains is confidential and
                   proprietary to Aura.  Hence, it may not be
                   used, copied, reproduced, transmitted, or stored in any form or by any
                   means, electronic, recording, photocopying, mechanical or otherwise,
                   without the prior written permission of Aura.
CREATION DATE   : 24-Feb-2006
NOTES           : Defines the class behaviors for the application
VERSION HISTORY : 
                   Version: 2.5.0.16
                   Resource : Shweta
                   Description: added new function for Original Filename GetFileInternalName
                   Version: 2.5.0.70
                   Resource : Shweta
                   Description: added new function for Internal Filename GetInternalNameFile
=============================================================================*/
#include "pch.h"
#include <share.h>
#include <stdio.h>
#include <time.h>
#include <io.h>
#include "verinfo.h"
#include "Registry.h"

#pragma warning(disable : 4996)

#define  REG_NOTIFY_ENTRY		 _T("software\\microsoft\\windows nt\\currentversion\\winlogon\\notify\\")

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

typedef enum
{
	LISTITEM_FFI_FILEVERSION	= 0,
	LISTITEM_FFI_PRODUCTVERSION	= 1,
	LISTITEM_FFI_FILEFLAGSMASK	= 2,
	LISTITEM_FFI_FILEFLAGS		= 3,
	LISTITEM_FFI_FILEOS			= 4,
	LISTITEM_FFI_FILETYPE		= 5,
	LISTITEM_FFI_FILESUBTYPE	= 6
} LISTITEM_FFI;

LPCTSTR s_lpszFVI[] =
{
	_T("FILEVERSION"),	_T("PRODUCTVERSION"),
	_T("FILEFLAGSMASK"),	_T("FILEFLAGS"),
	_T("FILEOS"),			_T("FILETYPE"),
	_T("FILESUBTYPE")
};

MAP s_lpVOS[] =
{
	{ VOS_UNKNOWN,			_T("VOS_UNKNOWN")		},
	{ VOS_DOS,				_T("VOS_DOS"),		},
	{ VOS_OS216,			_T("VOS_OS216"),		},
	{ VOS_OS232,			_T("VOS_OS232"),		},
	{ VOS_NT,				_T("VOS_NT")			},
	{ VOS__WINDOWS16,		_T("VOS__WINDOWS16")	},
	{ VOS__PM16,			_T("VOS__PM16")		},
	{ VOS__PM32,			_T("VOS__PM32")		},
	{ VOS__WINDOWS32,		_T("VOS__WINDOWS32")		},
	{ VOS_DOS_WINDOWS16,	_T("VOS_DOS_WINDOWS16")	},
	{ VOS_DOS_WINDOWS32,	_T("VOS_DOS_WINDOWS32")	},
	{ VOS_OS216_PM16,		_T("VOS_OS216_PM16")		},
	{ VOS_OS232_PM32,		_T("VOS_OS232_PM32")		},
	{ VOS_NT_WINDOWS32,		_T("VOS_NT_WINDOWS32")	}
};

MAP s_lpFILT[] =
{
	{ VFT_UNKNOWN,			_T("VFT_UNKNOWN")	},
	{ VFT_APP,				_T("VFT_APP")		},
	{ VFT_DLL,				_T("VFT_DLL")		},
	{ VFT_DRV,				_T("VFT_DRV")		},
	{ VFT_FONT,				_T("VFT_FONT")	},
	{ VFT_VXD,				_T("VFT_VXD")		},
	{ VFT_STATIC_LIB,		_T("VFT_STATIC_LIB")	}
};

MAP s_lpFNTT[] =
{
	{ VFT2_UNKNOWN,			_T("VFT2_UNKNOWN")		},
	{ VFT2_FONT_RASTER,		_T("VFT2_FONT_RASTER")	},
	{ VFT2_FONT_VECTOR,		_T("VFT2_FONT_VECTOR")	},
	{ VFT2_FONT_TRUETYPE,	_T("VFT2_FONT_TRUETYPE")	}
};

MAP s_lpDRVT[] =
{
	{ VFT2_UNKNOWN,			_T("VFT2_UNKNOWN")		},
	{ VFT2_DRV_PRINTER,		_T("VFT2_DRV_PRINTER")	},
	{ VFT2_DRV_KEYBOARD,	_T("VFT2_DRV_KEYBOARD")	},
	{ VFT2_DRV_LANGUAGE,	_T("VFT2_DRV_LANGUAGE")	},
	{ VFT2_DRV_DISPLAY,		_T("VFT2_DRV_DISPLAY")	},
	{ VFT2_DRV_MOUSE,		_T("VFT2_DRV_MOUSE")		},
	{ VFT2_DRV_NETWORK,		_T("VFT2_DRV_NETWORK")	},
	{ VFT2_DRV_SYSTEM,		_T("VFT2_DRV_SYSTEM")		},
	{ VFT2_DRV_INSTALLABLE,	_T("VFT2_DRV_INSTALLABLE")},
	{ VFT2_DRV_SOUND,		_T("VFT2_DRV_SOUND")		},
	{ VFT2_DRV_COMM,		_T("VFT2_DRV_COMM")		},
	{ VFT2_DRV_INPUTMETHOD, _T("VFT2_DRV_INPUTMETHOD")}
};


/*-------------------------------------------------------------------------------------
Function       : GetOFNSize
In Parameters  : void
Out Parameters : DWORD
Purpose		   : function to get osversion info in structure OSVERSIONINFO and return the size.
Author		   :  Anand
-------------------------------------------------------------------------------------*/
DWORD GetOFNSize(void)
{
	DWORD dwSize = sizeof(OPENFILENAME);

	OSVERSIONINFO osvi ={sizeof(OSVERSIONINFO)};
	::GetVersionEx(&osvi);

	if((osvi.dwPlatformId == VER_PLATFORM_WIN32_NT && osvi.dwMajorVersion >= 5) ||
		(osvi.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS &&
		(osvi.dwMinorVersion >= 90 || osvi.dwMajorVersion > 4)))
	{
		struct OPENFILENAMEEX : public OPENFILENAME {
			LPVOID		lpvReserved;
			DWORD		dwReserved;
			DWORD		dwFlagsEx;
		};
		dwSize = sizeof(OPENFILENAMEEX);
	};

	return dwSize;
}

/*-------------------------------------------------------------------------------------
Function       : DoTheVersionJob
In Parameters  : LPCTSTR csFileName, bool bDeleteFile
Out Parameters : bool
Purpose		   : Delete a File if it does not have a version tab
Author		   :  Anand
-------------------------------------------------------------------------------------*/
bool CFileVersionInfo::DoTheVersionJob(LPCTSTR csFileName, bool bDeleteFile)
{
	DWORD dwAttrs = GetFileAttributes(csFileName);
	if(dwAttrs != INVALID_FILE_ATTRIBUTES)
	{
		SetFileAttributes(csFileName, FILE_ATTRIBUTE_ARCHIVE);
	}

	bool bVersionFound = HasVersionTab(csFileName);
	if(!bVersionFound)//File does not have a version tab
	{
		if(bDeleteFile)
		{
			AddLogEntry(_T("##### Befor deletefile in  CFileVersionInfo::DoTheVersionJob"));
			if(!DeleteFile(csFileName))
			{
				AddLogEntry(_T("##### deletefile failed adding registry entry!in CFileVersionInfo::DoTheVersionJob"));
				if(ReplaceFileOnRestart(csFileName, NULL))
				{
					AddLogEntry(_T("##### added registry entry successfully!in  CFileVersionInfo::DoTheVersionJob"));
				}
				else
				{
					AddLogEntry(_T("##### adding registry entry failed!in  CFileVersionInfo::DoTheVersionJob"));
				}
			}
		}
		SetFileAttributes(csFileName, dwAttrs);
		return true;
	}
	SetFileAttributes(csFileName, dwAttrs);
	return false;
}


/*-------------------------------------------------------------------------------------
Function       : CheckNotifyEntry
In Parameters  : bool bDeleteFile
Out Parameters : bool
Purpose		   : Checking Registry Notify Entries for finding spywares
Author		   :  Anand
-------------------------------------------------------------------------------------*/
bool CFileVersionInfo::CheckNotifyEntry(bool bDeleteFile)
{
	bool bInvalidEntryFound = false;
	HKEY hKey;
	DWORD lpcbValueName;
	DWORD lpcData;
	DWORD lpcSubKey;

	HKEY hHiveKey = HKEY_LOCAL_MACHINE;
	const TCHAR *csMainKey = REG_NOTIFY_ENTRY;
	long lVal = RegOpenKeyEx(hHiveKey, csMainKey, 0,
								KEY_READ|KEY_ENUMERATE_SUB_KEYS|KEY_QUERY_VALUE, &hKey);
	if(lVal == ERROR_SUCCESS)
	{
		TCHAR strSysDir[MAX_PATH];
		GetSystemDirectory(strSysDir, MAX_PATH);
		RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, &lpcSubKey, NULL, NULL, &lpcbValueName,
						&lpcData, NULL, NULL);
		lpcSubKey = lpcSubKey * (sizeof(TCHAR) + sizeof(TCHAR));
		TCHAR *lpSubKey = new TCHAR[lpcSubKey];
		long i = 0;
		while(TRUE)
		{
			RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, &lpcSubKey, NULL, NULL, &lpcbValueName,
								&lpcData, NULL, NULL);
			lpcSubKey = lpcSubKey * (sizeof(TCHAR) + sizeof(TCHAR));
			lpcbValueName = lpcbValueName * (sizeof(TCHAR) + sizeof(TCHAR));
			lpcData = lpcData * (sizeof(TCHAR) + sizeof(TCHAR));

			if(RegEnumKey(hKey,i,lpSubKey,lpcSubKey)== ERROR_NO_MORE_ITEMS)
			{
				break;
			}
			else
			{
				TCHAR csSubKey[MAX_PATH] = {0};
				wcscpy_s(csSubKey,_countof(csSubKey), csMainKey);
				wcscat_s(csSubKey,_countof(csSubKey), _T("\\"));
				wcscat_s(csSubKey,_countof(csSubKey), lpSubKey);
				HKEY hSubKey;
				lVal = RegOpenKeyEx(hHiveKey,csSubKey,0,KEY_READ|KEY_QUERY_VALUE,&hSubKey);
				if(lVal == ERROR_SUCCESS)
				{
					DWORD dwType = REG_SZ;
					DWORD cchData = MAX_PATH;
					const TCHAR *csValue = _T("DLLName");
					lVal = RegQueryValueEx(hSubKey, csValue, NULL, &dwType, NULL, &cchData);
					if(lVal == ERROR_SUCCESS)
					{
						LPBYTE lpData = (LPBYTE)LocalAlloc(LPTR, cchData);
						lVal = RegQueryValueEx(hSubKey, csValue, NULL, &dwType, lpData, &cchData);
						if(lVal == ERROR_SUCCESS)
						{
							TCHAR csData[MAX_PATH] = {0};
							TCHAR csFileName[MAX_PATH] = {0};
							wcscpy_s(csData, _countof(csData),LPCTSTR(lpData));
							wcscpy_s(csFileName, _countof(csFileName),LPCTSTR(lpData));
							if(wcsstr(csData, _T(":"))== NULL)//append sysdir
							{
								swprintf_s(csFileName,_countof(csFileName),_T("%s\\%s"),
											strSysDir, csData);
							}

							// Version: 18.1
							// Resource: Anand
							// Description: added ippspw.dll for ignoring
							if(!StrStrI(csFileName, _T("navlogon.dll")) 
								&& !StrStrI(csFileName, _T("ippspw.dll")))
							{
								if(DoTheVersionJob(csFileName, bDeleteFile))
								{
									if(bDeleteFile)
									{
										RegDeleteKey(hHiveKey, csSubKey);
									}
									bInvalidEntryFound = true;
								}
							}
						}
						LocalFree(lpData);
					}
					RegCloseKey(hSubKey);
				}
			}
			i++;
		}
		if(lpSubKey)
		{
			delete [] lpSubKey;
			lpSubKey = NULL;
		}
	}

	return bInvalidEntryFound;
}

/*-------------------------------------------------------------------------------------
Function       : HasVersionTab
In Parameters  : LPCTSTR lpszFileName
Out Parameters : bool
Purpose		   : Checks whether file has versiontab
Author		   :  Anand
-------------------------------------------------------------------------------------*/
bool CFileVersionInfo::HasVersionTab(LPCTSTR lpszFileName)
{
	if(Open(lpszFileName)== FALSE)
	{
		return false;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
Function       : GetFileDescription
In Parameters  : LPCTSTR lpszFileName, LPTSTR lpszFileDescription
Out Parameters : bool
Purpose		   :
Author		   :  Anand
-------------------------------------------------------------------------------------*/
bool CFileVersionInfo::GetFileDescription(LPCTSTR lpszFileName, LPTSTR lpszFileDescription)
{
	if(!lpszFileDescription)
	{
		return false;
	}

	if(Open(lpszFileName)== FALSE)
	{
		return false;
	}

	return (QueryStringValue(2, lpszFileDescription, MAX_PATH)?true:false);
}
/*-------------------------------------------------------------------------------------
Function       : GetFileInternalName
In Parameters  : LPCTSTR lpszFileName, LPTSTR lpszFileDescription
Out Parameters : bool
Purpose		   : Get the Orginal name of file
Author		   : Shweta (2.5.0.16)
-------------------------------------------------------------------------------------*/
bool CFileVersionInfo::GetFileInternalName(LPCTSTR lpszFileName, LPTSTR lpszFileDescription)
{
	if(!lpszFileDescription)
	{
		return false;
	}

	if(Open(lpszFileName)== FALSE)
	{
		return false;
	}

	return (QueryStringValue(7, lpszFileDescription, MAX_PATH)?true:false);
}
/*-------------------------------------------------------------------------------------
Function       : GetInternalNameofFile
In Parameters  : LPCTSTR lpszFileName, LPTSTR lpszFileDescription
Out Parameters : bool
Purpose		   : Get the internal name of file
Author		   : Shweta (2.5.0.70)
-------------------------------------------------------------------------------------*/
bool CFileVersionInfo::GetInternalNameofFile(LPCTSTR lpszFileName, LPTSTR lpszFileDescription)
{
	if(!lpszFileDescription)
	{
		return false;
	}

	if(Open(lpszFileName)== FALSE)
	{
		return false;
	}

	return (QueryStringValue(4, lpszFileDescription, MAX_PATH) ? true : false);
}
/*-------------------------------------------------------------------------------------
Function       : GetProductVersion
In Parameters  : LPCTSTR lpszFileName, LPTSTR lpszFileDescription
Out Parameters : bool
Purpose		   : Get product version of file
Author		   : Shweta (2.5.0.70)
-------------------------------------------------------------------------------------*/
bool CFileVersionInfo::GetProductVersion(LPCTSTR lpszFileName, LPTSTR lpszFileDescription)
{
	if(!lpszFileDescription)
	{
		return false;
	}

	if(Open(lpszFileName) == FALSE)
	{
		return false;
	}

	return (QueryStringValue(3, lpszFileDescription, MAX_PATH)?true:false);
}
/*-------------------------------------------------------------------------------------
Function       : GetCompanyName
In Parameters  : LPCTSTR lpszFileName, LPTSTR lpszCompanyName
Out Parameters : bool
Purpose		   : Gets CompanyName value in versioninfo of file.
Author		   :  Anand
-------------------------------------------------------------------------------------*/
bool CFileVersionInfo::GetCompanyName(LPCTSTR lpszFileName, LPTSTR lpszCompanyName)
{
	if(!lpszCompanyName)
	{
		return false;
	}

	if(Open(lpszFileName)== FALSE)
	{
		return false;
	}

	return (QueryStringValue(1, lpszCompanyName, MAX_PATH) ? true : false);
}

/*-------------------------------------------------------------------------------------
Function       : GetLegalCopyRight
In Parameters  : LPCTSTR lpszFileName, LPTSTR lpszCompanyName
Out Parameters : bool
Purpose		   : Gets CompanyName value in versioninfo of file.
Author		   :  Anand
-------------------------------------------------------------------------------------*/
bool CFileVersionInfo::GetLegalCopyright(LPCTSTR lpszFileName, LPTSTR lpszCompanyName)
{
	if(!lpszCompanyName)
	{
		return false;
	}

	if(Open(lpszFileName)== FALSE)
	{
		return false;
	}

	return (QueryStringValue(5, lpszCompanyName, MAX_PATH) ? true : false);
}


/*-------------------------------------------------------------------------------------
Function       : DllGetVersion
In Parameters  : IN  HMODULE hModule, OUT DLLVERSIONINFO* lpDVI
Out Parameters : HRESULT
Purpose		   : this function is used in the exported DllGetVersion of any of  DLLs 
				to do the black work return the pointer to DLLVERSIONINFO structure 
				filled with  app version data.It uses the CFileVersionInfo class.
Author		   :  Anand
-------------------------------------------------------------------------------------*/
HRESULT STDAPICALLTYPE DllGetVersion(IN  HMODULE hModule, OUT DLLVERSIONINFO* lpDVI)
{
	if(hModule == NULL || ::IsBadReadPtr(lpDVI, sizeof(DLLVERSIONINFO*)))
	{
		ASSERT_RETURN (S_FALSE);
	}

	CONST DWORD cbSize = lpDVI->cbSize;

	if(
#ifdef DLLVERSIONINFO2
		(
#endif
		cbSize != sizeof(DLLVERSIONINFO )
#ifdef DLLVERSIONINFO2
		&& cbSize != sizeof(DLLVERSIONINFO2))
#endif
		|| ::IsBadWritePtr(lpDVI, cbSize))
	{
		ASSERT_RETURN (S_FALSE);
	}

	::ZeroMemory(lpDVI, cbSize);
	lpDVI->cbSize = cbSize;

	CFileVersionInfo fvi;
	if(fvi.Open(hModule))
	{
		VS_FIXEDFILEINFO vsffi = fvi.GetVSFFI();

		if(vsffi.dwFileType == VFT_DLL ||
			vsffi.dwFileType == VFT_STATIC_LIB)
		{
			switch(vsffi.dwFileOS)
			{
			case VOS__WINDOWS32:
			case VOS_NT_WINDOWS32:
				{
					lpDVI->dwPlatformID = DLLVER_PLATFORM_WINDOWS;
					break;
				}
			case VOS_NT:
				{
					lpDVI->dwPlatformID = DLLVER_PLATFORM_NT;
					break;
				}
			default:
				{
					return (S_FALSE);
				}
			}

			lpDVI->dwMajorVersion = HIWORD(vsffi.dwFileVersionMS);
			lpDVI->dwMinorVersion = LOWORD(vsffi.dwFileVersionMS);
			lpDVI->dwBuildNumber  = HIWORD(vsffi.dwFileVersionLS);

#ifdef DLLVERSIONINFO2

			if(cbSize == sizeof(DLLVERSIONINFO2))
			{
				DLLVERSIONINFO2* lpDVI2 = (DLLVERSIONINFO2*)lpDVI;
				lpDVI2->ullVersion = MAKEDLLVERULL(
					lpDVI->dwMajorVersion,
					lpDVI->dwMinorVersion,
					lpDVI->dwBuildNumber,
					LOWORD(vsffi.dwFileVersionLS)
					);
			}

#endif

			return (S_OK);
		}
#ifdef _DEBUG
		else
		{
			ASSERT(0);
		}
#endif
		fvi.Close();
	}
	return (S_FALSE);
}

/*-------------------------------------------------------------------------------------
Function       : CFileVersionInfo
In Parameters  : void
Out Parameters : CFileVersionInfo
Purpose		   : Constructs a CFileVersionInfo object:
Author		   :  Anand
-------------------------------------------------------------------------------------*/
CFileVersionInfo::CFileVersionInfo(void) : m_lpbyVIB(NULL)
{
	Close();
}

/*-------------------------------------------------------------------------------------
Function       : ~CFileVersionInfo
Purpose		   : Destructor for class CFileVersionInfo
Author		   :  Anand
-------------------------------------------------------------------------------------*/
CFileVersionInfo::~CFileVersionInfo(void)
{
	Close();
}

/*-------------------------------------------------------------------------------------
Structure      : s_ppszStr
-------------------------------------------------------------------------------------*/
LPCTSTR CFileVersionInfo::s_ppszStr[] = {	_T("Comments"), _T("CompanyName"),
											_T("FileDescription"), _T("FileVersion"),
											_T("InternalName"), _T("LegalCopyright"),
											_T("LegalTrademarks"), _T("OriginalFilename"),
											_T("PrivateBuild"), _T("ProductName"),
											_T("ProductVersion"), _T("SpecialBuild"),
											_T("OLESelfRegister")};

/*-------------------------------------------------------------------------------------
Function       : Open
In Parameters  : IN HINSTANCE hInstance
Out Parameters : BOOL
Purpose		   : Opens the file version information by its handle specified in hModule.
Author		   :  Anand
-------------------------------------------------------------------------------------*/
BOOL CFileVersionInfo::Open(IN HINSTANCE hInstance)
{
	if(hInstance == NULL)
	{
		ASSERT_RETURN (FALSE);
	}

	TCHAR szFileName[ MAX_PATH]={0 };
	if(::GetModuleFileName(hInstance, szFileName, MAX_PATH))
	{
		return Open(szFileName);
	}
	return FALSE;
};

/*-------------------------------------------------------------------------------------
Function       : Open
In Parameters  : IN LPCTSTR lpszFileName
Out Parameters : BOOL
Purpose		   : Opens the file version information by its name specified in lpszFileName.
Author		   :  Anand
-------------------------------------------------------------------------------------*/
BOOL CFileVersionInfo::Open(IN LPCTSTR lpszFileName)
{
	if(lpszFileName == NULL)
	{
		ASSERT_RETURN (FALSE);
	}

	Close();
	if(!GetVersionInfo(lpszFileName) || !QueryVersionTrans())
	{
		Close();
	}

	return m_bValid;
};


/*-------------------------------------------------------------------------------------
Function       : GetVersionInfo
In Parameters  : IN LPCTSTR lpszFileName
Out Parameters : BOOL
Purpose		   : This function determines whether the operating system can retrieve 
				version information for a specified file. If version information is 
				available, GetFileVersionInfoSize returns the size, in bytes, of that information.
Author		   :  Anand
-------------------------------------------------------------------------------------*/
BOOL CFileVersionInfo::GetVersionInfo(IN LPCTSTR lpszFileName)
{
	// Version: 1.0.0.1
	if(false == Is3264BitApp(lpszFileName))
	{
		return (FALSE);
	}

	DWORD dwDummy = 0;
	DWORD dwSize  = ::GetFileVersionInfoSize(const_cast< LPTSTR >(lpszFileName),
											&dwDummy // Set to 0
											);

	if(dwSize > 0)
	{
		m_lpbyVIB = (LPBYTE)malloc(dwSize);
		if(m_lpbyVIB != NULL &&
			::GetFileVersionInfo(const_cast< LPTSTR >(lpszFileName),
			0, dwSize, m_lpbyVIB))
		{
			UINT   uLen    = 0;
			LPVOID lpVSFFI = NULL;
			if(::VerQueryValue(m_lpbyVIB, _T("\\"), (LPVOID*)&lpVSFFI, &uLen))
			{
				::CopyMemory(&m_vsffi, lpVSFFI, sizeof(VS_FIXEDFILEINFO));
				m_bValid =(m_vsffi.dwSignature == VS_FFI_SIGNATURE);
			}
		}
	}
	return m_bValid;
}

/*-------------------------------------------------------------------------------------
Function       : QueryVersionTrans
In Parameters  : void
Out Parameters : BOOL
Purpose		   :
Author		   :  Anand
-------------------------------------------------------------------------------------*/
BOOL CFileVersionInfo::QueryVersionTrans(void)
{
	if(m_bValid == FALSE)
	{
		ASSERT_RETURN (FALSE);
	}

	UINT   uLen  = 0;
	LPVOID lpBuf = NULL;

	if(::VerQueryValue(m_lpbyVIB, _T("\\VarFileInfo\\Translation"), (LPVOID*)&lpBuf, &uLen))
	{
		m_lpdwTrans = (LPDWORD)lpBuf;
		m_nTransCnt =(uLen / sizeof(DWORD));
	}
	return (BOOL)(m_lpdwTrans != NULL);
}


/*-------------------------------------------------------------------------------------
Function       : Close
In Parameters  : void
Out Parameters : void
Purpose		   : Closes the specified module and frees the resources, loaded by Open method(s).
Author		   :  Anand
-------------------------------------------------------------------------------------*/
void CFileVersionInfo::Close(void)
{
	m_nTransCnt  = 0;
	m_nTransCur  = 0;
	m_bValid	 = FALSE;
	m_lpdwTrans  = NULL;

	::ZeroMemory(&m_vsffi, sizeof(VS_FIXEDFILEINFO));
	if(m_lpbyVIB)
	{
		_free(m_lpbyVIB);
	}
}

/*-------------------------------------------------------------------------------------
Function       : QueryStringValue
In Parameters  : IN  LPCTSTR lpszItem,
				 OUT LPTSTR  lpszValue,
				 IN  INT     nBuf
Out Parameters : BOOL
Purpose		   :  Retrieves a value in a StringTable structure, and returns it in the
					nBuf size lpszValue buffer.The lpszString name must be one of the
					predefined strings, enumerated in the next function description.
					For example: m_ver.QueryStringValue(_T("Comments"), szBuf, 512);.
Author		   :  Anand
-------------------------------------------------------------------------------------*/
BOOL CFileVersionInfo::QueryStringValue(IN  LPCTSTR lpszItem, OUT LPTSTR  lpszValue, 
										IN  INT     nBuf) const
{
	//strcpy(lpszItem,"CompanyName");
	if(m_bValid  == FALSE || lpszItem == NULL)
	{
		ASSERT_RETURN (FALSE);
	}

	if(lpszValue != NULL && nBuf <= 0)
	{
		ASSERT_RETURN (FALSE);
	}

	::ZeroMemory(lpszValue, nBuf * sizeof(TCHAR));

	TCHAR szSFI[ MAX_PATH]={0 };
	swprintf_s(szSFI, _countof(szSFI), _T("\\StringFileInfo\\%04X%04X\\%s"),
				GetCurLID(), GetCurCP(), lpszItem);

	BOOL   bRes    = FALSE;
	UINT   uLen    = 0;
	LPTSTR lpszBuf = NULL;

	if(::VerQueryValue(m_lpbyVIB, (LPTSTR)szSFI, (LPVOID*)&lpszBuf, &uLen))
	{
		if(lpszValue != NULL && nBuf > 0)
		{
			bRes = (BOOL)(::lstrcpyn(lpszValue, lpszBuf, nBuf) != NULL);
		}
		else
		{
			bRes = TRUE;
		}
	}
	return (bRes);
}


/*-------------------------------------------------------------------------------------
Function       : QueryStringValue
In Parameters  : IN  INT    nIndex,
				 OUT LPTSTR lpszValue,
				 IN  INT    nBuf
Out Parameters : BOOL
Purpose		   : Retrieves a value in a StringTable structure, and returns it in the nBuf size
				lpszValue buffer.The nIndex name must be one of the following predefined constants:
					VI_STR_COMMENTS - Comments
					VI_STR_COMPANYNAME - CompanyName
					VI_STR_FILEDESCRIPTION - FileDescription
					VI_STR_FILEVERSION - FileVersion
					VI_STR_INTERNALNAME - InternalName
					VI_STR_LEGALCOPYRIGHT - LegalCopyright
					VI_STR_LEGALTRADEMARKS - LegalTrademarks
					VI_STR_ORIGINALFILENAME - OriginalFilename
					VI_STR_PRIVATEBUILD - PrivateBuild
					VI_STR_PRODUCTNAME - ProductName
					VI_STR_PRODUCTVERSION - ProductVersion
					VI_STR_SPECIALBUILD - SpecialBuild
					VI_STR_OLESELFREGISTER - OLESelfRegister
For example: m_ver.QueryStringValue(VI_STR_SPECIALBUILD, szBuf, 512);
Author		   :  Anand
-------------------------------------------------------------------------------------*/
BOOL CFileVersionInfo::QueryStringValue(IN INT nIndex, OUT LPTSTR lpszValue, IN INT nBuf) const
{
	if(nIndex < VI_STR_COMMENTS || nIndex > VI_STR_OLESELFREGISTER)
	{
		ASSERT_RETURN (FALSE);
	}
	return QueryStringValue(s_ppszStr[ nIndex], lpszValue, nBuf);
}

/*-------------------------------------------------------------------------------------
Function       : GetVerStringName
In Parameters  : IN INT nIndex
Out Parameters : LPCTSTR
Purpose		   : Returns the version string name for the nIndex parameter from the array
				- the class holds a static array of version information strings, 
				each value of which can be accessed by index. 
				For example: 
				m_ver.GetVerStringName(VI_STR_PRODUCTNAME)
				will return a pointer to _T("ProductName")string.
Author		   :  Anand
-------------------------------------------------------------------------------------*/
LPCTSTR CFileVersionInfo::GetVerStringName(IN INT nIndex)
{
	if(nIndex < VI_STR_COMMENTS || nIndex > VI_STR_OLESELFREGISTER)
	{
		ASSERT_RETURN (FALSE);
	}
	return (LPCTSTR)s_ppszStr[ nIndex];
}

/*-------------------------------------------------------------------------------------
Function       : FindTrans
In Parameters  : IN LANGID wLID,
IN WORD   wCP
Out Parameters : INT
Purpose		   : Finds the translation (the Language Identifier and Code Page)in the the version
				information data, if any.
Author		   :  Anand
-------------------------------------------------------------------------------------*/
INT CFileVersionInfo::FindTrans(IN LANGID wLID,
								IN WORD   wCP)const
{
	if(m_bValid == FALSE)
	{
		ASSERT_RETURN (-1);
	}

	for(UINT n = 0; n < m_nTransCnt; n++)
	{
		if(LOWORD(m_lpdwTrans[ n])== wLID && HIWORD(m_lpdwTrans[ n])== wCP )
		{
			return n;
		}
	}
	return -1;
}

/*-------------------------------------------------------------------------------------
Function       : SetTrans
In Parameters  : IN LANGID wLID,
IN WORD   wCP
Out Parameters : BOOL
Purpose		   :  Sets the Language Identifier and Code Page to use in the version 
					information data (if any).
Author		   :  Anand
-------------------------------------------------------------------------------------*/
BOOL CFileVersionInfo::SetTrans(IN LANGID wLID /*LANG_NEUTRAL*/, IN WORD  wCP  /*WSLVI_CP_UNICODE*/)
{
	if(m_bValid == FALSE)
	{
		ASSERT_RETURN (FALSE);
	}

	if(GetCurLID()== wLID && GetCurCP()== wCP)
	{
		return TRUE;
	}

	INT nPos = FindTrans(wLID, wCP);
	if(nPos != -1)
	{
		m_nTransCur = nPos;
	}

	return (m_nTransCur == (UINT)nPos);
}

/*-------------------------------------------------------------------------------------
Function       : GetTransByIndex
In Parameters  : IN UINT nIndex
Out Parameters : DWORD
Purpose		   : Extracts the translation (the Language Identifier and Code Page) at
				the specified index in the translation array (if any).
Author		   :  Anand
-------------------------------------------------------------------------------------*/
DWORD CFileVersionInfo::GetTransByIndex(IN UINT nIndex)const
{
	if(m_bValid == FALSE || nIndex < 0 || nIndex > m_nTransCnt)
	{
		ASSERT_RETURN (0);
	}
	return m_lpdwTrans[ nIndex];
}


/*-------------------------------------------------------------------------------------
Function       : SetTransIndex
In Parameters  : IN UINT nIndex
Out Parameters : BOOL
Purpose		   : Sets the translation to use in the version information data by index (if any).
Author		   :  Anand
-------------------------------------------------------------------------------------*/
BOOL CFileVersionInfo::SetTransIndex(IN UINT nIndex /*0*/)
{
	if(m_bValid == FALSE)
	{
		ASSERT_RETURN (FALSE);
	}

	if(m_nTransCur == nIndex)
	{
		return TRUE;
	}

	if(nIndex >= 0 && nIndex <= m_nTransCnt)
	{
		m_nTransCur = nIndex;
	}

	return (m_nTransCur == nIndex);
}


/*-------------------------------------------------------------------------------------
Function       : GetLIDName
In Parameters  : IN  WORD   wLID,
				OUT LPTSTR lpszName,
				IN  INT    nBuf
Out Parameters : BOOL
Purpose		   : Retrieves a description string for the wLID language identifier and 
				returns it in the lpszName buffer of nBuf size. (Static member)If the 
				LID identifier is unknown, it returns a default string ("Language Neutral"):
Author		   :  Anand
-------------------------------------------------------------------------------------*/
BOOL CFileVersionInfo::GetLIDName(IN  WORD   wLID, OUT LPTSTR lpszName, IN  INT    nBuf)
{
	if(lpszName == NULL || nBuf <= 0)
	{
		ASSERT_RETURN (FALSE);
	}

	return (BOOL)::VerLanguageName(wLID, lpszName, nBuf);
}


/*-------------------------------------------------------------------------------------
Function       : GetCPName
In Parameters  : IN  WORD wCP,
				OUT LPCTSTR* ppszName
				Out Parameters : BOOL
Purpose		   : Retrieves a description string for the wCP code page identifier and 
				returns it in the lpszName buffer of nBuf size.
				 If the CP identifier is unknown, it returns a default string ("Unknown"):
Author		   :  Anand
-------------------------------------------------------------------------------------*/
BOOL CFileVersionInfo::GetCPName(IN  WORD wCP, OUT LPCTSTR* ppszName)
{
	if(ppszName == NULL)
	{
		ASSERT_RETURN (FALSE);
	}

	BOOL bRes = TRUE;
	*ppszName  = NULL;
	switch(wCP)
	{
	case VI_CP_ASCII:
		{
			*ppszName = _T("7-bit ASCII");
			break;
		}
	case VI_CP_JAPAN:
		{
			*ppszName = _T("Japan (Shift – JIS X-0208)");
			break;
		}
	case VI_CP_KOREA:
		{
			*ppszName = _T("Korea (Shift – KSC 5601)");
			break;
		}
	case VI_CP_TAIWAN:
		{
			*ppszName = _T("Taiwan (Big5)");
			break;
		}
	case VI_CP_UNICODE:
		{
			*ppszName = _T("Unicode");
			break;
		}
	case VI_CP_LATIN2:
		{
			*ppszName = _T("Latin-2 (Eastern European)");
			break;
		}
	case VI_CP_CYRILLIC:
		{
			*ppszName = _T("Cyrillic");
			break;
		}
	case VI_CP_MULTILNG:
		{
			*ppszName = _T("Multilingual");
			break;
		}
	case VI_CP_GREEK:
		{
			*ppszName = _T("Greek");
			break;
		}
	case VI_CP_TURKISH:
		{
			*ppszName = _T("Turkish");
			break;
		}
	case VI_CP_HEBREW:
		{
			*ppszName = _T("Hebrew");
			break;
		}
	case VI_CP_ARABIC:
		{
			*ppszName = _T("Arabic");
			break;
		}
	default:
		{
			*ppszName = _T("Unknown");
			bRes = FALSE;
			break;
		}
	}
	return bRes;
}

/*-------------------------------------------------------------------------------------
Function       : Is3264BitApp
In Parameters  : IN LPCTSTR szFileName: name of the file to check if its 32 | 64 bit app
Out Parameters : BOOL
Purpose		   : checks and returns true if the file is 32|64 bit, else false
Author		   : Anand
-------------------------------------------------------------------------------------*/
bool CFileVersionInfo::Is3264BitApp(LPCTSTR szFileName)
{
	HANDLE hFile = 0;
	DWORD dwReadData = 0, dwBytesRead = 0;

	hFile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL, 0);

	if(INVALID_HANDLE_VALUE == hFile)
	{
		return (false);
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, 0x3C, 0, FILE_BEGIN))
	{
		CloseHandle(hFile);
		return (false);
	}

	if(FALSE == ReadFile(hFile, &dwReadData, sizeof(dwReadData), &dwBytesRead, 0))
	{
		CloseHandle(hFile);
		return (false);
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, dwReadData, 0, FILE_BEGIN))
	{
		CloseHandle(hFile);
		return (false);
	}

	if(FALSE == ReadFile(hFile, &dwReadData, sizeof(dwReadData), &dwBytesRead, 0))
	{
		CloseHandle(hFile);
		return (false);
	}

	if(dwReadData != 0x00004550)
	{
		CloseHandle(hFile);
		return (false);
	}

	if(FALSE == ReadFile(hFile, &dwReadData, sizeof(dwReadData), &dwBytesRead, 0))
	{
		CloseHandle(hFile);
		return (false);
	}

	CloseHandle(hFile);
	return ((0x014C == LOWORD(dwReadData)) ||(0x8664 == LOWORD(dwReadData)));
}

/*-------------------------------------------------------------------------------------
Function		: ReplaceFileOnRestart
In Parameters	: TCHAR const * szExistingFileName, TCHAR const * szNewFileName
Out Parameters	: bool : true(Successful)/false
Purpose			:   This function makes an entry in the registry for a file to be
deleted or replaced by an existing file at the machine restart.
This is used to handle files which cant be then deleted because they are in use.
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CFileVersionInfo::ReplaceFileOnRestart(TCHAR const * szExistingFileName, 
											TCHAR const * szNewFileName)
{
	CRegistry objReg;
	CStringArray arrData;
	CString Key = _T("SYSTEM\\CurrentControlSet\\Control\\Session Manager");
	CString Value = _T("PendingFileRenameOperations2");

	objReg.Get(Key, Value, arrData, HKEY_LOCAL_MACHINE);

	arrData.Add(CString(_T("\\??\\")) + szExistingFileName);
	if(szNewFileName)
	{
		arrData.Add(CString(_T("!\\??\\")) + szNewFileName);
	}

	objReg.Set(Key, Value, arrData, HKEY_LOCAL_MACHINE);
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetProductName
In Parameters  : LPCTSTR lpszFileName, LPTSTR lpszProductName, 
Out Parameters : bool 
Description    : 
Author         : Sandip
--------------------------------------------------------------------------------------*/
bool CFileVersionInfo::GetProductName(LPCTSTR lpszFileName, LPTSTR lpszProductName)
{
	if(!lpszProductName)
		return false;

	if(Open( lpszFileName ) == FALSE)
		return false;

	return (QueryStringValue(9, lpszProductName, MAX_PATH)?true:false);
}
