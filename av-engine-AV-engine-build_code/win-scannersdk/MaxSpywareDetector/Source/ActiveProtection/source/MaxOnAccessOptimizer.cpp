#include "pch.h"
#include "MaxOnAccessOptimizer.h"

CMaxOnAccessOptimizer::CMaxOnAccessOptimizer(void)
{
	memset(&m_byHeaderBuff[0x00],0x00,sizeof(m_byHeaderBuff));
}

CMaxOnAccessOptimizer::~CMaxOnAccessOptimizer(void)
{
}

BOOL CMaxOnAccessOptimizer::GetFileHeaderBuff(LPCTSTR pszFileAccess)
{
	BOOL	bRetValue = FALSE;

	if (pszFileAccess == NULL)
	{
		return bRetValue;
	}

	FILE	*fpInFile = NULL;

	fpInFile = _wfopen(pszFileAccess,L"rb");
	if (fpInFile == NULL)
	{
		return bRetValue;
	}
	memset(&m_byHeaderBuff[0x00],0x00,sizeof(m_byHeaderBuff));
	
	DWORD	dwBytesRead = 0x00;

	dwBytesRead = fread(&m_byHeaderBuff[0x00],0x01,0x50,fpInFile);
	fclose(fpInFile);
	fpInFile = NULL;

	//if (dwBytesRead == 0x50 || dwBytesRead == 0x44)
	if (dwBytesRead > 0x40)
	{
		bRetValue = TRUE;
	}

	return bRetValue;
}

BOOL CMaxOnAccessOptimizer::CheckForFileType()
{
	BOOL	bRetValue = FALSE;
	BYTE	bPESig[] = {0x4D, 0x5A};
	BYTE	bWMASig[] = {0x30,0x26,0xB2,0x75,0x8E,0x66,0xCF,0x11,0xA6,0xD9,0x00,0xAA,0x00,0x62,0xCE,0x6C};
	BYTE	bOLESig[] = {0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1};
	BYTE	szSISHeader[] = {0x12, 0x3A, 0x00, 0x10};
	BYTE	szSISDllHeader[] = {0x79, 0x00, 0x00, 0x10};
	BYTE	szSISExeHeader[] = {0x7A, 0x00, 0x00, 0x10};
	BYTE	bRTFSig[5] = {0x7B, 0x5C, 0x72, 0x74, 0x66};
	BYTE    bstRiffFileFormID[] = {0x41,0x43, 0x4F,0x4E};
	BYTE	bstRiffFileFileID[] = {0x52, 0x49, 0x46, 0x46};
	BYTE	bELFSig[]		= {0x7F, 0x45, 0x4C, 0x46};
	BYTE	bRegSigV4[] = {0x52, 0x45, 0x47, 0x45, 0x44, 0x49, 0x54, 0x34}; 
	BYTE	bRegSig[] = {0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x52, 0x00, 0x65, 0x00, 0x67, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 0x00, 0x72, 0x00, 0x79, 0x00, 0x20, 0x00, 0x45, 0x00, 0x64, 0x00, 0x69, 0x00, 0x74, 0x00};
	BYTE	bMaxEMLSig[]	= {0x7b, 0x37, 0x39, 0x39, 0x35, 0x33, 0x39, 0x45, 0x35, 0x2d, 0x45, 0x44, 0x43, 0x45, 0x2d, 0x34, 0x35, 0x36, 0x35, 0x2d, 0x39, 0x41, 0x36, 0x32, 0x2d, 0x31, 0x45, 0x39, 0x35, 0x37, 0x46, 0x30, 0x41, 0x30, 0x46, 0x38, 0x34, 0x7d};	//{799539E5-EDCE-4565-9A62-1E957F0A0F84}
	BYTE	bJCLASSSig[] = {0xCA, 0xFE, 0xBA, 0xBE};
	BYTE	bMSCHMSig[] 	= {0x49,0x54,0x53,0x46};
	BYTE	bMSSZDDSig[]	= {0x53, 0x5A,0x44,0x44};
	BYTE	bCryptCFFSig[]	= {0xB6, 0xB9, 0xAC, 0xAE};
	BYTE	bMSCABSig[] 	= {0x4D,0x53,0x43,0x46};
	BYTE	bRARSig[]		= {0x52, 0x61, 0x72, 0x21};
	BYTE	bZIPSig[]		= {0x50, 0x4B, 0x03, 0x04};
	BYTE	bZIPSig_1[] 	= {0x50, 0x4B, 0x30, 0x30, 0x50, 0x4B, 0x03, 0x04};
	BYTE	bGZipSig[]		= {0x1F, 0x8B};
	BYTE	b7zSig[]		= {0x37, 0x7A, 0xBC, 0xAF};
	BYTE	bMAC_O_32_LE[] = {0xCE, 0xFA, 0xED, 0xFE}; //Mac 32 Bit Little Endian
	BYTE	bMAC_O_64_LE[] = {0xCF, 0xFA, 0xED, 0xFE}; //Mac 64 Bit Little Endian
	BYTE	bMAC_O_32_BE[] = {0xFE, 0xED, 0xFA, 0xCE}; //Mac 32 Bit Big Endian
	BYTE	bMAC_O_64_BE[] = {0xFE, 0xED, 0xFA, 0xCF}; //Mac 64 Bit Big Endian

	BYTE	bUBSig_Class_1[]		= {0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x03};
	BYTE	bUBSig_Class_2[]		= {0xBE, 0xBA, 0xFE, 0xCA, 0x00, 0x03};

	BYTE	bIOS_DEB[] = {0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E, 0x0A, 0x64, 0x65, 0x62, 0x69, 0x61, 0x6E, 0x2D, 0x62, 0x69, 0x6E, 0x61, 0x72, 0x79}; //IOS deb files
	BYTE	bUBSig_1[]		= {0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00};
	BYTE	bUBSig_2[]		= {0xBE, 0xBA, 0xFE, 0xCA, 0x00, 0x00};
	BYTE	bMSISig[]		= {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};

	BYTE	bEichar[] = {0x58, 0x35, 0x4F, 0x21, 0x50, 0x25, 0x40, 0x41, 0x50, 0x5B, 0x34};

	if (memcmp(&m_byHeaderBuff[0x00], &bPESig[0], sizeof(bPESig)) == 0)
	{
		return TRUE;
	}
	if (memcmp(&m_byHeaderBuff[0x00], &bWMASig[0], sizeof(bWMASig)) == 0)
	{
		return TRUE;
	}
	if (memcmp(&m_byHeaderBuff[0x00], &bOLESig[0], sizeof(bOLESig)) == 0)
	{
		return TRUE;
	}

	/*--------------- EICHAR Test File Type ------------------*/
	if (memcmp(&m_byHeaderBuff[0x00], &bEichar[0], sizeof(bEichar)) == 0)
	{
		return TRUE;
	}
	
	/*--------------- SIS File Type ------------------*/
	if (memcmp(&m_byHeaderBuff[0x00], &szSISExeHeader[0], sizeof(szSISExeHeader)) == 0)
	{
		return TRUE;
	}
	if (memcmp(&m_byHeaderBuff[0x00], &szSISDllHeader[0], sizeof(szSISDllHeader)) == 0)
	{
		return TRUE;
	}
	if (memcmp(&m_byHeaderBuff[0x04], &szSISHeader[0], sizeof(szSISHeader)) == 0)
	{
		return TRUE;
	}
	/*------------------------------------------------*/
	if (memcmp(&m_byHeaderBuff[0x00], &bRTFSig[0], sizeof(bRTFSig)) == 0)
	{
		return TRUE;
	}

	if (memcmp(&m_byHeaderBuff[0x00], &bstRiffFileFileID[0], sizeof(bstRiffFileFileID)) == 0 && memcmp(&m_byHeaderBuff[0x08], &bstRiffFileFormID[0], sizeof(bstRiffFileFormID)) == 0)
	{
		return TRUE;
	}

	if (memcmp(&m_byHeaderBuff[0x00], &bELFSig[0], sizeof(bELFSig)) == 0)
	{
		return TRUE;
	}

	for(int i = 0x00; i < 0x04; i++)
	{
		if ((memcmp(&m_byHeaderBuff[i], &bRegSig[0], sizeof(bRegSig)) == 0) || (memcmp(&m_byHeaderBuff[i], &bRegSigV4[0], sizeof(bRegSigV4)) == 0))
		{
			return TRUE;
		}
	}
	
	if (memcmp(&m_byHeaderBuff[0],bMaxEMLSig,sizeof(bMaxEMLSig)) == 0x00)
	{
		return TRUE;
	}

	if (memcmp(&m_byHeaderBuff[0],bJCLASSSig,sizeof(bJCLASSSig)) == 0x00)
	{
		return TRUE;
	}

	if (memcmp(&m_byHeaderBuff[0],bMSCHMSig,sizeof(bMSCHMSig)) == 0x00)
	{
		return TRUE;
	}

	if (memcmp(&m_byHeaderBuff[0],bMSSZDDSig,sizeof(bMSSZDDSig)) == 0x00)
	{
		return TRUE;
	}
	if (memcmp(&m_byHeaderBuff[0],bMSCABSig,sizeof(bMSCABSig)) == 0x00)
	{
		return TRUE;
	}
	if (memcmp(&m_byHeaderBuff[0],bCryptCFFSig,sizeof(bCryptCFFSig)) == 0x00 && m_byHeaderBuff[0x10] == 0xB2 && m_byHeaderBuff[0x11] == 0xA5)
	{
		return TRUE;
	}

	if (memcmp(&m_byHeaderBuff[0],bRARSig,sizeof(bRARSig)) == 0x00)
	{
		return TRUE;
	}
	if (memcmp(&m_byHeaderBuff[0],bZIPSig,sizeof(bZIPSig)) == 0x00)
	{
		return TRUE;
	}

	if (memcmp(&m_byHeaderBuff[0],bZIPSig_1,sizeof(bZIPSig_1)) == 0x00)
	{
		return TRUE;
	}
	
	if (memcmp(&m_byHeaderBuff[0],bGZipSig,sizeof(bGZipSig)) == 0x00)
	{
		return TRUE;
	}

	if (memcmp(&m_byHeaderBuff[0],b7zSig,sizeof(b7zSig)) == 0x00)
	{
		return TRUE;
	}

	if ( (memcmp(&m_byHeaderBuff[0], bMAC_O_32_BE, sizeof(bMAC_O_32_BE)) == 0x00)
		|| (memcmp(&m_byHeaderBuff[0], bMAC_O_32_LE, sizeof(bMAC_O_32_LE)) == 0x00) 
		|| (memcmp(&m_byHeaderBuff[0], bMAC_O_64_BE, sizeof(bMAC_O_64_BE)) == 0x00)
		|| (memcmp(&m_byHeaderBuff[0], bMAC_O_64_LE, sizeof(bMAC_O_64_LE)) == 0x00))
	{
		return TRUE;
	}

	if (memcmp(&m_byHeaderBuff[0], bUBSig_Class_1, sizeof(bUBSig_Class_1)) == 0x00 || memcmp(&m_byHeaderBuff[0], bUBSig_Class_2, sizeof(bUBSig_Class_2)) == 0x00)
	{
		return TRUE;
	}

	if (memcmp(&m_byHeaderBuff[0], bIOS_DEB, sizeof(bIOS_DEB)) == 0x00)
	{
		return TRUE;
	}

	if (memcmp(&m_byHeaderBuff[0], bUBSig_1, sizeof(bUBSig_1)) == 0x00 || memcmp(&m_byHeaderBuff[0], bUBSig_2, sizeof(bUBSig_2)) == 0x00)
	{
		return TRUE;
	}

	if (memcmp(&m_byHeaderBuff[0],bMSISig,sizeof(bMSISig)) == 0x00)
	{
		return TRUE;
	}

	return bRetValue;
}

BOOL CMaxOnAccessOptimizer::CheckProcessRule(LPCTSTR pszFileAccess, LPCTSTR pszProcessName)
{
	BOOL	bRetValue = FALSE;

	if (pszProcessName == NULL || pszFileAccess == NULL)
	{
		return FALSE;
	}

	if (_tcsstr(pszProcessName,L":\\program files") != NULL)
	{
		return TRUE;
	}

	if (_tcsstr(pszProcessName,L"dllhost.exe") != NULL)
	{
		return TRUE;
	}

	TCHAR	szExt[MAX_PATH] = {0x00},*pTemp = NULL;

	pTemp = _tcsrchr((TCHAR *)pszFileAccess,L'.');
	if (pTemp != NULL)
	{
		if (_tcslen(pTemp) < MAX_PATH)
		{
			_tcscpy(szExt,pTemp);
			_tcslwr(szExt);
			if (_tcsstr(L".xls.doc.pdf.xlsx.docx.ppt.pptx.manifest.config.drv.cs.etl.ps1.psm1.winmd.dat.sqlite.sqlite-shm.sqlite-wal.pri.~tmp.mui.evtx.pf.out.err",szExt) != NULL)
			{
				return TRUE;
			}
		}
	}

	return bRetValue;
}

BOOL CMaxOnAccessOptimizer::CheckSkipExt(LPCTSTR pszFileAccess)
{
	BOOL	bRetValue = FALSE;
	TCHAR	*pTemp = NULL;
	TCHAR	szExt2Check[] = {L".aamdownload,aamdownload.aamd,.manifest,.config,.drv,.pf,.out,.err"};

	if (pszFileAccess == NULL)
	{
		return bRetValue;
	}

	pTemp = _tcsrchr((TCHAR *)pszFileAccess,'.');
	if (pTemp == NULL)
	{
		return bRetValue;
	}

	if (_tcsstr(szExt2Check,pTemp) != NULL)
	{
		return TRUE;
	}

	return bRetValue;
}


BOOL CMaxOnAccessOptimizer::CheckKnownExt(LPCTSTR pszFileAccess)
{
	BOOL	bRetValue = FALSE;
	//TCHAR	szAccessedFile[1024] = {0x00};
	TCHAR	*pTemp = NULL;
	TCHAR	szExt2Check[] = {L".vb,.vbe,.vbs,.vbscript,.ws,.wsf,.wsh,.ksh,.js,.jse,.csh,.phs,.jsx,.html,.asp,.jsp,.aspx,.scpt,.htm,.dmg,.bat,.inf,.rgs,.com"};

	if (pszFileAccess == NULL)
	{
		return bRetValue;
	}

	pTemp = _tcsrchr((TCHAR *)pszFileAccess,'.');
	if (pTemp == NULL)
	{
		return bRetValue;
	}

	if (_tcsstr(szExt2Check,pTemp) != NULL)
	{
		return TRUE;
	}

	return bRetValue;
}

//TRUE ==> Skip
//FALSE ==> Send For Scanning
BOOL CMaxOnAccessOptimizer::SkipFileScanning(LPCTSTR pszFileAccess, LPCTSTR	pszProcessPath)
{
	BOOL	bRetValue = TRUE;

	if (pszFileAccess != NULL && pszProcessPath != NULL)
	{
		if (_tcsstr(pszFileAccess,L"\\winsxs\\") != NULL || _tcsstr(pszProcessPath,L"\\winsxs\\") != NULL)
		{
			return bRetValue;
		}
		//Added to skip Microsoft Store Apps
		if (_tcsstr(pszFileAccess,L"\\windowsapps\\") != NULL || _tcsstr(pszProcessPath,L"\\windowsapps\\") != NULL)
		{
			return bRetValue;
		}
		//Added to skip Microsoft Store Apps
		if (_tcsstr(pszFileAccess,L"\\winmetadata\\") != NULL || _tcsstr(pszProcessPath,L"\\winmetadata\\") != NULL)
		{
			return bRetValue;
		}
		//Added to skip Microsoft Store Apps
		if (_tcsstr(pszFileAccess,L"\\local\\packages\\microsoft.") != NULL || _tcsstr(pszProcessPath,L"\\local\\packages\\microsoft.") != NULL)
		{
			return bRetValue;
		}
		
		if (_tcsstr(pszFileAccess,L".net\\assembly\\") != NULL || _tcsstr(pszProcessPath,L".net\\assembly\\") != NULL)
		{
			return bRetValue;
		}
		if (_tcsstr(pszFileAccess,L".net\\framework") != NULL || _tcsstr(pszProcessPath,L".net\\framework") != NULL)
		{
			return bRetValue;
		}
		if (_tcsstr(pszFileAccess,L"system32\\oobe") != NULL || _tcsstr(pszProcessPath,L"system32\\oobe") != NULL)
		{
			return bRetValue;
		}
		if (_tcsstr(pszFileAccess,L"\\windowspowershell\\") != NULL || _tcsstr(pszProcessPath,L"\\windowspowershell\\") != NULL)
		{
			return bRetValue;
		}
		if (_tcsstr(pszFileAccess,L"\\microsoft\\onedrive\\") != NULL || _tcsstr(pszProcessPath,L"\\microsoft\\onedrive\\") != NULL)
		{
			return bRetValue;
		}
		if (_tcsstr(pszFileAccess,L"\\automaticdestinations\\") != NULL || _tcsstr(pszProcessPath,L"\\automaticdestinations\\") != NULL)
		{
			return bRetValue;
		}
		if (_tcsstr(pszFileAccess,L"\\windows\\setup\\state\\") != NULL || _tcsstr(pszProcessPath,L"\\windows\\setup\\state\\") != NULL)
		{
			return bRetValue;
		}
		if (_tcsstr(pszFileAccess,L"\\apprepository\\") != NULL || _tcsstr(pszProcessPath,L"\\apprepository\\") != NULL)
		{
			return bRetValue;
		}
		if (_tcsstr(pszFileAccess,L"\\system32\\catroot2\\") != NULL || _tcsstr(pszProcessPath,L"\\system32\\catroot2\\") != NULL)
		{
			return bRetValue;
		}
		if (_tcsstr(pszFileAccess,L"\\thumbcache_") != NULL || _tcsstr(pszProcessPath,L"\\thumbcache_") != NULL)
		{
			return bRetValue;
		}
		if (_tcsstr(pszFileAccess,L"\\iconcache_") != NULL || _tcsstr(pszProcessPath,L"\\iconcache_") != NULL)
		{
			return bRetValue;
		}
		if (_tcsstr(pszFileAccess,L"\\windows\\prefetch\\") != NULL || _tcsstr(pszProcessPath,L"\\windows\\prefetch\\") != NULL)
		{
			return bRetValue;
		}
		if (_tcsstr(pszFileAccess,L"\\temp\\expression_host_") != NULL || _tcsstr(pszProcessPath,L"\\temp\\expression_host_") != NULL)
		{
			return bRetValue;
		}
	}

	if (_tcsstr(pszProcessPath,L"\\") != NULL)
	{
		if (CheckProcessRule(pszFileAccess,pszProcessPath) == TRUE)
		{
			return TRUE;
		}
	}

	if (CheckSkipExt(pszFileAccess) == TRUE)
	{
		return TRUE;
	}

	if (GetFileHeaderBuff(pszFileAccess) == FALSE)
	{
		return bRetValue;
	}

	if (CheckForFileType() == TRUE)
	{
		return FALSE;
	}

	if (CheckKnownExt(pszFileAccess) == TRUE)
	{
		return FALSE;
	}

	

	return bRetValue;
}

BOOL CMaxOnAccessOptimizer::SkipFileScanningExecute(LPCTSTR	pszProcessPath)
{
	BOOL	bRetValue = TRUE;

	if (pszProcessPath != NULL)
	{
		if (_tcslen(pszProcessPath) == 0x00)
		{
			return bRetValue;
		}

		if (pszProcessPath[_tcslen(pszProcessPath) -1] == L'\\')
		{
			return bRetValue;
		}

		if (_tcsstr(pszProcessPath,L"\\winsxs\\") != NULL)
		{
			return bRetValue;
		}
		//Added to skip Microsoft Store Apps
		if (_tcsstr(pszProcessPath,L"\\windowsapps\\") != NULL)
		{
			return bRetValue;
		}
		//Added to skip Microsoft Store Apps
		if (_tcsstr(pszProcessPath,L"\\winmetadata\\") != NULL)
		{
			return bRetValue;
		}
		//Added to skip Microsoft Store Apps
		if (_tcsstr(pszProcessPath,L"\\local\\packages\\microsoft.") != NULL)
		{
			return bRetValue;
		}
		
		if (_tcsstr(pszProcessPath,L".net\\assembly\\") != NULL)
		{
			return bRetValue;
		}
		if (_tcsstr(pszProcessPath,L".net\\framework") != NULL)
		{
			return bRetValue;
		}
		if (_tcsstr(pszProcessPath,L".net\\framework") != NULL)
		{
			return bRetValue;
		}
		if (_tcsstr(pszProcessPath,L"system32\\oobe") != NULL || _tcsstr(pszProcessPath,L"\\windowspowershell\\") != NULL || _tcsstr(pszProcessPath,L"\\microsoft\\onedrive\\") != NULL)
		{
			return bRetValue;
		}
	}
	
	return FALSE;
}