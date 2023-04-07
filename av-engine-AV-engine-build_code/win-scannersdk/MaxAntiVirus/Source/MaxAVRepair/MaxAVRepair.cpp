/*======================================================================================
FILE             : MaxAVRepair.cpp
ABSTRACT         : This module repaires virus files deteted by AuAVDBScan.dll
DOCUMENTS	     : 
AUTHOR		     : Tushar Kadam + Virus Team
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : June 2010
NOTES		     : This module repaires virus files deteted by AuAVDBScan.dll
				   Contains set of predefine Constants and Repaire routines that can be released in DSVRepaire.db	
VERSION HISTORY  : 
======================================================================================*/

#include "MaxAVRepair.h"
#include "RepairModuls.h"
#include "atlstr.h"
#include "MaxConstant.h"

DWORD RepairFile(CMaxPEFile *pMaxPEFile, LPCTSTR szParam, LPCTSTR szOriginalFilePath = NULL);

BOOL WINAPI DllMain(HINSTANCE hInstDLL,  // handle to DLL module
					DWORD fdwReason,     // reason for calling function
					LPVOID lpReserved )  // reserved
{
	// Perform actions based on the reason for calling.
	switch( fdwReason ) 
	{ 
	case DLL_PROCESS_ATTACH:
		// Initialize once for each new process.
		// Return FALSE to fail DLL load.
		break;

	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;

	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.
		break;

	case DLL_PROCESS_DETACH:
		// Perform any necessary cleanup.
		break;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

/*-------------------------------------------------------------------------------------
	Function		: CleanFile
	In Parameters	: LPCTSTR szFilePath, LPCTSTR szParam
	Out Parameters	: Reapire Status either REAPIR_STATUS_SUCCES or REAPIR_STATUS_FAILURE 
	Purpose			: Exported Function
	Author			: Tushar Kadam
	Description		: This is the DLL entry point function for Repaire infected file
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD CleanFile(LPCTSTR szFilePath, LPCTSTR szParam)
{
	CMaxPEFile objMaxPEFile;
	objMaxPEFile.OpenFile(szFilePath, true);
	return RepairFile(&objMaxPEFile, szParam);
}

/*-------------------------------------------------------------------------------------
	Function		: DBRepairFile
	In Parameters	: LPCTSTR szFilePath, LPCTSTR szParam
	Out Parameters	: Reapire Status either REAPIR_STATUS_SUCCES or REAPIR_STATUS_FAILURE 
	Purpose			: Exported Function
	Author			: Tushar Kadam
	Description		: This is the DLL entry point function for Repaire infected file
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD DBRepairFile(CMaxPEFile *pMaxPEFile, LPCTSTR szParam)
{
	return RepairFile(pMaxPEFile, szParam);
}

/*-------------------------------------------------------------------------------------
	Function		: _DBRepairFile
	In Parameters	: LPCTSTR szFilePath, LPCTSTR szParam, LPCTSTR szOriginalFilePath
	Out Parameters	: Reapire Status either REAPIR_STATUS_SUCCES or REAPIR_STATUS_FAILURE 
	Purpose			: Exported Function
	Author			: Tushar Kadam
	Description		: This is the DLL entry point function for Repaire infected file
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD _DBRepairFile(CMaxPEFile *pMaxPEFile, LPCTSTR szParam, LPCTSTR szOriginalFilePath)
{
	return RepairFile(pMaxPEFile, szParam, _tcslen(szOriginalFilePath) ? szOriginalFilePath : NULL);
}

/*-------------------------------------------------------------------------------------
	Function		: RepairFile
	In Parameters	: LPCTSTR szFilePath, LPCTSTR szParam, LPCTSTR szOriginalFilePath
	Out Parameters	: Reapire Status either REAPIR_STATUS_SUCCES or REAPIR_STATUS_FAILURE 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: This function removes malicious code from infected file
					  or takes neccessry actions	
--------------------------------------------------------------------------------------*/
DWORD RepairFile(CMaxPEFile *pMaxPEFile, LPCTSTR szParam, LPCTSTR szOriginalFilePath/* = NULL*/)
{
	DWORD dwRepairResult = REAPIR_STATUS_FAILURE;
	
	CString csParam = szParam;
	int i = csParam.GetLength();
	if(csParam.GetLength() == 0)
	{
		return dwRepairResult;
	}
	
	CRepairModuls objRepairModuls(pMaxPEFile, (szOriginalFilePath != NULL) ? szOriginalFilePath : pMaxPEFile->m_szFilePath);	
	if(csParam.Find(L"#") == -1 && objRepairModuls.Check4OLEFile())
	{
		objRepairModuls.m_csModParam = csParam;		
		if(objRepairModuls.CleanOLEMacro())
		{
			dwRepairResult = REAPIR_STATUS_SUCCESS;
		}
		return dwRepairResult;
	}
	if(0 == csParam.CompareNoCase(REPAIR_HELP_FILES))
	{
		if(objRepairModuls.CleanHLPFile())
		{
			dwRepairResult = REAPIR_STATUS_SUCCESS;
		}
		return dwRepairResult;
	}

	if(0 == csParam.CompareNoCase(REPAIR_WMA_FILES))
	{
		if(objRepairModuls.CleanWMAFile())
		{
			dwRepairResult = REAPIR_STATUS_SUCCESS;
		}
		return dwRepairResult;
	}
	
	if(0 == csParam.CompareNoCase(REPAIR_LNK_FILES))
	{
		if(objRepairModuls.CleanLNKFile())
		{
			dwRepairResult = REAPIR_STATUS_SUCCESS;
		}
		return dwRepairResult;
	}

	int iVal = 0, iFun = 0;
	char *pHex	= NULL;
	
	CString csFunNo = csParam.Tokenize(_T("#"), iVal);
	objRepairModuls.m_csModParam = csParam.Tokenize(_T("#"), iVal);;

	// Added by Rupali on 06-12-2010 for Script file repair changes
	if( 0 == csFunNo.CompareNoCase(REPAIR_IFRAME_TAG) || 
		0 == csFunNo.CompareNoCase(REPAIR_OBJECT_TAG) || 
		0 == csFunNo.CompareNoCase(REPAIR_EICAR_TAG) || 
		0 == csFunNo.CompareNoCase(REPAIR_PNG_TAG) || 
		0 == csFunNo.CompareNoCase(REPAIR_SCRIPT_TAG))
	{
		iFun = strtol(CStringA(csFunNo), &pHex, 0x10);
		if(objRepairModuls.CleanScriptFile(iFun))
		{
			dwRepairResult = REAPIR_STATUS_SUCCESS;
		}
		return dwRepairResult;
	}
	//End

	if(!objRepairModuls.ReadPeFile() && 0 != csFunNo.CompareNoCase(REPAIR_TTF_FILES))
	{
		return dwRepairResult;
	}	

	CStringA csTok;
	bool bRet = false;

	while(csFunNo != "")
	{
		csTok = csFunNo.Left(2);
		iFun = strtol(csTok, &pHex, 0x10);
				
		csFunNo = csFunNo.Mid(2);
		switch(iFun)
		{
			case 0xFF:
				bRet = objRepairModuls.RepairDelete();
				break;
			case 0xFE: 
				bRet = objRepairModuls.RepairQuarantine();
				break;
			case 0x00: 
				bRet = objRepairModuls.GetParameters();
				break;
			case 0x1:
				bRet = objRepairModuls.RewriteAddressOfEntryPoint();
				break;
			case 0x2:
				bRet = objRepairModuls.TruncateEP();
				break;
			case 0x3:
				bRet = objRepairModuls.CalculateLastSectionDataSize();
				break;
			case 0x4:
				bRet = objRepairModuls.CalculateImageSize();				
				break;
			case 0x5:
				bRet = objRepairModuls.CalculateChecksum();
				break;
			case 0x6:
				bRet = objRepairModuls.RemoveLastSection();
				break;
			case 0xFC:
			case 0x7:
				bRet = objRepairModuls.SetFileEnd();
				break;
			case 0x8:
				bRet = objRepairModuls.FillWithZero();
				break;
			case 0x9:
				bRet = objRepairModuls.ReplaceOriDataDecryption();
				break;
			case 0x0A:
				bRet = objRepairModuls.ReplaceOriginalData();
				break;
			case 0x0B:
				bRet = objRepairModuls.DecryptionSalityFloatXOR();
				break;
			case 0x0C:
				bRet = objRepairModuls.ReadPeFile();
				break;
			case 0x0D:
				bRet = objRepairModuls.WriteDWORD();
				break;
			case 0x0E:
				bRet = objRepairModuls.RepairHidragA();
				break;
			case 0x0F:
				bRet = objRepairModuls.RepairChimeraA();
				break;
			case 0x10:
				bRet = objRepairModuls.RepairDownloaderBL();
				break;
			case 0x11:
				bRet = objRepairModuls.SetFileEndEx();
				break;
			case 0x12:
				{
					// Added check for prepender viruses to skip stub checking here.
					// This change is to avoid modifying all integrated prepender viruses.
					// Once we modify the viruses in panel we can remove this check.
					bool bDoNotDelete = false;
					CString csParamStart = objRepairModuls.m_csModParam.Left(8);
					if(0 == csParamStart.CompareNoCase(L"[FS]-[Y]"))
					{ 
						bDoNotDelete = true;
					}
					// End					
					bRet = objRepairModuls.CheckForVirusStub(bDoNotDelete);
					if (bRet == false)
					{
						objRepairModuls.m_bStubDeleted = true;
					}
					break;
				}
			case 0x13:
				bRet = objRepairModuls.FixResource();
				break;
			case 0x14:
				bRet = objRepairModuls.FixResName();
				break;			
			case 0x15:
				bRet = objRepairModuls.Check4String();
				break;	
			case 0x16:
				bRet = objRepairModuls.SetFileEndWithFileAlignment();
				break;	
			case 0x17:
				bRet = objRepairModuls.DWordXOR();
				break;
			case 0x18:
				bRet = objRepairModuls.ReturnValue();	
				break;
			case 0x19:
				bRet = objRepairModuls.RepairSmallA();
				break;	
				// 1A, 1B and 1C function IDs are for script repair
			case 0x1D:
				bRet = objRepairModuls.RepairXorer();
				break;			
			case 0x1E:
				bRet = objRepairModuls.RepairSectionHeader();
				break;
			case 0x1F:
				bRet = objRepairModuls.RenameFile();
				objRepairModuls.m_bStubDeleted = true;
				break;
			case 0x20:
				bRet = objRepairModuls.DecryptionSalityFloatXOREx();
				break;
			case 0x21:
				bRet = objRepairModuls.ReplaceDataInReadBuffer();
				break;
			case 0x22:
				bRet = objRepairModuls.GetBufferforDecryption();
				break;
			case 0x23: 
				bRet = objRepairModuls.SpecialRepair();
				break;
			case 0x24: 
				bRet = objRepairModuls.RepairOptionalHeader();
				break;
			case 0x25: 
				bRet = objRepairModuls.CalculateSectionAlignment();
				break;
			default:
				bRet = false;
				break;	
		}
		
		if(!bRet || objRepairModuls.m_bStubDeleted)
			break;
	}
	if(objRepairModuls.m_bStubDeleted || bRet) 
	{
		dwRepairResult = REAPIR_STATUS_SUCCESS;
		/*if(!objRepairModuls.m_bStubDeleted && !objRepairModuls.m_objMaxPEFile.ValidateFile())
		{
			dwRepairResult = REAPIR_STATUS_CORRUPT;
		}*/
	}	
	return dwRepairResult;
}
