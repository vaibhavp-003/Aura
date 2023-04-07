/*======================================================================================
   FILE				: ScanManager.cpp
   ABSTRACT			: DB Scan manager
   DOCUMENTS		: 
   AUTHOR			: Tushar Kadam
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 22 Jul 2010
   NOTES			: This module is Part AuAVDBScan Dll. 
   VERSION HISTORY	: 
=====================================================================================*/
#include "pch.h"
#include "ScanManager.h"
 
//This thread is usefull to load database in multi-threading
DWORD WINAPI AndroidDBLoadThread(LPVOID lpParam);

/*-------------------------------------------------------------------------------------
	Function		: CScanManager
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CScanManager::CScanManager(void)
: m_dwTotalSignatures(0),
m_DexS2S(false),m_objMaxRepairVirDB(false)
{
	m_dwTotalInitTime = 0;
	m_dwTotalScanTime = 0;
	m_dwNoOfFilesScanned = 0;
	m_dwTotalSignatures = 0;
	m_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
	m_bIsUSBScan = false;
	m_bIsActMonScan = false;
	m_bIsCryptMonScan = false;
	m_bIsMemoryScan = false;
	CPDFSig::LoadDll();

	_tcscpy(m_szDBPath,L"");
	m_hAndroidDBThread = NULL;
	m_dwAndroidSigCount = 0x00;
	m_bAndroidDBLoaded = FALSE;
	m_bRepairDBLoaded = false;
}

/*-------------------------------------------------------------------------------------
	Function		: CScanManager
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: destructor od ScanManager Class
--------------------------------------------------------------------------------------*/
CScanManager::~CScanManager(void)
{
	if(m_hEvent)
	{
		CloseHandle(m_hEvent);
		m_hEvent = NULL;
	}
	CPDFSig::UnLoadDll();
}

/*-------------------------------------------------------------------------------------
	Function		: CleanupMaxInTemp
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Deletes all the extracted / unpacked files present in Temp folder (Product Temp)
--------------------------------------------------------------------------------------*/
void CScanManager::CleanupMaxInTemp()
{
	TCHAR szFolderPath[MAX_PATH] = {0}, szFilePath[MAX_PATH] = {0};
	DWORD dwRetValue = 0;
	HANDLE hSearch = 0;
	BOOL bMoreFiles = FALSE;
	WIN32_FIND_DATA stFindData = {0};

	dwRetValue = GetTempPath(_countof(szFolderPath), szFolderPath);
	if(0 == dwRetValue || dwRetValue >= _countof(szFolderPath))
	{
		return;
	}

	if(_tcslen(szFolderPath) + 5 >= _countof(szFilePath))
	{
		return;
	}

	_tcscpy_s(szFilePath, _countof(szFilePath), szFolderPath);
	_tcscat_s(szFilePath, _countof(szFilePath), _T("Max\\*"));
	hSearch = FindFirstFile(szFilePath, &stFindData);
	if(INVALID_HANDLE_VALUE == hSearch)
	{
		return;
	}

	do
	{
		if( (!_tcscmp(stFindData.cFileName, L".")) || (!_tcscmp(stFindData.cFileName, L"..")) ||
			((stFindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY))
		{
			continue;
		}

		if(_tcslen(szFolderPath) + _tcslen(stFindData.cFileName) + 4 < _countof(szFilePath))
		{
			_stprintf_s(szFilePath, _countof(szFilePath), _T("%sMax\\%s"), szFolderPath, stFindData.cFileName);
			DeleteFile(szFilePath);
		}
	}while(FindNextFile(hSearch, &stFindData));

	FindClose(hSearch);
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: LoadSignatureDB
	In Parameters	: DataBase Path
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Loads the Virus Database from given path
--------------------------------------------------------------------------------------*/
int CScanManager::LoadSignatureDB(LPCTSTR szDBPath)
{
	USES_CONVERSION;
	DWORD dwStartTime = GetTickCount();

	char	szTemp[MAX_SZ_LEN] = {0};
	TCHAR	szLogLine[MAX_SZ_LEN] = {0x00};
	DWORD dwRet = 0;

	CleanupMaxInTemp();

	_tcscpy(m_szDBPath,szDBPath); 

	if(m_bIsCryptMonScan == true)
	{
		dwRet = m_DigiScanTree.LoadSignatureDB(szDBPath,VIRUS_DB_DIGI_SIG);
		if(dwRet >1)
		{
			m_dwTotalSignatures = m_dwTotalSignatures + (dwRet -1);
		}
		return m_dwTotalSignatures;
	}


	dwRet = m_FileInfectorTree.LoadSignatureDB(szDBPath, VIRUS_DB_PE_SIG);
	if (dwRet > 1)
	{
		m_dwTotalSignatures = m_dwTotalSignatures + (dwRet -1);
	}
	/*Added to Handle VB Signatures*/
	dwRet = m_VBPETree.LoadSignatureDB(szDBPath, VIRUS_YARA_SIG);
	if (dwRet > 1)
	{
		m_dwTotalSignatures = m_dwTotalSignatures + (dwRet - 1);
	}
	
	if(m_bIsMemoryScan == true) //For memory Scanner we need only SDV1
	{
		return m_dwTotalSignatures;
	}
	

	dwRet = m_16COMTree.LoadSignatureDB(szDBPath, VIRUS_DB_COM_SIG);
	if (dwRet > 1)
	{
		m_dwTotalSignatures = m_dwTotalSignatures + (dwRet -1);
	}

	if (m_bIsUSBScan == false)
	{
		LaunchAndroidDBLaodingThread();
	}

	//if (m_bIsActMonScan == false) //For L1 Testing
	{
		dwRet = m_ScriptTree.LoadSignatureDB(szDBPath, VIRUS_DB_SCRIPT_SIG);
		if (dwRet > 1)
		{
			m_dwTotalSignatures = m_dwTotalSignatures + (dwRet -1);
			//sprintf_s(szTemp, MAX_SZ_LEN, "#-#-# Script Signature loaded. Count:%d", dwRet);
			//OutputDebugString(A2CT(szTemp));
		}
	}

	dwRet = m_OLETree.LoadSignatureDB(szDBPath, VIRUS_DB_OLE_SIG);
	if (dwRet > 1)
	{
		m_dwTotalSignatures = m_dwTotalSignatures + (dwRet -1);
	}

	dwRet = m_INFTree.LoadSignatureDB(szDBPath, VIRUS_DB_INF_SIG);
	if(dwRet >1) 
	{
		m_dwTotalSignatures = m_dwTotalSignatures + (dwRet -1);
	}

	dwRet = m_PDFTree.LoadSignatureDB(szDBPath, VIRUS_DB_PDF_SIG);
	if(dwRet >1)
	{
		m_dwTotalSignatures = m_dwTotalSignatures + (dwRet -1);
	}

	dwRet = m_DigiScanTree.LoadSignatureDB(szDBPath,VIRUS_DB_DIGI_SIG);
	if(dwRet >1)
	{
		m_dwTotalSignatures = m_dwTotalSignatures + (dwRet -1);
	}

	m_dwTotalInitTime += (GetTickCount() - dwStartTime);
	return m_dwTotalSignatures;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanFile
	In Parameters	: CMaxPEFile *pMaxPEFile, LPTSTR szVirusName, LPTSTR szMacroName, DWORD &dwThreatID
	Out Parameters	: Virus ID else 0
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Scan file buffer with database tree according to file type
--------------------------------------------------------------------------------------*/
bool CScanManager::ScanDigiCert(CMaxPEFile *pMaxPEFile, LPSTR szVirusName)
{
	bool	bFoundVirus = false;
	DWORD	dwMinBytesReq = 0x00, dwBytesRead = 0x00;

	/*
	if (m_bIsActMonScan == true)
	{
		return bFoundVirus;
	}
	*/

	if (!pMaxPEFile)
	{
		return bFoundVirus;
	}

	BYTE	*pbDigiBuff = NULL;

	DWORD	dwReadBuffOffset = pMaxPEFile->m_stPEHeader.DataDirectory[0x4].VirtualAddress;

	if(0x0 == dwReadBuffOffset)
	{
		return bFoundVirus;
	}

	DWORD BUFF_SIZE  = pMaxPEFile->m_stPEHeader.DataDirectory[0x4].Size;

	if(0x0 == BUFF_SIZE) 
	{
		return bFoundVirus;
	}

	DWORD dwOverlayStart = pMaxPEFile->m_stSectionHeader[pMaxPEFile->m_stPEHeader.NumberOfSections - 1].PointerToRawData + pMaxPEFile->m_stSectionHeader[pMaxPEFile->m_stPEHeader.NumberOfSections - 1].SizeOfRawData; 
	if(pMaxPEFile->m_stPEHeader.DataDirectory[0x04].VirtualAddress != dwOverlayStart)
	{
		dwReadBuffOffset = pMaxPEFile->m_dwFileSize - BUFF_SIZE;
	}

	if(BUFF_SIZE > 0x3C00)	// size should be less than 15kb
	{
		BUFF_SIZE = 0x3C00;	// 1st 15kb from start of Certificate
	}

	pbDigiBuff = new BYTE[BUFF_SIZE];
	if(!pbDigiBuff)
	{
		return bFoundVirus;
	}
	dwMinBytesReq = BUFF_SIZE/3;
	//if(!GetBuffer(dwReadBuffOffset, BUFF_SIZE, ()))
	if(pMaxPEFile->ReadBuffer(&pbDigiBuff[0x00],dwReadBuffOffset,BUFF_SIZE,dwMinBytesReq,&dwBytesRead))
	{
		if (dwBytesRead && dwBytesRead >= dwMinBytesReq)
		{
			int		iVirusPos = -1;	
			char	szDigiVirusName[MAX_PATH] = {0x00};
			iVirusPos = m_DigiScanTree.ScanBuffer4Virus(&pbDigiBuff[0x00],dwBytesRead,&szDigiVirusName[0x00]);
			if (iVirusPos >= 0x00 && strlen(szDigiVirusName) > 0x00)
			{
				strcpy(szVirusName,szDigiVirusName);
				bFoundVirus = true;
			}
		}
	}

	if(pbDigiBuff)
	{
		delete []pbDigiBuff;
		pbDigiBuff =NULL;
	}
	return bFoundVirus;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanFile
	In Parameters	: CMaxPEFile *pMaxPEFile, LPTSTR szVirusName, LPTSTR szMacroName, DWORD &dwThreatID
	Out Parameters	: Virus ID else 0
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Scan file buffer with database tree according to file type
--------------------------------------------------------------------------------------*/
DWORD CScanManager::ScanFile(CMaxPEFile *pMaxPEFile, LPTSTR szVirusName, LPTSTR szMacroName, DWORD &dwThreatID)
{
	m_dwNoOfFilesScanned++;
	DWORD dwStartTime = GetTickCount();

	bool	bFoundDigiCertVirus = false;
	DWORD	dwRetValue = SCAN_ACTION_CLEAN;
	dwThreatID = 0;
	
	CScanFileManager objScanFile(pMaxPEFile);

	DWORD dwBufReadStartTime = GetTickCount();
	int iFileType = objScanFile.GetBuffer4Scanning();
	m_dwBufferReadingTime += (GetTickCount() - dwBufReadStartTime);

	dwBufReadStartTime = GetTickCount();
	int	iResult = -1;
	if(iFileType > 0)
	{
		
		switch(iFileType)
		{
		case VIRUS_FILE_TYPE_PE:
		case VIRUS_FILE_TYPE_ELF:
			{
				if (pMaxPEFile->m_bIsVBFile == false)
				{
					AddLogEntry(L"Not a VB File");
					iResult = m_FileInfectorTree.ScanBuffer4Virus(objScanFile.m_szScnBuffer, objScanFile.m_iBufferSize, objScanFile.m_szVirusName);
				}
				else
				{
					AddLogEntry(L"VB File");
					iResult = m_VBPETree.ScanBuffer4Virus(objScanFile.m_szScnBuffer, objScanFile.m_iBufferSize, objScanFile.m_szVirusName);
				}
				m_dwPEFileScanTime += (GetTickCount() - dwBufReadStartTime);
				if (strlen(objScanFile.m_szVirusName) == 0x00)
				{
					if (VIRUS_FILE_TYPE_PE == iFileType)
					{
						DWORD dwDigiStartTime = GetTickCount();
						bool bRetValue = ScanDigiCert(pMaxPEFile,objScanFile.m_szVirusName);
						m_dwDIGIScanTime += (GetTickCount() - dwDigiStartTime);
						if (bRetValue == false)
						{
							//CMaxIconScanner	objMaxIcnScnMgr;
							dwDigiStartTime = GetTickCount();
							bRetValue = m_MaxIcnScnMgr.ScanFile(pMaxPEFile,m_szDBPath,objScanFile.m_szVirusName);
							m_dwPEICOScanTime += (GetTickCount() - dwDigiStartTime);
							if (bRetValue == true)
							{
								iResult = 270594;
								bFoundDigiCertVirus = true;
								//strcpy(objScanFile.m_szVirusName,"Win.MxResIcn.Heur.Gen");
							}
						}
						else
						{
							iResult = 161086;
							bFoundDigiCertVirus = true;
						}
					}
				}
				m_dwPEScanTime += (GetTickCount() - dwBufReadStartTime);
			}
			break;
		case VIRUS_FILE_TYPE_DOS:
			{
				if (m_hAndroidDBThread != NULL)
				{
					WaitForSingleObject(m_hAndroidDBThread,INFINITE);
					m_hAndroidDBThread = NULL;
				}
				if (m_bIsUSBScan == false)
				{
					iResult = m_16DOSTree.ScanBuffer4Virus(objScanFile.m_szScnBuffer, objScanFile.m_iBufferSize, objScanFile.m_szVirusName);
				}
				m_dwDOSScanTime += (GetTickCount() - dwBufReadStartTime);
			}
			break;
		case VIRUS_FILE_TYPE_COM:
		case VIRUS_FILE_TYPE_BAT:
			{
				//if (m_bIsUSBScan == false)
				//{
					iResult = m_16COMTree.ScanBuffer4Virus(objScanFile.m_szScnBuffer, objScanFile.m_iBufferSize, objScanFile.m_szVirusName);
					m_dwCOMScanTime += (GetTickCount() - dwBufReadStartTime);
				//}
			}
			break;
		case VIRUS_FILE_TYPE_REG:
			{
				if (m_hAndroidDBThread != NULL)
				{
					WaitForSingleObject(m_hAndroidDBThread,INFINITE);
					m_hAndroidDBThread = NULL;
				}
				if (m_bIsUSBScan == false)
				{
					iResult = m_WMATree.ScanBuffer4Virus(objScanFile.m_szScnBuffer, objScanFile.m_iBufferSize, objScanFile.m_szVirusName);				
				}
				m_dwRegScanTime += (GetTickCount() - dwBufReadStartTime);
			}
			break;		
		case VIRUS_FILE_TYPE_WMA:
			{
				if (m_hAndroidDBThread != NULL)
				{
					WaitForSingleObject(m_hAndroidDBThread,INFINITE);
					m_hAndroidDBThread = NULL;
				}
				if (m_bIsUSBScan == false)
				{
					iResult = m_SISTree.ScanBuffer4Virus(objScanFile.m_szScnBuffer, objScanFile.m_iBufferSize, objScanFile.m_szVirusName);
				}
				m_dwWMAScanTime += (GetTickCount() - dwBufReadStartTime);
			}
			break;		
		case VIRUS_FILE_TYPE_SCRIPT:
			{
				//if (m_bIsActMonScan == false)
				{
					DWORD dwBuffSize = sizeof(objScanFile.m_szScriptBuffer);
					DWORD dwRetBuffSize = 0;
					for(int i = 0; objScanFile.m_objScript.GetFileBuffer(objScanFile.m_szScriptBuffer, dwBuffSize, dwRetBuffSize, i, pMaxPEFile); i++)
					{
						if (i == 0x00)
						{
							objScanFile.m_iBufferSize = dwRetBuffSize;
							//Comment 03-09-2021 Due to false+
							/*
							if (objScanFile.m_objScript.CheckForExploitScript(objScanFile.m_szScriptBuffer, objScanFile.m_iBufferSize) == true)
							{
								iResult = 0x100;
								strcpy(&objScanFile.m_szVirusName[0],"SCRPT.Exploit.Generic");
								break;
							}
							*/
						}
						objScanFile.m_iBufferSize = dwRetBuffSize;
						iResult = m_ScriptTree.ScanBuffer4Virus(objScanFile.m_szScriptBuffer, objScanFile.m_iBufferSize, objScanFile.m_szVirusName);
						if(iResult != -1 && objScanFile.m_szVirusName[0])
						{
							break;
						}
					}
				}
				m_dwScriptScanTime += (GetTickCount() - dwBufReadStartTime);
			}
			break;
		case VIRUS_FILE_TYPE_OLE:
			{
				for(DWORD dwCnt = 0; dwCnt < objScanFile.m_objOLEScan.m_dwCntMacroModule; dwCnt++)
				{
					iResult = m_OLETree.ScanBuffer4Virus(objScanFile.m_objOLEScan.m_ppMacrosVar[dwCnt]->pbyMacBuff,
						objScanFile.m_objOLEScan.m_ppMacrosVar[dwCnt]->dwSizeOfMacro,
						objScanFile.m_szVirusName);
					if (iResult != -1 && strlen(objScanFile.m_szVirusName) > 0)
					{						
						dwThreatID = -1;
						_stprintf_s(szMacroName, 
							MAX_PATH,
							_T("%s"),
							CString(objScanFile.m_objOLEScan.m_ppMacrosVar[dwCnt]->pStreamName));
						break;
					}
				}
				objScanFile.m_objOLEScan.ReleaseMacroBuffer();
				m_dwOLEScanTime += (GetTickCount() - dwBufReadStartTime);
			}
			break;
		case VIRUS_FILE_TYPE_INF:
			{
				iResult = m_INFTree.ScanBuffer4Virus(objScanFile.m_szScnBuffer,objScanFile.m_iBufferSize,objScanFile.m_szVirusName);
				m_dwINFScanTime += (GetTickCount() - dwBufReadStartTime);
			}
			break;
		case VIRUS_FILE_TYPE_PDF:
			{
				WaitForSingleObject(m_hEvent, INFINITE);
				if(objScanFile.m_objPDFSig.DecryptPDFFile(pMaxPEFile->m_szFilePath))
				{
					objScanFile.m_iBufferSize = sizeof(objScanFile.m_szScriptBuffer);
					memset(objScanFile.m_szScriptBuffer, 0, objScanFile.m_iBufferSize);
					if(objScanFile.m_objPDFSig.EnumFirstScript(objScanFile.m_szScriptBuffer, objScanFile.m_iBufferSize))
					{
						do
						{
							iResult = m_PDFTree.ScanBuffer4Virus(objScanFile.m_szScriptBuffer, objScanFile.m_iBufferSize, objScanFile.m_szVirusName);
							if(-1 != iResult && objScanFile.m_szVirusName[0])
							{
								break;
							}
						}while(objScanFile.m_objPDFSig.EnumNextScript(objScanFile.m_szScriptBuffer, objScanFile.m_iBufferSize));
					}

					objScanFile.m_objPDFSig.CloseEnum();
				}
				SetEvent(m_hEvent);	
				m_dwPDFScanTime += (GetTickCount() - dwBufReadStartTime);

			}
			break;
		case VIRUS_FILE_TYPE_DEX:
			{
				if (m_hAndroidDBThread != NULL)
				{
					WaitForSingleObject(m_hAndroidDBThread,INFINITE);
					m_hAndroidDBThread = NULL;
				}

				if (m_bIsUSBScan == false)
				{

					LPTSTR szVirusName = 0;
					bool bVirusFound = false;
					/*
					if(m_DexS2S.SearchItem((LPCTSTR)objScanFile.m_szScnBuffer, szVirusName))
					{
						if(szVirusName)
						{
							bVirusFound = true;
							sprintf_s(objScanFile.m_szVirusName, _countof(objScanFile.m_szVirusName), "%S", szVirusName);
							iResult = 0;
						}
					}
					*/
					if(!bVirusFound)
					{
						DWORD dwMapSize = 0, dwMapOffset = 0;
						if(objScanFile.GetDexMapDetails(dwMapOffset, dwMapSize))
						{
							MAP_ITEM *pMapItems = new MAP_ITEM[dwMapSize];
							if(pMapItems)
							{						
								if(pMaxPEFile->ReadBuffer(pMapItems, dwMapOffset, dwMapSize * sizeof(MAP_ITEM), dwMapSize * sizeof(MAP_ITEM)))
								{								
									for(DWORD i = 0; i < dwMapSize; i++)
									{
										DWORD dwSizeofSection = (i == dwMapSize - 1) ? (pMaxPEFile->m_dwFileSize -  pMapItems[i].offset): (pMapItems[i + 1].offset - pMapItems[i].offset);
										switch(pMapItems[i].type)
										{		
										case TYPE_CODE_ITEM:
										case TYPE_STRING_DATA_ITEM:			
											{
												DWORD dwBytesToRead = 0x0;
												for(DWORD dwFileOffset = pMapItems[i].offset; dwFileOffset < (pMapItems[i].offset + dwSizeofSection); dwFileOffset += dwBytesToRead)
												{
													// Read buffer in 64KB chunks. Calulate no of bytes to read if remaining bytes less than 64KB
													dwBytesToRead = (pMapItems[i].offset + dwSizeofSection - dwFileOffset) < 0x10000 ? (pMapItems[i].offset + dwSizeofSection - dwFileOffset) : 0x10000;

													memset(objScanFile.m_szScriptBuffer, 0, objScanFile.m_iBufferSize);
													objScanFile.m_iBufferSize = 0;
													if(!pMaxPEFile->ReadBuffer(objScanFile.m_szScriptBuffer, dwFileOffset, dwBytesToRead, 0, (DWORD *)&objScanFile.m_iBufferSize))
													{
														break;
													}										

													iResult = m_DexTree.ScanBuffer4Virus(objScanFile.m_szScriptBuffer, objScanFile.m_iBufferSize, objScanFile.m_szVirusName);
													if(iResult != -1 && objScanFile.m_szVirusName[0])
													{
														break;
													}
												}				
												break;
											}
										}
										if(iResult != -1 && objScanFile.m_szVirusName[0])
										{
											break;
										}
									}
								}
								delete []pMapItems;
								pMapItems = NULL;
							}
						}					
					}
				}
				m_dwDEXScanTime += (GetTickCount() - dwBufReadStartTime);
			}
			break;
		case VIRUS_FILE_TYPE_MAC:
		case VIRUS_FILE_TYPE_SIS:
			{
				if (m_hAndroidDBThread != NULL)
				{
					WaitForSingleObject(m_hAndroidDBThread,INFINITE);
					m_hAndroidDBThread = NULL;
				}
				if (m_bIsUSBScan == false)
				{
					iResult = m_SISTree.ScanBuffer4Virus(objScanFile.m_szScnBuffer, objScanFile.m_iBufferSize, objScanFile.m_szVirusName);
				}
				m_dwMACScanTime += (GetTickCount() - dwBufReadStartTime);
			}
			break;
		case VIRUS_FILE_TYPE_RTF:
			{
				if (m_hAndroidDBThread != NULL)
				{
					WaitForSingleObject(m_hAndroidDBThread,INFINITE);
					m_hAndroidDBThread = NULL;
				}
				if (m_bIsUSBScan == false)
				{
					if(objScanFile.m_objMaxRTF.Check4RtfExploitEx(objScanFile.m_szScriptBuffer,sizeof(objScanFile.m_szScriptBuffer),pMaxPEFile) == true)
					{					
						memcpy(objScanFile.m_szVirusName, "Virus.RTF.Exploit.CVE.3333.Gen", 32);
						iResult = 1;
						break;					
					}

					DWORD dwRetBuffSize = 0, dwStartingAdd = 0, dwBytesRead = 0;
					for(int i = 0; objScanFile.m_objMaxRTF.GetFileBuffer(objScanFile.m_szScriptBuffer, dwStartingAdd , dwRetBuffSize, dwBytesRead, pMaxPEFile); i++)
					{
						dwStartingAdd += dwRetBuffSize;
						objScanFile.m_iBufferSize = dwBytesRead;
						iResult = m_RTFTree.ScanBuffer4Virus(objScanFile.m_szScriptBuffer, objScanFile.m_iBufferSize, objScanFile.m_szVirusName);
						if(iResult != -1 && objScanFile.m_szVirusName[0])
						{
							break;
						}
					}				
				}
				m_dwRTFScanTime += (GetTickCount() - dwBufReadStartTime);
			}
			break;
		case VIRUS_FILE_TYPE_ICON:
			{
				if (m_hAndroidDBThread != NULL)
				{
					WaitForSingleObject(m_hAndroidDBThread,INFINITE);
					m_hAndroidDBThread = NULL;
				}
				if (m_bIsUSBScan == false)
				{
					DWORD dwBuffSize = sizeof(objScanFile.m_szScriptBuffer);
					DWORD dwRetBuffSize = 0;
					for(int i = 0; objScanFile.m_objMaxCursor.GetICONBuffer(objScanFile.m_szScriptBuffer, dwBuffSize, dwRetBuffSize, i, pMaxPEFile); i++)
					{
						objScanFile.m_iBufferSize = dwRetBuffSize;
						iResult = m_CursorTree.ScanBuffer4Virus(objScanFile.m_szScriptBuffer, objScanFile.m_iBufferSize, objScanFile.m_szVirusName);
						if(iResult != -1 && objScanFile.m_szVirusName[0])
						{
							break;
						}
					}
				}
				m_dwICOScanTime += (GetTickCount() - dwBufReadStartTime);
			}
			break;
		case VIRUS_FILE_TYPE_CUR:
			{
				if (m_hAndroidDBThread != NULL)
				{
					WaitForSingleObject(m_hAndroidDBThread,INFINITE);
					m_hAndroidDBThread = NULL;
				}
				if (m_bIsUSBScan == false)
				{
					if(objScanFile.m_objMaxCursor.IsExploitANI(pMaxPEFile))
					{
						memcpy(objScanFile.m_szVirusName, "Virus.ANI.Exploit.MS05.Gen", 28);
						iResult = 1;
						break;
					}

					DWORD dwBuffSize = sizeof(objScanFile.m_szScriptBuffer);
					DWORD dwRetBuffSize = 0;
					for(int i = 0; objScanFile.m_objMaxCursor.GetANIBuffer(objScanFile.m_szScriptBuffer, dwRetBuffSize, pMaxPEFile); i++)
					{
						objScanFile.m_iBufferSize = dwRetBuffSize;
						iResult = m_CursorTree.ScanBuffer4Virus(objScanFile.m_szScriptBuffer,objScanFile.m_iBufferSize,objScanFile.m_szVirusName);
						if(iResult != -1 && objScanFile.m_szVirusName[0])
						{
							break;
						}
					}
				}
				m_dwCurScanTime += (GetTickCount() - dwBufReadStartTime);
			}
			break;
		case VIRUS_FILE_TYPE_JCLASS:
			{
				if (m_hAndroidDBThread != NULL)
				{
					WaitForSingleObject(m_hAndroidDBThread,INFINITE);
					m_hAndroidDBThread = NULL;
				}
				if (m_bIsUSBScan == false)
				{
					DWORD dwRetBuffSize = 0, dwTotalBytesRead = 0;
					for(int i = 0; objScanFile.m_objScript.GetJClassFileBuffer(objScanFile.m_szScriptBuffer, dwRetBuffSize, i, dwTotalBytesRead, pMaxPEFile); i++)
					{
						objScanFile.m_iBufferSize = dwRetBuffSize;
						iResult = m_SISTree.ScanBuffer4Virus(objScanFile.m_szScriptBuffer,objScanFile.m_iBufferSize,objScanFile.m_szVirusName);
						if(iResult != -1 && objScanFile.m_szVirusName[0])
						{
							break;
						}
						else if(dwTotalBytesRead <= 0 || dwTotalBytesRead >= pMaxPEFile->m_dwFileSize)
						{
							break;
						}
					}
				}
				m_dwJCLASSScanTime += (GetTickCount() - dwBufReadStartTime);
			}
			break;
		case VIRUS_FILE_TYPE_TTF:
			{
				if (m_hAndroidDBThread != NULL)
				{
					WaitForSingleObject(m_hAndroidDBThread,INFINITE);
					m_hAndroidDBThread = NULL;
				}
				if (m_bIsUSBScan == false)
				{
					int iRetVal = objScanFile.m_objMaxTTF.Check4TTFDelOrRepair(pMaxPEFile);
					if(iRetVal == 1)
					{
						memcpy(objScanFile.m_szVirusName, "Virus.TTF.Exploit.Win32.CVE-2010-2883.a", 41);
						iResult = 1;
						break;
					}
					if(pMaxPEFile->ReadBuffer(objScanFile.m_szScnBuffer, objScanFile.m_objMaxTTF.m_dwStartOffset, objScanFile.m_objMaxTTF.m_dwBufferSize, objScanFile.m_objMaxTTF.m_dwBufferSize))
					{
						iResult = m_RTFTree.ScanBuffer4Virus(&(objScanFile.m_szScnBuffer[0]), objScanFile.m_objMaxTTF.m_dwBufferSize, objScanFile.m_szVirusName);
						if(iResult != -1 && objScanFile.m_szVirusName[0])
						{
							iResult = 1;	
							if(iRetVal != 2)
							{
								_stprintf_s(szMacroName, MAX_PATH, _T("FC#[C%d]"), objScanFile.m_objMaxTTF.m_dwStartOffset);
								dwThreatID = -1;
							}
						}
					}
				}
				m_dwTTFScanTime += (GetTickCount() - dwBufReadStartTime);
			}
			break;
		case VIRUS_FILE_TYPE_HELP:  //Helpfile
			{ 
				if (m_hAndroidDBThread != NULL)
				{
					WaitForSingleObject(m_hAndroidDBThread,INFINITE);
					m_hAndroidDBThread = NULL;
				}
				if (m_bIsUSBScan == false)
				{
					if(objScanFile.m_objMaxHelp.TraverseDirectoy(objScanFile.m_szScriptBuffer, pMaxPEFile))
					{ 					
						DWORD dwBuffSize = sizeof(objScanFile.m_szScriptBuffer);
						DWORD dwRetBuffSize = 0;
						for(int i = 0; objScanFile.m_objMaxHelp.GetHelpBuffer(objScanFile.m_szScriptBuffer, dwBuffSize, dwRetBuffSize, i, pMaxPEFile); i++)
						{
							objScanFile.m_iBufferSize = dwRetBuffSize;
							iResult = m_RTFTree.ScanBuffer4Virus(objScanFile.m_szScriptBuffer, objScanFile.m_iBufferSize, objScanFile.m_szVirusName);
							if(iResult != -1 && objScanFile.m_szVirusName[0])
							{
								_stprintf_s(szMacroName, MAX_PATH, _T("FB"));
								dwThreatID = -1;
								break;
							}
						}
					}
				}
				m_dwHLPScanTime += (GetTickCount() - dwBufReadStartTime);
			}
			break;
		}

		int	iRetValue = objScanFile.Check4LinkInfection();
		if (iRetValue == 1)
		{
			iResult = 1;	
			_stprintf_s(szMacroName, MAX_PATH, _T("FA"));
			dwThreatID = -1;
		}
		else if (iRetValue == 2)
		{
			iResult = 1;	
			dwThreatID = 0;
		}

		if(iResult != -1 && strlen(objScanFile.m_szVirusName) > 0)		
		{	
			dwRetValue = SCAN_ACTION_REPAIR;

			if(iFileType == VIRUS_FILE_TYPE_PE || iFileType == VIRUS_FILE_TYPE_SCRIPT || iFileType == VIRUS_FILE_TYPE_WMA)
			{
				if (bFoundDigiCertVirus == false)
				{
					char *ptr = strrchr(objScanFile.m_szVirusName, '_');
					if(ptr != NULL)
					{
						ptr++;
						if(0 == dwThreatID)
						{
							dwThreatID = atol(ptr);
						}
						ptr--;
						*ptr = '\0';
					}
				}
			}

			if(0 == dwThreatID)
			{
				dwRetValue = SCAN_ACTION_DELETE;
			}
			/*------------------Added For SDR1.DB Remove FF Expression------------------------*/
			else
			{
				LPTSTR szParam;
				if(dwThreatID != -1)
				{
					if(m_bRepairDBLoaded == true)
					{
						TCHAR szVirusID[MAX_PATH] = {0};
						_stprintf_s(szVirusID, MAX_PATH, L"%d", dwThreatID);
						if(!m_objMaxRepairVirDB.SearchItem(szVirusID, szParam))
						{
							dwRetValue = SCAN_ACTION_DELETE;
						}
					}
				}
			
			}
			/*---------------------------------------END---------------------------------------*/
			_stprintf_s(szVirusName, MAX_PATH, L"%s", CString(objScanFile.m_szVirusName));		
		}
	}

	if (iResult == 270594 || iResult == 161086 || iResult == 121218)
	{
		dwThreatID = iResult;
		dwRetValue = SCAN_ACTION_DELETE;
	}

	m_dwBufferScanTime += (GetTickCount() - dwBufReadStartTime);

	objScanFile.m_objPDFSig.CloseEnum();
	m_dwTotalScanTime += (GetTickCount() - dwStartTime);
	return dwRetValue;
}

/*-------------------------------------------------------------------------------------
	Function		: UnloadDatabase
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Unloading of database as respective structures from memory
--------------------------------------------------------------------------------------*/
int CScanManager::UnloadDatabase(void)
{
	AddLogEntry(L"Virus DB Unload!");
	if (m_hAndroidDBThread != NULL)
	{
		TerminateThread(m_hAndroidDBThread,0x01);
		//WaitForSingleObject(m_hAndroidDBThread,INFINITE);
		m_hAndroidDBThread = NULL;
	}

	m_VBPETree.UnLoadSignatureDB();
	m_FileInfectorTree.UnLoadSignatureDB();
	m_ScriptTree.UnLoadSignatureDB();
	m_WMATree.UnLoadSignatureDB();
	m_16DOSTree.UnLoadSignatureDB();
	m_16COMTree.UnLoadSignatureDB();
	m_INFTree.UnLoadSignatureDB(); //neeraj
	m_PDFTree.UnLoadSignatureDB();
	m_OLETree.UnLoadSignatureDB();
	m_DexS2S.RemoveAll();
	m_DexTree.UnLoadSignatureDB();
	m_SISTree.UnLoadSignatureDB();
	m_RTFTree.UnLoadSignatureDB();
	m_CursorTree.UnLoadSignatureDB();
	m_DigiScanTree.UnLoadSignatureDB();

	m_objMaxRepairVirDB.RemoveAll(); //Added For SDR1.DB (Remove FF)

	WCHAR *wcsTemp = new WCHAR[MAX_PATH];
	wmemset(wcsTemp, 0, MAX_PATH);
	swprintf_s(wcsTemp, MAX_PATH, _T("TNF: %d, VDBIT: %d, VDBST: %d"), m_dwNoOfFilesScanned, m_dwTotalInitTime, m_dwTotalScanTime);
	AddLogEntry(wcsTemp);

	CTimeSpan ctTotalInitTime = (m_dwTotalInitTime/1000);
	CTimeSpan ctTotalScanTime = (m_dwTotalScanTime/1000);

	wmemset(wcsTemp, 0, MAX_PATH);
	swprintf_s(wcsTemp, MAX_PATH, _T("Total VirusDB Init Time : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total VirusDB Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d"),
				(DWORD)ctTotalInitTime.GetHours(), (DWORD)ctTotalInitTime.GetMinutes(), (DWORD)ctTotalInitTime.GetSeconds(),
				(DWORD)ctTotalScanTime.GetHours(), (DWORD)ctTotalScanTime.GetMinutes(), (DWORD)ctTotalScanTime.GetSeconds());
	AddLogEntry(wcsTemp);

	
	CTimeSpan ctTotalPEScanTime = (m_dwPEScanTime / 1000);
	CTimeSpan ctTotalDOSScanTime = (m_dwDOSScanTime / 1000);
	CTimeSpan ctTotalCOMScanTime = (m_dwCOMScanTime / 1000);
	CTimeSpan ctTotalRegScanTime = (m_dwRegScanTime / 1000);
	CTimeSpan ctTotalWMAScanTime = (m_dwWMAScanTime / 1000);
	CTimeSpan ctTotalSCRIPTScanTime = (m_dwScriptScanTime / 1000);
	CTimeSpan ctTotalOLEScanTime = (m_dwOLEScanTime / 1000);
	CTimeSpan ctTotalINFScanTime = (m_dwINFScanTime / 1000);
	CTimeSpan ctTotalPDFScanTime = (m_dwPDFScanTime / 1000);
	CTimeSpan ctTotalDEXScanTime = (m_dwDEXScanTime / 1000);
	CTimeSpan ctTotalMACScanTime = (m_dwMACScanTime / 1000);
	CTimeSpan ctTotalRFTScanTime = (m_dwRTFScanTime / 1000);
	CTimeSpan ctTotalICOScanTime = (m_dwICOScanTime / 1000);
	CTimeSpan ctTotalCURScanTime = (m_dwCurScanTime / 1000);
	CTimeSpan ctTotalJCLASSScanTime = (m_dwJCLASSScanTime / 1000);
	CTimeSpan ctTotalTTFScanTime = (m_dwTTFScanTime / 1000);
	CTimeSpan ctTotalHLPScanTime = (m_dwHLPScanTime / 1000);

	wmemset(wcsTemp, 0, MAX_PATH);
	swprintf_s(wcsTemp, MAX_PATH, _T("Total PE Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total DOS Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total COM Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d"),
		(DWORD)ctTotalPEScanTime.GetHours(), (DWORD)ctTotalPEScanTime.GetMinutes(), (DWORD)ctTotalPEScanTime.GetSeconds(),
		(DWORD)ctTotalDOSScanTime.GetHours(), (DWORD)ctTotalDOSScanTime.GetMinutes(), (DWORD)ctTotalDOSScanTime.GetSeconds(),
		(DWORD)ctTotalCOMScanTime.GetHours(), (DWORD)ctTotalCOMScanTime.GetMinutes(), (DWORD)ctTotalCOMScanTime.GetSeconds());
	AddLogEntry(wcsTemp);

	wmemset(wcsTemp, 0, MAX_PATH);
	swprintf_s(wcsTemp, MAX_PATH, _T("Total REG Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total MAC Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total SCRPT Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d"),
		(DWORD)ctTotalRegScanTime.GetHours(), (DWORD)ctTotalRegScanTime.GetMinutes(), (DWORD)ctTotalRegScanTime.GetSeconds(),
		(DWORD)ctTotalWMAScanTime.GetHours(), (DWORD)ctTotalWMAScanTime.GetMinutes(), (DWORD)ctTotalWMAScanTime.GetSeconds(),
		(DWORD)ctTotalSCRIPTScanTime.GetHours(), (DWORD)ctTotalSCRIPTScanTime.GetMinutes(), (DWORD)ctTotalSCRIPTScanTime.GetSeconds());
	AddLogEntry(wcsTemp);

	wmemset(wcsTemp, 0, MAX_PATH);
	swprintf_s(wcsTemp, MAX_PATH, _T("Total OLE Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total INF Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total PDF Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d"),
		(DWORD)ctTotalOLEScanTime.GetHours(), (DWORD)ctTotalOLEScanTime.GetMinutes(), (DWORD)ctTotalOLEScanTime.GetSeconds(),
		(DWORD)ctTotalINFScanTime.GetHours(), (DWORD)ctTotalINFScanTime.GetMinutes(), (DWORD)ctTotalINFScanTime.GetSeconds(),
		(DWORD)ctTotalPDFScanTime.GetHours(), (DWORD)ctTotalPDFScanTime.GetMinutes(), (DWORD)ctTotalPDFScanTime.GetSeconds());
	AddLogEntry(wcsTemp);

	wmemset(wcsTemp, 0, MAX_PATH);
	swprintf_s(wcsTemp, MAX_PATH, _T("Total DEX Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total MAC Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total RTF Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d"),
		(DWORD)ctTotalDEXScanTime.GetHours(), (DWORD)ctTotalDEXScanTime.GetMinutes(), (DWORD)ctTotalDEXScanTime.GetSeconds(),
		(DWORD)ctTotalMACScanTime.GetHours(), (DWORD)ctTotalMACScanTime.GetMinutes(), (DWORD)ctTotalMACScanTime.GetSeconds(),
		(DWORD)ctTotalRFTScanTime.GetHours(), (DWORD)ctTotalRFTScanTime.GetMinutes(), (DWORD)ctTotalRFTScanTime.GetSeconds());
	AddLogEntry(wcsTemp);

	wmemset(wcsTemp, 0, MAX_PATH);
	swprintf_s(wcsTemp, MAX_PATH, _T("Total ICO Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total CUR Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total JClass Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d"),
		(DWORD)ctTotalICOScanTime.GetHours(), (DWORD)ctTotalICOScanTime.GetMinutes(), (DWORD)ctTotalICOScanTime.GetSeconds(),
		(DWORD)ctTotalCURScanTime.GetHours(), (DWORD)ctTotalCURScanTime.GetMinutes(), (DWORD)ctTotalCURScanTime.GetSeconds(),
		(DWORD)ctTotalJCLASSScanTime.GetHours(), (DWORD)ctTotalJCLASSScanTime.GetMinutes(), (DWORD)ctTotalJCLASSScanTime.GetSeconds());
	AddLogEntry(wcsTemp);

	wmemset(wcsTemp, 0, MAX_PATH);
	swprintf_s(wcsTemp, MAX_PATH, _T("Total ICO Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total CUR Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d"),
		(DWORD)ctTotalTTFScanTime.GetHours(), (DWORD)ctTotalTTFScanTime.GetMinutes(), (DWORD)ctTotalTTFScanTime.GetSeconds(),
		(DWORD)ctTotalHLPScanTime.GetHours(), (DWORD)ctTotalHLPScanTime.GetMinutes(), (DWORD)ctTotalHLPScanTime.GetSeconds());
	AddLogEntry(wcsTemp);

	CTimeSpan ctTotalPEFileScanTime = (m_dwPEFileScanTime / 1000);
	CTimeSpan ctTotalDIGIScanTime = (m_dwDIGIScanTime / 1000);
	CTimeSpan ctTotalPEICOScanTime = (m_dwPEICOScanTime / 1000);

	wmemset(wcsTemp, 0, MAX_PATH);
	swprintf_s(wcsTemp, MAX_PATH, _T("Total PE File Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total DIGI Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total PE_ICO Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d"),
		(DWORD)ctTotalPEFileScanTime.GetHours(), (DWORD)ctTotalPEFileScanTime.GetMinutes(), (DWORD)ctTotalPEFileScanTime.GetSeconds(),
		(DWORD)ctTotalDIGIScanTime.GetHours(), (DWORD)ctTotalDIGIScanTime.GetMinutes(), (DWORD)ctTotalDIGIScanTime.GetSeconds(),
		(DWORD)ctTotalPEICOScanTime.GetHours(), (DWORD)ctTotalPEICOScanTime.GetMinutes(), (DWORD)ctTotalPEICOScanTime.GetSeconds());
	AddLogEntry(wcsTemp);

	delete [] wcsTemp;
	wcsTemp = NULL;

	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: SetDebugPrivileges
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Sets priviledges from system to access memory
--------------------------------------------------------------------------------------*/
int CScanManager::SetDebugPrivileges(void)
{
	TOKEN_PRIVILEGES	tp_CurPriv;
	HANDLE				hToken=NULL;

	if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken))
	{
		return 1;
	}
	
	tp_CurPriv.PrivilegeCount = 1;
	LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tp_CurPriv.Privileges[0].Luid);
	tp_CurPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken,FALSE,&tp_CurPriv,sizeof(TOKEN_PRIVILEGES),0,0);

	CloseHandle(hToken);

	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: SetProductRegistryPath
	In Parameters	: Registry Path
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Sets product registry path for internal use
--------------------------------------------------------------------------------------*/
DWORD CScanManager::SetProductRegistryPath(LPCTSTR szKeyPath)
{
	if(!szKeyPath || (_tcslen(szKeyPath) >= _countof(m_FileInfectorTree.m_szProdRegKeyPath)))
	{
		return FALSE;
	}

	_tcscpy_s(m_FileInfectorTree.m_szProdRegKeyPath, _countof(m_FileInfectorTree.m_szProdRegKeyPath), szKeyPath);
	_tcscpy_s(m_ScriptTree.m_szProdRegKeyPath, _countof(m_ScriptTree.m_szProdRegKeyPath), szKeyPath);
	_tcscpy_s(m_WMATree.m_szProdRegKeyPath, _countof(m_WMATree.m_szProdRegKeyPath), szKeyPath);
	_tcscpy_s(m_16DOSTree.m_szProdRegKeyPath, _countof(m_16DOSTree.m_szProdRegKeyPath), szKeyPath);
	_tcscpy_s(m_16COMTree.m_szProdRegKeyPath, _countof(m_16COMTree.m_szProdRegKeyPath), szKeyPath);
	_tcscpy_s(m_INFTree.m_szProdRegKeyPath, _countof(m_INFTree.m_szProdRegKeyPath), szKeyPath);
	_tcscpy_s(m_PDFTree.m_szProdRegKeyPath, _countof(m_PDFTree.m_szProdRegKeyPath), szKeyPath);
	_tcscpy_s(m_OLETree.m_szProdRegKeyPath, _countof(m_OLETree.m_szProdRegKeyPath), szKeyPath);
	_tcscpy_s(m_DexTree.m_szProdRegKeyPath, _countof(m_DexTree.m_szProdRegKeyPath), szKeyPath);
	_tcscpy_s(m_SISTree.m_szProdRegKeyPath, _countof(m_SISTree.m_szProdRegKeyPath), szKeyPath);
	_tcscpy_s(m_RTFTree.m_szProdRegKeyPath, _countof(m_RTFTree.m_szProdRegKeyPath), szKeyPath);
	_tcscpy_s(m_CursorTree.m_szProdRegKeyPath, _countof(m_CursorTree.m_szProdRegKeyPath), szKeyPath);
	_tcscpy_s(m_DigiScanTree.m_szProdRegKeyPath, _countof(m_CursorTree.m_szProdRegKeyPath), szKeyPath);
	return TRUE;
}

/*-------------------------------------------------------------------------------------
	Function		: LoadSignatureDBS2S
	In Parameters	: LPCTSTR szDBPath, LPCTSTR szDBName, CS2S& objDB (Tree Structure)
	Out Parameters	: DWORD : Signatrue Count
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Loads the Header Dex (Android) Signature is BalBST s-2-s
--------------------------------------------------------------------------------------*/
DWORD CScanManager::LoadSignatureDBS2S(LPCTSTR szDBPath, LPCTSTR szDBName, CS2S& objDB)
{
	TCHAR szDBFilePath[MAX_PATH] = {0};

	if(!szDBPath || !szDBName || !(*szDBName))
	{
		return 0;
	}

	if(_tcslen(szDBPath) + _tcslen(szDBName) >= _countof(szDBFilePath))
	{
		return 0;
	}

	_stprintf_s(szDBFilePath, _countof(szDBFilePath), _T("%s%s"), szDBPath, szDBName);
	if(!objDB.Load(szDBFilePath))
	{
		//using ole db object to set the database registry value to download patch
		m_OLETree.SetDatabasePatchDownload(szDBFilePath);
		return 0;
	}

	return objDB.GetCount();
}

/*-------------------------------------------------------------------------------------
	Function		: GetPEBuffer
	In Parameters	: CMaxPEFile *pMaxPEFile, BYTE *pBuff, unsigned int iBuffSize, unsigned int &iRetBuffSize, PERegions *pPERegions
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Get file's scan buffer
--------------------------------------------------------------------------------------*/
bool CScanManager::GetPEBuffer(CMaxPEFile *pMaxPEFile, BYTE *pBuff, unsigned int iBuffSize, unsigned int &iRetBuffSize, PERegions *pPERegions) 
{	
	CScanFileManager objScanFile(pMaxPEFile);
	objScanFile.m_stPERegions = *pPERegions;
	int iFileType = objScanFile.GetBuffer4Scanning();
	if(VIRUS_FILE_TYPE_PE == iFileType)	
	{
		iRetBuffSize = objScanFile.m_iBufferSize;
		if(iBuffSize > iRetBuffSize)
		{
			iBuffSize = iRetBuffSize;
		}
		memcpy(pBuff, objScanFile.m_szScnBuffer, iBuffSize);
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDexBuffer
	In Parameters	: CMaxPEFile *pMaxPEFile, BYTE *pBuff, unsigned int iBuffSize, unsigned int &iRetBuffSize
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Get buffer from dex file (Android)
--------------------------------------------------------------------------------------*/
bool CScanManager::GetDexBuffer(CMaxPEFile *pMaxPEFile, BYTE *pBuff, unsigned int iBuffSize, unsigned int &iRetBuffSize) 
{	
	CScanFileManager objScanFile(pMaxPEFile);
	int iFileType = objScanFile.GetBuffer4Scanning();
	if(VIRUS_FILE_TYPE_DEX == iFileType)
	{		
		BYTE *byBuff = NULL;
		DWORD dwSize = iRetBuffSize = 0;
		if(objScanFile.GetDexFileBuffer(&byBuff, dwSize))
		{
			iRetBuffSize = dwSize;
			iRetBuffSize = (iRetBuffSize > iBuffSize ? iBuffSize : iRetBuffSize);
			memcpy(pBuff, byBuff, iRetBuffSize);
		}
		if(byBuff)
		{
			delete [] byBuff;
			byBuff = NULL;
		}
		return true;
	}
	return false;
}


/*-------------------------------------------------------------------------------------
	Function		: LoadAndroidDBs
	In Parameters	: 
	Out Parameters	: Total Signature Count
	Purpose			: 
	Author			: Tushar Kadam
	Description		: LoadAll the Android Database (MultiThreading) 
--------------------------------------------------------------------------------------*/
DWORD	CScanManager::LoadAndroidDBs()
{
	DWORD	dwRetValue = 0x00;
	DWORD	dwRet;
	TCHAR	szLogLine[MAX_SZ_LEN] = {0x00};

	dwRet = m_DexTree.LoadSignatureDB(m_szDBPath, VIRUS_DB_DEX_SIG);
	if(dwRet >1)
	{
		dwRetValue = dwRetValue + (dwRet -1);
	}

	dwRet = m_SISTree.LoadSignatureDB(m_szDBPath, VIRUS_DB_SIS_SIG);
	if(dwRet >1)
	{
		//m_dwTotalSignatures = m_dwTotalSignatures + (dwRet -1);
		dwRetValue = dwRetValue + (dwRet - 1);
	}

	dwRet = m_RTFTree.LoadSignatureDB(m_szDBPath, VIRUS_DB_RTF_SIG);
	if(dwRet >1)
	{
		//m_dwTotalSignatures = m_dwTotalSignatures + (dwRet -1);
		dwRetValue = dwRetValue + (dwRet - 1);
	}

	dwRet = m_CursorTree.LoadSignatureDB(m_szDBPath, VIRUS_DB_CURSOR_SIG);
	if(dwRet >1)
	{
		//m_dwTotalSignatures = m_dwTotalSignatures + (dwRet -1);
		//sprintf_s(szTemp, MAX_SZ_LEN, "#-#-# CUR Signature loaded. Count:%d", dwRet);
		dwRetValue = dwRetValue + (dwRet - 1);
	}

	dwRet = m_16DOSTree.LoadSignatureDB(m_szDBPath, VIRUS_DB_DOS_SIG);
	if (dwRet > 1)
	{
		//m_dwTotalSignatures = m_dwTotalSignatures + (dwRet -1);
		//sprintf_s(szTemp, MAX_SZ_LEN, "#-#-# DOS Signature loaded. Count:%d", dwRet);
		dwRetValue = dwRetValue + (dwRet - 1);

	}

	dwRet = m_WMATree.LoadSignatureDB(m_szDBPath, VIRUS_DB_WMA_SIG);
	if (dwRet > 1)
	{
		//m_dwTotalSignatures = m_dwTotalSignatures + (dwRet -1);
		//sprintf_s(szTemp, MAX_SZ_LEN, "#-#-# WMA Signature loaded. Count:%d", dwRet);
		dwRetValue = dwRetValue + (dwRet - 1);
	}

	/*----------------Added For SDR1.DB Remove FF Expression----------------------*/
	if(m_objMaxRepairVirDB.Load(VIRUS_DB_REPAIR))
	{
		m_bRepairDBLoaded = true;
	}
	/*------------------------------------------END-------------------------------*/

	return dwRetValue;
}

/*-------------------------------------------------------------------------------------
	Function		: AndroidDBLoadThread
	In Parameters	: 
	Out Parameters	: Total Signature Count
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Launched thread to load Android DB.
--------------------------------------------------------------------------------------*/
DWORD WINAPI AndroidDBLoadThread(LPVOID lpParam)
{
	CScanManager	*pThisClass = (CScanManager	*)lpParam;
	DWORD			dwRetValue = 0x00;

	dwRetValue = pThisClass->LoadAndroidDBs();

	return dwRetValue;
}

/*-------------------------------------------------------------------------------------
	Function		: LaunchAndroidDBLaodingThread
	In Parameters	: 
	Out Parameters	: 1 if Success else 0
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Launched thread to load Android DB.
--------------------------------------------------------------------------------------*/
DWORD	CScanManager::LaunchAndroidDBLaodingThread()
{
	DWORD	dwRetValue = 0x00;
	DWORD	dwTdreadID = 0x00;

	m_hAndroidDBThread = NULL;
	m_hAndroidDBThread = CreateThread(NULL,0,AndroidDBLoadThread,(LPVOID)this,0,&dwTdreadID);
	if (AndroidDBLoadThread != NULL)
	{
		dwRetValue = 0x01;
	}

	return dwRetValue;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanFullFile4Yara
	In Parameters	: 
	Out Parameters	: true if Success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Full binary file scanner for YAYA DB
--------------------------------------------------------------------------------------*/
bool CScanManager::ScanFullFile4YaraWithExp(CMaxPEFile *pMaxPEFile)
{
	bool		bVirusFound = false;
	
	CMaxExceptionFilter::InitializeExceptionFilter();
	__try
	{
		bVirusFound = ScanFullFile4Yara(pMaxPEFile);

	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception Cought :: Max Yara Scanner")))
	{
	}
	
	return bVirusFound;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanFullFile4Yara
	In Parameters	: 
	Out Parameters	: true if Success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Full binary file scanner for YAYA DB
--------------------------------------------------------------------------------------*/
bool CScanManager::ScanFullFile4Yara(CMaxPEFile *pMaxPEFile)//, CScanFileManager *pScanFileMgr)
{
	bool		bVirusFound = false;
	

	if (pMaxPEFile == NULL)
	{
		return bVirusFound;	
	}

	if (pMaxPEFile->m_dwFileSize > (1024 * 1024 * 35))
	{
		return bVirusFound;
	}

	CMaxYara	objYaraScanMgr(pMaxPEFile);
	//objYaraScanMgr.GetIMPHashforYARA(); 
	if (objYaraScanMgr.ScanFile(&m_YaraTree))
	{
		return true;
	}
	
	return bVirusFound;
}
	
/*-------------------------------------------------------------------------------------
	Function		: ScanFullFile4Yara
	In Parameters	: 
	Out Parameters	: true if Success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Full binary file scanner for YAYA DB
--------------------------------------------------------------------------------------*/
bool CScanManager::GetIMPHashforYARA(CMaxPEFile *pMaxPEFile,char *szImpHash)
{
	bool		bReturn = false;
	try
	{
		typedef struct _MAX_IMP_TABLE_STRUCT
		{
			DWORD	dwNameTableRVA;
			DWORD	dwTimeStamp;
			DWORD	dwFwrdChain;
			DWORD	dwNameRVA;
			DWORD	dwAddTableRVA;
		}MAX_IMP_TABLE_STRUCT,*LPMAX_IMP_TABLE_STRUCT;
		
		typedef struct _MAX_NAME_TABLE_STRUCT
		{
			WORD	wHint;
			char	szData[MAX_PATH];
		}MAX_NAME_TABLE_STRUCT;

		if (szImpHash)
		{
			strcpy(szImpHash,"");
		}

		if (pMaxPEFile == NULL)
		{
			return bReturn;	
		}

		if (pMaxPEFile->m_bPEFile == false)
		{
			return bReturn;
		}

		DWORD	dwIMPTableRVA = 0x00, dwIMPTableOffset = 0x00, dwIMPTableSize = 0x00;
		DWORD	dwEntryCnt = 0x00;

		dwIMPTableRVA = pMaxPEFile->m_stPEHeader.DataDirectory[0x01].VirtualAddress; 
		dwIMPTableSize = pMaxPEFile->m_stPEHeader.DataDirectory[0x01].Size;

		if ((dwIMPTableSize % 20) != 0x00)
		{
			return bReturn;
		}

		dwEntryCnt = dwIMPTableSize / 20;

		if (dwEntryCnt == 0x00)
		{
			return bReturn;
		}

		//MAX_IMP_TABLE_STRUCT	objImpTable[dwEntryCnt] = {0x00};
		MAX_IMP_TABLE_STRUCT	*pImpTable = NULL;

		pImpTable = new MAX_IMP_TABLE_STRUCT[dwEntryCnt];

		pMaxPEFile->Rva2FileOffset(dwIMPTableRVA,&dwIMPTableOffset);

		if (dwIMPTableOffset == 0x00 || dwIMPTableOffset >= pMaxPEFile->m_dwFileSize)
		{
			return bReturn;
		}

		if (!pMaxPEFile->ReadBuffer((LPVOID)pImpTable,dwIMPTableOffset,dwIMPTableSize,dwIMPTableSize))
		{
			return bReturn;
		}

		char	szIMPHashBuff[5120] = {0x00};

		
		for (int i = 0x00; i < dwEntryCnt; i++)
		{
			DWORD	dwFileOffset = 0x00;
			char	szDllName[MAX_PATH] = {0x00};
			
			pMaxPEFile->Rva2FileOffset(pImpTable[i].dwNameRVA ,&dwFileOffset);
			
			if (pImpTable[i].dwNameRVA != 0x00 && dwFileOffset < pMaxPEFile->m_dwFileSize)
			{
				strcpy(szDllName,"");

				pMaxPEFile->ReadBuffer(&szDllName[0x00],dwFileOffset,MAX_PATH,5);
				strlwr(szDllName);

				char	*pTemp = NULL;
				pTemp = strstr(szDllName,".dll");
				if (pTemp)
				{
					*pTemp = '\0';
					pTemp = NULL;
				}

				if (strlen(szDllName) > 0x00)
				{
					dwFileOffset = 0x00;
					pMaxPEFile->Rva2FileOffset(pImpTable[i].dwNameTableRVA ,&dwFileOffset);
					if (pImpTable[i].dwNameTableRVA != 0x00 && dwFileOffset < pMaxPEFile->m_dwFileSize)
					{
						while(1)
						{
							DWORD					dwAPIRVA = 0x00,dwAPIOffset = 0x00;
							MAX_NAME_TABLE_STRUCT	objNMTable = {0x00};

							if (!pMaxPEFile->ReadBuffer(&dwAPIRVA,dwFileOffset,sizeof(DWORD),sizeof(DWORD)))
							{
								break;
							}
							pMaxPEFile->Rva2FileOffset(dwAPIRVA ,&dwAPIOffset);

							if (dwAPIRVA == 0x00 || dwAPIOffset == 0x00)
							{
								break;
							}

							dwFileOffset += sizeof(DWORD);
							if (dwAPIOffset < pMaxPEFile->m_dwFileSize)
							{
								pMaxPEFile->ReadBuffer(&objNMTable,dwAPIOffset,sizeof(MAX_NAME_TABLE_STRUCT),5);
								strlwr(objNMTable.szData);
								if (strlen(objNMTable.szData) > 0x00)
								{
									char szName2Append[MAX_PATH] = {0x00};
									sprintf(szName2Append,"%s.%s",szDllName,objNMTable.szData);
									if (strlen(szIMPHashBuff) > 0x00)
									{
										strcat(szIMPHashBuff,",");
									}
									strcat(szIMPHashBuff,szName2Append);
								}
							}
							else
							{
								break;
							}
						}
					}
				}
			}

		}

		DWORD	dwBuffLen = 0x00;
		dwBuffLen = strlen(szIMPHashBuff);
		if (dwBuffLen > 0x00)
		{
			CMaxMD5	objMD5;
			if (szImpHash)
			{
				strcpy(szImpHash,objMD5.digestString((BYTE *)&szIMPHashBuff[0x00],dwBuffLen * sizeof(char)));
				bReturn = true;
			}
		}
	}
	catch(...)
	{
		
	}

	return bReturn;
}