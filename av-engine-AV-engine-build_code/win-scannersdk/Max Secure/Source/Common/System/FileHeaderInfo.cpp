/*=============================================================================
   FILE			: FileHeaderInfo.cpp
   ABSTRACT		: Reads the PE header 
   DOCUMENTS	: 
   AUTHOR		: 
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 20/09/2006
   NOTES		:
VERSION HISTORY	: 06 Jan 2008, Nupur : This file will read the ascii CRC values.  
============================================================================*/

#include "StdAfx.h"
#include "FileHeaderInfo.h"

#include <direct.h>
#include <math.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

typedef int( far _cdecl * GETSIGINFO ) ( unsigned int , WCHAR * , unsigned char * , unsigned char * , unsigned char * , unsigned char * ,
									 unsigned char * , unsigned char * , unsigned char * , unsigned char * , int * , LARGE_INTEGER * , 
									 LARGE_INTEGER * , int * , int * , unsigned char *, int) ;

GETSIGINFO GetSignatureInfo = NULL;

#define	FEATURE_32BIT_EXEC_PATH		1
#define	FEATURE_16BIT_EXEC_PATH		4
#define	FEATURE_GET_FILE_LENGTH		8
#define FEATURE_ONLY_OP_CODE		16	//000 - 10000
#define FEATURE_32_BYTES_LENGTH		32	//001 - 00000
#define FEATURE_64_BYTES_LENGTH		64	//010 - 00000

#define	FEATURES_ALL				FEATURE_32BIT_EXEC_PATH + FEATURE_16BIT_EXEC_PATH + FEATURE_GET_FILE_LENGTH
#define	FEATURES_MIN_REQUIRED		FEATURE_32BIT_EXEC_PATH + FEATURE_GET_FILE_LENGTH + FEATURE_ONLY_OP_CODE + FEATURE_32_BYTES_LENGTH

//WCHAR ExecExtension[13][5] =
//{
//	{ L".EXE" } , { L".DLL" } , { L".OCX" } , { L".SYS" } , { L".CPL" } ,
//	{ L".SCR" } , { L".VXD" } , { L".COM" } , { L".BIN" } , { L".386" } ,
//	{ L".OVL" } , { L".OVR" } , { L".PIF" }
//};

/*-------------------------------------------------------------------------------------
	Function		: Malloc
	In Parameters	: int 
	Out Parameters	: 
	Purpose			: Global memory allocation
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void *Malloc(int Size)
{
	HGLOBAL Ptr;
	Ptr = GlobalAlloc(GMEM_FIXED, Size);
	return(Ptr);
}

/*-------------------------------------------------------------------------------------
	Function		: Free
	In Parameters	: int 
	Out Parameters	: 
	Purpose			: Deallocates global memory.
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void Free(void *Ptr)
{ 
	GlobalFree((HGLOBAL *)Ptr);
}

/*-------------------------------------------------------------------------------------
	Function		: CopyStringToWCHAR
	In Parameters	: WCHAR* ,  const TCHAR *
	Out Parameters	: 
	Purpose			: Converts TCHAR to WCHAR
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CopyStringToWCHAR(WCHAR *wsString, const TCHAR *csStringToCopy)
{
	for(unsigned int i = 0; i < wcslen(csStringToCopy); i++)
	{
		wsString[i] = (WCHAR) csStringToCopy[i];
	}
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: IsExecutableExtension
	In Parameters	: WCHAR 
	Out Parameters	: int
	Purpose			: Checks for Executable files.
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
//int IsExecutableExtension(WCHAR *FullFilePathWithWildCard)
//{
//	WCHAR *ExtPtr;
//	INT i;
//
//	ExtPtr = wcsrchr(FullFilePathWithWildCard , '.');
//	if(ExtPtr != NULL)
//	{
//		for(i = 0; i < 13; i++)
//		{
//			if(_wcsicmp(ExtPtr, ExecExtension[i]) == 0)
//				return i;
//		}
//	}
//	return -1;
//}

/*-------------------------------------------------------------------------------------
	Function		: IsGoodCRC
	In Parameters	: CStringA,  int
	Out Parameters	: inline bool
	Purpose			: Checks for NULL block CRC Signatures.
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
inline bool IsGoodCRC(LPBYTE lpCRCValue, int iSizeOfBlock)
{
	if((iSizeOfBlock == 2048) && (memcmp(lpCRCValue, NULL_CRC_VALUE_2048_SIZE, 8)))
		return true;
	if((iSizeOfBlock == 1024) && (memcmp(lpCRCValue, NULL_CRC_VALUE_1024_SIZE, 8)))
		return true;
	if((iSizeOfBlock == 512) && (memcmp(lpCRCValue, NULL_CRC_VALUE_512_SIZE, 8)))
		return true;
	if((iSizeOfBlock == 256) && (memcmp(lpCRCValue, NULL_CRC_VALUE_256_SIZE, 8)))
		return true;
	if((iSizeOfBlock == 128) && (memcmp(lpCRCValue, NULL_CRC_VALUE_128_SIZE, 8)))
		return true;
	if((iSizeOfBlock == 64) && (memcmp(lpCRCValue, NULL_CRC_VALUE_64_SIZE, 8)))
		return true;
	if((iSizeOfBlock == 32) && (memcmp(lpCRCValue, NULL_CRC_VALUE_32_SIZE, 8)))
		return true;
	if((iSizeOfBlock == 16) && (memcmp(lpCRCValue, NULL_CRC_VALUE_16_SIZE, 8)))
		return true;
	if((iSizeOfBlock == 8) && (memcmp(lpCRCValue, NULL_CRC_VALUE_8_SIZE, 8)))
		return true;

	if(!memcmp(lpCRCValue, NULL_CRC_VALUE_0_SIZE, 8))
		return false;

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _GetCRCValue
	In Parameters	: CFile,  int, LPBYTE
	Out Parameters	: bool
	Purpose			: Gets CRC value of a given file
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CFileHeaderInfo::_GetCRCValue(CFile &oFile, int iDataSize, LPBYTE lpCRCValue)
{
	if(oFile.GetPosition() >= oFile.GetLength())
		return false;

	char *strBigBuffer = new char[iDataSize+1];
	ZeroMemory(strBigBuffer, iDataSize+1);
	int iDataRead = oFile.Read(strBigBuffer, iDataSize);
	if(iDataRead != iDataSize) // if not enough data read from file, return empty signature!
	{
		delete [] strBigBuffer;
		return false;
	}

	if(m_objCrc64.GetCRC8Byte((UCHAR*)strBigBuffer, iDataSize, lpCRCValue, 8))
	{
		if(IsGoodCRC(lpCRCValue, iDataSize))
		{
			delete [] strBigBuffer;
			return true;
		}
	}
	delete [] strBigBuffer;
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CFileHeaderInfo
	In Parameters	:  
	Out Parameters	: 
	Purpose			: Constructor
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CFileHeaderInfo::CFileHeaderInfo(void):m_objDatabase(false)
{
	m_hDisasmEngineDll = NULL;
	GetSignatureInfo   = NULL;
	m_bImportDBLoaded = false;

	m_hDisasmEngineDll = LoadLibrary(_T("DisasmEngineDll.dll"));
	if(m_hDisasmEngineDll == NULL)
		AddLogEntry(_T("In CFileHeaderInfo::CFileHeaderInfo Could not load DisasmEngineDll.dll"));

	if(m_hDisasmEngineDll)
		GetSignatureInfo = (GETSIGINFO)GetProcAddress(m_hDisasmEngineDll, LPCSTR("GetSignatureInformationNew"));

	if(GetSignatureInfo == NULL)
		AddLogEntry(_T("In CFileHeaderInfo::CFileHeaderInfo Could not locate function GetSignatureInfo"));

	m_MD5Signature = (unsigned char *)Malloc(16);
	m_ExecPathCrc = (unsigned char *)Malloc(8);
	m_ExecWidthCrc = (unsigned char *)Malloc(8);
	m_ExecPath = (unsigned char *)Malloc(4096);
	m_ExecWidth = (unsigned char *)Malloc(4096);
	m_Exec16Path = (unsigned char *)Malloc(4096);
	m_Exec16Width = (unsigned char *)Malloc(4096);
	m_DOSHeader = (unsigned char *)Malloc ( sizeof ( PMS_IMAGE_DOS_HEADER ) ) ;
	m_ExtendedHeader = (unsigned char *)Malloc ( sizeof ( PMS_IMAGE_FILE_HEADER ) ) ;
	m_OptionalHeader = (unsigned char *)Malloc ( sizeof ( PMS_IMAGE_OPTIONAL_HEADER ) ) ;
	m_SectionHeader = (unsigned char *)Malloc ( sizeof ( PMS_IMAGE_SECTION_HEADER ) * MAX_NO_OF_SECTIONS ) ;
	m_ImportDirectoryTable = (unsigned char *)Malloc ( sizeof ( PMS_IMAGE_IMPORT_DIRECTORY_TABLE ) * MAX_NO_OF_IMPORT_DIR_TABLE ) ;
	m_FullFilePathWithWildCard = (WCHAR *)Malloc ( 4096 * 2 ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CFileHeaderInfo
	In Parameters	:  
	Out Parameters	: 
	Purpose			: destructor
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CFileHeaderInfo::~CFileHeaderInfo(void)
{
	if(m_hDisasmEngineDll)
		FreeLibrary(m_hDisasmEngineDll);

	Free ( m_MD5Signature );
	Free ( m_ExecPathCrc );
	Free ( m_ExecWidthCrc );
	Free ( m_FullFilePathWithWildCard );
	Free ( m_SectionHeader ) ;
	Free ( m_OptionalHeader ) ;
	Free ( m_ExtendedHeader ) ;
	Free ( m_DOSHeader ) ;
	Free ( m_ExecWidth ) ;
	Free ( m_ExecPath ) ;
	Free ( m_Exec16Path ) ;
	Free ( m_Exec16Width ) ;
	Free ( m_ImportDirectoryTable ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: IsInitialized
	In Parameters	:  
	Out Parameters	: bool
	Purpose			: Checks for DisasmEngineDll.dll initialization
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CFileHeaderInfo::IsInitialized()
{
	return (m_hDisasmEngineDll && GetSignatureInfo);
}

bool CFileHeaderInfo::LoadDatabase(const CString &csDBFile, CString csLogFolderPath)
{
	m_bImportDBLoaded = false;
	m_pLogFile = NULL;
	if(!m_objDatabase.Load(csDBFile))
	{
		OutputDebugString(_T("Failed to load DB: ") + csDBFile);
		return false;
	}

	m_pLogFile = new CFile();
	m_pLogFile->Open(csLogFolderPath + _T("\\MissingDLL.Log"), CFile::modeCreate | CFile::modeWrite | CFile::shareDenyNone);

	m_bImportDBLoaded = true;
	return true;
}

bool CFileHeaderInfo::UnLoadDatabase()
{
	if(m_bImportDBLoaded)
	{
		m_objDatabase.RemoveAll();
		m_pLogFile->Close();
		delete m_pLogFile;
		m_pLogFile = NULL;
		m_bImportDBLoaded = false;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetFileHeaderInfo
	In Parameters	: const TCHAR *,  bool
	Out Parameters	: bool
	Purpose			: Initializes PE header Info for a given file
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CFileHeaderInfo::GetFileHeaderInfo(const TCHAR *sFileName, bool bCheckNullExec, int iExecutableType)
{
	m_EntryPoint.QuadPart = 0;
	m_iInternalFileType = 0;
	m_iFileLength.QuadPart = 0;
	m_iEntryPointSectionNumber = -1;
	m_iNewEntryPointSectionNumber = -1;

	memset(m_MD5Signature, 0, 16);
	memset(m_ExecPathCrc, 0, 8);
	memset(m_ExecWidthCrc, 0, 8);
	memset(m_ExecPath, 0, 4096);
	memset(m_ExecWidth, 0, 4096);
	memset(m_Exec16Path, 0, 4096);
	memset(m_Exec16Width, 0, 4096);
	memset(m_FullFilePathWithWildCard, 0, 4096 * 2);
	memset(m_DOSHeader , 0 , sizeof ( PMS_IMAGE_DOS_HEADER ) ) ;
	memset(m_ExtendedHeader , 0 , sizeof ( PMS_IMAGE_FILE_HEADER ) ) ;
	memset(m_OptionalHeader , 0 , sizeof ( PMS_IMAGE_OPTIONAL_HEADER ) ) ;
	memset(m_SectionHeader , 0 , sizeof ( PMS_IMAGE_SECTION_HEADER ) * MAX_NO_OF_SECTIONS ) ;
	memset(m_ImportDirectoryTable , 0 , sizeof ( PMS_IMAGE_IMPORT_DIRECTORY_TABLE ) * MAX_NO_OF_IMPORT_DIR_TABLE ) ;

	m_sFileName = (TCHAR*)sFileName;
	CopyStringToWCHAR(m_FullFilePathWithWildCard, sFileName);

	GetSignatureInfo(FEATURES_MIN_REQUIRED, m_FullFilePathWithWildCard, m_ExecPath, m_ExecWidth, 
					m_Exec16Path, m_Exec16Width, m_DOSHeader, m_ExtendedHeader, m_OptionalHeader, 
					m_SectionHeader, &m_iInternalFileType, &m_EntryPoint, &m_iFileLength, 
					&m_iEntryPointSectionNumber, &m_iNewEntryPointSectionNumber, m_MD5Signature, iExecutableType);

	m_pDosHeader =  (PMS_IMAGE_DOS_HEADER *)m_DOSHeader;
	m_pOptionalHeader = (PMS_IMAGE_OPTIONAL_HEADER *)m_OptionalHeader;
	m_pSectionHeader = (PMS_IMAGE_SECTION_HEADER *)m_SectionHeader;
	m_pExtendedHeader = (PMS_IMAGE_FILE_HEADER *)m_ExtendedHeader;
	m_pDataDirectory = (PMS_IMAGE_DATA_DIRECTORY *)m_pOptionalHeader->DataDirectory;

	if(!m_pDosHeader || !m_pOptionalHeader || !m_pExtendedHeader || !m_pSectionHeader || !m_pDataDirectory)
	{
		OutputDebugString(L"##### GetSignatureInfo Failed!");
		return false;
	}

	if(bCheckNullExec)
	{
		if(m_pExtendedHeader->Machine == WIN_32_BIT_MACHINE_CODE)
		{
			m_objCrc64.GetCRC8Byte(m_ExecPath, strlen((const char*)m_ExecPath), m_ExecPathCrc, 8);
			m_objCrc64.GetCRC8Byte(m_ExecWidth, strlen((const char*)m_ExecWidth), m_ExecWidthCrc, 8);
		}
	}

	bool bCheckStatus = true; // always return true unless import check fails!

	if((m_pDataDirectory[DD_IMPORT_DIRECTORY_TABLE].VirtualAddress != 0) && (m_bImportDBLoaded))
	{
		CFile oFileRead;
		if(!oFileRead.Open(m_sFileName, CFile::modeRead | CFile::shareDenyNone))
			return false;

		long ulFileOffSet = _GetFileOffset(m_pDataDirectory[DD_IMPORT_DIRECTORY_TABLE].VirtualAddress);
		if(ulFileOffSet != -1)
		{
			//CString csTemp;
			//csTemp.Format(_T("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< Import Table FileName: %s\n"), csFileName);
			//OutputDebugString(csTemp);

			oFileRead.Seek(ulFileOffSet, 0);
			long iTableSize = (m_pDataDirectory[DD_IMPORT_DIRECTORY_TABLE].Size < (sizeof ( PMS_IMAGE_IMPORT_DIRECTORY_TABLE ) * MAX_NO_OF_IMPORT_TABLE_DATA)
								? m_pDataDirectory[DD_IMPORT_DIRECTORY_TABLE].Size : (sizeof ( PMS_IMAGE_IMPORT_DIRECTORY_TABLE ) * MAX_NO_OF_IMPORT_TABLE_DATA));

			oFileRead.Read(m_ImportDirectoryTable, iTableSize);
			m_pImportDirectoryTable = (PMS_IMAGE_IMPORT_DIRECTORY_TABLE *)m_ImportDirectoryTable;

			int iCnt = 0;
			do
			{
				BYTE Buffer[50] = {0};
				char *cDllName = NULL;
				ulFileOffSet = _GetFileOffset(m_pImportDirectoryTable[iCnt].NameRVA);
				if(ulFileOffSet == -1)
				{
					//OutputDebugString(_T("##### Invalid File Offset\n"));
					break;
				}
				oFileRead.Seek(ulFileOffSet, 0);
				oFileRead.Read(Buffer, 50);
				cDllName = (char*)Buffer;
				CStringA csTempA(cDllName);

				CString csDllName(csTempA);
				csDllName.MakeLower();
				LPTSTR lstrValue = NULL;
				if(!m_objDatabase.SearchItem(csDllName, lstrValue))
				{
					if(csDllName.Find(_T(".")) == -1)
					{
						csDllName += _T(".dll");
						if(m_objDatabase.SearchItem(csDllName, lstrValue))	// found after adding .dll to the name!
						{
							iCnt++;
							continue;
						}
					}

					CString csTemp;
					csTemp.Format(_T("%%%%% FileName: %s, Missing Import: %s"), m_sFileName, csDllName);
					OutputDebugString(csTemp);
					csTemp.Format(_T("FileName: %s, Missing Import: %s\r\n"), m_sFileName, csDllName);
					m_pLogFile->Write(csTemp, csTemp.GetLength());
					iCnt++;
					bCheckStatus = false;
					continue;
				}

				iCnt++;
			}while( m_pImportDirectoryTable[iCnt].NameRVA != 0 );
		}
		oFileRead.Close();
	}

	return bCheckStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: _GetFileOffset
	In Parameters	: unsigned long 
	Out Parameters	: 
	Purpose			: Return file offset for given Relative Virtual address.
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
long CFileHeaderInfo::_GetFileOffset(unsigned long ulRVA)
{
	int iSecNo = 0;
	for(; iSecNo < m_pExtendedHeader->NumberOfSections; iSecNo++)
	{
		long iSize = (m_pSectionHeader[iSecNo].SizeOfRawData == 0 ? m_pSectionHeader[iSecNo].Misc.VirtualSize : m_pSectionHeader[iSecNo].SizeOfRawData);
		if((ulRVA >= m_pSectionHeader[iSecNo].VirtualAddress) 
			&& (ulRVA < (m_pSectionHeader[iSecNo].VirtualAddress + iSize)))
			break;
	}

	if(iSecNo == m_pExtendedHeader->NumberOfSections)
		return -1;

	long iReturnValue = m_pSectionHeader[iSecNo].PointerToRawData + 
						(ulRVA - m_pSectionHeader[iSecNo].VirtualAddress);

	if(iReturnValue >= m_iFileLength.QuadPart)
		return -1;
	else
		return iReturnValue;
}

/*-------------------------------------------------------------------------------------
	Function		: GetExecWidthCRC
	In Parameters	:  
	Out Parameters	: CStringA
	Purpose			: Returns CRC signature of Execution Width
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
LPBYTE CFileHeaderInfo::GetExecWidthCRC()
{
	return m_ExecWidthCrc;
}

/*-------------------------------------------------------------------------------------
	Function		: GetExecPathCRC
	In Parameters	:  
	Out Parameters	: CStringA
	Purpose			: Returns CRC signature of Execution Path
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
LPBYTE CFileHeaderInfo::GetExecPathCRC()
{
	return m_ExecPathCrc;
}
/*-------------------------------------------------------------------------------------
	Function		: GetExecPathCRC
	In Parameters	:  
	Out Parameters	: CStringA
	Purpose			: Returns CRC signature of Execution Path
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/

LARGE_INTEGER CFileHeaderInfo::GetFileLength()
{
	return m_iFileLength;
}
/*-------------------------------------------------------------------------------------
	Function		: GetExecPathCRC
	In Parameters	:  
	Out Parameters	: CStringA
	Purpose			: Returns CRC signature of Execution Path
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
LPBYTE CFileHeaderInfo::GetMD5Signature()
{
	return m_MD5Signature;
}

/*-------------------------------------------------------------------------------------
	Function		: GetSectionSignature
	In Parameters	: int, int 
	Out Parameters	: bool
	Purpose			: Returns the CRC Signature of given file based on Group Type.
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CFileHeaderInfo::GetSectionSignature(int iGroupType, int iSizeOfBlock, LPBYTE lpCRCValue)
{
	if(iGroupType <= 0)
		return false;

	CFile oFile;
	if(!oFile.Open(m_sFileName, CFile::modeRead | CFile::shareDenyNone))
		return false;

	int iAOEPSectionNo = -1;
	if((iGroupType == 8) || (iGroupType == 9))
	{
		int iPos = (iGroupType == 8 ? m_pOptionalHeader->BaseOfCode : m_pOptionalHeader->BaseOfData);
		if((iPos > 0) && (iPos < m_iFileLength.QuadPart))
		{
			oFile.Seek(iPos, 0);
			if(_GetCRCValue(oFile, iSizeOfBlock, lpCRCValue))
			{
				oFile.Close();
				return true;
			}
		}
		oFile.Close();
		return false;
	}

	if(iGroupType == 3)
	{
		int iPos = _GetEndOfSectionsPos();
		if(iPos < m_iFileLength.QuadPart)
		{
			oFile.Seek(iPos, 0);
			if(_GetCRCValue(oFile, iSizeOfBlock, lpCRCValue))
			{
				oFile.Close();
				return true;
			}
		}
	}

	//Overlay data
	if(iGroupType == 10)
	{
		if((m_pOptionalHeader->SizeOfImage < m_iFileLength.QuadPart) && (m_pDataDirectory[DD_CERTIFICATE_TABLE].VirtualAddress == 0))
		{
			oFile.Seek(m_pOptionalHeader->SizeOfImage, 0);
			if(_GetCRCValue(oFile, iSizeOfBlock, lpCRCValue))
			{
				oFile.Close();
				return true;
			}
		}
	}

	// Overlay Last Block Data
	// Resource : Ritesh
	if(iGroupType == 12)		
	{
        LONGLONG iOverlayDataSize = m_iFileLength.QuadPart -  m_pOptionalHeader->SizeOfImage - m_pDataDirectory[DD_CERTIFICATE_TABLE].Size;
		if( iOverlayDataSize >= iSizeOfBlock ) //Overlay data size excluding Certificate
		{
			unsigned long  ulCertificateEndPos = (m_pDataDirectory[DD_CERTIFICATE_TABLE].Size + m_pDataDirectory[DD_CERTIFICATE_TABLE].VirtualAddress) ;
			unsigned long  ulCertificateStartPos = m_pDataDirectory[DD_CERTIFICATE_TABLE].VirtualAddress ;

			//When certificate does not exist in overlay
			if((m_pDataDirectory[DD_CERTIFICATE_TABLE].VirtualAddress == 0) || 
			   (ulCertificateEndPos < m_pOptionalHeader->SizeOfImage))
				oFile.Seek(m_iFileLength.QuadPart - iSizeOfBlock, 0);
			else 
			{				
				if( m_iFileLength.QuadPart == ulCertificateEndPos ) //Certificate is in the end
					oFile.Seek( ulCertificateStartPos - iSizeOfBlock , 0 ) ;
				else if( ulCertificateStartPos ==  m_pOptionalHeader->SizeOfImage) //certificate is in begining
					oFile.Seek( m_iFileLength.QuadPart - iSizeOfBlock , 0 ) ;
				else if(m_iFileLength.QuadPart - ulCertificateEndPos > iSizeOfBlock) //Certificate is in between
					oFile.Seek(m_iFileLength.QuadPart - iSizeOfBlock, 0);
			}

			if(_GetCRCValue(oFile, iSizeOfBlock, lpCRCValue))
			{
				oFile.Close();
				return true;
			}
		}
	}

	// After Header And Last Overlay 
	// Resource : Amrita
	if(iGroupType == 14)
	{
		oFile.Seek( m_pOptionalHeader->SizeOfHeaders , 0 ) ;
		if(_GetCRCValue(oFile, iSizeOfBlock, lpCRCValue))
		{
			bool bGoodSig = true;
			if(!memcmp(lpCRCValue, INVALID_TYPE_14_CRCVALUE, 8))
			{
				oFile.Seek(m_iFileLength.QuadPart - iSizeOfBlock, 0 );
				bGoodSig = _GetCRCValue(oFile, iSizeOfBlock, lpCRCValue);
			}
			if(!bGoodSig)
				bGoodSig = _GetCorruptSectionCrcNew(oFile, iSizeOfBlock, lpCRCValue);				

			oFile.Close();
			return bGoodSig;
		}
	}

	// Overlay And Last Section Data
	// Resource : Amrita
	if(iGroupType == 15)
	{		
		int iPos = 0 ;
		LONGLONG iOverlaySz = m_iFileLength.QuadPart -  m_pOptionalHeader->SizeOfImage ;
		if ( ( iOverlaySz >= iSizeOfBlock )  && ( m_pDataDirectory[DD_CERTIFICATE_TABLE].VirtualAddress == 0 ) )
			iPos = m_pOptionalHeader->SizeOfImage ;
		else
			iPos = m_pOptionalHeader->SizeOfHeaders ;

		oFile.Seek( iPos , 0 ) ;
		if(_GetCRCValue(oFile, iSizeOfBlock, lpCRCValue))
		{
			bool bGoodSig = true;
			if(!memcmp(lpCRCValue, INVALID_TYPE_15_CRCVALUE, 8))
			{
				int iLastPos = _GetLastSectionsPos(iSizeOfBlock);
				oFile.Seek(iLastPos , 0);
				bGoodSig = _GetCRCValue(oFile, iSizeOfBlock, lpCRCValue);
			}
			if(bGoodSig)
			{
				oFile.Close();
				return true;
			}
		}
	}

	if((iGroupType == 1) || (iGroupType == 3))
		iAOEPSectionNo = _GetSectionNumberByAddOfEntryPt();
	else if((iGroupType == 2))
		iAOEPSectionNo = _GetSectionNoOfResourceTable();
	else if(iGroupType == 4)
		iAOEPSectionNo = _GetSectionNoOfRelocationTable();
	else if(iGroupType == 5)
		iAOEPSectionNo = _GetSectionNumberByVirtualAddress(m_pOptionalHeader->BaseOfCode, iSizeOfBlock);
	else if(iGroupType == 6)
		iAOEPSectionNo = _GetSectionNumberByVirtualAddress(m_pOptionalHeader->BaseOfData, iSizeOfBlock);
	else if((iGroupType == 7) || (iGroupType == 10) || (iGroupType == 15))
	{
		bool bGoodSig = _GetCorruptSectionCrcNew(oFile, iSizeOfBlock, lpCRCValue);
		oFile.Close();
		return bGoodSig;
	}
	// Last Section Data
	// Resource : Ritesh
	else if(iGroupType == 11)					
	{
		iAOEPSectionNo = m_pExtendedHeader->NumberOfSections - 1 ;
	}
	// Last Section Last Block Data
	// Resource : Amrita
	else if(iGroupType == 17)	
	{
		int iLastSecLastpos = _GetEndOfSectionsPos() - iSizeOfBlock;	
		oFile.Seek( iLastSecLastpos, 0 ); 
		if(_GetCRCValue(oFile, iSizeOfBlock, lpCRCValue))
		{
			oFile.Close();
			return true;
		}
	}
	// AfterHeaderSecondBlockData 
	// Resource : Amrita
	else if(iGroupType == 13) 
	{		
		oFile.Seek( m_pOptionalHeader->SizeOfHeaders + iSizeOfBlock, 0 ); 
		if(_GetCRCValue(oFile, iSizeOfBlock, lpCRCValue))
		{
			oFile.Close();
			return true;
		}
	}
	// AfterHeaderThirdBlockData
	// Resource : Amrita
	else if(iGroupType == 16) 
	{		
		oFile.Seek( m_pOptionalHeader->SizeOfHeaders + ( 2 * iSizeOfBlock), 0 ); 
		if(_GetCRCValue(oFile, iSizeOfBlock, lpCRCValue))
		{
			oFile.Close();
			return true;
		}
	}

	// After this we must have a valid section number to proceed further!
	if((iAOEPSectionNo == -1) || (!_ValidateSectionInfo(iAOEPSectionNo, iSizeOfBlock)))
		return false;

	int iTotalNoOfBlocks = (m_pSectionHeader[iAOEPSectionNo].SizeOfRawData/iSizeOfBlock);
	int iBlockNo = 0;

	oFile.Seek(m_pSectionHeader[iAOEPSectionNo].PointerToRawData, 0);

	for(; iBlockNo < iTotalNoOfBlocks; iBlockNo++)
	{
		if(_GetCRCValue(oFile, iSizeOfBlock, lpCRCValue))
		{
			oFile.Close();
			return true;
		}
	}

	oFile.Close();
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _GetSectionNumberByAddOfEntryPt
	In Parameters	:  
	Out Parameters	: int
	Purpose			: Returns section number ciontaining address of entry point.
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
int CFileHeaderInfo::_GetSectionNumberByAddOfEntryPt()
{
	return (m_iNewEntryPointSectionNumber == -1 ? m_iEntryPointSectionNumber : m_iNewEntryPointSectionNumber);
}

/*-------------------------------------------------------------------------------------
	Function		: _GetCorruptSectionCrcNew
	In Parameters	: CFile,  unsigned int
	Out Parameters	: CStringA
	Purpose			: Return CRC of valid 512 byte block after the optional header.
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CFileHeaderInfo::_GetCorruptSectionCrcNew(CFile &oFile, unsigned int iSizeOfBlock, LPBYTE lpCRCValue)
{
	int iFileOffset = (m_pOptionalHeader->SizeOfHeaders == 0 ? m_pDosHeader->e_cparhdr : m_pOptionalHeader->SizeOfHeaders);
	int iTotalNoOfBlocks = static_cast<int>((m_iFileLength.QuadPart-iFileOffset)/iSizeOfBlock);
	int iBlockNo = 0;

	if(iFileOffset < 0)
		return false;

	oFile.Seek(iFileOffset, 0);
	for(; iBlockNo < iTotalNoOfBlocks; iBlockNo++)
	{
		if(_GetCRCValue(oFile, iSizeOfBlock, lpCRCValue))
		{
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _ValidateSectionInfo
	In Parameters	: int, int
	Out Parameters	: bool
	Purpose			: Checks for section validity.
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CFileHeaderInfo::_ValidateSectionInfo(int iSectionNo, int iSizeOfBlock)
{
	if(iSectionNo > m_pExtendedHeader->NumberOfSections)
		return false;

	if((m_pSectionHeader[iSectionNo].PointerToRawData == 0) || (m_pSectionHeader[iSectionNo].SizeOfRawData == 0))
		return false;

	if((static_cast<__int64>(m_pSectionHeader[iSectionNo].PointerToRawData) > m_iFileLength.QuadPart)
		|| (static_cast<__int64>(m_pSectionHeader[iSectionNo].SizeOfRawData) > m_iFileLength.QuadPart)
		|| (m_pSectionHeader[iSectionNo].SizeOfRawData < static_cast<unsigned long>(iSizeOfBlock)))
		return false;
	else
		return true;
}

/*-------------------------------------------------------------------------------------
	Function		: _GetEndOfSectionsPos
	In Parameters	: - 
	Out Parameters	: int
	Purpose			: Returns the address of end of last section 
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
int CFileHeaderInfo::_GetEndOfSectionsPos()
{
	if(m_pExtendedHeader->NumberOfSections <= 0)
		return static_cast<int>(m_iFileLength.QuadPart);

	int iSecNo = m_pExtendedHeader->NumberOfSections - 1;
    int iPos = m_pSectionHeader[iSecNo].SizeOfRawData + m_pSectionHeader[iSecNo].PointerToRawData;
	return iPos;
}

/*-------------------------------------------------------------------------------------
	Function		: _GetSectionNumberByVirtualAddress
	In Parameters	: unsigned long int,  unsigned int
	Out Parameters	: int
	Purpose			: Returns section number of section containing the give virtual address.
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
int CFileHeaderInfo::_GetSectionNumberByVirtualAddress(unsigned long int uliVirtualAddress, unsigned int iSizeOfBlocks)
{
	int iSecNo = -1;
	if(uliVirtualAddress == 0)
		return -1;

	for(int iCtr = 0 ; iCtr < m_pExtendedHeader->NumberOfSections; iCtr++ )
	{
		if((m_pSectionHeader[iCtr].VirtualAddress == uliVirtualAddress) &&
			(m_pSectionHeader[iCtr].SizeOfRawData >= iSizeOfBlocks))
		{
			iSecNo = iCtr;
			break;
		}
	}
	return iSecNo;
}

/*-------------------------------------------------------------------------------------
	Function		: _GetSectionNoOfRelocationTable
	In Parameters	: - 
	Out Parameters	: int
	Purpose			: Returns the section number of the section containing Relocation Table
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
int CFileHeaderInfo::_GetSectionNoOfRelocationTable()
{
	unsigned long ulRVA = m_pDataDirectory[DD_RELOCATION_TABLE].VirtualAddress;

	if(ulRVA == 0) return -1;

	int iSecNo = 0;
	for(; iSecNo < m_pExtendedHeader->NumberOfSections; iSecNo++)
	{
		long iSize = (m_pSectionHeader[iSecNo].SizeOfRawData == 0 ? m_pSectionHeader[iSecNo].Misc.VirtualSize : m_pSectionHeader[iSecNo].SizeOfRawData);
		if((ulRVA >= m_pSectionHeader[iSecNo].VirtualAddress) 
			&& (ulRVA < (m_pSectionHeader[iSecNo].VirtualAddress + iSize)))
			break;
	}
	if(iSecNo == m_pExtendedHeader->NumberOfSections)
		return -1;
	else
		return iSecNo;
}

/*-------------------------------------------------------------------------------------
	Function		: _GetSectionNoOfResourceTable
	In Parameters	: - 
	Out Parameters	: int 
	Purpose			: Returns the section number of the section containing Resource Table
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
int CFileHeaderInfo::_GetSectionNoOfResourceTable()
{
	unsigned long ulRVA = m_pDataDirectory[DD_RESOURCE_TABLE].VirtualAddress;

	if(ulRVA == 0) return -1;

	int iSecNo = 0;
	for(; iSecNo < m_pExtendedHeader->NumberOfSections; iSecNo++)
	{
		long iSize = (m_pSectionHeader[iSecNo].SizeOfRawData == 0 ? m_pSectionHeader[iSecNo].Misc.VirtualSize : m_pSectionHeader[iSecNo].SizeOfRawData);
		if((ulRVA >= m_pSectionHeader[iSecNo].VirtualAddress) 
			&& (ulRVA < (m_pSectionHeader[iSecNo].VirtualAddress + iSize)))
			break;
	}
	if(iSecNo == m_pExtendedHeader->NumberOfSections)
		return -1;
	else
		return iSecNo;
}

/*-------------------------------------------------------------------------------------
	Function		: _GetLastSectionsPos
	In Parameters	: int iSizeOfBlock
	Out Parameters	: int 
	Purpose			: Returns the Starting position of the Last section
	Author			: Amrita
--------------------------------------------------------------------------------------*/
int CFileHeaderInfo::_GetLastSectionsPos(int iSizeOfBlock)
{
	if(m_pExtendedHeader->NumberOfSections <= 0)
	{
		if(m_iFileLength.QuadPart > iSizeOfBlock)
			return static_cast<int>(m_iFileLength.QuadPart - iSizeOfBlock);
		else
			return 0;
	}
	int iSecNo = m_pExtendedHeader->NumberOfSections - 1;
	return m_pSectionHeader[iSecNo].PointerToRawData;
}