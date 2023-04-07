#include "StdAfx.h"
#include "CDataTypes.h"
#include "Packers.h"
#include "FileSignature.h"
#include "balbst.h"
#include <math.h>

const ULONG64 SIZE_LIMIT_FOR_MD5_IN_FULLSCAN = 1048576 * 5;			// 5 MB file size limit!
const ULONG64 SIZE_LIMIT_FOR_MD5_IN_DEEPSCAN = 1048576 * 15;		//15 MB file size limit!

const int iSizeOfBuffer = 65536;
unsigned char *g_buffer = NULL;
int MDFile(HANDLE hFile, BYTE *Signature, unsigned char *buffer, const int iSizeOfBuffer);
int MDFile15MBLimit(HANDLE hFile, BYTE *Signature, unsigned char *buffer, const int iSizeOfBuffer);

CFileSignature::CFileSignature(void)
{
	m_lpPEScannerSig = NULL;
	memset(&dwUnPackSuccess, 0, sizeof(DWORD) * PACKERS_COUNT);
	memset(&dwUnPackFailed, 0, sizeof(DWORD) * PACKERS_COUNT);
	g_buffer = new unsigned char[iSizeOfBuffer];
	GetTempPath(MAX_PATH, m_szTempFolderName);
}

CFileSignature::~CFileSignature(void)
{
	delete [] g_buffer;
	g_buffer = NULL;
}

int CFileSignature::CreateSignature(LPCTSTR cFullFileName, PESCANNERSIG &PEScannerSig, bool bDeepScan)
{
	m_iCurrentLevel = 0;
	m_bIsPacked = false;
	m_bIsValidPE = false;
	m_bHasPEHeader = false;
	m_eTopLevelPacker = eUNKNOWN;
	m_bSuccessfullyUnpacked = false;
	m_bTempFileCreated = false;
	m_hTempFile = INVALID_HANDLE_VALUE;
	m_bMD5Success = false;
	m_ulFileSize = 0;
	int iSignatureStatus = SIG_STATUS_NOT_PE_FILE;

	m_bDeepScan = bDeepScan;
	m_lpPEScannerSig = &PEScannerSig;
	GetUnPackedFile(cFullFileName);

	if(m_bIsValidPE)
	{
		iSignatureStatus = SIG_STATUS_PRIMARY_SIGNATURE_FAILED;
		DWORD dwPriSig = 0, dwSecSig = 0;
		if((m_iCurrentLevel != 0) && (m_bSuccessfullyUnpacked))
		{
			PESIG Signature = {0};
			iSignatureStatus = m_objPESignature.CreateSignature(m_szUnPackedFileName, m_ulFileSize, Signature, dwPriSig, dwSecSig);
			DeleteTempFile();
			switch(iSignatureStatus)
			{
			case SIG_STATUS_NOT_PE_FILE:
				dwUnPackFailed[ePESIGUNPACK]++;
				iSignatureStatus = SIG_STATUS_PRIMARY_SIGNATURE_FAILED; //to atleast add md5 in db
				break;
			case SIG_STATUS_PE_SUCCESS:
				{
					dwUnPackSuccess[ePESIGUNPACK]++;
					CreateCRC64Buffer(Signature.byPriSig, iMAX_PRI_SIG_LEN, m_lpPEScannerSig->ulPriSig);
					CreateCRC64Buffer(Signature.bySecSig, iMAX_SEC_SIG_LEN, m_lpPEScannerSig->ulSecSig);
					break;
				}
			case SIG_STATUS_PRIMARY_SIGNATURE_FAILED:
				dwUnPackFailed[ePESIGUNPACK]++;
				dwUnPackFailed[ePRISIG]++;
				break;
			case SIG_STATUS_SECONDARY_SIGNATURE_FAILED:
				dwUnPackFailed[ePESIGUNPACK]++;
				dwUnPackFailed[eSECSIG]++;
				break;
			}
		}

		// We will never create a PE signature of the packed file!
		if((iSignatureStatus != SIG_STATUS_PE_SUCCESS) && (!m_bIsPacked))
		{
			PESIG Signature = {0};
			iSignatureStatus = m_objPESignature.CreateSignature(cFullFileName, m_ulFileSize, Signature, dwPriSig, dwSecSig);
			switch(iSignatureStatus)
			{
			case SIG_STATUS_PE_SUCCESS:
				{
					dwUnPackSuccess[ePESIGMAIN]++;
					CreateCRC64Buffer(Signature.byPriSig, iMAX_PRI_SIG_LEN, m_lpPEScannerSig->ulPriSig);
					CreateCRC64Buffer(Signature.bySecSig, iMAX_SEC_SIG_LEN, m_lpPEScannerSig->ulSecSig);
					break;
				}
			case SIG_STATUS_PRIMARY_SIGNATURE_FAILED:
				dwUnPackFailed[ePESIGMAIN]++;
				dwUnPackFailed[ePRISIG]++;
				break;
			case SIG_STATUS_SECONDARY_SIGNATURE_FAILED:
				dwUnPackFailed[ePESIGMAIN]++;
				dwUnPackFailed[eSECSIG]++;
				break;
			}
		}
	}

	if((iSignatureStatus == SIG_STATUS_NOT_PE_FILE) && (m_bMD5Success))
	{
		iSignatureStatus = SIG_STATUS_MD5_SUCCESS;
	}

	//Helps in ignoring large files if we were not able to make a signature!
	if(bDeepScan)
	{
		m_lpPEScannerSig->bDeepScanDone = bDeepScan;		//even if md5 is not created we have done a deep scan of this file!
	}
	else
	{
		m_lpPEScannerSig->bDeepScanDone = m_bMD5Success;	//signatures successfully generated in full, deep not required!
	}

#ifdef _PE_FOR_PARSELOG_
	m_lpPEScannerSig->bHasPEHeader = m_bHasPEHeader;
	m_lpPEScannerSig->IsValidPE = m_bIsValidPE;
	m_lpPEScannerSig->bIsPacked = m_bIsPacked;
	m_lpPEScannerSig->wTopLevelPacker = m_eTopLevelPacker;
	m_lpPEScannerSig->bUnPackSuccess = (m_bIsPacked ? ((m_iCurrentLevel != 0) && m_bSuccessfullyUnpacked) : false); //unpacksuccess is only required if its a packed file!
	m_lpPEScannerSig->wNoOfUnpacks = m_iCurrentLevel;
	m_lpPEScannerSig->bPESigSuccess = ((iSignatureStatus == SIG_STATUS_PE_SUCCESS) ? true : false);
	m_lpPEScannerSig->iStatus = iSignatureStatus;
#endif //#ifdef _PE_FOR_PARSELOG_

	return iSignatureStatus;
}

void CFileSignature::GetUnPackedFile(LPCTSTR szFileName)
{
	bool bSuccess = false;
	m_ulFileSize = 0;
	m_dwNoOfSections = 0;

	m_bSuccessfullyUnpacked = false;
	m_hCurrentFile = INVALID_HANDLE_VALUE;

	if(!OpenFile(szFileName))
	{
		return;
	}

	if((m_iCurrentLevel == 0) && m_bDeepScan)	//Always Create MD5 incase of Deep scan
	{
		PrepareMD5Signature();
	}

	if(!LoadFilePEHeader())
	{
		CloseFile();
		if(m_iCurrentLevel == 0)
		{
			dwUnPackFailed[eVALIDPE]++;
		}
		else
		{
			dwUnPackFailed[eUNPACKED]++;
		}
		return;
	}
	if(m_iCurrentLevel == 0)
	{
		if(!m_bDeepScan)	//Create MD5 only if its a valid PE File
		{
			PrepareMD5Signature();
		}
		dwUnPackSuccess[eVALIDPE]++;
	}
	else
	{
		dwUnPackSuccess[eUNPACKED]++;
	}
	if(m_iCurrentLevel == 0)
	{
		m_bIsValidPE = true;
	}
	if(IsPackedFileHeuristically())
	{
		if(m_iCurrentLevel == 0)
		{
			m_bIsPacked = true;
		}

		dwUnPackSuccess[eHERUPACK]++;
		PACKERS_TYPE ePackerType = TryAllUnPacker();
		if(ePackerType == eUNKNOWN)
		{
			dwUnPackFailed[ePackerType]++;
			m_bSuccessfullyUnpacked = false;	// we dont have an unpacker! use the original file!
			CloseFile();						// try to use the last loaded pe header info
			DeleteTempFile();
		}
		else
		{
			CloseFile();						// try to use the last loaded pe header info
			CloseTempFile();

			if(ePackerType == eVALIDPE) // do we already have a valid pe file??
			{
				m_bSuccessfullyUnpacked = true;		// yes, we were able to unpack successfully!
			}
			else
			{
				if(m_iCurrentLevel == 0)
				{
					m_eTopLevelPacker = ePackerType;
				}
				dwUnPackSuccess[ePackerType]++;
				m_bSuccessfullyUnpacked = true;		// yes, we were able to unpack successfully!
				_tcscpy_s(m_szUnPackedFileName, m_szTempFileName);

				if(m_iCurrentLevel < MAX_RECURSION_LEVEL)	//recursive scan
				{
					m_iCurrentLevel++;
					GetUnPackedFile(m_szUnPackedFileName);
				}
			}
		}
		return;
	}
	else
	{
		dwUnPackFailed[eHERUPACK]++;
		//need this check incase of recursive unpacking, we may reach an unpacked file before the MAX_RECURSION_LEVEL!
		m_bSuccessfullyUnpacked = true;	// this file is a valid PE but not packed!
	}
	CloseFile(); // try to use the last loaded pe header info
	return;
}

void CFileSignature::PrepareMD5Signature()
{
#ifndef _PE_FOR_PARSELOG_ 
	if((m_ulFileSize <= SIZE_LIMIT_FOR_MD5_IN_FULLSCAN) || m_bDeepScan)
#endif
	{
		BYTE byMD5Sig[iMAX_MD5_SIG_LEN] = {0};
		::SetFilePointer(m_hCurrentFile, 0, NULL, FILE_BEGIN);
		MDFile15MBLimit(m_hCurrentFile, byMD5Sig, g_buffer, iSizeOfBuffer);
#ifdef _PE_FOR_PARSELOG_
		memcpy(m_lpPEScannerSig->byMD5Sig, byMD5Sig, iMAX_MD5_SIG_LEN);
		CreateCRC64Buffer(byMD5Sig, iMAX_MD5_SIG_LEN, m_lpPEScannerSig->ulMD5Sig15MB);
#else
		CreateCRC64Buffer(byMD5Sig, iMAX_MD5_SIG_LEN, m_lpPEScannerSig->ulMD5Sig);
#endif //#ifdef _PE_FOR_PARSELOG_
		::SetFilePointer(m_hCurrentFile, 0, NULL, FILE_BEGIN);

#ifdef _PE_FOR_PARSELOG_
		m_lpPEScannerSig->ulFileSize = m_ulFileSize;
		if(m_ulFileSize > SIZE_LIMIT_FOR_MD5_IN_DEEPSCAN)
		{
			MDFile(m_hCurrentFile, byMD5Sig, g_buffer, iSizeOfBuffer);
			memcpy(m_lpPEScannerSig->byMD5Sig, byMD5Sig, iMAX_MD5_SIG_LEN);
			CreateCRC64Buffer(byMD5Sig, iMAX_MD5_SIG_LEN, m_lpPEScannerSig->ulMD5Sig);
			::SetFilePointer(m_hCurrentFile, 0, NULL, FILE_BEGIN);
		}
		else
		{
			m_lpPEScannerSig->ulMD5Sig = m_lpPEScannerSig->ulMD5Sig15MB;
		}
#endif //#ifdef _PE_FOR_PARSELOG_

		m_bMD5Success = true;
	}
}

bool CFileSignature::OpenFile(LPCTSTR szFileName)
{
	m_hCurrentFile = ::CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(m_hCurrentFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	m_ulFileSize = GetFileSize(m_hCurrentFile, 0);
	return true;
}

void CFileSignature::CloseFile()
{
	if(m_hCurrentFile != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(m_hCurrentFile);
		m_hCurrentFile = INVALID_HANDLE_VALUE;
	}
}

bool CFileSignature::CreateTempFile()
{
	swprintf_s(m_szTempFileName, MAX_PATH, _T("%s%d-MaxUnpacked.temp"), m_szTempFolderName, m_iCurrentLevel);
	//_tcscat_s(m_szTempFileName, _T("MaxUnpacked.temp"));

	m_hTempFile = CreateFile(m_szTempFileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_WRITE|FILE_SHARE_READ|FILE_SHARE_DELETE, 0, CREATE_ALWAYS, 0, 0);
	if(m_hTempFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	m_bTempFileCreated = true;
	return true;
}

void CFileSignature::DeleteTempFile()
{
	if(m_hTempFile != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(m_hTempFile);
		m_hTempFile = INVALID_HANDLE_VALUE;
	}
	if(m_bTempFileCreated)
	{
		for(int iCtr = 0; iCtr < m_iCurrentLevel || iCtr == MAX_RECURSION_LEVEL; iCtr++)
		{
			swprintf_s(m_szTempFileName, MAX_PATH, _T("%s%d-MaxUnpacked.temp"), m_szTempFolderName, iCtr);
			::DeleteFile(m_szTempFileName);
			m_bTempFileCreated = false;
		}
	}
}

void CFileSignature::CloseTempFile()
{
	if(m_hTempFile != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(m_hTempFile);
		m_hTempFile = INVALID_HANDLE_VALUE;
	}
}

bool CFileSignature::LoadFilePEHeader()
{
	DWORD dwBytesRead = 0;

	//TODO: get actual entry point section
	m_iEPSectionIndex = 0;

	if(!ReadFile(m_hCurrentFile, &m_DosHeader, sizeof(m_DosHeader), &dwBytesRead, 0))
	{
		//SendToLog(L"Reading DOS header failed");
		return false;
	}

	if(EXE_SIGNATURE != m_DosHeader.e_magic)
	{
		//SendToLog(L"MZ not found");
		return false;
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(m_hCurrentFile, m_DosHeader.e_lfanew, 0, FILE_BEGIN))
	{
		//SendToLog(L"Seeking to NtHeader failed: %u", m_DosHeader.e_lfanew);
		return false;
	}

	if(!ReadFile(m_hCurrentFile, &m_ImageNTHdr, sizeof(m_ImageNTHdr), &dwBytesRead, 0))
	{
		//SendToLog(L"Reading NT file header failed");
		return false;
	}

	if(PE_SIGNATURE != m_ImageNTHdr.Signature)
	{
		//SendToLog(L"PE not found");
		return false;
	}

	if(m_iCurrentLevel == 0)
	{
		m_bHasPEHeader = true;
	}

	if(m_ImageNTHdr.FileHeader.NumberOfSections > MAX_SECTIONS)
	{
		//SendToLog(L"Too many sections: %i", m_ImageNTHdr.FileHeader.NumberOfSections);
		return false;
	}

	if(m_ImageNTHdr.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
		m_ImageNTHdr.FileHeader.Machine == IMAGE_FILE_MACHINE_IA64)
	{
		if(m_ImageNTHdr.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64))
		{
			return false;
		}

		DWORD dwDifferenceInSize = sizeof(IMAGE_OPTIONAL_HEADER64) - sizeof(IMAGE_OPTIONAL_HEADER32);
		if(SetFilePointer(m_hCurrentFile, dwDifferenceInSize, 0, FILE_CURRENT) == INVALID_SET_FILE_POINTER)
		{
			return false;
		}
	}

	m_dwNoOfSections = m_ImageNTHdr.FileHeader.NumberOfSections;

	if(!ReadFile(m_hCurrentFile, &m_ImgSectionHdr, sizeof(IMAGE_SECTION_HEADER) * m_dwNoOfSections, &dwBytesRead, 0))
	{
		//SendToLog(L"Reading section header failed");
		return false;
	}

	AlignExeSectionInfo();

	m_dwEPOffset = 0;
	m_dwEPRVA = EC32(m_ImageNTHdr.OptionalHeader.AddressOfEntryPoint);
	unsigned int err = 0;
	if(!(m_dwEPOffset = GetRawAddress(m_dwEPRVA, &m_ExeSection[0], m_dwNoOfSections, &err, m_ulFileSize)) && err)
	{
		//SendToLog(L"EntryPoint out of file");
		//ePEType = PE_BROKEN;
		return false;
	}

	if(m_dwEPOffset == 0x00)
	{
		//SendToLog(L"EntryPoint 0");
		//ePEType = PE_BROKEN;
		return false;
	}

	m_dwEPBuffSize = 0;
	::SetFilePointer(m_hCurrentFile, m_dwEPOffset, NULL, FILE_BEGIN);
	if(!ReadFile(m_hCurrentFile, &m_epbuff, EP_BUFFSIZE, &m_dwEPBuffSize, NULL))
	{
		//SendToLog(L"Reading epbuff failed");
		//return false;
	}

	return true;
}

void CFileSignature::AlignExeSectionInfo()
{
	char  sname[9] = {0};
	DWORD valign = m_ImageNTHdr.OptionalHeader.SectionAlignment;
	DWORD falign = m_ImageNTHdr.OptionalHeader.FileAlignment;

	m_hdr_size = 0;
	m_hdr_size = EC32(m_ImageNTHdr.OptionalHeader.SizeOfHeaders);
	m_hdr_size = PESALIGN(m_hdr_size, valign);						/* Aligned headers virtual size */
	m_minval = 0;
	m_maxval = 0;

	for(unsigned int index = 0; index < m_dwNoOfSections; index++)
	{
		strncpy_s(sname, (char *)m_ImgSectionHdr[index].Name, 8);
		sname[8] = 0;
		memset(&m_ExeSection[index], 0, sizeof(EXE_SECTION));
		m_ExeSection[index].rva = PEALIGN(EC32(m_ImgSectionHdr[index].VirtualAddress), valign);
		m_ExeSection[index].vsz = PESALIGN(EC32(m_ImgSectionHdr[index].Misc.VirtualSize), valign);
		m_ExeSection[index].raw = PEALIGN(EC32(m_ImgSectionHdr[index].PointerToRawData), falign);
		m_ExeSection[index].rsz = PESALIGN(EC32(m_ImgSectionHdr[index].SizeOfRawData), falign);
		m_ExeSection[index].chr = EC32(m_ImgSectionHdr[index].Characteristics);
		m_ExeSection[index].urva = EC32(m_ImgSectionHdr[index].VirtualAddress); /* Just in case */
		m_ExeSection[index].uvsz = EC32(m_ImgSectionHdr[index].Misc.VirtualSize);
		m_ExeSection[index].uraw = EC32(m_ImgSectionHdr[index].PointerToRawData);
		m_ExeSection[index].ursz = EC32(m_ImgSectionHdr[index].SizeOfRawData);

		if(!m_ExeSection[index].vsz && m_ExeSection[index].rsz)
		{
			m_ExeSection[index].vsz = PESALIGN(m_ExeSection[index].ursz, valign);
		}

		if(m_ExeSection[index].rsz && m_ulFileSize > m_ExeSection[index].raw 
			&& !CompareBuffer(0, (DWORD)m_ulFileSize, m_ExeSection[index].raw, m_ExeSection[index].rsz))
		{
			m_ExeSection[index].rsz = m_ulFileSize - m_ExeSection[index].raw;
		}

		if(!index)
		{
			m_minval = m_ExeSection[index].rva;
			m_maxval = m_ExeSection[index].rva + m_ExeSection[index].rsz;
		}
		else
		{
			if(m_ExeSection[index].rva < m_minval)
			{
				m_minval = m_ExeSection[index].rva;
			}

			if(m_ExeSection[index].rva + m_ExeSection[index].rsz > m_maxval)
			{
				m_maxval = m_ExeSection[index].rva + m_ExeSection[index].rsz;
			}
		}
	}
}

DWORD CFileSignature::GetRawAddress(DWORD rva, EXE_SECTION *shp, WORD nos, unsigned int *err, ULONG64 fsize)
{
	int index, found = 0;
	DWORD ret = 0;

	if(rva < m_hdr_size) /* Out of section EP - mapped to imagebase+rva */
	{
		if(rva >= fsize)
		{
			*err=1;
			return 0;
		}
		*err=0;
		return rva;
	}

	for(index = nos-1; index >= 0; index--)
	{
		if(shp[index].rsz && shp[index].rva <= rva && shp[index].rsz > rva - shp[index].rva)
		{
			found = 1;
			break;
		}
	}

	if(!found)
	{
		*err = 1;
		return 0;
	}

	ret = rva - shp[index].rva + shp[index].raw;
	*err = 0;
	return ret;
}

off_t CFileSignature::MaxSeekSect(EXE_SECTION *s)
{
	off_t ret;
	if(!s->rsz)
	{
		return 0;
	}
	if((ret=::SetFilePointer(m_hCurrentFile, s->raw,NULL, FILE_BEGIN)) == -1)
	{
		//g_pLogApp->AddLog(_T("MaxSeekSect: lseek()failed"));
	}
	return ret+1;
}

/*--------------------------------------------------------------------------------------
Function       : IsPackedFileHeuristically
In Parameters  : 
Out Parameters : bool 
Description    : Detects whether a file is packed based on 8 Heuristic characteristics
Author         : Vaibhav Desai
--------------------------------------------------------------------------------------*/
bool CFileSignature::IsPackedFileHeuristically()
{
	unsigned int index = 0;
	int iPackedFileCharacteristics[8] = {0};
	bool bIsExecutableSection = false;
	double dblSum = 0;
	double dblEuclidean_distance = 0;
	DWORD dwSumofSectionSize = 0;
	bool bIsPacked = false;

	for(index = 0; index < m_dwNoOfSections; index++)
	{
		//1.Executable section
		if(m_ImgSectionHdr[index].Characteristics & 0x20000000)
		{
			bIsExecutableSection = true;
			if(m_ImgSectionHdr[index].Characteristics & 0x80000000)
			{
				//2.Executable + Writable
				iPackedFileCharacteristics[eEXCUTABLE_AND_WRITABLE_SECTION]++;
			}
		}
		//3.If Code Section - No Executable  & Vice-versa
		if(((m_ImgSectionHdr[index].Characteristics & 0x20000000) && !(m_ImgSectionHdr[index].Characteristics & 0x20)) 
			|| (!(m_ImgSectionHdr[index].Characteristics & 0x20000000) && (m_ImgSectionHdr[index].Characteristics & 0x20)))
		{
			iPackedFileCharacteristics[eCODE_OR_EXCUTABLE_SECTION]++;
		}

		//4.Not Printable Name
		if(0x00 == *((UINT64 *)&(m_ImgSectionHdr[index].Name)))
		{
			iPackedFileCharacteristics[eNOT_PRINTABLE_NAME]++;
		}

		dwSumofSectionSize += m_ImgSectionHdr[index].SizeOfRawData;
	}

	if(!bIsExecutableSection)
	{
		iPackedFileCharacteristics[eNO_EXCUTABLE_SECTION] = 1;
	}

	//5.Sum of Section Size > File Size
	if(dwSumofSectionSize > m_ulFileSize)
	{
		iPackedFileCharacteristics[eSUM_OF_SECTION_SIZE] = 1;
	}

	//6.Position of PE Signature < Size of Image Dos Header
	if(m_DosHeader.e_lfanew < 0x40)
	{
		iPackedFileCharacteristics[ePOSITION_OF_PESIGNATURE] = 1;
	}

	//7.EP Section Executable?
	if(!(m_ImgSectionHdr[m_iEPSectionIndex].Characteristics & 0x20000000))
	{
		iPackedFileCharacteristics[eENTRYPOINT_SECTION_NOT_EXCUTABLE] = 1;
	}

	//8.EP Sectioin Code?
	if(!(m_ImgSectionHdr[m_iEPSectionIndex].Characteristics & 0x20))
	{
		iPackedFileCharacteristics[eENTRYPOINT_SECTION_NOT_CODE] = 1;
	}

	for(index = 0; index < PACKER_CHARACTERISTIC_COUNT; index++)
	{
		dblSum += (iPackedFileCharacteristics[index] * iPackedFileCharacteristics[index]);
	}

	dblEuclidean_distance = sqrt(dblSum);

	if(dblEuclidean_distance > PACKER_THRESHOLD_LIMIT)
	{
		bIsPacked = true;
		//m_iPackedFileHeuristically++;
	}

	return bIsPacked;
}

PACKERS_TYPE CFileSignature::TryAllUnPacker()
{
	PACKERS_TYPE ePackerType = eVALIDPE; //required for check against 0

	m_wIndex = 0;
	m_ifound = 0;
	for(; m_wIndex < m_dwNoOfSections - 1; m_wIndex++)
	{
		if(!m_ImgSectionHdr[m_wIndex].SizeOfRawData
			&& m_ImgSectionHdr[m_wIndex].Misc.VirtualSize
			&& m_ImgSectionHdr[m_wIndex + 1].SizeOfRawData
			&& m_ImgSectionHdr[m_wIndex + 1].Misc.VirtualSize)
		{
			m_ifound = 1;
			break;
		}
	}

	if(ePackerType = CheckForMEWPack())
		return ePackerType;

	if(m_dwEPBuffSize < 168)
	{
		return eUNKNOWN;
	}

	if(ePackerType = CheckForUPACK())
		return ePackerType;

	if(ePackerType = CheckForFSG2())
		return ePackerType;
	
	if(ePackerType = CheckForFSG133())
		return ePackerType;
	
	if(ePackerType = CheckForFSG131())
		return ePackerType;
	
	if(ePackerType = CheckForUPXPack())
		return ePackerType;
	
	if(ePackerType = CheckForPETITE())
		return ePackerType;
	
	if(ePackerType = CheckForPESPIN())
		return ePackerType;
	
	if(ePackerType = CheckForYODAPACK())
		return ePackerType;
	
	if(ePackerType = CheckForWWPack())
		return ePackerType;
	
	if(ePackerType = CheckForASPACK())
		return ePackerType;
	
	if(ePackerType = CheckForNSPACK())
		return ePackerType;

	return eVALIDPE;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSignature::CheckForUPACK
In Parameters  :
Out Parameters : PACKERS_TYPE
Description    : This Funtions Checks Given File is Packed with UPack
Author & Date  : Siddharam pujari
--------------------------------------------------------------------------------------*/
PACKERS_TYPE CFileSignature::CheckForUPACK()
{
	PACKERS_TYPE ePackType = eVALIDPE;
	unsigned int ssize = 0, dsize = 0;
	UINT nsections = m_dwNoOfSections;
	char *DestBuff = NULL;
	DWORD nBytesRead = 0;

	int upack = (m_ImageNTHdr.FileHeader.SizeOfOptionalHeader == 0x148);
	if(m_ifound || upack)
	{
		while(((upack && nsections == 3) && (((m_epbuff[0] == '\xbe') 
				&& ReadInt32(m_epbuff + 1) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase) > m_minval && (m_epbuff[5] == '\xad') 
				&& (m_epbuff[6] == '\x50')) 
			|| ((m_epbuff[0] == '\xbe') 
				&& ReadInt32(m_epbuff + 1) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase) > m_minval && (m_epbuff[5] == '\xff') 
				&& (m_epbuff[6] == '\x36')))) 
			|| ((!upack && nsections == 2) && (((m_epbuff[0] == '\x60') 
				&& (m_epbuff[1] == '\xe8') 
				&& ReadInt32(m_epbuff + 2) == 0x9) 
			|| ((m_epbuff[0] == '\xbe') 
				&& ReadInt32(m_epbuff + 1) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase) < m_minval 
				&& ReadInt32(m_epbuff + 1) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase) > 0 
				&& (m_epbuff[5] == '\xad') 
				&& (m_epbuff[6] == '\x8b')
				&& (m_epbuff[7] == '\xf8')))))
		{
			uint32_t vma, off;
			int a, b, c;

			a = m_ExeSection[0].vsz;
			b = m_ExeSection[1].vsz;
			if(upack)
			{
				c = m_ExeSection[2].vsz;
				ssize = m_ExeSection[0].ursz + m_ExeSection[0].uraw;
				off = m_ExeSection[0].rva;
				vma = EC32(m_ImageNTHdr.OptionalHeader.ImageBase) + m_ExeSection[0].rva;
			}
			else
			{
				c = m_ExeSection[1].rva;
				ssize = m_ExeSection[1].uraw;
				off = 0;
				vma = m_ExeSection[1].rva - m_ExeSection[1].uraw;
			}

			dsize = a + b + c;

			if(!CompareBuffer(0, dsize, m_ExeSection[1].rva - off, m_ExeSection[1].ursz) 
				|| (upack && !CompareBuffer(0, dsize, m_ExeSection[2].rva - m_ExeSection[0].rva, ssize)) 
				|| ssize > dsize)
			{
				break;
			}

			if((DestBuff = (char *)MaxCalloc(dsize, sizeof(char))) == NULL)
			{
				return eUNKNOWN; //stop checking this file further 
			}

			::SetFilePointer(m_hCurrentFile, 0, NULL, FILE_BEGIN);

			if(false == (ReadFile(m_hCurrentFile, (LPBYTE)DestBuff, ssize, &nBytesRead, NULL) && (nBytesRead == ssize)))
			{
				free(DestBuff);
				DestBuff = NULL;
				return eUNKNOWN; //stop checking this file further 
			}

			if(upack)
			{
				memmove(DestBuff + m_ExeSection[2].rva - m_ExeSection[0].rva, DestBuff, ssize);
			}

			::SetFilePointer(m_hCurrentFile, m_ExeSection[1].uraw, NULL, FILE_BEGIN);

			nBytesRead = 0;
			if(ReadFile(m_hCurrentFile, (LPBYTE)(DestBuff + m_ExeSection[1].rva - off), m_ExeSection[1].ursz, &nBytesRead, NULL))
			{
				if(m_ExeSection[1].ursz != nBytesRead)
				{
					if(DestBuff)
					{
						free(DestBuff);
						DestBuff = NULL;
					}
					return eUNKNOWN; //stop checking this file further 
				}

			}
			else
			{
				if(DestBuff)
				{
					free(DestBuff);
					DestBuff = NULL;
				}
				return eUNKNOWN; //stop checking this file further 
			}
			if(CreateTempFile())
			{
				if(UnPackUPack(upack, DestBuff, dsize, (char*)m_epbuff, vma, m_dwEPOffset, 
									EC32(m_ImageNTHdr.OptionalHeader.ImageBase), 
									m_ExeSection[0].rva, (void*)m_hTempFile) != -1)
				{
					ePackType = eUPACK;
				}
				else
				{
					ePackType = eVALIDPE;
					dwUnPackFailed[eUPACK]++;
				}
			}
			else
			{
				ePackType = eUNKNOWN; //stop checking this file further 
			}
			if(DestBuff)
			{
				free(DestBuff);
				DestBuff = NULL;
			}
			break;
		}
	}
	return ePackType;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSignature::CheckForFSG2
In Parameters  :
Out Parameters : PACKERS_TYPE
Description    : This Funtions Checks Given File is Packed with FSG2 Pack
Author & Date  : Siddharam Pujari
--------------------------------------------------------------------------------------*/
PACKERS_TYPE CFileSignature::CheckForFSG2()
{
	PACKERS_TYPE ePackType = eVALIDPE;
	unsigned int ssize = 0, dsize = 0;
	char *SrcBuff = NULL;
	char *DestBuff = NULL;
	DWORD nBytesRead = 0;

	while(m_ifound && (m_epbuff[0] == '\x87') && m_epbuff[1] == '\x25')
	{
		uint32_t newesi, newedi, newebx, newedx;

		ssize = m_ExeSection[m_wIndex + 1].rsz;
		dsize = m_ExeSection[m_wIndex].vsz;
		
		if(ssize <= 0x19 || dsize <= ssize)
		{
			return eUNKNOWN; //stop checking this file further 
		}

		newedx = ReadInt32(m_epbuff + 2) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase);
		if(!CompareBuffer(m_ExeSection[m_wIndex + 1].rva, m_ExeSection[m_wIndex + 1].rsz, newedx, 4))
		{
			break;
		}

		if((SrcBuff = (char *)MaxMalloc(ssize)) == NULL)
		{
			return eUNKNOWN; //stop checking this file further 
		}

		nBytesRead = 0;
		if(!MaxSeekSect(&m_ExeSection[m_wIndex + 1]) 
			|| (false == (ReadFile(m_hCurrentFile, (LPBYTE)SrcBuff, ssize, &nBytesRead, NULL) 
			&& (nBytesRead == ssize))))
		{
			free(SrcBuff);
			SrcBuff = NULL;
			return eUNKNOWN; //stop checking this file further 
		}

		DestBuff = SrcBuff + newedx - m_ExeSection[m_wIndex + 1].rva;
		if(newedx < m_ExeSection[m_wIndex + 1].rva || !CompareBuffer(SrcBuff, ssize, DestBuff, 4))
		{
			free(SrcBuff);
			SrcBuff = NULL;
			break;
		}

		newedx = ReadInt32(DestBuff) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase);
		if(!CompareBuffer(m_ExeSection[m_wIndex + 1].rva, m_ExeSection[m_wIndex + 1].rsz, newedx, 4))
		{
			free(SrcBuff);
			SrcBuff = NULL;
			break;
		}

		DestBuff = SrcBuff + newedx - m_ExeSection[m_wIndex + 1].rva;
		if(!CompareBuffer(SrcBuff, ssize, DestBuff, 32))
		{
			free(SrcBuff);
			SrcBuff = NULL;
			break;
		}

		newedi = ReadInt32(DestBuff) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase);
		newesi = ReadInt32(DestBuff + 4) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase);
		newebx = ReadInt32(DestBuff + 16) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase);
		newedx = ReadInt32(DestBuff + 20);

		if(newedi != m_ExeSection[m_wIndex].rva)
		{
			free(SrcBuff);
			SrcBuff = NULL;
			break;
		}

		if(newesi < m_ExeSection[m_wIndex + 1].rva || newesi - m_ExeSection[m_wIndex + 1].rva >= m_ExeSection[m_wIndex + 1].rsz)
		{
			free(SrcBuff);
			SrcBuff = NULL;
			break;
		}

		if(!CompareBuffer(m_ExeSection[m_wIndex + 1].rva, m_ExeSection[m_wIndex + 1].rsz, newebx, 16))
		{
			free(SrcBuff);
			SrcBuff = NULL;
			break;
		}

		newedx = ReadInt32(newebx + 12 - m_ExeSection[m_wIndex + 1].rva + SrcBuff) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase);
		if((DestBuff = (char *)MaxCalloc(dsize, sizeof(char))) == NULL)
		{
			free(SrcBuff);
			SrcBuff = NULL;
			return eUNKNOWN; //stop checking this file further 
		}

		if(CreateTempFile())
		{
			if(UnPackFSG200(newesi - m_ExeSection[m_wIndex + 1].rva + SrcBuff, DestBuff, 
							ssize + m_ExeSection[m_wIndex + 1].rva - newesi, dsize, newedi, 
							EC32(m_ImageNTHdr.OptionalHeader.ImageBase), newedx, (void*)m_hTempFile))
			{
				ePackType = eFSG20;
			}
			else
			{
				ePackType = eVALIDPE;
				dwUnPackFailed[eFSG20]++;
			}
		}
		else
		{
			ePackType = eUNKNOWN; //stop checking this file further 
		}

		if(SrcBuff)
		{
			free(SrcBuff);
			SrcBuff = NULL;
		}
		if(DestBuff)
		{
			free(DestBuff);
			DestBuff = NULL;
		}
		break;
	}

	return ePackType;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSignature::CheckForFSG133
In Parameters  :
Out Parameters : PACKERS_TYPE
Description    : This Funtions Checks Given File is Packed with FSG133 Pack
Author & Date  : Siddharam pujari
--------------------------------------------------------------------------------------*/
PACKERS_TYPE CFileSignature::CheckForFSG133()
{
	PACKERS_TYPE ePackType = eVALIDPE;
	unsigned int err=0;
	unsigned int ssize = 0, dsize = 0;
	char *SrcBuff = NULL;
	char *DestBuff = NULL;
	DWORD nBytesRead = 0;

	while(m_ifound && m_epbuff[0] == '\xbe' 
		&& ReadInt32(m_epbuff + 1) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase) < m_minval)
	{
		int sectcnt = 0;
		char *support = NULL;
		uint32_t newesi, newedi, oldep, gp, t;
		struct Max_Exe_Sections *sections = NULL;

		ssize = m_ExeSection[m_wIndex + 1].rsz;
		dsize = m_ExeSection[m_wIndex].vsz;

		if(ssize <= 0x19 || dsize <= ssize)
		{
			return eUNKNOWN; //stop checking this file further 
		}
		if(!(gp = GetRawAddress(ReadInt32(m_epbuff + 1) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase), NULL, 0, &err, m_ulFileSize)) && err)
		{
			break;
		}

		::SetFilePointer(m_hCurrentFile, gp, NULL, FILE_BEGIN);
		gp = m_ExeSection[m_wIndex + 1].raw - gp;

		if((support = (char *)MaxMalloc(gp)) == NULL)
		{
			return eUNKNOWN; //stop checking this file further 
		}

		nBytesRead = 0;
		if(false == (ReadFile(m_hCurrentFile, (LPBYTE)support, gp, &nBytesRead, NULL) && (nBytesRead == gp)))
		{
			if(support)
			{
				free(support);
				support = NULL;
			}
			return eUNKNOWN; //stop checking this file further 
		}

		newedi = ReadInt32(support + 4) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase); /* 1st DestBuff */
		newesi = ReadInt32(support + 8) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase); /* Source */

		if(newesi < m_ExeSection[m_wIndex + 1].rva 
			|| newesi - m_ExeSection[m_wIndex + 1].rva >= m_ExeSection[m_wIndex + 1].rsz)
		{
			if(support)
			{
				free(support);
				support = NULL;
			}
			break;
		}

		if(newedi != m_ExeSection[m_wIndex].rva)
		{
			if(support)
			{
				free(support);
				support = NULL;
			}
			break;
		}

		for(t = 12; t < gp - 4; t += 4)
		{
			uint32_t rva = ReadInt32(support+t);
			if(!rva)
			{
				break;
			}

			rva -= EC32(m_ImageNTHdr.OptionalHeader.ImageBase) +1;
			sectcnt++;

			if(rva < m_ExeSection[m_wIndex].rva || rva - m_ExeSection[m_wIndex].rva >= m_ExeSection[m_wIndex].vsz)
			{
				break;
			}
		}

		if(t >= gp - 4 || ReadInt32(support + t))
		{
			if(support)
			{
				free(support);
				support = NULL;
			}
			break;
		}

		if((sections = (struct Max_Exe_Sections *)MaxMalloc((sectcnt + 1) * sizeof(struct Max_Exe_Sections))) == NULL)
		{
			if(support)
			{
				free(support);
				support = NULL;
			}
			return eUNKNOWN; //stop checking this file further 
		}

		sections[0].rva = newedi;
		for(t = 1; t <= (uint32_t)sectcnt; t++)
		{
			sections[t].rva = ReadInt32(support + 8 + t * 4) - 1 - EC32(m_ImageNTHdr.OptionalHeader.ImageBase);
		}

		if(support)
		{
			free(support);
			support = NULL;
		}

		if((SrcBuff = (char *)MaxMalloc(ssize)) == NULL){

			if(sections)
			{
				free(sections);
				sections = NULL;
			}
			return eUNKNOWN; //stop checking this file further 
		}

		nBytesRead = 0;
		if(!MaxSeekSect(&m_ExeSection[m_wIndex + 1]) 
			|| (false == (ReadFile(m_hCurrentFile, (LPBYTE)SrcBuff, ssize, &nBytesRead, NULL)) 
			&& (nBytesRead == ssize)))
		{
			if(sections)
			{
				free(sections);
				sections = NULL;
			}
			if(SrcBuff)
			{
				free(SrcBuff);
				SrcBuff = NULL;
			}
			return eUNKNOWN; //stop checking this file further 
		}

		if((DestBuff = (char *)MaxCalloc(dsize, sizeof(char))) == NULL)
		{
			if(SrcBuff)
			{
				free(SrcBuff);
				SrcBuff = NULL;
			}
			if(sections)
			{
				free(sections);
				sections = NULL;
			}
			return eUNKNOWN; //stop checking this file further 
		}

		oldep = m_dwEPRVA + 161 + 6 + ReadInt32(m_epbuff + 163);

		if(CreateTempFile())
		{
			if(UnPackFSG133(SrcBuff + newesi - m_ExeSection[m_wIndex + 1].rva, DestBuff,
							ssize + m_ExeSection[m_wIndex + 1].rva - newesi, dsize, 
							sections, sectcnt, EC32(m_ImageNTHdr.OptionalHeader.ImageBase), 
							oldep, (void*)m_hTempFile))
			{
				ePackType  = eFSG133;
			}
			else
			{
				ePackType = eVALIDPE;
				dwUnPackFailed[eFSG20]++;
			}
		}
		else
		{
			ePackType = eUNKNOWN;
		}

		if(SrcBuff)
		{
			free(SrcBuff);
			SrcBuff = NULL;
		}
		if(sections)
		{
			free(sections);
			sections = NULL;
		}
		if(DestBuff)
		{
			free (DestBuff);
			DestBuff = NULL;
		}
		break;
	}
	return ePackType;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSignature::CheckForFSG131
In Parameters  :
Out Parameters : PACKERS_TYPE
Description    : This Funtions Checks Given File is Packed with FSG131 Pack
Author & Date  : Siddharam pujari
--------------------------------------------------------------------------------------*/
PACKERS_TYPE CFileSignature::CheckForFSG131()
{
	PACKERS_TYPE ePackType = eVALIDPE;
	unsigned int err=0;
	unsigned int ssize = 0, dsize = 0;
	char *SrcBuff = NULL;
	char *DestBuff = NULL;
	DWORD nBytesRead = 0;

	while(m_ifound 
			&& (m_epbuff[0] == '\xbb')
			&& ReadInt32(m_epbuff + 1) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase) < m_minval
			&& (m_epbuff[5] == '\xbf')
			&& (m_epbuff[10] == '\xbe')
			&& m_dwEPRVA >= m_ExeSection[m_wIndex + 1].rva
			&& m_dwEPRVA - m_ExeSection[m_wIndex + 1].rva > m_ExeSection[m_wIndex + 1].rva - 0xe0)
	{
		int sectcnt = 0;
		uint32_t t;
		uint32_t gp = GetRawAddress(ReadInt32(m_epbuff+1) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase), NULL, 0, &err, m_ulFileSize);
		char *support = NULL;
		uint32_t newesi = ReadInt32(m_epbuff+11) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase);
		uint32_t newedi = ReadInt32(m_epbuff+6) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase);
		uint32_t oldep = m_dwEPRVA - m_ExeSection[m_wIndex + 1].rva;
		struct Max_Exe_Sections *sections = NULL;

		ssize = m_ExeSection[m_wIndex + 1].rsz;
		dsize = m_ExeSection[m_wIndex].vsz;

		if(err)
		{
			break;
		}

		if(newesi < m_ExeSection[m_wIndex + 1].rva
			|| newesi - m_ExeSection[m_wIndex + 1].rva >= m_ExeSection[m_wIndex + 1].raw)
		{
			break;
		}

		if(newedi != m_ExeSection[m_wIndex].rva)
		{
			break;
		}

		if(ssize <= 0x19 || dsize <= ssize)
		{
			return eUNKNOWN; //stop checking this file further 
		}

		::SetFilePointer(m_hCurrentFile, gp, NULL, FILE_BEGIN);
		gp = m_ExeSection[m_wIndex + 1].raw - gp;

		if((support = (char *)MaxMalloc(gp)) == NULL)
		{
			return eUNKNOWN; //stop checking this file further 
		}

		nBytesRead = 0;
		if(false == (ReadFile(m_hCurrentFile, (LPBYTE)support, gp, &nBytesRead, NULL) && (nBytesRead == gp)))
		{
			if(support)
			{
				free(support);
				support = NULL;
			}
			return eUNKNOWN; //stop checking this file further 
		}

		for(t = 0; t < gp - 2; t += 2)
		{
			uint32_t rva = support[t]|(support[t+1]<<8);
			if(rva == 2 || rva == 1)
			{
				break;
			}

			rva = ((rva-2)<<12) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase);
			sectcnt++;

			if(rva < m_ExeSection[m_wIndex].rva || rva - m_ExeSection[m_wIndex].rva >= m_ExeSection[m_wIndex].vsz)
			{
				break;
			}
		}

		if(t >= gp-10 || ReadInt32(support + t + 6) != 2)
		{
			if(support)
			{
				free(support);
				support = NULL;
			}
			break;
		}

		if((sections = (struct Max_Exe_Sections *)MaxMalloc((sectcnt + 1)* sizeof(struct Max_Exe_Sections))) == NULL)
		{
			if(support)
			{
				free(support);
				support = NULL;
			}
			return eUNKNOWN; //stop checking this file further 
		}

		sections[0].rva = newedi;
		for(t = 0; t <= (uint32_t)sectcnt - 1; t++)
		{
			sections[t+1].rva = (((support[t*2]|(support[t*2+1]<<8)) -2)<<12) -EC32(m_ImageNTHdr.OptionalHeader.ImageBase);
		}

		if(support)
		{
			free(support);
			support = NULL;
		}

		if((SrcBuff = (char *)MaxMalloc(ssize)) == NULL)
		{
			if(sections)
			{
				free(sections);
				sections = NULL;
			}
			return eUNKNOWN; //stop checking this file further 
		}

		if(!MaxSeekSect(&m_ExeSection[m_wIndex + 1])
			|| (false == (ReadFile(m_hCurrentFile, (LPBYTE)SrcBuff, ssize, &nBytesRead, NULL)) && (nBytesRead == ssize)))
		{
			if(sections)
			{
				free(sections);
				sections =NULL;
			}
			if(SrcBuff)
			{
				free(SrcBuff);
				SrcBuff = NULL;
			}
			return eUNKNOWN; //stop checking this file further 
		}

		if((DestBuff = (char *)MaxCalloc(dsize, sizeof(char))) == NULL)
		{
			if(SrcBuff)
			{
				free(SrcBuff);
				SrcBuff = NULL;
			}
			if(sections)
			{
				free(sections);
				sections =NULL;
			}
			return eUNKNOWN; //stop checking this file further 
		}

		gp = 0xda + 6*(m_epbuff[16] == '\xe8');
		oldep = m_dwEPRVA + gp + 6 + ReadInt32(SrcBuff+gp+2+oldep);

		if(CreateTempFile())
		{
			if(UnPackFSG133(SrcBuff + newesi - m_ExeSection[m_wIndex + 1].rva, DestBuff, 
							ssize + m_ExeSection[m_wIndex + 1].rva - newesi, dsize, sections, sectcnt, 
							EC32(m_ImageNTHdr.OptionalHeader.ImageBase), oldep, (void*)m_hTempFile))
			{
				ePackType = eFSG131;
			}
			else
			{
				ePackType = eVALIDPE;
				dwUnPackFailed[eFSG131]++;
			}
		}
		else
		{
			ePackType = eUNKNOWN; //stop checking this file further 
		}

		if(SrcBuff)
		{
			free(SrcBuff);
			SrcBuff = NULL;
		}
		if(sections)
		{
			free(sections);
			sections = NULL;
		}
		if(DestBuff)
		{
			free (DestBuff);
			DestBuff = NULL;
		}
		break;
	}
	return ePackType;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSignature::CheckForUPXPack
In Parameters  :
Out Parameters : PACKERS_TYPE
Description    : This Funtions Checks Given File is Packed with UPX Pack
Author & Date  : Siddharam Pujari
--------------------------------------------------------------------------------------*/
PACKERS_TYPE CFileSignature::CheckForUPXPack()
{
	PACKERS_TYPE ePackType = eVALIDPE;
	unsigned int ssize = 0, dsize = 0;
	char *SrcBuff;
	char *DestBuff;
	DWORD nBytesRead = 0;
	UPXFUNC lpfnupx = NULL;
	int upx_success = 0;

	if(m_ifound)
	{
		ssize = m_ExeSection[m_wIndex + 1].rsz;
		dsize = m_ExeSection[m_wIndex].vsz + m_ExeSection[m_wIndex + 1].vsz;

		if(ssize <= 0x19 || dsize <= ssize || dsize > MAX_ALLOCATION)
		{
			return eUNKNOWN;
		}

		if((SrcBuff = (char *)MaxMalloc(ssize)) == NULL)
		{
			return eUNKNOWN;
		}

		if((DestBuff = (char *)MaxCalloc(dsize + 8192, sizeof(char))) == NULL)
		{
			if(SrcBuff)
			{
				free(SrcBuff);
				SrcBuff = NULL;
			}
			return eUNKNOWN;
		}

		nBytesRead = 0;
		if(!MaxSeekSect(&m_ExeSection[m_wIndex + 1])
			|| (false == (ReadFile(m_hCurrentFile, (LPBYTE)SrcBuff, ssize, &nBytesRead, NULL)) 
			&& (nBytesRead == ssize)))
		{
			if(SrcBuff)
			{
				free(SrcBuff);
				SrcBuff = NULL;
			}
			if(DestBuff)
			{
				free(DestBuff);
				DestBuff = NULL;
			}
			return eUNKNOWN;
		}

		lpfnupx = NULL;
		if(MemStrCompare(UPX_NRV2B, 24, (char*)(m_epbuff + 0x69), 13) || MemStrCompare(UPX_NRV2B, 24, m_epbuff + 0x69 + 8, 13))
		{
			lpfnupx = UPX_Inflate2b;
		}
		else if(MemStrCompare(UPX_NRV2D, 24, (char*)(m_epbuff + 0x69), 13) || MemStrCompare(UPX_NRV2D, 24, m_epbuff + 0x69 + 8, 13))
		{
			lpfnupx = UPX_Inflate2d;
		}
		else if(MemStrCompare(UPX_NRV2E, 24, (char*)(m_epbuff + 0x69), 13) || MemStrCompare(UPX_NRV2E, 24, m_epbuff + 0x69 + 8, 13))
		{
			lpfnupx = UPX_Inflate2e;
		}

		if(lpfnupx)
		{
			int skew = ReadInt32(m_epbuff + 2) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase) - m_ExeSection[m_wIndex + 1].rva;

			if(m_epbuff[1] != '\xbe' || skew <= 0 || skew > 0xfff)
			{
				skew = 0;
				if(lpfnupx(SrcBuff, ssize, DestBuff, &dsize, m_ExeSection[m_wIndex].rva, m_ExeSection[m_wIndex + 1].rva, m_dwEPRVA) >= 0)
				{
					upx_success = 1;
				}
			}
			else
			{
				if(lpfnupx(SrcBuff + skew, ssize - skew, DestBuff, &dsize, m_ExeSection[m_wIndex].rva, m_ExeSection[m_wIndex + 1].rva, m_dwEPRVA-skew) >= 0 
					|| lpfnupx(SrcBuff, ssize, DestBuff, &dsize, m_ExeSection[m_wIndex].rva, m_ExeSection[m_wIndex + 1].rva, m_dwEPRVA) >= 0)
				{
					upx_success = 1;
				}
			}
		}

		if(!upx_success && lpfnupx != UPX_Inflate2b)
		{
			if(UPX_Inflate2b(SrcBuff, ssize, DestBuff, &dsize, m_ExeSection[m_wIndex].rva, m_ExeSection[m_wIndex + 1].rva, m_dwEPRVA) == -1 && UPX_Inflate2b(SrcBuff + 0x15, ssize - 0x15, DestBuff, &dsize, m_ExeSection[m_wIndex].rva, m_ExeSection[m_wIndex + 1].rva, m_dwEPRVA - 0x15) == -1)
			{
			}
			else
			{
				upx_success = 1;
			}
		}

		if(!upx_success && lpfnupx != UPX_Inflate2d)
		{
			if(UPX_Inflate2d(SrcBuff, ssize, DestBuff, &dsize, m_ExeSection[m_wIndex].rva, m_ExeSection[m_wIndex + 1].rva, m_dwEPRVA) == -1 && UPX_Inflate2d(SrcBuff + 0x15, ssize - 0x15, DestBuff, &dsize, m_ExeSection[m_wIndex].rva, m_ExeSection[m_wIndex + 1].rva, m_dwEPRVA - 0x15) == -1)
			{
			}
			else
			{
				upx_success = 1;
			}
		}

		if(!upx_success && lpfnupx != UPX_Inflate2e)
		{
			if(UPX_Inflate2e(SrcBuff, ssize, DestBuff, &dsize, m_ExeSection[m_wIndex].rva, m_ExeSection[m_wIndex + 1].rva, m_dwEPRVA) == -1 && UPX_Inflate2e(SrcBuff + 0x15, ssize - 0x15, DestBuff, &dsize, m_ExeSection[m_wIndex].rva, m_ExeSection[m_wIndex + 1].rva, m_dwEPRVA - 0x15) == -1)
			{
			}
			else
			{
				upx_success = 1;
			}
		}

		if(MemStrCompare(UPX_LZMA2, 20, m_epbuff + 0x2f, 20))
		{
			uint32_t strictdsize=ReadInt32(m_epbuff+0x21);
			if(strictdsize<=dsize)
			{
				upx_success = UPX_InflateLzma(SrcBuff, ssize, DestBuff, &strictdsize, m_ExeSection[m_wIndex].rva, m_ExeSection[m_wIndex + 1].rva, m_dwEPRVA) >=0;
			}
		}
		else if(MemStrCompare(UPX_LZMA1, 20, m_epbuff + 0x39, 20))
		{
			uint32_t strictdsize=ReadInt32(m_epbuff+0x2b);
			if(strictdsize<=dsize)
			{
				upx_success = UPX_InflateLzma(SrcBuff, ssize, DestBuff, &strictdsize, m_ExeSection[m_wIndex].rva, m_ExeSection[m_wIndex + 1].rva, m_dwEPRVA) >=0;
			}
		}

		if(!upx_success)
		{
			if(SrcBuff)
			{
				free(SrcBuff);
				SrcBuff = NULL;
			}
			if(DestBuff)
			{
				free(DestBuff);
				DestBuff = NULL;
			}
		}
		if(upx_success)
		{
			if(SrcBuff)
			{
				free(SrcBuff);
				SrcBuff = NULL;
			}
			if(CreateTempFile())
			{
				DWORD dwBytesWritten = 0;
				if(false == ::WriteFile(m_hTempFile, DestBuff, dsize, &dwBytesWritten, 0))
				{
					ePackType = eVALIDPE;
					dwUnPackFailed[eUPX]++;
				}
				else
				{
					ePackType = eUPX;
				}
			}
			else
			{
				ePackType = eUNKNOWN;
			}

			if(DestBuff)
			{
				free(DestBuff);
				DestBuff = NULL;
			}
			::SetFilePointer(m_hTempFile, 0, NULL, FILE_BEGIN);
		}
	}
	return ePackType;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSignature::CheckForPETITE
In Parameters  :
Out Parameters : PACKERS_TYPE
Description    : This Funtions Checks Given File is Packed with PETITE Pack
Author & Date  : Siddharam pujari
--------------------------------------------------------------------------------------*/
PACKERS_TYPE CFileSignature::CheckForPETITE()
{
	PACKERS_TYPE ePackType = eVALIDPE;
	unsigned int dsize = 0;
	UINT nsections = m_dwNoOfSections;
	char *DestBuff;
	DWORD nBytesRead = 0;

	if(m_dwEPBuffSize < 200)
	{
		return eUNKNOWN;
	}

	m_ifound = 2;

	if(m_epbuff[0] != '\xb8' 
		|| (uint32_t)ReadInt32(m_epbuff + 1) != m_ExeSection[nsections - 1].rva + EC32(m_ImageNTHdr.OptionalHeader.ImageBase))
	{
		if(nsections < 2 || m_epbuff[0] != '\xb8' 
			|| (uint32_t)ReadInt32(m_epbuff + 1) != m_ExeSection[nsections - 2].rva + EC32(m_ImageNTHdr.OptionalHeader.ImageBase))
		{
			m_ifound = 0;
		}
		else
		{
			m_ifound = 1;
		}
	}

	if(m_ifound)
	{
		if(ReadInt32(m_epbuff + 0x80) == 0x163c988d)
		{
			//g_pLogApp->AddLog(L"Petite: level zero compression is not supported yet\n");
			ePackType = eVALIDPE;
			dwUnPackFailed[ePETITE]++;
		} 
		else 
		{
			dsize = m_maxval - m_minval;
			if((DestBuff = (char *)MaxCalloc(dsize, sizeof(char))) == NULL)
			{
				return eUNKNOWN;
			}

			for(m_wIndex = 0; m_wIndex < nsections; m_wIndex++)
			{
				if(m_ExeSection[m_wIndex].raw)
				{
					if(!MaxSeekSect(&m_ExeSection[m_wIndex]) 
						|| (false == (ReadFile(m_hCurrentFile, (LPBYTE)DestBuff + m_ExeSection[m_wIndex].rva - m_minval, m_ExeSection[m_wIndex].ursz, &nBytesRead, NULL))
						&& (nBytesRead == m_ExeSection[m_wIndex].ursz)))
					{
						if(DestBuff)
						{
							free(DestBuff);
							DestBuff = NULL;
						}
						return eUNKNOWN;
					}
				}
			}

			if(CreateTempFile())
			{
				if(!PETITE_Inflate2x_1to9(DestBuff, m_minval, m_maxval - m_minval, 
										reinterpret_cast<Max_Exe_Sections*>(m_ExeSection), 
										nsections - (m_ifound == 1 ? 1 : 0), 
										EC32(m_ImageNTHdr.OptionalHeader.ImageBase),
										m_dwEPRVA, (void*)m_hTempFile, m_ifound,
										EC32(m_ImageNTHdr.OptionalHeader.DataDirectory[2].VirtualAddress),
										EC32(m_ImageNTHdr.OptionalHeader.DataDirectory[2].Size)))
				{
					ePackType = ePETITE;
				}
				else
				{
					ePackType = eVALIDPE;
					dwUnPackFailed[ePETITE]++;
				}
			}
			else
			{
				ePackType = eUNKNOWN;
			}
			if(DestBuff)
			{
				free(DestBuff);
				DestBuff = NULL;
			}
		}
	}
	return ePackType;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSignature::CheckForPESPIN
In Parameters  :
Out Parameters : PACKERS_TYPE
Description    : This Funtions Checks Given File is Packed with PESPIN Pack
Author & Date  : Siddharam pujari
--------------------------------------------------------------------------------------*/
PACKERS_TYPE CFileSignature::CheckForPESPIN()
{
	PACKERS_TYPE ePackType = eVALIDPE;
	UINT nsections = m_dwNoOfSections;
	DWORD nBytesRead = 0;

	if(nsections > 1 && m_dwEPRVA >= m_ExeSection[nsections - 1].rva
			&& m_dwEPRVA < m_ExeSection[nsections - 1].rva + m_ExeSection[nsections - 1].rsz - 0x3217 - 4
			&& memcmp(m_epbuff+4, "\xe8\x00\x00\x00\x00\x8b\x1c\x24\x83\xc3", 10) == 0)
	{
		char *spinned = NULL;
		if((spinned = (char *)MaxMalloc(m_ulFileSize)) == NULL)
		{
			return eUNKNOWN;
		}

		::SetFilePointer(m_hCurrentFile, 0, NULL, FILE_BEGIN);

		nBytesRead = 0;
		if(false == (ReadFile(m_hCurrentFile, (LPBYTE)spinned, m_ulFileSize, &nBytesRead, NULL)
					&& (nBytesRead == m_ulFileSize)))
		{
			if(spinned)
			{
				free(spinned);
				spinned = NULL;
			}
			return eUNKNOWN;
		}

		if(CreateTempFile())
		{
			if(!UnPackSpin(spinned, m_ulFileSize, reinterpret_cast<Max_Exe_Sections*>(m_ExeSection), nsections - 1, m_dwEPRVA, m_hTempFile))
			{
				ePackType = ePESPIN;
			}
			else
			{
				ePackType = eVALIDPE;
				dwUnPackFailed[ePESPIN]++;
			}
		}
		else
		{
			ePackType = eUNKNOWN;
		}
		if(spinned)
		{
			free(spinned);
			spinned = NULL;
		}
	}
	return ePackType;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSignature::CheckForYODAPACK
In Parameters  :
Out Parameters : PACKERS_TYPE
Description    : This Funtions Checks Given File is Packed with YODA Pack
Author & Date  : Siddharam Pujari
--------------------------------------------------------------------------------------*/
PACKERS_TYPE CFileSignature::CheckForYODAPACK()
{
	PACKERS_TYPE ePackType = eVALIDPE;
	UINT nsections = m_dwNoOfSections;
	DWORD nBytesRead = 0;

	if(nsections > 1 && EC32(m_ImageNTHdr.OptionalHeader.AddressOfEntryPoint) == m_ExeSection[nsections - 1].rva + 0x60
					&& memcmp(m_epbuff, "\x55\x8B\xEC\x53\x56\x57\x60\xE8\x00\x00\x00\x00\x5D\x81\xED\x6C\x28\x40\x00\xB9\x5D\x34\x40\x00\x81\xE9\xC6\x28\x40\x00\x8B\xD5\x81\xC2\xC6\x28\x40\x00\x8D\x3A\x8B\xF7\x33\xC0\xEB\x04\x90\xEB\x01\xC2\xAC", 51) == 0
					&& m_ulFileSize >= m_ExeSection[nsections - 1].raw + 0xC6 + 0xb97)
	{
		char *spinned = NULL;
		if((spinned = (char *)MaxMalloc(m_ulFileSize)) == NULL)
		{
			return eUNKNOWN;
		}

		::SetFilePointer(m_hCurrentFile, 0, NULL, FILE_BEGIN);
		nBytesRead = 0;
		if(false == (ReadFile(m_hCurrentFile, (LPBYTE)spinned, m_ulFileSize, &nBytesRead, NULL) && (nBytesRead == m_ulFileSize)))
		{
			if(spinned)
			{
				free(spinned);
				spinned = NULL;
			}
			return eUNKNOWN;
		}

		if(CreateTempFile())
		{
			if(!UnPackYoda(spinned, m_ulFileSize, reinterpret_cast<Max_Exe_Sections*>(m_ExeSection), nsections-1, m_DosHeader.e_lfanew, m_hTempFile))
			{
				ePackType = eYC13;
			}
			else
			{
				ePackType = eVALIDPE;
				dwUnPackFailed[eYC13]++;
			}
		}
		else
		{
			ePackType = eUNKNOWN;
		}
		if(spinned)
		{
			free(spinned);
			spinned = NULL;
		}
	}
	return ePackType;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSignature::CheckForWWPack
In Parameters  :
Out Parameters : PACKERS_TYPE
Description    : This Funtions Checks Given File is Packed with WWPack
Author & Date  : Siddharam Pujari
--------------------------------------------------------------------------------------*/
PACKERS_TYPE CFileSignature::CheckForWWPack()
{
	PACKERS_TYPE ePackType = eVALIDPE;
	unsigned int i=0;
	unsigned int ssize = 0;
	UINT nsections = m_dwNoOfSections;
	char *SrcBuff = NULL;
	DWORD nBytesRead = 0;

	while(nsections > 1 &&
		m_dwEPRVA == m_ExeSection[nsections - 1].rva &&
		memcmp(m_epbuff, "\x53\x55\x8b\xe8\x33\xdb\xeb", 7) == 0 &&
		memcmp(m_epbuff+0x68, "\xe8\x00\x00\x00\x00\x58\x2d\x6d\x00\x00\x00\x50\x60\x33\xc9\x50\x58\x50\x50", 19) == 0)
	{
		uint32_t head = m_ExeSection[nsections - 1].raw;
		uint8_t *packer;

		ssize = 0;
		for(i=0;; i++)
		{
			if(m_ExeSection[i].raw<head)
			{
				head = m_ExeSection[i].raw;
			}
			if(i+1 == nsections)
			{
				break;
			}
			if(ssize<m_ExeSection[i].rva+m_ExeSection[i].vsz)
			{
				ssize=m_ExeSection[i].rva+m_ExeSection[i].vsz;
			}
		}
		if(!head || !ssize || head>ssize)
		{
			break;
		}

		if(!(SrcBuff=(char *)MaxCalloc(ssize, sizeof(char))))
		{
			return eUNKNOWN;
		}

		::SetFilePointer(m_hCurrentFile, 0, NULL, FILE_BEGIN);
		nBytesRead = 0;
		if(false == (ReadFile(m_hCurrentFile, (LPBYTE)SrcBuff, head, &nBytesRead, NULL) && (nBytesRead == head)))
		{
			if(SrcBuff)
			{
				free(SrcBuff);
				SrcBuff = NULL;
			}
			return eUNKNOWN;
		}
		for(i = 0; i < (unsigned int)nsections-1; i++)
		{
			if(!m_ExeSection[i].rsz)
			{
				continue;
			}
			if(!MaxSeekSect(&m_ExeSection[i]))
			{
				break;
			}
			if(!CompareBuffer(SrcBuff, ssize, SrcBuff+m_ExeSection[i].rva, m_ExeSection[i].rsz))
			{
				break;
			}
			if((false == ReadFile(m_hCurrentFile, (LPBYTE)SrcBuff+m_ExeSection[i].rva, m_ExeSection[i].rsz, &nBytesRead, NULL)) 
				&& (nBytesRead != m_ExeSection[i].rsz))
			{
				break;
			}
		}
		if(i + 1 != nsections)
		{
			if(SrcBuff)
			{
				free(SrcBuff);
				SrcBuff = NULL;
			}
			break;
		}
		if((packer = (uint8_t *)MaxCalloc(m_ExeSection[nsections - 1].rsz, sizeof(char))) == NULL)
		{
			if(SrcBuff)
			{
				free(SrcBuff);
				SrcBuff = NULL;
			}
			return eUNKNOWN;
		}
		if(!MaxSeekSect(&m_ExeSection[nsections - 1])
			|| ((false == ReadFile(m_hCurrentFile, (LPBYTE)packer, m_ExeSection[nsections - 1].rsz, &nBytesRead, NULL))
			&& (nBytesRead!= m_ExeSection[nsections - 1].rsz)))
		{
			if(SrcBuff)
			{
				free(SrcBuff);
				SrcBuff = NULL;
			}
			if(packer)
			{
				free(packer);
				packer = NULL;
			}
			return eUNKNOWN;
		}
		if(CreateTempFile())
		{
			if(!UnPackWWPack((uint8_t *)SrcBuff, ssize, packer, reinterpret_cast<Max_Exe_Sections*>(m_ExeSection), 
								nsections-1, m_DosHeader.e_lfanew, m_hTempFile))
			{
				ePackType = eWWPACK;
			}
			else
			{
				ePackType = eVALIDPE;
				dwUnPackFailed[eWWPACK]++;
			}
		}
		else
		{
			ePackType = eUNKNOWN;
		}
		
		if(SrcBuff)
		{
			free (SrcBuff);
			SrcBuff = NULL;
		}
		break;
	}
	return ePackType;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSignature::CheckForASPACK
In Parameters  :
Out Parameters : PACKERS_TYPE
Description    : This Funtions Checks Given File is Packed with ASPACK Pack
Author & Date  : Siddharam Pujari
--------------------------------------------------------------------------------------*/
PACKERS_TYPE CFileSignature::CheckForASPACK()
{
	PACKERS_TYPE ePackType = eVALIDPE;
	unsigned int ssize = 0;
	UINT nsections = m_dwNoOfSections;
	char *SrcBuff = NULL;
	DWORD nBytesRead = 0;

	while(m_dwEPOffset+58+0x70e < m_ulFileSize && !memcmp(m_epbuff,"\x60\xe8\x03\x00\x00\x00\xe9\xeb",8))
	{
		if(m_dwEPBuffSize <0x3bf || memcmp(m_epbuff+0x3b9, "\x68\x00\x00\x00\x00\xc3",6))
		{
			break;
		}
		ssize = 0;
		for(m_wIndex=0; m_wIndex< nsections; m_wIndex++)
		{
			if(ssize<m_ExeSection[m_wIndex].rva+m_ExeSection[m_wIndex].vsz)
			{
				ssize=m_ExeSection[m_wIndex].rva+m_ExeSection[m_wIndex].vsz;
			}
		}
		if(!ssize)
		{
			break;
		}

		if(!(SrcBuff=(char *)MaxCalloc(ssize, sizeof(char))))
		{
			return eUNKNOWN;
		}
		for(m_wIndex = 0; m_wIndex < (unsigned int)nsections; m_wIndex++)
		{
			if(!m_ExeSection[m_wIndex].rsz)
			{
				continue;
			}
			if(!MaxSeekSect(&m_ExeSection[m_wIndex]))
			{
				break;
			}
			if(!CompareBuffer(SrcBuff, ssize, SrcBuff+m_ExeSection[m_wIndex].rva, m_ExeSection[m_wIndex].rsz))
			{
				break;
			}

			if(false == (ReadFile(m_hCurrentFile, (LPBYTE)SrcBuff+m_ExeSection[m_wIndex].rva, m_ExeSection[m_wIndex].rsz, &nBytesRead, NULL))
						&& (nBytesRead == m_ExeSection[m_wIndex].rsz))
			{
				break;
			}
		}
		if(m_wIndex!=nsections)
		{
			if(SrcBuff)
			{
				free(SrcBuff);
				SrcBuff = NULL;
			}
			break;
		}

		if(CreateTempFile())
		{
			if(UnPackAsPack212((uint8_t *)SrcBuff, ssize, reinterpret_cast<Max_Exe_Sections*>(m_ExeSection),
								nsections, m_dwEPRVA-1, EC32(m_ImageNTHdr.OptionalHeader.ImageBase), m_hTempFile))
			{
				ePackType = eASPACK;
			}
			else
			{
				ePackType = eVALIDPE;
				dwUnPackFailed[eASPACK]++;
			}
			if(SrcBuff)
			{
				free(SrcBuff);
				SrcBuff = NULL;
			}
		}
		else
		{
			ePackType = eUNKNOWN;
		}
		break;
	}

	return ePackType;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSignature::CheckForNSPACK
In Parameters  :
Out Parameters : PACKERS_TYPE
Description    : This Funtions Checks Given File is Packed with NSPACK Pack
Author & Date  :  Siddharam Pujari
--------------------------------------------------------------------------------------*/
PACKERS_TYPE CFileSignature::CheckForNSPACK()
{
	PACKERS_TYPE ePackType = eVALIDPE;
	unsigned int err = 0;
	UINT nsections = m_dwNoOfSections;
	DWORD nBytesRead = 0;

	int nCheckNSPack = 1;
	while(nCheckNSPack)
	{
		uint32_t eprva = m_dwEPRVA;
		uint32_t start_of_stuff, ssize, dsize, rep = m_dwEPOffset;
		unsigned int nowinldr;
		char nbuff[24];
		char *src=m_epbuff, *dest = NULL;

		if(*m_epbuff == '\xe9')
		{
			eprva = ReadInt32(m_epbuff+1 )+ m_dwEPRVA + 5;
			if(!(rep = GetRawAddress(eprva, m_ExeSection, nsections, &err, m_ulFileSize)) && err)
			{
				break;
			}
			::SetFilePointer(m_hCurrentFile, rep, NULL, FILE_BEGIN);
			if(false == (ReadFile(m_hCurrentFile, (LPBYTE)nbuff, 24 , &nBytesRead, NULL)) && (nBytesRead == 24))
			{
				break;
			}
			src = nbuff;
		}

		if(memcmp(src, "\x9c\x60\xe8\x00\x00\x00\x00\x5d\xb8\x07\x00\x00\x00", 13) != 0)
		{
			break;
		}

		nowinldr = 0x54-ReadInt32(src+17);

		::SetFilePointer(m_hCurrentFile, rep-nowinldr, NULL, FILE_BEGIN);

		if(false == (ReadFile(m_hCurrentFile, (LPBYTE)nbuff, 4, &nBytesRead, NULL)) && (nBytesRead == 4))
		{
			break;
		}

		start_of_stuff = rep + ReadInt32(nbuff);
		::SetFilePointer(m_hCurrentFile, start_of_stuff, NULL, FILE_BEGIN);

		if(false == (ReadFile(m_hCurrentFile, (LPBYTE)nbuff, 20, &nBytesRead, NULL)) && (nBytesRead == 20))
		{
			break;
		}

		src = nbuff;
		if(!ReadInt32(nbuff))
		{
			start_of_stuff+=4;
			src+=4;
		}

		ssize = ReadInt32(src+5)|0xff;
		dsize = ReadInt32(src+9);

		if(!ssize || !dsize || dsize != m_ExeSection[0].vsz)
		{
			break;
		}
		::SetFilePointer(m_hCurrentFile, start_of_stuff, NULL, FILE_BEGIN);

		if(!(dest = (char*)MaxMalloc(dsize)))
		{
			break;
		}

		if(!(src = (char*)MaxMalloc(ssize)))
		{
			if (dest)
			{
				free(dest);
				dest = NULL;
			}
			break;
		}
		if(false == (ReadFile(m_hCurrentFile, (LPBYTE)src, ssize , &nBytesRead, NULL)) && (nBytesRead == ssize))
		{
			break;
		}

		eprva+=0x27a;
		if(!(rep = GetRawAddress(eprva, m_ExeSection, nsections, &err, m_ulFileSize)) && err)
		{
			break;
		}

		::SetFilePointer(m_hCurrentFile, rep, NULL, FILE_BEGIN);
		if(false == (ReadFile(m_hCurrentFile, (LPBYTE)nbuff, 5, &nBytesRead, NULL)) && (nBytesRead == 5))
		{
			break;
		}
		
		eprva = eprva + 5 + ReadInt32(nbuff + 1);
		
		if(CreateTempFile())
		{
			if(!UnPackNSPack(src, dest, m_ExeSection[0].rva, EC32(m_ImageNTHdr.OptionalHeader.ImageBase), eprva, m_hTempFile))
			{
				ePackType = eNSPACK;
			}
			else
			{
				ePackType = eVALIDPE;
				dwUnPackFailed[eNSPACK]++;
			}
		}
		else
		{
			ePackType = eUNKNOWN;
		}
		if (src)
		{
			free (src);
			src = NULL;
		}
		if (dest)
		{
			free(dest );
			dest = NULL;
		}
		break;
	}
	return ePackType;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSignature::CheckForMEWPack
In Parameters  :
Out Parameters : PACKERS_TYPE
Description    : This Funtions Checks Given File is Packed with MEW Pack
Author & Date  : siddharam pujari
--------------------------------------------------------------------------------------*/
PACKERS_TYPE CFileSignature::CheckForMEWPack()
{
	char *SrcBuff = NULL;
	PACKERS_TYPE ePackType = eVALIDPE;
	unsigned int ssize = 0, dsize = 0;

	if(m_ifound && (m_dwEPBuffSize >= 16) && (m_epbuff[0] == '\xe9'))
	{
		uint32_t fileoffset;
		fileoffset = (m_dwEPRVA + ReadInt32(m_epbuff + 1) + 5);
		while (fileoffset == 0x154 || fileoffset == 0x158)
		{
			uint32_t offdiff, uselzma;
			if(SetFilePointer(m_hCurrentFile, fileoffset, NULL, FILE_BEGIN) == -1)
			{
				return eUNKNOWN;
			}
			DWORD bytes = 0;
			BYTE buff[4096]={0};
			if(ReadFile(m_hCurrentFile, buff, 0xb0, &bytes, NULL))
			{
				if(bytes != 0xb0)
				{
					break;
				}
			}

			if((offdiff = ReadInt32(buff+1) - EC32(m_ImageNTHdr.OptionalHeader.ImageBase)) <= m_ExeSection[m_wIndex + 1].rva 
						|| offdiff >= m_ExeSection[m_wIndex + 1].rva + m_ExeSection[m_wIndex + 1].raw - 4)
			{
				break;
			}

			offdiff -= m_ExeSection[m_wIndex + 1].rva;

			if(!MaxSeekSect(&m_ExeSection[m_wIndex + 1]))
			{
				return eUNKNOWN;
			}
			ssize = m_ExeSection[m_wIndex + 1].vsz;
			dsize = m_ExeSection[m_wIndex].vsz;

			if((SrcBuff = (char *)MaxMalloc(ssize + dsize)) == NULL)
			{
				return eUNKNOWN;
			}

			if(m_ExeSection[m_wIndex + 1].rsz < offdiff + 12 || m_ExeSection[m_wIndex + 1].rsz > ssize)
			{
				if(SrcBuff)
				{
					free(SrcBuff);
					SrcBuff = NULL;
				}
				break;
			}
			if(ReadFile(m_hCurrentFile, (LPBYTE)(SrcBuff + dsize), m_ExeSection[m_wIndex + 1].rsz, &bytes, NULL))
			{
				if(bytes != m_ExeSection[m_wIndex + 1].rsz)
				{
					if(SrcBuff)
					{
						free(SrcBuff);
						SrcBuff = NULL;
					}
					return eUNKNOWN;
				}
			}

			if((buff[0x7b] == 0xe8))
			{
				if(!CompareBuffer(m_ExeSection[1].rva, m_ExeSection[1].vsz, ReadInt32(buff + 0x7c) + fileoffset + 0x80, 4))
				{
					if(SrcBuff)
					{
						free(SrcBuff);
						SrcBuff = NULL;
					}
					break;
				}
				uselzma = ReadInt32(buff + 0x7c) - (m_ExeSection[0].rva - fileoffset - 0x80);
			}
			else
			{
				uselzma = 0;
			}

			if(CreateTempFile())
			{
				if(UnPackMEW11(SrcBuff, offdiff, ssize, dsize, EC32(m_ImageNTHdr.OptionalHeader.ImageBase), 
								m_ExeSection[0].rva, uselzma, (void*)m_hTempFile))
				{
					ePackType = eMEW;
				}
				else
				{
					ePackType = eVALIDPE;
					dwUnPackFailed[eMEW]++;
				}
			}
			else
			{
				ePackType = eUNKNOWN;
			}
			if(SrcBuff)
			{
				free(SrcBuff);
				SrcBuff = NULL;
			}
			break;
		}

	}
	return ePackType;
}

