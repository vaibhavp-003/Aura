/*=============================================================================
   FILE		           : ZipStorage.cpp
   ABSTRACT		       :  implementation of the CZipStorage class.
   DOCUMENTS	       : 
   AUTHOR		       : 
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE      : 
   NOTES		      : 
   VERSION HISTORY    :
				
=============================================================================*/

#include "stdafx.h"
#include "ZipStorage.h"
#include "ZipArchive.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function       : CZipStorage
	Purpose		   : Constructor for class CZipArchive
	Author		   : 
-------------------------------------------------------------------------------------*/
char CZipStorage::m_gszExtHeaderSignat[] = {0x50, 0x4b, 0x07, 0x08};
CZipStorage::CZipStorage()
{
	m_pCallbackData = m_pZIPCALLBACKFUN = NULL;
	m_iWriteBufferSize = 65535;
	m_iCurrentDisk = -1;
	m_pFile = NULL;
}
/*-------------------------------------------------------------------------------------
	Function       : ~CZipStorage
	Purpose		   : Destructor for class CZipStorage
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipStorage::~CZipStorage()
{

}
/*-------------------------------------------------------------------------------------
	Function       : Read
	In Parameters  : void *pBuf, DWORD iSize, bool bAtOnce
	Out Parameters : DWORD
	Purpose		   : Read the File
	Author		   : 
-------------------------------------------------------------------------------------*/

DWORD CZipStorage::Read(void *pBuf, DWORD iSize, bool bAtOnce)
{
	if (iSize == 0)
		return 0;
	DWORD iRead = 0;
	while (!iRead)
	{
		iRead = m_pFile->Read(pBuf, iSize);
		if (!iRead)
			if (IsSpanMode())
				ChangeDisk(m_iCurrentDisk + 1);
			else
				ThrowError(ZIP_BADZIPFILE);
	}

	if (iRead == iSize)
		return iRead;
	else if (bAtOnce || !IsSpanMode())
		ThrowError(ZIP_BADZIPFILE);

	while (iRead < iSize)
	{
		ChangeDisk(m_iCurrentDisk + 1);
		UINT iNewRead = m_pFile->Read((char*)pBuf + iRead, iSize - iRead);
		if (!iNewRead && iRead < iSize)
			ThrowError(ZIP_BADZIPFILE);
		iRead += iNewRead;
	}

	return iRead;
}

/*-------------------------------------------------------------------------------------
	Function       : Open
	In Parameters  : LPCTSTR szPathName, int iMode, int iVolumeSize
	Out Parameters : void
	Purpose		   : Open the file in ziparchive
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipStorage::Open(LPCTSTR szPathName, int iMode, int iVolumeSize)
{
	m_pWriteBuffer.Allocate(m_iWriteBufferSize); 
	m_uBytesInWriteBuffer = 0;
	m_bNewSpan = false;
	m_pFile = &m_internalfile;

	if ((iMode == CZipArchive::create) ||(iMode == CZipArchive::createSpan)) // create new archive
	{
		m_iCurrentDisk = 0;
		if (iMode == CZipArchive::create)
		{
			m_iSpanMode = noSpan;
			OpenFile(szPathName, CFile::modeCreate | CFile::modeReadWrite);
		}
		else // create disk spanning archive
		{
			m_bNewSpan = true;
			m_iBytesWritten = 0;
			if (iVolumeSize <= 0) // pkzip span
			{
				if (!m_pZIPCALLBACKFUN)
					ThrowError(ZIP_NOCALLBACK);
				if (!CZipArchive::IsDriveRemovable(szPathName))
					ThrowError(ZIP_NONREMOVABLE);
				m_iSpanMode = pkzipSpan;
			}
			else
			{
				m_iTdSpanData = iVolumeSize;
				m_iSpanMode = tdSpan;
			}

			NextDisk(4, szPathName);
			Write(m_gszExtHeaderSignat, 4, true);
		}
	}
	else // open existing
	{
		OpenFile(szPathName, CFile::modeNoTruncate | ((iMode == CZipArchive::openReadOnly) ? CFile::modeRead : CFile::modeReadWrite));
		// m_uData, m_bAllowModif i m_iSpanMode ustalane automatycznie podczas odczytu central dir
		m_iSpanMode = iVolumeSize == 0 ? suggestedAuto : suggestedTd;
	}
		
}


/*-------------------------------------------------------------------------------------
	Function       : Open
	In Parameters  : CMemFile& mf, int iMode
	Out Parameters : void
	Purpose		   : Open the file lloaded in memory
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipStorage::Open(CMemFile& mf, int iMode)
{
	m_pWriteBuffer.Allocate(m_iWriteBufferSize); 
	m_uBytesInWriteBuffer = 0;
	m_bNewSpan = false;
	m_pFile = &mf;

	if (iMode == CZipArchive::create)
	{
		m_iCurrentDisk = 0;
		m_iSpanMode = noSpan;
		mf.SetLength(0);
	}
	else // open existing
	{
		mf.SeekToBegin();
		m_iSpanMode = suggestedAuto;
	}
}


/*-------------------------------------------------------------------------------------
	Function       : IsSpanMode
	In Parameters  : 
	Out Parameters : int
	Purpose		   : detect span mode
	Author		   : 
-------------------------------------------------------------------------------------*/
int CZipStorage::IsSpanMode()
{
	return m_iSpanMode == noSpan ? 0 : (m_bNewSpan ? 1 : -1);
}

/*-------------------------------------------------------------------------------------
	Function       : ChangeDisk
	In Parameters  : int iNumber
	Out Parameters : 
	Purpose		   : change the disk during extract operations
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipStorage::ChangeDisk(int iNumber)
{
	if (iNumber == m_iCurrentDisk)
		return;

	ASSERT(m_iSpanMode != noSpan);
	m_iCurrentDisk = iNumber;
	OpenFile(m_iSpanMode == pkzipSpan ? ChangePkzipRead() : ChangeTdRead(),
		CFile::modeNoTruncate | CFile::modeRead);
}

/*-------------------------------------------------------------------------------------
	Function       : ThrowError
	In Parameters  : int err
	Out Parameters : void
	Purpose		   : Throw the error
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipStorage::ThrowError(int err)
{
	AfxThrowZipException(err, m_pFile->GetFilePath());
}

/*-------------------------------------------------------------------------------------
	Function       : OpenFile
	In Parameters  : LPCTSTR lpszName, UINT uFlags, bool bThrow
	Out Parameters : bool
	Purpose		   : 
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipStorage::OpenFile(LPCTSTR lpszName, UINT uFlags, bool bThrow)
{
	CFileException* e = new CFileException;
	BOOL bRet = m_pFile->Open(lpszName, uFlags | CFile::shareDenyWrite, e);
	if (!bRet && bThrow)
		throw e;
	e->Delete();
	return bRet != 0;
}

/*-------------------------------------------------------------------------------------
	Function       : SetCurrentDisk
	In Parameters  : int iNumber
	Out Parameters : 
	Purpose		   : set the numer of the current disk
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipStorage::SetCurrentDisk(int iNumber)
{
	m_iCurrentDisk = iNumber;
}

/*-------------------------------------------------------------------------------------
	Function       : GetCurrentDisk
	In Parameters  : 
	Out Parameters : int
	Purpose		   : return the numer of the current disk
	Author		   : 
-------------------------------------------------------------------------------------*/
int CZipStorage::GetCurrentDisk()
{
	return m_iCurrentDisk;
}

/*-------------------------------------------------------------------------------------
	Function       : ChangePkzipRead
	In Parameters  : 
	Out Parameters : CString
	Purpose		   : change the disk in pkSpan mode
	Author		   : 
-------------------------------------------------------------------------------------*/
CString CZipStorage::ChangePkzipRead()
{
	CString szTemp = m_pFile->GetFilePath();
	m_pFile->Close();
	CallCallback(-1 , szTemp);
	return szTemp;
}

/*-------------------------------------------------------------------------------------
	Function       : ChangeTdRead
	In Parameters  : 
	Out Parameters : CString
	Purpose		   : change the disk in tdSpan mode
	Author		   : 
-------------------------------------------------------------------------------------*/
CString CZipStorage::ChangeTdRead()
{
	CString szTemp = GetTdVolumeName(m_iCurrentDisk == m_iTdSpanData);
	m_pFile->Close();
	return szTemp;
}

/*-------------------------------------------------------------------------------------
	Function       : Close
	In Parameters  : bool bAfterException
	Out Parameters : 
	Purpose		   : 
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipStorage::Close(bool bAfterException)
{
	if (!bAfterException)
	{
		Flush();
		if ((m_iSpanMode == tdSpan) && (m_bNewSpan))
		{
			// give to the last volume the zip extension
			CString szFileName = m_pFile->GetFilePath();
			CString szNewFileName = GetTdVolumeName(true);
			m_pFile->Close();
			if (CZipArchive::FileExists(szNewFileName))
				CFile::Remove(szNewFileName);
			CFile::Rename(szFileName, szNewFileName);
		}
		else
#ifdef _DEBUG // to prevent assertion if the file is already closed
 		if (m_pFile->m_hFile != CFile::hFileNull)
#endif
				m_pFile->Close();
	}
	else
#ifdef _DEBUG // to prevent assertion if the file is already closed
 		if (m_pFile->m_hFile != CFile::hFileNull)
#endif
				m_pFile->Close();


	m_pWriteBuffer.Release();
	m_iCurrentDisk = -1;
	m_iSpanMode = noSpan;
	m_pFile = NULL;
}

/*-------------------------------------------------------------------------------------
	Function       : GetTdVolumeName
	In Parameters  : bool bLast, LPCTSTR lpszZipName
	Out Parameters : CString
	Purpose		   : construct the name of the volume in tdSpan mode
	Author		   : 
-------------------------------------------------------------------------------------*/
CString CZipStorage::GetTdVolumeName(bool bLast, LPCTSTR lpszZipName)
{
	CString szFilePath = lpszZipName ? lpszZipName : m_pFile->GetFilePath();
	CString szPath = CZipArchive::GetFilePath(szFilePath);
	CString szName = CZipArchive::GetFileTitle(szFilePath);
	CString szExt;
	if (bLast)
		szExt = _T("zip");
	else
		szExt.Format(_T("%.3d"), m_iCurrentDisk);
	return szPath + szName + _T(".") + szExt;
}

/*-------------------------------------------------------------------------------------
	Function       : NextDisk
	In Parameters  : int iNeeded, LPCTSTR lpszFileName
	Out Parameters : void
	Purpose		   : function used to change disks during writing to the disk spanning archive
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipStorage::NextDisk(int iNeeded, LPCTSTR lpszFileName)
{
	Flush();
	ASSERT(m_iSpanMode != noSpan);
	if (m_iBytesWritten)
	{
		m_iBytesWritten = 0;
		m_iCurrentDisk++;
		if (m_iCurrentDisk >= 999)
			ThrowError(ZIP_TOOMANYVOLUMES);
	} 
	CString szFileName;
	bool bPkSpan = (m_iSpanMode == pkzipSpan);
	if (bPkSpan)
		szFileName  = lpszFileName ? lpszFileName : m_pFile->GetFilePath();
	else
		szFileName =  GetTdVolumeName(false, lpszFileName);

#ifdef _DEBUG // to prevent assertion if the file is already closed
	if (m_pFile->m_hFile != CFile::hFileNull)
#endif
		m_pFile->Close(); // if it is closed, so it will not close

	if (bPkSpan)
	{
		int iCode = iNeeded;
		while (true)
		{
			CallCallback(iCode, szFileName);
			if (CZipArchive::FileExists(szFileName))
				iCode = -2;
			else
			{
				CString label;
				label.Format(_T("pkback# %.3d"), m_iCurrentDisk + 1);
				if (!SetVolumeLabel(CZipArchive::GetDrive(szFileName), label)) /*not write label*/
					iCode = -3;
				else if (!OpenFile(szFileName, CFile::modeCreate | CFile::modeReadWrite, false))
					iCode = -4;
				else
					break;
			}

		}
		m_uCurrentVolSize = GetFreeVolumeSpace();
	}
	else
	{
		m_uCurrentVolSize = m_iTdSpanData;
		OpenFile(szFileName, CFile::modeCreate | CFile::modeReadWrite);
	}
}

/*-------------------------------------------------------------------------------------
	Function       : CallCallback
	In Parameters  : int iCode, CString szTemp
	Out Parameters : void
	Purpose		   : 
	Author		   : 
-------------------------------------------------------------------------------------*/
#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning(disable: 6011)
#endif
void CZipStorage::CallCallback(int iCode, CString szTemp)
{
	ASSERT(m_pZIPCALLBACKFUN);
	if (!(*m_pZIPCALLBACKFUN)(m_iCurrentDisk + 1, iCode, m_pCallbackData))
		throw new CZipException(CZipException::aborted, szTemp);
}
#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning(default: 6011)
#endif
/*-------------------------------------------------------------------------------------
	Function       : GetFreeVolumeSpace
	In Parameters  : 
	Out Parameters : DWORD
	Purpose		   : return the number of free bytes on the current removable disk
	Author		   : 
-------------------------------------------------------------------------------------*/
DWORD CZipStorage::GetFreeVolumeSpace()
{
	ASSERT (m_iSpanMode == pkzipSpan);
	DWORD SectorsPerCluster, BytesPerSector, NumberOfFreeClusters, TotalNumberOfClusters;		
	if (!GetDiskFreeSpace(
		CZipArchive::GetDrive(m_pFile->GetFilePath()),
		&SectorsPerCluster,
		&BytesPerSector,
		&NumberOfFreeClusters,
		&TotalNumberOfClusters))
			return 0;
	_int64 total = SectorsPerCluster * BytesPerSector * NumberOfFreeClusters;
	return (DWORD)total;
}


/*-------------------------------------------------------------------------------------
	Function       : UpdateSpanMode
	In Parameters  : WORD uLastDisk
	Out Parameters : 
	Purpose		   : nly called by CZipCentralDir when opening an existing archive
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipStorage::UpdateSpanMode(WORD uLastDisk)
{
	m_iCurrentDisk = uLastDisk;
	if (uLastDisk)
	{
		// disk spanning detected

		if (m_iSpanMode == suggestedAuto)
			m_iSpanMode = CZipArchive::IsDriveRemovable(m_pFile->GetFilePath()) ? 
				pkzipSpan : tdSpan;
		else
			m_iSpanMode = tdSpan;

		if (m_iSpanMode == pkzipSpan)
		{
			if (!m_pZIPCALLBACKFUN)
					ThrowError(ZIP_NOCALLBACK);
		}
		else /*if (m_iSpanMode == tdSpan)*/
			m_iTdSpanData = uLastDisk; // disk with .zip extension ( the last one)
			
		m_pWriteBuffer.Release(); // no need for this in this case
	}
	else 
		m_iSpanMode = noSpan;

}

/*-------------------------------------------------------------------------------------
	Function       : Write
	In Parameters  : void *pBuf, DWORD iSize, bool bAtOnce
	Out Parameters : void
	Purpose		   : 
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipStorage::Write(void *pBuf, DWORD iSize, bool bAtOnce)
{
	if (!IsSpanMode())
		WriteInternalBuffer((char*)pBuf, iSize);
	else
	{
		// if not at once, one byte is enough free space
		DWORD iNeeded = bAtOnce ? iSize : 1; 
		DWORD uTotal = 0;

		while (uTotal < iSize)
		{
			DWORD uFree;
			while ((uFree = VolumeLeft()) < iNeeded)
			{
				if ((m_iSpanMode == tdSpan) && !m_iBytesWritten && !m_uBytesInWriteBuffer)
					// in the tdSpan mode, if the size of the archive is less 
					// than the size of the packet to be written at once,
					// increase once the size of the volume
					m_uCurrentVolSize = iNeeded;
				else
					NextDisk(iNeeded);
			}

			DWORD uLeftToWrite = iSize - uTotal;
			DWORD uToWrite = uFree < uLeftToWrite ? uFree : uLeftToWrite;
			WriteInternalBuffer((char*)pBuf + uTotal, uToWrite);
			if (bAtOnce)
				return;
			else
				uTotal += uToWrite;
		}

	}
}


/*-------------------------------------------------------------------------------------
	Function       : WriteInternalBuffer
	In Parameters  : char *pBuf, DWORD uSize
	Out Parameters : 
	Purpose		   : write data to the internal buffer
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipStorage::WriteInternalBuffer(char *pBuf, DWORD uSize)
{
	DWORD uWritten = 0;
	while (uWritten < uSize)
	{
		DWORD uFreeInBuffer = GetFreeInBuffer();
		if (uFreeInBuffer == 0)
		{
			Flush();
			uFreeInBuffer = m_pWriteBuffer.GetSize();
		}
		DWORD uLeftToWrite = uSize - uWritten;
		DWORD uToCopy = uLeftToWrite < uFreeInBuffer ? uLeftToWrite : uFreeInBuffer;
		memcpy(m_pWriteBuffer + m_uBytesInWriteBuffer, pBuf + uWritten, uToCopy);
		uWritten += uToCopy;
		m_uBytesInWriteBuffer += uToCopy;
	}
}

/*-------------------------------------------------------------------------------------
	Function       : VolumeLeft
	In Parameters  : 
	Out Parameters : DWORD
	Purpose		   :  return the number of bytes left on the current volume
	Author		   : 
-------------------------------------------------------------------------------------*/
DWORD CZipStorage::VolumeLeft()
{
	// for pkzip span m_uCurrentVolSize is updated after each flush()
	return m_uCurrentVolSize  - m_uBytesInWriteBuffer - ((m_iSpanMode == pkzipSpan) ? 0 : m_iBytesWritten);
}

/*-------------------------------------------------------------------------------------
	Function       : Flush
	In Parameters  : 
	Out Parameters : 
	Purpose		   : flush the data from the read buffer to the disk
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipStorage::Flush()
{
	m_iBytesWritten += m_uBytesInWriteBuffer;
	if (m_uBytesInWriteBuffer)
	{
		m_pFile->Write(m_pWriteBuffer, m_uBytesInWriteBuffer);
		m_uBytesInWriteBuffer = 0;
	}
	if (m_iSpanMode == pkzipSpan) 
		// after writting it is difficult to predict the free space due to 
		// not completly written clusters, write operation may start from 
		// the new cluster
		m_uCurrentVolSize = GetFreeVolumeSpace();
}

/*-------------------------------------------------------------------------------------
	Function       : GetPosition
	In Parameters  : 
	Out Parameters : DWORD
	Purpose		   : return the position in the file, taking into account the bytes in the write buffer
	Author		   : 
-------------------------------------------------------------------------------------*/
DWORD CZipStorage::GetPosition()
{
	return static_cast<DWORD>(m_pFile->GetPosition() + m_uBytesInWriteBuffer);
}


/*-------------------------------------------------------------------------------------
	Function       : GetFreeInBuffer
	In Parameters  : 
	Out Parameters : DWORD
	Purpose		   : how many bytes left free in the write buffer
	Author		   : 
-------------------------------------------------------------------------------------*/
DWORD CZipStorage::GetFreeInBuffer()
{
	return m_pWriteBuffer.GetSize() - m_uBytesInWriteBuffer;
}
