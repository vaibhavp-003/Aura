#include "NonPEFile.h"
#include "mspack.h"
#include <shlwapi.h>
#include "MaxConstant.h"
#include "MaxMACUBFile.h"
#include "MaxISOScanner.h"

CNonPEFile::CNonPEFile()
{
}

CNonPEFile::~CNonPEFile(void)
{
}

bool CNonPEFile::ExtractFile(int iFileType, TCHAR *szFileName, TCHAR *szExtractedPath)
{	
	// Get temp folder path where to extrat the files
	TCHAR szTempFolderPath[MAX_PATH] = {0};
	GetModuleFileName(NULL, szTempFolderPath, MAX_PATH);
	WCHAR *cExtPtr = wcsrchr(szTempFolderPath, '\\');
	if(cExtPtr) *cExtPtr = '\0';
	_tcsncat_s(szTempFolderPath, MAX_PATH, _T("\\TempFolder"), 12);
	if(FALSE == PathIsDirectory(szTempFolderPath))
	{
		CreateDirectory(szTempFolderPath, 0);
	}
	_stprintf_s(szExtractedPath, MAX_PATH, _T("%s\\%08x_%05d_%d"), szTempFolderPath, GetTickCount(), GetCurrentThreadId(), rand());
	if(FALSE == PathIsDirectory(szExtractedPath))
	{
		CreateDirectory(szExtractedPath, 0);
	}

	switch(iFileType)
	{
	case VIRUS_FILE_TYPE_MSSZDD:
		{
			return ExtractMSSZDDFile(szFileName, szExtractedPath);
		}
	case VIRUS_FILE_TYPE_CRYPTCFF:
		{
			return ExtractCryptCFFFile(szFileName, szExtractedPath);
		}
	case VIRUS_FILE_TYPE_MSCHM:
		{
			return ExtractMSCHMFile(szFileName, szExtractedPath);
		}
	case VIRUS_FILE_TYPE_MSCAB:
		{
			return ExtractCabFile(szFileName, szExtractedPath);
		}
	case VIRUS_FILE_TYPE_UB:
		{
			return ExtractUBFile(szFileName, szExtractedPath);
		}
	case VIRUS_FILE_TYPE_DMG:
		{
			return ExtractDMGFile(szFileName, szExtractedPath);
		}
	}
	return false;
}

bool CNonPEFile::ExtractMSSZDDFile(TCHAR *szFileName, TCHAR *szExtractedPath)
{
	bool bRet = false;
	char szFilePath[MAX_PATH] = {0}, szTempFilePath[MAX_PATH] = {0};
	sprintf_s(szFilePath, MAX_PATH, "%S", szFileName);
	sprintf_s(szTempFilePath, MAX_PATH, "%S\\%d.mup", szExtractedPath, rand());

	msszdd_decompressor *szdd = mspack_create_szdd_decompressor(NULL);
	if(szdd)
	{
		msszddd_header *hdr = szdd->open(szdd, szFilePath);
		if(hdr)
		{
			if(MSPACK_ERR_OK == szdd->extract(szdd, hdr, szTempFilePath))
			{
				bRet = true;
			}
			szdd->close(szdd, hdr);	
		}
		mspack_destroy_szdd_decompressor(szdd);	
	}
	return bRet;
}

bool CNonPEFile::ExtractCryptCFFFile(TCHAR *szFileName, TCHAR *szExtractedPath)
{
	bool bRet = false;
	
	HANDLE hSrcFile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hSrcFile)
	{
		return bRet;
	}

	DWORD dwFileSize = 0, dwBytesRead = 0;
	SetFilePointer(hSrcFile, 8, NULL, FILE_BEGIN);
	ReadFile(hSrcFile, &dwFileSize, 4, &dwBytesRead, NULL);
	if(dwBytesRead != 4)
	{
		CloseHandle(hSrcFile);
		return bRet;
	}
	dwFileSize ^= 0xFFFFFFFF;
	
	SetFilePointer(hSrcFile, 0x10, NULL, FILE_BEGIN);
	
	TCHAR szTempFilePath[MAX_PATH] = {0};
	_stprintf_s(szTempFilePath, MAX_PATH, _T("%s\\%d.mup"), szExtractedPath, rand());

	HANDLE hDestFile = CreateFile(szTempFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hDestFile)
	{
		CloseHandle(hSrcFile);
		return bRet;
	}

	const int CFF_BUFF_SIZE	= 0x2800;
	BYTE *pReadBuffer = new BYTE[CFF_BUFF_SIZE];
	if(!pReadBuffer)
	{
		CloseHandle(hSrcFile);
		CloseHandle(hDestFile);
		return bRet;
	}
		
	DWORD dwBytes2Read = 0, dwBytesWritten = 0;
	for(DWORD dwTotalBytesRead = 0; dwTotalBytesRead < dwFileSize;)
	{
		dwBytes2Read = CFF_BUFF_SIZE;
		if ((dwFileSize - dwTotalBytesRead) < CFF_BUFF_SIZE)
		{
			dwBytes2Read = dwFileSize - dwTotalBytesRead;
		}

		ReadFile(hSrcFile, pReadBuffer, dwBytes2Read, &dwBytesRead, NULL);		
		dwTotalBytesRead += dwBytesRead;

		for(int i = 0; i < dwBytesRead; i++)
		{
			pReadBuffer[i] ^= 0xFF;
		}
		WriteFile(hDestFile, pReadBuffer, dwBytesRead, &dwBytesWritten, NULL);
		if(dwBytes2Read < CFF_BUFF_SIZE)
		{
			break;
		}
	}		
	CloseHandle(hDestFile);
	hDestFile = INVALID_HANDLE_VALUE;

	CloseHandle(hSrcFile);
	hSrcFile = INVALID_HANDLE_VALUE;

	if(pReadBuffer)
	{
		delete []pReadBuffer;
		pReadBuffer = NULL;
	}
	return true;
}

bool CNonPEFile::ExtractMSCHMFile(TCHAR *szFileName, TCHAR *szExtractedPath)
{
	bool bRet = false;
	char szFilePath[MAX_PATH] = {0}, szTempFilePath[MAX_PATH] = {0};
	sprintf_s(szFilePath, MAX_PATH, "%S", szFileName);

	mschm_decompressor *chm = mspack_create_chm_decompressor(NULL);
	if(chm)
	{
		mschmd_header *hdr = chm->open(chm, szFilePath);
		if(hdr)
		{
			mschmd_file *file = hdr->files;
			while(file)
			{
				if(strstr(file->filename, ".") && NULL == strstr(file->filename, ".hhc") && NULL == strstr(file->filename, ".hhk"))
				{
					sprintf_s(szTempFilePath, MAX_PATH, "%S\\%s.mup", szExtractedPath, file->filename + 1);
					if(MSPACK_ERR_OK == chm->extract(chm, file, szTempFilePath))
					{
						bRet = true;
					}
				}
				file = file->next;
			}
			chm->close(chm, hdr);	
		}
		mspack_destroy_chm_decompressor(chm);
	}
	return bRet;
}
bool CNonPEFile::ExtractUBFile(TCHAR *szFileName, TCHAR *szExtractedPath)
{
	bool	bRet = false;
	int		iFilesCnt = 0x00;

	CMaxPEFile		*pMaxPackPEFile = new CMaxPEFile();
	CMaxMACUBFile	objUBFile;
	
	if (szFileName == NULL || szExtractedPath == NULL)
	{
		if(pMaxPackPEFile)
		{
			delete pMaxPackPEFile;
			pMaxPackPEFile = NULL;
		}
		return bRet;
	}

	if (!pMaxPackPEFile->OpenFile(szFileName,false))
	{
		if(pMaxPackPEFile)
		{
			delete pMaxPackPEFile;
			pMaxPackPEFile = NULL;
		}
		return bRet;
	}
	
	if (objUBFile.IsValidUBFile(pMaxPackPEFile))
	{
		objUBFile.SetDestDirPath(szExtractedPath);
		if (objUBFile.ExtractUBFile(pMaxPackPEFile,&iFilesCnt) > 0x00)
		{
			bRet  = true;
		}
	}
	
	if(pMaxPackPEFile)
	{
		pMaxPackPEFile->CloseFile();
		delete pMaxPackPEFile;
		pMaxPackPEFile = NULL;
	}
	return bRet;
}

bool CNonPEFile::ExtractDMGFile(TCHAR *szFileName, TCHAR *szExtractedPath)
{
	bool	bRet = false;

	if (szFileName == NULL || szExtractedPath == NULL)
	{
		return bRet;
	}

	CMaxPEFile		*pMaxDMGFile = new CMaxPEFile();
	
	if (pMaxDMGFile->OpenFile(szFileName,false))
	{
		CMaxIsoScanner	objISOFile(pMaxDMGFile);
		if (objISOFile.IsValidDMGFile())
		{
			objISOFile.SetDestDirPath(szExtractedPath);
			bRet = objISOFile.ExtractDMGFile(pMaxDMGFile);
		}

		if (pMaxDMGFile)
		{
			delete pMaxDMGFile;
			pMaxDMGFile = NULL;
		}

		return bRet;
	}

	if (pMaxDMGFile)
	{
		pMaxDMGFile->CloseFile();
		delete pMaxDMGFile;
		pMaxDMGFile = NULL;
	}

	return bRet;
}
bool CNonPEFile::ExtractCabFile(TCHAR *szFileName, TCHAR *szExtractedPath)
{
	bool bRet = false;
	char szFilePath[MAX_PATH] = {0}, szTempFilePath[MAX_PATH] = {0};
	sprintf_s(szFilePath, MAX_PATH, "%S", szFileName);

	mscab_decompressor *cab = mspack_create_cab_decompressor(NULL);
	if(cab)
	{
		mscabd_cabinet *hdr = cab->open(cab, szFilePath);
		if(hdr)
		{
			mscabd_file *file = hdr->files;
			int i = 0;
			while(file)
			{
				i++;
				sprintf_s(szTempFilePath, MAX_PATH, "%S\\MaxExtract%d.mup", szExtractedPath, i);//file->filename + 1);
				if(MSPACK_ERR_OK == cab->extract(cab, file, szTempFilePath))
				{
					bRet = true;
				}
				file = file->next;
			}
			cab->close(cab, hdr);	
		}
		mspack_destroy_cab_decompressor(cab);
	}
	return bRet;
}
