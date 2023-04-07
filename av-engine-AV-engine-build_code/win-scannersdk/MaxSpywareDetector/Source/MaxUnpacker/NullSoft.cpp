#include "NullSoft.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"
#include <shlwapi.h>
#include "zlib.h"


CNullSoft::CNullSoft(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{
}

CNullSoft::~CNullSoft(void)
{
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_objTempFile.CloseFile();
}

bool CNullSoft::IsPacked() 
{
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff=new BYTE[255];

	memset(m_pbyBuff,0x00,255);

	const BYTE byNullSoftSig[]={0x4E,0x75,0x6C,0x6C,0x73,0x6F,0x66,0x74,0x49,0x6E,0x73,0x74};

     //or if(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].PointerToRawData +m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].SizeOfRawData + 0x08 + sizeof(byNullSoftSig)+0x01<=m_pMaxPEFile->m_dwFileSize)
	if(m_pMaxPEFile->m_dwFileSize>m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].PointerToRawData +m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].SizeOfRawData + 0x21)
	{
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,FA(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].PointerToRawData +m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].SizeOfRawData)+0x08,sizeof(byNullSoftSig),sizeof(byNullSoftSig)))
		{
			return false;
		}
		if(memcmp(m_pbyBuff,byNullSoftSig,sizeof(byNullSoftSig))==0x00)
		{
			return true;
		}
	}
	return false;
}

bool CNullSoft::Unpack(LPCTSTR szTempFileName)
{	
	bool	bRet = false;
	BYTE	*byfullFilebuff=NULL;

    DWORD dwSizetoAllocate=m_pMaxPEFile->m_dwFileSize-FA(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].PointerToRawData +m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].SizeOfRawData);
	
	if(m_pMaxPEFile->m_stPEHeader.DataDirectory[4].VirtualAddress>FA(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].PointerToRawData +m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].SizeOfRawData))
	{
		dwSizetoAllocate=m_pMaxPEFile->m_stPEHeader.DataDirectory[4].VirtualAddress-FA(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].PointerToRawData +m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].SizeOfRawData);
	}
	if(!(byfullFilebuff=(BYTE*)MaxMalloc(dwSizetoAllocate)))
	{
		return bRet;
	}

	if(!m_pMaxPEFile->ReadBuffer(byfullFilebuff,FA(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].PointerToRawData +m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].SizeOfRawData),dwSizetoAllocate,dwSizetoAllocate))
	{
		return bRet;
	}

	DWORD dwOffset=0;

	//if(dwOffset+0x22>dwSizetoAllocate)
	if(dwSizetoAllocate<0x22)
	{
		free(byfullFilebuff);
		byfullFilebuff=NULL;
		return bRet;
	}

	DWORD dwUnpackSize = 1<<16;
	DWORD dwCheckForMultipleFiles=0;
	BYTE byLZMAProp[0x4]={0};
	*(DWORD*)&byLZMAProp[0]=*(DWORD*)&byfullFilebuff[dwOffset+0x1C];

	/*TCHAR szTempFolderPath[MAX_PATH] = {0};
	GetModuleFileName(NULL, szTempFolderPath, MAX_PATH);
	WCHAR *cExtPtr = wcsrchr(szTempFolderPath, '\\');
	if(cExtPtr) *cExtPtr = '\0';
	_tcsncat_s(szTempFolderPath, MAX_PATH, _T("\\TempFolder"), 12);
	if(FALSE == PathIsDirectory(szTempFolderPath))
	{
		CreateDirectory(szTempFolderPath, 0);
	}
	_stprintf_s(LPTSTR(szTempFileName), MAX_PATH, _T("%s\\%08x_%05d_%d"), szTempFolderPath, GetTickCount(), GetCurrentThreadId(), rand());
	if(FALSE == PathIsDirectory(szTempFileName))
	{
		CreateDirectory(szTempFileName, 0);
	}*/

	//Check For Multiple Files
	if(byLZMAProp[0]!=0x5D)
	{
		dwCheckForMultipleFiles=1;
		if(dwSizetoAllocate<0x26)
		{
			free(byfullFilebuff);
			byfullFilebuff=NULL;
			return bRet;
		}
		*(DWORD*)&byLZMAProp[0]=*(DWORD*)&byfullFilebuff[dwOffset+0x20];
		//**** Check For LZMA ****//
		if(byLZMAProp[0]!=0x5D)
		{
			free(byfullFilebuff);
			byfullFilebuff=NULL;
			return bRet;
		}
		
	}

	
	

	if(dwCheckForMultipleFiles==0x00) //Single File Case
	{
		//Once tempfolder extraction is done
		//TCHAR szTempFilePath[MAX_PATH];
		//_stprintf_s(&szTempFilePath[0], MAX_PATH, _T("%s\\MaxExtract1.tmp"), szTempFileName);
		//HANDLE hTempFile = CreateFile(szTempFilePath, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_WRITE|FILE_SHARE_READ|FILE_SHARE_DELETE, 0, CREATE_ALWAYS, 0, 0);
		
		/******Code to be deleted later******/
		HANDLE hTempFile = INVALID_HANDLE_VALUE;
		hTempFile = CreateFile(szTempFileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_WRITE|FILE_SHARE_READ|FILE_SHARE_DELETE, 0, CREATE_ALWAYS, 0, 0);
		/*****************************/

		if(hTempFile == INVALID_HANDLE_VALUE)
		{
			free(byfullFilebuff);
			byfullFilebuff=NULL;
			return bRet;
		}
		::CloseHandle(hTempFile);

		if(!m_objTempFile.OpenFile(szTempFileName, true))
		{
			free(byfullFilebuff);
			byfullFilebuff=NULL;
			return bRet;
		}

		DWORD dwDestSize=0;
		if(dwSizetoAllocate<0x26)
		{
			free(byfullFilebuff);
			byfullFilebuff=NULL;
			return bRet;
		}


    /*

	//Try for Zlib Algorithm

	//Inflate Algorithm
	z_stream zcpr;
	memset(&zcpr,0,sizeof(z_stream));
	inflateInit(&zcpr);
	zcpr.avail_in = *(DWORD*)&byfullFilebuff[0x1C]&0x7FFFFFFF;
	zcpr.next_in = &byfullFilebuff[0x21];
	zcpr.total_in = 0x00;
	
	int ret=Z_OK;
	long lOrigToDo = *(DWORD*)&byfullFilebuff[0x1C]&0x7FFFFFFF;
	long lOrigDone = 0;
	int step=0;
	uLong dwTotalOut=0x00;
	BYTE *byDestBuff=new BYTE[0x8000];
	

	do
	{
		memset(byDestBuff,0,0x8000);
		zcpr.next_out = byDestBuff;
		long all_read_before = zcpr.total_in;
		zcpr.avail_in = min(lOrigToDo,0x8000);
		zcpr.avail_out = 0x8000;
		ret=inflate(&zcpr,Z_SYNC_FLUSH);
		lOrigDone += (zcpr.total_in-all_read_before);
		lOrigToDo -= (zcpr.total_in-all_read_before);
		step++;
	} while (ret==Z_OK && (m_objTempFile.WriteBuffer(byDestBuff,dwTotalOut,zcpr.total_out-dwTotalOut,zcpr.total_out-dwTotalOut)) && (dwTotalOut=zcpr.total_out) );

	bool bRet = false;
	if(ret==Z_STREAM_END && (zcpr.total_out-dwTotalOut>0))
	{
		m_objTempFile.WriteBuffer(byDestBuff,dwTotalOut,zcpr.total_out-dwTotalOut,zcpr.total_out-dwTotalOut);
		bRet = true;
	}
	inflateEnd(&zcpr);*/

        if(!(dwDestSize = LZMADecompress(byLZMAProp, /*0x8A4C*/dwSizetoAllocate-0x21-0x04,dwUnpackSize/*0x16090+0x15B0*/, 0x00, 0x00, NULL,&byfullFilebuff[0x21],0,false)))
		{
			free(byfullFilebuff);
			byfullFilebuff=NULL;
			return bRet;
		}

		m_objTempFile.CloseFile();
		
		/*if(!m_objTempFile.OpenFile(szTempFileName, true))
		{
			free(byfullFilebuff);
			byfullFilebuff=NULL;
			return false;
		}


		TCHAR szTempFilePath_script[MAX_PATH];
		_stprintf_s(&szTempFilePath_script[0], MAX_PATH, _T("%s\\MaxExtract0.tmp"), szTempFileName);
		HANDLE hTempFile_script = CreateFile(szTempFilePath_script, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_WRITE|FILE_SHARE_READ|FILE_SHARE_DELETE, 0, CREATE_ALWAYS, 0, 0);
		if(hTempFile_script == INVALID_HANDLE_VALUE)
		{
			free(byfullFilebuff);
			byfullFilebuff=NULL;
			return false;
		}
		BYTE *byBuff=new BYTE[*(DWORD*)&byfullFilebuff[0x14]];
		memset(byBuff,0,*(DWORD*)&byfullFilebuff[0x14]);
		if(!m_objTempFile.ReadBuffer(byBuff,0,*(DWORD*)&byfullFilebuff[0x14],*(DWORD*)&byfullFilebuff[0x14]))
		{
			free(byfullFilebuff);
			byfullFilebuff=NULL;
			return false;
		}
		LPDWORD pdwNoofBytesWritten=new DWORD;
		WriteFile(hTempFile_script,byBuff,*(DWORD*)&byfullFilebuff[0x14],pdwNoofBytesWritten,NULL);
		::CloseHandle(hTempFile_script);


		if(dwDestSize<=*(DWORD*)&byfullFilebuff[0x14]+0x08)
		{
			free(byfullFilebuff);
			byfullFilebuff=NULL;
			return false;
		}

		if(!m_objTempFile.CopyData(*(DWORD*)&byfullFilebuff[0x14]+0x08,0,dwDestSize-*(DWORD*)&byfullFilebuff[0x14]-0x08))
		{
			free(byfullFilebuff);
			byfullFilebuff=NULL;
			return false;
		}
		if(!m_objTempFile.ForceTruncate(dwDestSize-*(DWORD*)&byfullFilebuff[0x14]+0x08))
		{
			free(byfullFilebuff);
			byfullFilebuff=NULL;
			return false;
		}
        */
		if(byfullFilebuff)
		{
			free(byfullFilebuff);
			byfullFilebuff=NULL;

		}
		return true;	
	}
	else
	{
		int		i=0;
		DWORD	dwSrcSizeInIncrements=0x1C;
		DWORD	dwSrcSize=0;

		while(dwSrcSizeInIncrements+0x0A <= dwSizetoAllocate)
		{
			//TCHAR szTempFilePath[MAX_PATH];
			*(DWORD*)&byLZMAProp[0]=*(DWORD*)&byfullFilebuff[dwSrcSizeInIncrements+0x04];
			dwSrcSize=*(DWORD*)&byfullFilebuff[dwSrcSizeInIncrements]&0x7FFFFFFF;
			if(byLZMAProp[0]==0x5D)
			{
				//_stprintf_s(&szTempFilePath[0], MAX_PATH, _T("%s\\MaxExtract%d.tmp"), szTempFileName, i);
				//HANDLE hTempFile = CreateFile(szTempFilePath, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_WRITE|FILE_SHARE_READ|FILE_SHARE_DELETE, 0, CREATE_ALWAYS, 0, 0);
				HANDLE hTempFile = CreateFile(szTempFileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_WRITE|FILE_SHARE_READ|FILE_SHARE_DELETE, 0, CREATE_ALWAYS, 0, 0);
				if(hTempFile == INVALID_HANDLE_VALUE)
				{
					free(byfullFilebuff);
					byfullFilebuff=NULL;
					return bRet;
				}
				::CloseHandle(hTempFile);

				if(!m_objTempFile.OpenFile(szTempFileName, true))
				{
					free(byfullFilebuff);
					byfullFilebuff=NULL;
					return bRet;
				}


				DWORD dwDestSize=0;

				if(dwSrcSizeInIncrements+0x04+(*(DWORD*)&byfullFilebuff[dwSrcSizeInIncrements]&0x7FFFFFFF)>dwSizetoAllocate-0x04)
				{
					dwSrcSize=dwSizetoAllocate-dwSrcSizeInIncrements-0x09-0x04;
				}

				if(!(dwDestSize = LZMADecompress(byLZMAProp, dwSrcSize-0x05,dwUnpackSize*2, 0x00, 0x00, NULL,&byfullFilebuff[dwSrcSizeInIncrements+0x09],0,false)))
				{
					free(byfullFilebuff);
					byfullFilebuff=NULL;
					return bRet;
				}
				
                //Currently dropping onlty 1 file
				m_objTempFile.CloseFile();
				break;


			}
			dwSrcSizeInIncrements+=dwSrcSize+0x04;
			i++;
		}
		if(byfullFilebuff)
		{
			free(byfullFilebuff);
			byfullFilebuff=NULL;

		}
		return true;

	}
	return bRet;
}