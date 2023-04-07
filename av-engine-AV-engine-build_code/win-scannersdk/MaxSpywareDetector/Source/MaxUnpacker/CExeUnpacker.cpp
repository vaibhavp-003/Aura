#include "CExeUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"
#include "zlib.h"

CExeUnpacker::CExeUnpacker(CMaxPEFile *pMaxPEFile): CUnpackBase(pMaxPEFile)
{	
}

CExeUnpacker::~CExeUnpacker(void)
{
	m_objTempFile.CloseFile();
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

bool CExeUnpacker::IsPacked() 
{
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections == 0x02 && m_pMaxPEFile->m_dwAEPMapped % 0x04 == 0x00)
	{
		m_pbyBuff = new BYTE[255];	
		if(!m_pbyBuff)
		{
			return false;
		}

		//Just some bytes at AEP
		BYTE byCExePackbuff1[]={0x55,0x8B,0xEC,0x81,0xEC};
		
		//sxe..DllInflate Call
		BYTE byCExePackbuff2[]={0x73,0x78,0x65,0x00,0x22,0x20,0x00,0x00,0x22,0x00,0x00,0x00,0x44,0x6C,0x6C,0x49,0x6E,0x66,0x6C,0x61,0x74,0x65};
		if(m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_pMaxPEFile->m_dwAEPMapped, sizeof(byCExePackbuff1),sizeof(byCExePackbuff1)))
		{
			if(memcmp(m_pbyBuff, byCExePackbuff1, sizeof(byCExePackbuff1)) == 0x00)
			{
				if(m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_stSectionHeader[0].PointerToRawData+0x74,sizeof(byCExePackbuff2),sizeof(byCExePackbuff2)))
				{
					if(memcmp(m_pbyBuff, byCExePackbuff2, sizeof(byCExePackbuff2)) == 0x00)
					{
						return true;
					}
				}
			}
		}
	}
	return false;
}


bool CExeUnpacker::Unpack(LPCTSTR szTempFileName)
{	
	HANDLE hTempFile = CreateFile(szTempFileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_WRITE|FILE_SHARE_READ|FILE_SHARE_DELETE, 0, CREATE_ALWAYS, 0, 0);
	if(hTempFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	::CloseHandle(hTempFile);

	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		return false;
	}

	DWORD dwRsrcTableOffset = 0;
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_pMaxPEFile->m_stPEHeader.DataDirectory[2].VirtualAddress, &dwRsrcTableOffset))
	{
		return false ;
	}
	DWORD dwResID=0x63;
	DWORD dwName=0x02;
	DWORD dwLangID=0x00;
	DWORD dwRVA=0x00;
	DWORD dwSize=0x00;
	if(!FindRes(LPCTSTR(&dwResID),LPCWSTR(&dwName),LPCWSTR(&dwLangID),dwRVA,dwSize))
	{
		return false;
	}

	BYTE *bySrcbuff=NULL;
	if(!(bySrcbuff=(BYTE *)MaxMalloc(dwSize)))
	{
		return false;
	}

	if(OUT_OF_FILE==m_pMaxPEFile->Rva2FileOffset(dwRVA,&dwRVA))
	{
		free(bySrcbuff);
		bySrcbuff=NULL;
		return false;
	}
	
	if(!m_pMaxPEFile->ReadBuffer(bySrcbuff,dwRVA,dwSize,dwSize))
	{
		free(bySrcbuff);
		bySrcbuff=NULL;
		return false;
	}

	BYTE *byDestBuff=NULL;
	if(!(byDestBuff=(BYTE*)MaxMalloc(0x8000)))
	{
		free(bySrcbuff);
		bySrcbuff=NULL;
		return false;
	}


	//Inflate Algorithm
	z_stream zcpr;
	memset(&zcpr,0,sizeof(z_stream));
	inflateInit(&zcpr);
	zcpr.avail_in = dwSize;
	zcpr.next_in = bySrcbuff;
	zcpr.total_in = 0x00;
	
	int ret=Z_OK;
	long lOrigToDo = dwSize;
	long lOrigDone = 0;
	int step=0;
	uLong dwTotalOut=0x00;
	

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
	inflateEnd(&zcpr);

	if(bySrcbuff)
	{
		free(bySrcbuff);
		bySrcbuff=NULL;
	}
	if(byDestBuff)
	{
		free(byDestBuff);
		byDestBuff=NULL;
	}

	return bRet;
}


DWORD CExeUnpacker::FindResourceEx(LPCTSTR lpstNameID, DWORD dwRead)
{
	DWORD iRetStatus = 0x00;
	DWORD dwRsrcTableOffset = dwRead, dwRsrcTableStart;
	
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_pMaxPEFile->m_stPEHeader.DataDirectory[2].VirtualAddress, &dwRsrcTableStart))
	{
		return iRetStatus;
	}

	IMAGE_RESOURCE_DIRECTORY Rsrc_Dir;
	memset(&Rsrc_Dir, 0x00, sizeof(IMAGE_RESOURCE_DIRECTORY));
	
	if(!m_pMaxPEFile->ReadBuffer(&Rsrc_Dir, dwRsrcTableOffset, sizeof(IMAGE_RESOURCE_DIRECTORY), sizeof(IMAGE_RESOURCE_DIRECTORY)))
	{
		return iRetStatus;
	}
	DWORD	dwTotalRsrcEntry = Rsrc_Dir.NumberOfIdEntries + Rsrc_Dir.NumberOfNamedEntries;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pRsrc_Dir_Entry = new IMAGE_RESOURCE_DIRECTORY_ENTRY[dwTotalRsrcEntry];

	if(pRsrc_Dir_Entry == NULL)
	{
		return iRetStatus;
	}
	DWORD	dwReadOffset = dwRsrcTableOffset + sizeof(IMAGE_RESOURCE_DIRECTORY);
	if(!m_pMaxPEFile->ReadBuffer(pRsrc_Dir_Entry, dwReadOffset, (sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)*dwTotalRsrcEntry), (sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)*dwTotalRsrcEntry)))
	{
		delete pRsrc_Dir_Entry;
		return iRetStatus;
	}
	
	IMAGE_RESOURCE_DIR_STRING_U Res_Name;
	memset(&Res_Name, 0x00, sizeof(IMAGE_RESOURCE_DIR_STRING_U));
	LPTSTR		lpstRsrcName = NULL;
	WORD		wStrLen = 0x00;
	
	DWORD dwIndex = 0x00;
	for(dwIndex = 0x00; dwIndex < dwTotalRsrcEntry; dwIndex++)
	{	
		if(pRsrc_Dir_Entry[dwIndex].NameIsString)
		{
			dwReadOffset = dwRsrcTableStart + pRsrc_Dir_Entry[dwIndex].NameOffset;
			if(!m_pMaxPEFile->ReadBuffer(&wStrLen, dwReadOffset, sizeof(WORD), sizeof(WORD)))
			{
				delete pRsrc_Dir_Entry;
				return iRetStatus;
			}
			if(wStrLen == 0x00)
			{
				continue;
			}
			lpstRsrcName = new WCHAR[wStrLen+1];
			if(lpstRsrcName == NULL)
			{
				delete pRsrc_Dir_Entry;
				return iRetStatus;
			}
			memset(lpstRsrcName, 0x00, (wStrLen+1)*sizeof(WCHAR));

			if(!m_pMaxPEFile->ReadBuffer(lpstRsrcName, dwReadOffset + sizeof(WORD), wStrLen*sizeof(WCHAR), wStrLen*sizeof(WCHAR)))
			{
				delete pRsrc_Dir_Entry;
				delete lpstRsrcName;
				lpstRsrcName = NULL;
				return iRetStatus;
			}
			if(wcscmp(lpstRsrcName, lpstNameID) == 0x00)
			{
				break;
			}
			if(lpstRsrcName)
			{
				delete lpstRsrcName;
				lpstRsrcName = NULL;
			}
		}
		else
		{
			if(pRsrc_Dir_Entry[dwIndex].Id == *((DWORD*) &lpstNameID[0]))
			{
				break;
			}
		}		
	}

	if(lpstRsrcName)
	{
		delete lpstRsrcName;
		lpstRsrcName = NULL;
	}

	if(dwIndex == dwTotalRsrcEntry)
	{
		delete pRsrc_Dir_Entry;
		return iRetStatus;
	}
	iRetStatus = pRsrc_Dir_Entry[dwIndex].OffsetToDirectory;
	delete pRsrc_Dir_Entry;
	return iRetStatus;
}

int CExeUnpacker::FindRes(LPCTSTR lpstNameID, LPCTSTR lpstLaunguage, LPCTSTR lpstLangID, DWORD &dwRVA, DWORD &dwSize)
{
	int iRetStatus = 0x00 ;
	DWORD dwRsrcTableOffset = 0;
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_pMaxPEFile->m_stPEHeader.DataDirectory[2].VirtualAddress, &dwRsrcTableOffset))
	{
		return iRetStatus ;
	}
	
	DWORD dwOffset = FindResourceEx(lpstNameID,dwRsrcTableOffset) ;
	if(dwOffset == 0x00)
	{
		return iRetStatus ;
	}
	DWORD dwReadOffset = dwRsrcTableOffset + dwOffset ;
	dwOffset = FindResourceEx(lpstLaunguage,dwReadOffset) ; 
	if(dwOffset == 0x00)
	{
		return iRetStatus ;
	}
	dwReadOffset = dwRsrcTableOffset + dwOffset ;
	dwOffset = FindResourceEx(lpstLangID,dwReadOffset) ; 
	if(dwOffset == 0x00)
	{
		return iRetStatus ;
	}
	BYTE byBuffer[0x08] = {0x00} ;
	dwReadOffset = dwOffset + dwRsrcTableOffset ;
	if(!m_pMaxPEFile->ReadBuffer(byBuffer, dwReadOffset, 8, 8))
	{
		return iRetStatus ;
	}
	dwRVA = *((DWORD*)&byBuffer[0]) ;
	dwSize = *((DWORD*)&byBuffer[4]) ;
	iRetStatus = 0x01 ;

	return iRetStatus ;
}