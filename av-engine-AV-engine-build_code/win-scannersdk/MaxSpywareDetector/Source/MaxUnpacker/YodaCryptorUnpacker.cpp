#include "YodaCryptorUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CYodaCryptorDecrypt::CYodaCryptorDecrypt(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{	
	pSectionCheckList=NULL;
}

CYodaCryptorDecrypt::~CYodaCryptorDecrypt(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_objTempFile.CloseFile();
}

bool CYodaCryptorDecrypt::IsPacked() 
{
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&
		(m_pMaxPEFile->m_dwAEPMapped&0x000000FF)%0x60==0x00)
	{
		m_pbyBuff = new BYTE[255];
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,0x26,0x26))
		{
			return false;
		}
		m_dwOffsetMove=0x00;
		if(*(DWORD*)&m_pbyBuff[m_dwOffsetMove]==0x53EC8B55 && *(WORD*)&m_pbyBuff[m_dwOffsetMove+0x04]==0x5756)
		{
			m_dwOffsetMove=0x06;
			if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x26],m_pMaxPEFile->m_dwAEPMapped+0x26,m_dwOffsetMove,m_dwOffsetMove))
			{
				return false;
			}
		}

		if((*(WORD*)&m_pbyBuff[m_dwOffsetMove+0] == 0xE860 && *(DWORD*)&m_pbyBuff[m_dwOffsetMove+2]==0x00000000 && m_pbyBuff[m_dwOffsetMove+6]==0x5D 
			&& *(WORD*)&m_pbyBuff[m_dwOffsetMove+0x7]==0xED81 && m_pbyBuff[m_dwOffsetMove+0xD]==0xB9 && (*(WORD*)&m_pbyBuff[m_dwOffsetMove+0x12]==0xBD8D && (m_eYodaType=e8dBd)||
			*(WORD*)&m_pbyBuff[m_dwOffsetMove+0x12]==0xE981 && (m_eYodaType=e81E9))))
		{
			return true;
		}
	}
	return false;
}

bool CYodaCryptorDecrypt::Unpack(LPCTSTR szTempFileName)
{	
	if(!ReOrganizeFile(szTempFileName))
	{
		return false;
	}

	BYTE *byYodaCryptorDecryptbuff=NULL;

	DWORD dwDecryptionSize=0;
	DWORD dwDecryptorSize=0;
	DWORD dwEBPValue=m_objTempFile.m_stPEHeader.AddressOfEntryPoint+m_dwImageBase+0x6+m_dwOffsetMove;
	if(m_eYodaType==e8dBd)
	{
		dwDecryptionSize=*(DWORD*)&m_pbyBuff[0xE];
		dwDecryptorSize=*(DWORD*)&m_pbyBuff[0x14]-*(DWORD*)&m_pbyBuff[0x9]-0x14;
		m_dwOffsetMove+=0x14;
		dwEBPValue-=*(DWORD*)&m_pbyBuff[0x9];
	}
	else if(m_eYodaType==e81E9)
	{
		dwDecryptionSize=*(DWORD*)&m_pbyBuff[0x14]-*(DWORD*)&m_pbyBuff[0x1A];
		dwDecryptorSize=*(DWORD*)&m_pbyBuff[0x22]-*(DWORD*)&m_pbyBuff[0xF]-0x1A;
		m_dwOffsetMove+=0x1A;
		dwEBPValue-=*(DWORD*)&m_pbyBuff[0xF];
	}
	m_dwOffsetMove+=m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0x06;


	if(!(byYodaCryptorDecryptbuff=(BYTE*)MaxMalloc(m_objTempFile.m_dwFileSize)))
	{
		return false;
	}

	memset(byYodaCryptorDecryptbuff,0x0,m_objTempFile.m_dwFileSize);



	//Reading the full file with Virtual Sizes
	if(!m_objTempFile.ReadBuffer(byYodaCryptorDecryptbuff,0,m_objTempFile.m_dwFileSize,m_objTempFile.m_dwFileSize))
	{
		free(byYodaCryptorDecryptbuff);
		byYodaCryptorDecryptbuff=NULL;
		return false;
	}

	if(dwDecryptionSize>m_objTempFile.m_dwFileSize || dwDecryptorSize>m_objTempFile.m_dwFileSize)
	{
		//Return when the sizes to decrypt or the decryptor size> filesize
		free(byYodaCryptorDecryptbuff);
		byYodaCryptorDecryptbuff=NULL;
		return false;
	}

	while(byYodaCryptorDecryptbuff[m_dwOffsetMove]!=0xAC)
	{
		if(m_dwOffsetMove+0x01>m_objTempFile.m_dwFileSize)
		{
			free(byYodaCryptorDecryptbuff);
			byYodaCryptorDecryptbuff=NULL;
			return false;
		}
		m_dwOffsetMove++;
		dwDecryptorSize--;
	}
	m_dwOffsetMove++;
	dwDecryptorSize--;

	if(!UnPackYodaCryporPolyEmulator(&byYodaCryptorDecryptbuff[m_dwOffsetMove],&byYodaCryptorDecryptbuff[m_dwOffsetMove+dwDecryptorSize],dwDecryptionSize,dwDecryptorSize-0x03))
	{
		free(byYodaCryptorDecryptbuff);
		byYodaCryptorDecryptbuff = NULL;
		return false;
	}


	m_dwOffsetMove+=dwDecryptorSize;


	//if(m_dwOffsetMove+0x29+4>m_objTempFile.m_dwFileSize)
	//{
	//	free(byYodaCryptorDecryptbuff);
	//	byYodaCryptorDecryptbuff = NULL;
	//	return false;
	//}

	//if(*(DWORD*)&byYodaCryptorDecryptbuff[m_dwOffsetMove+0x29]+dwEBPValue+4-m_dwImageBase>m_objTempFile.m_dwFileSize)
	//{
	//	free(byYodaCryptorDecryptbuff);
	//	byYodaCryptorDecryptbuff = NULL;
	//	return false;
	//}

	//DWORD dwYodaFlag=*(DWORD*)&byYodaCryptorDecryptbuff[*(DWORD*)&byYodaCryptorDecryptbuff[m_dwOffsetMove+0x29]+dwEBPValue-m_dwImageBase];
	//

	//0x32 Moves to the offset where the call resolve starts
	if(m_eYodaType==e8dBd)
	{
		m_dwOffsetMove+=0x31;
	}
	else if(m_eYodaType==e81E9)
	{
		m_dwOffsetMove+=0x50;
	}

	if(m_dwOffsetMove+1>m_objTempFile.m_dwFileSize)
	{
		free(byYodaCryptorDecryptbuff);
		byYodaCryptorDecryptbuff = NULL;
		return false;
	}
	m_dwOffsetMove+=1+byYodaCryptorDecryptbuff[m_dwOffsetMove];


	//Bypasses the calls which are reolved for internal use in YodaCrypt
	//Move 0xC bytes ahead to a jump which then takes to an antidebug
	if(m_eYodaType==e8dBd)
	{
		m_dwOffsetMove+=0xF3;
		m_dwOffsetMove+=0xB;
	}
	else if(m_eYodaType==e81E9)
	{
		m_dwOffsetMove+=0x153;
		m_dwOffsetMove+=0xF;
	}

	if(m_dwOffsetMove+1>m_objTempFile.m_dwFileSize)
	{
		free(byYodaCryptorDecryptbuff);
		byYodaCryptorDecryptbuff = NULL;
		return false;
	}
	m_dwOffsetMove+=byYodaCryptorDecryptbuff[m_dwOffsetMove]+0x01;

	//Move 0x32 bytes down which takes to the decompression of the sections
	m_dwOffsetMove+=0x34;
	if(m_eYodaType==e81E9)
	{
		m_dwOffsetMove+=0x10;
	}
	if(m_dwOffsetMove+4>m_objTempFile.m_dwFileSize)
	{
		free(byYodaCryptorDecryptbuff);
		byYodaCryptorDecryptbuff = NULL;
		return false;
	}
	m_dwOffsetMove+=*(DWORD*)&byYodaCryptorDecryptbuff[m_dwOffsetMove]+0x04;

	DWORD dwBackOffset=0x00;

	if(m_eYodaType==e8dBd)
	{
		m_dwOffsetMove+=0x18;
	}

	else if(m_eYodaType==e81E9)
	{
		m_dwOffsetMove+=0x10;
		if(m_dwOffsetMove+4>m_objTempFile.m_dwFileSize)
		{
			free(byYodaCryptorDecryptbuff);
			byYodaCryptorDecryptbuff = NULL;
			return false;
		}
		dwBackOffset=m_dwOffsetMove;
		dwBackOffset+=0x10+0x09;
		m_dwOffsetMove+=*(DWORD*)&byYodaCryptorDecryptbuff[m_dwOffsetMove]+0x04;

		dwDecryptorSize=m_dwOffsetMove-dwBackOffset-0x0D;
		while(byYodaCryptorDecryptbuff[dwBackOffset+dwDecryptorSize]!=0xAA)
		{
			if(dwBackOffset+dwDecryptorSize>m_objTempFile.m_dwFileSize)
			{
				free(byYodaCryptorDecryptbuff);
				byYodaCryptorDecryptbuff = NULL;
				return false;
			}
			dwDecryptorSize--;
		}

	}


	//Moving to the place where it checks the section Names and then moves in counts of 0xA
	m_dwOffsetMove+=0x0F;
	if(m_dwOffsetMove+1 > m_objTempFile.m_dwFileSize)
	{
		free(byYodaCryptorDecryptbuff);
		byYodaCryptorDecryptbuff = NULL;
		return false;
	}
	if(byYodaCryptorDecryptbuff[m_dwOffsetMove]==0x3E)
	{
		m_dwOffsetMove+=0x01;
	}
	m_dwOffsetMove+=0x02;


	//Gets the number of sections to check..Stop when it reads instruction CMP DWORD PTR DS:[ESI+14],0
	BYTE dwNoofSectionsToCheck=0;
	DWORD dwEachSectionCheckLoop=0;

	stSectionCheckList * head=NULL;


	/*DWORD *dwEachSectionCheck=NULL;
	if(!(dwEachSectionCheck==(DWORD*)MaxMalloc(sizeof(DWORD))))
	{
	free(byYodaCryptorDecryptbuff);
	byYodaCryptorDecryptbuff=NULL;
	return false;
	}*/

	if(m_dwOffsetMove+dwEachSectionCheckLoop+0x04>m_objTempFile.m_dwFileSize)
	{
		free(byYodaCryptorDecryptbuff);
		byYodaCryptorDecryptbuff = NULL;
		return false;
	}
	head=(stSectionCheckList*)MaxMalloc(sizeof(stSectionCheckList));
	memset(head,0,sizeof(stSectionCheckList));
	pSectionCheckList=head;
	pSectionCheckList->dwValue=dwEachSectionCheckLoop;
	pSectionCheckList->next=NULL;
	while((*(DWORD*)&byYodaCryptorDecryptbuff[m_dwOffsetMove+dwEachSectionCheckLoop]&0x00FFFFFF)!=0x00740014 && dwNoofSectionsToCheck<0x20)
	{
		dwNoofSectionsToCheck++;
		pSectionCheckList->next=(stSectionCheckList*)MaxMalloc(sizeof(stSectionCheckList));
		memset(pSectionCheckList->next,0,sizeof(stSectionCheckList));
		pSectionCheckList=pSectionCheckList->next;
		pSectionCheckList->next=NULL;

		if(byYodaCryptorDecryptbuff[m_dwOffsetMove+dwEachSectionCheckLoop+6]==0xE9)
		{
			dwEachSectionCheckLoop+=0x0D;
		}
		else if(byYodaCryptorDecryptbuff[m_dwOffsetMove+dwEachSectionCheckLoop+6]==0xEB)
		{
			dwEachSectionCheckLoop+=0xA;
		}
		else if(byYodaCryptorDecryptbuff[m_dwOffsetMove+dwEachSectionCheckLoop+4]==0x74)
		{
			dwEachSectionCheckLoop+=0x09;
		}
		else if(byYodaCryptorDecryptbuff[m_dwOffsetMove+dwEachSectionCheckLoop+4]==0x0F)
		{
			dwEachSectionCheckLoop+=0x0D;
		}
		pSectionCheckList->dwValue=dwEachSectionCheckLoop;
		if(m_dwOffsetMove+dwEachSectionCheckLoop+0x04>m_objTempFile.m_dwFileSize)
		{
			free(byYodaCryptorDecryptbuff);
			byYodaCryptorDecryptbuff = NULL;
			return false;
		}

	}

	/********DECRYPTS SECTIONS*********/

	bool bSectionFlag=true;
	for(DWORD dwSecCnt=0;dwSecCnt<m_pMaxPEFile->m_stPEHeader.NumberOfSections;dwSecCnt++)
	{
		if(m_pMaxPEFile->m_stSectionHeader[dwSecCnt].PointerToRawData!=0x00 && m_pMaxPEFile->m_stSectionHeader[dwSecCnt].SizeOfRawData!=0x00)
		{
			bSectionFlag=true;
			pSectionCheckList=head;
			for(DWORD j=0;j<dwNoofSectionsToCheck  && pSectionCheckList!=NULL;j++,pSectionCheckList=pSectionCheckList->next)
			{
				if(*(DWORD*)&m_pMaxPEFile->m_stSectionHeader[dwSecCnt].Name[0]==*(DWORD*)&byYodaCryptorDecryptbuff[m_dwOffsetMove+pSectionCheckList->dwValue])
				{
					bSectionFlag=false;
					break;
				}
			}

			if(bSectionFlag==true)
			{
				//Read the jump offset + 0x08 because this we are subtracting in below code - 0x2F(part from where all
				//section checks end till the decryption loop begins) - 0x05 (part which does not from part of the decryption
				//and is below the decryption loop) - dwNoOfSections*0x0A (move by the no of section checks encountered)


				if(m_dwOffsetMove+0x7+0x04>m_objTempFile.m_dwFileSize)
				{
					free(byYodaCryptorDecryptbuff);
					byYodaCryptorDecryptbuff = NULL;
					return false;
				}
				if(byYodaCryptorDecryptbuff[m_dwOffsetMove+0x6]==0xE9)
					dwDecryptorSize=*(DWORD*)&byYodaCryptorDecryptbuff[m_dwOffsetMove+0x7]-dwEachSectionCheckLoop-0x05-0x2F+0x0B;
				else if(byYodaCryptorDecryptbuff[m_dwOffsetMove+0x6]==0xEB)
					dwDecryptorSize=byYodaCryptorDecryptbuff[m_dwOffsetMove+0x7]-dwEachSectionCheckLoop-0x05-0x2F+0x08;
				//else if(byYodaCryptorDecryptbuff[m_dwOffsetMove+0x4]==0x74)
				//dwDecryptorSize=byYodaCryptorDecryptbuff[m_dwOffsetMove+0x5]-dwEachSectionCheckLoop-0x05-0x2F+0x08;


				if(m_dwOffsetMove+dwEachSectionCheckLoop+0x2F+dwDecryptorSize+1>m_objTempFile.m_dwFileSize)
				{
					free(byYodaCryptorDecryptbuff);
					byYodaCryptorDecryptbuff = NULL;
					return false;
				}
				if(m_objTempFile.m_stSectionHeader[dwSecCnt].VirtualAddress+m_pMaxPEFile->m_stSectionHeader[dwSecCnt].SizeOfRawData>m_objTempFile.m_dwFileSize)
				{
					free(byYodaCryptorDecryptbuff);
					byYodaCryptorDecryptbuff = NULL;
					return false;
				}
				if(m_eYodaType==e81E9)
				{
					if(!UnPackYodaCryporPolyEmulator(&byYodaCryptorDecryptbuff[dwBackOffset],&byYodaCryptorDecryptbuff[m_objTempFile.m_stSectionHeader[dwSecCnt].VirtualAddress],m_pMaxPEFile->m_stSectionHeader[dwSecCnt].SizeOfRawData,dwDecryptorSize))
					{
						free(byYodaCryptorDecryptbuff);
						byYodaCryptorDecryptbuff = NULL;
						return false;
					}
				}
				else
				{
					if(!UnPackYodaCryporPolyEmulator(&byYodaCryptorDecryptbuff[m_dwOffsetMove+dwEachSectionCheckLoop+0x2F],&byYodaCryptorDecryptbuff[m_objTempFile.m_stSectionHeader[dwSecCnt].VirtualAddress],m_pMaxPEFile->m_stSectionHeader[dwSecCnt].SizeOfRawData,dwDecryptorSize))
					{
						free(byYodaCryptorDecryptbuff);
						byYodaCryptorDecryptbuff = NULL;
						return false;
					}
				}
			}
		}
	}
	/*********DECRYPT SECTION END**********/

	pSectionCheckList=head;
	stSectionCheckList *temp=NULL;
	while(pSectionCheckList!=NULL)
	{
		head=pSectionCheckList->next;
		free(pSectionCheckList);
		pSectionCheckList=NULL;
		pSectionCheckList=head;
	}

	//Place after decrypting the sections
	if(m_eYodaType==e81E9)
	{
		m_dwOffsetMove+=dwEachSectionCheckLoop+0x03;//0x2F+0xA;
		m_dwOffsetMove+=byYodaCryptorDecryptbuff[m_dwOffsetMove];
		m_dwOffsetMove+=0x0A;
		if(m_dwOffsetMove+1>m_objTempFile.m_dwFileSize)
		{
			free(byYodaCryptorDecryptbuff);
			byYodaCryptorDecryptbuff = NULL;
			return false;
		}
		if(byYodaCryptorDecryptbuff[m_dwOffsetMove]==0x0F)
		{
			m_dwOffsetMove+=0x04;
		}
		m_dwOffsetMove+=0x03;
	}
	else
	{
		m_dwOffsetMove+=dwEachSectionCheckLoop+0x2F+dwDecryptorSize+0x05+0x0F;
	}
	if(m_dwOffsetMove+0x0E+0x04>m_objTempFile.m_dwFileSize)
	{
		free(byYodaCryptorDecryptbuff);
		byYodaCryptorDecryptbuff = NULL;
		return false;
	}
	if(m_eYodaType==e81E9)
	{
		if(*(DWORD*)&byYodaCryptorDecryptbuff[m_dwOffsetMove+0x0E]+dwEBPValue-m_dwImageBase+0x04>m_objTempFile.m_dwFileSize)
		{
			free(byYodaCryptorDecryptbuff);
			byYodaCryptorDecryptbuff = NULL;
			return false;
		}
		//Setting the AEP here
		*(DWORD*)&byYodaCryptorDecryptbuff[m_objTempFile.m_stPEOffsets.AddressOfEntryPoint]=*(DWORD*)&byYodaCryptorDecryptbuff[*(DWORD*)&byYodaCryptorDecryptbuff[m_dwOffsetMove+0x0E]+dwEBPValue-m_dwImageBase];

	}
	else
	{
		if(*(DWORD*)&byYodaCryptorDecryptbuff[m_dwOffsetMove+0x08]+dwEBPValue-m_dwImageBase+0x04>m_objTempFile.m_dwFileSize)
		{
			free(byYodaCryptorDecryptbuff);
			byYodaCryptorDecryptbuff = NULL;
			return false;
		}
		//Setting the AEP here
		*(DWORD*)&byYodaCryptorDecryptbuff[m_objTempFile.m_stPEOffsets.AddressOfEntryPoint]=*(DWORD*)&byYodaCryptorDecryptbuff[*(DWORD*)&byYodaCryptorDecryptbuff[m_dwOffsetMove+0x08]+dwEBPValue-m_dwImageBase];

	}


	//Sets the TLS to Zero
	//Left this for now


	/*********DECRYPT IMPORT TABLE*********/
	if(m_eYodaType==e81E9)
	{
		m_dwOffsetMove+=0x6D;
	}
	else
	{
		m_dwOffsetMove+=0x57;
	}
	if(m_dwOffsetMove+2+0x11+0x04 > m_objTempFile.m_dwFileSize)
	{
		free(byYodaCryptorDecryptbuff);
		byYodaCryptorDecryptbuff = NULL;
		return false;
	}
	DWORD dwImportOffsetInBuff=*(DWORD*)&byYodaCryptorDecryptbuff[m_dwOffsetMove+2]+dwEBPValue-m_dwImageBase;
	/*m_dwOffsetMove+=0x11;
	if(m_eYodaType==e81E9)
	{
	m_dwOffsetMove+=0x02;
	}
	m_dwOffsetMove+=byYodaCryptorDecryptbuff[m_dwOffsetMove]+0x01;

	m_dwOffsetMove+=0x05;*/

	DWORD dwImportDLLNameRVA;
	DWORD dwImportAddressNameRVA;
	DWORD dwImportNameRVA;
	BYTE *byImportTableBuff=0x00;
	DWORD dwImportTableSize=m_objTempFile.m_stPEHeader.SectionAlignment;

	if(!(byImportTableBuff=(BYTE*)MaxMalloc(dwImportTableSize)))
	{
		free(byYodaCryptorDecryptbuff);
		byYodaCryptorDecryptbuff = NULL;
		return false;
	}
	memset(byImportTableBuff,0,dwImportTableSize);




	//Decryption Loop of the Import Table
	/*m_dwOffsetMove+=0x1E;*/

	//To get the decryptor for the API Names and DllNames Mostly it is ROR AL,4 but still checked again
	dwDecryptorSize=0;
	if(m_dwOffsetMove+dwDecryptorSize+0x04+sizeof(DWORD)>m_objTempFile.m_dwFileSize)
	{
		free(byYodaCryptorDecryptbuff);
		byYodaCryptorDecryptbuff = NULL;
		free(byImportTableBuff);
		byImportTableBuff=NULL;
		return false;
	}
	/*while(*(DWORD*)&byYodaCryptorDecryptbuff[m_dwOffsetMove+dwDecryptorSize]!=0x003F80AA && byYodaCryptorDecryptbuff[m_dwOffsetMove+dwDecryptorSize+0x04]!=0x75)
	{
	dwDecryptorSize++;
	if(m_dwOffsetMove+dwDecryptorSize+0x04+sizeof(DWORD)>m_objTempFile.m_dwFileSize)
	{
	free(byYodaCryptorDecryptbuff);
	byYodaCryptorDecryptbuff = NULL;
	free(byImportTableBuff);
	byImportTableBuff=NULL;
	return false;
	}
	}*/



	DWORD dwMainCounterofDLL=0;
	if(dwImportOffsetInBuff+0x04+dwMainCounterofDLL+sizeof(DWORD)>m_objTempFile.m_dwFileSize)
	{
		free(byYodaCryptorDecryptbuff);
		byYodaCryptorDecryptbuff = NULL;
		free(byImportTableBuff);
		byImportTableBuff=NULL;
		return false;
	}
	DWORD dwStrlen=0;
	while(*(DWORD*)&byYodaCryptorDecryptbuff[dwImportOffsetInBuff+0x04+dwMainCounterofDLL]!=0x00)
	{
		dwImportDLLNameRVA=*(DWORD*)&byYodaCryptorDecryptbuff[dwImportOffsetInBuff+dwMainCounterofDLL];
		dwImportAddressNameRVA=*(DWORD*)&byYodaCryptorDecryptbuff[dwImportOffsetInBuff+dwMainCounterofDLL+0x04];
		dwImportNameRVA=*(DWORD*)&byYodaCryptorDecryptbuff[dwImportOffsetInBuff+dwMainCounterofDLL+0x04];

		if(dwImportAddressNameRVA==0x00)
		{
			dwImportAddressNameRVA=dwImportNameRVA;
		}

		if(m_dwOffsetMove+dwDecryptorSize+0x01>m_objTempFile.m_dwFileSize)
		{
			free(byYodaCryptorDecryptbuff);
			byYodaCryptorDecryptbuff = NULL;
			free(byImportTableBuff);
			byImportTableBuff=NULL;
			return false;
		}

		if(dwImportDLLNameRVA+sizeof(BYTE)>m_objTempFile.m_dwFileSize)
		{
			free(byYodaCryptorDecryptbuff);
			byYodaCryptorDecryptbuff = NULL;
			free(byImportTableBuff);
			byImportTableBuff=NULL;
			return false;

		}
		dwStrlen=0x00;
		while(byYodaCryptorDecryptbuff[dwImportDLLNameRVA+dwStrlen]!=0x00)
		{
			dwStrlen++;
			if(dwImportDLLNameRVA+dwStrlen+sizeof(BYTE)>m_objTempFile.m_dwFileSize)
			{
				free(byYodaCryptorDecryptbuff);
				byYodaCryptorDecryptbuff = NULL;
				free(byImportTableBuff);
				byImportTableBuff=NULL;
				return false;

			}
		}
		/*if(!UnPackYodaCryporPolyEmulator(&byYodaCryptorDecryptbuff[m_dwOffsetMove],&byYodaCryptorDecryptbuff[dwImportDLLNameRVA],dwStrlen,dwDecryptorSize))
		{
		free(byYodaCryptorDecryptbuff);
		byYodaCryptorDecryptbuff = NULL;
		free(byImportTableBuff);
		byImportTableBuff=NULL;
		return false;
		}*/
		while(dwStrlen!=0x00)
		{
			MAX_ROR(byYodaCryptorDecryptbuff[dwImportDLLNameRVA+dwStrlen-1],4);
			dwStrlen--;
		}

		DWORD dwCounter=0x00;
		if(dwImportAddressNameRVA+dwCounter+sizeof(DWORD)>m_objTempFile.m_dwFileSize)
		{
			free(byYodaCryptorDecryptbuff);
			byYodaCryptorDecryptbuff = NULL;
			free(byImportTableBuff);
			byImportTableBuff=NULL;
			return false;
		}
		while(*(DWORD*)&byYodaCryptorDecryptbuff[dwImportAddressNameRVA+dwCounter]!=0x00)
		{
			if((*(DWORD*)&byYodaCryptorDecryptbuff[dwImportAddressNameRVA+dwCounter]&IMAGE_ORDINAL_FLAG)!=IMAGE_ORDINAL_FLAG)
			{
				if(m_dwOffsetMove+dwDecryptorSize+0x01>m_objTempFile.m_dwFileSize)
				{
					free(byYodaCryptorDecryptbuff);
					byYodaCryptorDecryptbuff = NULL;
					free(byImportTableBuff);
					byImportTableBuff=NULL;
				}
				if(*(DWORD*)&byYodaCryptorDecryptbuff[dwImportAddressNameRVA+dwCounter]+0x02+sizeof(BYTE)>m_objTempFile.m_dwFileSize)
				{
					free(byYodaCryptorDecryptbuff);
					byYodaCryptorDecryptbuff = NULL;
					free(byImportTableBuff);
					byImportTableBuff=NULL;
					return false;
				}
				dwStrlen=0x00;
				while(byYodaCryptorDecryptbuff[*(DWORD*)&byYodaCryptorDecryptbuff[dwImportAddressNameRVA+dwCounter]+0x02+dwStrlen]!=0x00)
				{
					dwStrlen++;
					if(*(DWORD*)&byYodaCryptorDecryptbuff[dwImportAddressNameRVA+dwCounter]+0x02+dwStrlen+sizeof(BYTE)>m_objTempFile.m_dwFileSize)
					{
						free(byYodaCryptorDecryptbuff);
						byYodaCryptorDecryptbuff = NULL;
						free(byImportTableBuff);
						byImportTableBuff=NULL;
						return false;

					}
				}
				while(dwStrlen!=0x00)
				{
					MAX_ROR(byYodaCryptorDecryptbuff[*(DWORD*)&byYodaCryptorDecryptbuff[dwImportAddressNameRVA+dwCounter]+0x02+dwStrlen-1],4);
					dwStrlen--;
				}
				/*if(!UnPackYodaCryporPolyEmulator(&byYodaCryptorDecryptbuff[m_dwOffsetMove],&byYodaCryptorDecryptbuff[*(DWORD*)&byYodaCryptorDecryptbuff[dwImportAddressNameRVA+dwCounter]+0x02],dwStrlen,dwDecryptorSize))
				{
				free(byYodaCryptorDecryptbuff);
				byYodaCryptorDecryptbuff = NULL;
				free(byImportTableBuff);
				byImportTableBuff=NULL;
				return false;
				}*/
			}
			dwCounter+=0x04;
			if(dwImportAddressNameRVA+dwCounter+sizeof(DWORD)>m_objTempFile.m_dwFileSize)
			{
				free(byYodaCryptorDecryptbuff);
				byYodaCryptorDecryptbuff = NULL;
				free(byImportTableBuff);
				byImportTableBuff=NULL;
				return false;
			}
		}
		while(((dwMainCounterofDLL/0x0C)*0x14)+0x14 > dwImportTableSize)
		{
			byImportTableBuff=(BYTE*)realloc(byImportTableBuff,dwImportTableSize+m_objTempFile.m_stPEHeader.SectionAlignment);
			memset(&byImportTableBuff[dwImportTableSize],0,m_objTempFile.m_stPEHeader.SectionAlignment);
			dwImportTableSize+=m_objTempFile.m_stPEHeader.SectionAlignment;
		}
		*(DWORD*)&byImportTableBuff[((dwMainCounterofDLL/0x0C)*0x14)+0x0C]=dwImportDLLNameRVA;
		*(DWORD*)&byImportTableBuff[((dwMainCounterofDLL/0x0C)*0x14)+0x10]=dwImportAddressNameRVA;
		dwMainCounterofDLL+=0x0C;
		if(dwImportOffsetInBuff+0x08+dwMainCounterofDLL+sizeof(DWORD)>m_objTempFile.m_dwFileSize)
		{
			free(byYodaCryptorDecryptbuff);
			byYodaCryptorDecryptbuff = NULL;
			free(byImportTableBuff);
			byImportTableBuff=NULL;
			return false;
		}

	}

	/*********DECRYPT IMPORT END**********/


	//Incrementing the no. of sections by 1 and pointing the Import Table to the new offset
	*(WORD*)&byYodaCryptorDecryptbuff[m_objTempFile.m_stPEOffsets.NumberOfSections]=m_objTempFile.m_stPEHeader.NumberOfSections+1;
	*(DWORD*)&byYodaCryptorDecryptbuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x0C]=m_objTempFile.m_dwFileSize;

	//Writing the complete buffer with all the new changes except the Import Table
	if(!m_objTempFile.WriteBuffer(byYodaCryptorDecryptbuff,0,m_objTempFile.m_dwFileSize,m_objTempFile.m_dwFileSize))
	{
		free(byYodaCryptorDecryptbuff);
		byYodaCryptorDecryptbuff = NULL;
		free(byImportTableBuff);
		byImportTableBuff=NULL;
		return false;
	}

	if(byYodaCryptorDecryptbuff)
	{
		free(byYodaCryptorDecryptbuff);
		byYodaCryptorDecryptbuff = NULL;
	}

	//Closing and Opening the file to reflect the changes
	m_objTempFile.CloseFile();
	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		free(byImportTableBuff);
		byImportTableBuff=NULL;
		return false;
	}

	//Adding a new Section
	if(!AddNewSection(dwImportTableSize,1))
	{
		free(byImportTableBuff);
		byImportTableBuff=NULL;
		return false;
	}

	m_objTempFile.CloseFile();
	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		free(byImportTableBuff);
		byImportTableBuff=NULL;
		return false;
	}

	//Writing the basic Import Directory Table buffer to memory
	if(!m_objTempFile.WriteBuffer(byImportTableBuff, m_objTempFile.m_dwFileSize, dwImportTableSize, dwImportTableSize))
	{
		free(byImportTableBuff);
		byImportTableBuff=NULL;
		return false;
	}	

	if(byImportTableBuff)
	{
		free(byImportTableBuff);
		byImportTableBuff=NULL;
	}

	if(!m_objTempFile.CalculateImageSize())
	{
		return false;
	}


	return true;
}





bool CYodaCryptorDecrypt::UnPackYodaCryporPolyEmulator(BYTE* byDecryptor_offset, BYTE* byCode_offset, DWORD dwDecryptionSize,DWORD dwDecryptorSize)
{
	BYTE byDecryptionSizeReverse=(BYTE)dwDecryptionSize;

	for(DWORD i=0;i<dwDecryptionSize;i++) /* Byte looper - Decrypts every byte and write it back */
	{
		for(DWORD j=0;j<dwDecryptorSize;j++)   /* Poly Decryptor "Emulator" */
		{
			switch(byDecryptor_offset[j])
			{

			case 0xEB:	/* JMP short */
				j++;
				if(j+1>dwDecryptorSize)
				{
					return false;
				}
				j = j + byDecryptor_offset[j];
				break;

			case 0xFE:	/* DEC  AL */
				byCode_offset[i]--;
				j++;
				break;

			case 0x2A:	/* SUB AL,CL */
				byCode_offset[i]-= byDecryptionSizeReverse;
				j++;
				break;

			case 0x02:	/* ADD AL,CL */
				byCode_offset[i]+= byDecryptionSizeReverse;
				j++;
				break
					;
			case 0x32:	/* XOR AL,CL */
				byCode_offset[i]^= byDecryptionSizeReverse;
				j++;
				break;
				;
			case 0x04:	/* ADD AL,num */
				j++;
				if(j+1>dwDecryptorSize)
				{
					return false;
				}
				byCode_offset[i]+= byDecryptor_offset[j];
				break;
				;
			case 0x34:	/* XOR AL,num */
				j++;
				if(j+1>dwDecryptorSize)
				{
					return false;
				}
				byCode_offset[i]^= byDecryptor_offset[j];
				break;

			case 0x2C:	/* SUB AL,num */
				j++;
				if(j+1>dwDecryptorSize)
				{
					return false;
				}
				byCode_offset[i]-= byDecryptor_offset[j];
				break;


			case 0xC0:
				j++;
				if(j+1>dwDecryptorSize)
				{
					return false;
				}
				if(byDecryptor_offset[j]==0xC0) /* ROL AL,num */
				{
					j++;
					if(j+1>dwDecryptorSize)
					{
						return false;
					}
					MAX_ROL(byCode_offset[i],byDecryptor_offset[j]);
				}
				else			/* ROR AL,num */
				{
					j++;
					if(j+1>dwDecryptorSize)
					{
						return false;
					}
					MAX_ROR(byCode_offset[i],byDecryptor_offset[j]);
				}
				break;

			case 0xD2:
				j++;
				if(j+1>dwDecryptorSize)
				{
					return false;
				}
				if(byDecryptor_offset[j]==0xC8) /* ROR AL,CL */
				{
					j++;
					if(j+1>dwDecryptorSize)
					{
						return false;
					}
					MAX_ROR(byCode_offset[i],byDecryptionSizeReverse);
				}
				else			/* ROL AL,CL */
				{
					j++;
					if(j+1>dwDecryptorSize)
					{
						return false;
					}
					MAX_ROL(byCode_offset[i],byDecryptionSizeReverse);
				}
				break;

			case 0x90:
			case 0xF8:
			case 0xF9:
			case 0xE9:
			case 0xE8:
			case 0xAC:
				break;

			default:
				//DBGMessage("yC: Unhandled opcode %x\n", (unsigned char)byDecryptor_offset[j]);
				return false;
			}
		}
		byDecryptionSizeReverse--;
	}
	return true;

}