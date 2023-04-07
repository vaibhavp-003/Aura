#include "PolyCryptPEDecrypter.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CPolyCryptPEDecryptor::CPolyCryptPEDecryptor(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{
	m_pbyBuff = NULL;
}

CPolyCryptPEDecryptor::~CPolyCryptPEDecryptor(void)
{
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_objTempFile.CloseFile();
}

bool CPolyCryptPEDecryptor::IsPacked() 
{
	if( m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&  
		((m_pMaxPEFile->m_wAEPSec==m_pMaxPEFile->m_stPEHeader.NumberOfSections-1) || m_iCurrentLevel>0) &&
		m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData==m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Misc.VirtualSize &&
		m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Misc.VirtualSize==0x1000 &&
		m_pMaxPEFile->m_dwAEPMapped-m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].PointerToRawData<0x15 &&
		m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Characteristics==0xE0000020 )		
	{
		m_pbyBuff = new BYTE[m_pMaxPEFile->m_dwAEPMapped-m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].PointerToRawData+0x06];
		if(!m_pbyBuff)
		{
			return false;
		}

		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].PointerToRawData,m_pMaxPEFile->m_dwAEPMapped-m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].PointerToRawData+0x06,m_pMaxPEFile->m_dwAEPMapped-m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].PointerToRawData+0x06))
		{
			return false;
		}

		if(m_pbyBuff[0]==0x91 && *(WORD*)&m_pbyBuff[0x1]==0xF48B && m_pbyBuff[0x3]==0xAD && *(WORD*)&m_pbyBuff[m_pMaxPEFile->m_dwAEPMapped-m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].PointerToRawData]==0xE860 &&
			*(DWORD*)&m_pbyBuff[m_pMaxPEFile->m_dwAEPMapped-m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].PointerToRawData+0x02]+m_pMaxPEFile->m_dwAEPMapped+0x06==m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].PointerToRawData)
		{
			return true;
		}
	}
	return false;
}

bool CPolyCryptPEDecryptor::Unpack(LPCTSTR szTempFileName)
{	
	if(!ReOrganizeFile(szTempFileName))
	{
		return false;
	}

	BYTE *byFullFilebuff=NULL;
	//Just allocating a buffer of 30h extra for the length of the max_instruction
	if(!(byFullFilebuff=(BYTE*)MaxMalloc(m_objTempFile.m_dwFileSize+0x30)))
	{
		return false;
	}
	//Filling the extra 30h bytes with zeroes
	memset(&byFullFilebuff[m_objTempFile.m_dwFileSize],0x00,0x30);
	if(!m_objTempFile.ReadBuffer(byFullFilebuff,0,m_objTempFile.m_dwFileSize,m_objTempFile.m_dwFileSize))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	DWORD dwOffset=m_objTempFile.m_stPEHeader.AddressOfEntryPoint;
	DWORD dwCounter=0;
	WORD wDecryptionKey1=byFullFilebuff[dwOffset-0x04];
	dwOffset+=0x06;

	if(dwOffset+0x100 > m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	//First decryption.Decrypts part of the loader
	for(DWORD i=1;i<0x100;i++)
	{
		byFullFilebuff[dwOffset+i]^=BYTE(wDecryptionKey1);
	}

	WORD wDecryptionKey=0;
	DWORD dwDecryptionKey2Offset=0;
	DWORD dwLength = 0, dwInstructionCountFound = 0;
	DWORD dwEBPValue=0x00;
	DWORD dwDestRVA=0;
	DWORD dwPolyKeyOffset=0;
	char  szInstruction[1024] = {0x00};
	bool bContinue=false;

	CEmulate objEmulate(m_pMaxPEFile);

	while(dwOffset <= m_objTempFile.m_dwFileSize)
	{
		dwLength = objEmulate.DissassemBuffer((char*)&byFullFilebuff[dwOffset],szInstruction);
		if(strstr(szInstruction,"WORD PTR") && dwLength==0x07)
		{
			if(dwEBPValue+*(DWORD*)&byFullFilebuff[dwOffset+0x03]-m_dwImageBase+0x04>m_objTempFile.m_dwFileSize)
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}
			wDecryptionKey1=*(WORD*)&byFullFilebuff[dwEBPValue+*(DWORD*)&byFullFilebuff[dwOffset+0x03]-m_dwImageBase];
			wDecryptionKey=wDecryptionKey1;
			dwDecryptionKey2Offset=dwEBPValue+*(DWORD*)&byFullFilebuff[dwOffset+0x03]-m_dwImageBase-0x14;
			if(dwDestRVA+dwCounter*0x02>m_objTempFile.m_dwFileSize)
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}

			DecryptParts(&byFullFilebuff[dwDestRVA],dwCounter*0x02,&wDecryptionKey1);

			dwOffset=dwDestRVA;
			dwOffset-=dwLength;
		}
		else if(strstr(szInstruction,"JMP") && dwLength==0x02 && byFullFilebuff[dwOffset]==0xEB)
		{
			dwEBPValue=dwOffset;
			dwOffset+=byFullFilebuff[dwOffset+1];
		}
		else if(strstr(szInstruction,"MOV ECX") && dwLength==0x05 && byFullFilebuff[dwOffset]==0xB9)
		{
			dwCounter=*(DWORD*)&byFullFilebuff[dwOffset+1];
			if(dwInstructionCountFound==0x02)
			{
				if(dwDestRVA+(dwCounter*0x02)>m_objTempFile.m_dwFileSize)
				{
					free(byFullFilebuff);
					byFullFilebuff=NULL;
					return false;
				}
				DecryptParts(&byFullFilebuff[dwDestRVA],dwCounter*0x02,&wDecryptionKey1);
				dwInstructionCountFound=2;
				dwOffset=dwDestRVA;
				dwOffset-=dwLength;
			}
		}
		else if(strstr(szInstruction,"LEA") && dwLength==0x06 && *(WORD*)&byFullFilebuff[dwOffset]==0xB58D)
		{
			dwInstructionCountFound+=1;
			if(dwOffset+0x02+0x04>m_objTempFile.m_dwFileSize)
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}
			dwDestRVA=*(DWORD*)&byFullFilebuff[dwOffset+0x02]-m_dwImageBase+dwEBPValue;
			if(dwInstructionCountFound==0x04)
			{
				break;
			}
		}
		else if(strstr(szInstruction,"LEA") && dwLength==0x06 && *(WORD*)&byFullFilebuff[dwOffset]==0xBD8D && dwInstructionCountFound==0x02)
		{
			dwInstructionCountFound+=1;
			if(dwOffset+0x02+0x04>m_objTempFile.m_dwFileSize)
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}
			dwPolyKeyOffset=*(DWORD*)&byFullFilebuff[dwOffset+0x02]-m_dwImageBase+dwEBPValue-0x79;
		}
		else if(strstr(szInstruction,"SUB ECX") && dwLength==0x06 && *(WORD*)&byFullFilebuff[dwOffset]==0xE981)
		{
			dwEBPValue-=*(DWORD*)&byFullFilebuff[dwOffset+0x02]-m_dwImageBase;
		}
		else if(strstr(szInstruction,"CALL") && dwLength==0x05 && byFullFilebuff[dwOffset]==0xE8)
		{
			dwOffset+=*(DWORD*)&byFullFilebuff[dwOffset+1];
		}
		dwOffset+=dwLength;
	}

	if(dwDestRVA+0x04>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	dwDestRVA=*(DWORD*)&byFullFilebuff[dwDestRVA]-m_dwImageBase+dwEBPValue;

	if(dwDestRVA+0x04>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	while(*(DWORD*)&byFullFilebuff[dwDestRVA]!=0x00)
	{
		dwDestRVA+=0x04;
		if(dwDestRVA+0x04>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
	}

	if(dwPolyKeyOffset==0x00)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	/* dwDestRVA=*(DWORD*)&byFullFilebuff[dwDestRVA-0x04]+dwEBPValue-m_dwImageBase;

	if(dwDestRVA+0x01>m_objTempFile.m_dwFileSize)
	{
	free(byFullFilebuff);
	byFullFilebuff=NULL;
	return false;
	}

	while(byFullFilebuff[dwDestRVA]!=0x00)
	{
	dwDestRVA+=0x01;
	if(dwDestRVA+0x01>m_objTempFile.m_dwFileSize)
	{
	free(byFullFilebuff);
	byFullFilebuff=NULL;
	return false;
	}
	}*/

	dwDestRVA+=0x08;
	m_pStructSingleBlockInfo=NULL;
	m_pStructMainBlockInfo=NULL;

	if(dwDestRVA+sizeof(DecompressBlockInfo)>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	m_pStructMainBlockInfo=(DecompressBlockInfo*)&byFullFilebuff[dwDestRVA];
	dwDestRVA+=sizeof(DecompressBlockInfo);

	if(dwDestRVA+(sizeof(SingleBlockInfo)*m_pStructMainBlockInfo->dwNoofBlocks)>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}



	while(m_pStructMainBlockInfo->dwNoofBlocks!=0x00)
	{
		wDecryptionKey1=wDecryptionKey;
		m_pStructSingleBlockInfo=(SingleBlockInfo*)&byFullFilebuff[dwDestRVA];

		if(m_pStructSingleBlockInfo->dwDecryptRVA+m_pStructSingleBlockInfo->dwSize*0x02>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		DecryptParts(&byFullFilebuff[m_pStructSingleBlockInfo->dwDecryptRVA],m_pStructSingleBlockInfo->dwSize,&wDecryptionKey1);
		if(dwPolyKeyOffset+0x14 >m_objTempFile.m_dwFileSize)
		{
			return false;
		}
		for(DWORD i=0;i<m_pStructSingleBlockInfo->dwSize;i+=2)
		{
			if(!DecryptKey(&byFullFilebuff[dwDecryptionKey2Offset+(i%0x14)+1],&byFullFilebuff[dwDecryptionKey2Offset+(i%0x14)],HIBYTE(LOWORD(m_pStructSingleBlockInfo->dwSize>>1)-(LOWORD(i)>>1)),LOBYTE(LOWORD(m_pStructSingleBlockInfo->dwSize>>1)-(LOWORD(i)>>1)),(WORD*)&byFullFilebuff[dwDecryptionKey2Offset+(i%0x14)],dwPolyKeyOffset,byFullFilebuff))
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}
			byFullFilebuff[m_pStructSingleBlockInfo->dwDecryptRVA+i]^=byFullFilebuff[m_pStructSingleBlockInfo->dwDecryptRVA+i+1];
			byFullFilebuff[m_pStructSingleBlockInfo->dwDecryptRVA+i+1]^=byFullFilebuff[m_pStructSingleBlockInfo->dwDecryptRVA+i];
			byFullFilebuff[m_pStructSingleBlockInfo->dwDecryptRVA+i]^=byFullFilebuff[m_pStructSingleBlockInfo->dwDecryptRVA+i+1];
			MAX_ROR(*(WORD*)&byFullFilebuff[m_pStructSingleBlockInfo->dwDecryptRVA+i],1);
			*(WORD*)&byFullFilebuff[m_pStructSingleBlockInfo->dwDecryptRVA+i]-=*(WORD*)&byFullFilebuff[dwDecryptionKey2Offset+(i%0x14)];
			MAX_ROL(*(WORD*)&byFullFilebuff[m_pStructSingleBlockInfo->dwDecryptRVA+i],2);
			*(WORD*)&byFullFilebuff[m_pStructSingleBlockInfo->dwDecryptRVA+i]^=*(WORD*)&byFullFilebuff[dwDecryptionKey2Offset+(i%0x14)];
		}
		dwDestRVA+=sizeof(SingleBlockInfo);
		m_pStructMainBlockInfo->dwNoofBlocks--;
	}

	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x0C]=m_pStructMainBlockInfo->dwResolveImports;
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.AddressOfEntryPoint]=m_pStructMainBlockInfo->dwAEP;

	if(!m_objTempFile.WriteBuffer(byFullFilebuff,0,m_objTempFile.m_dwFileSize,m_objTempFile.m_dwFileSize))
	{
		free(byFullFilebuff);
		byFullFilebuff = NULL;
		return false;
	}

	if(byFullFilebuff)
	{
		free(byFullFilebuff);
		byFullFilebuff = NULL;
	}

	return true;
}

void CPolyCryptPEDecryptor::DecryptParts(BYTE *bybuff,DWORD dwCounter,WORD *wDecryptionKey1)
{
	for (DWORD i=0;i<dwCounter;i+=2)
	{
		*(WORD*)&bybuff[i]^=*wDecryptionKey1;
		*wDecryptionKey1=(*wDecryptionKey1&0xFF00)|BYTE((LOBYTE(*wDecryptionKey1)+HIBYTE(*wDecryptionKey1)));
		*wDecryptionKey1=ntohs(*wDecryptionKey1);
		MAX_ROR(*wDecryptionKey1,1);
		*wDecryptionKey1+=0x1;
	}
}

bool CPolyCryptPEDecryptor::DecryptKey(BYTE *byKeyHigh,BYTE *byKeyLow,BYTE byCounterHigh,BYTE byCounterLow,WORD *wKey,DWORD dwPolyKeyOffset,BYTE *byFullfilebuff)
{
	BYTE byKey[8]={0};
	byKey[1]=byCounterLow;
	byKey[3]=*byKeyLow;
	byKey[5]=byCounterHigh;
	byKey[7]=*byKeyHigh;

	for(DWORD j=0;j<0x14;j++)   /* Poly Decryptor "Emulator" */
	{
		switch(byFullfilebuff[dwPolyKeyOffset+j])
		{
		case 0xF6:	/* NOT BL,CL,BH,CH */
			j++;
			if(j+1>0x14)
			{
				return false;
			}
			byKey[byFullfilebuff[dwPolyKeyOffset+j]%0x08]=~byKey[byFullfilebuff[dwPolyKeyOffset+j]%0x08];
			break;
		case 0x2A:	/* SUB BL,CL */
			j++;
			if(j+1>0x14)
			{
				return false;
			}
			byKey[3]-= byKey[byFullfilebuff[dwPolyKeyOffset+j]%0x08];
			break;
		case 0x0A:	/* OR BH,Bl */
			j++;
			if(j+1>0x14)
			{
				return false;
			}
			byKey[(byFullfilebuff[dwPolyKeyOffset+j]-0xC0)/0x08] |= byKey[byFullfilebuff[dwPolyKeyOffset+j]%0x08];
			break;		
		case 0x02:	/* ADD AL,CL */
			j++;
			if(j+1>0x14)
			{
				return false;
			}
			byKey[3]+= byKey[byFullfilebuff[dwPolyKeyOffset+j]%0x08];
			break;
		case 0xFE:	/* DEC INC BL */
			j++;
			if(j+1>0x14)
			{
				return false;
			}
			if(byFullfilebuff[dwPolyKeyOffset+j]>=0xC8)
				byKey[byFullfilebuff[dwPolyKeyOffset+j]%0x08]--;
			else
				byKey[byFullfilebuff[dwPolyKeyOffset+j]%0x08]++;
			break;
		case 0x32:	/* XOR AL,CL */
			j++;
			if(j+1>0x14)
			{
				return false;
			}
			byKey[(byFullfilebuff[dwPolyKeyOffset+j]-0xC0)/0x08]^=byKey[byFullfilebuff[dwPolyKeyOffset+j]%0x08];
			break;
		case 0xD0:
			j++;
			if(j+1>0x14)
			{
				return false;
			}
			if(byFullfilebuff[dwPolyKeyOffset+j]>=0xC8) /* ROL AL,num */
			{
				MAX_ROR(byKey[byFullfilebuff[dwPolyKeyOffset+j]%0x08],1);
			}
			else			/* ROR AL,num */
			{
				MAX_ROL(byKey[byFullfilebuff[dwPolyKeyOffset+j]%0x08],1);
			}
			break;
		default:
			//DBGMessage("yC: Unhandled opcode %x\n", (unsigned char)byDecryptor_offset[j]);
			return false;
		}
	}
	*wKey=byKey[3]|WORD(byKey[7]<<8);
	return true;
}
