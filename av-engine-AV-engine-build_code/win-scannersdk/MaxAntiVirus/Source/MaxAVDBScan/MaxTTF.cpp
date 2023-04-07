/*======================================================================================
   FILE				: MaxRTF.cpp
   ABSTRACT			: Supportive class for TTF File Scanner
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
   NOTES			: This module manages the scanning for file tyep TTF. 
   VERSION HISTORY	: 
=====================================================================================*/
#include "MaxTTF.h"
#include "math.h"

/*-------------------------------------------------------------------------------------
	Function		: CMaxTTF
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CMaxTTF::CMaxTTF()
{
	memset(&m_stTTFHeader, 0, sizeof(m_stTTFHeader));
	m_dwStartOffset=0;
	m_dwBufferSize=0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CMaxTTF
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor
--------------------------------------------------------------------------------------*/
CMaxTTF::~CMaxTTF()
{
	if(m_stTTFHeader.pTable_Directory)
	{
		delete[] m_stTTFHeader.pTable_Directory;
		m_stTTFHeader.pTable_Directory = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: IsValidTTFFile
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Checks for valid TTF File
--------------------------------------------------------------------------------------*/
bool CMaxTTF::IsValidTTFFile(CMaxPEFile *pMaxPEFile)
{
	bool bRet = false;
	if(pMaxPEFile->m_dwFileSize == 0 || pMaxPEFile->m_dwFileSize > MAX_FILE_SIZE_TO_SCAN)
	{
		return false;
	}
	if(!pMaxPEFile->ReadBuffer(&m_stTTFHeader.stOffset_Table, 0, sizeof(OFFSET_SUBTABLE), sizeof(OFFSET_SUBTABLE)))
	{
		return bRet;
	}

	if(ntohl(m_stTTFHeader.stOffset_Table.Version) == 0x00010000)
	{
		WORD wNoOfTables = ntohs(m_stTTFHeader.stOffset_Table.Num_Tables);
		if(wNoOfTables >= 0xA)
		{
			WORD wLogValue=WORD(floor(log(double(wNoOfTables))/log((double)2)));
			if(ntohs(m_stTTFHeader.stOffset_Table.Search_Range)==(wLogValue*0x10) || (ntohs(m_stTTFHeader.stOffset_Table.Search_Range)==WORD((pow(2,double(wLogValue))*0x10)))) //(2^4 * 16)
			{
				if(ntohs(m_stTTFHeader.stOffset_Table.Entry_Selector)==wLogValue)
				{
					if(ntohs(m_stTTFHeader.stOffset_Table.Range_Shift)==((wNoOfTables*0x10)-ntohs(m_stTTFHeader.stOffset_Table.Search_Range)))
					{
						return true;
					}
				}
			}
		}
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: SortValues
	In Parameters	: 
	Out Parameters	: 
	Purpose			: Internal supportive function
	Author			: Tushar Kadam
	Description		: Sorts Header values
--------------------------------------------------------------------------------------*/
bool CMaxTTF::SortValues()
{
	BYTE byflag=0x01;
	TABLE_DIRECTORY *ptrOriginalAddress=m_stTTFHeader.pTable_Directory;
	while(byflag)
	{
		byflag=0x00;
		m_stTTFHeader.pTable_Directory=ptrOriginalAddress;
		for(WORD i=1; i<=ntohs(m_stTTFHeader.stOffset_Table.Num_Tables)-0x01; i++,m_stTTFHeader.pTable_Directory++)
		{
			TABLE_DIRECTORY *temp=m_stTTFHeader.pTable_Directory+1;
			if(ntohl(m_stTTFHeader.pTable_Directory->Offset_Beginning_Of_sfnt) > ntohl(temp->Offset_Beginning_Of_sfnt))
			{
				m_stTTFHeader.pTable_Directory->Offset_Beginning_Of_sfnt+=temp->Offset_Beginning_Of_sfnt;
				temp->Offset_Beginning_Of_sfnt=m_stTTFHeader.pTable_Directory->Offset_Beginning_Of_sfnt-temp->Offset_Beginning_Of_sfnt;
				m_stTTFHeader.pTable_Directory->Offset_Beginning_Of_sfnt-=temp->Offset_Beginning_Of_sfnt;

				m_stTTFHeader.pTable_Directory->Length+=temp->Length;
				temp->Length=m_stTTFHeader.pTable_Directory->Length-temp->Length;
				m_stTTFHeader.pTable_Directory->Length-=temp->Length;

				byflag=0x01;
			}
		}
	}
	m_stTTFHeader.pTable_Directory=ptrOriginalAddress;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: Check4TTFDelOrRepair
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: Internal supportive function
	Author			: Tushar Kadam
	Description		: Check for Repaire action either repaire or delete
--------------------------------------------------------------------------------------*/
int CMaxTTF::Check4TTFDelOrRepair(CMaxPEFile *pMaxPEFile)
{
	int bRet = 0;
	WORD wNoOfTables = ntohs(m_stTTFHeader.stOffset_Table.Num_Tables);
	if(wNoOfTables > 0x20)
	{
		return bRet;
	}

	m_stTTFHeader.pTable_Directory= new TABLE_DIRECTORY[wNoOfTables];
	if(!m_stTTFHeader.pTable_Directory)
	{
		return bRet;
	}
	WORD wSizeOfSubtables = sizeof(TABLE_DIRECTORY)*wNoOfTables;
	memset(m_stTTFHeader.pTable_Directory,0,wSizeOfSubtables);
	TABLE_DIRECTORY *ptrtemp;

	if(!pMaxPEFile->ReadBuffer(m_stTTFHeader.pTable_Directory, 0xC, wSizeOfSubtables, wSizeOfSubtables))
	{
		return bRet;
	}

	if(wSizeOfSubtables>=0xF0)
	{
		ptrtemp=m_stTTFHeader.pTable_Directory+0xE;
		if(memcmp(&(ptrtemp->Tag),"SING",0x04)==0x00)
		{
			if(ntohl(ptrtemp->Checksum)==0xD9BCC8B5)
			{
				if(ntohl(ptrtemp->Offset_Beginning_Of_sfnt)==0x011C)
				{
					if(ntohl(ptrtemp->Length)==0x00001DDF)
					{
						BYTE bySINGTablebuff[0x40] = {0};
						if(!pMaxPEFile->ReadBuffer(bySINGTablebuff, 0x11C, 0x40, 0x40))
						{
							return bRet;
						}
						BYTE *bySingtemp = bySINGTablebuff;
						if(*(WORD*)bySingtemp==0x00)
						{
							bySingtemp+=2;
							if(ntohs(*(WORD*)bySingtemp)==0x0100)
							{
								bySingtemp+=2;
								if(ntohs(*(WORD*)bySingtemp)==0x010E || *(WORD*)bySingtemp==0x0F02 )
								{
									bySingtemp+=2;
									if(ntohs(*(WORD*)bySingtemp)==0x0001 || *(WORD*)bySingtemp==0x00 )
									{
										bySingtemp+=2;
										if(*(DWORD*)bySingtemp==0x00 || *(DWORD*)bySingtemp==0x01)
										{
											bySingtemp+=4;
											if(*(WORD*)bySingtemp==0x00)
											{
												bySingtemp+=2;
												if(ntohs(*(WORD*)bySingtemp)==0x003A || ntohs(*(WORD*)bySingtemp)==0x3A00 || *(WORD*)bySingtemp==0x00 )
												{
													bySingtemp+=2;
													while(*bySingtemp!=0x00 && (bySingtemp-bySINGTablebuff)<0x3F)
													{
														bySingtemp++;
													}
													if(bySingtemp-(bySINGTablebuff+0x10)>0x1B)
													{
														bySingtemp=NULL;
														return 1;
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	ptrtemp=m_stTTFHeader.pTable_Directory+0x07;
	if(ntohl(ptrtemp->Offset_Beginning_Of_sfnt)==0x3BAE4 && ntohl(ptrtemp->Checksum)==0x18D3694B)
	{
		if((ntohl(ptrtemp->Offset_Beginning_Of_sfnt)+ntohl(ptrtemp->Length))<pMaxPEFile->m_dwFileSize)
		{
			m_dwStartOffset=ntohl(ptrtemp->Offset_Beginning_Of_sfnt);
			m_dwBufferSize=pMaxPEFile->m_dwFileSize-(ntohl(ptrtemp->Offset_Beginning_Of_sfnt)+ntohl(ptrtemp->Length));
			return 2;
		}
	}
	else if(pMaxPEFile->m_dwFileSize%0x1000==0x00)
	{
		if(SortValues())
		{
			ptrtemp=m_stTTFHeader.pTable_Directory+(wNoOfTables-0x01);
			DWORD dwAlignedFileOffset=ntohl(ptrtemp->Offset_Beginning_Of_sfnt)+ntohl(ptrtemp->Length)-((ntohl(ptrtemp->Offset_Beginning_Of_sfnt)+ntohl(ptrtemp->Length))%0x200)+0x200;
			if(pMaxPEFile->m_dwFileSize - dwAlignedFileOffset <= 0x1000)
			{
				if((ntohl(ptrtemp->Offset_Beginning_Of_sfnt)+ntohl(ptrtemp->Length))<pMaxPEFile->m_dwFileSize)
				{ 
					m_dwBufferSize = pMaxPEFile->m_dwFileSize-(ntohl(ptrtemp->Offset_Beginning_Of_sfnt)+ntohl(ptrtemp->Length));
					m_dwStartOffset = ntohl(ptrtemp->Offset_Beginning_Of_sfnt)+ntohl(ptrtemp->Length);
					return 3;
				}
			}
		}
	}
	return 0;
}
