/*======================================================================================
FILE             : RepaireModuls.cpp
ABSTRACT         : This module repaires virus files deteted by AuAVDBScan.dll
DOCUMENTS	     : 
AUTHOR		     : Tushar Kadam + Virus Team
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : June 2010
NOTES		     : This module repaires virus files deteted by AuAVDBScan.dll
				   Contains set of predefine Constants and Repaire routines that can be released in DSVRepaire.db	
VERSION HISTORY  : 
======================================================================================*/

#include "MaxAVRepair.h"
#include "RepairModuls.h"
#include "Imagehlp.h"

BYTE *CRepairModuls::m_pbySrcBytesBlk = NULL;  
BYTE *CRepairModuls::m_pbyDstBytesBlk = NULL;
DWORD CRepairModuls::m_dwBytesRead = 0;
DWORD CRepairModuls::m_dwBytesWrite = 0;

/*-------------------------------------------------------------------------------------
Function		: Constructor 
In Parameters	: -
Out Parameters	: -
Purpose			: To initialize member variables 
Author			: Yuvraj
--------------------------------------------------------------------------------------*/
CRepairModuls::CRepairModuls(CMaxPEFile *pMaxPEFile, LPCTSTR szOriginalFilePath):
m_pMaxPEFile(pMaxPEFile),
m_csOriginalFilePath(szOriginalFilePath)
{
	m_byReadBuffer = NULL;
	m_dwSizeofBuff = 0;
	m_dwStartofDecryption = 0;
	m_dwDecryptionLength = 0;
	m_iStep = 0;
	m_iSaveArg = 0;
	m_bInternalCall = false;
	m_bStubDeleted	= false;

	::ZeroMemory(&m_dwArgs,sizeof(m_dwArgs));
	::ZeroMemory(&m_dwSaveArgs, sizeof(m_dwSaveArgs));
	::ZeroMemory(&m_dwReturnValues, sizeof(m_dwReturnValues));
	
	m_csFilePath = pMaxPEFile->m_szFilePath;
	m_dwFileSize = pMaxPEFile->m_dwFileSize;
}

/*-------------------------------------------------------------------------------------
Function		: Destructor
In Parameters	: -
Out Parameters	: -
Purpose			: To release resources of class
Author			: Yuvraj 
--------------------------------------------------------------------------------------*/
CRepairModuls::~CRepairModuls(void)
{	
	if (m_byReadBuffer != NULL)
	{
		delete []m_byReadBuffer;
		m_byReadBuffer = NULL;
	}
}

/*-------------------------------------------------------------------------------------
Function		: ReadPeFile
In Parameters	: -
Out Parameters	: Returns true if File is PE file otherwise false
Purpose			: Checks PE file and loads the offsets in the structure
Author			: Rupali
--------------------------------------------------------------------------------------*/
bool CRepairModuls::ReadPeFile()
{
	if(m_pMaxPEFile->m_bPEFile)
	{
		m_pSectionHeader = &m_pMaxPEFile->m_stSectionHeader[0];
		m_wNoOfSecs = m_pMaxPEFile->m_stPEHeader.NumberOfSections;
		m_dwAEPMapped = GetMappedAddress(m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint);
		m_dwFileSize = m_pMaxPEFile->m_dwFileSize;
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: RepairDelete
In Parameters	: -
Out Parameters	: bool
Purpose			: Deletes the file from disk
Author			: Yuvraj
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairDelete()
{
	if(_taccess_s(m_csFilePath, 0))
	{
		//File Not Found
		return false;
	}
	m_pMaxPEFile->CloseFile();
	SetFileAttributes(m_csFilePath, FILE_ATTRIBUTE_NORMAL);	
	if(TRUE == DeleteFile(m_csFilePath))
	{
		m_bStubDeleted = true;
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: RepairQuarantine
In Parameters	: -
Out Parameters	: bool
Purpose			: Fill Zero bytes to DOS Signature(MZ) and NT Header Signature(PE)  
Author			: Yuvraj
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairQuarantine()
{
	return RepairDelete();
}

/*-------------------------------------------------------------------------------------
Function		: CheckForVirusStub
In Parameters	: -
Out Parameters	: bool
Purpose			: Repair for Downloader.Bl virus 
Author			: Ajay
m_dwArgs[0] = dwVirStubSize
--------------------------------------------------------------------------------------*/
bool CRepairModuls::CheckForVirusStub(bool bDoNotDelete /*= false*/)
{
	if(!m_bInternalCall)
	{
		GetParameters();
	}

	if((m_dwFileSize >= (m_dwArgs[0]- 0x50) && m_dwFileSize <= (m_dwArgs[0] + 0x100) && !bDoNotDelete) ||
		(m_dwArgs[2] && m_dwFileSize >= (m_dwArgs[2]- 0x50) && m_dwFileSize <= (m_dwArgs[2] + 0x100)) || 
		m_dwArgs[0] == 0)           
	{
		if(0 == m_dwArgs[1])
		{
			return RepairDelete() ? false : true;
		}
		else
		{
			BYTE *pbyBuffer = new BYTE[m_ibyArgLen];
			if(pbyBuffer)
			{
				memset(pbyBuffer, 0, m_ibyArgLen);
				if(m_pMaxPEFile->ReadBuffer(pbyBuffer, m_dwArgs[1], m_ibyArgLen, m_ibyArgLen))
				{
					if(memcmp(pbyBuffer, m_byArg, m_ibyArgLen) == 0)
					{
						return RepairDelete() ? false : true;
					}
				}
			}
		}
	}
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: GetParameters
In Parameters	: -
Out Parameters	: bool
Purpose			: Get the arguments of function and fill the array with value of arguments 
Author			: Yuvraj
--------------------------------------------------------------------------------------*/
bool CRepairModuls::GetParameters()
{
	CString csParameters;
	CStringA csToEval;
	int iStart, iFurther, iLen, iArgs;
	
	iStart = iFurther = iLen = iArgs = 0;
	memset(m_dwArgs, 0, sizeof(m_dwArgs));

	memset(m_byArg, 0, sizeof(m_byArg));
	m_ibyArgLen = 0;

	// Added by Rupali on 24 Mar 11. To skip if paramter is not passed 
	int iModParamLen = m_csModParam.Trim().GetLength();
	if(iModParamLen == 0)
		return false;

	if(m_iStep > iModParamLen)
		return false;
	// End

	csParameters = m_csModParam.Tokenize(_T(","), m_iStep);

	while(csParameters != "")
	{
		iLen = csParameters.GetLength();

		iFurther = csParameters.Find(_T(']'), iStart);
		if(iFurther == -1)
			break;

		if((iFurther + 1) > iLen)
		{
			return false;
		}

		if((csParameters.GetAt(iFurther + 1) == _T('[')) || (csParameters.GetAt(iFurther + 1) == _T('M')) 
			||(iLen == iFurther + 1))
		{
			csToEval = csParameters.Mid(0, iFurther + 1);
			
			m_dwArgs[iArgs] = EvaluateExpression(csToEval);
			iArgs++;

			csParameters = csParameters.Mid(iFurther + 1);
			iStart = 0;
		}
		else
		{
			iStart = iFurther + 1;
		}
	}
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: EvaluateExpression
In Parameters	: char * 
Out Parameters	: DWORD
Purpose			: Expression parsing - Takes in a valid string expression and parses it into a DWORD
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
DWORD_PTR CRepairModuls::EvaluateExpression(const char * str)
{
	DWORD_PTR dwResult = 0;
	DWORD_PTR dwValue = 0;
	DWORD dwOffset = 0;

	int index = 0;
	const char * start = 0;
	const char * end = 0;
	char szNumber[20]={0};
	char opr = 0;	// 1 - add, 2 - subtract
	bool bMapResult = false;

	if(*str == 'M')
	{
		bMapResult = true;
		str ++;
	}

	while(str && *str)
	{
		if(*str == '[')
		{
			str++;
			start = str;
			while(*str && *str != ']')
			{
				end = str;
				str++;
			}
			end++;

			switch(*start)
			{
			case 'E' :
				{
					start ++;
					if(*start == 'M')
					{
						if(start + 1 == end)
						{
							dwValue = m_dwAEPMapped;
						}
						else
						{
							start++;
							if(end - start < sizeof(szNumber))
							{
								DWORD_PTR dwMA = 0;
								strncpy_s(szNumber, sizeof(szNumber), start, end - start);
								dwValue = atoi(szNumber);
								dwMA = m_dwAEPMapped;
								m_pMaxPEFile->ReadBuffer(&dwValue, dwMA + dwValue, sizeof(DWORD));
							}
							else
							{
								; // eror
							}
						}
					}
					else if(*start == 'U')
					{
						if(start + 1 == end)
						{
							dwValue =  m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint;
						}
						else
						{
							start++;
							if(end - start < sizeof(szNumber))
							{
								strncpy_s(szNumber, sizeof(szNumber), start, end - start);		
								dwValue = atoi(szNumber);
								m_pMaxPEFile->ReadBuffer(&dwValue, m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint + dwValue, sizeof(DWORD));
							}
							else
							{
								; // eror
							}
						}
					}
				}
				break;
			case 'L' :
				{
					start++;
					szNumber[0]= *start;
					start++;
					szNumber[1]= *start;
					start++;
					szNumber[2]= 0;
					index = atoi(szNumber);

					if(m_wNoOfSecs >= index - 1)
					{
						index = m_wNoOfSecs - index - 1;
					}
					if(start == end)
					{
						dwValue = m_pSectionHeader[index].PointerToRawData;
					}
				}
				break;
			case 'A' :
				{
					start++;
					szNumber[0]= *start;
					start++;
					szNumber[1]= *start;
					start++;
					szNumber[2]= 0;
					index = atoi(szNumber);

					if(index < m_wNoOfSecs)
					{
						index = m_pMaxPEFile->m_wAEPSec + index;
						if(start == end)
						{
							dwValue = m_pSectionHeader[index].PointerToRawData;
						}						
					}
				}
				break;
			case 'F' :
				{
					start ++;
					if(*start == 'S')
					{
						dwValue = m_dwFileSize;
						start ++;
						if(*start == '-')
						{
							start++;
							if(end - start < sizeof(szNumber))
							{
								strncpy_s(szNumber, sizeof(szNumber), start, end - start);
								dwValue = atoi(szNumber);
								m_pMaxPEFile->ReadBuffer(&dwValue, m_dwFileSize - dwValue, sizeof(DWORD));
							}
							else
							{
								; // eror
							}
						}
						else
						{
							;
						}
					}
					else if(*start == 'N')
					{
						dwValue = m_csFilePath.GetLength() - m_csFilePath.ReverseFind('\\') - 1;
					}
					else
					{
						szNumber[0]= *start;
						start++;
						szNumber[1]= *start;
						start++;
						szNumber[2]= 0;
						index = atoi(szNumber);

						if(index >= m_wNoOfSecs)
						{
							break; // error
						}

						if(start == end)
						{
							dwValue = m_pSectionHeader[index].PointerToRawData;
						}
						else
						{
							if(end - start < sizeof(szNumber))
							{
								memset(szNumber, 0, sizeof(szNumber));
								strncpy_s(szNumber, sizeof(szNumber), start, end - start);
								dwValue = atoi(szNumber);
								m_pMaxPEFile->ReadBuffer(&dwValue, m_pSectionHeader[index].PointerToRawData + dwValue, sizeof(DWORD));
							}
							else
							{
								; // eror
							}
						}

					}
				}
				break;
			case 'D' :
				{
					if(start + 1 == end)
					{
						dwValue = m_dwStartofDecryption;
					}
					else
					{
						start++;
						if(end - start < sizeof(szNumber))
						{
							strncpy_s(szNumber, sizeof(szNumber), start, end - start);
							dwValue = atoi(szNumber);
							memcpy_s(&dwValue, sizeof(dwValue),&m_byReadBuffer[dwValue], sizeof(dwValue));
						}
						else
						{
							; // eror
						}
					}
				}
				break;
			case 'C' :
				{
					start++;
					DWORD dwBytesToRead = 4;
					if(*start == 'B')
					{
						start++;
						dwBytesToRead = 1;
					}
					else if(*start == 'W')
					{
						start++;
						dwBytesToRead = 2;
					}					
					if(*start == 'M')
					{
						dwOffset = dwResult;
						dwValue = dwResult = 0;
						m_pMaxPEFile->ReadBuffer(&dwResult, GetMappedAddress(dwOffset), dwBytesToRead);
					}
					else
					{
						if(*start == 'U')
						{
							dwOffset = dwResult;
							dwValue = dwResult = 0;
							m_pMaxPEFile->ReadBuffer(&dwResult, dwOffset, dwBytesToRead);
						}
						else if(*start == '-')
						{
							start++;
							if(((end - start) + 1) < sizeof(szNumber))
							{
								strncpy_s(szNumber, sizeof(szNumber), start, ((end - start) + 1));
								dwValue = atoi(szNumber);
								dwValue = -dwValue; 
							}

						}
						else
						{
							if(((end - start) + 1)< sizeof(szNumber))
							{
								strncpy_s(szNumber, sizeof(szNumber), start,((end - start) + 1));
								dwValue = atoi(szNumber);
							}
							else
							{
								; // eror
							}
						}
					}
				}
				break;
			case 'B' :
				{
					start ++;
					dwValue = m_pMaxPEFile->m_stPEHeader.ImageBase;					
				}
				break;

			case 'Y': //Tushar ==> 21 Dec 2010 : For Overlay Size
				{
					start ++;
					int iNoSect = m_wNoOfSecs - 1;
					for(int i=iNoSect;i>=0;i--)
					{
						if(m_pSectionHeader[i].SizeOfRawData)
						{
							DWORD dwStartOfOverlay = m_pSectionHeader[i].PointerToRawData + 
													m_pSectionHeader[i].SizeOfRawData;
							if(m_dwFileSize > dwStartOfOverlay)
							{
								dwValue = m_dwFileSize - dwStartOfOverlay;
							}
							else
							{
								dwValue = 0;
							}
							break;
						}
					}
				}
				break;
			case 'R' :
				{
					start++;
					szNumber[0]= *start;
					start++;
					szNumber[1]= *start;
					start++;
					szNumber[2]= 0;
					index = atoi(szNumber);

					if(m_wNoOfSecs >= index - 1)
					{
						index = m_wNoOfSecs - index - 1;
					}					
					if(start == end)
					{
						dwValue = m_pSectionHeader[index].SizeOfRawData;
					}					
				}
				break;
			case 'S':
				{
					start++;
					dwValue = 0;					
					if(start == end)
					{
						m_dwSaveArgs[m_iSaveArg] = dwResult;
						m_iSaveArg++;
					}
					else if(*start == 'M')
					{
						m_dwSaveArgs[m_iSaveArg] = GetMappedAddress(dwResult);
						m_iSaveArg++;
					}
					else
					{
						if(((end - start) + 1) < sizeof(szNumber))
						{
							strncpy_s(szNumber, sizeof(szNumber), start,((end - start) + 1));
							index = atoi(szNumber);
							dwValue = m_dwSaveArgs[index];
						}
					}									
				}
				break;
			case 'X'://Tushar ==> 11 Jan 2011 : Added by Yash to Handle store return value of existing functions.(Slugin.A MOD File Problem)
				{
					start ++;					
					dwValue = 0;					
					if(start == end)
					{
						dwValue = m_dwReturnValues[0];
					}
					else
					{
						if(((end - start) + 1) < sizeof(szNumber))
						{
							strncpy_s(szNumber, sizeof(szNumber), start,((end - start) + 1));
							index = atoi(szNumber);
							dwValue = m_dwReturnValues[index];
						}
					}	
				}
				break;
			case 'N'://Tushar ==> 16 Feb 2011 : Added to Handle for Optional Header Values
				{
					start++;
					dwValue=m_pMaxPEFile->m_stPEHeader.e_lfanew;
				}
				break;
				// Added by Rupali on 4 Apr 11. To add text string in the expression.
			case 'T' :
				{
					start ++;
					if(end - start < MAX_INPUT_STR_PARAM)
					{		
						memset(m_byArg, 0x00, MAX_INPUT_STR_PARAM);
						
						char szBuff[3]={0};
						char *pHex = NULL;
						
						m_ibyArgLen = 0;
						for(int i = 0; i < end-start; i += 2)
						{
							szBuff[0] = start[i];
							szBuff[1] = start[i+1];
							szBuff[2] = '\0';
							int iChar = strtol(szBuff, &pHex, 0x10);
							m_byArg[m_ibyArgLen++] = iChar;
						}
					}					
				}
				break;
				// End
			default:
				{
					; // error
				}
				break;
			}

			if(opr == 1)
			{
				dwResult = dwValue + dwResult;
			}
			else if(opr == 2)
			{
				// Added by Rupali on 10 Mar 2011. Needed for virus Dropet by Yash.
				if(dwResult > dwValue)
					dwResult = dwResult - dwValue;
				else
					dwResult = dwValue - dwResult;
				// End
			}
			else if(opr == 3)
			{
				dwResult = dwResult ^ dwValue;
			}
			else if(opr == 4)
			{
				dwResult = ~dwValue;
			}
			else if(opr == 5)
			{
				dwResult >>= dwValue;
			}			
			else if(opr == 6)
			{
			  dwResult = dwResult * dwValue;
			}
			else if(opr == 7)
			{
			  dwResult = dwResult | dwValue;
			}
			else if(opr == 8)
			{
				dwResult <<= dwValue;
			}	
			else
			{
				dwResult = dwValue;
			}
		}

		if(*str == '+')
		{
			opr = 1;
		}
		else if(*str == '-')
		{
			opr = 2;
		}
		else if(*str == '^')
		{
			opr = 3;
		}
		else if(*str == '~')
		{
			opr = 4;
		}
		else if(*str == '>')
		{
			opr = 5;
		}
		else if(*str == '*')
		{
		   opr = 6;
		}
		else if(*str == '|')
		{
		   opr = 7;
		}
		else if(*str == '<')
		{
			opr = 8;
		}
		str++;
	}

	if(bMapResult)
	{
		dwResult = GetMappedAddress(dwResult);
	}

	return (dwResult);
}

/*-------------------------------------------------------------------------------------
Function		: GetMappedAddress
In Parameters	: DWORD Address
Out Parameters	: DWORD
Purpose			: Maps a given virtual address to a file offset
Author			: Rishi Diwan
--------------------------------------------------------------------------------------*/
DWORD CRepairModuls::GetMappedAddress(DWORD dwRVAAddress)
{	
	if(m_wNoOfSecs > 0 && dwRVAAddress < m_pSectionHeader[0].VirtualAddress)
	{
		return dwRVAAddress;
	}

	WORD dwAddressSection = 0;

	for(WORD wSec = 0; wSec < m_wNoOfSecs; wSec++)
	{
		if(dwRVAAddress >= m_pSectionHeader[wSec].VirtualAddress && 
			((dwRVAAddress < (m_pSectionHeader[wSec].VirtualAddress + m_pSectionHeader[wSec].Misc.VirtualSize)) || 
			(dwRVAAddress < (m_pSectionHeader[wSec].VirtualAddress + m_pSectionHeader[wSec].SizeOfRawData))))
		{
			return (dwRVAAddress - m_pSectionHeader[wSec].VirtualAddress + m_pSectionHeader[wSec].PointerToRawData);
		}
	}
	return -1;
}

/*-------------------------------------------------------------------------------------
Function		: RewriteAddressOfEntryPoint
In Parameters	: DWORD dwNewAddressOfEntryPoint
Out Parameters	: bool
Purpose			: Yuvraj
Author			: Writes new Address of entry point to the file
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RewriteAddressOfEntryPoint()
{
	if(!m_bInternalCall)
	{
		if(!GetParameters())
		{
			return false;
		}
	}
	if(GetMappedAddress(m_dwArgs[0]) > m_dwFileSize)
	{
		return RepairDelete();
	}
	return m_pMaxPEFile->WriteAEP(m_dwArgs[0]);
}

/*-------------------------------------------------------------------------------------
Function		: GetBufferforDecryption
In Parameters	: Start of Read & Size of Read
Out Parameters	: bool
Purpose			: Reads Buffer for Special Decryption
Author			: Yash
m_dwArgs[0] Start offset,
m_dwArgs[1] Size to read
--------------------------------------------------------------------------------------*/
bool CRepairModuls::GetBufferforDecryption()
{
	if(!m_bInternalCall)
	{
		GetParameters();
	}
	m_byReadBuffer = new BYTE[m_dwArgs[1]];
	if(NULL == m_byReadBuffer)
	{
		return false;
	}

	bool bRet = m_pMaxPEFile->ReadBuffer(m_byReadBuffer, m_dwArgs[0], m_dwArgs[1], 0, &m_dwSizeofBuff);
	if(0 == m_dwSizeofBuff)
	{
		return RepairDelete();
	}
	return bRet;
}

/*-------------------------------------------------------------------------------------
Function		: ReplaceOriginalData
In Parameters	: DWORD OriginalDataOffset, DWORD SizeofReplacement, DWORD ReplacementOffset
Out Parameters	: bool
Purpose			: Read the data of size from original offset and write it to replacement offset 
Author			: Yuvraj
--------------------------------------------------------------------------------------*/
bool CRepairModuls::ReplaceOriginalData()
{
	if(!m_bInternalCall)
	{
		if(!GetParameters())
		{
			return false;
		}
	}	
	
	if(0 == m_dwArgs[1] || m_dwArgs[0] >= m_dwFileSize)
	{
		return RepairDelete();
	}
	if(m_dwArgs[1] >= m_dwFileSize)
	{
		return false;
	}
	return CopyData(m_dwArgs[0], m_dwArgs[2], m_dwArgs[1], m_dwArgs[3], m_dwArgs[4], m_dwArgs[5]);	
}

/*-------------------------------------------------------------------------------------
Function		: FillWithZero
In Parameters	: DWORD dwOffset, DWORD dwLength
Out Parameters	: bool
Purpose			: Fill the bytes with zero from the given offset to the length
Author			: Yuvraj
m_dwArgs[0]: Offset from where to start filling the zeros.
m_dwArgs[1]: No of bytes to fill.
--------------------------------------------------------------------------------------*/
bool CRepairModuls::FillWithZero()
{
	if(!m_bInternalCall)
	{
		if(!GetParameters())
		{
			return false;
		}
	}
	return m_pMaxPEFile->FillWithZeros(m_dwArgs[0], m_dwArgs[1]);
}

/*-------------------------------------------------------------------------------------
Function		: CalculateLastSectionDataSize
In Parameters	: -
Out Parameters	: bool
Purpose			: Calculates the Size of Raw data of the last section after the virus code is removed
Author			: Yuvraj
m_dwArgs[0]		: Case no
0: Default value. if 0 set SRD and VS by lookibng at newly set file size
1: Only set SRD, do not set VS
2: Use m_dwArgs[1] to reduce SRD and m_dwArgs[2] to reduce VS	
--------------------------------------------------------------------------------------*/
bool CRepairModuls::CalculateLastSectionDataSize()
{
	if(!m_bInternalCall)
	{
		GetParameters();
	}

	if(m_dwArgs[0] == 0 || m_dwArgs[0] == 1)
	{
		// Update SRD only
		return m_pMaxPEFile->CalculateLastSectionProperties();
	}

	if(0 == m_wNoOfSecs)
	{
		return true;
	}

	// Search for the last section having non zero SRD 
	int iLastSection = 0; 	
	for(int iSec = m_wNoOfSecs - 1; iSec > 0; iSec--) 
	{
		//Check whether the SRD of section is non zero
		if(m_pSectionHeader[iSec].SizeOfRawData != 0x00) 
		{
			iLastSection = iSec;
			break;
		}
	}	
	
	// Set modified Last section SRD
	DWORD dwSRD = m_pSectionHeader[iLastSection].SizeOfRawData - m_dwArgs[1];
	if(!m_pMaxPEFile->WriteSectionCharacteristic(iLastSection, dwSRD, SEC_SRD))
	{
		return false;
	}

	// Set modified Virtual size
	DWORD dwVS	= m_pSectionHeader[iLastSection].Misc.VirtualSize - m_dwArgs[2];
	if(!m_pMaxPEFile->WriteSectionCharacteristic(iLastSection, dwVS, SEC_VS))
	{
		return false;
	}

	m_dwReturnValues[0] = dwSRD;
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: RemoveLastSection
In Parameters	: int iNoOfSec
Out Parameters	: bool
Purpose			: Removes given number of sections, if no sections are given it will remove 
				  last section. Also considers Overlay
Author			: Yuvraj
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RemoveLastSection()
{
	if(!m_bInternalCall)
	{
		GetParameters();
	}

	if(m_dwArgs[0] == 0)
	{
		m_dwArgs[0] = 1;
	}
	bool bTruncateOverlay = (m_dwArgs[1] == 0) ? false : true;
	return m_pMaxPEFile->RemoveLastSections((WORD)m_dwArgs[0], bTruncateOverlay);
}

/*-------------------------------------------------------------------------------------
Function		: SetFileEnd
In Parameters	: DWORD dwFileEnd
Out Parameters	: bool
Purpose			: Set the end of file to given addr. no consideration
Author			: Rupali
Be careful while changing this function as its used by TTF file format also.
--------------------------------------------------------------------------------------*/
bool CRepairModuls::SetFileEnd()
{
	if(!m_bInternalCall)
	{
		if(!GetParameters())
		{
			return false;
		}
	}
	m_pMaxPEFile->ForceTruncate(m_dwArgs[0]);	
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: SetFileEndEx
In Parameters	: DWORD dwFileEnd
Out Parameters	: bool
Purpose			: Set the end of file, considers Overlay when setendoffile addr. inside 
				  last section or equal to pointer to raw data of last section. 
Author			: Yuvraj
--------------------------------------------------------------------------------------*/
bool CRepairModuls::SetFileEndEx()
{
	if(!m_bInternalCall)
	{
		if(!GetParameters())
		{
			return false;
		}
	}
	return m_pMaxPEFile->TruncateFile(m_dwArgs[0]);	
}

/*-------------------------------------------------------------------------------------
Function		: SetFileEndWithFileAlignment
In Parameters	: None
Out Parameters	: bool
Purpose			: Set the end of file with aligned offset
				  [Overlay is not maintained. So use this when virus overwrites overlay or some part of last section.]
Author			: Manjunath
m_dwArgs[0]		:DWORD dwFileEnd
--------------------------------------------------------------------------------------*/
bool CRepairModuls::SetFileEndWithFileAlignment()
{
	if(!m_bInternalCall)
	{
		if(!GetParameters())
		{
			return false;
		}
	}
	return m_pMaxPEFile->TruncateFileWithFileAlignment(m_dwArgs[0]);
}

/*-------------------------------------------------------------------------------------
Function		: TruncateEP
In Parameters	: -
Out Parameters	: bool
Purpose			: Truncates file to the previous entry point
Author			: Rishi Diwan
--------------------------------------------------------------------------------------*/
bool CRepairModuls::TruncateEP()
{
	if(m_dwAEPMapped  == m_pSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections - 1].PointerToRawData)
	{
		return m_pMaxPEFile->RemoveLastSections(1, true);	
	}
	if(m_dwAEPMapped > 0)
	{
		return m_pMaxPEFile->ForceTruncate(m_dwAEPMapped);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: RepairOptionalHeader
In Parameters	: Three DWORD Values 
					1. Field no to modify
					2. New value to write 
					3. New value to write for data directories
Out Parameters	: bool
Purpose			: Repair Optional Header Values Specifically Directories (RVA & Size)
Author			: Yash
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairOptionalHeader()
{
	if(!m_bInternalCall)
	{
		GetParameters();
	}

	if(0 == m_dwArgs[0])
	{
		m_wNoOfSecs--;
		return m_pMaxPEFile->WriteNumberOfSections(m_wNoOfSecs);
	}
	bool bForceSetDataDirSize = m_dwArgs[3] ? true : false;
	return m_pMaxPEFile->RepairOptionalHeader(m_dwArgs[0], m_dwArgs[1], m_dwArgs[2], bForceSetDataDirSize);
}

/*-------------------------------------------------------------------------------------
Function		: RepairSectionHeader
In Parameters	: None
Out Parameters	: Returns true if successful otherwise false
Author			: Rupali

Description		: Writes Section Header Values 

m_dwArgs[0]		: Section no to modify
m_dwArgs[1]		: Offset of property to modify
				Attribute Name				Offset	
				Section Name				 0
				Virtual size				 8
				RVA							 12
				Size of Raw data			 16
				Pointer to raw data			 20
				Pointer to Relocations		 24
				Pointer to Line Numbers		 28
				Number of  Relocations		 32
				Number to Line Numbers		 34
				Characteristics				 36
m_dwArgs[2]		: New value to write
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairSectionHeader()
{
	if(!m_bInternalCall)
	{
		if(!GetParameters())
		{
			return false;
		}
	}
	return m_pMaxPEFile->WriteSectionCharacteristic((WORD)m_dwArgs[0] - 1, m_dwArgs[2], 	m_dwArgs[1]);
}

/*-------------------------------------------------------------------------------------
Function		: CalculateChecksum
In Parameters	: -
Out Parameters	: bool
Purpose			: Calculates and Writes new checksum of repaired file
Author			: Rishi Diwan
--------------------------------------------------------------------------------------*/
bool CRepairModuls::CalculateChecksum()
{
	m_pMaxPEFile->SetFileName(m_csFilePath);
	return m_pMaxPEFile->CalculateChecksum();
}

/*-------------------------------------------------------------------------------------
Function		: CalculateImageSize
In Parameters	: -
Out Parameters	: bool
Purpose			: Calculates image size and Writes new image size of repaired file
Author			: Rishi Diwan
--------------------------------------------------------------------------------------*/
bool CRepairModuls::CalculateImageSize()
{
	return m_pMaxPEFile->CalculateImageSize();
}

/******************************************************************************
Function Name	:	CopyData
Author			:	Rupali	
Input			:	dwReadStartAddr		: File offset of data to copy.
					dwWriteStartAddr	: File offset of data to be copied at.
					dwSizeOfData		: Size of data to copy
Output			:   Returns true if data copy is suceesful else returns false.
Description		:	Function copies data from sorce oddset to destination in 
					chunks OF 64kb buffer. Seperated this function as it is 
					required for copying data in ReplaceOriginalData and also
					to copy overlay in case of RemovelastSection.
*******************************************************************************/
bool CRepairModuls::CopyData(DWORD dwReadStartAddr, 
							 DWORD dwWriteStartAddr, 
							 DWORD dwSizeOfData, 
							 DWORD dwOperation, 
							 DWORD dwKey, 
							 DWORD dwDecryptionSize/* = 0*/,
							 DWORD dwStartOfSecondDecryp/* = 0*/,
							 DWORD dwDisplacement/* = 0*/,
							 DWORD dwDecLevel/* = 6*/)
{
	BYTE *byBuffer = NULL;
	BYTE byDecKey = 0;
	try
	{
		DWORD dwChunk = 0x10000;
		if(2 == dwOperation)  
		{
			dwChunk = 0x1000;
		}
		if(dwSizeOfData < dwChunk)
		{
			dwChunk = dwSizeOfData;
		}

		byBuffer = new BYTE[dwChunk];
		if(!byBuffer)
		{
			return false;
		}

		if(0 == dwDecryptionSize)
		{
			dwDecryptionSize = dwSizeOfData;
		}

		BYTE byKeyBuff[0x200] = {0};
		if(dwOperation == DECRYPTION_DORIFEL)
		{
			for(int i = 0; i < 0x100; i = i++)
			{
				byKeyBuff[i] = (BYTE)i;
			}

			BYTE byData[0x100] = {0};

			if(dwKey==2)
			{
              BYTE byKey2[0x10]={0x32,0x5A,0x03,0x0B,0x09,0x6F,0x21,0x2C,0x08,0x21,0x12,0x36,0x42,0x1F,0x0C,0x0D};
			  memcpy(byData,byKey2,0x10);
			}
			else
			{
			  m_pMaxPEFile->ReadBuffer(byData, 0x1B3C4, 0x10, 0x10);
			}
		

			BYTE byVal1 = 0, byVal2 = 0, temp = 0, AL = 0;
			for(int i = 0, j = 0; i < 0x100; i = i++, j++)
			{
				if(j == 0x10)
				{
					j = 0;
				}
				byVal1 = byKeyBuff[i];
				AL += byVal1;

				byVal2 = byData[j];
				AL += byVal2;

				temp = byKeyBuff[i];
				byKeyBuff[i] = byKeyBuff[AL];
				byKeyBuff[AL] = temp;
			}
			memcpy(&byKeyBuff[0x100], byKeyBuff, 0x100);
		}


		DWORD	dwBytesRead = 0, dwDecryptionCnt = 0, dwFlag = 0;		
		DWORD	dwSecDecryptionCnt = dwStartOfSecondDecryp, dwProFDec = 0;
		DWORD	dwSecCnt = dwSecDecryptionCnt, dwIdx = 0;; 
		BYTE	byPrevByte = 0, byTempPrevByte = 0, bySavePrevByte[10];
		BYTE	BL = 0, CL = 0, EDI = 0;
		int		iKey = 1;
						
		for(DWORD dwOffset = 0; dwOffset < dwSizeOfData; dwOffset += dwChunk)
		{		
			memset(byBuffer, 0, dwChunk);

			if(!m_pMaxPEFile->ReadBuffer(byBuffer, dwReadStartAddr + dwOffset, dwChunk, 0, &dwBytesRead))
			{
				delete [] byBuffer;
				byBuffer = NULL;
				return false;
			}

			switch(dwOperation)
			{
				// Added by Rupali on 9 May 11. Added decryption by Ajay
				case 1:
					for(DWORD dwCnt = 0; dwCnt < dwBytesRead && dwDecryptionCnt < dwDecryptionSize; dwCnt++, dwDecryptionCnt++)	
					{
						byBuffer[dwCnt] ^= dwKey;
					}
					break;
				// End
				// Added by Rupali on 28 May 11. Added decryption by Adnan
				case 2:
					byDecKey = static_cast<BYTE>(dwKey);
					for(DWORD dwIndex = dwChunk - 1; dwIndex < dwChunk; dwIndex--)
					{
						byDecKey = byDecKey >> 0x06 | byDecKey << 0x02;
						byBuffer[dwIndex] ^= byDecKey;
						byDecKey--;
					}	
					break;
				// End
				case 3:
					byTempPrevByte = byBuffer[dwChunk-1];
					for(DWORD dwIndex = dwChunk - 1; dwIndex >= 0x01; dwIndex--)
					{
						byBuffer[dwIndex] -= byBuffer[dwIndex-1];
					}
					if(0 != dwOffset)
					{						
						byBuffer[0] -= byPrevByte;
					}
					byPrevByte = byTempPrevByte;
					break;
				case 4: 
					DecryptGlkajC(byBuffer, dwBytesRead);
					break;
				// Xorer decryption
				case 5:
					{
						if(dwDecryptionSize && (dwDecryptionCnt <= dwDecryptionSize) && dwDecLevel)
						{
							DWORD dwCnt = 0, dwFirstDecDisp = 2;  
							BYTE EncMZ[] = {0xB2, 0xA5};

							//Some variants of Xorer in first level encryption encrypts every byte and some variants encrypts leaving one byte in between
							//If every byte is encrypted then we get B2A5 in first two bytes otherwise we get B25A
							if(((dwDecLevel | 2) == dwDecLevel) && !memcmp(&byBuffer[0], EncMZ, _countof(EncMZ)))
								dwFirstDecDisp = 1;

							for(dwCnt = 0; (dwCnt < dwBytesRead) && (dwDecryptionCnt < dwDecryptionSize); dwCnt += dwFirstDecDisp, dwDecryptionCnt += dwFirstDecDisp)	
							{
								if((dwDecLevel | 2) == dwDecLevel) //1st level
								{
									byBuffer[dwCnt] ^= dwKey;
								}							
							}
							if((dwSecDecryptionCnt <= dwDecryptionSize) && ((dwDecLevel | 4) == dwDecLevel))
							{
								for(; dwSecCnt < dwBytesRead && dwSecDecryptionCnt < dwDecryptionSize; dwSecCnt += dwDisplacement, dwSecDecryptionCnt += dwDisplacement)
								{
									byBuffer[dwSecCnt] ^= dwKey;
								}
								dwSecCnt -= dwDisplacement;
								dwSecCnt = dwDisplacement - (dwBytesRead - dwSecCnt);
							}
						}
						break;
					}
				case 6:	// Protector.A
					{
						DWORD dwCnt = 0;
						bySavePrevByte[dwFlag] = byBuffer[dwBytesRead-1];
						for (dwCnt = dwBytesRead-1; dwCnt > 0; dwCnt--)
						{
							byBuffer[dwCnt] ^= byBuffer[dwCnt-1];
						}
						if(dwFlag  == 0)
						{
							byBuffer[dwCnt] ^= (byBuffer[dwCnt] ^ 0x4D);
							dwFlag++;
						}
						else
						{
							DWORD dwTempFlag = dwFlag;
							byBuffer[dwCnt] = (byBuffer[dwCnt] ^ bySavePrevByte[--dwTempFlag]);
							dwFlag++;
						}
					}
					break;

				case 7: // Protector.B and Protector.D
					{
						DWORD dwCnt = 0;
						BYTE byFirstByte;
						for(dwCnt = 0; dwCnt < dwBytesRead-1; dwCnt += 4)
						{
							byFirstByte			= byBuffer[dwCnt];
							byBuffer[dwCnt]		= byBuffer[dwCnt+3];
							byBuffer[dwCnt + 3]	= byFirstByte;
						}
					}
					break;
				case 8: // Protector.C
					for(DWORD i=0;i<dwBytesRead;i++)
					{
						// If 0x0 or byte same as key then leave the byte as it is
						if   (byBuffer[i]==0x00 || byBuffer[i]==dwKey);   
						else  byBuffer[i] ^= dwKey;  
					}
					break;
				case 9: // Protector.E
					{
						BYTE byFirstByte, bySwapVar;
						for(DWORD i = 0; i < dwBytesRead-1; i += 4)
						{
							byFirstByte	    = byBuffer[i];
							byBuffer[i]	    = byBuffer[i+3];
							byBuffer[i+3]   = byFirstByte;
							bySwapVar	    = byBuffer[i+1];
							byBuffer[i+1]   = byBuffer[i+2];
							byBuffer[i+2]   = bySwapVar;
						}
					}
					break;
				case 10 : // Protector.F
					{
						if(dwProFDec == 0 && byBuffer[0] == 0x4D && byBuffer[1] == 0x5A)
						{
							dwProFDec = 1;
							break;
						}
						else if(dwProFDec == 1)
						{
							break;
						}
						for(DWORD i = 0; i < dwBytesRead-1; i += 4)
						{
							byBuffer[i]     ^= (BYTE)m_dwArgs[4];
							byBuffer[i+1]	+= (BYTE)m_dwArgs[5];
							byBuffer[i+2]	-= (BYTE)m_dwArgs[6];
							byBuffer[i+3]	^= (BYTE)m_dwArgs[7];
						}	
					}
					break;
				case 11:
					for(DWORD dwTemp = 0x00; dwTemp < dwBytesRead; dwTemp++, dwIdx++)
					{
						dwIdx = dwIdx % dwKey;
						byBuffer[dwTemp] ^= m_byReadBuffer[dwIdx];
					}
					break;
				case 12:
					{
						int iRem = dwBytesRead % 4; 
						for(DWORD dwCount = 0; dwCount < (dwBytesRead - iRem); dwCount += 4)
						{
        						*(DWORD *)&byBuffer[dwCount] ^= 0xC1CADA33;
						}
					}
					break;
				case DECRYPTION_DORIFEL:
					{						
						for(DWORD i = 0; i < dwBytesRead; i++)
						{
							if(iKey == 0x100)
							{
								iKey = 0;
							}
							CL = byKeyBuff[iKey];
							EDI += CL;
							BL = byKeyBuff[EDI];
							byKeyBuff[iKey] = BL;
							byKeyBuff[EDI] = CL;

							CL += byKeyBuff[iKey];
							byBuffer[i] ^= byKeyBuff[CL];	
							iKey++;
						}
					}
					break;
				default:
					break;
			}
			if((dwOffset + dwChunk) > dwSizeOfData || dwBytesRead != dwChunk)
			{
				dwBytesRead = dwSizeOfData - dwOffset;
			}
			if(!m_pMaxPEFile->WriteBuffer(byBuffer, dwWriteStartAddr + dwOffset, dwBytesRead, dwBytesRead))
			{
				delete [] byBuffer;
				byBuffer = NULL;
				return false;
			}
		}

		delete [] byBuffer;
		byBuffer = NULL;
		return true;
	}
	catch(...)
	{
		if(byBuffer)
		{
			delete [] byBuffer;
			byBuffer = NULL;
		}
		OutputDebugString(L"Exception in CRepairModuls::CopyData");
		return false;
	}
}

/*-------------------------------------------------------------------------------------
Function		: ReplaceOriDataDecryption
In Parameters	: DWORD dwOriginalDataOffset, DWORD dwSizeOfReplacement, 
				  DWORD dwPointOfReplacement, DWORD dwStartOfDecryption, 
				  DWORD dwDecryptionLength
Out Parameters	: bool
Purpose			: In case of original data present in m_byReadBuffer, perfoms replacement action of data
Author			: Yuvraj
--------------------------------------------------------------------------------------*/
bool CRepairModuls::ReplaceOriDataDecryption()
{
	if(!m_bInternalCall)
	{
		if(!GetParameters())
		{
			return false;
		}
	}

	if(m_byReadBuffer == NULL)
	{
		return false;
	}
	
	if(m_dwArgs[0] >= m_dwStartofDecryption && 	m_dwArgs[0] < m_dwStartofDecryption + m_dwDecryptionLength)
	{
		DWORD dwRelativeOffset = m_dwArgs[0] - m_dwStartofDecryption;
		return m_pMaxPEFile->WriteBuffer(&m_byReadBuffer[dwRelativeOffset], m_dwArgs[2], m_dwArgs[1], m_dwArgs[1]);		
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		:	SpecialRepair
In Parameters	:	
Out Parameters	:	bool
Purpose			:	Repair for W32.Importer.A virus 
Author			:	Yash
Date			:	05 Jan 2011
--------------------------------------------------------------------------------------*/
bool CRepairModuls::SpecialRepair()
{
	bool	bRet	= false;	
	if(!m_bInternalCall)
	{
		if(!GetParameters())
			return bRet;
	}
	
	switch(m_dwArgs[0])
	{
		case GET_VALUE:
			bRet = GetValueNextToString();
			break;
		case SPECIAL_REPAIR_IMPORTER_A:
			bRet = RepairImporterA();
			break;
			//Tushar ==> 11 Jan 2011 : Added by Yash and Code Analyzed by Rupali
		case SPECIAL_REPAIR_RENAMED_FILE: //Expression="23#[C3]" W32.Belod.A
			bRet = RepairRenameFile();//_T(".dat"));
			break;
			// Added by Rupali o 19 Apr 11. Added special repair for virus HLLC.Ext by Prajkta.
		case SPECIAL_REPAIR_HLLC_EXT:
			bRet = Repair_HLLC_Ext();
			break;			
			// End
			// Added by Rupali on 18 Apr 2011. Added special repair for virus Warray by Neeraj.			
		case SPECIAL_REPAIR_WARRAY:
			bRet = RepairWarray();
			break;
			// End
			//Tushar ==> 07 Feb 2011 : Added by Tushar
		case SPECIAL_REPAIR_APATHY://APATHY.5378
			bRet=RepairApathy();
			break;
		case SPECIAL_REPAIR_SALITY://Sality.H,I,J
			bRet=RepairSalityByteXOR();
			break;
			// Added by Rupali on 1 Mar 2011. Added Virus Velost by Neeraj.
		case SPECIAL_REPAIR_VELOST:
			bRet = RepairVelost123341();
			break;
			// End
		case SPECIAL_REPAIR_REDEMPTION:
			bRet = RepairRedemption();
			break;
			// End
			// Added by Rupali on 25 Apr 2011. Added special repair for stream viruses by Ravi.
		case SPECIAL_REPAIR_STREAM:
			bRet = RepairStream();
			break;
			// End	
		case CHECK_AEP_SECTION:
			bRet = CheckAEPSection();
            break;
			// Added by Rupali on 9 June 2011. Added special repair for virus Tinit by Adnan.			
		case SPECIAL_REPAIR_TINIT_A:
			bRet = RepairTinitA();
            break;
			// End
			// Added by Rupali on 26 Mar 2011. Added special repair for virus Renamer by Omkar.			
		case SPECIAL_REPAIR_RENAMER:
			bRet = RepairRenamer();
            break;
			// End
			// Added by Rupali on 8 Apr 2011. Added special repair for virus REFROSO.CKTK by Ravi.			
		case SPECIAL_REPAIR_OTWYCAL_G:
			bRet = RepairOtwycalG();
            break;
			// End					
			// Added by Rupali on 5 May 2011. Added special repair for virus Nemsi.B by Adnan.			
		case SPECIAL_REPAIR_NEMSI_B:
			bRet = RepairNemsiB();
            break;
			// End		
		case SPECIAL_REPAIR_ASSILL:
			bRet = RepairAssill();
			break;
		case SPECIAL_REPAIR_WINEMMEM:
			bRet = RepairWinemmem();
			break;
		case SPECIAL_REPAIR_SABUREX:
			bRet = RepaireSaburex();
			break;	
		case SPECIAL_REPAIR_9X_CIH:
			bRet = Repair9XCIH();
			break;		
		case SPECIAL_REPAIR_CHITON_B:
			bRet = RepairChitonB();
			break;		
		case SPECIAL_REPAIR_MUCE_B:
			bRet = RepairMuceB();
			break;
		case SPECIAL_REPAIR_PADIC:
			bRet = RepairPadic();
			break;
		case SPECIAL_REPAIR_EMAR:
			bRet = RepairEmar();
			break;
		case SPECIAL_REPAIR_MIAM:
			{
				DWORD dwFileOffset;
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwArgs[2], &dwFileOffset) || m_dwArgs[1] == 0xFFFFFFFF)
				{
					return RepairDelete();
				}				
				DWORD dwAepSectNo = m_pMaxPEFile->GetSectionNoFromOffset(m_dwArgs[1]);
				DWORD dwOffSectNo = m_pMaxPEFile->GetSectionNoFromOffset(dwFileOffset);

				DWORD dwOriAEP = m_dwArgs[2], dwTruncateOffset = m_dwArgs[1];
				if(dwAepSectNo == dwOffSectNo)
				{					
					m_pMaxPEFile->ReadBuffer(&dwOriAEP, dwFileOffset + 1051, 4, 4);
					dwOriAEP -= m_pMaxPEFile->m_stPEHeader.ImageBase;
					dwTruncateOffset = dwFileOffset;
				}
				if(m_pMaxPEFile->WriteAEP(dwOriAEP))
				{
					bRet = m_pMaxPEFile->TruncateFile(dwTruncateOffset);
				}
			}
			break;
		case SPECIAL_REPAIR_KIRO:
			bRet = RepairKiro();
			break;
		case SPECIAL_REPAIR_KLEZ:
			bRet = RepairKlez();
			break;		
		case GET_SEC_PRD:
			{
				DWORD dwSec = m_pMaxPEFile->GetSectionNoFromOffset(m_dwArgs[1]);			
				if((m_dwArgs[1] > m_dwFileSize))
				{
					return RepairDelete();
				}
				else if((dwSec == 0xFF) && (m_dwArgs[1] < m_dwFileSize))
				{
					dwSec = m_wNoOfSecs - 1;				
				}
				m_dwReturnValues[0] = m_pSectionHeader[dwSec].PointerToRawData;
				bRet = true;
			}
			break;			
		case INTERCHANGE_SECTION_HEADERS:
			bRet= InterChangeSectionHeaders(m_dwArgs[1],m_dwArgs[2]);
		case SPECIAL_REPAIR_TRIONC:
			bRet = RepairTrionC();
			break;
		case SPECIAL_REPAIR_DOCPACK: //31
			bRet = RepairDOCPACK();
			break;
		case SPECIAL_REPAIR_STRING_TO_DECIMAL:	//32 for virus.Lamer.a by Gajanan on 01/08/2014
			bRet=RepairLamer();
			break;
		case SPECIAL_REPAIR_PIONEERBT:
			bRet = RepairPIONEERBT();
			break;
		case SPECIAL_REPAIR_RECYL:
			bRet = RepairRecyl();
			break;
		case SPECIAL_REPAIR_SHIPUP:
			bRet = RepairShipUp();
			break;
		case SPECIAL_REPAIR_RANSOM:
			bRet = RepairRansom();
			break;
		case SPECIAL_REPAIR_LAMEREL:
			bRet = RepairLAMEREL();
			break;
		case SPECIAL_REPAIR_PIONEERDLL:
			bRet = RepairPIONEERCZ();
			break;
		case SPECIAL_REPAIR_MULTI_PREPENDER:
			bRet = RepairMultiLevPrependerInf();
			break;
		case SPECIAL_REPAIR_LAMER_CQ:
			bRet = RepairLamerCQ();
		default:
			break;
	}
	return bRet;
}

/*-------------------------------------------------------------------------------------
Function		: ReturnValue
In Parameters	: Two DWORD values
Out Parameters	: bool
Purpose			: To Store return values in m_dwReturnValues[] array
Author			: Tushar Kadam (30 Nov 2010)
--------------------------------------------------------------------------------------*/
bool CRepairModuls::ReturnValue()
{
	if(!m_bInternalCall)
	{
		GetParameters();
	}

	DWORD dwFirstArg = m_dwArgs[0];
	DWORD dwSecArg = m_dwArgs[1];

	bool bRet = true;
	switch(m_dwArgs[2])
	{
	case 1:
		{	
			DWORD dwTemp = dwFirstArg % 0x10;
			m_dwReturnValues[0] = dwFirstArg - (dwTemp + dwSecArg);
		}
		break;
	case 2:
		{	
			BYTE byValArr[4]={0};
			for(int i=0;i<4;i++)
			{
				byValArr[i]=*((BYTE *)&dwFirstArg +i);
				byValArr[i]-=0x06;
			}
			m_dwReturnValues[0] = *((DWORD*)(byValArr));
		}
		break;
	case 3://Tushar ==> 20 Dec 2010 : Added by Yash for Galkaj
		{
			if(!m_dwSizeofBuff)
			{
				return false;
			}
			BYTE byDecKey = LOBYTE(m_dwArgs[1]);
			for(int i = m_dwSizeofBuff; i > 0; i--)
			{
				// Added by Rupali on 9 May 11. Added case for virus Ditex.A
				if(1 == m_dwArgs[0])
				{
					m_byReadBuffer[i - 1] +=  (BYTE)m_dwArgs[1];
				}
				// Added by Rupali on 23 May 11. Added case for virus Poson.1631
				else if(2 == m_dwArgs[0])
				{
					m_byReadBuffer[i - 1] ^=  (BYTE)m_dwArgs[1];
				}
				else if(3 == m_dwArgs[0])
				{
					if((m_byReadBuffer[i - 1]) != 0 && (m_byReadBuffer[i - 1]) != (BYTE)m_dwArgs[1])
					{						
						m_byReadBuffer[i - 1] ^=  (BYTE)m_dwArgs[1];
					}
				}
				// Added case for virus Belial.2537
				else if(4 == m_dwArgs[0])
				{
					m_byReadBuffer[i - 1] -=  (BYTE)m_dwArgs[1];
				}
				else if(5 == m_dwArgs[0])
				{  					
					m_byReadBuffer[i - 1] ^=  byDecKey;
					byDecKey += 1;
				}
				else if(6 == m_dwArgs[0]) // ROR
				{  					
					m_byReadBuffer[i - 1] = m_byReadBuffer[i - 1] >> byDecKey | m_byReadBuffer[i - 1] << (0x08 - byDecKey); 
				}
				else if(7 == m_dwArgs[0])
				{
					m_byReadBuffer[i - 1] =  ~m_byReadBuffer[i - 1];
				}
			}
			m_dwReturnValues[0] = *(DWORD *)&m_byReadBuffer[0];
		}
		break;
		//Tushar ==> 05 Jan 2011 : Added by Yash
	case 4://Mkar.E & Mkar.C After checking MZ stub will be deleted
		{
			if(!m_dwReturnValues[0])
			{
				return RepairDelete();
			}
		}
		break;
		//Tushar ==> 05 Jan 2011 : Added by Yash
	case 5://Write DWORD Value at Specified Location 
		{
			if(0x0C==dwFirstArg)
			{
				dwFirstArg += m_pMaxPEFile->m_stPEOffsets.NoOfDataDirs;//Pioneer Case
			}
			if(!m_pMaxPEFile->WriteBuffer(&dwSecArg, dwFirstArg, 0x4, 0x4))
				return false;
		}
		break;
		//Tushar ==> 11 Jan 2011 : Added by Yash and Code Analyzed by Rupali
	case 6://Added for Agent.A & VB.F can be used for other viruses (DWORD XOR Constant Value)
		{
			if(!m_dwSizeofBuff)
			{
				return false;
			}
			for(DWORD i = 0x00; i < m_dwSizeofBuff; i++ )
			{
				m_byReadBuffer[i] ^= dwSecArg;
			}
			m_dwReturnValues[0] = m_dwSizeofBuff - 26;
		}
		break;
		//Tushar ==> 11 Jan 2011 : Added by Yash and Code Analyzed by Rupali
	case 7://BYTE XOR Variable Value (Read from Location dwSecArg)(Three Virus)
		{	
			BYTE byKey = 0x00;
			m_pMaxPEFile->ReadBuffer(&byKey, dwSecArg, 1);
			if(!m_dwSizeofBuff)
			{
				return false;
			}
			for(int i=0;i<=3;i++)
			{
				m_byReadBuffer[i]=m_byReadBuffer[i]^byKey;
			}
			DWORD dwOAEP = *(DWORD*)m_byReadBuffer;
			m_dwReturnValues[0] = dwOAEP;
		}
		break;
		// Added by Rupali on 7 Feb 2011. Added Decryption routine for W32.Savior.
	case SAVIOR_DECRYPTION:
		DecryptionSavior(dwFirstArg);
		break;	
		// End 
	case 9: //Tushar ==> 21 Feb 2011 : Changes for Nimnul Varient
		{
			DWORD dwAEP=0,dwEBP=0,dwEAX=0;
			dwAEP = m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint + m_pMaxPEFile->m_stPEHeader.ImageBase;
			dwEBP=(dwAEP+0x6)-(dwFirstArg);
			dwEBP+=(dwSecArg);

			if(!m_pMaxPEFile->ReadBuffer(&dwEAX, GetMappedAddress(dwEBP-m_pMaxPEFile->m_stPEHeader.ImageBase), sizeof(DWORD)))
			{
				return false;
			}

			dwAEP=dwAEP-dwEAX;
			dwAEP-=m_pMaxPEFile->m_stPEHeader.ImageBase;
			m_dwReturnValues[0]=dwAEP;
		}
		break;
		// Added by Rupali on 3 Mar 2011. Added repair for virus Adson.1703 by Neeraj.
	case ADSON_1703_DECRYPTION:
		{
			__int64 dwMulResult = (__int64)dwFirstArg * (__int64)dwSecArg;
			m_dwReturnValues[0] = (dwMulResult/0x100000000) - m_pMaxPEFile->m_stPEHeader.ImageBase + 0x01;
		}
		break;
		// Added repair for virus Magic.1590 by Ajay.
	case MAGIC_1590_DECRYPTION:
		{
			DWORD dwEAX=0, dwECX=0, dwBytesRead=0;

			m_pMaxPEFile->ReadBuffer(&dwEAX, m_dwAEPMapped + 6, 1);

			BYTE *byValEAX;
			WORD *wValECX, *wValEAX;
			DWORD dwCounter = dwECX = m_dwArgs[0], dwVal=0;
			for(DWORD dwCnt = 0; dwCnt < dwCounter; dwCnt++)   //	 3 actions to perform
			{
				// byte ^= AL
				byValEAX			=(BYTE *)&dwEAX; 
				m_byReadBuffer[dwCnt] ^= byValEAX[0];  //bytes are stored in reverse order   

				// AX += CX
				wValEAX				=(WORD *)&dwEAX;
				wValECX				=(WORD *)&dwECX;
				wValEAX[0] 			= wValEAX[0] + wValECX[0]; 	
				dwEAX				= wValEAX[0];

				//CX--
				dwECX--;
			}

			if(m_dwArgs[1] !=0) //  For Magic.1922
			{ 
				if(dwEAX & 1)
				{
					dwEAX -= LOBYTE(dwEAX);
				}
				dwEAX += m_byReadBuffer[0x1] + m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint;
				dwECX = *(DWORD *)&m_byReadBuffer[0x9];
				for(DWORD dwCnt = 0; dwCnt < 0x1C7; dwCnt++)   //	To obtain 2nd Decrption keys
				{					
					wValEAX				=(WORD *)&dwEAX;
					wValECX				=(WORD *)&dwECX;
					wValEAX[0] 			= wValEAX[0] + wValECX[0]; 	
					dwEAX				= wValEAX[0];
					dwECX--;
				}
				for(int j = 0x1F6; j <0x1FA; j++)
				{
					m_byReadBuffer[j]  ^= LOBYTE(dwEAX);
					wValEAX				= (WORD *)&dwEAX;
					wValECX				= (WORD *)&dwECX;
					wValEAX[0] 			=  wValEAX[0] + wValECX[0]; 	
					dwEAX				=  wValEAX[0];
					dwECX--;
				}
				dwVal = *(DWORD *)&m_byReadBuffer[0x1F6];
			}
			else //For Magic.1590
			{
				DWORD dwMul=1;
				for(int j = 0x1C7; j <= 0x1CA; j++, dwMul *= 0x100)
				{
					dwVal += m_byReadBuffer[j] * dwMul;
				}
			}
			m_dwReturnValues[0] = m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint + dwVal;
		}
		break;
		// Added by Rupali on 30 Mar 2011. Added repair for virus Agent.CX by Rohan.
	case AGENT_CX_DECRYPTION:
		{
			DWORD dwBytesTobeRead	= m_dwSizeofBuff - 6;
			DWORD dwInterimDecKey	= dwFirstArg;
			DWORD dwShiftCount		= (dwSecArg - 0x19cd + 3) % 0x20;
			dwInterimDecKey			= _rotr(dwInterimDecKey, dwShiftCount);

			for(DWORD dwOffset = 0; dwOffset < dwBytesTobeRead + 0x3; dwOffset++)
			{
				*((DWORD*)(&m_byReadBuffer[dwOffset])) ^= dwInterimDecKey;
				dwInterimDecKey = _rotl(dwInterimDecKey, 1);
			}

			BYTE *byTemp	= m_byReadBuffer;
			m_byReadBuffer	= &m_byReadBuffer[0x3];

			m_dwArgs[0] = m_dwAEPMapped;
			m_dwArgs[1] = dwBytesTobeRead;

			m_bInternalCall = true;
			bRet = ReplaceDataInReadBuffer();
			m_bInternalCall = false;
			m_byReadBuffer = byTemp;
		}
		break;
		// End
		// Added by Rupali on 1 Apr 2011. Added repair for virus Qudos by Yash.
	case QUDOS_DECRYPTION:
		{
			BYTE byBL=0x00;
			for(DWORD dwOffset = 0; dwOffset < m_dwSizeofBuff; dwOffset++)
			{
				byBL = m_byReadBuffer[dwOffset];
				byBL = byBL ^ LOBYTE(dwFirstArg);
				m_byReadBuffer[dwOffset] = byBL;
				dwFirstArg = _lrotl(dwFirstArg, 8);
				dwFirstArg ^= dwSecArg;
				dwFirstArg = ~dwFirstArg;
				dwSecArg--;
			}
			m_dwReturnValues[0]=(*(DWORD *)(m_byReadBuffer + 0x190));
		}
		break;
		// End
		// Added by Rupali on 7 Apr 11. Added decryption for Adson.1559 by Neeraj.
	case ADSON_1559_DECRYPTION:
		{
			DWORD dwBytesRead = 0, dwAEPFirstPart = 0;
			if(dwSecArg > dwFirstArg)
			{
				dwAEPFirstPart = dwSecArg / 0x10000; //HIWORD
			}
			else
			{
				if(!m_pMaxPEFile->ReadBuffer(&dwAEPFirstPart, m_dwAEPMapped + 0x5E3, sizeof(DWORD), sizeof(DWORD)))
				{
					return false;
				}
				__int64 dwMulResult = (__int64)dwFirstArg * (__int64)dwAEPFirstPart; //Multiply by key
				dwAEPFirstPart = (dwMulResult / 0x1000000000000); //HIWORD of HIDWORD
			}

			DWORD dwAEPSecondPart = 0; 
			if(!m_pMaxPEFile->ReadBuffer(&dwAEPSecondPart, m_dwAEPMapped + 0x5EB, sizeof(DWORD), sizeof(DWORD)))
			{
				return false;
			}
			dwAEPSecondPart = dwAEPSecondPart * dwFirstArg;

			DWORD dwAEPThirdPart = 0;
			if(!m_pMaxPEFile->ReadBuffer(&dwAEPThirdPart, m_dwAEPMapped + 0x5E7, sizeof(DWORD), sizeof(DWORD)))
			{
				return false;
			}
			dwAEPThirdPart = (dwAEPThirdPart + dwAEPSecondPart) * 0x10000; //LOWWORD for ImageBase & part of AEP
			m_dwReturnValues[0] = dwAEPThirdPart + dwAEPFirstPart - m_pMaxPEFile->m_stPEHeader.ImageBase;
		}
		break;
		// Added by Rupali on 7 Apr 11. Added decryption for Oroch.5420 by Yash.
	case OROCH_DECRYPTION:
		bRet = DecryptionOroch5420();
		break;

		// Added by Rupali on 14 Apr 11. Added decryption for virus Sadon.900 by Neeraj
	case DECRYPTION_SADON_900:
		{
			WORD wKey = LOWORD(dwFirstArg);
			BYTE bKey = LOBYTE(wKey);
			for(int i =0; i < 0x5; i++)
			{
				m_byReadBuffer[i] ^= bKey;
				bKey += HIBYTE(wKey);
			}
			m_dwReturnValues[0] = *(DWORD *)&m_byReadBuffer[1];
			if(!m_dwReturnValues[0])
				bRet = false;
		}
		break;
		// End
		// Added by Rupali on 20 Apr 11. Added decryption for virus Bartel by Omkar
	case DECRYPTION_BARTEL:
		bRet = Decryption_Bartel(dwFirstArg, dwSecArg);
		break;
		// End
		// Added by Rupali on 25 Apr 11. Added decryption for virus Artelad by Prajkta
	case DECRYPTION_ARTELAD_2173:
		bRet = Decryption_Artelad_2173(dwFirstArg, dwSecArg);
		break;
		// End
		// Added by Rupali on 28 Apr 11. Added decryption for virus Lamewin by Ravi.
	case DECRYPTION_LAMEWIN:
		bRet = Decryption_Lamewin();
		break;
		// End
		// Added by Rupali on 30 Apr 11. Added decryption for virus Killis by Adnan.
	case DECRYPTION_KILLIS:
		bRet = Decryption_Killis();
		break;
		// End
		// Added by Rupali on 7 May 11. Added decryption for virus Rainsong by Ajay.
	case DECRYPTION_RAINSONG:
		bRet = Decryption_RainSong();
		break;
		// End
	case DECRYPTION_ALISAR:
		bRet = Decryption_Alisar(dwFirstArg);
		break;
	case DECRYPTION_ROSEC:
		bRet = DecryptionRosec();
		break;
	case DECRYPTION_TUPAC:
		bRet = DecryptionTupac();
		break;
	case DECRYPTION_CABANAS:
		{
			int iRotateCount = 5;
			for(DWORD dwOffset = 0; dwOffset < m_dwSizeofBuff; dwOffset++, iRotateCount--)
			{
				m_byReadBuffer[dwOffset] ^= (BYTE)m_dwArgs[1];
				m_byReadBuffer[dwOffset] = m_byReadBuffer[dwOffset] << iRotateCount | m_byReadBuffer[dwOffset] >> (8 - iRotateCount);
			}
		}
		break;
	case DECRYPTION_TANK:
		{
			BYTE bKey = (BYTE)m_dwArgs[3], bTemp = 0;
			for(int i = 0; i < m_dwArgs[1]; i++)
			{
				if(i != 0)
				{	
					bTemp = bKey & 0x80;
					bKey = _lrotl(bKey, m_dwArgs[4]);
					if(bTemp)
					{
						bKey = bKey + 1;
					}
				}
				m_byReadBuffer[i] ^= bKey;
			}			
			m_pMaxPEFile->WriteBuffer(m_byReadBuffer, m_dwArgs[0], m_dwArgs[1]);	
		}
		break;
	case DECRYPTION_EVAR:
		{			
			if(m_dwArgs[0] != 0)	// Evar.3587
			{
				m_dwReturnValues[0] = _lrotl(m_dwArgs[0], (BYTE)m_dwArgs[1]);
			}
			else  // Evar.3582
			{
				for(DWORD i = 0; i < 8; i += 4)
				{
					*(DWORD*)&m_byReadBuffer[i] = _lrotl(*(DWORD*)&m_byReadBuffer[i], (BYTE)m_dwArgs[1]);
				}
				m_dwReturnValues[0] = *(DWORD*)&m_byReadBuffer[0x3];
			}
		}
		break;
	case DECRYPTION_DICTATOR: 
		{	
			DWORD dwNewKey = (dwSecArg * 81)+ dwFirstArg;
			for(int i = 0; i < 8; i += 4)
			{   
				*(DWORD *)&m_byReadBuffer[i] ^= dwNewKey;
				dwNewKey += dwSecArg;
			}
			m_dwReturnValues[0] = *(DWORD*)&m_byReadBuffer[2]- m_pMaxPEFile->m_stPEHeader.ImageBase;
		}
		break;
	case DECRYPTION_ADSON_1734:
		DecryptionAdson1734();
		break;
	case DECRYPTION_RAMDILE:
		bRet = DecryptionRamdile();		
		break;
	case DECRYPTION_IH6:
		{
			DWORD *pBuffer = (DWORD *)m_byReadBuffer;
			DWORD dwKey = _lrotr(m_dwArgs[0], (BYTE)m_dwArgs[1]);
			for(int i = 0; i < 2; i++)
			{
				pBuffer[i] += dwKey;
				dwKey = _lrotr(dwKey, 1);
			}
			m_dwReturnValues[0] = *(DWORD *)&m_byReadBuffer[2];
		}
		break;
	case DECRYPTION_YAZ_A:
		{
			for(int i = 0; i <= 0x4C; i += 4)
			{
				*((DWORD *)&m_byReadBuffer[i]) -= m_dwArgs[1];
			}
			m_pMaxPEFile->WriteBuffer(&m_byReadBuffer[0x3], m_dwAEPMapped, 0x4C);		
		}
		break;
	case DECRYPTION_ESTATIC:			
		{
			BYTE dwOffset = m_byReadBuffer[m_dwArgs[1]];
			for(DWORD i = 0; i < m_dwArgs[1]; i += dwOffset)
			{
				m_byReadBuffer[i] ^= LOBYTE(i+1);							
			}
			m_pMaxPEFile->WriteBuffer(m_byReadBuffer, m_dwArgs[0], m_dwArgs[1]);	
		}
		break;
	case DECRYPTION_GODOG:
		{
			for(DWORD i=0;i<8;i=i+4)
			{
				*(DWORD *)&m_byReadBuffer[i] = _lrotl((*(DWORD *)&m_byReadBuffer[i] - 1), (BYTE)m_dwArgs[1]);
			}
			m_dwReturnValues[0] = *(DWORD *)&m_byReadBuffer[3];
		}
		break;
	case DECRYPTION_SMALL_2602:
		{
			if(dwFirstArg==0x1)
			{
				(*(DWORD*)&m_byReadBuffer[0])++;
				(*(DWORD*)&m_byReadBuffer[4])++;
			}
			*(DWORD*)&m_byReadBuffer[0] ^=dwSecArg;
			*(DWORD*)&m_byReadBuffer[4] ^=dwSecArg;

			if(dwFirstArg==0x0)
			{
				(*(DWORD*)&m_byReadBuffer[0])--;
				(*(DWORD*)&m_byReadBuffer[4])--;
			}
			m_dwReturnValues[0] = *(DWORD *)&m_byReadBuffer[1];
		}
		break;
	case DECRYPTION_DELF_DJ:
		{
			for(DWORD i = 1; i < 0x3E8; i++)
			{
				m_byReadBuffer[i - 1] ^=  (0x17 + i);
			}
			if(m_byReadBuffer[0] != 0x4D)
			{
				return RepairDelete();
			}
			m_pMaxPEFile->WriteBuffer(m_byReadBuffer, m_dwArgs[0], m_dwArgs[1]);
		}
		break;
	case DECRYPTION_POSITON_4668:
		{
			for(BYTE i = 0; i < 4; i++)
			{
				m_byReadBuffer[i] += 0x4;
				m_byReadBuffer[i] = ~m_byReadBuffer[i];

				//Performing Rotate Left by 6 bits
				WORD wShiftLeft = BYTE(m_byReadBuffer[i]);
				wShiftLeft = _rotl(wShiftLeft, 6);
				m_byReadBuffer[i] = (LOBYTE(wShiftLeft)|HIBYTE(wShiftLeft));

				m_byReadBuffer[i] -= 0x1;
				m_byReadBuffer[i] = ~m_byReadBuffer[i];
				m_byReadBuffer[i] ^= dwFirstArg;
			}
			m_dwReturnValues[0] = *(DWORD *)&m_byReadBuffer[0];
			break;
		}
	case DECRYPTION_XOR:
		{
			if(m_dwArgs[4] == 0)
			{
				for(DWORD i = 0; i < m_dwArgs[0]; i = i + 4)
				{
					*(DWORD*)&m_byReadBuffer[i] ^= m_dwArgs[1];
				}
			}
			else if(m_dwArgs[4] == 0x1)
			{
				BYTE bDecKey = (BYTE)m_dwArgs[1];
				for(DWORD i = 0; i < m_dwArgs[0]; i++)
				{
					m_byReadBuffer[i] ^= bDecKey--;
				}
			}

			m_dwReturnValues[0] = *(DWORD *)&m_byReadBuffer[m_dwArgs[3]];
			break;
		}
	case DECRYPTION_MOCKODER_1120:
		{
			*(DWORD *)&m_byReadBuffer[0] = ~(*(DWORD *)&m_byReadBuffer[0]);
			m_dwArgs[1] -= 1;//Counter I have taken it as usual
			*(DWORD *)&m_byReadBuffer[0] = ((*(DWORD *)&m_byReadBuffer[0]<< BYTE(m_dwArgs[1])) | (*(DWORD *)&m_byReadBuffer[0] >> (32 - BYTE(m_dwArgs[1]))));
			*(DWORD *)&m_byReadBuffer[0] ^= m_dwArgs[0];
			m_dwReturnValues[0] = *(DWORD *)&m_byReadBuffer[0];
			break;
		}
	case DECRYPT_PATCHED_MD:
		{
			DWORD dwAEPOffset = 0,dwKey = 0;
			
			if(m_pMaxPEFile->ReadBuffer(&dwAEPOffset, m_dwAEPMapped + 0x14, sizeof(DWORD), sizeof(DWORD)))
			{
				dwKey = _lrotl(dwSecArg, 0x9);
				for(DWORD i = 4; i > 0; i--)
				{					 
					 m_byReadBuffer[i - 1] ^= (BYTE)dwKey;
					 dwKey = _lrotl(dwKey, 1);
				}
				if(dwAEPOffset - *(DWORD *)&m_byReadBuffer[0] < m_dwFileSize)
				{					
					if(m_pMaxPEFile->WriteAEP(dwAEPOffset - *(DWORD *)&m_byReadBuffer[0]))
					{
						if(dwAEPOffset == m_pSectionHeader[m_wNoOfSecs - 1].VirtualAddress)
						{
							if(m_pMaxPEFile->RemoveLastSections(1, true))
							{
								m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, 0x4A);
								return true;
							}
						}
					}
				}
				else
				{
					if(m_pMaxPEFile->ReadBuffer(&dwKey, m_dwAEPMapped + 0x31, sizeof(DWORD), sizeof(DWORD)))
					{
						if(m_pMaxPEFile->WriteAEP((dwKey ^ dwSecArg)))
						{
							if(dwAEPOffset == m_pSectionHeader[m_wNoOfSecs - 1].VirtualAddress)
							{
								if(m_pMaxPEFile->RemoveLastSections(1, true))
								{
									m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, 0x4A);
									return true;
								}
							}
						}						
					}					
				}				
			}
		}
		break;
	case DECRYPTION_PARVO:
		{
			BYTE byROLCnt = 4;
			for(int i = 1; i <= 0x100; i++)
			{
				m_byReadBuffer[i - 1] = ~(m_byReadBuffer[i - 1]);
				DWORD dwRotateCounter = byROLCnt % 0x08;
				m_byReadBuffer[i - 1] = m_byReadBuffer[i - 1] << dwRotateCounter | m_byReadBuffer[i - 1] >> (0x08 - dwRotateCounter);
			}
			m_pMaxPEFile->WriteBuffer(m_byReadBuffer,  m_dwArgs[0], m_dwArgs[1]);
		}
		break;
	case DECRYPTION_PRIEST:
		{
			DWORD dwKey = m_dwArgs[0], wTemp = 0;
			// Calculate key
			for(int j = 0; j < 2; j++)
			{
				wTemp = LOWORD(dwKey);		//extracted AX
				wTemp = (wTemp & 0xFF) << 8 | (wTemp >> 8); //exchange AH and AL
				dwKey &= 0xFFFF0000;
				dwKey |= wTemp;
				dwKey = _lrotr(dwKey,0x01);
			}
			// Decryption
			for(int i = 0; i < 3; i++)
			{
				*(DWORD *)&m_byReadBuffer[i] ^= dwKey;

				wTemp = LOWORD(dwKey);
				wTemp = (wTemp & 0xFF) << 8 | (wTemp >> 8);
				dwKey &= 0xFFFF0000;
				dwKey |= wTemp;
				dwKey = _lrotr(dwKey,0x01);
			}
			m_dwReturnValues[0] = *(DWORD *)&m_byReadBuffer[3];
		}
		break;
	case DECRYPTION_WORD_XOR:
		{
			WORD wXorKey = m_dwArgs[0];
			for(int i = 0; i < m_dwSizeofBuff;  i = i + 2)
			{
				*(WORD *)&m_byReadBuffer[i] ^= wXorKey;
				if(m_dwArgs[4]) // Lamer.FM: XOR->ADD->ROL
				{
					*(WORD*)&m_byReadBuffer[i] += m_dwArgs[4];
				}
				if(m_dwArgs[3])	// Lamer.FN: XOR->ROL
				{
					*(WORD *)&m_byReadBuffer[i] = (*(WORD *)&m_byReadBuffer[i] << m_dwArgs[3])|(*(WORD *)&m_byReadBuffer[i] >> (16 - m_dwArgs[3]));
				}
			}
			m_dwReturnValues[0] = *(DWORD *)&m_byReadBuffer[0];
			m_dwReturnValues[1] = m_byReadBuffer[m_dwArgs[1]];
		}
		break;
	case DECRYPTION_MATRIX_3597:
		{
			DWORD dwMOVKey = m_dwArgs[0];
			DWORD dwSUBKey = m_dwArgs[1];
			DWORD dwADDKey = 0, dwSUBKey1 = 0;
						
			dwADDKey = *(DWORD *)&m_byReadBuffer[0x0];
			dwSUBKey1 = *(DWORD *)&m_byReadBuffer[0xC];
			dwMOVKey -= dwSUBKey;
			for(DWORD i = 0x1C0; i < m_dwSizeofBuff;  i=i+4)
			{
				*(DWORD *)&m_byReadBuffer[i] -= 1;
				*(DWORD *)&m_byReadBuffer[i] += dwADDKey;
				*(DWORD *)&m_byReadBuffer[i] -= dwSUBKey1;
				*(DWORD *)&m_byReadBuffer[i] += 1;
				*(DWORD *)&m_byReadBuffer[i] ^= dwMOVKey;
			}
			m_pMaxPEFile->WriteBuffer(&m_byReadBuffer[0x1C3], m_dwAEPMapped , 0xD);
		}
		break;
	case DECRYPTION_PIONEER_BG:
		{
			DWORD dwOffset = *(DWORD *)&m_byReadBuffer[0x0] - dwFirstArg, dwTemp = 0;
			if(m_pMaxPEFile->ReadBuffer(&dwTemp, (dwOffset - 4), 0x4, 0x4))
			{
				DWORD dwOriGinalAEP = dwTemp >> 0x10;
				dwOffset = *(DWORD *)&m_byReadBuffer[0x4] - dwFirstArg;
				if(m_pMaxPEFile->ReadBuffer(&dwTemp,(dwOffset - 4),0x4,0x4))
				{
					dwOriGinalAEP = dwOriGinalAEP + ((dwTemp << 0x10) >> 0x10);
					m_dwReturnValues[0] = dwOriGinalAEP;
				}
			}
		}
		break;
	case DECRYPTION_LAMER_ER:
		{
			for(int i = 0; i < m_dwSizeofBuff; i ++)
			{
				if(m_byReadBuffer[i] != 0x00 && m_byReadBuffer[i] != m_dwArgs[1])
				{
					m_byReadBuffer[i] ^= m_dwArgs[1];
				}
			}	
		}
		break;
	/*case DECRYPTION_LAMER_EL:
		DecryptionLamerEL();
		break;*/
	case DECRYPTION_NEG:
		{
			if(m_dwArgs[4] == 0)
			{
				for(DWORD i = 0; i < m_dwArgs[0]; i = i + 2)
				{
					*(WORD*)&m_byReadBuffer[i] = 0 - *(WORD *)&m_byReadBuffer[i];
					if(m_dwArgs[3])
					{
						*(WORD*)&m_byReadBuffer[i] += m_dwArgs[3];
						*(WORD *)&m_byReadBuffer[i] = (*(WORD *)&m_byReadBuffer[i] << m_dwArgs[4])|(*(WORD *)&m_byReadBuffer[i] >> (16 - m_dwArgs[4]));
					}
				}
			}
			else if(m_dwArgs[4] == 1)
			{
				for(DWORD i = 0; i < m_dwArgs[0]; i = i + 4)
				{
					*(DWORD*)&m_byReadBuffer[i] = 0 - *(DWORD *)&m_byReadBuffer[i];					
				}
			}			
			m_dwReturnValues[0] = *(DWORD *)&m_byReadBuffer[m_dwArgs[1]];
			m_dwReturnValues[1] = m_byReadBuffer[0];
			break;
		}
	case DECRYPTION_KINO:
		{
			m_dwReturnValues[0] = (m_dwArgs[0] << m_dwArgs[1]) | (m_dwArgs[0] >> (32 - m_dwArgs[1]));	// ROL DWORD		
			m_dwReturnValues[0] = ntohl(m_dwReturnValues[0]); //BSWAP
		}
		break;
	case DECRYPTION_ZOMBIE:
		{
			for(int i = 0; i < m_dwSizeofBuff;  i=i+4)
			{
				*(DWORD *)&m_byReadBuffer[i] = ~(*(DWORD *)&m_byReadBuffer[i]);
				*(DWORD *)&m_byReadBuffer[i]+= 1;
				*(DWORD *)&m_byReadBuffer[i] ^= m_dwArgs[1];
			}
			m_dwReturnValues[0] = *(DWORD *)&m_byReadBuffer[0x3];
		}
		break;
	case DECRYPTION_CABRES:
		{
			bRet = DecryptionCabres();
			break;
		}	
	case DECRYPTION_ILMX:
		{
			DWORD dwDecOff = m_dwArgs[0];
			BYTE bXORKey = m_dwArgs[1];
			const int ILMX1291_BUFF_SIZE = 0x30;
			m_byReadBuffer = new BYTE [ILMX1291_BUFF_SIZE]; 
			m_pMaxPEFile->Rva2FileOffset(dwDecOff,&dwDecOff);
			if(dwDecOff == 0x0 || dwDecOff > m_dwFileSize)
			{
				return RepairDelete();
			}
			if(!m_pMaxPEFile->ReadBuffer(&m_byReadBuffer[0x0],dwDecOff + 0x118,sizeof(DWORD),sizeof(DWORD)))
			{
				return false;
			}
			if(!m_pMaxPEFile->ReadBuffer(&m_byReadBuffer[0x4],dwDecOff + 0x4E0,0x2B,0x2B))
			{
				return false;
			}
			for(int i = 0; i < ILMX1291_BUFF_SIZE;  i++)
			{
				m_byReadBuffer[i] ^= bXORKey;
			}
			m_dwReturnValues[0] = *(DWORD *)&m_byReadBuffer[0x0] - m_pMaxPEFile->m_stPEHeader.ImageBase;
			m_pMaxPEFile->WriteBuffer(&m_byReadBuffer[0x4],m_dwAEPMapped,0x2B,0x2B);
		}
		break;
	case DECRYPTION_FABI:
		{
			DWORD key = dwFirstArg + dwSecArg;
			for(int i = 0; i< m_dwSizeofBuff; i+=4)
			{
			 *(DWORD *)m_byReadBuffer[i] ^= key;
			 key+=dwSecArg;
	                }
			m_dwReturnValues[0] = m_byReadBuffer[0x2];
		}
		break;
	case DECRYPTION_CRYTEX1290:
		{
			DWORD dwEDX = m_dwArgs[0],dwEAX = 0x0, dwEBX = 0x7FFFFFFF;
			DWORD dwMultVal = 0x10DCD, dwAddVal = 0x116C5;
			for(DWORD i = 0x0; i < m_dwSizeofBuff; i += 0x4)
			{
				dwEAX = dwEDX * dwMultVal;
				dwEAX += dwAddVal;
				dwEDX = dwEAX % dwEBX;
				*(DWORD *)&m_byReadBuffer[i] ^= dwEDX;
			}
			m_dwReturnValues[0] = *(DWORD *)&m_byReadBuffer[m_dwSizeofBuff - 0x4] - m_pMaxPEFile->m_stPEHeader.ImageBase;
		}
		break;
	case DECRYPTION_LAMERHB:
		{
			for(int i = 0; i < m_dwSizeofBuff; i = i+4)
			{
				*(DWORD *)&m_byReadBuffer[i] += m_dwArgs[1];
			}
		}
		m_dwReturnValues[0]= *(DWORD *)&m_byReadBuffer[0x1];
		break;
	default:
		break;
	}
	return bRet;
}

/*-------------------------------------------------------------------------------------
Function		: DecryptionSalityFloatXOR
In Parameters	: DWORD dwDecryptionKey, DWORD dwDecryptionLength, DWORD dwDecryptionOffset
Out Parameters	: bool
Purpose			: Decrypts the buffer specifically for Sality variant virus
Author			: Tushar Kadam
m_dwDecryptionLength: Setting value of m_dwDecryptionLength to 0x1000 instead of m_dwArgs[1]
as cleanning was failing if the SRD of section is less than m_dwArgs[1].
Use m_dwArgs[1] as counter.
--------------------------------------------------------------------------------------*/
bool CRepairModuls::DecryptionSalityFloatXOR()
{
	if(!m_bInternalCall)
	{
		if(!GetParameters())
		{
			return false;
		}
	}
	m_dwArgs[3]=GetMappedAddress(m_dwSaveArgs[0]+ m_dwArgs[3]);
	if(m_dwArgs[3] == 0xffffffff)  
	{
		return RepairDelete();	
	}

	m_dwStartofDecryption = m_dwArgs[2]; 
	m_dwDecryptionLength = 0x1000;


	if(m_dwDecryptionLength > m_dwFileSize)
	{
		return RepairDelete();	
	}
	
	if(m_byReadBuffer)
	{
		delete [] m_byReadBuffer;
		m_byReadBuffer = NULL;
	}
	m_byReadBuffer = new BYTE[m_dwDecryptionLength];
	memset(m_byReadBuffer, 0, m_dwDecryptionLength);

	if(!m_pMaxPEFile->ReadBuffer(m_byReadBuffer, m_dwStartofDecryption, m_dwDecryptionLength, m_dwDecryptionLength))
	{
		if(m_dwStartofDecryption == 0xFFFFFFFF || m_dwStartofDecryption + m_dwDecryptionLength >= m_dwFileSize)
		{
			return RepairDelete();		
		}
		return false;
	}

	WORD wKey = (WORD)m_dwArgs[0];
	DWORD_PTR dwTemp = 0;
	DWORD_PTR dwCounter = (m_dwArgs[1] / 2);
	
	for(DWORD i = 0; i < m_dwDecryptionLength / 2; i += 2, dwCounter--)
	{
		dwTemp = wKey * dwCounter;
		dwTemp -=(dwCounter * 2);
		*((WORD *)&m_byReadBuffer[i])^=(WORD)dwTemp;
	}	
	return true;
}

// Modified by Rupali on 24 Mar 11. Changes by Manjunath.
/*-------------------------------------------------------------------------------------
Function		: RepairHidragA
In Parameters	: -
Out Parameters	: bool
Purpose			: Repair for Hidrag.A virus 
Author			: Vilas Suvarnakar
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairHidragA()
{
	DWORD dwEndOfLastSec = m_pSectionHeader[m_wNoOfSecs-1].PointerToRawData + m_pSectionHeader[m_wNoOfSecs-1].SizeOfRawData;
	if((m_dwFileSize > 0x8CA0 && m_dwFileSize <= 0x8E00) || dwEndOfLastSec >= m_dwFileSize)
	{
		return RepairDelete();
	}

	DWORD dwResPRD = 0; 
	if(!m_pMaxPEFile->ReadBuffer(&dwResPRD, 0x7C0C, sizeof(DWORD), sizeof(DWORD)))
	{
		return (false);
	}
	DWORD dwResRva = 0;
	if(!m_pMaxPEFile->ReadBuffer(&dwResRva, 0x7C0C + 4, sizeof(DWORD), sizeof(DWORD)))
	{
		return (false);
	}

	//Read data for decryption
	DWORD	dwDecLength, dwDecStartOffset;
	DWORD dwTmpDecStartOffset = m_dwFileSize - dwEndOfLastSec - 0x400;
	if(dwTmpDecStartOffset > m_pMaxPEFile->m_dwFileSize)
	{
		return RepairDelete();
	}
	
	if(dwEndOfLastSec < dwTmpDecStartOffset)
	{
		dwDecStartOffset = dwTmpDecStartOffset;
		dwDecLength = dwEndOfLastSec;
	}
	else
	{
		dwDecLength = dwTmpDecStartOffset;
		dwDecStartOffset = dwEndOfLastSec;
	}
	
	BYTE *pStartHeader = new BYTE[dwDecLength];
	if(NULL == pStartHeader)
	{
		return false;
	}

	if(!m_pMaxPEFile->ReadBuffer(pStartHeader, dwDecStartOffset, dwDecLength, dwDecLength))
	{
		if(pStartHeader)
		{
			delete []pStartHeader;
			pStartHeader = NULL;
		}
		return RepairDelete();
	}

	for(DWORD dwOffset = 0; dwOffset < dwDecLength; dwOffset++)
	{
		pStartHeader[dwOffset] -= LOBYTE(dwOffset);
	}

	if(*((WORD* )&pStartHeader[0] ) != 0x5A4D)
	{
		//Delete File
		if(pStartHeader)
		{
			delete []pStartHeader;
			pStartHeader = NULL;
		}
		return RepairDelete();
	}

	//Code to fix the carsh, bcz of corrupt/big PRD and RVA in location 0x7C0C from start of the file.
	IMAGE_SECTION_HEADER LastSectionHeader;
	bool bSecHeaderOutOfStartHeader = false;
	if(!GetLastSectionInfo(&pStartHeader[0], dwDecLength, &LastSectionHeader, bSecHeaderOutOfStartHeader))
	{
		if(pStartHeader)
		{
			delete []pStartHeader;
			pStartHeader = NULL;
		}
		return false;
	}
	if(!bSecHeaderOutOfStartHeader && ((dwResPRD > LastSectionHeader.PointerToRawData) || (dwResRva > LastSectionHeader.VirtualAddress)))
	{
		//Delete File
		if(pStartHeader)
		{
			delete []pStartHeader;
			pStartHeader = NULL;
		}
		return RepairDelete();
	}
	
	//Read resource. Hidrag always infects the file with resource section
	if(!m_pMaxPEFile->m_stPEHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress)
	{
		if(pStartHeader)
		{
			delete []pStartHeader;
			pStartHeader = NULL;
		}
		return false;
	}
	
	DWORD dwInfResSecStart = 0x00, dwInfResVA, dwInfResSize = 0;
	WORD wSecNo, wResSecNo = 0;
	//Resource section not always be the last section
	if(m_pMaxPEFile->m_stPEHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress != m_pSectionHeader[m_wNoOfSecs-1].VirtualAddress)
	{
		dwInfResVA = m_pMaxPEFile->m_stPEHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
		dwInfResSecStart = GetMappedAddress(dwInfResVA);
		if(dwInfResSecStart <= 0x0)
		{
			if(pStartHeader)
			{
				delete []pStartHeader;
				pStartHeader = NULL;
			}
			return false;
		}

		for(wSecNo = 0; wSecNo < m_wNoOfSecs; wSecNo++)
		{
			if(m_pSectionHeader[wSecNo].VirtualAddress >= dwInfResVA)
				break;
		}

		if(wSecNo >= m_wNoOfSecs)
		{
			if(pStartHeader)
			{
				delete []pStartHeader;
				pStartHeader = NULL;
			}
			return false;
		}
		dwInfResSecStart =  m_pSectionHeader[wSecNo].PointerToRawData;
		dwInfResSize = m_pSectionHeader[wSecNo].SizeOfRawData;
		dwInfResVA = m_pSectionHeader[wSecNo].VirtualAddress;
		wResSecNo = wSecNo;
	}
	else
	{
		dwInfResSize = m_pSectionHeader[m_wNoOfSecs-1].SizeOfRawData;
		dwInfResSecStart = m_pSectionHeader[m_wNoOfSecs-1].PointerToRawData;
		dwInfResVA = m_pSectionHeader[m_wNoOfSecs-1].VirtualAddress;
		wResSecNo = m_wNoOfSecs-1;
	}
	//End

	BYTE *pResource = NULL;
	if(dwInfResSize)
	{
		pResource = new BYTE [dwInfResSize];
		if( NULL == pResource )
		{
			if(pStartHeader)
			{
				delete []pStartHeader;
				pStartHeader = NULL;
			}
			return (false);
		}
	
		if(!m_pMaxPEFile->ReadBuffer(pResource, dwInfResSecStart, dwInfResSize, dwInfResSize))
		{
			if(pResource)
			{
				delete []pResource;
				pResource = NULL;
			}
			if(pStartHeader)
			{
				delete []pStartHeader;
				pStartHeader = NULL;
			}
			return (false);
		}
		FiXRes((IMAGE_RESOURCE_DIRECTORY*)pResource, &pResource, (dwResRva-dwInfResVA));
	}

	if(!m_pMaxPEFile->WriteBuffer(pStartHeader, 0, dwDecLength, dwDecLength))
	{
		if(pStartHeader)
		{
			delete []pStartHeader;
			pStartHeader = NULL;
		}
		if(pResource)
		{
			delete []pResource;
			pResource = NULL;
		}
		return false;
	}
	
	if(pStartHeader)
	{
		delete []pStartHeader;
		pStartHeader = NULL;
	}

	m_pMaxPEFile->ForceTruncate(dwTmpDecStartOffset);

	//Check for overlay
	DWORD dwTmpOverlayOffset = dwTmpDecStartOffset;
	DWORD dwTmpOverlayLength = dwResPRD + m_pSectionHeader[wResSecNo].SizeOfRawData;
	
	DWORD	dwOverlayLength, dwOverlayOffset;
	if(dwTmpOverlayOffset < dwTmpOverlayLength)
	{
		dwOverlayOffset = dwTmpOverlayLength;
		dwOverlayLength = dwTmpOverlayOffset - dwResPRD;
	}
	else
	{
		dwOverlayOffset = dwTmpOverlayOffset;
		dwOverlayLength = m_pSectionHeader[wResSecNo].SizeOfRawData;
	}

	BYTE *pOverlay = NULL;
	if (dwOverlayLength > 0)
	{
		pOverlay = new BYTE [dwOverlayLength];
		if(NULL == pOverlay)
		{
			if(pResource)
			{
				delete []pResource;
				pResource = NULL;
			}
			return false;
		}

		if(!m_pMaxPEFile->ReadBuffer(pOverlay, dwResPRD, dwOverlayLength, dwOverlayLength))
		{
			if(pResource)
			{
				delete []pResource;
				pResource = NULL;
			}
			if(pOverlay)
			{
				delete []pOverlay;
				pOverlay = NULL;
			}
			return (false);
		}
	}

	//Write resource
	if(dwInfResSize)
	{
		m_pMaxPEFile->WriteBuffer(pResource, dwResPRD, dwInfResSize);
	}
	
	if(pResource)
	{
		delete []pResource;
		pResource = NULL;
	}

	//Write Overlay
	if((dwOverlayLength > 0) && pOverlay)
	{
		m_pMaxPEFile->WriteBuffer(pOverlay, dwOverlayOffset, dwOverlayLength);			
		if( pOverlay )
		{
			delete []pOverlay;
			pOverlay = NULL;
		}
	}
	return true;
}
// End

/*-------------------------------------------------------------------------------------
	Function		: GetLastSectionInfo
	In Parameters	: BYTE *pStartHeader, DWORD dwStartHeaderLen, IMAGE_SECTION_HEADER *pSection_Header, bool &bSecHeaderOutOfStartHeader
	Out Parameters	: true if success else false
	Purpose			: Exported Function
	Author			: Tushar Kadam
	Description		: collect last section header information
--------------------------------------------------------------------------------------*/
bool CRepairModuls::GetLastSectionInfo(BYTE *pStartHeader, DWORD dwStartHeaderLen, IMAGE_SECTION_HEADER *pSection_Header, bool &bSecHeaderOutOfStartHeader)
{	
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pStartHeader;
	if(pDosHeader->e_magic != 0x5A4D)
	{
		return false;
	}
	if(pDosHeader->e_lfanew > (LONG)dwStartHeaderLen) //m_pDosHeader->e_lfanew pointing out of pStartHeader buffer
	{
		bSecHeaderOutOfStartHeader = true;
		return true;
	}

	DWORD dwSignature = *(DWORD *)&pStartHeader[pDosHeader->e_lfanew];
	if(dwSignature != 0x4550 )
	{
		return false;
	}
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)&pStartHeader[pDosHeader->e_lfanew + sizeof(DWORD)];
	DWORD dwOffset = pDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pFileHeader->SizeOfOptionalHeader + (pFileHeader->NumberOfSections - 1) * IMAGE_SIZEOF_SECTION_HEADER;

	memcpy(pSection_Header, &pStartHeader[dwOffset], IMAGE_SIZEOF_SECTION_HEADER);				
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: FiXRes
In Parameters	: IMAGE_RESOURCE_DIRECTORY *dir, BYTE **root, DWORD delta
Out Parameters	: void
Purpose			: Supportive Function for Hidrag.A
Author			: Vilas Suvernakar
--------------------------------------------------------------------------------------*/
void CRepairModuls::FiXRes(IMAGE_RESOURCE_DIRECTORY *dir, BYTE **root, DWORD delta)
{
	IMAGE_RESOURCE_DIRECTORY_ENTRY *entry = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);
	for(int i = 0; i < dir->NumberOfNamedEntries + dir->NumberOfIdEntries; i++, entry++)
	{
		void *ptr = *root + entry->OffsetToDirectory;
		if (entry->DataIsDirectory) 
		{
			FiXRes( (IMAGE_RESOURCE_DIRECTORY*)ptr, root, delta);
		}
		else
		{
			IMAGE_RESOURCE_DATA_ENTRY *data = (IMAGE_RESOURCE_DATA_ENTRY*)ptr;
			if (data->OffsetToData) 
			{
				data->OffsetToData += delta;
			}
		}
	}
}

/*-------------------------------------------------------------------------------------
Function		: RepairChimeraA
In Parameters	: - 
Out Parameters	: bool
Purpose			: Repair for Chimera.A virus 
Author			: Rohit
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairChimeraA()
{
	DWORD dwKey1 = 0;
	if(!m_pMaxPEFile->ReadBuffer(&dwKey1, m_dwAEPMapped + 1, sizeof(DWORD), sizeof(DWORD)))
	{
		return false;
	}

	DWORD dwDecrytionBufferOffset = 0;
	if(!m_pMaxPEFile->ReadBuffer(&dwDecrytionBufferOffset, m_dwAEPMapped + 6, sizeof(DWORD), sizeof(DWORD)))
	{
		return false;
	}

	DWORD dwKey2 = 0;
	if(!m_pMaxPEFile->ReadBuffer(&dwKey2, m_dwAEPMapped + 11, sizeof(DWORD), sizeof(DWORD)))
	{
		return false;
	}
	
	dwDecrytionBufferOffset -= m_pSectionHeader[m_wNoOfSecs -1].VirtualAddress;
 	DWORD dwNewDecrypOffset = (m_pSectionHeader[m_wNoOfSecs -1].PointerToRawData + dwDecrytionBufferOffset) - m_pMaxPEFile->m_stPEHeader.ImageBase;

	const int CHIMERA_BUFF_SIZE = 0x1000;
	BYTE *bDecryptionBuffer = new BYTE[CHIMERA_BUFF_SIZE];
	if(NULL == bDecryptionBuffer)
	{
		return false; 
	}
	memset(bDecryptionBuffer, 0x00, CHIMERA_BUFF_SIZE);
	if(!m_pMaxPEFile->ReadBuffer(bDecryptionBuffer, dwNewDecrypOffset, CHIMERA_BUFF_SIZE, CHIMERA_BUFF_SIZE))
	{
		delete []bDecryptionBuffer;
		return RepairDelete();
	}

	// First Decryption Loop
	DWORD dwTemp = 0;
	for(DWORD dECX = 0x3F1, dwCounter = 0; dECX != 0 && dwCounter < CHIMERA_BUFF_SIZE - 4; dECX--, dwCounter += 0x04)					
	{
		dwTemp = dwKey1 % 128;
		dwKey1 = dwKey1 / 128;
		dwKey1 = dwKey1 + (dwTemp * (DWORD)pow((double)2,25));  //ror 7
		dwKey1 -= dwKey2;
		dwKey2 -= dECX;	 
		*((DWORD *)&bDecryptionBuffer[dwCounter]) ^= dwKey1;
	}

	dwKey1 = *((DWORD*)&bDecryptionBuffer[0x11]);
	dwKey2 = *((DWORD*)&bDecryptionBuffer[0x1F]);

	for(DWORD dECX = 0x3E2, dwCounter = 0x3C; dECX != 0 && dwCounter < CHIMERA_BUFF_SIZE - 4; dECX--, dwCounter += 0x04)					
	{
		dwTemp = dwKey1 % (DWORD)pow((double)2, 19);
		dwKey1 = dwKey1 / (DWORD)pow((double)2, 19);
		dwKey1 = dwKey1 + (dwTemp * (DWORD)pow((double)2, 13));
		dwKey1 += dwKey2;	 
 		dwKey2 += dECX;	 
		*((DWORD *)&bDecryptionBuffer[dwCounter]) ^= dwKey1;
	}

	if(!m_pMaxPEFile->WriteBuffer(&bDecryptionBuffer[3983], m_dwAEPMapped, 45, 45))
	{
		delete []bDecryptionBuffer;
		return false;
	}
	delete []bDecryptionBuffer;

	if(!m_pMaxPEFile->TruncateFile(dwNewDecrypOffset))
		return false;
	
	return CalculateChecksum();
}

/*-------------------------------------------------------------------------------------
Function		: RepairDownloaderBL
In Parameters	: -
Out Parameters	: bool
Purpose			: Repair for Downloader.BL virus 
Author			: Mangesh
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairDownloaderBL()
{  
	DWORD	dwPatchAddressVA = 0, dwPatchAddress = 0, dwReadOffset = m_dwAEPMapped + 0x3E;
	WORD	wPatchSize = 0;

	m_byReadBuffer = new BYTE[0x500];
	if(m_byReadBuffer == NULL)
	{
		return false;
	}
	memset(m_byReadBuffer, 0, 0x500);

	for(int iCnt = 0; iCnt < 4; iCnt++) 
	{
		// Read patched address    
		m_pMaxPEFile->ReadBuffer(&dwPatchAddressVA, dwReadOffset, sizeof(DWORD));
		dwReadOffset += 4;
		
		// Read size of patched data  
		m_pMaxPEFile->ReadBuffer(&wPatchSize, dwReadOffset, sizeof(WORD));		
		dwReadOffset += 2;
		if(0 == wPatchSize)
			break;

		// Check if size is crossing array size. If so we need to check those samples.
		if(wPatchSize + m_dwSizeofBuff > 0x500)
		{
			return false;
		}

		// Read buffer       
		dwPatchAddress = GetMappedAddress(dwPatchAddressVA);
		m_pMaxPEFile->ReadBuffer(&m_byReadBuffer[m_dwSizeofBuff], dwPatchAddress, wPatchSize);
		
		m_pMaxPEFile->FillWithZeros(dwPatchAddress, wPatchSize);
		m_dwSizeofBuff += wPatchSize;
	}

	if(m_dwSizeofBuff < 0x204)
		return false;

	// Write original data at AEP which start form 0X204 byte from end of Buffer
	m_pMaxPEFile->WriteBuffer(&m_byReadBuffer[m_dwSizeofBuff - 0x204], m_dwAEPMapped, 0x204);	
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: FixResource
In Parameters	: DWORD : Resource Type
				  DWORD : Resource ID
				  DWORD : Action to Take	
Out Parameters	: bool
Purpose			: Fixing or Cleaning Resource for the Trats and Perez Virus
Author			: Yuvraj
Modified By		: Tushar Kadam (25 Sept 2010)
--------------------------------------------------------------------------------------*/
bool CRepairModuls::FixResource()
{	
	if(!m_bInternalCall)
	{
		GetParameters();
	}

	DWORD dwResType = m_dwArgs[0]; 
	DWORD dwResID	= m_dwArgs[1]; 
	DWORD dwAction	= m_dwArgs[2];
	DWORD dwLangID	= 0x0000;
	
	DWORD dwSize = 0 , dwRVA = 0;
	int iRetVal = 0;
	switch(dwResType)
	{
	case 0 : 
		iRetVal = FindRes(_T("BIN"), LPCTSTR(&dwResID), LPCTSTR(&dwLangID), dwRVA, dwSize);
		break;
	case 1:
		iRetVal = FindRes(LPCTSTR(&dwResID), _T("PERES"), LPCTSTR(&dwLangID), dwRVA, dwSize);
		break;
	case 3:
		dwLangID = 0x0804;
		iRetVal = FindRes(_T("EXEFILE"), _T("EXEFILE"), LPCTSTR(&dwLangID), dwRVA, dwSize);
		break;
	case 4:
		dwLangID = 0x0804;
		iRetVal = FindRes(_T("EDATA"), _T("DIALOG2"), LPCTSTR(&dwLangID), dwRVA, dwSize);
		break;
	case 5:
		dwLangID = 0x0804;
		iRetVal = FindRes(_T("EXEFILE"), _T("EXE"), LPCTSTR(&dwLangID), dwRVA, dwSize);
		break;	
	case 6:
		{
			dwLangID = 0x0804;
			DWORD ID = 0x0A;
			iRetVal = FindRes(LPCTSTR(&ID), LPCTSTR(&dwResID), LPCTSTR(&dwLangID), dwRVA, dwSize);
		}
		break;
	case 10:
		iRetVal = FindRes(LPCTSTR(&dwResType), LPCTSTR(&dwResID), LPCTSTR(&dwLangID), dwRVA, dwSize);
		break;

	}
	if(!iRetVal)
	{
		return RepairDelete();	
	}
	
	DWORD dwMapAddress = GetMappedAddress(dwRVA);
	if (dwAction == 0x00)
	{
		if (dwSize < 0x64 || dwSize > m_pMaxPEFile->m_dwFileSize)
		{
			RepairDelete();
		}
		else
		{
			if(!CopyData(dwMapAddress, 0x00, dwSize))
				return false;
			if(!m_pMaxPEFile->ForceTruncate(dwSize))
				return false;
		}
	}
	else if (dwAction == 1)
	{
		if(!m_pMaxPEFile->FillWithZeros(dwMapAddress, dwSize))
			return false;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: FixResName
In Parameters	: DWORD : Resource ID
				  DWORD : Resource Type
Out Parameters	: bool
Purpose			: Fixing or Cleaning Resource Name for the Perez Virus
Author			: Tushar Kadam
--------------------------------------------------------------------------------------*/
bool CRepairModuls::FixResName()
{
	if(!m_bInternalCall)
	{
		GetParameters();
	}

	DWORD dwResID	= m_dwArgs[0];
	DWORD dwResType = m_dwArgs[1];

	DWORD dwOffset = m_pMaxPEFile->m_stPEOffsets.NoOfDataDirs + 0x14, dwBaseResAT = 0;
	if(!m_pMaxPEFile->ReadBuffer(&dwBaseResAT, dwOffset, sizeof(DWORD), sizeof(DWORD)))
		return false;

	DWORD dwBaseResATFileOffset = GetMappedAddress(dwBaseResAT);
	WORD wNoofResTypes = 0x00;

	dwOffset = dwBaseResATFileOffset + 0x0C;
	if(!m_pMaxPEFile->ReadBuffer(&wNoofResTypes, dwOffset, sizeof(WORD), sizeof(WORD)))
		return false;

	DWORD dwDummy = wNoofResTypes;
	dwOffset += sizeof(WORD);
	if(!m_pMaxPEFile->ReadBuffer(&wNoofResTypes, dwOffset ,sizeof(WORD), sizeof(WORD)))
		return false;

	wNoofResTypes += (WORD)dwDummy;
	dwOffset += sizeof(WORD);
	int i = 0;
	for(; i < (wNoofResTypes * 2); i++)
	{
		dwDummy = 0x00;
		if(!m_pMaxPEFile->ReadBuffer(&dwDummy, dwOffset, sizeof(DWORD), sizeof(DWORD)))
			return false;

		dwOffset += sizeof(DWORD);
		if (dwDummy == dwResType)
		{
			if(!m_pMaxPEFile->ReadBuffer(&dwDummy, dwOffset, sizeof(DWORD), sizeof(DWORD)))
				return false;
			break;
		}
	}

	if (i == (wNoofResTypes * 2))
		return false;

	dwDummy = dwDummy << 0x01;
	dwDummy = dwDummy >> 0x01;

	dwOffset = dwBaseResATFileOffset + dwDummy + 0x0C;

	if(!m_pMaxPEFile->ReadBuffer(&wNoofResTypes, dwOffset, sizeof(WORD), sizeof(WORD)))
		return false;
	dwDummy = wNoofResTypes;
	dwOffset += sizeof(WORD);
	if(!m_pMaxPEFile->ReadBuffer(&wNoofResTypes, dwOffset, sizeof(WORD), sizeof(WORD)))
		return false;
	wNoofResTypes += (WORD)dwDummy;

	unsigned char szResName[50] = {0};
	unsigned char szPeres[] = {0x05,0x00,0x50,0x00,0x45,0x00,0x52,0x00,0x45,0x00,0x53,0x00};
	
	dwOffset +=0x02;
	for(i=0;i<wNoofResTypes;i++)
	{
		if(!m_pMaxPEFile->ReadBuffer(&dwDummy, dwOffset, sizeof(DWORD), sizeof(DWORD)))
			return false;

		dwDummy = dwDummy << 0x01;
		dwDummy = dwDummy >> 0x01;
		dwDummy+= dwBaseResATFileOffset;

		if(!m_pMaxPEFile->ReadBuffer(szResName, dwDummy, 0x0C, 0x0C))
			return false;

		if (dwResID == 0x00)
		{
			if (memcmp(szResName,szPeres,0x0C) == 0x00)
			{
				if(m_pMaxPEFile->FillWithZeros(dwDummy, 0x0C))
				{
					return true;
				}
				break;
			}
		}
		dwOffset +=0x8;
	}
	return false;
}


// Modified by Rupali on 5 Apr 11. Function will search for a string passed throgh 
// the expression
/*-------------------------------------------------------------------------------------
Function		: Check4String
In Parameters	: None
Out Parameters	: true if search is successful else false
Purpose			: searcing for a string
Author			: Rupali
m_dwArg[0]		: Offset to start searching for a string
m_byArg			: String to search in hex format deafaut string is MZ if no string 
					is present in the expression
m_dwArg[1]		: 
0: Default case. Return offset where string matches i.e. matched string start offset
1: Skips NOPs. Return offset after matching string and skipped NOPs i.e offset of 
	instruction after matched string and immediate NOPs	
2: Push instruction offset. Return offset of Push instruction after matching the string  
3: String length. Returns legnth of the string if string is present else returns zero
4: Delete the file if string not present
5: Check the string at fixed offset if string is not present then search for MZ at offset
	sent in m_dwArg[2]
5: Check the string at fixed offset if string is present then search for MZ at offset
	sent in m_dwArg[2] otherwise use the offset sent in m_dwArg[0].
6: Check the string at fixed offset if string is not present then search for string
	at offset sent in m_dwArg[2].
7. Return true and donot reset m_dwReturnValues[0] to zero. In case of multiple 0x15 having 
   same offset different Strings.  	
--------------------------------------------------------------------------------------*/

bool CRepairModuls::Check4String()
{
	if(!m_bInternalCall)
	{
		if(!GetParameters())
			return false;
	}
	DWORD	dwBytesRead = 0, dwFileOffSet = m_dwArgs[0];
	if(0 == dwFileOffSet)
	{
		return RepairDelete();
	}
	
	// handle case 5 which is used for prepended viruses
	if(m_dwArgs[1] == 5 || m_dwArgs[1] == 6)
	{
		if(!m_ibyArgLen)
		{
			return false;
		}
		BYTE *pbyBuffer = new BYTE[m_ibyArgLen];
		if(pbyBuffer)
		{
			memset(pbyBuffer, 0, m_ibyArgLen);
			if(m_pMaxPEFile->ReadBuffer(pbyBuffer, dwFileOffSet, m_ibyArgLen, m_ibyArgLen))
			{
				if((memcmp(pbyBuffer, m_byArg, m_ibyArgLen) == 0) || m_dwArgs[1] == 6)
				{
					dwFileOffSet = m_dwArgs[2];
				}
			}
			delete []pbyBuffer;
		}
		if(m_dwArgs[1] == 5)
		{
			m_ibyArgLen = 0;
		}
	}
	
	if(7 != m_dwArgs[1])
		m_dwReturnValues[0] = 0;

	// Default search string is MZ if no string is present in the expression
	bool bCheckForMZ = false;
	if(!m_ibyArgLen)
	{
		bCheckForMZ = true;
		m_ibyArgLen = 2;
		memcpy(m_byArg, "MZ", m_ibyArgLen);
	}

	const int SRCH_BUFF_SIZE = 0x1000;
	BYTE byBuffer[SRCH_BUFF_SIZE];
	WORD wLastSec = m_wNoOfSecs - 1;
	
	if(dwFileOffSet > 25)
		dwFileOffSet -= 25;
	if(dwFileOffSet > m_dwFileSize)
	{
		return RepairDelete();
	}
	
	// Search the string from file offset send to the end of file in chunks of 0x1000
	for(DWORD dwOffset = dwFileOffSet; dwOffset < m_dwFileSize; dwOffset += SRCH_BUFF_SIZE)
	{
		memset(byBuffer, 0, SRCH_BUFF_SIZE);
		if(!m_pMaxPEFile->ReadBuffer(byBuffer, dwOffset, SRCH_BUFF_SIZE, 0, &dwBytesRead))
			return false;
	
		for(DWORD iOffset = 0x00; iOffset < dwBytesRead; iOffset++)
		{
			if(!memcmp(&byBuffer[iOffset], m_byArg, m_ibyArgLen))
			{
				m_dwReturnValues[0] = dwOffset + iOffset;
				
				// Found string match
				switch(m_dwArgs[1])
				{
				case 1:
					{
						// Parameter is send as 1 then skip NOPs and return 
						// address of 1st valid instruction.
						m_dwReturnValues[0] += m_ibyArgLen;
						// Skip NOPs
						while(byBuffer[m_dwReturnValues[0] - dwOffset] == 0x90 && (m_dwReturnValues[0] - dwOffset) < dwBytesRead)
							m_dwReturnValues[0]++;
					}
					break;
				case 2:
					{
						// Parameter is send as 2 then look for Push instruction and 
						// return address of 1st valid instruction.
						m_dwReturnValues[0] += m_ibyArgLen;
	
						DWORD dwFileSizeVA	= m_pSectionHeader[wLastSec].VirtualAddress + 
								m_pSectionHeader[wLastSec].Misc.VirtualSize + 
								m_pMaxPEFile->m_stPEHeader.ImageBase;												

						DWORD dwTemp = 0;
						for(DWORD dw = m_dwReturnValues[0] - dwOffset; dw < dwBytesRead; dw++)
						{
							if(byBuffer[dw] == 0x68)
							{
								dwTemp = *(DWORD* )&byBuffer[dw + 1];
								if( dwTemp > 0 && dwTemp < dwFileSizeVA)
								{
									m_dwReturnValues[0] += dw - (m_dwReturnValues[0] - dwOffset);
									return true;
								}
							}
						}
						return false;
					}
					// Added by Rupali on 23 Apr 11. Added for flatei variants.
				case 3:
					{
						// If string is present return string length else return zero.
						m_dwReturnValues[0] = m_ibyArgLen;
					}
					// End				
				}
				return true;
			}
		}
	}
	if(7 == m_dwArgs[1])
	{
		return true;
	}

	if(bCheckForMZ)
	{		
		int iCnt;
		for(iCnt = wLastSec; iCnt > 0; iCnt--)
		{	
			if(0 != m_pSectionHeader[iCnt].SizeOfRawData)
			{
				break;
			}
		}
		DWORD dwEndAddress = m_pSectionHeader[iCnt].PointerToRawData + m_pSectionHeader[iCnt].SizeOfRawData;
		if(SearchForMZPE(m_byArg, m_ibyArgLen, m_pSectionHeader[iCnt].PointerToRawData, dwEndAddress))
		{
			return true;
		}
	}

	if(3 == m_dwArgs[1])
	{
		return true;
	}
	else if(4 == m_dwArgs[1] || 5 == m_dwArgs[1] || 6 == m_dwArgs[1] || bCheckForMZ)
	{
		RepairDelete();		
	}
	return false;
}
// End 

/*-------------------------------------------------------------------------------------
	Function		: SearchForMZPE
	In Parameters	: BYTE *bySearchString, DWORD dwStringLen, DWORD dwStartAddress, DWORD dwEndAddress
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Searches for another PE File in overlay or resource
--------------------------------------------------------------------------------------*/
bool CRepairModuls::SearchForMZPE(BYTE *bySearchString, DWORD dwStringLen, DWORD dwStartAddress, DWORD dwEndAddress)
{
	DWORD dwBytesRead = 0;

	const int SRCH_BUFF_SIZE = 0x1000;
	BYTE byBuffer[SRCH_BUFF_SIZE];

	// Search the string from file offset send to the end of file in chunks of 0x1000
	for(DWORD dwOffset = dwStartAddress; dwOffset < dwEndAddress; dwOffset += SRCH_BUFF_SIZE)
	{
		memset(byBuffer, 0, SRCH_BUFF_SIZE);
		if(!m_pMaxPEFile->ReadBuffer(byBuffer, dwOffset, SRCH_BUFF_SIZE, 0, &dwBytesRead))
		{
			return false;
		}
	
		for(unsigned int iOffset = 0x00; iOffset < dwBytesRead; iOffset++)
		{
			if(!_memicmp(&byBuffer[iOffset], m_byArg, m_ibyArgLen))
			{
				DWORD dwFoundOffset = dwOffset + iOffset;
			
				DWORD dwPEOffset = 0, dwPE = 0;
				m_pMaxPEFile->ReadBuffer(&dwPEOffset, dwFoundOffset + 0x3C, sizeof(DWORD));

				if (dwPEOffset < m_dwFileSize)
				{
					m_pMaxPEFile->ReadBuffer(&dwPE, dwFoundOffset + dwPEOffset, sizeof(WORD));
					if (dwPE == 0x4550)
					{
						m_dwReturnValues[0] = dwFoundOffset;
						return true;
					}
				}
			}
		}
	}
	return false; 
}

/*-------------------------------------------------------------------------------------
Function		: DWordXOR
In Parameters	: DWORD Offset,DWORD Len,DWORD XORKey (e.g InMemoryDword=0x0066BB1A will 
be read as 0x1ABB6600;if key=0x1A2B3C4D,XORVal=0x00905A4D;memory now becomes=0x4D5A9000) 
Out Parameters	: bool
Purpose			: Decrypt a buffer
Author			: Ajay
--------------------------------------------------------------------------------------*/
bool CRepairModuls::DWordXOR()
{
	if(!m_bInternalCall)
	{
		GetParameters();
	}

	DWORD *pbyReadBuffer = new DWORD[((m_dwArgs[1])/(sizeof(DWORD)))];
	memset(pbyReadBuffer, 0, m_dwArgs[1]);

	if(!m_pMaxPEFile->ReadBuffer(pbyReadBuffer, m_dwArgs[0], m_dwArgs[1], m_dwArgs[1]))
	{
		delete []pbyReadBuffer;
		return (false);
	}

	if(m_dwArgs[3] == 1)      // m_dwArgs[3]==1   means ROL present. This condition is for PRO.H & PRO.G
	{
		for(DWORD i=0; i<m_dwArgs[1] && (m_dwArgs[1]/(i+1))>=0x4; i++)
		{
			pbyReadBuffer[i] ^= m_dwArgs[2];
			m_dwArgs[2] = _lrotl(m_dwArgs[2],3);
		}
	}
	else
	{
		for(DWORD i=0; i<m_dwArgs[1] && (m_dwArgs[1]/(i+1))>=0x4; i++)
		{
			pbyReadBuffer[i] ^= m_dwArgs[2];
		}
	}

	if(!m_pMaxPEFile->WriteBuffer(pbyReadBuffer, m_dwArgs[0], m_dwArgs[1], m_dwArgs[1]))
	{
		delete []pbyReadBuffer;
		return (false);
	}

	return true;
}

// Added by Rupali on 19-11-2010 for WMA repair changes
/*-----------------------------------------------------------------------------
Function		: CleanWMAFile
In Parameters	: -
Out Parameters	: -
Purpose			: Routine for clean infected WMA file.
Author			: Sourabh Kadam
Description		: This Routine will clean URLANDEXIT type files
-----------------------------------------------------------------------------*/
bool CRepairModuls::CleanWMAFile()
{	
	DWORD	dwAEP = 0;		
	if(!m_pMaxPEFile->ReadBuffer(&dwAEP, 0x10, 4, 4))
	{
		return false;
	}
	if (dwAEP > m_dwFileSize)
	{
		return false;
	}
	DWORD dwdupAep = dwAEP, dwBytesRead = 0;
	if (dwAEP < 0x200)
	{
		dwBytesRead = dwAEP;
		dwAEP = 0;
	}
	else
	{
		dwBytesRead = 0x200;
		dwAEP  =  dwAEP - 0x200;
	}
	BYTE	szScanBuffer[MAX_BUFF_SIZE] = {0};
	unsigned int iBufferSize = 0;
	
	if(!m_pMaxPEFile->ReadBuffer(&szScanBuffer[iBufferSize], dwAEP, dwBytesRead, 0, &dwBytesRead))
	{
		return false;
	}
	
	char	ch;
	DWORD	i = 0;
	DWORD	dwPatchSize = 0;
	bool	vFound = false;
	const unsigned char chURLANDEXIT[] = {
							0x55,0x00,0x52,0x00,0x4C,0x00,
							0x41,0x00,0x4E,0x00,0x44,0x00,
							0x45,0x00,0x58,0x00,0x49,0x00,0x54
							};
	for(i = 0; i < dwBytesRead; i++ )
	{
		ch = NULL;
		ch = (char)szScanBuffer[i];
		if((ch == 'u') || (ch =='U'))
		{
			if(!memcmp(&szScanBuffer[i],chURLANDEXIT,19))
			{
				vFound = true;
				break;
			}
		}
	}

	if(vFound)
	{
		dwAEP = dwAEP + i;
		dwPatchSize = dwdupAep - dwAEP;
		LPBYTE	bPatchBuffer = NULL;
		DWORD	dwSizeOfReplacement = 0;
		DWORD	dwNewAEP = 0;
		
		dwSizeOfReplacement = m_dwFileSize - (dwPatchSize + dwAEP);
		bPatchBuffer = (BYTE *)malloc(dwSizeOfReplacement);
		memset(bPatchBuffer,0x00,dwPatchSize);

		if(!m_pMaxPEFile->ReadBuffer(bPatchBuffer, dwAEP + dwPatchSize, dwSizeOfReplacement, dwSizeOfReplacement))
		{
			return false;
		}

		if(!m_pMaxPEFile->WriteBuffer(bPatchBuffer, dwAEP - 0x2E, dwSizeOfReplacement, dwSizeOfReplacement))
		{
			return false;
		}
		free(bPatchBuffer);
		bPatchBuffer = NULL;
		dwNewAEP = dwAEP - 0x2E;
		if(!m_pMaxPEFile->WriteBuffer(&dwNewAEP, 0x10, sizeof(DWORD), sizeof(DWORD)))
		{
			return false;
		}
		m_pMaxPEFile->ForceTruncate(m_dwFileSize - (dwPatchSize + 0x2E));		
	}
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: RepairSmallA
In Parameters	: NULL
Out Parameters	: bool
Purpose			: To Repair Win32.Small.A bcz its Decryption Loop.
Author			: Rohit (30 Nov 2010)
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairSmallA()
{
	DWORD	dwOriginalAepOffset = 0,dwBytesRead=0,dwFilePointerRet=0;
	DWORD	dwBytesWritten=0,dwVirCodeAddr = 0;
	
	m_pMaxPEFile->ReadBuffer(&dwVirCodeAddr, m_dwAEPMapped + 0x0C, sizeof(DWORD));
	dwVirCodeAddr += 6;
	dwVirCodeAddr = GetMappedAddress(dwVirCodeAddr - m_pMaxPEFile->m_stPEHeader.ImageBase);

	DWORD	dwLow, dwHigh ,dEAX=0,dEBX=0,dECX=0,dEDX=0,dESP=0,dESI=0,dEDI=0;	
	DWORD	dwPushEDX = 0, dwPushDwordPtr = 0;

	BYTE *bBuffer = new BYTE[4000];
	unsigned __int64 iVal;
	long lIndexCount = 0xC3;	

	// Decryption logic starts from here
	memset(bBuffer,0x00,4000);
	m_pMaxPEFile->ReadBuffer(bBuffer, dwVirCodeAddr, 3715);
	
	// First TimeStamp
	ULONGLONG ull = GetTickCount();                           
	iVal = __rdtsc();
  
	dwLow = iVal &0xFFFFFFFF;
	dwHigh = iVal>>0x20;

	*((DWORD*)&bBuffer[0x9E]) = dwLow;
	*((DWORD*)&bBuffer[0xA2]) = dwHigh;
	dEAX = dwLow;
	dEDX = dwHigh;

	dECX = *((DWORD*)&bBuffer[0xBB]); 
	dEAX = dECX;
	dECX*=dECX;
	dEAX = dECX;
	dEDX = dEAX;

	dEDX = ~dEDX;

	*((DWORD*)&bBuffer[0xBF]) ^= dEDX;
	dEDX = ~dEDX;

	dEBX = dwVirCodeAddr + 0xC3;
	dECX = 370;
	dESI = 0x92;
	dEDI = 0x96;
	
	DWORD dwTemp = dwVirCodeAddr + 0xE83;
	while(dEBX != dwTemp)
	{
		dwPushDwordPtr = *((DWORD*)&bBuffer[lIndexCount]);

		dwPushEDX = dEDX;

		ULONGLONG ull = GetTickCount();                 // Second TimeStamp
		iVal = __rdtsc();
  
		dwLow = iVal &0xFFFFFFFF;
		dwHigh = iVal>>0x20;

		*((DWORD*)&bBuffer[0xA6]) = dwLow;
		*((DWORD*)&bBuffer[0xAA]) = dwHigh;    
		dEAX = dwLow;
		dEDX = dwHigh;

		dEDX = dwPushEDX;

		dEAX -= *((DWORD*)&bBuffer[0x9E]);
	
		if(dEAX & 0x80000000)
			dEAX = ~dEAX;	
		dEAX  = dEAX /(pow((double)2,(double)19));
   
		dEAX = ~dEAX;
		dEDX ^= dEAX;
		*((DWORD*)&bBuffer[lIndexCount]) ^=dEDX;

		dEDX = dwPushDwordPtr;
	
		for(int j=0;j<8;j++)
			bBuffer[0x9E + j]=bBuffer[0xA6 + j];

		dEBX += 0x04;
		lIndexCount +=4;
		
		dECX--;
	}
	 	
	m_pMaxPEFile->WriteBuffer(&bBuffer[2853], m_dwAEPMapped, 16);	
	m_pMaxPEFile->TruncateFile(dwVirCodeAddr - 5, true);

	delete []bBuffer;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanScriptFile
	In Parameters	: int iFunc
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Added on 06-12-2010 for Script file repair changes
--------------------------------------------------------------------------------------*/
bool CRepairModuls::CleanScriptFile(int iFunc)
{	
	// Added by Rupali on 3 Mar 2011. Moved this from common function as we will be reading
	// buffer from differnt location for depending on the type of infection.
	if(!ReadScriptFile(iFunc))
	{
		return false;
	}
	// End

	bool bRet = false;
	switch(iFunc)
	{
	case REPAIR_IFRAME:
		{
			bRet = ScriptRepair(IFRAME_START_TAG, IFRAME_END_TAG);
			break;
		}
	case REPAIR_OBJECT:
		{
			bRet = ScriptRepair(OBJECT_START_TAG, OBJECT_END_TAG, OBJECT_REPAIR_OFFSET);
			break;
		}	
	case REPAIR_SCRIPT:
		{
			bRet = ScriptTagRepair();
			break;
		}
	case REPAIR_EICAR:
		{
			bRet = ScriptRepair(EICAR_START_TAG, EICAR_END_TAG);
			break;
		}
	case REPAIR_PNG:
		{
			bRet = CleanPNGFile();
			break;
		}
	}

	return bRet;
}

/*-------------------------------------------------------------------------------------
	Function		: ScriptRepair
	In Parameters	: char *szTagStart, char *szTagEnd, int iRepairOffset
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Added on 06-12-2010 for Script file repair changes
--------------------------------------------------------------------------------------*/
bool CRepairModuls::ScriptRepair(char *szTagStart, char *szTagEnd, int iRepairOffset)
{	
	if(!m_bInternalCall)
	{
		GetParameterForScript();
	}
		
	int iTagStartlen	= strlen(szTagStart);
	int iTagEndlen		= strlen(szTagEnd);
				
	BYTE byTagStart[START_TAG_LENGTH], byTagEnd[END_TAG_LENGTH];
	memcpy(byTagStart, szTagStart, iTagStartlen);
	memcpy(byTagEnd, szTagEnd, iTagEndlen);
				
	bool bClean = false, bRet = false;

	for(DWORD dw = 0; dw <= m_dwBufferSize; dw++)
	{
		// Look for the start of the tag 
		if(_memicmp(&m_byReadBuffer[dw], byTagStart, iTagStartlen) == 0)
		{
			// Start tag matched. Now match the part of signature which 
			// identifies the infected area
			for(DWORD dwCount1 = dw + 1; dwCount1 < m_dwBufferSize; dwCount1++)
			{
				if(_memicmp(&m_byReadBuffer[dwCount1], byTagStart, iTagStartlen) == 0)
				{	
					// Reset the start of the tag location if there are multiple tags
					dw = dwCount1;
				}	
				else if(_memicmp(&m_byReadBuffer[dwCount1], m_pbyParameter, m_iParameterlen) == 0)
				{
					// Virus signature is matched so look for end tag to clean the infection
					for(DWORD dwCount2=dwCount1; dwCount2 < m_dwBufferSize; dwCount2++)
					{
						if(_memicmp(&m_byReadBuffer[dwCount2], byTagEnd, iTagEndlen) == 0)
						{
							// Got the infected area. Now clean the infected tag by filling the spaces
							// In case of object tag skip the HTML tag. And leave the </object> tag so
							// that false positive results in the recursive scan can be avoided.
							DWORD dwStartClean = dw + iRepairOffset;
							DWORD dwEndClean = dwCount2;
							if(0 == iRepairOffset)
							{							
								dwEndClean += iTagEndlen;							
							}
							//Added by Rupali on 3 Mar 2011. Fill infection with spaces.
							DWORD dwWrite = 0x20;		
							memset(m_byReadBuffer,0x20,(dwEndClean - dwStartClean) + 0x10);

							if(m_dwFileSize < SCRIPT_BUFF_SIZE || iRepairOffset || _stricmp(szTagStart, EICAR_START_TAG) == 0)
							{
								m_pMaxPEFile->WriteBuffer(m_byReadBuffer, dwStartClean, (dwEndClean - dwStartClean), (dwEndClean - dwStartClean));
							}
							else
							{
								dwStartClean = m_dwFileSize - SCRIPT_BUFF_SIZE + dwStartClean;
								dwEndClean   = m_dwFileSize - SCRIPT_BUFF_SIZE + dwEndClean;
								m_pMaxPEFile->WriteBuffer(m_byReadBuffer, dwStartClean, (dwEndClean - dwStartClean), (dwEndClean - dwStartClean));								
							}
							bRet = true;
							// End
							dw = dwEndClean;
							bClean = true;
							break;
						}//if(_memicmp(&m_byReadBuffer[dwCount2],byScriptEn,8)==0)
					}
					if(bClean)
					{
						break;
					}
				}//if(_memicmp(&m_byReadBuffer[dwCount1], m_pbyParameter, m_iParameterlen) == 0)
			}
		}//if(_memicmp(&m_byReadBuffer[dw],byScriptSt,6) == 0)
	}	
	if(!bClean)               
	{
		RepairDelete();       
	}
	delete []m_pbyParameter;	
	return bRet;
}

/*-------------------------------------------------------------------------------------
	Function		: ScriptRepair
	In Parameters	: char *szTagStart, char *szTagEnd, int iRepairOffset
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Added on 3 Mar 2011 for Script file repair changes

// Searching for infection from bottam to up in chunks of 64K so that script 
// files larger than 64k size can be repaired
// Modified on 22 June 2011. To clean corrupt script files.
--------------------------------------------------------------------------------------*/
bool CRepairModuls::ScriptTagRepair()
{	
	if(!m_bInternalCall)
	{
		GetParameterForScript();
	}
		
	int iTagStartlen	= strlen(SCRIPT_START_TAG);
	int iTagEndlen		= strlen(SCRIPT_END_TAG);
	int iLastTagEndOffset = 0;
				
	BYTE byTagStart[START_TAG_LENGTH], byTagEnd[END_TAG_LENGTH];
	memcpy(byTagStart, SCRIPT_START_TAG, iTagStartlen);
	memcpy(byTagEnd, SCRIPT_END_TAG, iTagEndlen);
				
	DWORD dwEnd = 0;
	bool bClean = false, bRet = false, bFoundSig = false, bSigNotFound = true;

	DWORD dwReadOffset = 0 , dwBytestoRead = SCRIPT_BUFF_SIZE, dwBytesRead = 0;
	if(m_dwFileSize > SCRIPT_BUFF_SIZE)
	{
		dwReadOffset =  m_dwFileSize - SCRIPT_BUFF_SIZE;
	}
	/*else
	{
		dwReadOffset = m_dwFileSize;
		dwBytestoRead = m_dwFileSize;
	}*/

	while(dwReadOffset >= 0 && 0 != dwBytestoRead)
	{
		for(int iOffset1 = m_dwBufferSize - END_TAG_LENGTH; iOffset1 >= 0; iOffset1--)
		{
			// Look for the end of the tag 
			if(_memicmp(&m_byReadBuffer[iOffset1], byTagEnd, iTagEndlen) == 0)
			{
				if(!iLastTagEndOffset)
				{
					iLastTagEndOffset = iOffset1;
				}
				// End tag matched. Now match the part of signature which 
				// identifies the infected area
				while(dwReadOffset >= 0 && 0 != dwBytestoRead)
				{
					bFoundSig = false;
					for(int iOffset2 = iOffset1 - iTagEndlen; iOffset2 >= 0; iOffset2--)
					{					
						if(_memicmp(&m_byReadBuffer[iOffset2], m_pbyParameter, m_iParameterlen) == 0)
						{
							bFoundSig = true;
							bSigNotFound = false;

							// Virus signature is matched so look for end tag to clean the infection
							// If script tag is lie beyaond lower 64k buffer then we continue reading next 
							// 64 chunk of buffer to find start of the infection till the starting of file
							while(dwReadOffset >= 0 && 0 != dwBytestoRead) // if file is smaller than 64KB ReadOffset will be 0
							{
								bClean = false;
								for(int iOffset3 = iOffset2 - iTagStartlen; iOffset3 >= 0; iOffset3--)
								{
									if(_memicmp(&m_byReadBuffer[iOffset3], byTagStart, iTagStartlen) == 0)
									{
										// Got the start of infected script tag so truncate file from start of script. 
										dwEnd = dwReadOffset + iOffset3;
										if(0 == dwEnd)
										{
											return RepairDelete();
										}
																		
										iOffset1 = iOffset3;
										bRet = bClean = true;
										break;
									}//if(_memicmp(&m_byReadBuffer[iOffset3],byScriptEn,8)==0)							
								}
								if(bClean)
								{
									break;
								}
								
								if(m_dwFileSize < SCRIPT_BUFF_SIZE)
								{
									// Confirmation string is present but could not find start tag so return failed.
									delete []m_pbyParameter;
									return RepairDelete();
									//return bRet;
								}
								
								if(dwReadOffset >= SCRIPT_BUFF_SIZE)
								{
									dwBytestoRead = SCRIPT_BUFF_SIZE;
									dwReadOffset -= SCRIPT_BUFF_SIZE;
								}
								else
								{
									// Reading last chunk.
									dwBytestoRead = dwReadOffset;
									dwReadOffset = 0; 
								}							

								m_pMaxPEFile->ReadBuffer(m_byReadBuffer, dwReadOffset, dwBytestoRead, 0, &dwBytesRead);
								if (dwBytesRead <= 0)
								{
									delete []m_pbyParameter;
									return bRet;
								}
								iOffset2 = m_dwBufferSize = dwBytesRead;
							}
							if(bClean)
							{
								break;
							}
						}//if(_memicmp(&m_byReadBuffer[iOffset2], m_pbyParameter, m_iParameterlen) == 0)
					}

					if(bClean)
						break;
					if(!bClean)
					{
						if(0 == dwReadOffset && bFoundSig)
						{
							bRet = RepairDelete();
						}

						if(dwReadOffset >= SCRIPT_BUFF_SIZE)
						{
							dwBytestoRead = SCRIPT_BUFF_SIZE;
							dwReadOffset -= SCRIPT_BUFF_SIZE;
						}
						else
						{
							// Reading last chunk.
							dwBytestoRead = dwReadOffset;
							dwReadOffset = 0; 
						}	
						if(!m_pMaxPEFile->ReadBuffer(m_byReadBuffer, dwReadOffset, dwBytestoRead, 0, &dwBytesRead))
						{
							//rushi : this function is written for repairing the file in which EndTag is not there in files.
							//in this function we are checking signature after Final EndTag if Signature is found then we deleting the 
							// code after EndTag
							if(bSigNotFound && iLastTagEndOffset)
							{
								if(m_dwFileSize - iLastTagEndOffset >= SCRIPT_BUFF_SIZE)
								{
									dwBytestoRead = SCRIPT_BUFF_SIZE;
								}
								else
								{
									dwBytestoRead = m_dwFileSize - iLastTagEndOffset;
								}								
								if(m_pMaxPEFile->ReadBuffer(m_byReadBuffer, iLastTagEndOffset, dwBytestoRead, 0, &dwBytesRead))
								{
									for(int iOffset4 = iLastTagEndOffset; iOffset4 < SCRIPT_BUFF_SIZE; iOffset4++)
									{									
										if(_memicmp(&m_byReadBuffer[iOffset4], m_pbyParameter, m_iParameterlen) == 0)
										{
											m_pMaxPEFile->ForceTruncate(iLastTagEndOffset + 9);
											delete []m_pbyParameter;
											return true;
										}
									}
								}
							}
							return false;
						}
						iOffset1 = dwBytesRead;
					}
				}//if(_memicmp(&m_byReadBuffer[dw],byScriptSt,6) == 0)
			}
		}		
		if(dwReadOffset >= SCRIPT_BUFF_SIZE)
		{
			dwBytestoRead = SCRIPT_BUFF_SIZE;
			dwReadOffset -= SCRIPT_BUFF_SIZE;
		}
		else
		{
			// Reading last chunk.
			dwBytestoRead = dwReadOffset;
			dwReadOffset = 0; 
		}	
		if(dwBytestoRead == 0)
		{
			break;
		}
		if(!m_pMaxPEFile->ReadBuffer(m_byReadBuffer, dwReadOffset, dwBytestoRead, 0, &dwBytesRead))
			return false;
		m_dwBufferSize = dwBytesRead;
	}	
	if(dwEnd)
	{
		m_pMaxPEFile->ForceTruncate(dwEnd);		
	}
	delete []m_pbyParameter;
	if(!bRet)
	{
		bRet = RepairDelete();
	}
	return bRet;
}

/*-----------------------------------------------------------------------------
Function		: CleanPNGFile

Purpose			: Routine for clean infected WMA file.
Author			: _mangesh
Description		: This Routine will clean PNG type files
-----------------------------------------------------------------------------*/
bool CRepairModuls::CleanPNGFile()
{
	if(!m_bInternalCall)
	{
		GetParameterForScript();
	}
	if(m_iParameterlen == 0)
	{
		m_pbyParameter = new BYTE[8];
		if(!m_pbyParameter)
		{
			return false;
		}
		BYTE  byTagEnd[] = {0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82};
		memcpy(m_pbyParameter, byTagEnd, 8);
		m_iParameterlen = 8;
	}

	for(DWORD dwCount = m_dwBufferSize - m_iParameterlen - 1; dwCount >= 0; dwCount--)
	{
		if(memcmp(&m_byReadBuffer[dwCount], m_pbyParameter, m_iParameterlen) == 0)
		{
			DWORD dwTruncateOff = (m_dwFileSize - (m_dwBufferSize - dwCount));			
			if(m_iParameterlen == 0)
			{
				dwTruncateOff +=  sizeof(m_pbyParameter);
			}

			if(m_pMaxPEFile->ForceTruncate(dwTruncateOff))
			{
				return true;
			}
		}
		if(dwCount == 0)
		{
			break;
		}		
	}
	return RepairDelete();
}

/*-------------------------------------------------------------------------------------
Function		: ReadScriptFile
In Parameters	: -
Out Parameters	: bool
Purpose			: Read the script file and stores into buffer(Only for Script File)
Author			: Yash
--------------------------------------------------------------------------------------*/
bool CRepairModuls::ReadScriptFile(int iFunc)
{
	// Added by Rupali on 3 Mar 2011. Modified function to read buffer less than
	// 64K for script files. 
	m_dwBufferSize = 0x00;
	if (m_dwFileSize < SCRIPT_BUFF_SIZE)
	{
		// If file is less than 64K then read whole file.
		m_byReadBuffer = new BYTE[m_dwFileSize];
		memset(m_byReadBuffer, 0x00, m_dwFileSize);

		if(!m_pMaxPEFile->ReadBuffer(m_byReadBuffer, 0, m_dwFileSize, 0, &m_dwBufferSize))
			return false;
	}
	else
	{
		// File is larger than 64K 
		m_byReadBuffer = new BYTE[SCRIPT_BUFF_SIZE];
		if(!m_byReadBuffer)
			return false;
		memset(m_byReadBuffer, 0x00, SCRIPT_BUFF_SIZE);

		if(REPAIR_OBJECT == iFunc || REPAIR_EICAR == iFunc )
		{
			// Read 64K buffer from start of file 
			if(!m_pMaxPEFile->ReadBuffer(m_byReadBuffer, 0, SCRIPT_BUFF_SIZE, 0, &m_dwBufferSize))
				return false;			
		}
		else
		{
			// For Script and IFrame infections read buffer from end
			if(!m_pMaxPEFile->ReadBuffer(m_byReadBuffer, (m_dwFileSize - SCRIPT_BUFF_SIZE), SCRIPT_BUFF_SIZE, 0, &m_dwBufferSize))
				return false;			
		}
	}
	// End
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: GetParameterForScript
In Parameters	: -
Out Parameters	: bool
Purpose			: Get the arguments of function and fill the buffer with confirmation string 
Author			: Yash
--------------------------------------------------------------------------------------*/
bool CRepairModuls::GetParameterForScript()
{		
	TCHAR szParameters[MAX_PATH];
	wcscpy_s(szParameters, MAX_PATH, m_csModParam);	
	
	int ilen=(_tcsclen(szParameters));
		
	m_pbyParameter = new BYTE[(ilen / 2)];
	memset(m_pbyParameter, 0x00, (ilen / 2));
	
	char szBuff[3]={0};
	char *pHex = NULL;
	
	int iCnt=0;
	for(int i = 0; i < ilen; i += 2)
	{
		szBuff[0] = szParameters[i];
		szBuff[1] = szParameters[i+1];
		szBuff[2] = '\0';
		int iChar = strtol(szBuff, &pHex, 0x10);
		m_pbyParameter[iCnt++] = iChar;
	}
	m_iParameterlen = iCnt - 1;	
	return true;
}
//End

/*-------------------------------------------------------------------------------------
Function		: DecryptionSalityFloatXOR_Ex
In Parameters	: DWORD dwDecryptionKey, DWORD dwDecryptionLength, DWORD dwDecryptionStartOffset, DWORD dwDecryptionPoint
Out Parameters	: bool
Purpose			: Decrypts the buffer specifically for Sality variant virus in which counter starts from 0
Author			: Manjunath
--------------------------------------------------------------------------------------*/
bool CRepairModuls::DecryptionSalityFloatXOREx()
{
	if(!m_bInternalCall)
	{
		GetParameters();
	}
	
	WORD wKey = (WORD)m_dwArgs[0];
		
	m_byReadBuffer = new BYTE[m_dwArgs[1]];
	if(NULL == m_byReadBuffer)
	{
		return false;
	}
	
	memset(m_byReadBuffer, 0, m_dwArgs[1]);

	if(!m_pMaxPEFile->ReadBuffer(m_byReadBuffer, m_dwArgs[2] + m_dwArgs[3], m_dwArgs[1], m_dwArgs[1]))
	{
		return false;
	}

	DWORD_PTR dwTemp = 0;
	for(DWORD i = 0; i < m_dwArgs[1]; i += 2)
	{
		dwTemp = (WORD)((m_dwArgs[3] + i) * wKey);
		dwTemp -= ((m_dwArgs[3] + i)/2);
		*(WORD *)&m_byReadBuffer[i] ^= (WORD)dwTemp;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: ReplaceDataInReadBuffer
In Parameters	: DWORD dwReplacementOffset, DWORD dwSizeOfReplacement, 
Out Parameters	: bool
Purpose			: In case of original data present in m_byReadBuffer, perfoms replacement action of data at given location
Author			: Manjunath
m_dwArgs[0]: Replacement Offset
m_dwArgs[1]: Size Of Replacement
--------------------------------------------------------------------------------------*/
bool CRepairModuls::ReplaceDataInReadBuffer() 
{
	if(!m_bInternalCall)
	{
		GetParameters();
	}

	DWORD dwBytesWritten = 0;

	if(m_byReadBuffer == NULL)
		return false;

	if(!m_pMaxPEFile->WriteBuffer(m_byReadBuffer, m_dwArgs[0], m_dwArgs[1], m_dwArgs[1]))
	{
		return false;
	}
	
	return true;
}

/*-------------------------------------------------------------------------------------
Function		:	RepairImporterA
In Parameters	: 
Out Parameters	:	bool
Purpose			:	Repair for W32.Importer.A virus 
Author			:	Adnan
Date			:	05 Jan 2011
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairImporterA()
{
	DWORD dwImportDirectoryTableRVA = m_pMaxPEFile->m_stPEHeader.DataDirectory[1].VirtualAddress;
	if(dwImportDirectoryTableRVA == 0x0)
		return(false);

	WORD wSec = 0;
	for(; wSec < m_wNoOfSecs - 1; wSec++)
	{
		if((dwImportDirectoryTableRVA >= m_pSectionHeader[wSec].VirtualAddress) && 
			(dwImportDirectoryTableRVA <= (m_pSectionHeader[wSec].VirtualAddress + m_pSectionHeader[wSec].SizeOfRawData )))
			break;
	}
	DWORD dwSetFileOffset = GetMappedAddress(dwImportDirectoryTableRVA + 0x10);
	
	DWORD	dwImportAddressTableRVA = 0x0; 
	if(!m_pMaxPEFile->ReadBuffer(&dwImportAddressTableRVA, dwSetFileOffset, sizeof(DWORD), sizeof(DWORD)))
		return (false);
	
	if(dwImportAddressTableRVA != m_pSectionHeader[m_wNoOfSecs - 1].VirtualAddress)
	{
		return RepairDelete();
	}
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwImportAddressTableRVA, &dwSetFileOffset)) //changed code
	{
		return RepairDelete();
	}
			
	DWORD dwSize = m_pSectionHeader[m_wNoOfSecs - 1].SizeOfRawData;
	BYTE *byBuffer = new BYTE[dwSize];	
	if(!byBuffer)
		return false;

	memset(byBuffer,0x0,dwSize);
	if(!m_pMaxPEFile->ReadBuffer(byBuffer, dwSetFileOffset, m_pSectionHeader[m_wNoOfSecs - 1].SizeOfRawData, m_pSectionHeader[m_wNoOfSecs - 1].SizeOfRawData))
		return (false);
	DWORD dwMappedImportAddressTableRVA = 0;

	while(1)
	{
		if((dwMappedImportAddressTableRVA ) > m_pSectionHeader[m_wNoOfSecs - 1].SizeOfRawData)
			return (false);
		if((*((DWORD *) &byBuffer[dwMappedImportAddressTableRVA]) == 0x0) && (byBuffer[dwMappedImportAddressTableRVA + 0x4] == 0xE8))
			break;
		dwMappedImportAddressTableRVA += 0x4;
		dwImportAddressTableRVA += 0x4;
	}

	BYTE	bySearchString[5] = {0};
	DWORD	dwTempImportAddressTableRVA = dwImportAddressTableRVA + m_pMaxPEFile->m_stPEHeader.ImageBase + 0x4;
	DWORD	dwOffset = 0;

	for(; dwOffset < 5; dwOffset++)
	{
		bySearchString[dwOffset] = (BYTE)dwTempImportAddressTableRVA;
		dwTempImportAddressTableRVA = dwTempImportAddressTableRVA >> 0x8;
	}

	BYTE *byBuffer1 = new BYTE[m_pSectionHeader[wSec].SizeOfRawData];
	dwSetFileOffset = m_pSectionHeader[wSec].PointerToRawData;
			
	if(!m_pMaxPEFile->ReadBuffer(byBuffer1, dwSetFileOffset, m_pSectionHeader[wSec].SizeOfRawData, m_pSectionHeader[wSec].SizeOfRawData))
	{
		delete []byBuffer;
		delete []byBuffer1;
		return(false);
	}

	for(dwOffset = 0; dwOffset < m_pSectionHeader[wSec].SizeOfRawData; dwOffset++)
	{
		if(memcmp(&byBuffer1[dwOffset],bySearchString,0x4)==0)
		{
			break;
		}
	}

	if(dwOffset == m_pSectionHeader[wSec].SizeOfRawData )
	{
		delete []byBuffer;
		delete []byBuffer1;
		return RepairDelete();
	}
	dwImportAddressTableRVA = m_pSectionHeader[wSec].VirtualAddress + dwOffset;

	int i = 0;
	while(1)
	{
		if((*((DWORD *) (byBuffer + i)) == 0x0))
			break;
		*((DWORD *)&byBuffer1[dwOffset]) = *((DWORD *)&byBuffer[i]);
		i += 0x4;
		dwOffset += 0x4;
	}

	delete []byBuffer;

	dwSetFileOffset = m_pSectionHeader[wSec].PointerToRawData;
	
	if(!m_pMaxPEFile->WriteBuffer(byBuffer1, dwSetFileOffset, m_pSectionHeader[wSec].SizeOfRawData, m_pSectionHeader[wSec].SizeOfRawData))
	{
		delete []byBuffer1;
		return(false);
	}
	
	delete []byBuffer1;
	dwSetFileOffset = GetMappedAddress(m_pMaxPEFile->m_stPEHeader.DataDirectory[1].VirtualAddress + 0x10);
	
	if(!m_pMaxPEFile->WriteBuffer(&dwImportAddressTableRVA, dwSetFileOffset, 4, 4))
	{
		return(false);
	}
	m_pMaxPEFile->RemoveLastSections();
	CalculateChecksum();
	return(true);
}

/*-------------------------------------------------------------------------------------
Function		: RepairRenameFile
In Parameters	: LPTSTR CurExtOfOrgFile
Out Parameters	: bool
Purpose			: Deletes virus stub/file. If renamed original file exists then change 
					the original file name with currently scanning virus file name.
Author			: Manjunath

Modified by Rupali on 19 Apr 11. To take renamed extension through expression.
m_dwArgs[0]: Special repair case no
m_dwArgs[1]: 0 if extension is used by virus to rename the file
			 1 if string is used by virus and prepened to the original file name
			 2 if string is used by virus and prepened to the original file name 
				and file is encrypted currently used by Brof.C			 
m_dwArgs[2]: This case should be used if virus has renamed the original file and 
			 then infected it.

m_dwArgs[3]: This case should be used if original file needs to be trucated 
m_dwArgs[4]: Offset where to trucate the file
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairRenameFile()
{
	wchar_t szExtension[MAX_INPUT_STR_PARAM] = {0};
	
	if(m_ibyArgLen)
	{
		size_t iRet = 0;
		mbstowcs_s(&iRet, szExtension, MAX_INPUT_STR_PARAM, (const char*)m_byArg, MAX_INPUT_STR_PARAM);
	}

	if(m_dwArgs[2])
	{	
		int iLength = m_csOriginalFilePath.ReverseFind('.');
		if(-1 == iLength)
			return true;
		CString csTempExt = m_csOriginalFilePath.Right(m_csOriginalFilePath.GetLength() - iLength);		
		
		CString csTemp;
		csTemp.Format(L"%s", szExtension);
		int iTemp = csTemp.ReverseFind('.');
		csTemp = csTemp.Right(csTemp.GetLength() - iTemp);
		if(csTempExt.CompareNoCase(csTemp) != 0)
			return true;
		m_csOriginalFilePath = m_csOriginalFilePath.Left(iLength);		
	}
	
	// Read file before deleting the file to check if renamed file is virus stub
	const int HDR_SIZE = 0x250;
	BYTE byInfectedFileData[HDR_SIZE] = {0};
	DWORD dwBytesToRead = m_dwFileSize > HDR_SIZE ? HDR_SIZE : m_dwFileSize;	
	m_pMaxPEFile->ReadBuffer(byInfectedFileData, 0, dwBytesToRead);
	
	//Delete the virus stub/file
	if(!RepairDelete())
		return false;

	CString csRenamedFilePath = m_csOriginalFilePath;

	// Get file path that virus uses to store the original file.
	switch(m_dwArgs[1])
	{
	// Virus has appended some extension to the original file name
	case 0:
		{
			int iLength = csRenamedFilePath.ReverseFind('.');
			if(-1 == iLength)
				return true;
			csRenamedFilePath = csRenamedFilePath.Left(iLength);
			csRenamedFilePath.Append(szExtension);
			break;
		}
	case 1:
	case 2:
		{
			// Virus has prepended some string to the original file name
			int iLength = csRenamedFilePath.ReverseFind('\\');
			if(-1 == iLength)
				return true;
			iLength++;
			CString csFileName = csRenamedFilePath.Right(csRenamedFilePath.GetLength() - iLength);			
			csRenamedFilePath = csRenamedFilePath.Left(iLength);
			csRenamedFilePath.AppendFormat(L"%s%s",szExtension, csFileName);
			break;
		}
	case 3:
		{
			int iLength = csRenamedFilePath.ReverseFind('.');
			if(-1 == iLength)
				return true;
			csRenamedFilePath = csRenamedFilePath.Left(iLength);
			CString csFileName = csRenamedFilePath.Right(4);
			
			iLength = csRenamedFilePath.ReverseFind('\\');
			if(-1 == iLength)
				return true;
			csRenamedFilePath = csRenamedFilePath.Left(iLength+1) + csFileName;			
			break;
		}	
	case 5: 
		{
			// Virus has prepended some string to the original file name
			int iLength = csRenamedFilePath.ReverseFind('\\');
			if(-1 == iLength)
				return true;
			iLength++;
			CString csFileName = csRenamedFilePath.Right(csRenamedFilePath.GetLength() - iLength);
			TCHAR szTempPath[MAX_PATH] = {0};
			if(!GetTempPath(MAX_PATH, szTempPath))
				return true;
			csRenamedFilePath.Format(L"%s%s%s",szTempPath, szExtension, csFileName);
			break;
		}
		// Added for virus Chiton.T
	case 6:
		{
			int iLength = m_csOriginalFilePath.ReverseFind('.');
			if(-1 == iLength)
				return true;
			m_csOriginalFilePath = m_csOriginalFilePath.Left(iLength);
			m_csOriginalFilePath.Append(L".doc");

			iLength = m_csOriginalFilePath.ReverseFind('\\');
			if(-1 == iLength)
				return true;
			iLength++;
			CString csFileName = m_csOriginalFilePath.Right(m_csOriginalFilePath.GetLength() - iLength);
			csRenamedFilePath = m_csOriginalFilePath.Left(iLength);
			csRenamedFilePath.AppendFormat(L"%s%s",szExtension, csFileName);
			MoveFile(csRenamedFilePath, m_csOriginalFilePath);
			return true;
		}
	case 7:
		csRenamedFilePath.Append(szExtension);
		break;			
	case 8:
		{
			// rundll32.exe is changed to rundll86.exe
			int iLength = csRenamedFilePath.ReverseFind('.');
			if(iLength < 3)
				return true;
			iLength -=2;
			csRenamedFilePath = csRenamedFilePath.Left(iLength);
			csRenamedFilePath.Append(szExtension);
			break;
		}
	}

	// Check whether file is valid file by checking MZ at the start
	DWORD dwFileFlag = GENERIC_READ;
	if(m_dwArgs[1] == 2 || m_dwArgs[3] == 1)
	{
		dwFileFlag = GENERIC_READ | GENERIC_WRITE;
	}
	
	SetFileAttributes(csRenamedFilePath, FILE_ATTRIBUTE_NORMAL);	
	HANDLE	hOrgFileHandle = CreateFile(csRenamedFilePath,
										dwFileFlag, 
										FILE_SHARE_READ, 
										NULL, 
										OPEN_EXISTING, 
										FILE_ATTRIBUTE_NORMAL, 
										NULL);	
	if (INVALID_HANDLE_VALUE != hOrgFileHandle)
	{
		// Check if the renamed file is virus stub. If so delete renamed file also.
		DWORD dwBytesRead = 0;
		if(m_dwFileSize == GetFileSize(hOrgFileHandle, 0))
		{
			// Check header to confirm the file is virus stub
			BYTE byOriFileData[HDR_SIZE] = {0};			
			SetFilePointer(hOrgFileHandle, 0, 0, FILE_BEGIN);
			ReadFile(hOrgFileHandle, byOriFileData, dwBytesToRead, &dwBytesRead, 0x00);
			if(dwBytesRead == dwBytesToRead)
			{
				if(memcmp(byOriFileData, byInfectedFileData, dwBytesToRead) == 0)
				{
					if (INVALID_HANDLE_VALUE != hOrgFileHandle)
					{
						CloseHandle(hOrgFileHandle);
					}
					DeleteFile(csRenamedFilePath);
					return true;
				}
			}
		}
		if(m_dwArgs[1] == 2)
		{
			DecryptRenamedFile(hOrgFileHandle);			
		}

		DWORD	dwMZ = 0;
		SetFilePointer(hOrgFileHandle, 0, 0, FILE_BEGIN);
		ReadFile(hOrgFileHandle, &dwMZ, sizeof(WORD), &dwBytesRead, 0x00);
		if(m_dwArgs[3])
		{
			SetFilePointer(hOrgFileHandle, GetFileSize(hOrgFileHandle, 0) - m_dwArgs[4], 0, FILE_BEGIN);
			SetEndOfFile(hOrgFileHandle);
		}
		if (INVALID_HANDLE_VALUE != hOrgFileHandle)
		{
			CloseHandle(hOrgFileHandle);
		}
				
		if(dwBytesRead == sizeof(WORD))
		{
			if(dwMZ == 0x5A4D)
			{
				// Rename the renamed file with currently scanning virus file name.
				MoveFile(csRenamedFilePath, m_csFilePath);
			}
		}
	}
	// In error case if Renamed file does not exists we cannt recover original 
	// file  so just deleted the virus stub. Return true as virus file is deleted	
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: RepairApathy
In Parameters	: 
Out Parameters	: bool
Purpose			: Repair Virus.W32.Weird.D 
Author			: ADNAN
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairApathy()
{	
	m_bInternalCall=true;
	bool bRet=false;

	m_dwArgs[0]=0x1FFF;
	bRet=CheckForVirusStub();
	if(!bRet)
		return true;

	DWORD dwFileSize = m_dwFileSize - 0x1502;

	m_dwArgs[0] = dwFileSize;
	m_dwArgs[1] = 0x1502;
	m_dwArgs[2] = 0;
	bRet = ReplaceOriginalData();
	if(!bRet)
		return false;

	m_dwArgs[0] = dwFileSize;
	bRet=SetFileEnd();
	if(!bRet)
		return false;

	//Decryption Starts from Here
	DWORD EDI=0x0,dwTemp=0x0,EAX=0x0,dwBytesRead=0x0,ESI=0x0,EBX=0x0,ECX=0x0,EBX1=0x0,dwcount=0x0;
	WORD bTemp=0x0;

	if(!m_pMaxPEFile->ReadBuffer(&dwTemp, 0x3c, sizeof(DWORD)))
		return false;

	EDI+=dwTemp;
	
	if(!m_pMaxPEFile->ReadBuffer(&EAX, EDI + 0x88, sizeof(DWORD)))
		return false;

	EDI+=0x104;
				
	if(!m_pMaxPEFile->ReadBuffer(&dwTemp, EDI, sizeof(DWORD)))
		return false;

	while(EAX != dwTemp)
	{
		EDI+=0x28;
					
		if(!m_pMaxPEFile->ReadBuffer(&dwTemp, EDI, sizeof(DWORD)))
			return false;		
	}
	
	if(!m_pMaxPEFile->ReadBuffer(&ESI, EDI+0x8, sizeof(DWORD)))
		return false;

	EBX = 0x4000 - EAX;
	while(1)
	{
		ESI+=0x10;
		
		if(!m_pMaxPEFile->ReadBuffer(&bTemp, ESI - 0x2, sizeof(WORD)))
			return false;

		ECX=(DWORD)bTemp;
		
		dwBytesRead=0x00;
		
		if(!m_pMaxPEFile->ReadBuffer(&bTemp, ESI-0x4, sizeof(WORD)))
			return false;

		ECX+=bTemp;
		while(ECX!=0x00)
		{
			if(!m_pMaxPEFile->ReadBuffer(&EBX1, ESI+4, sizeof(DWORD)))
				return false;

			if(!(EBX1 & 0x80000000))
			{
				dwcount++;
			}
			ESI+=0x8;
			
			if(ECX>0x00)
				ECX--;
		}
		
		if(!m_pMaxPEFile->ReadBuffer(&dwTemp, ESI, sizeof(DWORD)))
			return false;

		if(dwTemp!=0x00)
			break;
	}
	while(dwcount!=0)
	{
		if(!m_pMaxPEFile->ReadBuffer(&dwTemp, ESI, sizeof(DWORD)))
			return false;
		
		dwTemp-=EBX;
		
		if(!m_pMaxPEFile->WriteBuffer(&dwTemp, ESI, 0x4, 0x4))
			return false;
		
		ESI+=0x10;
		
		if(dwcount>0x00)
			dwcount--;
	}
	return true;

}

/*-------------------------------------------------------------------------------------
Function		: RepairSalityByteXOR
In Parameters	: 
Out Parameters	: bool
Purpose			: Repair Virus.W32.Sality three Variant
Author			: Manjunath
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairSalityByteXOR()
{
	if(!m_bInternalCall)
	{
		GetParameters();
	}
	m_bInternalCall = true;
	
	DWORD dwDecBuffSize = m_dwArgs[0];
	DWORD dwMainKeyOffset = m_dwArgs[1];
	DWORD dwExtraByteOffset = m_dwArgs[2];

	//Virus allocates dwDecBuffSize bytes and reads (dwDecBuffSize - 1) bytes
	//Check for stub
	if((dwDecBuffSize + 0x100) >= m_dwFileSize)
	{
		m_dwArgs[0] = m_dwFileSize;
		m_dwArgs[1] = 0;
		return CheckForVirusStub();
	}

	WORD wSubVal = 0;
	if(!m_pMaxPEFile->ReadBuffer(&wSubVal, 0x300, sizeof(WORD), sizeof(WORD)))
		return false;

	DWORD dwDecStartOffset = m_dwFileSize - (dwDecBuffSize - 0x01) - wSubVal;
	
	m_dwArgs[0]=dwDecStartOffset;
	m_dwArgs[1]=dwDecBuffSize;
	if(!GetBufferforDecryption())
		return false;

	if(m_dwSizeofBuff < (dwDecBuffSize - 0x01))
		return false;
	
	BYTE MainKeyBuff[0x0C] = {0};			
	if(!m_pMaxPEFile->ReadBuffer(&MainKeyBuff[1], dwMainKeyOffset, 0x0A, 0x0A))
		return false;

	DWORD dwTempVal = 0x00, dwEAX, dwESI;
	for(dwESI = 0x01; dwESI <= 0x0A; dwESI++)
	{
		dwEAX = MainKeyBuff[dwESI];
		dwEAX += dwTempVal;
		dwEAX++;
		dwTempVal = dwEAX;
	}

	DWORD dwEBX = 0, dwECX = 0, dwEDX = 0, dwDecLength = dwDecBuffSize - 0x02;
	BYTE qwBuff[0x08], byBL;
	_int64 qwValue;

	//Decrypt Original file code
	for(dwESI = 0x00;  dwDecLength >= dwESI; dwESI++)
	{
		dwEDX = 0x00;
		byBL = m_byReadBuffer[dwESI];
		dwEAX = dwESI;
		dwEAX--;
		dwECX = 0x0A;

		dwEDX -= (dwEAX >> (sizeof(DWORD) * CHAR_BIT - 1)); //CDQ instruction

		//IDIV ECX instruction
		memcpy(&qwBuff[0], &dwEAX, 4);
		memcpy(&qwBuff[4], &dwEDX, 4);
		qwValue = *(_int64 *)&qwBuff[0];
		
		dwEAX = (DWORD)(qwValue / dwECX);
		dwEDX = (DWORD)(qwValue % dwECX);
		/////

		dwEDX++;
		byBL ^= MainKeyBuff[dwEDX];
		dwEBX = byBL;

		dwEAX = dwTempVal;
		dwEAX *= dwESI;
		dwEBX ^= dwEAX;

		m_byReadBuffer[dwESI] = LOBYTE(dwEBX);
	}
	m_byReadBuffer[0] = 0x4D;
	m_byReadBuffer[1] = 0x5A;

	//Decrypt remaining bytes related to virus
	BYTE TmpBuff[0x16] = {0};			
	if(!m_pMaxPEFile->ReadBuffer(&TmpBuff[1], dwExtraByteOffset, 0x14, 0x14))
		return false;

	dwEAX = dwEBX = dwECX = dwEDX = dwESI = 0x00;
	for(dwESI = 0x01;  dwESI <= 0x14; dwESI++)
	{
		dwEDX = 0x00;
		byBL = TmpBuff[dwESI];
		dwEAX = dwESI;
		dwEAX--;
		dwECX = 0x0A;

		dwEDX -= (dwEAX >> (sizeof(DWORD) * CHAR_BIT - 1)); //CDQ instruction

		//IDIV ECX instruction
		memcpy(&qwBuff[0], &dwEAX, 4);
		memcpy(&qwBuff[4], &dwEDX, 4);
		qwValue = *(_int64 *)&qwBuff[0];
		
		dwEAX = (DWORD)(qwValue / dwECX);
		dwEDX = (DWORD)(qwValue % dwECX);
		/////

		dwEDX++;
		byBL ^= MainKeyBuff[dwEDX];
		dwEBX = byBL;

		dwEAX = dwESI;
		dwEAX += 0xBB8;
		m_byReadBuffer[dwEAX] = LOBYTE(dwEBX);
	}
	////
	
	m_dwArgs[0]=0x00;
	m_dwArgs[1]=(dwDecBuffSize - 0x01);
	if(!ReplaceDataInReadBuffer(/*0x00, (dwDecBuffSize - 0x01)*/))
		return false;
	
	m_dwArgs[0]=dwDecStartOffset;
	SetFileEnd();

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: ScriptRepair
	In Parameters	: char *szTagStart, char *szTagEnd, int iRepairOffset
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Added on 26 Feb 07 for calculation of section allignment
--------------------------------------------------------------------------------------*/
bool CRepairModuls::CalculateSectionAlignment()
{
	for(WORD i=0; i <= m_wNoOfSecs - 1; i++)
	{
		if((m_pSectionHeader[i].VirtualAddress != 0x00) && (m_pSectionHeader[i].VirtualAddress != m_pMaxPEFile->m_stPEHeader.SectionAlignment))
		{
			return m_pMaxPEFile->RepairOptionalHeader(0x0B, m_pSectionHeader[i].VirtualAddress, 0);
		}
	}
	return true;
}
// End

// Modified by Rupali on 12 Mar 11. Integrated changes by YAsh for skipped samples.
/*-------------------------------------------------------------------------------------
Function		: RepairVelost123341
In Parameters	: None
Out Parameters	: bool
Author			: Yash + Neeraj
Purpose			: To Repair Velostinfected Files
					+ First Find AEP check it is correct AEP or Wrong AEP.
					+ If Wrong AEP then again check for Correct AEP.
					+ Remove Dead Code from Last Section
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairVelost123341()
{	
	BYTE byRead[0x10]	= {0x00};
	BYTE byForSearch[]	= {0x60,0xE8,0x0A,0x00,0x00,0x00,0x64,0x67,0x8B,0x26,0x00,0x00,0xFF,0x64,0x24,0x28};
	BYTE byReadBuffer[0x300] = {0x00};
	DWORD dwBytesRead=0x00;

	bool bInfectedAEP = false;
	
	int	iLastSectionNo = m_wNoOfSecs - 1;
	
	// Find for AEP in virus code 
	DWORD dwFoundAEP_RVA = FindAEPForVelost(m_dwAEPMapped);
	
	//Loop for AEP Find and AEP check		
	while(dwFoundAEP_RVA)
	{
		DWORD dwFoundAEP	= GetMappedAddress(dwFoundAEP_RVA);
		DWORD dwOriginalAEP = dwFoundAEP_RVA;
		dwFoundAEP_RVA		= 0;
		bInfectedAEP		= false;

		for(int i = 0; i <= iLastSectionNo; i++)
		{
			//Is current AEP and found AEP is in Same Section
			if( m_dwAEPMapped >= m_pSectionHeader[i].PointerToRawData &&
				m_dwAEPMapped <= m_pSectionHeader[i].PointerToRawData + m_pSectionHeader[i].SizeOfRawData &&
				dwFoundAEP >= m_pSectionHeader[i].PointerToRawData && 
				dwFoundAEP <= m_pSectionHeader[i].PointerToRawData + m_pSectionHeader[i].SizeOfRawData)
			{
				if(!m_pMaxPEFile->ReadBuffer(byRead, dwFoundAEP, 0x10, 0x10))
					return false;

				//Check for Velost infected AEP 
				if(memcmp(byRead, byForSearch, 0x10)==0)
				{
					dwFoundAEP_RVA = FindAEPForVelost(dwFoundAEP);
					if(dwFoundAEP_RVA)
					{
						bInfectedAEP = true;
					}
				}
				break;
			}
		}
		if(!bInfectedAEP)
		{
			m_bInternalCall = true;
			m_dwArgs[0] = dwOriginalAEP;
			if(!RewriteAddressOfEntryPoint())
				return false;
			m_bInternalCall = false;
			m_dwReturnValues[0] = m_dwAEPMapped;
		}
	}

	// Check for virus deadcode in the file if so remove it
	
	//Search for deadcode in lower part of the last section 
	DWORD dwReadOffset = m_pSectionHeader[iLastSectionNo].PointerToRawData + 
						m_pSectionHeader[iLastSectionNo].SizeOfRawData - 0x1000;

	DWORD dwBytesToRead = 0x200;

	//if dwReadOffset is negative value or in second last section
	if(m_pSectionHeader[iLastSectionNo].PointerToRawData > dwReadOffset)
	{
		dwReadOffset = m_pSectionHeader[iLastSectionNo].PointerToRawData;
	}

	//BYTE	byForSearch2[] = {0xF8,0xBC,0x12,0x00,0x00,0x00,0x00,0x00,0xC8,0x05,0x91,0x7C,0x98,0x20};
	BYTE	byForSearch2[] = {0xC8,0x05,0x91,0x7C,0x98,0x20,0x0A,0x00,0xDC,0xCD,0x07,0x00,0x51,0x05};
	DWORD	dwCount = 0x00;
	bool	bFileEnd = false;

	//Loop for Dead Code Removal reading bytes in chunks of 0x200 bytes
	while(!bFileEnd)
	{			
		if(!m_pMaxPEFile->ReadBuffer(byReadBuffer, dwReadOffset + dwCount, dwBytesToRead, 0, &dwBytesRead))
		{
			break;
		}
		for(DWORD dw = 0; dw < dwBytesRead - 0x10; dw++)
		{
			if(memcmp(&byReadBuffer[dw], byForSearch, 0x10) == 0)
			{
				m_dwReturnValues[0] = dwReadOffset + dwCount + dw;
				bFileEnd = true;
				break;
			}
			if(memcmp(&byReadBuffer[dw], byForSearch2, 14) == 0)
			{
				m_dwReturnValues[0] = dwReadOffset + dwCount + dw - 0x70;					
				bFileEnd = true;
				break;
			}
		}		
		dwCount += dwBytesToRead;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: FindAEPForVelost
In Parameters	: dwOffSet Offset for AEP Search
Out Parameters	: DWORD dwOAEP
Author			: Yash + Neeraj
Purpose			: Find Original AEP and return.
--------------------------------------------------------------------------------------*/
DWORD CRepairModuls::FindAEPForVelost(DWORD dwOffSet)
{
	BYTE byReadBuffer[0x300]={0x00};			
	if(!m_pMaxPEFile->ReadBuffer(byReadBuffer, dwOffSet, 0x300, 0x300))
		return 0;

	BYTE byDWORD[] = {0x00, 0x58, 0x61, 0x68};
	for(DWORD dwCount = 0; dwCount < 0x300; dwCount++)
	{
		if(memcmp(&byReadBuffer[dwCount], byDWORD, 4) == 0)
		{
			DWORD dwAEP =(*(DWORD *)&byReadBuffer[dwCount + 4]);
			dwAEP -= m_pMaxPEFile->m_stPEHeader.ImageBase;
			// Added by Rupali on 24 Mar 11. Fix for corrupt samples.
			if(GetMappedAddress(dwAEP) != dwOffSet)
				return dwAEP;
			break;
			// End
		}
	}
	return 0;
}
// End

/******************************************************************************
Function Name	        :	RepairWin32Renamer
Author			:	omkar	
Input			:	csFilePath  
Output			:       
Modified		:       Ramandeep -> For "Docx Renamer trojan" use 2nd param as '2' and 3rd param 
                                as folder name created by trojan where the original doc's are hidden.
                                Use:23#[C14][C2][T746864753368]
					
*******************************************************************************/
bool CRepairModuls::RepairRenamer()
{
	WORD	wLastSecNo		 = m_wNoOfSecs - 1;
	DWORD	dwStartOfOverlay = m_pSectionHeader[wLastSecNo].PointerToRawData + 
								m_pSectionHeader[wLastSecNo].SizeOfRawData;

	const	DWORD dwChunkSize	= 0x1000; 
	BYTE	bBuffer[dwChunkSize]= {0x00};
	
	//wshacker signature string
	const BYTE WSHACKER[0x09] = {0x77,0x73,0x77,0x68,0x61,0x63,0x6B,0x65,0x72};
	
	DWORD	dwBytesRead = 0x00; 
		
	if(m_dwArgs[1]!=2)
	{
		// Read file from the end of the file.
		for(DWORD dwOffset = m_dwFileSize - dwChunkSize; dwOffset >= (dwStartOfOverlay - dwChunkSize); dwOffset -= 0x1000)
		{
			dwBytesRead = 0;
			memset(bBuffer, 0, sizeof(bBuffer));
			
			m_pMaxPEFile->ReadBuffer(bBuffer, dwOffset, dwChunkSize, 0, &dwBytesRead);
			if(dwBytesRead <= 0)
				break;

			for(int iSigOffset = dwBytesRead - 1; iSigOffset >= 0; iSigOffset--)
			{
				if(_memicmp(&bBuffer[iSigOffset], WSHACKER, sizeof(WSHACKER)) == 0)
				{
					// Found signature string
					iSigOffset += dwOffset + 0xD;
			
					// Copy original file from found offset
					if(CopyData(iSigOffset, 0, m_dwFileSize - iSigOffset))
					{
						m_bInternalCall = true;
						m_dwArgs[0]		= m_dwFileSize - iSigOffset;
						if(SetFileEnd())
						{
							m_bInternalCall = false;
							
							// Virus appends .exe extension to the original file so remove the extension
							TCHAR szOrgFileName[MAX_PATH];						
							_tcscpy_s(szOrgFileName, MAX_PATH, m_csFilePath);
							LPTSTR lptPtr = _tcsrchr(szOrgFileName, _T('.'));
							if(lptPtr)
							{
								*lptPtr = 0; 
								m_pMaxPEFile->CloseFile(); 
								MoveFile(m_csFilePath, szOrgFileName);
								return true;
							}
						}
					}// end of if loop and we replaced orignal data
					return false;
				}
			}			
			// To cover if signature string lies on chunck boundries
			dwOffset += sizeof(WSHACKER);
		} // end while outer

		return false;
	}
	//Docx Renamer trojan
	//if(detection done)
	if(2==m_dwArgs[1] && m_byArg)
	{

		TCHAR szFilePath[MAX_PATH] ={0};
		TCHAR szFileOriPath[MAX_PATH] ={0};

		_tcscpy_s(szFilePath,MAX_PATH, m_pMaxPEFile->m_szFilePath);
		LPTSTR lptPtr = _tcsrchr(szFilePath, _T('.exe'));

		

			if (lptPtr)
			{
				*lptPtr = 0; 
				//copy file name hear
				_tcscpy_s(szFileOriPath,MAX_PATH,szFilePath);
				size_t iRet=0;
				LPTSTR lptPtrSlash = _tcsrchr(szFilePath, _T('\\'));
				TCHAR szFileName[MAX_PATH] ={0},szDirName[MAX_PATH]={0}; 
				_tcscpy_s(szFileName,MAX_PATH, lptPtrSlash);
				*lptPtrSlash = 0;

				wcscat(szFilePath,_T("\\"));

				mbstowcs_s(&iRet,szDirName,MAX_INPUT_STR_PARAM, (const char*)m_byArg, MAX_INPUT_STR_PARAM);
				
				wcscat(szFilePath,szDirName);//pick up folder name from exe				
				wcscat(szFilePath,szFileName);
				DWORD dwAttributes;
				dwAttributes=FILE_ATTRIBUTE_NORMAL ;
				SetFileAttributes(szFilePath, dwAttributes);
				//_tccpy(szFilePath,szFileName);				
				if(!MoveFile(szFilePath,szFileOriPath))	return true;
				
				HANDLE dwRet= CreateFile(szFileOriPath,GENERIC_READ,FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);				
				if(INVALID_HANDLE_VALUE == dwRet)
				{
					return true;
				}

				CloseHandle(dwRet);
				return true;
			}

	}
	return false;
	//End Docx Renamer trojan
}


/*-------------------------------------------------------------------------------------
	Function		: RepairOtwycalG
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Added special repair for virus Otwycal.G by Ravi.
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairOtwycalG()
{	
	DWORD dwOriginalAEP = 0;				
	if(!m_pMaxPEFile->ReadBuffer(&dwOriginalAEP, m_dwAEPMapped + 0x2BC, sizeof(DWORD), sizeof(DWORD)))
	{
		return false;
	}

	DWORD dwAEPSec = m_pMaxPEFile->Rva2FileOffset(m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint, NULL);
	DWORD dwAEPSecRVA = m_pSectionHeader[dwAEPSec].VirtualAddress;

	dwOriginalAEP -= m_pMaxPEFile->m_stPEHeader.ImageBase;
	if(dwOriginalAEP == dwAEPSecRVA)
	{
		if(!m_pMaxPEFile->ReadBuffer(&dwOriginalAEP, dwAEPSecRVA + 0x1, sizeof(DWORD), sizeof(DWORD)))
		{
			return false;
		}
		dwOriginalAEP += dwAEPSecRVA + 5;
	}

	if(!m_pMaxPEFile->WriteAEP(dwOriginalAEP))
		return false;
	
	if(!m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, 0x188))
		return false;
	
	 return m_pMaxPEFile->TruncateFile(m_dwAEPMapped + 0x188, true);
}



/*-------------------------------------------------------------------------------------
	Function		: RepairWarray
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Added special repair for virus Warray by Neeraj.
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairWarray()
{	
	//Delete the virus stub/file
	if(!RepairDelete())
		return false;

	wchar_t szExtension[MAX_INPUT_STR_PARAM] = {0};	
	if(m_ibyArgLen)
	{
		size_t iRet = 0;
		mbstowcs_s(&iRet, szExtension, MAX_INPUT_STR_PARAM, (const char*)m_byArg, MAX_INPUT_STR_PARAM);
	}

	//Virus keeps name of the file which has the original file in .WAR file
	CString csWarFilePath = m_csFilePath, csFinalPath = L"";
	bool bFileFound = false;

	while(1)
	{
		int iLength = csWarFilePath.ReverseFind(_T('.'));	
		if(iLength == -1)
			return true;
		
		csWarFilePath = csWarFilePath.Left(iLength);	
		csWarFilePath.Append(szExtension); 

		if(_taccess_s(csWarFilePath, 0))
		{
			break;
		}

		// Open the .war file to read file name
		HANDLE hOrgFileHandle = CreateFile( csWarFilePath,
											GENERIC_READ, 
											FILE_SHARE_READ, 
											NULL, 
											OPEN_EXISTING, 
											FILE_ATTRIBUTE_NORMAL, 
											NULL);	
		if (INVALID_HANDLE_VALUE == hOrgFileHandle)
		{
			return true;
		}
		
		//Read name of file which contain original data
		BYTE	byBuffer[MAX_PATH]	= {0x00};
		DWORD	dwBytesRead			= 0x00;
		
		SetFilePointer(hOrgFileHandle,0, 0, FILE_BEGIN);
		ReadFile(hOrgFileHandle, byBuffer, MAX_PATH, &dwBytesRead, 0); 
		if(dwBytesRead)
		{
			// Form the file path to get the original file
			iLength = csWarFilePath.ReverseFind(_T('\\'));
			if(iLength == -1)
			{
				CloseHandle(hOrgFileHandle);
				return true;
			}
			csFinalPath = csWarFilePath.Left(iLength);
			
			wchar_t szOriFileName[MAX_PATH] = {0};
			size_t iRet = 0;
			mbstowcs_s(&iRet, szOriFileName, MAX_PATH, (const char*)byBuffer, MAX_PATH);
			if(-1 == CString(szOriFileName).Find(L":\\"))
			{
				// File contains just original file name
				csFinalPath.AppendFormat(L"\\%s", szOriFileName); 
			}
			else
			{
				// File contains full path of original file 
				csFinalPath = szOriFileName; 
				csFinalPath  = csFinalPath .Mid(csFinalPath.Find(L":\\") -1);
			}
		}
		
		// We are done with .war file so delete it
		CloseHandle(hOrgFileHandle);
		SetFileAttributes(csWarFilePath, FILE_ATTRIBUTE_NORMAL);
		DeleteFile(csWarFilePath);
		
		csWarFilePath = csFinalPath;
	}

	if(csFinalPath.IsEmpty())
	{
		return true;
	}
	SetFileAttributes(csFinalPath, FILE_ATTRIBUTE_NORMAL);

	if(0 == _taccess_s(csFinalPath, 0))
	{
		MoveFile((LPCWSTR)csFinalPath, (LPCWSTR)m_csFilePath);	
	}
	return true;
}
// End


/*-------------------------------------------------------------------------------------
	Function		: Repair_HLLC_Ext
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Added special repair for virus HLLC.Ext by Prajkta.
--------------------------------------------------------------------------------------*/
bool CRepairModuls::Repair_HLLC_Ext()
{
	const TCHAR	Extensions[][5] = { _T(".JHG"), _T(".ETR"), _T(".DER"), _T(".OIY"), 
									_T(".PLK"), _T(".BCF"), _T(".WRD"), _T(".VCD"),
									_T(".ADE"), _T(".AAS"), _T(".JNV"), _T(".WNX"), 
									_T(".CXZ"), _T(".POI"), _T(".NUT"), _T(".YTY"),
									_T(".PLP"), _T(".7WE"), _T(".D0F"), _T(".8JM"), 
									_T(".BZA"), _T(".IAL"), _T(".WDW"), _T(".QWE"),
									_T(".RFV"), _T(".PMN"), _T(".MEM"),  _T(".ddd")	};

	TCHAR szFilePath[MAX_PATH] = {0}; 
	_tcscpy_s(szFilePath, MAX_PATH, m_csFilePath);
	LPTSTR lptPtr = _tcsrchr (szFilePath, _T('.'));
	if(!lptPtr)
		return false;
	
	*lptPtr = '\0';
	int strLen = _tcslen(szFilePath);

	for(int iCnt = 0; iCnt < _countof(Extensions); iCnt++)
	{				
		szFilePath[strLen] = '\0';
		_tcscat_s(szFilePath, MAX_PATH, Extensions[iCnt]);
		if(_taccess(szFilePath, 0) == 0)
		{
			m_ibyArgLen = _tcslen(Extensions[iCnt]);
			size_t iRet = 0;
			wcstombs_s(&iRet, (char *)m_byArg, MAX_INPUT_STR_PARAM, (wchar_t *)Extensions[iCnt], MAX_INPUT_STR_PARAM);
	
			if(RepairRenameFile())
			{
				return true;
			}
		}
	}
	return false;
}

// Added by Rupali on 8 Mar 2011. Added special repair for virus Brof.C.
/******************************************************************************
Function Name	:	DecryptRenamedFile
Author			:	Rupali	
Input			:	Handle of the file to decrypt 
Output			:   None
Description		:	The function decrypts the file. Presently decryption if for
					virus Brof.C
*******************************************************************************/
void CRepairModuls::DecryptRenamedFile(HANDLE hFileHandle)
{
	BYTE	bBuffer[DECRYPT_BUFF_SIZE]	= {0x00};
	DWORD	dwBytesReadWrite			= 0x00;

	SetFilePointer(hFileHandle, 0, 0, FILE_BEGIN);
	ReadFile(hFileHandle, bBuffer, DECRYPT_BUFF_SIZE, &dwBytesReadWrite, NULL);

	int iCounter	= 0x00;
	WORD wXORKey	= 0x00;
	
	if(bBuffer[0x00] != 0x4D || bBuffer[0x01] != 0x5B)
		return;

	// Decrypt the whole file. Reading file in a chunk of 1 KB and decrypt the same.
	for(int iCount = 0x00; dwBytesReadWrite != 0x00; iCount++ )
	{
		for(int i = 0, iCounter = 0x100, wXORKey = 0x00; i < (int)dwBytesReadWrite && iCounter > 0x00; i += 2, iCounter--)
		{
			wXORKey += static_cast<WORD>(iCounter);
			*((WORD*)&bBuffer[i]) ^= wXORKey;
		}

		SetFilePointer(hFileHandle, static_cast<DWORD>(iCount * DECRYPT_BUFF_SIZE), 0, FILE_BEGIN);
		WriteFile(hFileHandle, bBuffer, dwBytesReadWrite, &dwBytesReadWrite, NULL);		

		SetFilePointer(hFileHandle, static_cast<DWORD>((iCount+1)*DECRYPT_BUFF_SIZE), 0, FILE_BEGIN);
		ReadFile(hFileHandle, bBuffer, DECRYPT_BUFF_SIZE, &dwBytesReadWrite, NULL);
	}
}
// End

// Added by Rupali on 20 Apr 11. Added decryption for virus Bartel by Omkar
bool CRepairModuls::Decryption_Bartel(DWORD dwOrignalFileSize, DWORD dwKey)
{
	BYTE bRORCounter = 0, bDL = 0, bAH = (BYTE)dwKey; 

	// decryption loop
	for(DWORD dwOffset = 0; dwOffset < dwOrignalFileSize; dwOffset++)
	{
		bRORCounter = bRORCounter % 0x08;					
		
		//ROR AL,CL		 
		m_byReadBuffer[dwOffset] = m_byReadBuffer[dwOffset] >> bRORCounter | m_byReadBuffer[dwOffset] << (0x08 - bRORCounter); 

		//XOR AL,CL
		m_byReadBuffer[dwOffset] ^= bDL;					 

		//XOR AL,AH
		m_byReadBuffer[dwOffset] ^= bAH;

		bDL++;
		bRORCounter++;						
	}
	return true;
}
// End


/*-------------------------------------------------------------------------------------
	Function		: Decryption_Artelad_2173
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Added special repair for virus Artelad by Prajkta.
--------------------------------------------------------------------------------------*/
bool CRepairModuls::Decryption_Artelad_2173(DWORD  dwKey1, DWORD dwKey2)
{
	DWORD dwRotateCounter = 0x21 % sizeof(DWORD);
	for(DWORD i = 0; i < 8; i += 4)
	{
		*((DWORD *) &m_byReadBuffer[i]) = _lrotl(*((DWORD *) &m_byReadBuffer[i]), dwRotateCounter);
		*((DWORD *) &m_byReadBuffer[i]) = 0x00 - *((DWORD *) &m_byReadBuffer[i]);
		*((DWORD *) &m_byReadBuffer[i]) = (~(*((DWORD *) &m_byReadBuffer[i]))); 
		*((DWORD *) &m_byReadBuffer[i]) = *((DWORD *) &m_byReadBuffer[i]) ^ dwKey1;
		*((DWORD *) &m_byReadBuffer[i]) = *((DWORD *) &m_byReadBuffer[i]) + dwKey2;
	}
			 
	*((DWORD *) &m_byReadBuffer[0x00]) = *((DWORD *) &m_byReadBuffer[0x03]);
	m_dwReturnValues[0] =  *((DWORD *) m_byReadBuffer);
	return true;
}
// End


/*-------------------------------------------------------------------------------------
	Function		: RepairStream
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Added special repair for stream viruses.
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairStream()
{	
	bool	bRet = false;	

	wchar_t szExtension[MAX_INPUT_STR_PARAM] = {0};	
	if(m_ibyArgLen)
	{
		size_t iRet = 0;
		mbstowcs_s(&iRet, szExtension, MAX_INPUT_STR_PARAM, (const char*)m_byArg, MAX_INPUT_STR_PARAM);
	}

	CString csSTRFilePath = m_csFilePath + szExtension;

	CString csTempFilePath = m_csFilePath + L".tmp";
	
	HANDLE hStreamFile = CreateFile(csSTRFilePath, 
									GENERIC_READ, 
									0, 
									NULL, 
									OPEN_EXISTING, 
									FILE_ATTRIBUTE_NORMAL, 
									NULL);	
	
	if (INVALID_HANDLE_VALUE != hStreamFile)
	{		
		HANDLE hOriFile = CreateFile(csTempFilePath,
									GENERIC_READ | GENERIC_WRITE,
									0,
									NULL,
									CREATE_ALWAYS,
									FILE_ATTRIBUTE_NORMAL,
									NULL);	
		if (INVALID_HANDLE_VALUE != hOriFile)
		{
			const DWORD dwChunkSize = 0x10000;
			BYTE  *pbBuffer = new BYTE[dwChunkSize];
			if(pbBuffer)
			{
				DWORD dwBytesRead = 0, dwBytesWritten = 0;
				while(1)
				{
					dwBytesRead = 0x00;
					memset(pbBuffer, 0, dwChunkSize);			
					ReadFile(hStreamFile, pbBuffer, dwChunkSize, &dwBytesRead, NULL);
					WriteFile(hOriFile, pbBuffer, dwBytesRead, &dwBytesWritten, NULL);
					if(dwBytesRead < dwChunkSize)
					{		
						bRet = true;
						break;
					}
				}
				delete []pbBuffer;
			}
			CloseHandle(hStreamFile);			
		}
		CloseHandle(hOriFile);
	}
	if(!RepairDelete())
		return false;
	
	if(bRet)
	{
		MoveFile(csTempFilePath, m_csFilePath);
	}		
	return bRet; 
}
// End

/*-------------------------------------------------------------------------------------
	Function		: Decryption_Lamewin
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Added special repair and decryption for virus Decryption_Lamewin.
--------------------------------------------------------------------------------------*/
bool CRepairModuls::Decryption_Lamewin()
{
	DWORD dwDecryptionKey = 0, dwKey = m_dwAEPMapped;

	for(int i = 0; i < 4; i++)
	{ 
		dwDecryptionKey += LOBYTE(dwKey);
		dwKey = dwKey >> 8;
	}

	for(DWORD dwOffset = 0; dwOffset < 6;dwOffset++)
	{
		m_byReadBuffer[dwOffset] ^= LOBYTE(dwDecryptionKey);
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: Decryption_Killis
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Added special repair and decryption for virus Killis.
--------------------------------------------------------------------------------------*/
bool CRepairModuls::Decryption_Killis()
{
	if(m_dwArgs[0] == 0x00 || m_dwArgs[1] == 0x00)
		return false;

	m_dwStartofDecryption = m_dwArgs[0];
	m_dwDecryptionLength  = m_dwArgs[1];
	BYTE bDecKey = static_cast<BYTE>(m_dwArgs[3]);

	
	WORD wCounter = static_cast<WORD>(m_dwArgs[1]); 
	for(int i = m_dwArgs[1] - 1; i >= 0; i--)
	{
		bDecKey ^= static_cast<BYTE>(wCounter);
		m_byReadBuffer[i] ^= bDecKey;
		wCounter--;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: RepairNemsiB
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Added special repair for virus Nemsi.B.
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairNemsiB()
{
	bool bRet = false;
	
	if(m_dwFileSize == (m_pMaxPEFile->m_stSectionHeader[m_wNoOfSecs-1].PointerToRawData + 
		m_pMaxPEFile->m_stSectionHeader[m_wNoOfSecs-1].SizeOfRawData))
	{
		return RepairDelete();
	}
	DWORD dwOriFileSize = m_dwFileSize -  m_dwArgs[1] - m_dwArgs[3];
	if(!CopyData( m_dwArgs[1], 0, dwOriFileSize))
		return bRet;

	m_dwArgs[0] = dwOriFileSize;
	m_bInternalCall = true;
	if(!SetFileEnd())
		return bRet;

	DWORD dwTemp = 0x00, dwBytesRead = 0x00;
			
	if(!m_pMaxPEFile->ReadBuffer(&dwTemp, 0x3C, sizeof(DWORD), sizeof(DWORD)))
		return bRet;

	dwTemp += 0x2C;
			
	if(!m_pMaxPEFile->ReadBuffer(&dwTemp, dwTemp, sizeof(DWORD), sizeof(DWORD)))
		return bRet;

	dwTemp = GetMappedAddress(dwTemp);
	if(!dwTemp)
		return bRet;

	m_byReadBuffer = new BYTE[NEMSI_BUFF_SIZE];
	if(m_byReadBuffer)
	{
		memset(m_byReadBuffer, 0x00, NEMSI_BUFF_SIZE);
			
		if(m_pMaxPEFile->ReadBuffer(m_byReadBuffer, dwTemp, NEMSI_BUFF_SIZE, NEMSI_BUFF_SIZE))
		{				
			DWORD dwNemsiCounter = m_dwArgs[2];
			for(DWORD i = 0x00, j = dwNemsiCounter; i < dwNemsiCounter; i++, j++)
			{
				m_byReadBuffer[i] ^= m_byReadBuffer[j];
			}

			if(m_pMaxPEFile->WriteBuffer(m_byReadBuffer, dwTemp, dwNemsiCounter, dwNemsiCounter))
			{
				bRet = true;
			}
		}
	}
	return bRet;
}

/*-------------------------------------------------------------------------------------
	Function		: Decryption_RainSong
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Added special repair and decryption for virus RainSong.
--------------------------------------------------------------------------------------*/
bool CRepairModuls::Decryption_RainSong()
{
	DWORD dwOriginalAEP = 0 ;					
	if(m_pMaxPEFile->ReadBuffer(&dwOriginalAEP, GetMappedAddress(m_dwArgs[0]) + 11, sizeof(DWORD), sizeof(DWORD)))
	{
		DWORD dwKey = LOWORD(m_dwArgs[1]);
		dwKey <<= 16;
		m_dwArgs[1] >>= 16;
		dwKey |= m_dwArgs[1];

		dwOriginalAEP ^= dwKey;
		m_dwReturnValues[0] = ~dwOriginalAEP - m_pMaxPEFile->m_stPEHeader.ImageBase;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckAEPSection
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Trucates appnded section.
--------------------------------------------------------------------------------------*/
bool CRepairModuls::CheckAEPSection()
{
	if(m_pMaxPEFile->m_wAEPSec != m_wNoOfSecs - 1)
	{
		m_bInternalCall = true;	
		m_dwArgs[0] = m_dwArgs[1];
		m_dwArgs[1] = 0;
		if(Check4String())
		{
			switch(m_dwArgs[2])
			{
			case 0:
				{
					m_pMaxPEFile->TruncateFile(m_dwReturnValues[0], true);
				}
				break;
			case 1:
				{
					m_pMaxPEFile->FillWithZeros(m_dwReturnValues[0], m_dwArgs[3]);
				}
				break;
			}
			m_bStubDeleted = true;
		}
		m_bInternalCall = false;	
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptionOroch5420
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Description routine for Virus Oroch.5420
--------------------------------------------------------------------------------------*/
bool CRepairModuls::DecryptionOroch5420()
{
	//AEP should be last section
	if(!(m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint > 
		m_pSectionHeader[m_wNoOfSecs-1].VirtualAddress))
	{
		return false;
	}

	//Required value divided in between two DWORD operations
	//i.e last byte of dwVal2 and first 3 bytes of dwVal1

	WORD wOperationFlag = *(WORD*)(m_byReadBuffer + 0x25);				
	m_dwReturnValues[0] = 0;

	//Check Operation Flag
	switch(wOperationFlag)
	{
	case 0x85FF:
		(*(DWORD*)&m_byReadBuffer[0x130])++;
		(*(DWORD*)&m_byReadBuffer[0x12C])++;
		break;

	case 0x8DFF:
		(*(DWORD*)&m_byReadBuffer[0x130])--;
		(*(DWORD*)&m_byReadBuffer[0x12C])--;
		break;

	case 0x9DF7://NEG
		(*(DWORD*)&m_byReadBuffer[0x130]) = 0 - (*(DWORD*)&m_byReadBuffer[0x130]);
		(*(DWORD*)&m_byReadBuffer[0x12C]) = 0 - (*(DWORD*)&m_byReadBuffer[0x12C]);
		break;

	case 0x95F7://NOT
		(*(DWORD*)&m_byReadBuffer[0x130]) = ~(*(DWORD*)&m_byReadBuffer[0x130]);
		(*(DWORD*)&m_byReadBuffer[0x12C]) = ~(*(DWORD*)&m_byReadBuffer[0x12C]);
		break;
	default:
		return false;
	}	
	m_dwReturnValues[0] = *(DWORD*)&m_byReadBuffer[0x12F];
	if(!m_dwReturnValues[0])
	{
		return false;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: RepairTinitA
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Reapire routine for Virus Tinit.A
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairTinitA()
{
	DWORD	dwNoofEntryInImportTable = m_pMaxPEFile->m_stPEHeader.DataDirectory[1].Size / 20;
	DWORD	dwImportDirTableOff = GetMappedAddress(m_pMaxPEFile->m_stPEHeader.DataDirectory[1].VirtualAddress);
	if(dwImportDirTableOff == 0x00 || m_pMaxPEFile->m_stPEHeader.DataDirectory[1].Size > 0x10000)
	{
		return false;
	}

	BYTE	*bBuffer = new BYTE[m_pMaxPEFile->m_stPEHeader.DataDirectory[1].Size];
	if(bBuffer == NULL)
	{
		return false;
	}
	
	DWORD dwBytesRead = 0x00;
			
	if(!m_pMaxPEFile->ReadBuffer(bBuffer, dwImportDirTableOff, m_pMaxPEFile->m_stPEHeader.DataDirectory[1].Size, m_pMaxPEFile->m_stPEHeader.DataDirectory[1].Size))
	{
		if(bBuffer)
		{
			delete bBuffer;
			bBuffer = NULL;
		}
		return false;
	}
	
	DWORD	dwDllNameOff = 0x00;
	BYTE	byDLLNameBuff[13] = {0x00};

	char *szKernel32dll = "kernel32.dll";
	DWORD dwIndex = 0x00;
	for(dwIndex = 0x00; dwIndex < dwNoofEntryInImportTable; dwIndex++)
	{
		dwDllNameOff = GetMappedAddress(*((DWORD *) &bBuffer[dwIndex*20 + 12]));
		if(dwDllNameOff == 0x00)
		{
			if(bBuffer)
			{
				delete bBuffer;
				bBuffer = NULL;
			}
			return false;
		}
			
		if(!m_pMaxPEFile->ReadBuffer(byDLLNameBuff, dwDllNameOff, 12, 12))
		{
			if(bBuffer)
			{
				delete bBuffer;
				bBuffer = NULL;
			}
			return false;
		}
		for(DWORD dwTemp = 0x00; dwTemp < 12; dwTemp++)
		{
			byDLLNameBuff[dwTemp] = (BYTE)tolower(byDLLNameBuff[dwTemp]);
		}
		if(strcmp(szKernel32dll,(char *)byDLLNameBuff) == 0x00)
		{
			break;
		}
		memset(byDLLNameBuff, 0x00, 13);
	}

	if(dwIndex == dwNoofEntryInImportTable)
	{
		if(bBuffer)
		{
			delete bBuffer;
			bBuffer = NULL;
		}
		return false;
	}

	DWORD	dwImportAddTableOff = GetMappedAddress(*((DWORD*)&bBuffer[dwIndex*20 + 16]));
	DWORD	dwImportNameTableOff = GetMappedAddress(*((DWORD*)&bBuffer[dwIndex*20]));

	if(dwImportAddTableOff == 0x00)
	{
		if(bBuffer)
		{
			delete bBuffer;
			bBuffer = NULL;
		}
		return false;
	}
	if(bBuffer)
	{
		delete bBuffer;
		bBuffer = NULL;
	}

	DWORD	dwTemp1 = m_dwArgs[1];//Original AEP
	DWORD	dwTemp2 = m_dwArgs[2];//First write DWORD
	DWORD	dwTemp3 = m_dwArgs[3];//Second write DWORD

	m_pMaxPEFile->WriteBuffer(&dwTemp2, dwImportAddTableOff, 4);
	m_pMaxPEFile->WriteBuffer(&dwTemp3, dwImportAddTableOff + 4, 4);

	if(dwImportNameTableOff)
	{
		m_pMaxPEFile->WriteBuffer(&dwTemp2, dwImportNameTableOff, 4);
		m_pMaxPEFile->WriteBuffer(&dwTemp3, dwImportNameTableOff + 4, 4);
	}

	m_pMaxPEFile->WriteAEP(m_dwArgs[1]);
	
	m_bInternalCall = true;
	m_dwArgs[0] = 1;
	m_dwArgs[1] = 1;
	RemoveLastSection();
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: FindResourceEx
	In Parameters	: 
	Out Parameters	: Returns file offset of resource
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Finds the resource from resource table with given ID
--------------------------------------------------------------------------------------*/
DWORD CRepairModuls::FindResourceEx(LPCTSTR lpstNameID, DWORD dwRead)
{
	DWORD iRetStatus = 0x00;
	DWORD dwRsrcTableOffset = dwRead;
	
	DWORD dwRsrcTableStart = GetMappedAddress(m_pMaxPEFile->m_stPEHeader.DataDirectory[2].VirtualAddress);
	if(dwRsrcTableStart == 0x00)
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
				delete lpstRsrcName;
				lpstRsrcName = NULL;
				break;
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

	if(dwIndex == dwTotalRsrcEntry)
	{
		delete pRsrc_Dir_Entry;
		return iRetStatus;
	}
	iRetStatus = pRsrc_Dir_Entry[dwIndex].OffsetToDirectory;
	delete pRsrc_Dir_Entry;
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: FindRes
	In Parameters	: LPCTSTR lpstNameID, LPCTSTR lpstLaunguage, LPCTSTR lpstLangID, DWORD &dwRVA, DWORD &dwSize
	Out Parameters	: Returns file offset of resource
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Finds the resource from resource table with given ID
--------------------------------------------------------------------------------------*/
int CRepairModuls::FindRes(LPCTSTR lpstNameID, LPCTSTR lpstLaunguage, LPCTSTR lpstLangID, DWORD &dwRVA, DWORD &dwSize)
{
	int iRetStatus = 0x00;
	DWORD dwRsrcTableOffset = GetMappedAddress(m_pMaxPEFile->m_stPEHeader.DataDirectory[2].VirtualAddress);
	if(dwRsrcTableOffset == 0x00)
	{
		return iRetStatus;
	}
	
	DWORD dwOffset = FindResourceEx(lpstNameID,dwRsrcTableOffset);
	if(dwOffset == 0x00)
	{
		return iRetStatus;
	}
	DWORD dwReadOffset = dwRsrcTableOffset + dwOffset;
	dwOffset = FindResourceEx(lpstLaunguage,dwReadOffset); 
	if(dwOffset == 0x00)
	{
		return iRetStatus;
	}
	dwReadOffset = dwRsrcTableOffset + dwOffset;
	dwOffset = FindResourceEx(lpstLangID,dwReadOffset); 
	if(dwOffset == 0x00)
	{
		return iRetStatus;
	}
	BYTE byBuffer[0x08] = {0x00};
	dwReadOffset = dwOffset + dwRsrcTableOffset;
			
	if(!m_pMaxPEFile->ReadBuffer(byBuffer, dwReadOffset, 8, 8))
	{
		return iRetStatus;
	}
	dwRVA = *((DWORD*)&byBuffer[0]);
	dwSize = *((DWORD*)&byBuffer[4]);
	return 0x01;
}

/*-------------------------------------------------------------------------------------
	Function		: Decryption_Alisar
	In Parameters	: DWORD dwBufferSize
	Out Parameters	: true if success else flase
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Decryption and repaire routine for virus Alisar
--------------------------------------------------------------------------------------*/
bool CRepairModuls::Decryption_Alisar(DWORD dwBufferSize)
{
	BYTE *byDecryptedBuffer = new BYTE[dwBufferSize];
	for(DWORD dwIndex =0; dwIndex < dwBufferSize; dwIndex+=4)
	{
		DWORD dwKey = *(DWORD *)&m_byReadBuffer[dwIndex];
		dwKey = ~dwKey;
		DWORD dwEncDword = *(DWORD*)&m_byReadBuffer[dwIndex + 4];
		DWORD dwDecDword = dwKey ^ dwEncDword;
		memcpy(&byDecryptedBuffer[dwIndex], &dwDecDword, 4);
	}
	memset(m_byReadBuffer,0,dwBufferSize);
	memcpy(m_byReadBuffer, byDecryptedBuffer, dwBufferSize);
	if(byDecryptedBuffer)
	{
		delete byDecryptedBuffer;
		byDecryptedBuffer = NULL;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptGlkajC
	In Parameters	: BYTE* byBuffer, DWORD dwBuffSize
	Out Parameters	: true if success else flase
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Decryption and repaire routine for virus Glkaj.C
--------------------------------------------------------------------------------------*/
bool CRepairModuls::DecryptGlkajC(BYTE* byBuffer, DWORD dwBuffSize)
{
	// This virus Decrypts 0x08 bytes at a time. So 1-7 bytes cannot be decrypted. 
	// Hence do not consider those bytes for decryption.
	if(dwBuffSize < 8)
	{
		return false;
	}
	dwBuffSize -= (dwBuffSize % 0x08);

	//Primary Keys
	DWORD dwKey1 = m_dwArgs[6];
	DWORD dwKey2 = m_dwArgs[7];
	DWORD dwKey3 = m_dwArgs[8];
	DWORD dwKey4 = m_dwArgs[9];

	DWORD dwInitialKeyStat	= m_dwArgs[10];
	DWORD dwLoopKeyStat		= m_dwArgs[11];
	DWORD dwDecryptionCnt	= m_dwArgs[12];

	DWORD dwEAX = 0x00, dwECX = 0x00, dwEDX = 0x00, dwEDI = 0x00;

	DWORD dwInitialKey  = dwInitialKeyStat;
	DWORD dwLoopKey		= dwLoopKeyStat;

	if(dwDecryptionCnt > 0x20)
	{
		return false;
	}

	for(DWORD dwBuffIndex = 0x00; dwBuffIndex < dwBuffSize; dwBuffIndex += 0x08)
	{
		dwEDX = *((DWORD *)(&byBuffer[dwBuffIndex]));
		dwECX = *((DWORD *)(&byBuffer[dwBuffIndex + 0x04]));

		dwInitialKey	= dwInitialKeyStat;
		dwLoopKey		= dwLoopKeyStat;

		for(DWORD dwDecryptionCntr = 0x00; dwDecryptionCntr < dwDecryptionCnt; dwDecryptionCntr++)
		{
			//1st part
			dwEAX = dwEDX;
			dwEAX <<= 4;
			dwEAX += dwKey1;

			//2nd part
			dwEDI = dwEDX;
			dwEDI >>= 5;
			dwEDI += dwKey2;

			//3rd part
			dwEAX ^= dwEDI;

			//4th part
			dwEDI = dwInitialKey;
			dwEDI += dwEDX;

			//5th part
			dwEAX ^= dwEDI;

			//6th part
			dwECX -= dwEAX;

			//7th part
			dwEAX = dwECX;
			dwEAX <<= 4;
			dwEAX += dwKey3;

			//8th part
			dwEDI = dwECX;
			dwEDI >>= 5;
			dwEDI += dwKey4;

			//9th part
			dwEAX ^= dwEDI;

			//10th part
			dwEDI = dwInitialKey;
			
			//11th part - Altering 1st Secondary key using 2nd Secondary key
			dwInitialKey += dwLoopKey;

			//12th part
			dwEDI += dwECX;
			dwEAX ^= dwEDI;

			//13th part
			dwEDX -= dwEAX;
		}

		*((DWORD *)(&byBuffer[dwBuffIndex])) = dwEDX;
		*((DWORD *)(&byBuffer[dwBuffIndex + 0x04])) = dwECX;

	}//for	
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: RepairAssill
	In Parameters	: 
	Out Parameters	: true if success else flase
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Repaire routine for virus Assill
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairAssill()
{
	bool bRetStatus = false;
	
	//Virus save information regarding to cleaning of file at the start of overlay of infected file.
	//We read this and extract information.

	BYTE	byBuffer[0x28] = {0x00};
	DWORD dwReadOffset = m_pSectionHeader[m_wNoOfSecs-1].PointerToRawData;
	dwReadOffset += m_pSectionHeader[m_wNoOfSecs-1].SizeOfRawData + 0x64;
			
	if(!m_pMaxPEFile->ReadBuffer(byBuffer, dwReadOffset, 0x28, 0x28))
	{
		return bRetStatus;
	}
	
	DWORD	dwOriFileSize			= *((DWORD*)&byBuffer[0x0C]);
	DWORD	dwOriRsrcPRD			= *((DWORD*)&byBuffer[4]);
	DWORD	dwOriRsrcRVA			= *((DWORD*)&byBuffer[0x18]);
	DWORD	dwOriRsrcSRD			= *((DWORD*)&byBuffer[8]);
	DWORD	dwOriDataSizeAtFileEnd	= *((DWORD*)&byBuffer[0x10]);
	DWORD	dwResourcReplacementOffset = 0, dwRewriteAdd = 0;
		
	if(*((DWORD*)&byBuffer[0x00]) == 0x00)
	{
		dwResourcReplacementOffset = dwOriRsrcPRD;
		dwRewriteAdd = dwOriRsrcSRD;
	}
	else if(*((DWORD*)&byBuffer[0x00]) == 0x01)
	{
		dwResourcReplacementOffset = dwOriFileSize;
		dwRewriteAdd = dwOriRsrcPRD;
	}
	else
		return bRetStatus;

	// Copy original File resource at he end of file.
	if(!CopyData(m_pSectionHeader[m_wNoOfSecs-1].PointerToRawData,
				m_dwFileSize, 
				m_pSectionHeader[m_wNoOfSecs-1].SizeOfRawData))
	{
		return bRetStatus;
	}

	DWORD	dwNTHeaderStartOffset	= *((DWORD*)&byBuffer[0x14]);
	if(dwNTHeaderStartOffset > 0x1000)
	{
		return bRetStatus;
	}
	const int ASSILL_BUFF_SIZE = dwNTHeaderStartOffset + 0x320 + 0x100;

	if(m_byReadBuffer)
	{
		delete []m_byReadBuffer;
		m_byReadBuffer = NULL;
	}

	//Here 0x100 is given for safer side. It is not needed. 
	m_byReadBuffer = new BYTE[ASSILL_BUFF_SIZE];
	if(m_byReadBuffer == NULL)
	{
		return bRetStatus;
	}
	memset(m_byReadBuffer, 0x00, ASSILL_BUFF_SIZE);
	
	if(!m_pMaxPEFile->ReadBuffer(m_byReadBuffer, dwOriRsrcPRD, ASSILL_BUFF_SIZE, ASSILL_BUFF_SIZE))
	{
		return bRetStatus;
	}
	
	// This function decrypt original file header.
	DecryptAssill(dwNTHeaderStartOffset);
	
	//After Decryption we write decrypted buffer from we read for decryption
	if(!m_pMaxPEFile->WriteBuffer(m_byReadBuffer, dwOriRsrcPRD, ASSILL_BUFF_SIZE, ASSILL_BUFF_SIZE))
	{
		return bRetStatus;
	}

	//Here we copy decrypted bytes from start of resurce to file strt(0x00 offset)
	if(!CopyData(dwOriRsrcPRD, 0x00, dwOriRsrcSRD))
	{
		return bRetStatus;
	}
	//Here we copy 0x232c bytes from the end of file to last write finish.
	if(!CopyData(dwOriFileSize, dwRewriteAdd, dwOriDataSizeAtFileEnd))
	{
		return bRetStatus;
	}

	//Now before writing resource back we need to fix RVA in resource.
	if(m_byReadBuffer)
	{
		delete []m_byReadBuffer;
		m_byReadBuffer = NULL;
	}
	
	//If resource size is less than 0x10000 then we read whole buffer and send it to FixRes
	//otherwise 0x10000 bytes we send to FixRes as it needs only header not data so there is no harm sendin 0x10000 bytes.
	DWORD dwSizeOfRead = 0x00;
	if(m_pSectionHeader[m_wNoOfSecs-1].SizeOfRawData > 0x10000)
	{
		dwSizeOfRead = 0x10000;
	}
	else
	{
		dwSizeOfRead = m_pSectionHeader[m_wNoOfSecs-1].SizeOfRawData;
	}
	m_byReadBuffer = new BYTE[dwSizeOfRead];
	if(m_byReadBuffer == NULL)
	{
		return bRetStatus;
	}

	if(!m_pMaxPEFile->ReadBuffer(m_byReadBuffer, m_dwFileSize, dwSizeOfRead, dwSizeOfRead))
	{
		return bRetStatus;
	}

	FiXRes((IMAGE_RESOURCE_DIRECTORY*)&m_byReadBuffer[0], &m_byReadBuffer, (dwOriRsrcRVA-m_pSectionHeader[m_wNoOfSecs-1].VirtualAddress));

	//Here we write back fixed resource at the end of file and then move it its original place by using CopyData function
	if(!m_pMaxPEFile->WriteBuffer(m_byReadBuffer, m_dwFileSize, dwSizeOfRead, dwSizeOfRead))
	{
		return bRetStatus;
	}
	if(!CopyData(m_dwFileSize, dwResourcReplacementOffset, m_pSectionHeader[m_wNoOfSecs-1].SizeOfRawData))
	{
		return bRetStatus;
	}
	//Virus Save original file size so we truncate it from there.
	return m_pMaxPEFile->ForceTruncate(m_dwFileSize - 0x232C);	
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptAssill
	In Parameters	: 
	Out Parameters	: true if success else flase
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Decryption routine for virus Assill
--------------------------------------------------------------------------------------*/
void CRepairModuls::DecryptAssill(DWORD	dwNTHeaderStartOffset)
{	
	DWORD dwIndex = 0x00;
	for(dwIndex = 0x00; dwIndex < 0x96; dwIndex++)
	{
		m_byReadBuffer[dwIndex] = (0xFF - m_byReadBuffer[dwIndex]) ^ 0x0A;
	}
	for(dwIndex = 0; dwIndex < 0x320; dwIndex++)
	{
		m_byReadBuffer[dwIndex+dwNTHeaderStartOffset] = (0xFF - m_byReadBuffer[dwIndex+dwNTHeaderStartOffset]) ^ 0x0A;
	}
	DWORD dwCounter = 0x00, dwMoveNoBytes = dwNTHeaderStartOffset;
	int i = 0xC8 + dwNTHeaderStartOffset;
	BYTE byTemp = 0x00;
	
	for(dwCounter = 0x00; dwCounter < 0x65; dwCounter++, i--)
	{		
		byTemp = m_byReadBuffer[i];
		m_byReadBuffer[i] = m_byReadBuffer[i - 0x64];
		m_byReadBuffer[i -0x64]  = byTemp;
	}

	dwMoveNoBytes = dwNTHeaderStartOffset;
	i = dwMoveNoBytes - 0x01;
	int j = dwMoveNoBytes + 0x32A;
	byTemp = 0x00;
	
	for(dwCounter = 0x00; dwCounter < 0x4F; dwCounter++)
	{
		i += 0x02;
		j -= 0x0A;

		byTemp = m_byReadBuffer[i];
		m_byReadBuffer[i] = m_byReadBuffer[j];
		m_byReadBuffer[j] = byTemp;
	}

	dwMoveNoBytes = dwNTHeaderStartOffset;
	i = dwMoveNoBytes + 0x39;
	j = dwMoveNoBytes;
	byTemp = 0x00;
	for(dwCounter = 0x00; dwCounter < 0x27; dwCounter++)
	{
		i += 0x02;
		j += 0x14;

		byTemp = m_byReadBuffer[i];
		m_byReadBuffer[i] = m_byReadBuffer[j];
		m_byReadBuffer[j] = byTemp;
	}
	byTemp = m_byReadBuffer[dwNTHeaderStartOffset + 1];
	m_byReadBuffer[dwNTHeaderStartOffset + 1] = m_byReadBuffer[0];
	m_byReadBuffer[0] = m_byReadBuffer[j + 0x14];
	m_byReadBuffer[j + 0x14] = byTemp;
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: RepairWinemmem
	In Parameters	: 
	Out Parameters	: true if success else flase
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Repaire routine for virus Winemmem
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairWinemmem()
{
	if(m_dwArgs[1] >= m_pMaxPEFile->m_dwFileSize)
	{
		return RepairDelete();
	}

	DWORD dwOrgCodeOffset = m_dwArgs[1];	
	DWORD dwFileOffset, dwSize, dwRVA;

	// Maximun 10 entries need to look 
	for(int iOffset = 0, iCnt = 0; iCnt < 10; iOffset += 8, iCnt++)	
	{
		if(*((DWORD *)&m_byReadBuffer[iOffset]) == 0) 
		{
			break;
		}

		dwRVA	= *((DWORD *)&m_byReadBuffer[iOffset]) - m_pMaxPEFile->m_stPEHeader.ImageBase;
		dwSize  = *((DWORD *)&m_byReadBuffer[iOffset + 4]); 
		
		// Calculate write offset	
		m_pMaxPEFile->Rva2FileOffset(dwRVA, &dwFileOffset);  

		if(!CopyData(dwOrgCodeOffset, dwFileOffset, dwSize, 0, 0))
		{
			return false;
		}
		// Increment read offset
		dwOrgCodeOffset += dwSize;	
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: RepaireSaburex
	In Parameters	: 
	Out Parameters	: true if success else flase
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Repaire routine for virus Saburex
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepaireSaburex()
{
	// Read offset of compressed data
	if(m_dwArgs[3] > m_dwFileSize || m_dwArgs[1] == 0)
	{
		return RepairDelete();
	}
	bool bRetVal = false;  

	// m_dwSaveArgs[1] is size of compressed code
	BYTE *pbySourceMemory = new BYTE[m_dwArgs[1]];	
	if(NULL == pbySourceMemory)
	{
		return bRetVal;
	}	
	memset(pbySourceMemory, 0, m_dwArgs[1]);

	if(!m_pMaxPEFile->ReadBuffer(pbySourceMemory, m_dwArgs[3], m_dwArgs[1], m_dwArgs[1]))
	{
		return bRetVal;
	}
	
	m_dwSizeofBuff = m_dwArgs[2];
	m_byReadBuffer = new BYTE[m_dwSizeofBuff];
	if(NULL == m_byReadBuffer)
	{
		return bRetVal;
	}
	memset(m_byReadBuffer, 0, m_dwSizeofBuff);
	
	// cabinet api signature
	lstrcpyA((char *)pbySourceMemory , "MSCF");
	
	DWORD dwBytesDecrypted;
	if( DecompressMemory (pbySourceMemory, m_byReadBuffer, m_dwSaveArgs[1], dwBytesDecrypted) != NULL && 
		dwBytesDecrypted == m_dwArgs[2])  
	{
		bRetVal = true;
	}

	delete[] pbySourceMemory; 
	return bRetVal;
}

/*-------------------------------------------------------------------------------------
	Function		: mem_alloc
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Allocates Memory
--------------------------------------------------------------------------------------*/
void HUGE * FAR DIAMONDAPI CRepairModuls::mem_alloc(ULONG cb)
{
	BYTE *mem_blk = new BYTE[cb];
	return mem_blk; 
}

/*-------------------------------------------------------------------------------------
	Function		: mem_free
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Releases Memory
--------------------------------------------------------------------------------------*/
void FAR DIAMONDAPI CRepairModuls::mem_free(__in_opt void HUGE *pv)
{
	delete[] pv;
}

/*-------------------------------------------------------------------------------------
	Function		: file_open
	In Parameters	: __in LPSTR pszFile, int oflag, int pmode
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Opens Input file in given mode
--------------------------------------------------------------------------------------*/
INT_PTR FAR DIAMONDAPI CRepairModuls::file_open(__in LPSTR pszFile, int oflag, int pmode)
{
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: file_read
	In Parameters	: __in INT_PTR hf, __out_ecount(cb) void FAR *pv, UINT cb
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Reads buffer from Input file in given mode
--------------------------------------------------------------------------------------*/
UINT FAR DIAMONDAPI CRepairModuls::file_read(__in INT_PTR hf, __out_ecount(cb) void FAR *pv, UINT cb)
{
	BYTE *pbySrcPtr = m_pbySrcBytesBlk + m_dwBytesRead;
	memcpy((BYTE*)pv, pbySrcPtr, cb);
	m_dwBytesRead += cb;
	return cb;
}

/*-------------------------------------------------------------------------------------
	Function		: file_write
	In Parameters	: __in INT_PTR hf, __in_ecount(cb) void FAR *pv, UINT cb
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Writes buffer from Input file in given mode
--------------------------------------------------------------------------------------*/
UINT FAR DIAMONDAPI CRepairModuls::file_write(__in INT_PTR hf, __in_ecount(cb) void FAR *pv, UINT cb)
{
	BYTE *pbyDstPtr = m_pbyDstBytesBlk + m_dwBytesWrite;
	memcpy(pbyDstPtr, (BYTE*)pv, cb);
	m_dwBytesWrite += cb;
	return cb;
}

/*-------------------------------------------------------------------------------------
	Function		: file_close
	In Parameters	: __in INT_PTR hf, __in_ecount(cb) void FAR *pv, UINT cb
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Close file handle open for I/O
--------------------------------------------------------------------------------------*/
int FAR DIAMONDAPI CRepairModuls::file_close(__in INT_PTR hf)
{
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: file_seek
	In Parameters	: __in INT_PTR hf, long dist, int seektype
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Sets file pointer at given file address
--------------------------------------------------------------------------------------*/
long FAR DIAMONDAPI CRepairModuls::file_seek(__in INT_PTR hf, long dist, int seektype)
{
	if(seektype == 1)
	{
		m_dwBytesRead += dist;
	}
	else
	{
		m_dwBytesRead = dist;
	}
	return m_dwBytesRead;
}

/*-------------------------------------------------------------------------------------
	Function		: notification_function
	In Parameters	: FDINOTIFICATIONTYPE fdint, PFDINOTIFICATION pfdin
	Out Parameters	: 
	Purpose			: 
	Author			: Anand Shrivastava
	Description		: 
--------------------------------------------------------------------------------------*/
INT_PTR FAR DIAMONDAPI CRepairModuls::notification_function(FDINOTIFICATIONTYPE fdint, PFDINOTIFICATION pfdin)
{
	if(fdint == -1) 
	{
		return 0;
	}
	return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: DecompressMemory
	In Parameters	: BYTE *pbySourceMem, BYTE *pbyDestinationMem, DWORD dwSizeOfBlk, DWORD &dwBytesWritten
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Decompresses ( expands) given buffer in memory
--------------------------------------------------------------------------------------*/
bool CRepairModuls::DecompressMemory(BYTE *pbySourceMem, BYTE *pbyDestinationMem, DWORD dwSizeOfBlk, DWORD &dwBytesWritten)
{
	m_pbySrcBytesBlk = pbySourceMem;
	m_pbyDstBytesBlk = pbyDestinationMem;
	m_dwBytesRead	= 0;
	m_dwBytesWrite	= 0;

    ERF fdierr; 
	HFDI hfdi = FDICreate(mem_alloc, mem_free, file_open, file_read, file_write, file_close, file_seek, 0, &fdierr);	
	if(hfdi == NULL)  
	{
		  return false; 
	}
	if((FDICopy(hfdi, "", "", 0 ,notification_function, 0, 0) == FALSE) && (fdierr.erfOper != 0x04))
	{
		FDIDestroy(hfdi);
		return false; 
	}
	FDIDestroy(hfdi);
	dwBytesWritten = m_dwBytesWrite;
	if(NULL != m_pbyDstBytesBlk)
	{
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		:	WriteDWORD
In Parameters	:	m_dwArgs[0]: Write offset
					m_dwArgs[1]: Valuse to write
Out Parameters	:	bool
Purpose			:	Fucntion writes given DOWRD value to file at the offset in m_dwArgs[0]
Author			:	Rupali
--------------------------------------------------------------------------------------*/
bool CRepairModuls::WriteDWORD()
{
	bool bRetValue = false;
	if(!m_bInternalCall)
	{
		if(!GetParameters())
		{
			return bRetValue;
		}
	}
	if(m_pMaxPEFile->WriteBuffer(&m_dwArgs[0], m_dwArgs[1], 4, 4))
	{
		return true;
	}
	return bRetValue;
}

/*-------------------------------------------------------------------------------------
Function		:	RepairXorer
In Parameters	:	DWORD dwStartOfSecondDecryp, DWORD dwDisplacement, DWORD dwStubChk
					DWORD dwOrgFileStartReadOffset, DWORD dwOrgFileSizeReadOffset
					DWORD dwDecLengthReadOffset
Out Parameters	:	bool
Purpose			:	Xorer Virus Repair.
Author			:	Manjunath
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairXorer()
{
	bool bRetValue = false;
	if(!m_bInternalCall)
	{
		if(!GetParameters())
			return bRetValue;
	}

	DWORD dwStartOfSecondDecryp = m_dwArgs[0];		//The distance from the file start where second level xoring starts
	DWORD dwDisplacement = m_dwArgs[1];				//The distance between 2nd level xored location 		
	DWORD dwStubChk = m_dwArgs[2];					//Stub file size. Normally the PESize of virus file (Prepender)
	DWORD dwOrgFileOffset = m_dwArgs[3];			//Original file start offset. [It will be recalculated after finding 0xB2, 0x5A].
	DWORD dwOrgFileSize = m_dwArgs[4];				//The Original file size.
	DWORD dwDecLength = m_dwArgs[5];				//Decryption Length
	DWORD dwDecLevel = m_dwArgs[6];					//2 for 1st level, 4 for second level, 2|4 = 6 for both.
	
	if(dwStubChk != 0)
	{
		m_dwArgs[0] = dwStubChk;
		m_dwArgs[1] = 0;
		m_bInternalCall = true;
		if(!CheckForVirusStub())
			return true;
		m_bInternalCall = false;
	}

	DWORD dwBytesRead = 0;

	// Get Data To Set MZ location of Orignal File
	BYTE	byNewTemp[0x101] = {0};
	dwBytesRead = 0;
			
	if(!m_pMaxPEFile->ReadBuffer(&byNewTemp, dwOrgFileOffset, 0x101, 0x101))
	{
		return RepairDelete();
	}
	
	int i = 0;
	for(i = 0; i <= 0x100; i++)
	{
		if((dwDecLevel | 2) == dwDecLevel)
		{
			if((byNewTemp[i] == 0xB2) && (byNewTemp[i+1] == 0x5A || byNewTemp[i+1] == 0xA5))
			{
				dwOrgFileOffset += i;
				break;
			}
		}
		else
		{
			if((byNewTemp[i] == 0x4D) && (byNewTemp[i+1] == 0x5A))
			{
				dwOrgFileOffset += i;
				break;
			}
		}
	}

	if(i > 0x100)
	{
		return RepairDelete();		
	}

	//Read file size from start location of 4D 5A / B2 5A - 0x08
	if(dwOrgFileSize == 0)
		dwOrgFileSize = *(DWORD *)&byNewTemp[i- 0x8];

	//Check Original file start offset valid or not
	if((dwOrgFileOffset > m_dwFileSize) || (dwStubChk && (dwOrgFileOffset < dwStubChk)))
		return bRetValue;

	//Check original file size valid or not
	if((dwOrgFileSize > m_dwFileSize) || (dwOrgFileSize == 0))
	{
		return RepairDelete();
	}

	//Check Decryption length valid or not.
	if((dwDecLength > dwOrgFileSize))
	{
		dwDecLength = dwOrgFileSize;
	}

	if(CopyData(dwOrgFileOffset, 0, dwOrgFileSize, 5, 0xFF, dwDecLength, dwStartOfSecondDecryp ,dwDisplacement, dwDecLevel))
	{
		m_dwArgs[0] = dwOrgFileSize;
		m_bInternalCall = true;
		bRetValue = SetFileEnd();
		m_bInternalCall = false;
	}
	return bRetValue;
}

/*-------------------------------------------------------------------------------------
Function		: GetValueNextToString()
In Parameters	: Search String offset
Out Parameters	: true is success otherwise false				 
Author			: Ravi Prakash Mishra

Description: Function searched a given string in reverse order and if matched returns
number next to the string. Also saves length of the number in saved arguments
m_dwArgs[0]: Special repair case no
m_dwArgs[1]: Size of Search Buffer 
m_dwArgs[2]: To be used if string to be checked in whole buffer. Default is to 
check first occurance of the string from the end of the buffer.
m_byArg: Check string value
--------------------------------------------------------------------------------------*/
bool CRepairModuls::GetValueNextToString()
{
	const DWORD SRCH_BUFF_SIZE = m_dwArgs[1];	
	DWORD dwStartIndex = 0, dwEndIndex = 0;
	bool bFoundString = false;

	for(int iOffset = SRCH_BUFF_SIZE - m_ibyArgLen; iOffset >= 0; iOffset--)
	{   
		if(!memcmp(&m_byReadBuffer[iOffset], m_byArg, m_ibyArgLen))
		{
			bFoundString = true;
			if(m_dwArgs[2] == 0) 
			{	
				dwEndIndex = dwStartIndex = iOffset + m_ibyArgLen;
				break;
			}	 
			dwEndIndex = dwStartIndex = iOffset + m_ibyArgLen + (m_dwArgs[3] - m_ibyArgLen);
		}
	}
	if(bFoundString)
	{
		while(m_byReadBuffer[dwEndIndex] >= 0x30 && m_byReadBuffer[dwEndIndex] <= 0x39 && dwEndIndex <= SRCH_BUFF_SIZE)
		{
			dwEndIndex++;
		}
		if(dwEndIndex > dwStartIndex)
		{
			char szNumberBuff[MAX_PATH] = {0};
			strncpy_s(szNumberBuff, MAX_PATH, (char *)&m_byReadBuffer[dwStartIndex], dwEndIndex - dwStartIndex);
			m_dwReturnValues[0] = atoi(szNumberBuff);
			if(m_dwReturnValues[0] < m_dwFileSize)
			{				
				m_dwSaveArgs[m_iSaveArg++] = dwEndIndex - dwStartIndex;
				return true;
			}
		}
	}
	RepairDelete();
	return false;
}

bool CRepairModuls::Repair9XCIH()
{
	DWORD dwVirusAEP = m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint;

	m_bInternalCall = true;
	DWORD dwCavityStart = m_pMaxPEFile->m_stPEHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + (m_wNoOfSecs  * IMAGE_SIZEOF_SECTION_HEADER);

	if(dwVirusAEP > m_pSectionHeader[0].VirtualAddress)
	{
		m_dwArgs[0] = dwCavityStart;
		m_dwArgs[1] = m_pSectionHeader[0].PointerToRawData - m_dwArgs[0]; 
		FillWithZero();
		return true;
	}

	DWORD dwVirPatchAdd[10]={00};
	DWORD dwTemp = dwVirusAEP;
	DWORD dwInc = 0;		   
	DWORD dwLastSecVS = m_pSectionHeader[m_wNoOfSecs - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSecs - 1].SizeOfRawData + m_pMaxPEFile->m_stPEHeader.ImageBase;
	int j = 0;

	//Copy Address of Virus patch 
	do
	{		 
		dwInc += 0x08;
			
		m_pMaxPEFile->ReadBuffer((BYTE *)&dwVirPatchAdd[j], (dwVirusAEP - dwInc), sizeof(DWORD));
		dwTemp = dwVirusAEP - dwInc;
		j++;  
	}while(dwTemp >= dwCavityStart && dwVirPatchAdd[j - 1] > m_pMaxPEFile->m_stPEHeader.ImageBase && dwVirPatchAdd[j - 1] < dwLastSecVS);

	//Fill Cavity with zero
	m_dwArgs[0] = dwTemp + 0X08;
	m_dwArgs[1] = m_pSectionHeader[0].PointerToRawData - m_dwArgs[0]; 
	FillWithZero();

	//Goto Virus patch Address and fill with zero till end of section
	for(int i = 0; i <= (j - 2); i++)
	{
		//Check for valid Address
		if(dwVirPatchAdd[i] > m_pMaxPEFile->m_stPEHeader.ImageBase && dwVirPatchAdd[i] < dwLastSecVS)
		{
			m_dwArgs[0] = GetMappedAddress(dwVirPatchAdd[i] - m_pMaxPEFile->m_stPEHeader.ImageBase);

			//Check for valid section
			for(int k = 0 ; k < m_wNoOfSecs ; k++)
			{
				if(m_dwArgs[0] > m_pSectionHeader[k].PointerToRawData && m_dwArgs[0] < (m_pSectionHeader[k].PointerToRawData + m_pSectionHeader[k].SizeOfRawData))			 
				{
					m_dwArgs[1] = m_pSectionHeader[k].PointerToRawData + m_pSectionHeader[k].SizeOfRawData - m_dwArgs[0];
					FillWithZero();
					break;
				}
			}
		}
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: RepairChitonB
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Repaire routine for Chiton.B
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairChitonB()
{
	DWORD dwLastSecPRD = m_pSectionHeader[m_wNoOfSecs -1].PointerToRawData;
	BYTE *pbyBuffer = new BYTE[m_ibyArgLen];
	if(pbyBuffer)
	{
		memset(pbyBuffer, 0, m_ibyArgLen);
		if(m_pMaxPEFile->ReadBuffer(pbyBuffer, dwLastSecPRD, m_ibyArgLen, m_ibyArgLen))
		{
			if(memcmp(pbyBuffer, m_byArg, m_ibyArgLen) == 0)
			{
				m_pMaxPEFile->FillWithZeros(dwLastSecPRD, m_dwArgs[1]);
				m_bStubDeleted = true;
				delete []pbyBuffer;
				return false;
			}
		}
		delete []pbyBuffer;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: RepairChitonB
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Decryption routine for Rosec
--------------------------------------------------------------------------------------*/
bool CRepairModuls::DecryptionRosec()
{	
	BYTE  *bXorKeyBuff = new BYTE[m_dwArgs[1]];
	if(NULL == bXorKeyBuff)
	{
		return false;
	}

	if(!m_pMaxPEFile->ReadBuffer(bXorKeyBuff, m_dwArgs[0], m_dwArgs[1], m_dwArgs[1]))
	{
		delete []bXorKeyBuff;
		return false;
	}
	
	DWORD dwXorKey2 = 0, dwXorKey3 = 0;
	for(int iOffset = 0; iOffset < 11; iOffset++)
	{
		dwXorKey2 = dwXorKey2 + bXorKeyBuff[iOffset];
	}

	DWORD dwKeyCnt=0;
	for(DWORD dwKeyIdx = 2, dwOffset = 0; dwOffset < m_dwSizeofBuff; dwOffset++)
	{
		m_byReadBuffer[dwOffset] ^= bXorKeyBuff[dwKeyIdx++];
		if(dwKeyIdx == m_dwArgs[1])
		{
			dwKeyIdx = 1;
		}
		dwXorKey3 = dwXorKey2 * (dwOffset + 2);
		m_byReadBuffer[dwOffset] ^= dwXorKey3;
	}
	delete []bXorKeyBuff;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptionTupac
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Decryption routine for Tupac virus
--------------------------------------------------------------------------------------*/
bool CRepairModuls::DecryptionTupac()
{	
	DWORD dwKey = m_dwArgs[0]; 
	for(DWORD dwOffset = 0; dwOffset < 0x852 - 0xBA; dwOffset += 8 )
	{
		dwKey = _lrotr(dwKey,1);
	}

	for(DWORD dwOffset = 0; dwOffset < 0x30; dwOffset += 8)
	{
		*((DWORD*)&m_byReadBuffer[dwOffset] ) ^= dwKey;
		dwKey = _lrotr(dwKey,1);	
	}
	
	return m_pMaxPEFile->WriteBuffer(&m_byReadBuffer[0x3], m_dwAEPMapped, 0x24, 0x24);
}

/*-------------------------------------------------------------------------------------
	Function		: RepairMuceB
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Repaire routine for virus : Muce.B
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairMuceB()
{
	bool bRetStatus = false;
	
	DWORD dwLangID = 0x400, dwResID1 = 0x0A;

	//For 1st Resource
	DWORD dwResID = 0x20F, dwOriDataStart = 0, dwOriDataSize = 0;
	if(!FindRes(LPCTSTR(&dwResID1), LPCTSTR(&dwResID), LPCTSTR(&dwLangID), dwOriDataStart, dwOriDataSize))
	{
		return RepairDelete();
	}	
	//For 2nd Resource
	DWORD dwDecStart = 0, dwDecBuffSize = 0;
	dwResID = 0x211; 
	if(!FindRes(LPCTSTR(&dwResID1), LPCTSTR(&dwResID), LPCTSTR(&dwLangID), dwDecStart, dwDecBuffSize))
	{
		return bRetStatus;
	}

	if( dwDecBuffSize >= 0x500 || 
		OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwDecStart,&dwDecStart) ||
		OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwOriDataStart,&dwOriDataStart))
	{
		return bRetStatus;
	}

	m_byReadBuffer = new BYTE[dwDecBuffSize];
	if(NULL != m_byReadBuffer)
	{		
		if(m_pMaxPEFile->ReadBuffer(m_byReadBuffer, dwDecStart, dwDecBuffSize, dwDecBuffSize))
		{
			if(CopyData(dwOriDataStart, 0, dwOriDataSize, 11, dwDecBuffSize))
			{
				bRetStatus = m_pMaxPEFile->ForceTruncate(dwOriDataSize);
			}
		}
		delete []m_byReadBuffer;
		m_byReadBuffer = NULL;
	}
	return bRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: RenameFile
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Renames existing file (infected) with original file
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RenameFile()
{
	if(!m_bInternalCall)
	{
		if(!GetParameters())
		{
			return false;
		}
	}

	if(m_dwArgs[0] == 1)
	{
		WORD SignToMatch = *(WORD *)m_byReadBuffer;		
		switch(SignToMatch)
		{
		case 0xD8FF:
			memcpy_s(m_byArg , 0x05, ".jpeg", 0x05);
			break;
		case 0x4449:
			memcpy_s(m_byArg , 0x04, ".mp3", 0x04);
			break;
		default:
			break;
		}
	}
	else if(m_dwArgs[0] == 2)
	{
		TCHAR sztempFilePath[MAX_PATH]={0};
		TCHAR szOrigFilePath[MAX_PATH]={0};
		wcscpy_s(szOrigFilePath,MAX_PATH,m_pMaxPEFile->m_szFilePath);
		wcscpy_s(sztempFilePath,MAX_PATH,m_pMaxPEFile->m_szFilePath);


		WCHAR *ExtensionLocation = _tcsrchr(sztempFilePath, 0x202E);

		if(ExtensionLocation!=NULL)
		{
			ExtensionLocation+=1;
			if(ExtensionLocation+0x04 > sztempFilePath +_tcslen(sztempFilePath))
			{
				return false;	
			}

			if(memcmp(ExtensionLocation,_T("cod"),0x03)==0x00)
			{
				wcscpy(ExtensionLocation-1,_T(".doc"));
			}
			else if(memcmp(ExtensionLocation,_T("slx"),0x03)==0x00)
			{
				wcscpy(ExtensionLocation-1,_T(".xls"));
			}
			memset(ExtensionLocation+3,0,2);
			m_pMaxPEFile->CloseFile();
			if(!m_pMaxPEFile->OpenFile(szOrigFilePath,true))
			{
				return false;
			}
			BYTE byFirstByte[0x3D]={0};
			if(!m_pMaxPEFile->ReadBuffer(byFirstByte,0,0x3D,0x3D))
			{
				return false;
			}

			if(byFirstByte[0]==0x50 || byFirstByte[0x3C] == 0x02)
			{
				if(byFirstByte[0x3C] == 0x02)
				{
					memset(byFirstByte, 0x00, 0x3D);
					if(!m_pMaxPEFile->ReadBuffer(byFirstByte, 0x20C, 1, 1))
					{
						return false;
					}
					if(byFirstByte[0] == 0x05)
					{
						if(ExtensionLocation+5>sztempFilePath+260)
						{
							return false;	
						}
						memset(ExtensionLocation+4,0,2);
						wcscpy(ExtensionLocation+3,_T("x"));
					}
				
				}
				else
				{
					if(ExtensionLocation+5>sztempFilePath+260)
					{
						return false;	
					}
					memset(ExtensionLocation+4,0,2);
					wcscpy(ExtensionLocation+3,_T("x"));
				}
			}
			m_pMaxPEFile->CloseFile();
			MoveFile(szOrigFilePath,sztempFilePath);
		}
		return true;
	}

	wchar_t szExtension[MAX_INPUT_STR_PARAM] = {0};
	
	size_t iRet = 0;
	mbstowcs_s(&iRet, szExtension, MAX_INPUT_STR_PARAM, (const char*)m_byArg, MAX_INPUT_STR_PARAM);
	
	// Virus has changed extension of the original file 
	CString csRenamedFilePath = m_csFilePath;
	int iLength = csRenamedFilePath.ReverseFind('.');
	if(-1 == iLength)
	{
		return false;
	}
	csRenamedFilePath = csRenamedFilePath.Left(iLength);
	csRenamedFilePath.Append(szExtension);

	m_pMaxPEFile->CloseFile();

	// Rename the renamed file with required file name.
	MoveFile(m_csFilePath, csRenamedFilePath);	
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptionSavior
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Decryption routine for Virus : Savior
--------------------------------------------------------------------------------------*/
void CRepairModuls::DecryptionSavior(DWORD dwFirstArg)
{	
	__int64 iFirstArg = dwFirstArg;
	DWORD dwSecKey = dwFirstArg;
	DWORD dwOffset = m_dwSizeofBuff - 4;
	DWORD dwRCLConst = m_dwArgs[3];
	DWORD dwCarry = 0, dwStoreCarry = 0 ;
	for(DWORD dwCnt = 0; dwCnt < m_dwArgs[1]; dwCnt++)
	{
		*(DWORD *)&m_byReadBuffer[dwOffset] ^= dwFirstArg;
		dwOffset -= 4;
		iFirstArg += (__int64)dwSecKey;	
		dwStoreCarry = iFirstArg / 0x100000000;
		if (dwStoreCarry >= 0x01)
		{
			dwStoreCarry = 0x01;
		}
		dwFirstArg = (DWORD)iFirstArg;
		iFirstArg = dwFirstArg;
		for ( DWORD dwRot = 0; dwRot < dwRCLConst; dwRot++)
		{
			if (dwRot != 0)
			{
				dwStoreCarry = dwCarry;
			}
			dwCarry = dwSecKey & 0X80000000;
			dwSecKey = dwSecKey << 1;
			if(dwStoreCarry > 0x00)
			{
				dwSecKey = dwSecKey | 0x01;
			}
		}
	}
	m_pMaxPEFile->WriteAEP(*(DWORD*)&m_byReadBuffer[dwOffset + 0xd]);
}

/*-------------------------------------------------------------------------------------
	Function		: RepairPadic
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Reapre routine for Virus : Padic
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairPadic()
{
	for(int iOffset = m_dwSizeofBuff; iOffset > 0; iOffset = iOffset - 4)
	{
		*(DWORD *)&m_byReadBuffer[iOffset - 4] ^=  m_dwArgs[1];
	}
	m_pMaxPEFile->WriteBuffer(&m_byReadBuffer[0x1], m_dwAEPMapped, 0x24, 0x24);

	IMAGE_IMPORT_DESCRIPTOR objIMPORTTable = {0};
	if(m_pMaxPEFile->GetImportAndNameTableRVA("kernel32.dll", objIMPORTTable))
	{
		DWORD dwImpTableRVA = objIMPORTTable.OriginalFirstThunk;
		m_pMaxPEFile->Rva2FileOffset(dwImpTableRVA, &dwImpTableRVA) ;
		
		DWORD dwFunNameRVA = m_pMaxPEFile->GetFunNameRva("GlobalAlloc", dwImpTableRVA);
		m_pMaxPEFile->WriteBuffer(&m_byReadBuffer[0x73], dwFunNameRVA, 0xC, 0xC);

		return true;
	}
	return false;	
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptionAdson1734
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Decryption routine for Virus : Adson.1734
--------------------------------------------------------------------------------------*/
void CRepairModuls::DecryptionAdson1734()
{
	__int64 iFirstArg = m_dwArgs[0], iAddValue = 0;
	DWORD dwFirstVal = *(DWORD *)&m_byReadBuffer[0];
	iFirstArg = ((__int64)dwFirstVal - iFirstArg) >> 32;
	if(iFirstArg & 0x80000000)
	{
		iAddValue  = *(DWORD *)&m_byReadBuffer[0] + (*(DWORD *)&m_byReadBuffer[4] * (__int64)m_dwArgs[0]);
	}
	else
	{
		iAddValue = *(DWORD *)&m_byReadBuffer[4] + (*(DWORD *)&m_byReadBuffer[0] * 0x100000000) ;
	}
	if(m_dwArgs[1] != 0)
	{
		if(m_dwArgs[1] == 2)
		{
			iAddValue = (iAddValue >> 32) - m_dwArgs[1];
		}
		else 
		{
			iAddValue = iAddValue >> 16;
		}
		m_dwReturnValues[0] = (DWORD)(iAddValue - m_pMaxPEFile->m_stPEHeader.ImageBase + m_dwArgs[1]);
	}
	else
	{
		m_dwReturnValues[0] = (DWORD)((iAddValue / 0x100) - m_pMaxPEFile->m_stPEHeader.ImageBase);
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptionRamdile
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Decryption routine for Virus : Ramdile
--------------------------------------------------------------------------------------*/
bool CRepairModuls::DecryptionRamdile()
{
	for(int i = 0; i < 9; i++)
	{
		m_byReadBuffer[i]= ~(m_byReadBuffer[i]);
	}

	DWORD	dwXorKey = 0, dwAddKey = 0;
	BYTE	byReadBuffer[0x40] = {0};
	
	if(!m_pMaxPEFile->ReadBuffer(byReadBuffer, m_dwArgs[0], 0x40))
	{
		return false;
	}
	for(int i = 0; i < 0x40; i++)
	{
		byReadBuffer[i] = ~(byReadBuffer[i]);
	}
	dwXorKey = *((DWORD *)&byReadBuffer[0xC]);				
	dwAddKey =  ~(*((DWORD *)&byReadBuffer[0x13])) + 1;				
	dwXorKey -= dwAddKey * 0x84;
	
	*((DWORD *)&m_byReadBuffer[0x0])^= dwXorKey;
	dwXorKey -= dwAddKey;
	*((DWORD *)&m_byReadBuffer[0x4])^= dwXorKey;
	
	m_dwReturnValues[0] = *((DWORD *)&m_byReadBuffer[0x1]);
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: RepairEmar
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Reapre routine for Virus : Emar
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairEmar()
{
	BYTE byKey[] = {0xB2, 0x2, 0x7, 0x5, 0x75, 0xC9, 0x3A, 0x55, 0xAA};
	if(m_dwArgs[2])
	{
		if(!m_pMaxPEFile->ReadBuffer(&byKey, m_dwArgs[2], sizeof(byKey), sizeof(byKey)))
		{
			return false;
		}
	}
	DWORD dwType = 0;
	for(DWORD dwCnt = 0; dwCnt < m_dwArgs[1]; dwCnt++)
	{
		if(dwType > 9)
		{
			dwType = 0;
		}
		switch(dwType)
		{
		case 0:
			m_byReadBuffer[dwCnt] = ~m_byReadBuffer[dwCnt];
			if(m_byReadBuffer[0] != 0x4D)
			{
				return RepairDelete();
			}
			break;
		case 1 :
			m_byReadBuffer[dwCnt] ^= byKey[0]; 
			break;
		case 2 :
			m_byReadBuffer[dwCnt] = m_byReadBuffer[dwCnt] << (byKey[1] % 8) | m_byReadBuffer[dwCnt] >> (0x08 - (byKey[1] % 8));
			break;
		case 3 : 
			m_byReadBuffer[dwCnt] = m_byReadBuffer[dwCnt] >> (byKey[2] % 8) | m_byReadBuffer[dwCnt] << (0x08 - (byKey[2] % 8));
			break;
		case 4 :
			m_byReadBuffer[dwCnt] = m_byReadBuffer[dwCnt] << (byKey[3] % 8) | m_byReadBuffer[dwCnt] >> (0x08 - (byKey[3] % 8));
			m_byReadBuffer[dwCnt] = ~m_byReadBuffer[dwCnt];
			break;
		case 5 :
			m_byReadBuffer[dwCnt] ^= byKey[4];
			m_byReadBuffer[dwCnt] = m_byReadBuffer[dwCnt] >> 0x03 | m_byReadBuffer[dwCnt] << (0x08 - 0x03);
			break;
		case 6 :
			m_byReadBuffer[dwCnt] = ~m_byReadBuffer[dwCnt];
			m_byReadBuffer[dwCnt] ^= byKey[5];
			m_byReadBuffer[dwCnt] = m_byReadBuffer[dwCnt] << 0x01 | m_byReadBuffer[dwCnt] >> (0x08 - 0x01);

			break;
		case 7 :
			m_byReadBuffer[dwCnt] = ~m_byReadBuffer[dwCnt];
			m_byReadBuffer[dwCnt] ^= byKey[6];

			break;
		case 8 :
			m_byReadBuffer[dwCnt] ^= byKey[7];
			break;
		case 9 :
			m_byReadBuffer[dwCnt] = ~m_byReadBuffer[dwCnt];
			m_byReadBuffer[dwCnt] = m_byReadBuffer[dwCnt] >> 0x03 | m_byReadBuffer[dwCnt] << (0x08 - 0x03);				
			m_byReadBuffer[dwCnt] ^= byKey[8];
			break;
		}
		dwType++;
	}

	if(m_pMaxPEFile->WriteBuffer(m_byReadBuffer, 0x00, m_dwArgs[1], m_dwArgs[1]))
	{
		if(m_pMaxPEFile->ForceTruncate(m_pMaxPEFile->m_dwFileSize - m_dwArgs[1]))
		{
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: RepairKiro
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Repair routine for Virus : Kiro
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairKiro()
{
	DWORD dwReadOffset = 0x7000;
	WORD wMZ = 0;
	if(m_pMaxPEFile->ReadBuffer(&wMZ, dwReadOffset, 2, 2))
	{
		if(wMZ != 0x5A4D)
		{
			dwReadOffset = 0xD000;
			if(m_pMaxPEFile->ReadBuffer(&wMZ, dwReadOffset, 2, 2))
			{
				if(wMZ != 0x5A4D)
				{
					return RepairDelete();
				}
			}
		}
		DWORD dwBytesToWrite = ((m_dwFileSize - dwReadOffset) < 0x7000) ? (m_dwFileSize - dwReadOffset) : 0x7000;
		if(CopyData(dwReadOffset, 0, dwBytesToWrite))
		{
			m_pMaxPEFile->CloseFile_NoMemberReset();
			TCHAR szFilePath[MAX_PATH]= {0};
			_tcscpy_s(szFilePath, MAX_PATH, m_pMaxPEFile->m_szFilePath);
			if(m_pMaxPEFile->OpenFile(szFilePath, true))
			{
				ReadPeFile();
				return m_pMaxPEFile->ForceTruncate(m_pSectionHeader[m_wNoOfSecs - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSecs - 1].SizeOfRawData);						
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: RepairKlez
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Repair routine for Virus : Klez
--------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairKlez()
{
	bool bRet = false;

	BYTE byKey[2] = {0};
	if(!m_pMaxPEFile->ReadBuffer(byKey, m_pSectionHeader[2].PointerToRawData + 0xD0, sizeof(byKey), sizeof(byKey)))
	{
		return bRet;
	}
	BYTE byFileName[0x30] = {0};
	if(!m_pMaxPEFile->ReadBuffer(byFileName, m_pSectionHeader[2].PointerToRawData + 0x10D4, 0x30, 0x30))
	{
		return bRet;
	}
	for(int i = 0; i < 0x30; i++)
	{
		byFileName[i] ^= byKey[1];
		byFileName[i] = byFileName[i] >> (byKey[0]) | byFileName[i] << (8 - (byKey[0]));
	}

	HANDLE hFile = CreateFileA((LPCSTR)&byFileName[0],
		GENERIC_READ,
		FILE_SHARE_READ, 
		NULL, 
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN, 
		NULL);

	if(hFile == INVALID_HANDLE_VALUE)
	{
		return RepairDelete();
	}

	DWORD dwBytesRead = 0, dwCount;	
	ReadFile(hFile, &dwCount, 4, &dwBytesRead, NULL);
	if(4 != dwBytesRead)
	{
		CloseHandle(hFile);
		return bRet;
	}

	DWORD dwTableSize = dwCount * 2;	//2 pairs of DWORDs
	DWORD *dwTable = new DWORD[dwTableSize];		
	if(!dwTable)
	{
		CloseHandle(hFile);
		return bRet;
	}

	ReadFile(hFile, dwTable, dwTableSize * 4, &dwBytesRead, NULL);
	if(dwTableSize * 4 != dwBytesRead)
	{
		delete dwTable;
		dwTable = NULL;		
		CloseHandle(hFile);
		return bRet;
	}

	const int iMaxCount = 0x5000;
	m_byReadBuffer = new BYTE[iMaxCount];
	if(!m_byReadBuffer)
	{
		delete dwTable;
		dwTable = NULL;		
		CloseHandle(hFile);
		return bRet;
	}

	//createfile without any extension
	char * ptr = strrchr((char *)&byFileName[0], '.');
	*ptr = '\0';

	HANDLE hDestFile = CreateFileA((LPCSTR)&byFileName[0],
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, 
		NULL, 
		CREATE_ALWAYS, 
		FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN, 
		NULL);

	if(INVALID_HANDLE_VALUE == hDestFile)
	{
		delete dwTable;
		dwTable = NULL;		
		CloseHandle(hFile);
		return bRet;
	}

	DWORD dwPrevCount = 0, dwBytesWritten = 0, dwLocalCount = 0, dwCurrentCount = 0;	
	for(int i = 0; i < dwCount * 2; i += 1)
	{			
		if(i % 2)
		{
			dwLocalCount = dwTable[i] % iMaxCount;
			memset(m_byReadBuffer, 0, iMaxCount);
			for(int j = 0; j < dwTable[i]/iMaxCount; j++)
			{
				dwBytesWritten = 0;
				WriteFile(hDestFile, m_byReadBuffer, iMaxCount, &dwBytesWritten, NULL);
				if(iMaxCount != dwBytesWritten)
				{
					delete dwTable;
					dwTable = NULL;
					CloseHandle(hDestFile);
					CloseHandle(hFile);

					hFile = hDestFile = INVALID_HANDLE_VALUE;

					DeleteFileA((char *)&byFileName[0]);
					return bRet;
				}
				dwPrevCount += dwBytesWritten;
			}
			if(dwLocalCount)
			{
				dwBytesWritten = 0;
				WriteFile(hDestFile, m_byReadBuffer, dwLocalCount, &dwBytesWritten, NULL);
				if(dwLocalCount != dwBytesWritten)
				{
					delete dwTable;
					dwTable = NULL;
					CloseHandle(hDestFile);
					CloseHandle(hFile);
					hFile = hDestFile = INVALID_HANDLE_VALUE;
					DeleteFileA((char *)&byFileName[0]);
					return bRet;
				}
				dwPrevCount += dwBytesWritten;
			}
		}
		else
		{
			//dwCurrentCount += dwTable[i];
			dwTable[i] -= dwPrevCount;
			dwCurrentCount += dwTable[i];
			dwLocalCount = dwTable[i] % iMaxCount;
			for(int k = 0; k < dwTable[i]/iMaxCount; k++)
			{
				dwBytesRead = 0;
				ReadFile(hFile, m_byReadBuffer, iMaxCount, &dwBytesRead, NULL);
				if(dwBytesRead != iMaxCount)
				{
					delete dwTable;
					dwTable = NULL;
					CloseHandle(hDestFile);
					CloseHandle(hFile);
					hFile = hDestFile = INVALID_HANDLE_VALUE;
					DeleteFileA((char *)&byFileName[0]);
					return bRet;
				}

				dwBytesWritten = 0;
				WriteFile(hDestFile, m_byReadBuffer, dwBytesRead, &dwBytesWritten, NULL);
				if(dwBytesRead != dwBytesWritten)
				{
					delete dwTable;
					dwTable = NULL;
					CloseHandle(hDestFile);
					CloseHandle(hFile);
					hFile = hDestFile = INVALID_HANDLE_VALUE;
					DeleteFileA((char *)&byFileName[0]);
					return bRet;
				}
				dwPrevCount += dwBytesWritten;
			}

			if(dwLocalCount)
			{
				dwBytesRead = 0;
				memset(m_byReadBuffer, 0, iMaxCount);
				ReadFile(hFile, m_byReadBuffer, dwLocalCount, &dwBytesRead, NULL);

				if(dwBytesRead != dwLocalCount)
				{
					delete dwTable;
					dwTable = NULL;
					CloseHandle(hDestFile);
					CloseHandle(hFile);
					hFile = hDestFile = INVALID_HANDLE_VALUE;
					DeleteFileA((char *)&byFileName[0]);
					return bRet;
				}

				dwBytesWritten = 0;
				WriteFile(hDestFile, m_byReadBuffer, dwBytesRead, &dwBytesWritten, NULL);
				if(dwBytesRead != dwBytesWritten)
				{
					delete dwTable;
					dwTable = NULL;
					CloseHandle(hDestFile);
					CloseHandle(hFile);
					hFile = hDestFile = INVALID_HANDLE_VALUE;
					DeleteFileA((char *)&byFileName[0]);
					return bRet;
				}
				dwPrevCount += dwBytesWritten;
			}
		}
	}

	DWORD dwFileSize = GetFileSize(hFile, NULL);
	if(dwCurrentCount < dwFileSize)
	{
		DWORD dwRemCount = dwFileSize - dwCurrentCount - dwTableSize * 4 - 4;	//rem. file size = total file size - (size of table + first DWORD) - current offset

		dwLocalCount = dwRemCount % iMaxCount;
		for(int i = 0; i < dwRemCount/iMaxCount; i++)
		{
			dwBytesRead = 0;
			ReadFile(hFile, m_byReadBuffer, iMaxCount, &dwBytesRead, NULL);
			if(dwBytesRead != iMaxCount)
			{
				delete dwTable;
				dwTable = NULL;
				CloseHandle(hDestFile);
				CloseHandle(hFile);
				hFile = hDestFile = INVALID_HANDLE_VALUE;
				DeleteFileA((char *)&byFileName[0]);
				return bRet;
			}

			dwBytesWritten = 0;
			WriteFile(hDestFile, m_byReadBuffer, dwBytesRead, &dwBytesWritten, NULL);
			if(dwBytesRead != dwBytesWritten)
			{
				delete dwTable;
				dwTable = NULL;	
				CloseHandle(hDestFile);
				CloseHandle(hFile);
				hFile = hDestFile = INVALID_HANDLE_VALUE;
				DeleteFileA((char *)&byFileName[0]);
				return bRet;
			}
			dwPrevCount += dwBytesWritten;
		}

		if(dwLocalCount)
		{
			dwBytesRead = 0;
			ReadFile(hFile, m_byReadBuffer, dwLocalCount, &dwBytesRead, NULL);
			if(dwBytesRead != dwLocalCount)
			{
				delete dwTable;
				dwTable = NULL;
				CloseHandle(hDestFile);
				CloseHandle(hFile);
				hFile = hDestFile = INVALID_HANDLE_VALUE;
				DeleteFileA((char *)&byFileName[0]);
				return bRet;
			}

			dwBytesWritten = 0;
			WriteFile(hDestFile, m_byReadBuffer, dwLocalCount, &dwBytesWritten, NULL);
			if(dwLocalCount != dwBytesWritten)
			{
				delete dwTable;
				dwTable = NULL;
				CloseHandle(hDestFile);
				CloseHandle(hFile);
				hFile = hDestFile = INVALID_HANDLE_VALUE;
				DeleteFileA((char *)&byFileName[0]);
				return bRet;
			}
			dwPrevCount += dwBytesWritten;
		}
	}
	CloseHandle(hDestFile);
	CloseHandle(hFile);

	///File regenration is done Now delete <file>.exe, <file>.xyz and rename <Regenerated file> to file <file>.exe
	RepairDelete();//Current trojan file is deleted

	DWORD dwlen =  strlen((char *)&byFileName[0]);
	char * szFileName = new char [dwlen + 5];
	sprintf_s(szFileName, dwlen + 5, ("%s%s"), (char *)&byFileName[0], ".exe");

	MoveFileA((char *)&byFileName[0], szFileName);	//Renamed <file> to <file>.exe

	ptr = strchr((char *)&byFileName[0], '\0');
	*ptr = '.';
	DeleteFileA((char *)&byFileName[0]);	//Delete file with random extension

	//free all allocated memory
	delete szFileName;
	szFileName = NULL;		

	delete dwTable;
	dwTable = NULL;

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptionCabres
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Decryption routine for Virus : Cabres
--------------------------------------------------------------------------------------*/
bool CRepairModuls::DecryptionCabres()
{
	bool bRetVal = false;
	DWORD dwResID	= 0x0A; 
	DWORD dwLangID	= 0x0409;
	DWORD dwSize = 0 , dwRVA = 0;
	
	if(FindRes(LPCTSTR(&dwResID), _T("CABINET"), LPCTSTR(&dwLangID), dwRVA, dwSize))
	{

		BYTE *pbySourceMemory = new BYTE[dwSize];	
		if(NULL == pbySourceMemory)
		{
			return bRetVal;
		}	
		memset(pbySourceMemory, 0, dwSize);
		
		if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwRVA, &dwRVA))
		{
			if(!m_pMaxPEFile->ReadBuffer(pbySourceMemory, dwRVA, dwSize, dwSize))
			{
				if(pbySourceMemory)
				{
					delete[] pbySourceMemory; 
					pbySourceMemory = NULL;
				}
				return bRetVal;
			}
		}
		DWORD dwDestBuffSize = *(DWORD *)&pbySourceMemory[m_dwArgs[0]];
		m_byReadBuffer = new BYTE[dwDestBuffSize];
		if(NULL == m_byReadBuffer)
		{
			if(pbySourceMemory)
			{
				delete[] pbySourceMemory; 
				pbySourceMemory = NULL;
			}
			return bRetVal;
		}
		memset(m_byReadBuffer, 0, dwDestBuffSize);
		DWORD dwBytesDecrypted = 0;
		if((DecompressMemory (pbySourceMemory, m_byReadBuffer, dwDestBuffSize, dwBytesDecrypted) != NULL) && dwDestBuffSize == dwBytesDecrypted)  
		{
			bRetVal = true;
		}
		if(pbySourceMemory)
		{
			delete[] pbySourceMemory; 
			pbySourceMemory = NULL;
		}
		m_dwReturnValues[0] = dwBytesDecrypted;
	}
	return bRetVal;
}

/*-------------------------------------------------------------------------------------
	Function		: Check4OLEFile
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Check for Valid OLE file
--------------------------------------------------------------------------------------*/
bool CRepairModuls::Check4OLEFile()
{
	BYTE szHeader[8] = {0};
	if(m_pMaxPEFile->ReadBuffer(szHeader, 0, 8, 8))
	{
		BYTE szMSOfficeHeader[]	= {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
		if(memcmp(szHeader, szMSOfficeHeader, sizeof(szMSOfficeHeader)) == 0)
		{
			BYTE byMSI = 0;
			if(m_pMaxPEFile->ReadBuffer(&byMSI, 0x2C, 1, 1))
			{
				if(byMSI != 0xE9)
				{
					return true;
				}
			}
		}
	}
	return false;
}

// Added by Rupali on 13-11-2010 for OLE repair changes
/*-------------------------------------------------------------------------------------------------------
Function		: CleanOLEMacro
In Parameters	: None
Out Parameters	: bool
Purpose			: Repair Routine for Infected Macro Cleaning.
Author			: Sourabh Kadam
Description		: This Routine will clean the infected macro.
-------------------------------------------------------------------------------------------------------*/
bool CRepairModuls::CleanOLEMacro()
{
	LPSTORAGE   pRootStg = NULL;

	m_pMaxPEFile->CloseFile_NoMemberReset();
	
	//Opening storage In Read Write mode
	if(FAILED(StgOpenStorage(m_csFilePath, 
					NULL,STGM_SHARE_EXCLUSIVE | STGM_READWRITE , 
					NULL, 
					0, 
					&pRootStg)))
	{
		DWORD dwError = GetLastError();  
		return (false);
	}

	m_bMacroClean = false;
	//Passing Handle of Storage for traversing 
	ViewStorage(pRootStg);
	//Releasing storage handle
	OleStdRelease(pRootStg);

	m_pMaxPEFile->OpenFile_NoMemberReset(m_csFilePath);
	return m_bMacroClean;
}

/*-------------------------------------------------------------------------------------------------------
Function		: ViewStorage
In Parameters	: Handle Of Storage
Out Parameters	: HRESULT
Purpose			: Routine for Traversing storage.
Author			: Sourabh Kadam
Description		: This Routine will traverse all the storage.
-------------------------------------------------------------------------------------------------------*/
HRESULT CRepairModuls::ViewStorage(LPSTORAGE pStorage)
{
	LPENUMSTATSTG  pEnum = NULL;
	STATSTG        ss;
	LPSTORAGE      pSubStg = NULL;
	HRESULT        hr;
	ULONG          ulCount = 0;
	TCHAR*		   szType = NULL;
	TCHAR          szTreeString[80]={0};
	INT            nType = 0;	

	//Enumerating Storage Objects.
	hr = pStorage->EnumElements(0, NULL, 0, &pEnum);
	if(NOERROR != hr)
	{	
		OleStdRelease(pEnum);
		return hr;
	}

	while(TRUE)
	{
		hr = pEnum->Next(1, &ss, &ulCount);
		if(S_OK != hr)
		{
			OleStdRelease(pEnum);
			return hr;
		}
		// Identifying Object type
		switch(ss.type)
		{
			case STGTY_STREAM:			//Stream Object
				szType = _T("Stream");
				nType = TYPE_DOCUMENT;
			break;
			case STGTY_STORAGE:			//Storage Object
				szType = _T("Storage");
				nType = TYPE_FOLDER;
			break;
			case STGTY_LOCKBYTES:		//LockBytes Object
				szType = _T("Lockbytes");
				nType = TYPE_FOLDER;
			break;
			case STGTY_PROPERTY:		//Property Object
				szType = _T("Property");
				nType = TYPE_FOLDER;
			break;
			default:					//Unknown Object
				szType = _T("**Unknown**");
				nType = TYPE_FOLDER;
			break;
		}
		//Operation on Stream Object
		if(STGTY_STREAM == ss.type)
		{
			CString strName(ss.pwcsName);
			if(m_csModParam.CompareNoCase(strName) == 0)
			{
				hr=pStorage->DestroyElement(ss.pwcsName);
				if(S_OK == hr)
				{
					m_bMacroClean = true;
				}
				else
				{
					return ERROR;
				}
			}
		}
		//Operation on Storage Objects
		if(STGTY_STORAGE == ss.type)
		{
			//Opening Storage
			hr=pStorage->OpenStorage(ss.pwcsName, NULL, STGM_READWRITE | STGM_SHARE_EXCLUSIVE,NULL, 0, &pSubStg);
			if(!FAILED(hr))
			{
				ViewStorage(pSubStg);
				OleStdRelease(pSubStg);
			}
		}
	}
	//Releasing Storage
	OleStdRelease(pEnum);
	//Returns Repair status
	return hr;			
}

/*-------------------------------------------------------------------------------------------------------
Function		: OleStdRelease
In Parameters	: Handle Of LPUNKNOWN class
Out Parameters	: -
Purpose			: Routine for Releasing storage handles.
Author			: Sourabh Kadam
Description		: This Routine will release storage handles.
-------------------------------------------------------------------------------------------------------*/
void CRepairModuls::OleStdRelease(LPUNKNOWN pUnk)
{
	//Releasing handle
	if(NULL != pUnk)
  		pUnk->Release();
	pUnk = NULL;
}
// End

bool CRepairModuls::RepairRedemption()
{
	m_dwArgs[3] += m_dwArgs[2];
	m_dwArgs[1] -= m_pSectionHeader[0].VirtualAddress;// allocate buff of args[1] size read text section in that buff & pointer to buffer @ end of buff
	DWORD dwBuffStart = 0, dwBuffSize = 0;
	dwBuffStart = m_dwArgs[3]- m_dwArgs[2];
	dwBuffSize = m_dwArgs[4] - dwBuffStart;

	m_byReadBuffer = new BYTE[m_pSectionHeader[1].VirtualAddress- m_pSectionHeader[0].VirtualAddress];
	memset(m_byReadBuffer, 0,  m_pSectionHeader[1].VirtualAddress- m_pSectionHeader[0].VirtualAddress);

	if(m_pMaxPEFile->ReadBuffer(m_byReadBuffer, m_pSectionHeader[0].PointerToRawData, m_pSectionHeader[1].VirtualAddress- m_pSectionHeader[0].VirtualAddress, m_pSectionHeader[0].SizeOfRawData))
	{
		BYTE *byReadBuffer2 = new BYTE[dwBuffSize];
		memset(byReadBuffer2, 0, dwBuffSize);
		if(m_pMaxPEFile->ReadBuffer(byReadBuffer2,dwBuffStart, dwBuffSize, dwBuffSize))
		{
			DWORD  dwECX , dwEDX, dwEBX= 0, dwESI, dwEDI, dwEAX, dwEBP;
			BYTE byStackByte=0x0,byAL=0x61, byAH=0x8b,byCarryFlag=0x0, byBH=0x0, byBL=0x0, byDL=0x0, byZeroFlag = 0;
			WORD wBX;

			dwEBP =   m_dwArgs[1];//m_dwArgs[1] -1;
			dwESI =   m_dwArgs[2]- 5;//m_dwArgs[3]-5;//buff2
			dwECX =  m_dwArgs[2] - 4;
			dwEDI =  dwBuffSize - 1;//buff2 
			dwEAX =  dwEBP;
			dwEDX = *(DWORD *)&byReadBuffer2[dwESI+1];

			while(1)
			{
				if((byStackByte & 0x07)==0)
					byZeroFlag = 1;
				else byZeroFlag = 0;

				if(!byZeroFlag)
				{
lable1:		byCarryFlag = byAH & 0x80;
					byAH<<=1;
					if(byAH == 0)
						byZeroFlag = 1;
					byStackByte++;
					byZeroFlag = 0;
					if(!byCarryFlag)
					{
label:			byAL =m_byReadBuffer[dwEBP+dwEBX];
						byReadBuffer2[dwEDI] = byAL;
						byBH = byBL;
						dwEDI--;
						byBL = byAL;
						wBX=0x0;
						wBX = byBH;
						wBX<<=8;
						dwEBX = (BYTE)byBL;
						dwEBX = dwEBX | wBX;
						continue;
					}
					else
					{
						byCarryFlag = (BYTE)dwEDX & 0x00000001;
						dwEDX = _lrotr(dwEDX,1);
						if(dwECX==0)
							break;
						if(!byCarryFlag)
							dwEDX^=  0x2c047c3e;

						byAL = byReadBuffer2[dwESI];
						dwESI--;
						dwECX--;
						byZeroFlag = 0;
						dwEDX^=0x76c52b8d;
						byDL = (BYTE) dwEDX;
						byAL-=byDL;
						if(byAL == 0)
							byZeroFlag = 1;
						m_byReadBuffer[dwEBP+dwEBX] = byAL;
						//dwEDI--;
						goto label;

					}
				}
				else
				{
					byCarryFlag = (BYTE)dwEDX & 0x00000001;
					dwEDX = _lrotr(dwEDX,1);
					if(dwECX==0)
						break;
					if(byCarryFlag)
						dwEDX^= 0x2c047c3e;

					byAL = byReadBuffer2[dwESI];
					dwESI--;
					dwECX--;
					byZeroFlag = 0;
					dwEDX^= 0x5ac157b3;
					byDL = (BYTE) dwEDX;
					byAL-=byDL;
					if(byAL == 0)
						byZeroFlag = 1;
					byAH = byAL;
					goto lable1;
				}
			}

			m_pMaxPEFile->WriteBuffer(byReadBuffer2, dwBuffStart, dwBuffSize, dwBuffSize);
			memset(m_byReadBuffer, 0, 0x200);
			if(m_pMaxPEFile->ReadBuffer(m_byReadBuffer,0, 0x200, 0x200))
			{
				for(DWORD i = 0; i < 0x200; i++)
				{
					if((*(WORD*)&m_byReadBuffer[i]== 0x4550))//searching for PE
					{
						DWORD dwOff2NewExe = i; 
						if(m_pMaxPEFile->WriteBuffer(&dwOff2NewExe, 0x3c, sizeof(DWORD), sizeof(DWORD)))
						{
							return true;
						}
					}
				}
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: CleanHLPFile()
Out Parameters	: Return true if Repair File else return false
Purpose			: To Repair Help (.hlp) File .
Author			: Prajakta 
--------------------------------------------------------------------------------------*/
bool CRepairModuls::CleanHLPFile()
{
	bool iRet = false;
	
	m_byReadBuffer = new BYTE[1280];
	if(!m_byReadBuffer)
	{
		return iRet;
	}

	DWORD dwReadDIROffset = 0, dwDIRSize = 0;
	if(!m_pMaxPEFile->ReadBuffer(&dwReadDIROffset, 0x4, 0x4, 0x4))
	{	
		return iRet;
	}
	if(dwReadDIROffset + 0x500 < m_pMaxPEFile->m_dwFileSize )
	{	
		if(!m_pMaxPEFile->ReadBuffer(m_byReadBuffer, dwReadDIROffset, 0x500, 0x500))
		{
			return iRet;
		}
	}
	else
	{
		if(!m_pMaxPEFile->ReadBuffer(&dwDIRSize, dwReadDIROffset, 0x4, 0x4))
		{
			return iRet;
		}
		if(!m_pMaxPEFile->ReadBuffer(m_byReadBuffer, dwReadDIROffset, dwDIRSize, dwDIRSize))
		{
			return iRet;
		}
	}
	dwDIRSize = *(DWORD *)&m_byReadBuffer[0];
	if(dwReadDIROffset + dwDIRSize >= m_pMaxPEFile->m_dwFileSize)
	{
		return iRet;
	}
	if((*(WORD *)&m_byReadBuffer[0x1F] == 0x0000) && (*(WORD *)&m_byReadBuffer[0x25] == 0xFFFF))
	{		
		DWORD dwEntriesCnt = *(DWORD *)&m_byReadBuffer[0x2B];
		BYTE *byHelpBuff = new BYTE[dwEntriesCnt * sizeof(DWORD)];
		if(!byHelpBuff)
		{
			return iRet;
		}
		DWORD  byPos[0x100] = {0x0};
		DWORD i=0x37,j=0,dwCounter=1,t=0;
		while(i < dwDIRSize &&  dwCounter <= dwEntriesCnt)
		{
			if(m_byReadBuffer[i] == 0x00 )
			{	
				*(DWORD *)&byHelpBuff[j] = *(DWORD *)&m_byReadBuffer[i+ 0x1];
				byPos[t] = dwReadDIROffset + i + 0x1;
				t++;
				j += 4;
				i += 4;
				dwCounter++;
			}
			i++;

		}
		// copy unsorted data 
		i = 0;
		while(i < dwEntriesCnt * sizeof(DWORD))
		{
			m_byReadBuffer[i] = byHelpBuff[i];
			i++;

		}
		if(dwCounter == dwEntriesCnt + 0x1)
		{	
			//Code For Sorting	
			for (DWORD x = 0; x <= dwEntriesCnt * sizeof(DWORD); x+=4 )
			{
				for(DWORD y = 0; y < dwEntriesCnt * sizeof(DWORD); y+=4)
				{
					for (DWORD z = 0; z < ((dwEntriesCnt * sizeof(DWORD)) - (0x4 + y)); z+=4)
					{
						if(*(DWORD *)&byHelpBuff[z] > *(DWORD *)&byHelpBuff[z+4])
						{
							DWORD temp = *(DWORD *)&byHelpBuff[z+4];
							*(DWORD *)&byHelpBuff[z+4] = *(DWORD *)&byHelpBuff[z];
							*(DWORD *)&byHelpBuff[z] = temp;
						}
					}
				}
			}
			//Code For Finding Original Data
			DWORD dwAddSize = 0x0, dwDirSize = 0, dwOriData = 0;
			i = 0;
			while( i <= (dwEntriesCnt * sizeof(DWORD)-0x4) && dwOriData ==0)
			{
				if(!m_pMaxPEFile->ReadBuffer(&dwDirSize, *(DWORD *)&byHelpBuff[i], 0x4, 0x4))
				{
					break;
				}
				if(dwReadDIROffset > *(DWORD *)&byHelpBuff[i])
				{
					dwAddSize = dwDIRSize;
				}
				DWORD dwNewSize = 0;
				if((*(DWORD *)&byHelpBuff[i + 0x4] != *(DWORD *)&byHelpBuff[i]+ dwDirSize + dwAddSize) 
					&& m_pMaxPEFile->m_dwFileSize != *(DWORD *)&byHelpBuff[i]+ dwDirSize + dwAddSize)
				{
					dwNewSize=0;
					if(!m_pMaxPEFile->ReadBuffer(&dwNewSize, *(DWORD *)&byHelpBuff[i] + dwDirSize + dwAddSize, 0x4, 0x4))
					{
						break;
					}

					if(*(DWORD *)&byHelpBuff[i + 0x4] == *(DWORD *)&byHelpBuff[i]+ dwDirSize + dwAddSize + dwNewSize)
					{
						dwOriData = *(DWORD *)&byHelpBuff[i] + dwDirSize + dwAddSize;
					}
				}
				else if(dwReadDIROffset < *(DWORD *)&byHelpBuff[i] && *(DWORD *)&byHelpBuff[i] == dwReadDIROffset + dwDIRSize && dwOriData ==0x0 )
				{
					dwNewSize = 0;
					if(!m_pMaxPEFile->ReadBuffer(&dwNewSize, 0x10, 0x4, 0x4))
					{
						break;
					}
					if(dwNewSize + 0x10 == dwReadDIROffset)
					{
						dwOriData = 0x00000010;
					}
					else
					{
						break;
					}
				}
				i += 4;
				dwAddSize = 0;
			}
			//Code For Finding Position
			j = 0;
			DWORD dwOffset = 0, dwWriteOffset = 0;
			while( j <= (dwEntriesCnt * sizeof(DWORD)) && dwWriteOffset == 0x0)
			{
				if(*(DWORD *)&byHelpBuff[(dwEntriesCnt * sizeof(DWORD) - 0x4)] == *(DWORD *)&m_byReadBuffer[dwOffset])
				{
					dwWriteOffset = byPos[j] ;
				}
				dwOffset += 4;
				j++;
			}	
			if(dwWriteOffset < m_pMaxPEFile->m_dwFileSize)
			{
				if(m_pMaxPEFile->WriteBuffer(&dwOriData, dwWriteOffset, sizeof(DWORD), sizeof(DWORD)))
				{
					m_bInternalCall=true;
					m_dwArgs[0] = *(DWORD *)&byHelpBuff[(dwEntriesCnt * sizeof(DWORD) - 0x4)];
					if(m_pMaxPEFile->WriteBuffer(&m_dwArgs[0], 0xC, sizeof(DWORD), sizeof(DWORD)))
					{
						if(SetFileEnd())
						{  						
							iRet = true;
						}
					}
				}
			}
		}
		delete[] byHelpBuff;
		return iRet;
	}
	return iRet;
}
/*
void CRepairModuls::DecryptionLamerEL()
{
	if(m_byReadBuffer)
	{
		delete [] m_byReadBuffer;
		m_byReadBuffer = NULL;
	}
	m_byReadBuffer = new BYTE[0x1000];
	
	DWORD dwXorKey=m_dwArgs[1];
	DWORD dwCurPos=m_dwArgs[0],dwLastOffsetAdd=0;
	while( dwCurPos < m_pMaxPEFile->m_dwFileSize)
	{
		dwLastOffsetAdd=dwCurPos;
		dwCurPos = DecryptionLamerEL(dwCurPos,dwXorKey);
		if(dwCurPos == 0x0 )
		{
			break;
		}
		if(m_pMaxPEFile->m_dwFileSize - dwCurPos <0x400)
		{
			dwCurPos+=m_pMaxPEFile->m_dwFileSize - dwCurPos;
		}
	}
	if(m_pMaxPEFile->ReadBuffer(m_byReadBuffer, dwLastOffsetAdd, 0x200, 0x200))
	{
		for(int i = 0; i < 0x40; i++)
		{
			const BYTE bySig[] = {0x56,0x62,0x45,0x78,0x65,0x46,0x69,0x6C,0x65,0x42,0x69,0x6E,0x64};
			if(memcmp(&m_byReadBuffer[i], bySig, sizeof(bySig)) == 0x00)
			{
				dwLastOffsetAdd += (sizeof(bySig) + i);
				if(*(WORD *)&m_byReadBuffer[(sizeof(bySig)+ i)]!= 0x5a4d)
				{
					for(int j = sizeof(bySig)+ i; j < (sizeof(bySig)+ i + 0x64 );  j++)
					{
						*(WORD *)&m_byReadBuffer[j] ^= dwXorKey;
					}
					if(!m_pMaxPEFile->WriteBuffer(&m_byReadBuffer[sizeof(bySig)+ i], dwLastOffsetAdd, 0x64, 0x64))
					{
						break;
					}
				}
				m_dwReturnValues[0] = dwLastOffsetAdd;
				break;
			}
		}
	}
	return;
}

int CRepairModuls::DecryptionLamerEL(DWORD dwDecStart,DWORD dwXorKey)
{
	DWORD dwChunk = 0x1000,dwBytesToRead=0;
	if((m_pMaxPEFile->m_dwFileSize  -  dwDecStart)< dwChunk)
	{
		dwChunk = m_pMaxPEFile->m_dwFileSize  -  dwDecStart;
	}
	for(dwDecStart; dwDecStart < m_pMaxPEFile->m_dwFileSize; dwDecStart += dwChunk)
	{
		dwBytesToRead = (m_pMaxPEFile->m_dwFileSize - dwDecStart) < dwChunk ?  (m_pMaxPEFile->m_dwFileSize - dwDecStart) : dwChunk;
		if(!m_pMaxPEFile->ReadBuffer(m_byReadBuffer,dwDecStart, dwBytesToRead, dwBytesToRead))
		{
			dwDecStart=0;
			return dwDecStart;
		}
		for(int i = 0; i < dwBytesToRead;  i ++)
		{
			const BYTE bySignature[] = {0x56,0x62,0x45,0x78,0x65,0x46,0x69,0x6C,0x65,0x42,0x69,0x6E,0x64};
			if(memcmp(&m_byReadBuffer[i], bySignature, sizeof(bySignature)) == 0x00)
			{
				if(m_pMaxPEFile->m_dwFileSize - dwDecStart >= 0x400)
				{
					dwDecStart += (sizeof(bySignature)+ i);
					if(m_pMaxPEFile->ReadBuffer(m_byReadBuffer,dwDecStart,0x400,0x400))
					{	
						if(*(WORD *)&m_byReadBuffer[0]!= 0x5a4d)
						{
							for(int j = 0; j < 0x64;  j++)
							{
								*(WORD *)&m_byReadBuffer[j] ^= dwXorKey;
							}
							return DecryptionLamerEL(dwDecStart);
						}
						else
						{
							return DecryptionLamerEL(dwDecStart);
						}
					}
				}
			}
		}
	}
	return 0;
}

int CRepairModuls::DecryptionLamerEL(DWORD m_dwOffset)
{
	DWORD dwNoSectionsOffset,dwLSecPrd = 0,dwLSecSrd = 0,dwCerticatetable = 0,dwPEOffset = 0,m_dwMZOffset=0;
	dwPEOffset = *(DWORD *)&m_byReadBuffer[0x3C];
	if(dwPEOffset > 0x400 || *(WORD *)&m_byReadBuffer[dwPEOffset] != 0x4550)
	{
		m_dwOffset=0;
		return m_dwOffset;
	}

	dwNoSectionsOffset = *(DWORD *)&m_byReadBuffer[0x3C] + 0x06;
	dwCerticatetable = *(DWORD *)&m_byReadBuffer[0x3C] + 0x18 +  0x80;
	dwLSecSrd = *(DWORD *)&m_byReadBuffer[0x3C] + 0x18 + 0xE0 + ((*(WORD *)&m_byReadBuffer[dwNoSectionsOffset] -1) * 0x28) + 0x10;
	dwLSecPrd = *(DWORD *)&m_byReadBuffer[0x3C] + 0x18 + 0xE0 + ((*(WORD *)&m_byReadBuffer[dwNoSectionsOffset] -1) * 0x28) + 0x14;
	if(*(DWORD *)&m_byReadBuffer[dwCerticatetable] != 0)
	{
		if(*(DWORD *)&m_byReadBuffer[dwCerticatetable] == (*(DWORD *)&m_byReadBuffer[dwLSecSrd] + *(DWORD *)&m_byReadBuffer[dwLSecPrd]))
		{
			dwCerticatetable = *(DWORD *)&m_byReadBuffer[dwCerticatetable + 4];
		}
		else
		{
			dwCerticatetable = *(DWORD *)&m_byReadBuffer[dwCerticatetable + 4] + ( *(DWORD *)&m_byReadBuffer[dwCerticatetable] - (*(DWORD *)&m_byReadBuffer[dwLSecSrd] + *(DWORD *)&m_byReadBuffer[dwLSecPrd]));
		}
	}
	else
	{
		dwCerticatetable = 0;
	}
	m_dwOffset += *(DWORD *)&m_byReadBuffer[dwLSecSrd] + *(DWORD *)&m_byReadBuffer[dwLSecPrd] + dwCerticatetable;

	if(m_dwOffset + 0xC <= m_pMaxPEFile->m_dwFileSize )
	{
		DWORD dwReadByte = 0x40;
		if(m_pMaxPEFile->m_dwFileSize - m_dwOffset < 0x40)
		{
			dwReadByte = m_pMaxPEFile->m_dwFileSize - m_dwOffset;
		}
		if(!m_pMaxPEFile->ReadBuffer(m_byReadBuffer,m_dwOffset,dwReadByte,dwReadByte))
		{
			m_dwOffset=0;
			return m_dwOffset;
		}
		int x = 0;
		int counter=0;
		for(int k = 0; k < dwReadByte; k ++)
		{
			const BYTE bySignature[] = {0x53,0x68,0x69,0x74,0x2C,0x49,0x73,0x4F,0x76,0x65,0x72};
			if(memcmp(&m_byReadBuffer[k], bySignature, sizeof(bySignature)) == 0x00)
			{ 
				x=k;
				k+=sizeof(bySignature);
				counter++;
				if(counter ==1)
				{
					m_dwOffset += 0xD;
				}
			}
		}
		if(x != 0)
		{
			m_dwOffset += x;
		}
	}
	return m_dwOffset;
}				
*/
/*-------------------------------------------------------------------------------------
	Function		: InterChangeSectionHeaders
	In Parameters	: WORD wSection1, WORD wSection2
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: exchanges section header info with other section
--------------------------------------------------------------------------------------*/
bool CRepairModuls::InterChangeSectionHeaders(WORD wSection1, WORD wSection2)
{
	wSection1 = m_pMaxPEFile->m_stPEHeader.NumberOfSections - wSection1;
	wSection2 = m_pMaxPEFile->m_stPEHeader.NumberOfSections - wSection2;

	if(wSection1 > m_pMaxPEFile->m_stPEHeader.NumberOfSections - 1 || wSection2 > m_pMaxPEFile->m_stPEHeader.NumberOfSections - 1)
	{
		return false;
	}

	BYTE byBuff[sizeof(IMAGE_SECTION_HEADER) + sizeof(IMAGE_SECTION_HEADER)];
	WORD wSectionRead = wSection1;
	DWORD dwReadSize = sizeof(IMAGE_SECTION_HEADER);

	//Reading from file
	if(wSection2 < wSection1)
	{
		wSectionRead = wSection2;
	}

	if(wSection1 + 1 == wSection2 || wSection2 + 1 == wSection1)
	{
		dwReadSize += dwReadSize;
	}

	if(!m_pMaxPEFile->ReadBuffer(byBuff, m_pMaxPEFile->m_stPEOffsets.Magic + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + wSectionRead * sizeof(IMAGE_SECTION_HEADER), dwReadSize, dwReadSize))
	{
		return false;
	}

	if(dwReadSize == sizeof(IMAGE_SECTION_HEADER))
	{
		if(wSection2 < wSection1)
		{
			wSectionRead = wSection1;
		}
		if(!m_pMaxPEFile->ReadBuffer(&byBuff[sizeof(IMAGE_SECTION_HEADER)], m_pMaxPEFile->m_stPEOffsets.Magic + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + wSectionRead * sizeof(IMAGE_SECTION_HEADER), sizeof(IMAGE_SECTION_HEADER), sizeof(IMAGE_SECTION_HEADER)))
		{
			return false;
		}
	}

	//Actual Interchange
	for(DWORD i = 0; i < sizeof(IMAGE_SECTION_HEADER); i++)
	{
		byBuff[i] ^= byBuff[sizeof(IMAGE_SECTION_HEADER)+i];
		byBuff[sizeof(IMAGE_SECTION_HEADER) + i] = byBuff[i] ^ byBuff[sizeof(IMAGE_SECTION_HEADER) + i];
		byBuff[i] ^= byBuff[sizeof(IMAGE_SECTION_HEADER) + i];
	}

	//Writing back to file
	if(wSection2 < wSection1)
	{
		wSectionRead = wSection2;
	}

	if(!m_pMaxPEFile->WriteBuffer(byBuff, m_pMaxPEFile->m_stPEOffsets.Magic + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + wSectionRead * sizeof(IMAGE_SECTION_HEADER), dwReadSize, dwReadSize))
	{
		return false;
	}

	if(dwReadSize == sizeof(IMAGE_SECTION_HEADER))
	{
		if(wSection2 < wSection1)
		{
			wSectionRead = wSection1;
		}
		if(!m_pMaxPEFile->WriteBuffer(&byBuff[sizeof(IMAGE_SECTION_HEADER)], m_pMaxPEFile->m_stPEOffsets.Magic + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + wSectionRead * sizeof(IMAGE_SECTION_HEADER), sizeof(IMAGE_SECTION_HEADER), sizeof(IMAGE_SECTION_HEADER)))
		{
			return false;
		}
	}
	return true;
}

/*-----------------------------------------------------------------------------------------------------------
Function		: RepairDOCPACK  (Virus.Win32.DocPack.A)
In Parameters		: - 
Out Parameters		: bool
Purpose			: Decompress DOC File.
Author			: Tushar
------------------------------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairDOCPACK()
{
	bool		bResult = false;
	HMODULE		hNtdll = NULL;
	BYTE		*pInBuff = NULL;
	BYTE		*pOutBuff = NULL;
	DWORD		dwInSize = 0x00;
	DWORD		dwOutSize = 0x00;
	DWORD		dwFinalSize = 0x00;

	hNtdll = LoadLibrary(_T("NTDLL.dll"));
	if (NULL == hNtdll)
	{
		return bResult;
	}

	m_pRtlDecompressBuffer = NULL;
	m_pRtlDecompressBuffer = (RTLDecompressBuffer)GetProcAddress(hNtdll,"RtlDecompressBuffer");
	
	if (NULL == m_pRtlDecompressBuffer)
	{
		FreeLibrary(hNtdll);
		hNtdll = NULL;
		return bResult;
	}
	
	DWORD	dwTemp = 0x00, dwBytesRead = 0x00;

	dwTemp = m_pSectionHeader[m_wNoOfSecs - 0x01].PointerToRawData + m_pSectionHeader[m_wNoOfSecs - 0x01].SizeOfRawData+ 0x11;
	dwInSize = m_dwFileSize - dwTemp;

	if (dwInSize == 0x00 || dwInSize == m_dwFileSize)
	{
		FreeLibrary(hNtdll);
		hNtdll = NULL;
		return bResult;
	}

	dwOutSize = dwInSize * 12.5;
	pInBuff = new BYTE[dwInSize];
	pOutBuff = new BYTE[dwOutSize];

	m_pMaxPEFile->ReadBuffer(pInBuff,dwTemp,dwInSize,dwInSize,&dwBytesRead);
	if (dwBytesRead == 0x00)
	{
		delete[] pInBuff;
		delete[] pOutBuff;
		FreeLibrary(hNtdll);
		hNtdll = NULL;
		return bResult;
	}

	if (m_pRtlDecompressBuffer(0x02,pOutBuff,dwOutSize,pInBuff,dwInSize,&dwFinalSize) != 0x00)
	{
		delete[] pInBuff;
		delete[] pOutBuff;
		FreeLibrary(hNtdll);
		hNtdll = NULL;
		return RepairDelete();
	}

	if (dwFinalSize == 0x00)
	{
		delete[] pInBuff;
		delete[] pOutBuff;
		FreeLibrary(hNtdll);
		hNtdll = NULL;
		return bResult;
	}

	m_pMaxPEFile->WriteBuffer(pOutBuff,0x00,dwFinalSize,dwFinalSize);
	//m_pMaxPEFile->TruncateFile(dwFinalSize);
	m_pMaxPEFile->ForceTruncate(dwFinalSize);

	m_bInternalCall = true;
	m_dwArgs[0] = 0x02;
	RenameFile();
	m_bInternalCall = false;
	
	delete[] pInBuff;
	delete[] pOutBuff;
	FreeLibrary(hNtdll);
	hNtdll = NULL;

	return true;
}

/*-----------------------------------------------------------------------------------------------------------
Function		: RepairTrionC  (Virus.Win32.Trion.c)
In Parameters		: - 
Out Parameters		: bool
Purpose			: Decompress PE file.
Author			: Prashant [10-Dec-2012]
Compression		: 1. Check for continues 0x14 zeros
			  2. If it detects then place [R16C + No of Zeros] 2 DWORDS 
			  3. And Remove [no of zeros - 8] zeros
			  4. at the end of file put R16E end of file DWORD.
			  5. Prepend Virus Code size of 0x1004.
------------------------------------------------------------------------------------------------------------*/

bool CRepairModuls::RepairTrionC()
{
	DWORD dwFileSize		= 0;
	DWORD dwInfectedOffset		= 0x0;
	DWORD dwCleanOffset		= 0;
	DWORD dwNoOfZeros		= 0;
	BYTE byZeroCnt			= false;
	BYTE byFileEnd			= false;

	BYTE czZeroCounter[]	= {0x52, 0x31, 0x36, 0x43};		//R16C
	BYTE czFileEnd[]		= {0x52, 0x31, 0x36, 0x45};		//R16E

	dwFileSize = m_pMaxPEFile -> m_dwFileSize;
	
	BYTE *byCleanBuff = new BYTE[dwFileSize];
	BYTE *byInfectedBuff = new BYTE[dwFileSize];

	if(!m_pMaxPEFile->ReadBuffer(byInfectedBuff, 0x1004, dwFileSize - 0x1004, dwFileSize - 0x1004))
	{
		return false;
	}

	while(dwCleanOffset <= dwFileSize)
	{
		if(byInfectedBuff[dwInfectedOffset] == czZeroCounter[0])
		{	
			int iCnt = 0;
			for( int i=0; i < 4; i++)					// Compairing R16C
			{
				if(byInfectedBuff[dwInfectedOffset + i] == czZeroCounter[i])
				{
					iCnt++;
				}
				else
				{
					if(iCnt == 3)						// Checking R16E
					{
						if(byInfectedBuff[dwInfectedOffset + iCnt] == czFileEnd[iCnt])	// E
						{
							byFileEnd = true;
						}
					}
					else
					{
						break;
					}
				}

				if(iCnt == 4)
				{
					byZeroCnt = true;
				}
			}
			if(byZeroCnt == true)
			{
				dwNoOfZeros = *(DWORD *)&byInfectedBuff[dwInfectedOffset + 4] + 0x8;
				dwInfectedOffset += 8;
			}
		}
		
		if( byZeroCnt == true)							// Filling Zeros
		{
			for(DWORD dwIndex = 0; dwIndex < dwNoOfZeros; dwIndex++)
			{
				byCleanBuff[dwCleanOffset++] = 0x00;
			}
			byZeroCnt = false;
		}
		else											// Original data filling 
		{
			byCleanBuff[dwCleanOffset++] = byInfectedBuff[dwInfectedOffset++];
		}

	}//End while
	
	if(byFileEnd == true)
	{
		m_pMaxPEFile->FillWithZeros(0,dwFileSize);
		
		for(DWORD dwIndex = 0; dwIndex < 0x4; dwIndex++)					// Clear R16E
		{
			byCleanBuff[(dwFileSize - 4) +  dwIndex] = 0x00;
		}
		if(!m_pMaxPEFile->WriteBuffer(byCleanBuff,0,dwFileSize,dwFileSize))	// Writing to PE File
		{
			return false;
		}
		m_pMaxPEFile->ForceTruncate(dwFileSize);
	}
	return true;
}

/************************************************************************************************************
Function		: RepairLamer  (Virus.MSIL.Lamer.a)
In Parameters		: - 
Out Parameters		: bool
Purpose			: Getting decimal number from string of specified size.
Added by		: Gajanan Vaikunthe
m_dwArgs[1] :  File offset 
m_dwArgs[2] :  Size of string
'\0' is added at end for consideration of string , gives number up to non converting character  
**************************************************************************************************************/
bool CRepairModuls::RepairLamer()
{

                DWORD dwOff=0x0;
                DWORD dwSize=0;
                DWORD *pdwByteRead=0;
                BYTE  *byBuff;

                if(!m_dwArgs[1]|| !m_dwArgs[2])
                {
					return false;
                }

                dwOff=m_dwArgs[1];   //File offset 
                dwSize=m_dwArgs[2];  //Size of string
                byBuff=new BYTE[dwSize];


                if(!m_pMaxPEFile->ReadBuffer(byBuff,dwOff,dwSize,dwSize,pdwByteRead))
                {
                     return false;
                }

                byBuff[dwSize]='\0';
                m_dwReturnValues[0]=atoi((char *)byBuff);
                return true;

}       


/*-----------------------------------------------------------------------------------------------------------
Function	: RepairPIONEERBT  (Virus.Win32.Pioneer.bt)
In Parameters	: DWORD dwOffset ,DWORD dwLen ,DWORD dwXORKey
Out Parameters	: bool
Purpose		: To calculate DWORD(OEP) value and set the AEP of the file to this calculated OEP value
Author		: Ramandeep [27-Aug-2014]
Remark          :The OEP is divided between two dwords (3 LSbytes from the 1st Dword starting from AEP and MSByte
                 of second Dword starting from AEP).
Use             :23#[C32]["Offset"]["lenght"]["key"]

------------------------------------------------------------------------------------------------------------*/
bool CRepairModuls::RepairPIONEERBT()
{
	DWORD dwStartOffset	= 0; //initialization
	DWORD dwBuffSize        = 0;
	DWORD dwXorKey          = 0;
	DWORD dwNewAEP          = 0;
	BYTE  *byReadBuffer ;	

	dwBuffSize = m_dwArgs[2];
	dwXorKey   = m_dwArgs[3];
	dwStartOffset= m_dwArgs[1];

	byReadBuffer = new BYTE[dwBuffSize];	

	if(NULL == byReadBuffer)
	{
		return false;
	}
	memset(byReadBuffer, 0,dwBuffSize);	
	if(!m_pMaxPEFile->ReadBuffer(byReadBuffer, dwStartOffset, dwBuffSize, dwBuffSize))
	{
		delete[] byReadBuffer; 
		byReadBuffer = NULL;
		return false;
	}
	//logic to perform xor on the two dwords and copy the required data in 3rd dword(the OEP)

	(*(DWORD*)&byReadBuffer[0x0]) = (*(DWORD*)&byReadBuffer[0x0])^ dwXorKey;
	(*(DWORD*)&byReadBuffer[0x4]) = (*(DWORD*)&byReadBuffer[0x4])^ dwXorKey;
	(*(DWORD*)&byReadBuffer[0x8]) = (*(DWORD*)&byReadBuffer[0x0]);
	dwNewAEP=(*(DWORD*)&byReadBuffer[0x7]);

	if(byReadBuffer)
	{
		delete[] byReadBuffer; 
		byReadBuffer = NULL;
	}
	if(!m_pMaxPEFile->WriteAEP(dwNewAEP)) //change AEP with OEP
		return false;

	return true;
}

/*-----------------------------------------------------------------------------
Function		: CleanLNKFile
In Parameters	: -
Out Parameters	: -
Purpose			: Routine for clean infected LNK files of Browsers.
Author			: Sourabh Kadam
Description		: This Routine will clean Browsers LNK type files
-----------------------------------------------------------------------------*/
bool CRepairModuls::CleanLNKFile()
{
	
	
	HRESULT				hres; 
    IShellLink*			psl; 
	WCHAR				szGotPath[MAX_PATH] = {0x00}; 
    WIN32_FIND_DATA		wfd; 
	bool				bLnkFixed = false;
	TCHAR				szLNKFilePath[MAX_PATH] = {0x00};

	_tcscpy(szLNKFilePath,m_pMaxPEFile->m_szFilePath);

	if (m_pMaxPEFile)
	{
		m_pMaxPEFile->CloseFile();
	}

	CoInitialize(NULL);

    // Get a pointer to the IShellLink interface.
    hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl); 
    if (SUCCEEDED(hres)) 
    { 
        IPersistFile* ppf; 
        // Get a pointer to the IPersistFile interface. 
        hres = psl->QueryInterface(IID_IPersistFile, (void**)&ppf); 

        if (SUCCEEDED(hres)) 
        { 
            // Load the shortcut. 
            hres = ppf->Load(szLNKFilePath, STGM_READ); 

            if (SUCCEEDED(hres)) 
            { 
                // Get the path to the link target. 
                hres = psl->GetPath(szGotPath, MAX_PATH, (WIN32_FIND_DATA*)&wfd, SLGP_SHORTPATH); 

                if (SUCCEEDED(hres))
                {
                    //hres = psl->SetPath(newTargetPath);
					hres = psl->SetArguments(_T(""));
                    hres = ppf->Save(szLNKFilePath, TRUE); //save changes
					if (SUCCEEDED(hres)) 
					{ 
						bLnkFixed = true;
					}
                }
                else
                {
                    // Handle the error
                }

            } 
            // Release the pointer to the IPersistFile interface. 
            ppf->Release(); 
        } 
        // Release the pointer to the IShellLink interface. 
        psl->Release(); 
    } 
	CoUninitialize();
    return bLnkFixed; 
}

/************************************************************************************************************
Function		: RepairRecyl
In Parameters		: - 
Out Parameters		: bool
Purpose			: Rename extension
Added by		: Swapnil Sanghai + Sneha Kurade
Expression 		: 23#[C34]
**************************************************************************************************************/
bool CRepairModuls::RepairRecyl()
{
	WORD		wLastSecNo		 = m_wNoOfSecs - 1;
	DWORD		dwStartOfOverlay = m_pSectionHeader[wLastSecNo].PointerToRawData + m_pSectionHeader[wLastSecNo].SizeOfRawData;
	DWORD		dwOverlaySize = m_dwFileSize - dwStartOfOverlay;
	const		DWORD dwChunkSize	=  0x5000; 
	BYTE		bBuffer[dwChunkSize]= {0x00};

	CString		csFullFilePath(m_csFilePath);
	csFullFilePath.MakeLower();

	const BYTE PDF_HEADER[0x4] = {0x25, 0x50, 0x44, 0x46};
	const BYTE DOC_HEADER[0x8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
	const BYTE DOCX_HEADER[0x8] = {0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00};

	DWORD	dwBytesRead = 0x00;
	DWORD dwOffset = dwStartOfOverlay;

	//FOR .pdf files
	if(csFullFilePath.Right(8) == _T(".pdf.exe"))
	{

		if (dwOverlaySize == 0x46316 || dwOverlaySize == 0x6EE3F || dwOverlaySize == 0xDCDF7)
		{
			dwOffset =  dwStartOfOverlay + 0x19000;
		}
		else if(m_dwAEPMapped == 0xC76E) //added
		{
			dwOffset = dwStartOfOverlay + 0x5EC70;
		}
		else {
			dwOffset = dwStartOfOverlay;
		}
		for(dwOffset ; dwOffset >= (dwStartOfOverlay - dwChunkSize); dwOffset -= 0x1000)
		{

			dwBytesRead = 0;
			memset(bBuffer, 0, sizeof(bBuffer));
			m_pMaxPEFile->ReadBuffer(bBuffer, dwOffset, dwChunkSize, 0, &dwBytesRead);
			for(int iSigOffset = dwBytesRead - 1; iSigOffset >= 0; iSigOffset--)
			{
				if(_memicmp(&bBuffer[iSigOffset], PDF_HEADER, sizeof(PDF_HEADER)) == 0)
				{
					iSigOffset += dwOffset;
					if(CopyData(iSigOffset, 0, m_dwFileSize - iSigOffset))
					{
						m_bInternalCall = true;
						m_dwArgs[0]		= m_dwFileSize - iSigOffset;
						if(SetFileEnd())
						{
							m_bInternalCall = false;
							TCHAR szOrgFileName[MAX_PATH];						
							_tcscpy_s(szOrgFileName, MAX_PATH, m_csFilePath);
							LPTSTR lptPtr = _tcsrchr(szOrgFileName, _T('.'));
							if(lptPtr)
							{
								*lptPtr = 0; 
								m_pMaxPEFile->CloseFile(); 
								MoveFile(m_csFilePath, szOrgFileName);
								return true;
							}
						}
					}
					return false;
				}
			}
			dwOffset += sizeof(PDF_HEADER);
		} 
		RepairDelete();// Added
	}


	//FOR .doc files
	if (csFullFilePath.Right(8) == _T(".doc.exe")  && dwOverlaySize > 0x00 ) 
	{

		for(dwOffset; dwOffset >= (dwStartOfOverlay - dwChunkSize); dwOffset -= 0x1000)
		{
			dwBytesRead = 0;
			memset(bBuffer, 0, sizeof(bBuffer));
			m_pMaxPEFile->ReadBuffer(bBuffer, dwOffset, dwChunkSize, 0, &dwBytesRead);
			for(int iSigOffset = dwBytesRead - 1; iSigOffset >= 0; iSigOffset--)
			{
				if(_memicmp(&bBuffer[iSigOffset], DOC_HEADER, sizeof(DOC_HEADER)) == 0)
				{
					iSigOffset += dwOffset;
					if(CopyData(iSigOffset, 0, m_dwFileSize - iSigOffset))
					{
						m_bInternalCall = true;
						m_dwArgs[0]		= m_dwFileSize - iSigOffset;
						if(SetFileEnd())
						{
							m_bInternalCall = false;
							TCHAR szOrgFileName[MAX_PATH];						
							_tcscpy_s(szOrgFileName, MAX_PATH, m_csFilePath);
							LPTSTR lptPtr = _tcsrchr(szOrgFileName, _T('.'));
							if(lptPtr)
							{
								*lptPtr = 0; 
								m_pMaxPEFile->CloseFile(); 
								MoveFile(m_csFilePath, szOrgFileName);
								return true;
							}
						}
					}
					return false;
				}
			}
			dwOffset += sizeof(DOC_HEADER);
		}
		return false;
	}
	//FOR docx files
	if (csFullFilePath.Right(9) == _T(".docx.exe") && dwOverlaySize > 0x00)
	{

		if (dwOverlaySize == 0x28A34F || dwOverlaySize == 0x19208)
		{
			dwOffset =  dwStartOfOverlay + 0xC000;
		}
		else if(dwOverlaySize == 0x63C67)// added
		{
			dwOffset =  dwStartOfOverlay + 0x4400F;  
		}
		else 
		{
			dwOffset = dwStartOfOverlay;
		}
		for(dwOffset; dwOffset >= (dwStartOfOverlay - dwChunkSize); dwOffset -= 0x1000)
		{
			dwBytesRead = 0;
			memset(bBuffer, 0, sizeof(bBuffer));
			m_pMaxPEFile->ReadBuffer(bBuffer, dwOffset, dwChunkSize, 0, &dwBytesRead);
			for(int iSigOffset = dwBytesRead - 1; iSigOffset >= 0; iSigOffset--)
			{
				if(_memicmp(&bBuffer[iSigOffset], DOCX_HEADER, sizeof(DOCX_HEADER)) == 0)
				{
					iSigOffset += dwOffset;
					if(CopyData(iSigOffset, 0, m_dwFileSize - iSigOffset))
					{
						m_bInternalCall = true;
						m_dwArgs[0]		= m_dwFileSize - iSigOffset;
						if(SetFileEnd())
						{
							m_bInternalCall = false;
							TCHAR szOrgFileName[MAX_PATH];						
							_tcscpy_s(szOrgFileName, MAX_PATH, m_csFilePath);
							LPTSTR lptPtr = _tcsrchr(szOrgFileName, _T('.'));
							if(lptPtr)
							{
								*lptPtr = 0; 
								m_pMaxPEFile->CloseFile(); 
								MoveFile(m_csFilePath, szOrgFileName);
								return true;
							}
						}
					}
					return false;
				}
			}
			dwOffset += sizeof(DOCX_HEADER);
		} 
		return false;
	}
	if (csFullFilePath.Right(8) == _T(".exe.exe") || csFullFilePath.Right(4) == _T(".exe") || csFullFilePath.Right(5) == _T(".docx") || csFullFilePath.Right(4) == _T(".tmp") || dwOverlaySize <= 0x00) //Added
	{
		RepairDelete();
	}
	return false;
}

/*-----------------------------------------------------------------------------
Function		: RepairShipUp
Author			: Sneha Kurade
Input			: csFilePath  
Output			:   
Purpose			: Clean infected .jpg, .xls, .fas, .dwg files
Description		: This Routine will remove the .exe extension of this files
                          Use:23#[C35]
-----------------------------------------------------------------------------*/
bool CRepairModuls::RepairShipUp()
{
	WORD	wLastSecNo		 = m_wNoOfSecs - 1;
	const	DWORD dwChunkSize	= 0x100; 
	BYTE	bBuffer[dwChunkSize]= {0x00};

	//F.I.L.E signature string
	const BYTE FILE[0x7] = {0x46, 0x00, 0x49, 0x00, 0x4C, 0x00, 0x45};


	DWORD	dwBytesRead = 0x00; 

	// Read file from the end of the file.
	for(DWORD dwOffset = 0x9250; dwOffset >= dwChunkSize; dwOffset -= 0x1000)
	{
		dwBytesRead = 0;
		memset(bBuffer, 0, sizeof(bBuffer));

		m_pMaxPEFile->ReadBuffer(bBuffer, dwOffset, dwChunkSize, 0, &dwBytesRead);
		if(dwBytesRead <= 0)
			break;


		for(int iSigOffset = dwBytesRead - 1; iSigOffset >= 0x0; iSigOffset--)
		{
			if(_memicmp(&bBuffer[iSigOffset], FILE, sizeof(FILE)) == 0)
			{
				// Found signature string
				iSigOffset += dwOffset + 0x0A;

				// Copy original file from found offset
				if(CopyData(iSigOffset, 0, m_dwFileSize - iSigOffset))
				{
					m_bInternalCall = true;
					m_dwArgs[0]		= m_dwFileSize - iSigOffset;
					if(SetFileEnd())
					{
						m_bInternalCall = false;

						// Virus appends .exe extension to the original file so remove the extension
						TCHAR szOrgFileName[MAX_PATH];						
						_tcscpy_s(szOrgFileName, MAX_PATH, m_csFilePath);
						LPTSTR lptPtr = _tcsrchr(szOrgFileName, _T('.'));
						if(lptPtr)
						{
							*lptPtr = 0; 
							m_pMaxPEFile->CloseFile(); 
							MoveFile(m_csFilePath, szOrgFileName);
							return true;
						}
					}
				}// end of if loop and we replaced orignal data
				return false;
			}
		}			
		// To cover if signature string lies on chunck boundries
		dwOffset += sizeof(FILE);
	} // end while outer

	return false;

}


/*-----------------------------------------------------------------------------
Function		: RepairRansom
Author			: Sneha Kurade
Input			: csFilePath  
Output			:   
Purpose			: Clean infected .pdf, .docx files
Description		: This Routine will remove the .scr extension of this files
                          Use:23#[C36]
-----------------------------------------------------------------------------*/
bool CRepairModuls::RepairRansom()
{
	wchar_t szExtension[MAX_INPUT_STR_PARAM] = {0};

	WORD	wLastSecNo		 = m_wNoOfSecs - 1;
	const	DWORD dwChunkSize	= 0x124; 
	BYTE	bBuffer[dwChunkSize]= {0x00};
	DWORD    m_dwHeader = 0x0;


	CString		csFullFilePath(m_csFilePath);
	csFullFilePath.MakeLower();

	//Stub/do.vine signature string
	const BYTE STUBDOVINE[0xC] = {0x53, 0x74, 0x75, 0x62, 0x2F, 0x64, 0x6F, 0x2E, 0x76, 0x69, 0x6E, 0x65};
	DWORD	dwBytesRead = 0x00; 

	// Read file from the end of the file.
	for(DWORD dwOffset = 0xF725C; dwOffset >= dwChunkSize; dwOffset -= 0x1000)
	{
		dwBytesRead = 0;
		memset(bBuffer, 0, sizeof(bBuffer));

		m_pMaxPEFile->ReadBuffer(bBuffer, dwOffset, dwChunkSize, 0, &dwBytesRead);
		if(dwBytesRead <= 0)
			break;


		for(int iSigOffset = dwBytesRead - 1; iSigOffset >= 0x0; iSigOffset--)
		{
			if(_memicmp(&bBuffer[iSigOffset], STUBDOVINE, sizeof(STUBDOVINE)) == 0)
			{
				// Found signature string
				iSigOffset += dwOffset + 0x4A;  


				// Copy original file from found offset
				if(CopyData(iSigOffset, 0, m_dwFileSize - iSigOffset))
				{
					m_bInternalCall = true;
					m_dwArgs[0]		= m_dwFileSize - iSigOffset;
					if(SetFileEnd())
					{
						m_bInternalCall = false;

						TCHAR m_szOrgFileName[MAX_PATH];						
						_tcscpy_s(m_szOrgFileName, MAX_PATH, m_csFilePath);
						LPTSTR lptPtr = _tcsrchr(m_szOrgFileName, _T('.'));
						if(lptPtr)
						{
							*lptPtr = 0; 

							m_csOriginalFilePath = m_szOrgFileName;

							if(m_pMaxPEFile->ReadBuffer(&m_dwHeader, iSigOffset, 0x4, 0x4))
							{
								if(m_dwHeader == 0x46445025)
								{
									m_csOriginalFilePath.Append(L".pdf");
								}
								else
								{
									m_csOriginalFilePath.Append(L".docx");
								}
							}

							//m_csOriginalFilePath.Append(szExtension);
							m_pMaxPEFile->CloseFile(); 
							MoveFile(m_csFilePath, m_csOriginalFilePath);
							return true;
						}




					}
				}// end of if loop and we replaced orignal data
				return false;
			}
		}			
		// To cover if signature string lies on chunck boundries
		dwOffset += sizeof(STUBDOVINE);
	} // end while outer

	return false;

}

/*-----------------------------------------------------------------------------
Function		: RepairLAMEREL
Author			: Sneha Kurade
Input			: csFilePath  
Output			:   
Purpose			: Clean infected .pdf, .docx files
Description		: This Routine will remove the .scr extension of this files
                          Use:23#[C37]
-----------------------------------------------------------------------------*/
bool CRepairModuls::RepairLAMEREL()
{

	WORD	wLastSecNo		 = m_wNoOfSecs - 1;
	DWORD	dwStartOfOverlay = m_pSectionHeader[wLastSecNo].PointerToRawData + m_pSectionHeader[wLastSecNo].SizeOfRawData;
	const	DWORD dwChunkSize	=  0x2000; 
	BYTE	bBuffer[dwChunkSize]= {0x00};
	DWORD   m_dwHeader = 0x0;
	DWORD   m_dwFirstSecOffset = 0x0;  
	byte    byXorKey = 0x0;
	int     m_iMZCheck = 0x0;
	DWORD   dwCopyDataSize = 0x0;

	const BYTE LAMEREL[0xD] = {0x56, 0x62, 0x45, 0x78, 0x65, 0x46, 0x69, 0x6C, 0x65, 0x42, 0x69, 0x6E, 0x64}; 
	DWORD	dwBytesRead = 0x00; 


	for(DWORD dwOffset = m_dwFileSize - dwChunkSize; dwOffset >= (dwStartOfOverlay - dwChunkSize); dwOffset -= 0x2000)
	{
		dwBytesRead = 0;
		memset(bBuffer, 0, sizeof(bBuffer));

		m_pMaxPEFile->ReadBuffer(bBuffer, dwOffset, dwChunkSize, 0, &dwBytesRead);
		if(dwBytesRead <= 0)
			break;


		for(int iSigOffset = dwBytesRead - 1; iSigOffset >= 0x0; iSigOffset--)
		{
			if(_memicmp(&bBuffer[iSigOffset], LAMEREL, sizeof(LAMEREL)) == 0)
			{

				iSigOffset += dwOffset + 0xD;  

				m_pMaxPEFile->ReadBuffer(bBuffer, iSigOffset, 0x450, 0, &dwBytesRead);

				if(*(WORD *)&bBuffer[0]!= 0x5a4d)
				{
					byXorKey = 0x63;
					for(int m_iMZCheck = 0; m_iMZCheck < 0x10;  m_iMZCheck++)
					{
						if(*(WORD *)&bBuffer[m_iMZCheck] == 0x392E)
							break;
					}

					for(int j = m_iMZCheck; j <= (0x63 + m_iMZCheck);  j++)
					{
						bBuffer[j] ^= byXorKey;
					}

					byXorKey = 0x44;
					m_dwFirstSecOffset = *(DWORD *)&bBuffer[0x3C]; 
					m_dwFirstSecOffset = *(DWORD *)&bBuffer[m_dwFirstSecOffset+0x10C];

					for(int j = m_dwFirstSecOffset - 0x19; j < m_dwFirstSecOffset + 0x4C;  j++)
					{
						bBuffer[j] ^= byXorKey;

					}

					if(m_pMaxPEFile->WriteBuffer(bBuffer, 0, m_dwFirstSecOffset+0x4C, m_dwFirstSecOffset+0x4C))
					{
						m_dwArgs[0]		= m_dwFileSize - iSigOffset - 0x0D;
						dwCopyDataSize  = m_dwArgs[0]-(m_dwFirstSecOffset + 0x4C)-0x0D;

						if(CopyData(iSigOffset + m_dwFirstSecOffset + 0x4C, m_dwFirstSecOffset + 0x4C, dwCopyDataSize, dwCopyDataSize))
						{
							m_bInternalCall = true;

							if(SetFileEnd())
							{
								return true;
							}
						}

					}

					return false;
				}
			}
		}			

		dwOffset += sizeof(LAMEREL);
	} 

	return false;

}

bool CRepairModuls::RepairPIONEERCZ()
{
	bool	bRetStatus = false;

	CString		csFullFilePath(m_csFilePath);
	csFullFilePath.MakeLower();


	TCHAR m_szOrgFileName[MAX_PATH];						
	_tcscpy_s(m_szOrgFileName, MAX_PATH, m_csFilePath);
	LPTSTR lptPtr = _tcsrchr(m_szOrgFileName, _T('.'));
	if(lptPtr)
	{
		*lptPtr = 0; 

		m_csOriginalFilePath = m_szOrgFileName;

		m_csOriginalFilePath.Append(L".max");
	}
	m_pMaxPEFile->CloseFile(); 
	MoveFile(m_csFilePath, m_csOriginalFilePath);

	CreateDirectory(m_csFilePath,NULL);

	/*
	CRegistry objReg;
	objReg.DeleteKey(_T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\"),_T("LoadAppInit_DLLs"),HKEY_LOCAL_MACHINE);
	objReg.DeleteValue(_T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\"),_T("RequireSignedAppInit_DLLs"),HKEY_LOCAL_MACHINE);
	objReg.Set(_T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\"),_T("AppInit_DLLs"),_T(""),HKEY_LOCAL_MACHINE);
	*/
	return true;
}

bool CRepairModuls::RepairMultiLevPrependerInf()
{

	DWORD	dwStartOfOverlay = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSecs - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSecs - 1].PointerToRawData;
	const	DWORD dwChunkSize	= 0x5000; 
	BYTE	bBuffer[dwChunkSize]= {0x00};

	//MZ-PE signature string
	const BYTE byCheckMZ[] = {0x4D,0x5A};
	const BYTE byCheckPE[] = {0x50,0x45};

	DWORD	dwBytesRead = 0x00; 


	// Read file from the end of the file.
	for(DWORD dwOffset = m_dwFileSize - dwChunkSize; dwOffset >= (dwStartOfOverlay - dwChunkSize); dwOffset -= 0x5000)
	{
		dwBytesRead = 0;
		memset(bBuffer, 0, sizeof(bBuffer));

		m_pMaxPEFile->ReadBuffer(bBuffer, dwOffset, dwChunkSize, 0, &dwBytesRead);
		if(dwBytesRead <= 0)
			break;

		for(int iSigOffset = dwBytesRead - 1; iSigOffset >= 0; iSigOffset--)
		{
			//Check MZ offset
			if(_memicmp(&bBuffer[iSigOffset], byCheckMZ, sizeof(byCheckMZ)) == 0)
			{
				DWORD dwCheckPEoffset;
				dwCheckPEoffset = iSigOffset + dwOffset + 0x3C;
				DWORD dwPEoffset = 0x00;
				//Check PE offset
				m_pMaxPEFile->ReadBuffer(&dwPEoffset, dwCheckPEoffset, 0x04, 0x04);

				if(dwPEoffset > 0x0500)
					continue;

				DWORD PEOffset;
				PEOffset = iSigOffset + dwPEoffset;

				if(_memicmp(&bBuffer[PEOffset], byCheckPE, sizeof(byCheckPE)) == 0)
				{
					// Found signature string
					iSigOffset += dwOffset;

					// Copy original file from found offset
					if(CopyData(iSigOffset, 0, m_dwFileSize - iSigOffset))
					{
						m_bInternalCall = true;
						m_dwArgs[0]	= m_dwFileSize - iSigOffset;
						if(SetFileEnd())
						{
							m_bInternalCall = false;
							return true;
						}
					}// end of if loop and we replaced orignal data
					return false;
				}
			}
		}			
		// To cover if signature string lies on chunck boundries
		dwOffset += sizeof(byCheckMZ);
	} // end while outer

	return RepairDelete();
}

//Sagar Bade
bool CRepairModuls::RepairLamerCQ()
{ 
	const	DWORD dwChunkSize	= 0x5000; 
	BYTE	bBuffer[dwChunkSize]= {0x00};
	DWORD dwBytesRead=0x0;
	DWORD dwCheckVisua=0x0;
	bool bCQCheckMatched=false;
	const BYTE byCheckvisuamz[] = {0x76,0x69,0x73,0x75,0x61,0x4D,0x5A};

	DWORD dwStartOfOverlay = m_pSectionHeader[m_wNoOfSecs-1].PointerToRawData + m_pSectionHeader[m_wNoOfSecs-1].SizeOfRawData;
	if(m_pMaxPEFile->ReadBuffer(&dwCheckVisua,dwStartOfOverlay,0x04,0x04))
	{
		if(dwCheckVisua == 0x75736976)
		{
			bCQCheckMatched = true;
		}
	}
	if (bCQCheckMatched == true)
	{

		//DWORD dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData;

		DWORD dwCheckVisua = 0x0;
		for(DWORD dwOffset = m_dwFileSize - dwChunkSize; dwOffset >= dwStartOfOverlay; dwOffset -= 0x1000)
		{
			dwBytesRead = 0;
			memset(bBuffer, 0, sizeof(bBuffer));

			m_pMaxPEFile->ReadBuffer(bBuffer, dwOffset, dwChunkSize, 0, &dwBytesRead);
			if(dwBytesRead <= 0)
				break;
			for(int iSigOffset = dwBytesRead - 1; iSigOffset >= 0; iSigOffset--)
			{

				if(_memicmp(&bBuffer[iSigOffset], byCheckvisuamz, sizeof(byCheckvisuamz)) == 0)
				{
					DWORD dworifileoffset=dwOffset+iSigOffset+5;
					if(CopyData(dworifileoffset, 0, m_dwFileSize - dworifileoffset))
					{
						if(m_pMaxPEFile->TruncateFile(m_dwFileSize - dworifileoffset))
						{
							return true;
						}
					}
				}

			}
		}
		return RepairDelete();
	}
	return false;
}