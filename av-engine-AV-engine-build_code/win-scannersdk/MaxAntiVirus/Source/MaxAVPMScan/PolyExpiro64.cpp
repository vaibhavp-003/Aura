/*======================================================================================
FILE				: PolyExpiro64.cpp
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam + Virus Analysis Team
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This is detection module for malware Expiro (x64) Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyExpiro64.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyExpiro64
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyExpiro64::CPolyExpiro64(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile), m_dwPatchSize(0), m_AppendToLastSec(false)
 {
	m_pbyBuff = new BYTE[EXPIRO64_BUFF_SIZE];
	DetectVirus();
	
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyExpiro64
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyExpiro64::~CPolyExpiro64()
{
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Expiro (x64) Family
--------------------------------------------------------------------------------------*/
int CPolyExpiro64::DetectVirus()
{
	/*
	//Commented to cover new varients from both 32Bit and 64Bit
	if(false == m_pMaxPEFile->m_b64bit)
		return VIRUS_NOT_FOUND;
	*/	
	// Chk 1: Last section
	if(((m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000000) == 0xE0000000) ||
		((m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].Characteristics & 0x42000040) == 0x42000040) ||
		((m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].Characteristics & 0x40000040) == 0x40000040))
	{	

		// Chk 2: AEP bytes  
		BYTE byCheck2[] = {0x55, 0x48, 0x89, 0xE5, 0x53, 0x56, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0xD0, 0x00},
			byCheck2G3[] = {0x55, 0x48, 0x89, 0xE5, 0x56,0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC},//added
			byCheck2G2[] = {0x55, 0x48, 0x89, 0xE5, 0x56, 0x57, 0x41, 0x55, 0x41, 0x57, 0x48, 0x81, 0xEC, 0xA0, 0x00},//added
			byCheck2G1[] = {0x55, 0x48, 0x89, 0xE5, 0x53, 0x56, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x10, 0x01,0x00},
			byCheck2G[] = {0x55, 0x48, 0x89, 0xE5, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0xE0, 0x00},//Added for expiro.g (Gaurav)
			byCheck2D[] = {0x55, 0x48, 0x89, 0xE5, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0xD0, 0x00},// xPiro.d
			byCheck2E[] = {0x55, 0x48, 0x89, 0xE5, 0x56, 0x48, 0xFF, 0xCE, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC},// xPiro.e Virus code at the end of last section
			byCheck2F0[]= {0x57, 0x45, 0x51, 0x43, 0x57, 0x4F, 0xB9},
			byCheck2F1[]= {0x4C, 0x01, 0xDF, 0xE8, 0x2A, 0x00, 0x00, 0x00, 0x4D, 0xBF, 0x80, 0xE3},
			byCheck2F2[]= {0x47, 0x50, 0x57, 0x43, 0x56, 0x43, 0xBE, 0x30, 0x35},
			byCheck2F3[]= {0xE8, 0x29, 0x00, 0x00, 0x00, 0x4F, 0xBE, 0xC0, 0xE3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4F, 0xB8, 0x88},
			byCheck2F4[]= {0x43, 0x53, 0x53, 0x51, 0x4F, 0xBB, 0x60},
			byCheck2F5[]= {0x56, 0x41, 0x50, 0x41, 0x51, 0x4C}, 
			byCheck2F6[]= {0x51, 0x52, 0x43, 0x56, 0x48, 0xB9, 0x60},
			byCheck2F7[]= {0x50, 0x45, 0x50, 0x51, 0xB9, 0xD0, 0x4D, 0x04}, 
			byCheck2F8[]= {0x53, 0x57, 0x56, 0x43, 0x57, 0xBE, 0x00, 0x4A}, 
			byCheck2F9[]= {0x50, 0x51, 0x41, 0x57, 0x29, 0xC0, 0x83, 0xC0}, 
			byCheck2FA[]= {0x50, 0x43, 0x56, 0x43, 0x53, 0x48, 0x29, 0xC0}, 
			byCheck2FB[]= {0x55, 0x48, 0x89, 0xE5}, 
			byCheck2FC[]= {0x50, 0x41, 0x53, 0x47, 0x56, 0x48, 0xB8, 0x60}, //ADDED 
			byCheck2FD[]= {0x51, 0x50, 0x47, 0x57, 0x2B, 0xC9, 0x83, 0xC1}, //ADDED
			byCheck2FE[]= {0x56,0x50,0x41,0x53,0x48,0x29,0xF6,0x48,0x83,0xC6,0x60,0x65,0x4A,0x8B,0x06,0x47}, //Added for expiro.g (Swapnil)
			byCheck2FF[]= {0x47,0x52,0x57,0x45,0x53,0x4F,0x29,0xD2,0x4B,0x83,0xC2,0x60,0x65,0x4B,0x8B,0x3A}, //Added for expiro.g (Swapnil)
			byCheck2FG[]= {0x52,0x51,0x45,0x56,0x4C,0xBA,0x60,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x65,0x48}, //Added for expiro.g (Swapnil)
			byCheck2FH[]= {0x43,0x54,0x51,0x47,0x57,0x43,0xBC,0x60,0x00,0x00,0x00,0x65},			 //Added for expiro.g (Swapnil)
			byCheck2FI[]= {0x52,0x43,0x57,0x43,0x54,0xBA,0x60,0x00,0x00,0x00,0x65,0x4E,0x8B,0x3A},		 //Added for expiro.g (Swapnil)
			byCheck2FJ[]= {0x53,0x57,0x43,0x57,0x4C,0xBB,0xA1,0x57,0x00,0x00,0x00,0x00,0x00,0x00,0x4F}, //Added for expiro.g (Swapnil)
			byCheck2FK[]= {0x51,0x52,0x47,0x55,0x4A,0xB9,0x60,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x65,0x4A}, //Added AEP Bytes
			byCheck2FM[]= {0x57,0x56,0x52,0xBF,0x30,0x00,0x00,0x00,0x64,0x8B,0x37,0x50,0x8B},
			byCheck2FN[]= {0x47,0x57,0x45,0x52,0x52,0x41,0xBF,0x60},
			byCheck2FO[]= {0x53,0x57,0x43,0x57,0x4C,0xBB,0xCE,0x25}, //ADDED BY SNEHA 
			byCheck2FL[]= {0x50,0x52,0x51,0x8D,0x05,0x30,0x00,0x00,0x00,0x64,0x8B,0x10,0x53,0x89},
			byCheck2FS[]= {0x41,0x55,0x51,0x53,0x48,0xB9,0x00},//Added Sneha 20 Nov 2019
			byCheck2FT[]= {0x47,0x50,0x53,0x47,0x56,0x41,0xBE,0x80,0x3C,0x04, 0x00},//Added Sneha 20 Nov 2019
			byCheck2FU[]= {0x53,0x45,0x57,0x47,0x54,0x47,0x52,0x41},//Added Sneha 20 Nov 2019
			//byCheck2FV[]={0x47,0x55,0x41,0x51,0x41,0x56,0x45,0xBE,0xF0,0x15,0x04,0x00,0x4F,0xB9,0x00,0x50,0x0A,0x40,0x01,0x00,0x00,0x00,0x57,0x45};//Added by sagar 16 june 2020
			byCheck2FW[] = {0x47,0x55,0x41,0x51,0x41,0x56,0x45,0xBE,0xF0,0x15},		//  Newly Added Expiro.F
			byCheck2FX[] = {0x47,0x53,0x41,0x55,0x45,0x56,0x45,0xBB,0x60,0x00},
			byCheck2FY[]= {0x43,0x54,0x47,0x50,0x51,0x4F,0xBC,0x60, 0x00}, //Newly Added Expiro.RD
			byCheck2FZ[]= {0x47, 0x51, 0x50, 0x45, 0x52, 0x43, 0xB9, 0x60, 0x00, 0x00, 0x00}, //Newly Added Expiro64.Gen
			byCheck100[]= {0x52, 0x50, 0x53, 0xBA, 0x18, 0x00, 0x00, 0x00, 0x64}, //Newly Added Expiro.Gen
			byCheck101[]= {0x51,0x50,0x52,0x8D,0x0D,0x18,0x00,0x00,0x00,0x64,0x8B,0x01,0x01,0xC8}; //51,50,52,8D,0D,18,00,00,00,64
	


		if(memcmp(byCheck2, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2))!= 0 
			&& memcmp(byCheck2G3, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2G3))!= 0 
			&& memcmp(byCheck2G2, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2G2))!= 0 
			&& memcmp(byCheck2G, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2G))!= 0 
			&& memcmp(byCheck2G1, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2G1))!= 0
			&& memcmp(byCheck2D, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2D))!= 0 
			&& memcmp(byCheck2E, m_pMaxPEFile->m_byAEPBuff + 1, sizeof(byCheck2E))!= 0 
			&& memcmp(byCheck2F0, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2F0))!= 0 
			&& memcmp(byCheck2F2, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2F2))!= 0
			&& memcmp(byCheck2F4, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2F4))!= 0 
			&& memcmp(byCheck2F5, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2F5))!= 0  
			&& memcmp(byCheck2F6, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2F6))!= 0  
			&& memcmp(byCheck2F7, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2F7))!= 0  
			&& memcmp(byCheck2F8, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2F8))!= 0 
			&& memcmp(byCheck2F9, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2F9))!= 0 
			&& memcmp(byCheck2FA, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FA))!= 0 
			&& memcmp(byCheck2FB, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FB))!= 0 
			&& memcmp(byCheck2FC, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FC))!= 0 //ADDED
			&& memcmp(byCheck2FD, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FD))!= 0 //ADDED
			&& memcmp(byCheck2FE, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FE))!= 0 //Added for expiro.rc (Swapnil)
			&& memcmp(byCheck2FF, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FF))!= 0 //Added for expiro.rc (Swapnil)
			&& memcmp(byCheck2FG, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FG))!= 0 //Added for expiro.rc (Swapnil)
			&& memcmp(byCheck2FH, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FH))!= 0 //Added for expiro.rc (Swapnil)
			&& memcmp(byCheck2FI, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FI))!= 0 //Added for expiro.rc (Swapnil)
			&& memcmp(byCheck2FJ, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FJ))!= 0//Added for expiro.rc (Swapnil)
			&& memcmp(byCheck2FK, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FK))!= 0
			&& memcmp(byCheck2FL, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FL))!= 0
			&& memcmp(byCheck2FM, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FM))!= 0
			&& memcmp(byCheck2FN, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FN))!= 0
			&& memcmp(byCheck2FO, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FO))!= 0
			&& memcmp(byCheck2FT, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FT))!= 0//Added Sneha 20 Nov 2019
			&& memcmp(byCheck2FU, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FU))!= 0
			&& memcmp(byCheck2FW, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FW))!= 0
			&& memcmp(byCheck2FX, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FX))!= 0//Added Sneha 20 Nov 2019
			&& memcmp(byCheck2FY, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FY))!= 0
			&& memcmp(byCheck2FZ, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FZ))!= 0
			&& memcmp(byCheck100, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck100))!= 0
			&& memcmp(byCheck101, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck101))!= 0)
			//&& memcmp(byCheck2FV, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FV))!= 0)//Added Sagar 24 June 2020
			return VIRUS_NOT_FOUND;

		if(memcmp(byCheck2E, m_pMaxPEFile->m_byAEPBuff + 1, sizeof(byCheck2E))== 0)
		{
			m_AppendToLastSec = true;
		}
		else if((memcmp(byCheck2F0, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2F0))== 0 || memcmp(byCheck2F2, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2F2))== 0) && (memcmp(byCheck2F1, m_pMaxPEFile->m_byAEPBuff + 0x35, sizeof(byCheck2F1))== 0 || memcmp(byCheck2F3, m_pMaxPEFile->m_byAEPBuff + 0x32, sizeof(byCheck2F3))== 0))
		{
			m_AppendToLastSec = true;
		}
		else if((memcmp(byCheck2F4, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2F4)) == 0 || 
			memcmp(byCheck2F5, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2F5)) == 0 || 
			memcmp(byCheck2F6, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2F6)) == 0 || 
			memcmp(byCheck2F7, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2F7)) == 0 || 
			memcmp(byCheck2F8, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2F8)) == 0 || 
			memcmp(byCheck2F9, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2F9)) == 0 || 
			memcmp(byCheck2FA, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FA)) == 0 || 
			memcmp(byCheck2FB, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FB)) == 0 || 
			memcmp(byCheck2FC, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FC)) == 0 ||//added
			memcmp(byCheck2FD, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FD)) == 0 ||//ADDED
			memcmp(byCheck2FE, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FE)) == 0 ||//Added for expiro.rc (Swapnil)
			memcmp(byCheck2FF, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FF)) == 0 ||//Added for expiro.rc (Swapnil)
			memcmp(byCheck2FG, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FG)) == 0 ||//Added for expiro.rc (Swapnil)
			memcmp(byCheck2FH, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FH)) == 0 ||//Added for expiro.rc (Swapnil)
			memcmp(byCheck2FI, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FI)) == 0 ||//Added for expiro.rc (Swapnil)
			memcmp(byCheck2FJ, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FJ)) == 0 ||//Added for expiro.rc (Swapnil)
			memcmp(byCheck2FK, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FK)) == 0 ||
			memcmp(byCheck2FL, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FL)) == 0 ||
			memcmp(byCheck2FM, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FM)) == 0 ||
			memcmp(byCheck2FN, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FN)) == 0 ||
			memcmp(byCheck2FO, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FO)) == 0 ||
			memcmp(byCheck2FT, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FT)) == 0 || //Added Sneha 20 Nov 2019
			memcmp(byCheck2FU, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FU)) == 0 ||
			memcmp(byCheck2FW, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FW)) == 0 ||
			memcmp(byCheck2FX, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FX)) == 0 || //Added Sneha 20 Nov 2019
			memcmp(byCheck2FY, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FY)) == 0 ||
			memcmp(byCheck2FZ, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FZ)) == 0 ||
			memcmp(byCheck100, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck100)) == 0 ||
			memcmp(byCheck101, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck101)) == 0)) //Added Abhijeet : 21 Sep 2021 : Expiro.RD
			//memcmp(byCheck2FV, m_pMaxPEFile->m_byAEPBuff, sizeof(byCheck2FV))== 0))
		{
			m_AppendToLastSec = true;
		}

		if(m_AppendToLastSec == false)
		{
			// Chk 3: Decryption loop
			if(!GetBuffer(m_dwAEPMapped, EXPIRO64_BUFF_SIZE, EXPIRO64_BUFF_SIZE))
				return VIRUS_NOT_FOUND;
			BYTE byCheck3[]  = {0xB9, 0x06, 0x00, 0x00, 0x00, 0x89, 0xC0, 0xBA, 0xAB, 0xAA, 0xAA, 0xAA, 0xF7, 0xE2, 0xC1, 0xEA, 0x02},
				byCheck3D[] = {0x49, 0x83, 0xC2, 0x04, 0x48, 0x31, 0xD2, 0x49, 0xF7, 0xF2, 0x44, 0x8B, 0x55, 0xC8, 0x49, 0x89, 0xC1},
				byCheck3E[] = {0x48, 0x99, 0x49, 0xF7, 0xFA, 0x41, 0x89, 0xFA, 0x49, 0x89, 0xC1, 0x4D, 0x01, 0xD1},//{0x45, 0x89, 0xDA, 0x47, 0x8A, 0x14, 0x16, 0x44, 0x88, 0x55, 0xCF, 0x44, 0x0F, 0xB6, 0x55, 0xCF},

				byCheck3ED[] = {0x48, 0x99, 0x49, 0xF7, 0xFA, 0x49, 0x89, 0xC2, 0x49, 0xC1, 0xE2, 0x02},//{0x45, 0x89, 0xDA, 0x47, 0x8A, 0x14, 0x16, 0x44, 0x88, 0x55, 0xCF, 0x44, 0x0F, 0xB6, 0x55, 0xCF},
				byCheck3ED1[] = {0x48, 0x99, 0x49, 0xF7, 0xFA, 0x44, 0x8B,0x55,0x8C, 0x49, 0x89, 0xC1, 0x4D, 0x01, 0xD1},//{0x45, 0x89, 0xDA, 0x47, 0x8A, 0x14, 0x16, 0x44, 0x88, 0x55, 0xCF, 0x44, 0x0F, 0xB6, 0x55, 0xCF},
				byCheck3ED2[] = {0x48, 0x99, 0x49, 0xF7, 0xFD, 0x49, 0x29, 0xC2, 0x44, 0x8B, 0x4D, 0x90, 0x4D, 0x01, 0xCA},
				byCheck3ED3[] = {0x48, 0x99, 0x49, 0xF7, 0xFD, 0x41, 0x3B, 0xC2, 0x76, 0x1E, 0x41, 0x2B, 0xC2, 0x48, 0x8D},

				byCheck4A[] = {0x45, 0x31, 0xD3, 0x44, 0x88, 0x5D, 0xCF, 0x45, 0x89, 0xFB, 0x44, 0x8A, 0x55, 0xCF, 0x47, 0x88, 0x54, 0x1D, 0x00},
				byCheck4B[] = {0x45, 0x31, 0xD3, 0x44, 0x88, 0x5D, 0xCF, 0x44, 0x8B, 0x5D, 0xB0, 0x4C, 0x8B, 0x55, 0xC0, 0x44, 0x8A, 0x4D, 0xCF, 0x47, 0x88, 0x0C, 0x1A},
				byCheck4C[] = {0x45, 0x31, 0xD3, 0x44, 0x88, 0x9D, 0x7D, 0xFF, 0xFF, 0xFF, 0x44, 0x8B, 0x5D, 0xA0, 0x4D, 0x8D, 0x5B, 0x01, 0x44, 0x89, 0x5D, 0xA0},
				byCheck4C1[]= {0x45, 0x31, 0xD3, 0x44, 0x88, 0x9D, 0x7B, 0xFF, 0xFF, 0xFF, 0x44, 0x8B, 0x5D, 0x98, 0x4D, 0x8D, 0x5B, 0x01, 0x44, 0x89, 0x5D, 0x98},//g
				byCheck4D[] = {0x45, 0x31, 0xD1, 0x44, 0x88, 0x4D, 0xCF, 0x45, 0x89, 0xDA, 0x44, 0x8A, 0x4D, 0xCF, 0x47, 0x88, 0x0C, 0x16},

				byCheck4D1[] = {0x45, 0x31, 0xD1, 0x44, 0x88, 0x4D, 0xCF, 0x45, 0x89, 0xF2, 0x44, 0x8A, 0x4D, 0xCF, 0x47, 0x88, 0x4C, 0x15},
				byCheck4D2[] = {0x45, 0x31, 0xD1, 0x44, 0x88, 0x4D, 0x8F, 0x44, 0x8B, 0x55, 0xA8, 0x41, 0x83, 0xEA, 0x01, 0x44, 0x89, 0x55},                                                                               
				byCheck4D3[] = {0x45, 0x31, 0xD1, 0x44, 0x88, 0x4D, 0xCF, 0x44, 0x8B, 0x55, 0xB8, 0x4D, 0x8D, 0x52, 0x01, 0x44, 0x89, 0x55, 0xB8, 0x48, 0xC7, 0xC0, 0x04},

				byCheck4E[] = {0x45, 0x31, 0xD1, 0x44, 0x88, 0x4D, 0xCF, 0x45, 0x89, 0xDA, 0x44, 0x8A, 0x4D, 0xCF, 0x47, 0x88, 0x0C, 0x17},//0x45, 0x31, 0xCA, 0x44, 0x88, 0x55, 0xCF, 0x45, 0x89, 0xDA, 0x44, 0x8A, 0x4D, 0xCF, 0x47, 0x88, 0x0C, 0x16};
				byCheck4F[] = {0x45,0x31,0xD1,0x44,0x88,0x4D,0xB3,0x44,0x8B,0x55,0xAC,0x41,0x83,0xEA,0x01,0x44,0x89,0x55,0xAC,0x48,0xC7,0xC0,0x0B},
				byCheck4G[] = {0x45, 0x31, 0xD3, 0x44, 0x88, 0x5D, 0xCF, 0x45, 0x89, 0xFB, 0x44, 0x8A, 0x55, 0xCF, 0x47, 0x88, 0x14, 0x1E};


			bool b3rdChk = false;
			for(int i = 0; i < EXPIRO64_BUFF_SIZE - sizeof(byCheck3); i++)
			{
				if(b3rdChk == false)
				{
					if(memcmp(byCheck3, &m_pbyBuff[i], sizeof(byCheck3))==0)
						b3rdChk = true;

					if(memcmp(byCheck3D, &m_pbyBuff[i], sizeof(byCheck3D))==0)
						b3rdChk = true;

					if(memcmp(byCheck3E, &m_pbyBuff[i], sizeof(byCheck3E))==0)
						b3rdChk = true;

					if(memcmp(byCheck3ED1, &m_pbyBuff[i], sizeof(byCheck3ED1))==0)
						b3rdChk = true;//addes for expiro.g

					if(memcmp(byCheck3ED1, &m_pbyBuff[i], sizeof(byCheck3ED1))==0)
						b3rdChk = true;//addes for expiro.g

					if(memcmp(byCheck3ED2, &m_pbyBuff[i], sizeof(byCheck3ED2))==0)
						b3rdChk = true;//addes for expiro.g

					if(memcmp(byCheck3ED3, &m_pbyBuff[i], sizeof(byCheck3ED3))==0)
						b3rdChk = true;//addes for expiro.g

				}
				else
				{
					if(memcmp(byCheck4A, &m_pbyBuff[i], sizeof(byCheck4A))==0)
					{
						m_dwPatchSize = 0x4DD;
						break;
					}
					if(memcmp(byCheck4B, &m_pbyBuff[i], sizeof(byCheck4B))==0)
					{
						m_dwPatchSize = 0x47D;
						break;
					}
					if(memcmp(byCheck4C, &m_pbyBuff[i], sizeof(byCheck4C))==0)
					{
						m_dwPatchSize = 0x4F5;
						break;
					}
					if(memcmp(byCheck4C1, &m_pbyBuff[i], sizeof(byCheck4C1))==0)
					{
						m_dwPatchSize = 0x4F5;
						break;
					}
					if(memcmp(byCheck4D, &m_pbyBuff[i], sizeof(byCheck4D))==0)
					{
						m_dwPatchSize = 0x525;
						break;
					}
					if(memcmp(byCheck4D1, &m_pbyBuff[i], sizeof(byCheck4D1))==0)
					{
						m_dwPatchSize = 0x525;//matching expiro.g
						break;
					}
					if(memcmp(byCheck4D2, &m_pbyBuff[i], sizeof(byCheck4D2))==0)
					{
						m_dwPatchSize = 0x525;//matching expiro.g
						break;
					}
					if(memcmp(byCheck4D3, &m_pbyBuff[i], sizeof(byCheck4D3))==0)
					{
						m_dwPatchSize = 0x525;//matching expiro.g
						break;
					}
					if(memcmp(byCheck4E, &m_pbyBuff[i], sizeof(byCheck4E))==0)
					{
						m_dwPatchSize = 0x548;
						break;
					}
					if(memcmp(byCheck4F, &m_pbyBuff[i], sizeof(byCheck4F))==0)
					{
						m_dwPatchSize = 0x548;
						break;
					}
					if(memcmp(byCheck4G, &m_pbyBuff[i], sizeof(byCheck4G))==0)
					{
						m_dwPatchSize = 0x548;
						break;
					}

				}
			}
			if(m_dwPatchSize != 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("virus.win64.expiro.gen"));
				if((m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_dwPatchSize) > m_pMaxPEFile->m_dwFileSize)
					return VIRUS_FILE_DELETE;
				else
					return VIRUS_FILE_REPAIR;
			}
		}
		else	// Virus code upended to last section.
		{
			//	Calculating patch size
			if(!GetBuffer(m_dwAEPMapped + 0x100, EXPIRO64_BUFF_SIZE, EXPIRO64_BUFF_SIZE))
				return VIRUS_NOT_FOUND;
			m_dwPatchSize = 0;
			for(int i = EXPIRO64_BUFF_SIZE - 0x1; (i + 0x11) >= 0; i--)
			{
				if(m_pbyBuff[i - 0x11] == 0x48 && m_pbyBuff[i - 0x10] == 0xB8 && m_pbyBuff[i - 0x7] == 0x48 && m_pbyBuff[i - 0x6] == 0x05 && m_pbyBuff[i - 0x1] == 0x50 && m_pbyBuff[i] == 0xC3)
				{	
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0xFF && m_pbyBuff[i - 0x4] == 0xCA && m_pbyBuff[i - 0x3] == 0x4A && m_pbyBuff[i - 0x2] == 0xFF && m_pbyBuff[i - 0x1] == 0xCB && m_pbyBuff[i] == 0xC3)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0xC6 && m_pbyBuff[i - 0x4] == 0x67 && m_pbyBuff[i - 0x3] == 0x47 && m_pbyBuff[i - 0x2] == 0x8D && m_pbyBuff[i - 0x1] == 0x0A && m_pbyBuff[i] == 0xC3)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0xFF && m_pbyBuff[i - 0x4] == 0xC6 && m_pbyBuff[i - 0x3] == 0x4C && m_pbyBuff[i - 0x2] == 0xFF && m_pbyBuff[i - 0x1] == 0xCA && m_pbyBuff[i] == 0xC3)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0xFF && m_pbyBuff[i - 0x4] == 0xC4 && m_pbyBuff[i - 0x3] == 0x45 && m_pbyBuff[i - 0x2] == 0x29 && m_pbyBuff[i - 0x1] == 0xC0 && m_pbyBuff[i] == 0xC3)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0x4A && m_pbyBuff[i - 0x4] == 0x8B && m_pbyBuff[i - 0x3] == 0xDF && m_pbyBuff[i - 0x2] == 0x2B && m_pbyBuff[i - 0x1] == 0xFF && m_pbyBuff[i] == 0xC3)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0xFF && m_pbyBuff[i - 0x4] == 0xCA && m_pbyBuff[i - 0x3] == 0x4A && m_pbyBuff[i - 0x2] == 0xFF && m_pbyBuff[i - 0x1] == 0xC9 && m_pbyBuff[i] == 0xC3)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0xFF && m_pbyBuff[i - 0x4] == 0xC6 && m_pbyBuff[i - 0x3] == 0x4D && m_pbyBuff[i - 0x2] == 0x29 && m_pbyBuff[i - 0x1] == 0xF6 && m_pbyBuff[i] == 0xC3)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if((m_pbyBuff[i - 0x3] == 0x00 || m_pbyBuff[i - 0x3] == 0x01) && (m_pbyBuff[i - 0x2] == 0x50 || m_pbyBuff[i - 0x2] == 0x00) && (m_pbyBuff[i - 0x1] == 0x50 || m_pbyBuff[i - 0x1] == 0x90) && m_pbyBuff[i] == 0xC3)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0x8B && m_pbyBuff[i - 0x4] == 0xC3 && m_pbyBuff[i - 0x3] == 0x45 && m_pbyBuff[i - 0x2] == 0x2B && m_pbyBuff[i - 0x1] == 0xDB && m_pbyBuff[i] == 0xC3)//ADDED
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0xFF && m_pbyBuff[i - 0x4] == 0xCF && m_pbyBuff[i - 0x3] == 0x4A && m_pbyBuff[i - 0x2] == 0x29 && m_pbyBuff[i - 0x1] == 0xC0 && m_pbyBuff[i] == 0xC3)//ADDED
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0x67 && m_pbyBuff[i - 0x4] == 0x47 && m_pbyBuff[i - 0x3] == 0x8D && m_pbyBuff[i - 0x2] == 0x5D && m_pbyBuff[i - 0x1] == 0x00 && m_pbyBuff[i] == 0xC3)//Added for expiro.rc (Swapnil)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0x89 && m_pbyBuff[i - 0x4] == 0xFA && m_pbyBuff[i - 0x3] == 0x4A && m_pbyBuff[i - 0x2] == 0xFF && m_pbyBuff[i - 0x1] == 0xCF && m_pbyBuff[i] == 0xC3)//Added for expiro.rc (Swapnil)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0x8B && m_pbyBuff[i - 0x4] == 0xD1 && m_pbyBuff[i - 0x3] == 0x4D && m_pbyBuff[i - 0x2] == 0x8D && m_pbyBuff[i - 0x1] == 0x37 && m_pbyBuff[i] == 0xC3)//Added for expiro.rc (Swapnil)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0xFF && m_pbyBuff[i - 0x4] == 0xCE && m_pbyBuff[i - 0x3] == 0x48 && m_pbyBuff[i - 0x2] == 0xFF && m_pbyBuff[i - 0x1] == 0xC9 && m_pbyBuff[i] == 0xC3)//Added for expiro.rc (Swapnil)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0x8B && m_pbyBuff[i - 0x4] == 0xD7 && m_pbyBuff[i - 0x3] == 0x45 && m_pbyBuff[i - 0x2] == 0x29 && m_pbyBuff[i - 0x1] == 0xFF && m_pbyBuff[i] == 0xC3)//Added for expiro.rc (Swapnil)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0x01 && m_pbyBuff[i - 0x4] == 0x30 && m_pbyBuff[i - 0x3] == 0x00 && m_pbyBuff[i - 0x2] == 0x00 && m_pbyBuff[i - 0x1] == 0x50 && m_pbyBuff[i] == 0xC3)//Added for expiro.rc (Swapnil)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] ==0x8B  && m_pbyBuff[i - 0x4] == 0xCA && m_pbyBuff[i - 0x3] == 0x48 && m_pbyBuff[i - 0x2] == 0x29 && m_pbyBuff[i - 0x1] == 0xD2 && m_pbyBuff[i] == 0xC3)//ADDED 25 OCT
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] ==0x00  && m_pbyBuff[i - 0x4] == 0x50 && m_pbyBuff[i - 0x3] == 0x46 && m_pbyBuff[i - 0x2] == 0x2B && m_pbyBuff[i - 0x1] == 0xD2 && m_pbyBuff[i] == 0xC3)//ADDED 25 OCT
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[(i-0x3EC) - 0x5] ==0xC7  && m_pbyBuff[(i-0x3EC) - 0x4] == 0x57 && m_pbyBuff[(i-0x3EC) - 0x3] == 0x4B && m_pbyBuff[(i-0x3EC) - 0x2] == 0x8D && m_pbyBuff[(i-0x3EC) - 0x1] == 0x11 && m_pbyBuff[i-0x3EC] == 0xC3)//ADDED SNEHA
				{
					m_dwPatchSize = 0x100 + (i-0x3EC);
					break;
				}
				else if(m_pbyBuff[(i-0x34C) - 0x5] ==0xFF  && m_pbyBuff[(i-0x34C) - 0x4] == 0xC5 && m_pbyBuff[(i-0x34C) - 0x3] == 0x4B && m_pbyBuff[(i-0x34C) - 0x2] == 0xFF && m_pbyBuff[(i-0x34C) - 0x1] == 0xCA && m_pbyBuff[i-0x34C] == 0xC3)//ADDED SNEHA
				{
					m_dwPatchSize = 0x100 + (i-0x34C);
					break;
				}
				else if(m_pbyBuff[(i-0x471) - 0x5] ==0xED  && m_pbyBuff[(i-0x471) - 0x4] == 0x14 && m_pbyBuff[(i-0x471) - 0x3] == 0x00 && m_pbyBuff[(i-0x471) - 0x2] == 0x00 && m_pbyBuff[(i-0x471) - 0x1] == 0x50 && m_pbyBuff[i-0x471] == 0xC3)//ADDED SNEHA
				{
					m_dwPatchSize = 0x100 + (i-0x471);
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0x90  && m_pbyBuff[i - 0x4] == 0x07 && m_pbyBuff[i - 0x3] == 0x00 && m_pbyBuff[i - 0x2] == 0x00 && m_pbyBuff[i-0x1] == 0x50 && m_pbyBuff[i] == 0xC3)//ADDED Sneha 20 Nov 2019 (Sneha)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0xFF  && m_pbyBuff[i - 0x4] == 0xCE && m_pbyBuff[i - 0x3] == 0x4D && m_pbyBuff[i - 0x2] == 0x8D && m_pbyBuff[i - 0x1] == 0x22 && m_pbyBuff[i] == 0xC3)//ADDED Sneha 20 Nov 2019 (Sneha)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0xEB  && m_pbyBuff[i - 0x4] == 0xE7 && m_pbyBuff[i - 0x3] == 0xC7 && m_pbyBuff[i - 0x2] == 0x44 && m_pbyBuff[i - 0x1] == 0x24 && m_pbyBuff[i] == 0x20)//ADDED Sneha 20 Nov 2019 (Sneha)
				{
					m_dwPatchSize = 0x100 + (i-0x45A);
					break;
				}
				else if(m_pbyBuff[(i-0x459) - 0x5] ==0xC7  && m_pbyBuff[(i-0x459) - 0x4] == 0x4F && m_pbyBuff[(i-0x459) - 0x3] == 0xFF && m_pbyBuff[(i-0x459) - 0x2] == 0xC9 && m_pbyBuff[(i-0x459) - 0x1] == 0xC3)
				{
					m_dwPatchSize = 0x100 + (i-0x459);
					break;
				}
				else if(m_pbyBuff[(i-0x459) - 0x5] ==0x00  && m_pbyBuff[(i-0x459) - 0x4] == 0x46 && m_pbyBuff[(i-0x459) - 0x3] == 0x0F && m_pbyBuff[(i-0x459) - 0x2] == 0xAF && m_pbyBuff[(i-0x459) - 0x1] == 0xF0 && m_pbyBuff[i-0x459] == 0x4F)
				{
					m_dwPatchSize = 0x100 + (i-0x459);
					break;
				}
				else if(m_pbyBuff[(i-0x3EF) - 0x5] ==0xE9  && m_pbyBuff[(i-0x3EF) - 0x4] == 0x6C && m_pbyBuff[(i-0x3EF) - 0x3] == 0xFF && m_pbyBuff[(i-0x3EF) - 0x2] == 0xFF && m_pbyBuff[(i-0x3EF) - 0x1] == 0xFF)
				{
					m_dwPatchSize = 0x100 + (i - 0x3EF);
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0xE9 && m_pbyBuff[i - 0x4] == 0x69 && m_pbyBuff[i - 0x3] == 0xFF && m_pbyBuff[i - 0x2] == 0xFF && m_pbyBuff[i - 0x1] == 0xFF)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}
				else if(m_pbyBuff[i - 0x5] == 0xE9 && m_pbyBuff[i - 0x4] == 0x98 && m_pbyBuff[i - 0x3] == 0xFF && m_pbyBuff[i - 0x2] == 0xFF && m_pbyBuff[i - 0x1] == 0xFF)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}

				else if(m_pbyBuff[i - 0x5] ==0x4F  && m_pbyBuff[i - 0x4] == 0xE9 && m_pbyBuff[i - 0x3] == 0x82 && m_pbyBuff[i - 0x2] == 0xFF && m_pbyBuff[i - 0x1] == 0xFF && m_pbyBuff[i] == 0xFF)
				{
					m_dwPatchSize = 0x100 + i;
					break;
				}

			}
			// Getting last section Original Size SRD
			if(m_dwPatchSize != 0)
			{
				if(memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".vmp0", 5) == 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("virus.win64.expiro.gen"));
					return VIRUS_FILE_REPAIR;

				}
				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff =NULL;
				}
				m_pbyBuff = new BYTE[0x1000];
				if(!GetBuffer(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData - 0x1000, 0x1000, 0x1000))
					return VIRUS_NOT_FOUND;

				for(int i = 0xFFF; i >= 0; i--)
				{
					if(m_pbyBuff[i] != 0)
					{
						if(m_pbyBuff[i - 0x1] == 0)
							m_dwSizeOfLastSec = *(DWORD *)&m_pbyBuff[i - 0x4];
						break;
					}
				}
				if(m_dwSizeOfLastSec > m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData)
					return VIRUS_NOT_FOUND;

				if(m_dwSizeOfLastSec != 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("virus.win64.expiro.gen"));
					return VIRUS_FILE_REPAIR;
				}
			}
		}
	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Expiro (x64) Family
--------------------------------------------------------------------------------------*/
int CPolyExpiro64::CleanVirus()
{
	if(m_AppendToLastSec == false)
	{
		if(m_pMaxPEFile->CopyData(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData, m_dwAEPMapped, m_dwPatchSize))
		{	
			if(m_pMaxPEFile->TruncateFile(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
   else
   {	
		   if(m_pMaxPEFile->CopyData(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_dwSizeOfLastSec, m_dwAEPMapped, m_dwPatchSize + 0x1))
		   {	
			   if(m_pMaxPEFile->TruncateFile(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_dwSizeOfLastSec))
			   {
				   return REPAIR_SUCCESS;
			   }

		   }
	   
	}
	return REPAIR_FAILED;
}