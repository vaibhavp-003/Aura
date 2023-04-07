/*======================================================================================
FILE				: PolyTrojans64.cpp
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
NOTES				: This is detection module for malware x64 bit Trojans Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyTrojans64.h"
#include "SemiPolyDBScn.h"
#include "MaxBMAlgo.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyTrojans64
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyTrojans64::CPolyTrojans64(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyTrojans64
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyTrojans64::~CPolyTrojans64(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of x64 bit Trojans
					  Trojan-Downloader.Adload.a
					  Trojan.adware.mplug	
--------------------------------------------------------------------------------------*/
int CPolyTrojans64::DetectVirus(void)
{
	int	iRetStatus = VIRUS_NOT_FOUND;


//----------------------------------------------------- For Trojan : Trojan-Downloader.Adload.a ------------------------------------------------------------------------------------

	if( m_wNoOfSections == 0x6 && m_dwAEPUnmapped==0xC064 && m_wAEPSec == 4 && m_pMaxPEFile->m_stPEHeader.Subsystem == 0x1
		&& m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0xC00 )
	{

		if(false == m_pMaxPEFile->m_b64bit)
		return iRetStatus;

		if(m_pbyBuff)
		{
			delete[] m_pbyBuff;
			m_pbyBuff = NULL;
		}
	
		int ADLOADA_BUFF_SIZE = 0x1060;
		DWORD dwReadOff = m_pSectionHeader[5].PointerToRawData + 0x260;
	
		m_pbyBuff = new BYTE[ADLOADA_BUFF_SIZE];

		if(!m_pbyBuff)
		{
			return iRetStatus;
		}

		
		if(!GetBuffer(dwReadOff, ADLOADA_BUFF_SIZE, ADLOADA_BUFF_SIZE ))
		{
			return iRetStatus;
		}

		CSemiPolyDBScn	polydbObj;
		TCHAR			szVirusName[MAX_PATH] = {0};
		LPCTSTR			szAdloadA = (_T("6E0065007400680066006400720076002E007300790073*46656E69782D616D70204C544431*46656E69782D616D70204C544430")); //n.e.t.h.f.d.r.v...s.y.s  *  Fenix-amp LTD1  *  Fenix-amp LTD0 
		
		polydbObj.LoadSigDBEx(szAdloadA, _T("Trojan-Downloader.Adload.a"), FALSE);
		if(polydbObj.ScanBuffer(&m_pbyBuff[0x0], ADLOADA_BUFF_SIZE, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName) > 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_DELETE;
			}
		}
	}

	//================================================================
	//Analyst	: Gajanan
	//Name 	: Trojan.adware.mplug
	//================================================================
	iRetStatus = VIRUS_NOT_FOUND;

	if( m_wNoOfSections == 0x7 && m_wAEPSec == 0 )
	{
		if(false == m_pMaxPEFile->m_b64bit)
		return iRetStatus;

		if(m_pbyBuff)
		{
			delete[] m_pbyBuff;
			m_pbyBuff = NULL;
		}
	
		int BUFF_SIZE = 0x550;
		DWORD dwReadOff = m_pSectionHeader[1].PointerToRawData + 0x11000;
	
		m_pbyBuff = new BYTE[BUFF_SIZE];

		if(!m_pbyBuff)
		{
			return iRetStatus;
		}

		
		if(!GetBuffer(dwReadOff, BUFF_SIZE, BUFF_SIZE ))
		{
			return iRetStatus;
		}

		CSemiPolyDBScn	polydbObj;
		TCHAR			szVirusName[MAX_PATH] = {0};
		TCHAR			AdwareMplug_Sig[] = {_T("633A5C446576656C6F706D656E745C7265636F6D70696C655C657874656E73696F6E2D73657475705F323031335C4558545F53455455505F322E375F5243325C*62696E5C7836345C52656C656173652E4D696E696D616C5C4945506C7567696E2E706462")};
											//[c:\Development\recompile\extension-setup_2013\EXT_SETUP_2.7_RC2\]*[bin\x64\Release.Minimal\IEPlugin.pdb]
		
		polydbObj.LoadSigDBEx(AdwareMplug_Sig, _T("Trojan.adware.mplug"), FALSE);
		if(polydbObj.ScanBuffer(&m_pbyBuff[0x0], BUFF_SIZE, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName) > 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_DELETE;
			}
		}

	}
	else     // For Certificate Table.
	{
		if(false == m_pMaxPEFile->m_b64bit)
		return VIRUS_NOT_FOUND;

		DWORD	dwReadBuffOffset = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x4].VirtualAddress;

		if(0x0 == dwReadBuffOffset)
		{
			return VIRUS_NOT_FOUND;
		}

		DWORD BUFF_SIZE  = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x4].Size;

		if(0x0 == BUFF_SIZE) 
		{
			return VIRUS_NOT_FOUND;
		}
		if(BUFF_SIZE > 0x3C00)	// size should be less than 15kb
		{
			BUFF_SIZE = 0x3C00;	// 1st 15kb from start of Certificate
		}

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff =NULL;
		}

		m_pbyBuff = new BYTE[BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return VIRUS_NOT_FOUND;
		}
	
		if(!GetBuffer(dwReadBuffOffset, BUFF_SIZE, (BUFF_SIZE/3)))
			return VIRUS_NOT_FOUND;

		CSemiPolyDBScn		objdbscan;
		TCHAR				szVirusName[MAX_PATH] = {0};
		
		//------------------------------------Without Primary Checks------------------------------------

		LPCTSTR  szKranetG	= (_T("0CD194221ED016F035BD7BACA4027DC3*53616E20446965676F3126302406035504090C1D313036323020547265656E61205374726565742053756974652032333031*4D65676162726F7773653113301106035504030C0A4D65676162726F77736530*6365727473406D65676162726F7773652E62697A")); // YOGESH
		LPCTSTR  szGoobzo	= (_T("49737261656C*476F6F627A6F204C5444*476F6F627A6F204C5444")); // Goobzo

		objdbscan.LoadSigDBEx(szKranetG,		_T("not-a-virus:AdWare.Kranet.g"), TRUE);//Yogesh
		objdbscan.LoadSigDBEx(szGoobzo,			_T("Trojan.Goobzo"), FALSE);//Aniket

		if(objdbscan.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName) > 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff =NULL;
				}
				return VIRUS_FILE_DELETE;
			}
		}
		
		return VIRUS_NOT_FOUND;

	}

	return iRetStatus;	
	
}
