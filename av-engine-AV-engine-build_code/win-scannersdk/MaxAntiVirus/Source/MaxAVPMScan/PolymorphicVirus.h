/*======================================================================================
FILE				: PolymorphicVirus.h
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
NOTES				: MaxAVPClean.cpp : Defines the exported functions for the DLL application.
					  This Class implements the polymorphism for the detection of different fammily of malwares.
					  This class manges the mechanism for local db (reduces the repeatetive scaning for sma file with same code)
						
VERSION HISTORY		: 02 Oct 2012 : Categorized viruses in 0x0D.
					  30 Sep 2013 : Implemented REV_ID_TYPE structure (variable.h) for local DB
					  16 Oct 2017 : Revised new structure of REV_ID_TYPE
					  24 Jun 2016 : 1.0.2.68 : GRE_REV_ID : 2 : Added New Viruses in Semipoly Trojan By Santosh
					  05 Oct 2016 : 1.0.2.69 : GRE_REV_ID : 3 : Added New Viruses in Semipoly Trojan By Santosh
						 GR4_REV_ID : 2 : Added New Viruses in Semipoly Virus By Santosh
					  01 Dec 2016 : 1.0.2.70 : GRE_REV_ID : 4 : Added New Viruses in Semipoly Trojan By  + Alisha
						 GRB_REV_ID : 2 : Added New Viruses in Sality By Santosh + Alisha
						 GR4_REV_ID : 3 : Added New Viruses in Semipoly Virus By Santosh + Alisha
					  04 Jan 2017 : 1.0.2.72 : GRE_REV_ID : 5 : Added New Viruses in Semipoly Trojan By Santosh
						 GRB_REV_ID : 3 : Added New Viruses in Sality By Santosh + Alisha
						 GR7_REV_ID : 2 : Added New Viruses in Trojan By Alisha
						 GR5_REV_ID : 2 : Added New Viruses in Non Repairable Trojan By Alisha
					  09 Feb 2017 : 1.0.2.73 : GRE_REV_ID : 6 : Added New Viruses in Semipoly Trojan By Santosh +Tushar
						 GR4_REV_ID : 4 : Added New Viruses in Semipoly Virus By Santosh 
					  29 Mar 2017 : 1.0.2.74 : GR9_REV_ID : 2 : Added New Heuristic By Tushar(Add new class CPolyHeuristics)
						 GR7_REV_ID : 3 : Trojan
						 GRE_REV_ID : 7 : Semipoly Trojan
						 GR4_REV_ID : 4 : Semipoly Virus
						 GR5_REV_ID : 3 : Non Repairable Trojan
					  29 Mar 2017 : 1.0.2.76 : GR4_REV_ID : 6 : Changes in Virus.Pioneer.CZ
					  15 May 2017 : 1.0.2.77 : GR4_REV_ID : 7 : Changes for RansomCry by Alisha
					  26 May 2017 : 1.0.2.78 : GR4_REV_ID : 8 : Semipoly Virus
						 GR5_REV_ID : 4 : Non-Repairable Virus
						 GRE_REV_ID : 8 : Semipoly Trojan
					  27 Jul 2017 : 1.0.2.79 : GRE_REV_ID : 9 : Semipoly Trojan
						 GR4_REV_ID : 9 : Semipoly Virus, Trojan_Ransom
						 GR5_REV_ID : 5 : Non-Repairable Virus
						 GR8_REV_ID : 2 : Expiro
						 GR2_REV_ID : 2 : Rainsong
					 23 Jan 2018 : 1.0.2.84 : GR1_REV_ID : 2 : 
						 GR4_REV_ID : A : 
						 GR5_REV_ID : 6 : 
						 GR7_REV_ID : 4 : 
						 GR8_REV_ID : 3 : 
						 GRE_REV_ID : A : 
   				     08 Feb 2018 : 1.0.2.85 : GR1_REV_ID : 3 : 
						 GR4_REV_ID : B : 
						 GRE_REV_ID : B : 
					 28 Feb 2018 : 1.0.2.86 : GRE_REV_ID : C : 
					 04 Apr 2018 : 1.0.2.87 : GRE_REV_ID : D : Semipoly Trojan
						 GR4_REV_ID : C : Semipoly Virus
						 GR1_REV_ID : 4 : Poly Base
					 26 Apr 2018 : 1.0.2.88 : GR9_REV_ID : 3 : Nimnul Virus
						 GRE_REV_ID : E : Semipoly Trojan + Crab Ransomware
					 13 Jun 2018 : 1.0.2.90 : GR1_REV_ID : 5 : 
						 GR4_REV_ID : D : 
						 GR5_REV_ID : 7 : 
						 GRE_REV_ID : F : 	
=====================================================================================*/
#pragma once
#include "pch.h"
#include "Variables.h"
#include "PolyBase.h"
#include "MaxPEFile.h"

class CPolymorphicVirus
{
	LPCTSTR		m_pFileName;

	CPolyBase	*m_pPolyBase;
	CMaxPEFile	*m_pMaxPEFile;

	DWORD	CheckForVirus(bool bClean);	

public:
	static HANDLE	m_hEvent;

	CPolymorphicVirus(CMaxPEFile *pMaxPEFile);
	~CPolymorphicVirus();

	DWORD	CleanPolyMorphicEx(LPTSTR pVirusName, bool bClean);
	DWORD	CheckWhiteDigiCert();
	DWORD	CheckIsTrustedDigiCert(LPCTSTR m_szFile2Check);
	DWORD	VerifySignature(LPCWSTR pwszSourceFile);
};