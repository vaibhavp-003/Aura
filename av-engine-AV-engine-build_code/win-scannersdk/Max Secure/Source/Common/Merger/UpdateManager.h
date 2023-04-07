/*=============================================================================
   FILE		           :  UpdateManager.h
   ABSTRACT		       : Class for Defining the class behaviors for the application.
   DOCUMENTS	       : Refer The Live Update Design.doc, Live Update Requirement Document.doc
   AUTHOR		       :
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C) Aura
						 Created as an unpublished copyright work.  All rights reserved.
						 This document and the information it contains is confidential and
						 proprietary to Aura.  Hence, it may not be 
						 used, copied, reproduced, transmitted, or stored in any form or by any 
						 means, electronic, recording, photocopying, mechanical or otherwise, 
						 without the prior written permission of Aura.	
   CREATION DATE      : 2/3/2005
   NOTES		      : header file
   VERSION HISTORY    : 
=============================================================================*/
#pragma once
#include "MaxConstant.h"
#include "FWConstants.h"
#include "S2U.h"
#include "U2OU2O.h"
#include "FSDB.h"
#include "UUSSU.h"
#include "ThreatInfo.h"
#include "RegFix.h"
#include "S2S.h"
#include "BalBSTOpt.h"
#include "BufferToStructure.h"
#include "DirectoryManager.h"
#include "BlackDBManager.h"
#include "MaxNewPESig.h"

class CUpdateManager
{	
public:
	CUpdateManager(void);
	~CUpdateManager(void);

	CString GetDeltaVersion(const CString &csFileName);

	bool LoadDBType(const CString &csDataFolder, long lType, CString * pcsFileName = 0, bool bLoadFirewallDB = false);
	bool SaveDBType(const CString &csDataFolder, long lType, bool bSaveFirewallDB = false);
	bool MergeDBType(long lType, bool bMergeFirewallDB = false);
	bool IsVirusDBUpdated(){return m_bVirusDBUpdated;}
	bool ResetAllMembers();

	bool ExtractDeltaFile(const CString &csDeltaFileName);
	bool ExtractDeltaFileEx(const CString &csDeltaFileName);
private:
	CDirectoryManager	m_oDirectoryManager;
	CString				m_csDeltaFileName;
	CString				m_csMergeTempDataFolder;
	bool				m_bVirusDBUpdated;

	CS2U				m_objCookieDB;
	CU2OU2O				m_objFileDB;
	CU2OU2O				m_objFolderDB;
	CU2OU2O				m_objRegKeyDB;
	CUUSSU				m_objRegValDB;
	//CFSDB				m_objPESigB;
	CFSDB				m_objPESigFFS;
	CBlackDBManager		m_objBlackDBManager;
	CFSDB				m_objPESigW;
	CFSDB				m_objPESigQ;
	CRegFix				m_objRegFix;
	CThreatInfo			m_objNameDBMap;
	CS2S				m_objVirusR;
	CS2S				m_objVirusSPE;
	CS2S				m_objVirusSDos;
	CS2S				m_objVirusSCom;
	CS2S				m_objVirusSWMA;
	CS2S				m_objVirusSSCRIPT;
	CS2S				m_objVirusSOLE;
	CS2S				m_objVirusSINF;
	CS2S				m_objVirusSPDF;
	CS2S				m_objVirusSSIS;
	CS2S				m_objVirusSDEX;
	CS2S				m_objVirusSRTF;
	CS2S				m_objVirusSCURSOR;
	CBufferToStructure m_objAntiBanner;
	CBufferToStructure m_objAntiPhishing;

	bool MergeThreatNameDB();
	bool MergeBalBSTDB(const CString &csDBName, CBalBST& objMainDB, CBalBST& objDeltaDB);
	bool MergeBalBSTOptDB(const CString &csDBName, CFSDB& objMainDB, CFSDB& objDeltaDB);
	bool MergeBalBSTOptDB(const CString &csDBName, CBlackDBManager& objMainDB, CMaxNewPESig& objDeltaDB);
	bool MergeBalBSTOptFWDB(const CString &csDBName, CBalBSTOpt& objMainDB, CBalBSTOpt& objDeltaDB);
	bool MergeRegFixDB();
	void AddFileNameToFailedList(CString * pcsList, CString csFileName);
};
