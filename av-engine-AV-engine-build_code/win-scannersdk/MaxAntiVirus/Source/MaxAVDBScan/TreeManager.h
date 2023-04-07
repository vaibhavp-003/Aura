/*======================================================================================
FILE				: TreeManager.h
ABSTRACT			: Definition of module : Aho-corasick Tree structure
DOCUMENTS			: 
AUTHOR				: Tushar Kadam
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 22-Apr-2010
NOTES				: 
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar
=====================================================================================*/
#pragma once
//#pragma pack(1)
#include	"MaxPEFile.h"	

#ifndef RETURN_VALUES
	#include	"RetValues.h"	
#endif
#ifndef CNODE
	#include "Node.h"
#endif
#ifndef CVECTOR
	#include "Vector.h"
#endif
#ifndef CVIRUSNAMELIST
	#include "VirNmList.h"
#endif
#ifndef SIGMATCHLINK
	#include "SigMatchLink.h"
#endif

#ifndef CVECTLINKSTACK
	#include "VectLinkStack.h"
#endif
//#include "vector.h"

#ifndef CSECSIGDB
	#include "SecSigDB.h"
#endif

#include "TreeMemManager.h"

#define MAX_SIG_PARTS 1000 //100
#define BUFFER_GRANUALITY	(2 * 1024 * 1024)

typedef struct _MAX_YARA_PE_RULE_LIST
{
	DWORD	dwSigID;
	BOOL	bOnlyRule;
	TCHAR	szRules[1024];
}MAX_YARA_PE_RULE_LIST,*LPMAX_YARA_PE_RULE_LIST;

class CTreeManager
{
	//Used for Virus Name Management
	HANDLE	m_hNameDB = INVALID_HANDLE_VALUE;
	HANDLE	m_hNameDBMap = nullptr;
	LPVOID	m_pNameDBView = nullptr;
	int		OpeNameDBEx(void);
	
	TCHAR	m_szNameDBFile[MAX_PATH];
	BOOL	m_bSecDBCreated = FALSE;

	// Used for Laoding and Managing Tree
	unsigned int	m_iFinalLinkCount = 0;
	CSigMatchLink	**m_pSigMatchLink = nullptr;
	unsigned long	m_lTotalSigsAdded = 1;
	unsigned int	**m_pSigPartMgrLst = nullptr;

	int LoadSignatureDB(char *szSig2Add, unsigned long iSigID);
	int LoadnScanSecondarySigEx(unsigned int iFLinkID, 
		unsigned char * szBuffer, 
		unsigned int iBuffLen);
	int UnloadTreeEx(void);
	int IsValidSigEx(char *szVirusName, char *szSignature);
	int GetNoofPartsEx(char * szInput);
	//For Secondary Tree
	int AddSig2TreeEx(char * szSig, unsigned long lSigID, CVector * pRoot);
	//Original for Main Tree
	int AddSig2TreeEx(char * szSig, 
		char * szVir, 
		unsigned long lSigID, 
		CVector * pRoot);
	int ManageFinalNodesEx(unsigned int iSID, unsigned int iFID);

	//10 Aug 2011 : DOS Changes
	BOOL MergeFinalNodes(unsigned int iSouceID, unsigned int iDestID);

	// Used for Scanning and Virus Detection
	int ScanBuffEx(unsigned char * szBuff2Scan, 
		unsigned int iBuffSize, 
		CVector * pStart, 
		int & iMatchSigID, 
		CVector **pMatchVect);
	int Scan4SecSig(unsigned char * szBuffer,unsigned int iBuffLen);
	int Scan4SecSigYARA(unsigned char * szBuffer,unsigned int iBuffLen);
	
	int Scan4SecSigYARA(HANDLE pFileHandle,unsigned int iBuffLen);

	int LinkFailureNodes(void);
	LPVOID	Allocate_Memory(DWORD dwSize, bool bThrowException = false);
	void	Release_Memory(LPVOID& lpMemory);
	int		LoadNamenSecDB();

	CTreeMemManager	m_TreeMemMgr;

	LPVOID	Allocate_Heap_Memory(HANDLE &hSrcHep, DWORD dwSize);
	void	Release_Heap_Memory(HANDLE &hSrcHep, LPVOID& lpMemory);

	int LoadnScanSecondarySigExYAYA(unsigned int iFLinkIDs[],unsigned int iFLinkCnt, unsigned char * szBuffer, unsigned int iBuffLen);
	int LoadnScanSecondarySigExYAYA(unsigned int iFLinkIDs[],unsigned int iFLinkCnt, HANDLE pHandle, unsigned int iBuffLen);

public:

	CVector		m_TreeRoot;
	CVirNmList	m_NameList;
	DWORD		m_dwVectorCount = 1;
	DWORD		m_dwNodeCount = 0;
	DWORD		m_dwCharsAdded = 0;
	CSecSigDB	m_SecSigDB;
	TCHAR		m_szProdRegKeyPath[MAX_PATH];
	
	CTreeManager(void);
	~CTreeManager(void);

	int LoadSignatureDB(LPCTSTR szDBPath, LPCTSTR szDBFileName);
	int LoadSigDBEx(LPCTSTR pszSig2Add, LPCTSTR pszVirusName, BOOL bMoreSigs);
	int UnLoadSignatureDB(void);
	void SetDatabasePatchDownload(LPCTSTR szDBPath);

	int ScanBuffer4Virus(unsigned char * szBuffer, unsigned int iBuffLen, char *szVirusName);

	int ScanBuffer4YARA(unsigned char * szBuffer,unsigned int iBuffLen, char * szVirusName,TCHAR *pszPERule);
	int ScanBuffer4YARA(HANDLE pFileHandle,unsigned int iBuffLen, char * szVirusName,TCHAR *pszPERule);

	bool AddYARAPERules(TCHAR * pszSig, DWORD dwSigID);

	MAX_YARA_PE_RULE_LIST	**m_pYaraPEList = nullptr;
	unsigned long			m_dwYaraPEListCnt = 0;

	LPVOID					m_pVirtualBuffer = nullptr;
	bool					AllocateVirtualBuffer();
};
