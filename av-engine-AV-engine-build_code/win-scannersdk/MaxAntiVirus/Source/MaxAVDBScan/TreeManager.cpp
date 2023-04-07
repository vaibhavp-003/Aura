/*======================================================================================
   FILE				: TreeManager.cpp
   ABSTRACT			: Supportive class Scan Manager
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
   NOTES			: This module loads the Binary Trees (Aho-corasick). 
   VERSION HISTORY	: 10 Aug 2011 : DOS Changes
=====================================================================================*/
#include "TreeManager.h"
#include <stdio.h>
#include <tchar.h>
#include "S2S.h"

/*-------------------------------------------------------------------------------------
	Function		: CTreeManager
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CTreeManager::CTreeManager(void)
{

	m_TreeRoot.m_bIsFinal = 0;
	m_TreeRoot.m_cVector = 0;
	m_TreeRoot.m_iSigID = 0;
	m_TreeRoot.m_pFailureVect = nullptr;
	m_TreeRoot.m_pSuccessList = nullptr;
	
	memset(m_szNameDBFile,0,sizeof(m_szNameDBFile));

}

/*-------------------------------------------------------------------------------------
	Function		: CTreeManager
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for Tree Manager
--------------------------------------------------------------------------------------*/
CTreeManager::~CTreeManager(void)
{
	m_lTotalSigsAdded = 0;
	m_TreeRoot.m_bIsFinal = 0;
	m_TreeRoot.m_cVector = 0;
	m_TreeRoot.m_iSigID = 0;
	m_TreeRoot.m_pFailureVect = nullptr;
	m_TreeRoot.m_pSuccessList = nullptr;
	
	m_pNameDBView = nullptr;
	if (m_hNameDBMap != nullptr)
	{
		CloseHandle(m_hNameDBMap);
	}
	if (m_hNameDB != nullptr)
	{
		CloseHandle(m_hNameDB);
	}
	DeleteFile(m_szNameDBFile);
	DeleteFile(m_SecSigDB.m_szTempDBName);

	if (m_pVirtualBuffer)
	{
		VirtualFree(m_pVirtualBuffer,BUFFER_GRANUALITY,MEM_RELEASE);
		m_pVirtualBuffer = nullptr;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: Allocate_Heap_Memory
	In Parameters	: HANDLE &hSrcHep, DWORD dwSize
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Allocates memory from program heap
--------------------------------------------------------------------------------------*/
LPVOID CTreeManager::Allocate_Heap_Memory(HANDLE &hSrcHep, DWORD dwSize)
{
	return HeapAlloc(hSrcHep,HEAP_ZERO_MEMORY,dwSize);
}

/*-------------------------------------------------------------------------------------
	Function		: Release_Heap_Memory
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Release memory allocated by Allocate_Heap_Memory() 
--------------------------------------------------------------------------------------*/
void CTreeManager::Release_Heap_Memory(HANDLE &hSrcHep, LPVOID& lpMemory)
{
	if(lpMemory)
	{
		HeapFree(hSrcHep,HEAP_ZERO_MEMORY,lpMemory);
		lpMemory = nullptr;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: Allocate_Memory
	In Parameters	: DWORD dwSize, bool bThrowException
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Allocates memory using malloc
--------------------------------------------------------------------------------------*/
LPVOID CTreeManager::Allocate_Memory(DWORD dwSize, bool bThrowException)
{
	LPVOID lpMemory = malloc(dwSize);

	if(lpMemory)
	{
		memset(lpMemory, 0, dwSize);
	}
	else
	{
		if(bThrowException)
		{
			throw "Memory Alloc Failed";
		}
	}

	return lpMemory;
}

/*-------------------------------------------------------------------------------------
	Function		: Release_Memory
	In Parameters	: LPVOID& lpMemory
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Release memory using free
--------------------------------------------------------------------------------------*/
void CTreeManager::Release_Memory(LPVOID& lpMemory)
{
	if(lpMemory)
	{
		free(lpMemory);
		lpMemory = nullptr;
	}
}

/******************************************************************************
Function Name	:	LoadSignatureDB
Author			:	Tushar Kadam
Scope			:	Public
Input			:	char * -->Signature Db Name to be loaded
Output			:   if Success then  > 0 --> No. of signature loaded in memory
Functionality	:	If is a wrapper function for LoadSigDBEx
*******************************************************************************/
int CTreeManager::LoadSignatureDB(LPCTSTR szDBPath, LPCTSTR szDBFileName)
{
	TCHAR		szTempPath[MAX_PATH] = {0};
	DWORD		dwRet = MAX_PATH; 

	dwRet = GetTempPath(MAX_PATH,szTempPath);
	_stprintf_s(szTempPath, MAX_PATH, _T("%sMax"), szTempPath);

	CreateDirectory(szTempPath, nullptr);

	DWORD dwTickCount = GetTickCount();
	_stprintf_s(m_szNameDBFile,MAX_PATH,_T("%s\\%4X_%s_NM"), szTempPath, dwTickCount, szDBFileName);

	OpeNameDBEx();

	int		iSignature = 0;
	int		iAdded = 0;
	int		iFailed = 0;
	char	szVirusName[520] = {0};
	char	szSig2Add[MAX_SZ_LEN] = {0};

	CS2S	objVirusSigDBMap(false);
		
	TCHAR	szLoadDBPath[MAX_PATH];
	_stprintf_s(szLoadDBPath, MAX_PATH,_T("%s%s"), szDBPath, szDBFileName);
	
	if(!objVirusSigDBMap.Load(szLoadDBPath))
	{
		SetDatabasePatchDownload(szLoadDBPath); 
		return ERR_INVALID_FILE;
	}
	
	DWORD dwDBSize = objVirusSigDBMap.GetFileLength(nullptr);
	_stprintf_s(m_SecSigDB.m_szTempDBName,MAX_PATH,_T("%s\\%4X_%s_SEC"), szTempPath, dwTickCount, szDBFileName);
	m_SecSigDB.OpenSecDB(dwDBSize);
	
	if(objVirusSigDBMap.GetFirst() != nullptr)
	{
		LPVOID posSigEntry = objVirusSigDBMap.GetFirst();
		while(posSigEntry)
		{
			iSignature++;
			LPTSTR szSignature = nullptr;
			LPTSTR szVirName = nullptr;
			objVirusSigDBMap.GetKey(posSigEntry, szSignature);
			objVirusSigDBMap.GetData(posSigEntry, szVirName);
			
			sprintf_s(szVirusName, "%S", szVirName);

			TCHAR	*pTemp = nullptr;

			pTemp = _tcsrchr(szSignature,L']');
			if (pTemp != nullptr)
			{
				AddYARAPERules(szSignature,m_lTotalSigsAdded);
				pTemp++;
				szSignature = pTemp;
			}
			sprintf_s(szSig2Add, "%S", szSignature);

			if (strstr(szSig2Add,"*") != nullptr)
			{

				if(szSig2Add[strlen(szSig2Add)-1] == 0x20)
				{
					szSig2Add[strlen(szSig2Add)-1] = '\0';
				}			
				if(szSig2Add[strlen(szSig2Add)-1] == 0xA)
				{
					szSig2Add[strlen(szSig2Add)-1] = '\0';
				}
				if(szSig2Add[strlen(szSig2Add)-1] == 0xD) 
				{
					szSig2Add[strlen(szSig2Add)-1] = '\0';
				}

				if(IsValidSigEx(szVirusName,szSig2Add) > -1)
				{
					if(ERR_SUCCESS == AddSig2TreeEx(szSig2Add, szVirusName, m_lTotalSigsAdded, &m_TreeRoot))
					{
						iAdded++;
						m_lTotalSigsAdded++;
					}
					else
					{
						iFailed++;
					}
				}	
				else
				{
					iFailed++;
				}
			}
			posSigEntry = objVirusSigDBMap.GetNext(posSigEntry);
		}
	}

	objVirusSigDBMap.RemoveAll();

	if (m_lTotalSigsAdded > 1)
		LinkFailureNodes();
	
	if(m_lTotalSigsAdded < 1)
	{
		UnloadTreeEx();
		m_lTotalSigsAdded = 0;
	}
	return m_lTotalSigsAdded;
}

/******************************************************************************
Function Name	:	LoadSignatureDB
Author			:	Tushar Kadam
Scope			:	Public
Input			:	char * -->Signature to be Add
					unsigned long --> Siganture ID
Output			:   if Success then  > 0 --> No. of signature loaded in memory
Functionality	:	If is a overrided function for Secondary Tree Loadiing
*******************************************************************************/
int CTreeManager::LoadSignatureDB(char *szSig2Add, unsigned long iSigID)
{	
	return AddSig2TreeEx(szSig2Add,iSigID,&m_TreeRoot);
}

/******************************************************************************
Function Name	:	LoadSigDBEx
Author			:	Tushar Kadam
Scope			:	Private
Input			:	char * -->Signature Db Name to be loaded
Output			:   if Success then  > 0 --> No. of signature loaded in memory
*******************************************************************************/
/*int CTreeManager::LoadSigDBEx(LPCTSTR szDBPath, LPCTSTR szDBFileName)
{
}*/

/******************************************************************************
Function Name	:	UnloadTreeEx
Author			:	Tushar Kadam
Scope			:	Private
Work			:	Releases the memory used by the Tree
*******************************************************************************/
int CTreeManager::UnloadTreeEx(void)
{
	CVectLinkStack* pHead = nullptr;
	CVectLinkStack* pTail = nullptr;
	CVectLinkStack* pTmpHead = nullptr;
	CVectLinkStack* pDummyLink = nullptr;
	CVector			*pParentVect = nullptr;
	CNode			*pCurVectList = nullptr;
	int				iRet = ERR_SUCCESS;
	int				iCnt=0;

	m_SecSigDB.CloseSecDB();
	DeleteFile(m_SecSigDB.m_szTempDBName);

	if(m_pNameDBView != nullptr)
	{
		UnmapViewOfFile(m_pNameDBView);
		m_pNameDBView = nullptr;
	}

	if(m_hNameDBMap != nullptr)
	{
		CloseHandle(m_hNameDBMap);
		m_hNameDBMap = nullptr;
	}

	if(m_hNameDB != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hNameDB);
		m_hNameDB = INVALID_HANDLE_VALUE;
	}

	DeleteFile(m_szNameDBFile);

	if(m_TreeRoot.m_pSuccessList == nullptr)
		return ERR_SUCCESS;

	
	
	m_TreeMemMgr.ReleaseMemory();

	{//Tushar-->Assigning NULL's to Root Node
		m_TreeRoot.m_pFailureVect = nullptr;
		m_TreeRoot.m_pSuccessList = nullptr;
		m_TreeRoot.m_cVector = 0x00;
		m_TreeRoot.m_iSigID = 0x00;
		m_TreeRoot.m_bIsFinal = 0;

	}

	for (iCnt=m_iFinalLinkCount-1;iCnt >= 0;iCnt--)
	{
		if (m_pSigMatchLink[iCnt] != nullptr)
		{
			if (m_pSigMatchLink[iCnt]->m_FinalSigsCnt > 0)
			{
				for (unsigned int j=0;j<m_pSigMatchLink[iCnt]->m_FinalSigsCnt;j++)
				{
					
					Release_Memory((LPVOID&)m_pSigMatchLink[iCnt]->m_FinalSigs[j]);
				}
			}

			if(m_pSigMatchLink[iCnt]->m_FinalSigs)
			{
				Release_Memory((LPVOID&)m_pSigMatchLink[iCnt]->m_FinalSigs);
			}

			
			Release_Memory((LPVOID&)m_pSigMatchLink[iCnt]);
		}
	}

	if(m_pSigMatchLink)
	{
		Release_Memory((LPVOID&)m_pSigMatchLink);
	}

	if (m_pSigPartMgrLst != nullptr)
	{
		for (iCnt=(m_lTotalSigsAdded-2);iCnt>=0;iCnt--)
		{
			if (m_pSigPartMgrLst[iCnt] != nullptr)
			{
				
				Release_Memory((LPVOID&)m_pSigPartMgrLst[iCnt]);
			}
		}
		
		Release_Memory((LPVOID&)m_pSigPartMgrLst);
		m_pSigPartMgrLst = nullptr;
	}

	if (m_pYaraPEList)
	{
		for (iCnt=m_dwYaraPEListCnt-1;iCnt >= 0;iCnt--)
		{
			if (m_pYaraPEList[iCnt] != nullptr)
			{
				Release_Memory((LPVOID&)m_pYaraPEList[iCnt]);
			}
		}
		Release_Memory((LPVOID&)m_pYaraPEList);
		m_pYaraPEList = nullptr;
	}

	if (m_pVirtualBuffer)
	{
		VirtualFree(m_pVirtualBuffer,BUFFER_GRANUALITY,MEM_RELEASE);
		m_pVirtualBuffer = nullptr;
	}

	return iRet;
}

/******************************************************************************
Function Name	:	IsValidSigEx
Author			:	Tushar Kadam
Scope			:	Private
Input			:	char * -->Signature From DB for Validation
					char * -->OutPut Virus Name
					char * -->Output Signature to Add in Tree
Output			:   if Success then  >= 0 --> No. of part in Signature
*******************************************************************************/
int CTreeManager::IsValidSigEx(char *szVirusName, char *szSignature)
{	
	size_t iLength = strlen(szVirusName);
	if (iLength == 0)
	{
		return ERR_INVALID_INPUT;
	}
	
	if (iLength > MAX_VIRUS_NAME-1)
	{
		szVirusName[MAX_VIRUS_NAME-1] = '\0';
	}

	iLength = strlen(szSignature);
	if (iLength == 0)
	{
		return ERR_INVALID_INPUT;
	}

	int iParts = GetNoofPartsEx(szSignature);
	if (iParts <= 0)
	{
		return ERR_INVALID_INPUT;
	}

	iLength -= iParts;
	if ((iLength % 2) != 0)
	{
		return ERR_INVALID_INPUT;
	}
	iParts++;
	return iParts;
}

/******************************************************************************
Function Name	:	GetNoofPartsEx
Author			:	Tushar Kadam
Scope			:	Private
Input			:	char * -->Signature for Validation
Output			:   if Success then  >= 0 --> No. of '*' in Signature
*******************************************************************************/
int CTreeManager::GetNoofPartsEx(char * szInput)
{
	char		szData[MAX_SZ_LEN] = {0};
	char		*ptr= nullptr;
	int			iCount=0;
	
	strcpy_s(szData,MAX_SZ_LEN,szInput);
	if (strlen(szData) == 0)
	{
		return ERR_ZERO_LEN_INPUT;
	}
	
	ptr = strstr(szData,"*");
	while(ptr)
	{
		iCount++;
		ptr++;
		if (ptr == nullptr)
			break;
		ptr = strstr(ptr,"*");
	}

	return iCount;
}

/******************************************************************************
Function Name	:	AddSig2TreeEx
Author			:	Tushar Kadam
Scope			:	Private
Input			:	char * -->Signature 2 Add
					char * -->Virus Name
					unsigned long -->Current Signature Count Being Added
					CVector * -->Root of the Tree
Output			:   if Success then == 0
*******************************************************************************/
int CTreeManager::AddSig2TreeEx(char * szSig, char * szVir, unsigned long lSigID, CVector * pRoot)
{
	char			szSig2Add[MAX_SZ_LEN] = {0};
	char			szVirName[MAX_VIRUS_NAME] = {0};
	unsigned long	lCurSigID = 0;
	unsigned long	lNewSigID = 0;
	unsigned long	lDummy = 0;
	CVector			*pCurRoot = nullptr;
	CVector			*pCurVect = nullptr;
	size_t			iSigLen = 0;
	int				iPartsAdded=1;
	char			szChr2Add[3] = { 0 };
	char			*szDummy = nullptr;
	unsigned int	iChar=0;	 
	bool			bFound = false;
	CNode* pCurNode = nullptr;
	CNode* pTempNode = nullptr;
	
	DWORD			dwBytesWritten = 0;
	CVector			*pTempNewVect = nullptr;
	CNode			*pTempNewNode = nullptr;
	

	
	
	{//Intializing of Local Variables
		strcpy_s(szSig2Add,MAX_SZ_LEN,szSig);
		strcpy_s(szVirName,MAX_VIRUS_NAME,szVir);
		lCurSigID = lSigID;
		pCurRoot = pCurVect = pRoot;
	}

	

	iSigLen = strlen(szSig2Add);
	if (iSigLen == 0 || strlen(szVirName) == 0 || pCurRoot == nullptr || pCurVect == nullptr)
	{
		return ERR_INVALID_INPUT;
	}
	for (int i = 0; i < iSigLen; i+=2)
	{
		
		if (szSig2Add[i] != '*')
		{
			//Tushar-->Added Dummy variables to assigned memory
			pTempNewVect = nullptr;
			pTempNewNode = nullptr;

			szChr2Add[0] = szSig2Add[i];
			szChr2Add[1] = szSig2Add[i+1];
			szChr2Add[2] = '\0';
			iChar = strtol(szChr2Add,&szDummy,0x10);
			m_dwCharsAdded++;
			if (pCurVect->m_pSuccessList == nullptr)//Tushar-->No Sub Hierarchy is Available 
			{
				try
				{
					
					pTempNewNode = nullptr;
					
					pTempNewNode = (CNode*)m_TreeMemMgr.AllocateMemory(sizeof(CNode));
					memset(pTempNewNode,0,sizeof(CNode));
					pTempNewNode->m_cNodeChr = iChar;
					pCurVect->m_pSuccessList = pTempNewNode;
					m_dwNodeCount++;
					
					
					try
					{
						pTempNewVect = nullptr;
						pTempNewVect = (CVector*)m_TreeMemMgr.AllocateMemory(sizeof(CVector));
						
						memset(pTempNewVect,0,sizeof(CVector));
						pTempNewVect->m_cVector = iChar;
						pCurVect->m_pSuccessList->m_pSuccess = pTempNewVect;
						m_dwVectorCount++;

						pCurVect = pCurVect->m_pSuccessList->m_pSuccess;
					}
					catch(...)
					{
					}
				}
				catch(...)
				{
				}
			}//Tushar-->No Sub Hierarchy is Available
			else
			{//Tushar-->Sub Hierarchy is Available
				bFound = false;
				pCurNode = pCurVect->m_pSuccessList;
				pTempNode = pCurNode;
				while(pCurNode != nullptr)
				{
					if (pCurNode->m_cNodeChr == iChar)
					{
						bFound = true;
						pCurVect = pCurNode->m_pSuccess;
						break;
					}
					else
					{
						pTempNode = pCurNode;
						pCurNode = pCurNode->m_pNextNode;
					}
				}
				if (bFound == false)
				{
					try
					{
						pTempNewNode = nullptr;
						
						pTempNewNode = (CNode*)m_TreeMemMgr.AllocateMemory(sizeof(CNode));
						
						memset(pTempNewNode,0,sizeof(CNode));
						pTempNewNode->m_cNodeChr = iChar;
						pTempNode->m_pNextNode = pTempNewNode;
						m_dwNodeCount++;
						
						try
						{
							pTempNewVect = nullptr;
							
							pTempNewVect = (CVector*)m_TreeMemMgr.AllocateMemory(sizeof(CVector));
							memset(pTempNewVect,0,sizeof(CVector));
							pTempNewVect->m_cVector = iChar;
							pTempNode->m_pNextNode->m_pSuccess = pTempNewVect;
							m_dwVectorCount++;
							
							pCurVect = pTempNode->m_pNextNode->m_pSuccess;
						}
						catch(...)
						{
							//Problem with Allocating new Vetor Memory
						}
					}
					catch(...)
					{
						//Problem with Allocating new Node Memory	
					}
				}//End of bFound if
			}//Tushar-->Sub Hierarchy is Available
		}
		else//Tushar//If Character 2 Add is '*'
		{//
			
			if (m_SecSigDB.m_bIsValidSecSigDB != false)
			{
				if (m_SecSigDB.WriteSecSignature(lCurSigID,&szSig2Add[i+1]) == ERR_SUCCESS)
				{
				}
			}
			break;
		}
	}
	
	
	//Tushar-->End of the Signature. Need to Mark Final Node
	{
		pCurVect->m_bIsFinal = 1;
		
		lNewSigID = lCurSigID * MAX_SIG_PARTS;
		lDummy = pCurVect->m_iSigID;
		pCurVect->m_iSigID = ManageFinalNodesEx(lNewSigID,lDummy);
	}
	
	//Tushar-->Commented By Tushar. Managing Virus Name List Using File Maping Object
	if (INVALID_HANDLE_VALUE != m_hNameDB && nullptr != m_hNameDBMap && nullptr != m_pNameDBView)
	{
		memset(&m_NameList,0,sizeof(m_NameList));
		m_NameList.m_iFinalSigID = lNewSigID;
		strcpy_s(m_NameList.m_szVirusName,MAX_VIRUS_NAME,szVirName);
		WriteFile(m_hNameDB,&m_NameList,sizeof(m_NameList),&dwBytesWritten, nullptr);
	}
	else
	{
		
		return ERR_INVALID_POINTER;
	}
	return ERR_SUCCESS;
}

/******************************************************************************
Function Name	:	AddSig2TreeEx (Overloaded)
Author			:	Tushar Kadam
Scope			:	Private
Input			:	char * -->Signature 2 Add
					unsigned long -->Current Signature Count Being Added
					CVector * -->Root of the Tree
Output			:   if Success then == ERR_SUCCESS
*******************************************************************************/
int CTreeManager::AddSig2TreeEx(char * szSig, unsigned long lSigID, CVector * pRoot)
{
	char			szSig2Add[MAX_SZ_LEN] = {0};
	unsigned long	lCurSigID = 0;
	unsigned long	lNewSigID = 0;
	unsigned long	lDummy = 0;
	CVector			*pCurRoot = nullptr;
	CVector			*pCurVect = nullptr;
	size_t			iSigLen = 0;
	int				iPartsAdded=1;
	char			szChr2Add[3] = { 0 };
	char			*szDummy = nullptr;
	unsigned int	iChar=0;	 
	bool			bFound = false;
	CNode* pCurNode = nullptr;
	CNode* pTempNode = nullptr;
	DWORD			dwBytesWritten = 0;
	CVector			*pTempNewVect = nullptr;
	CNode			*pTempNewNode = nullptr;
	
	{//Intializing of Local Variables
		strcpy_s(szSig2Add,MAX_SZ_LEN,szSig);
		lCurSigID = lSigID;
		pCurRoot = pCurVect = pRoot;
	}

	iSigLen = strlen(szSig2Add);
	if (iSigLen == 0 || pCurRoot == nullptr || pCurVect == nullptr)
	{
		return ERR_INVALID_INPUT;
	}
	for(size_t i = 0; i < iSigLen; i+=2)
	{
		
		if (szSig2Add[i] != '*')
		{
			//Tushar-->Added Dummy variables to assigned memory
			pTempNewVect = nullptr;
			pTempNewNode = nullptr;

			szChr2Add[0] = szSig2Add[i];
			szChr2Add[1] = szSig2Add[i+1];
			szChr2Add[2] = '\0';
			iChar = strtol(szChr2Add,&szDummy,0x10);
			m_dwCharsAdded++;
			if (pCurVect->m_pSuccessList == nullptr)//Tushar-->No Sub Hierarchy is Available 
			{
				try
				{
					
					pTempNewNode = nullptr;
					
					pTempNewNode = (CNode*)m_TreeMemMgr.AllocateMemory(sizeof(CNode));
					memset(pTempNewNode,0,sizeof(CNode));
					pTempNewNode->m_cNodeChr = iChar;
					pCurVect->m_pSuccessList = pTempNewNode;
					m_dwNodeCount++;
					
					try
					{
						pTempNewVect = nullptr;
						
						pTempNewVect = (CVector*)m_TreeMemMgr.AllocateMemory(sizeof(CVector));
						
						memset(pTempNewVect,0,sizeof(CVector));
						pTempNewVect->m_cVector = iChar;
						pCurVect->m_pSuccessList->m_pSuccess = pTempNewVect;
						m_dwVectorCount++;

						pCurVect = pCurVect->m_pSuccessList->m_pSuccess;
					}
					catch(...)
					{
						//Problem with Allocating new Vetor Memory
					}
				}
				catch(...)
				{
					//Problem in Allocating New Node Memory
				}
			}//Tushar-->No Sub Hierarchy is Available
			else
			{//Tushar-->Sub Hierarchy is Available
				bFound = false;
				pCurNode = pCurVect->m_pSuccessList;
				pTempNode = pCurNode;
				while(pCurNode != nullptr)
				{
					if (pCurNode->m_cNodeChr == iChar)
					{
						bFound = true;
						pCurVect = pCurNode->m_pSuccess;
						break;
					}
					else
					{
						pTempNode = pCurNode;
						pCurNode = pCurNode->m_pNextNode;
					}
				}
				if (bFound == false)
				{
					try
					{
						pTempNewNode = nullptr;
						
						pTempNewNode = (CNode*)m_TreeMemMgr.AllocateMemory(sizeof(CNode));
						
						memset(pTempNewNode,0,sizeof(CNode));
						pTempNewNode->m_cNodeChr = iChar;
						pTempNode->m_pNextNode = pTempNewNode;
						m_dwNodeCount++;
						
						try
						{
							pTempNewVect = nullptr;
							
							pTempNewVect = (CVector*)m_TreeMemMgr.AllocateMemory(sizeof(CVector));
							
							memset(pTempNewVect,0,sizeof(CVector));
							pTempNewVect->m_cVector = iChar;
							pTempNode->m_pNextNode->m_pSuccess = pTempNewVect;
							m_dwVectorCount++;
							
							pCurVect = pTempNode->m_pNextNode->m_pSuccess;
						}
						catch(...)
						{
							//Problem with Allocating new Vetor Memory
						}
					}
					catch(...)
					{
						//Problem with Allocating new Node Memory	
					}
				}//End of bFound if
			}//Tushar-->Sub Hierarchy is Available
		}
		else//Tushar//If Character 2 Add is '*'
		{//
			pCurVect->m_bIsFinal = 1;
			lNewSigID = ((lCurSigID * MAX_SIG_PARTS) + iPartsAdded);
			lDummy = pCurVect->m_iSigID;
			pCurVect->m_iSigID = ManageFinalNodesEx(lNewSigID,lDummy);
			iPartsAdded++;
			
			pCurVect = pCurRoot;
			i--;
			
			
		}
	}
	
	//Tushar-->End of the Signature. Need to Mark Final Node
	{
		pCurVect->m_bIsFinal = 1;
		lNewSigID = ((lCurSigID * MAX_SIG_PARTS) + iPartsAdded);
		lDummy = pCurVect->m_iSigID;
		pCurVect->m_iSigID = ManageFinalNodesEx(lNewSigID,lDummy);
	}
	
	
	{
		if (m_lTotalSigsAdded == 1)
		{
			
			m_pSigPartMgrLst = (unsigned int**)Allocate_Memory(sizeof(unsigned int*));
			
			m_pSigPartMgrLst[0] = (unsigned int*)Allocate_Memory(sizeof(unsigned int));
			*m_pSigPartMgrLst[0] = lNewSigID;
			m_lTotalSigsAdded++;
		}
		else
		{
			m_pSigPartMgrLst = (unsigned int **)realloc(m_pSigPartMgrLst,m_lTotalSigsAdded*sizeof(unsigned int *));
			
			m_pSigPartMgrLst[m_lTotalSigsAdded-1] = (unsigned int*)Allocate_Memory(sizeof(unsigned int));
			*m_pSigPartMgrLst[m_lTotalSigsAdded-1] = lNewSigID;
			m_lTotalSigsAdded++;
		}
	}

	return ERR_SUCCESS;
}

/******************************************************************************
Function Name	:	ManageFinalNodesEx
Author			:	Tushar Kadam
Scope			:	Private
Input			:	unsigned int -->Signature ID
					unsigned int -->Final Node Link ID
Output			:   if Success then  >= 0 --> New Final Node Link ID
*******************************************************************************/
int CTreeManager::ManageFinalNodesEx(unsigned int iSID, unsigned int iFID)
{
	unsigned int		iSigID = 0;
	unsigned int	iFinalLinkID = 0;
	unsigned int	iRet = 0;
	

	{//Initializing Local Variables
		iSigID = iSID;
		iFinalLinkID = iFID;
	}
	if (iFinalLinkID == 0)//First Time Allocating Final Node
	{
		if (m_iFinalLinkCount == 0)
		{
			
			m_pSigMatchLink = (CSigMatchLink **)Allocate_Memory(sizeof(CSigMatchLink*));
			
			m_pSigMatchLink[0] = (CSigMatchLink*)Allocate_Memory(sizeof(CSigMatchLink));
			m_pSigMatchLink[0]->m_FinalSigsCnt = 1;
			
			m_pSigMatchLink[0]->m_FinalSigs = (unsigned int **)Allocate_Memory(sizeof(unsigned int *));
			
			m_pSigMatchLink[0]->m_FinalSigs[0] = (unsigned int*)Allocate_Memory(sizeof(unsigned int));
			*(m_pSigMatchLink[0]->m_FinalSigs[0]) = iSigID;
			m_iFinalLinkCount++;
		}
		else
		{
			if (m_iFinalLinkCount > 0)
			{
				m_pSigMatchLink = (CSigMatchLink **)realloc(m_pSigMatchLink,((m_iFinalLinkCount + 1)*sizeof(CSigMatchLink *)));
				
				m_pSigMatchLink[m_iFinalLinkCount] = (CSigMatchLink*)Allocate_Memory(sizeof(CSigMatchLink));
				m_pSigMatchLink[m_iFinalLinkCount]->m_FinalSigsCnt = 1;
				
				m_pSigMatchLink[m_iFinalLinkCount]->m_FinalSigs = (unsigned int **)Allocate_Memory(sizeof(unsigned int *));
				
				
				m_pSigMatchLink[m_iFinalLinkCount]->m_FinalSigs[0] = (unsigned int*)Allocate_Memory(sizeof(unsigned int));
				*(m_pSigMatchLink[m_iFinalLinkCount]->m_FinalSigs[0]) = iSigID;
				m_iFinalLinkCount++;
			}
		}
		iRet = m_iFinalLinkCount;
	}
	else
	{
		
		if ((iFinalLinkID-1) <= m_iFinalLinkCount)
		{
			m_pSigMatchLink[iFinalLinkID-1]->m_FinalSigsCnt++;
			m_pSigMatchLink[iFinalLinkID-1]->m_FinalSigs = (unsigned int **)realloc(m_pSigMatchLink[iFinalLinkID-1]->m_FinalSigs,(m_pSigMatchLink[iFinalLinkID-1]->m_FinalSigsCnt * sizeof(unsigned int *)));
			
			m_pSigMatchLink[iFinalLinkID-1]->m_FinalSigs[m_pSigMatchLink[iFinalLinkID-1]->m_FinalSigsCnt-1] = (unsigned int*)Allocate_Memory(sizeof(unsigned int));
			
			*(m_pSigMatchLink[iFinalLinkID-1]->m_FinalSigs[m_pSigMatchLink[iFinalLinkID-1]->m_FinalSigsCnt-1]) = iSigID;
			iRet = iFinalLinkID;
		}
	}

	return iRet;
}

/******************************************************************************
Function Name	:	MergeFinalNodes
Author			:	Tushar Kadam
Scope			:	Private
Input			:	unsigned int -->Signature ID
					unsigned int -->Final Node Link ID
Output			:   if Success then  >= 0 --> New Final Node Link ID
*******************************************************************************/
//10 Aug 2011 : DOS Changes
//DOS Changes to be Made -- Final (Add this new function)
BOOL CTreeManager::MergeFinalNodes(unsigned int iSouceID, unsigned int iDestID)
{
	BOOL	bRet = FALSE;

	if (iSouceID < 0x00 || iDestID < 0x00)
		return bRet;
	
	if (iSouceID == iDestID)
		return bRet;

	if (m_iFinalLinkCount < iSouceID || m_iFinalLinkCount < iDestID)
		return bRet;

	
	int	iCount = 0x00;
	int iDestCount = 0x00;

	iCount = m_pSigMatchLink[iSouceID-1]->m_FinalSigsCnt;
	iDestCount = m_pSigMatchLink[iDestID-1]->m_FinalSigsCnt;
	if (iCount == 0x00)
		return bRet;

	m_pSigMatchLink[iDestID-1]->m_FinalSigsCnt+=iCount;
	m_pSigMatchLink[iDestID-1]->m_FinalSigs = (unsigned int **)realloc(m_pSigMatchLink[iDestID-1]->m_FinalSigs,(m_pSigMatchLink[iDestID-1]->m_FinalSigsCnt * sizeof(unsigned int *)));
	for(int i=0x00;i<iCount;i++)
	{
		m_pSigMatchLink[iDestID-1]->m_FinalSigs[i+iDestCount] = (unsigned int*)Allocate_Memory(sizeof(unsigned int));
		*(m_pSigMatchLink[iDestID-1]->m_FinalSigs[i+iDestCount]) = *(m_pSigMatchLink[iSouceID-1]->m_FinalSigs[i]);
	}
	
	return TRUE;
}

/******************************************************************************
Function Name	:	LinkFailureNodes
Author			:	Tushar Kadam
Scope			:	Public
Input			:	No
Output			:   if Success then  ERR_SUCCESS
*******************************************************************************/
int CTreeManager::LinkFailureNodes(void)
{
	CVectLinkStack* pHead = nullptr;
	CVectLinkStack* pTail = nullptr;
	CVectLinkStack* pTmpHead = nullptr;
	CVectLinkStack* pDummyLink = nullptr;
	CVector* pParentVect = nullptr;
	CVector* pDummyVect = nullptr;
	CNode* pCurVectList = nullptr;
	CNode* pDummyNode = nullptr;
	bool			bChrFound = false;
	int				iRet = 0;
	DWORD			dwStackDepth = 1;
	DWORD			dwStackCnt = 0;
	BOOL			bRootTry = FALSE;

	HANDLE			hTempHeap = HeapCreate(HEAP_GENERATE_EXCEPTIONS,0x4000,0x00);
	if (hTempHeap != nullptr)
	{
		ULONG	HeapFragValue = 2;
		HeapSetInformation(hTempHeap,HeapCompatibilityInformation,&HeapFragValue,sizeof(HeapFragValue));
	}

	//Tushar-->Added this Check for Testing whether we have already enumerated Failures
	if (m_TreeRoot.m_pFailureVect != nullptr)
		return ERR_SUCCESS;

	//Tushar-->Initializing Stack for Adding Information
	{
		
		pDummyLink = (CVectLinkStack*)Allocate_Heap_Memory(hTempHeap,sizeof(CVectLinkStack));
		if (pDummyLink == nullptr)
			return ERR_NEW_ALLOC_FAIL;

		pDummyLink->m_pVect = &m_TreeRoot;
		pDummyLink->m_pParentVect = &m_TreeRoot;
		pHead  = pTmpHead = pTail = pDummyLink;
	}
	if (nullptr == pHead || nullptr == pTail || pTmpHead == nullptr)
		return ERR_NEW_ALLOC_FAIL;
	
	//Tushar-->Adding in the Stck for Enumaration of Failures (Levelwise).
	while(pTmpHead)
	{
		pParentVect = pTmpHead->m_pVect;
		pCurVectList = pParentVect->m_pSuccessList;
		if (pParentVect == nullptr)
		{
			
			iRet =  ERR_INVALID_POINTER;
			break;
		}
		while(pCurVectList != nullptr)
		{
			pDummyLink = nullptr;
			dwStackDepth++;
			
			pDummyLink = (CVectLinkStack*)Allocate_Heap_Memory(hTempHeap,sizeof(CVectLinkStack));
			
			if (pDummyLink != nullptr)
			{
				pDummyLink->m_pParentVect = pParentVect;
				pDummyLink->m_pVect = pCurVectList->m_pSuccess;

				pTail->m_pNextLink = pDummyLink;
				pTail = pTail->m_pNextLink;
			}
			pCurVectList = pCurVectList->m_pNextNode;
			if (pCurVectList == nullptr)
				break;
		}
		pTmpHead = pTmpHead->m_pNextLink;
		if (pTmpHead == nullptr)
			break;
	}
	
	//Tushar-->Enumarating Failure Node using above Stack
	pTmpHead = nullptr;
	pTmpHead = pHead;
	while(pTmpHead)
	{//Tushar-->1	
		//Tushar-->R1 : If the Vector is Root then ailure is also Root
		if (pTmpHead->m_pVect == &m_TreeRoot)
			pTmpHead->m_pVect->m_pFailureVect = pTmpHead->m_pVect;
		else
		{//Tushar-->2	
			//Tushar-->R2 : If parent is Root then Failure is also Root
			if (pTmpHead->m_pParentVect == &m_TreeRoot)
				pTmpHead->m_pVect->m_pFailureVect = pTmpHead->m_pParentVect;
			else
			{//Tushar-->3	
				pDummyVect = nullptr;
				pDummyVect = pTmpHead->m_pParentVect->m_pFailureVect;
				
				bRootTry = FALSE;
				do
				{
					bChrFound = false;
					pDummyNode = nullptr;
					pDummyNode = pDummyVect->m_pSuccessList;
					while(pDummyNode != nullptr)
					{//Tushar-->5
						//Tushar-->R3 : Found Valid Failure
						if (pDummyNode->m_cNodeChr == pTmpHead->m_pVect->m_cVector)
						{
							pTmpHead->m_pVect->m_pFailureVect = pDummyNode->m_pSuccess;
							if (pDummyNode->m_pSuccess->m_bIsFinal == 1)
							{
								//10 Aug 2011 : DOS Changes
								if (pTmpHead->m_pVect->m_iSigID == 0x00)
								{
									pTmpHead->m_pVect->m_iSigID = pDummyNode->m_pSuccess->m_iSigID;
									pTmpHead->m_pVect->m_bIsFinal = 1;
								}
								else
								{
									MergeFinalNodes(pDummyNode->m_pSuccess->m_iSigID,pTmpHead->m_pVect->m_iSigID);
								}								
							}
							bChrFound = true;
							break;
						}
						pDummyNode = pDummyNode->m_pNextNode;
						if (pDummyNode == nullptr)
							break;
					}//Tushar-->5 End
					if (bChrFound == true)
						break;

					if (bChrFound == false)
						pDummyVect = pDummyVect->m_pFailureVect;
					if (pDummyVect == nullptr)
						break;
					if (bRootTry == TRUE)
						break;
					if (pDummyVect == &m_TreeRoot && bRootTry == FALSE)
						bRootTry = TRUE;
				}while(pDummyVect != &m_TreeRoot || bRootTry);

				if (pDummyVect == &m_TreeRoot && bChrFound == false)
				{
					//Tushar-->R4 : Reach till Root so assigning Failure as Root
					pTmpHead->m_pVect->m_pFailureVect = &m_TreeRoot;
				}
			}//Tushar-->3 End
		}//Tushar-->2 End 
		pTmpHead = pTmpHead->m_pNextLink;
		dwStackCnt++;
	}//Tushar-->1 End 	

	//Tushar-->Need to Delete Vector Link Stack to Free memory
	
	
	{//Tushar-->Assigning all local variable NULL value
		pHead = nullptr;
		pTail = nullptr;
		pTmpHead = nullptr;
		pDummyLink = nullptr;
		pParentVect = nullptr;
		pDummyVect= nullptr;
		pCurVectList = nullptr;
		pDummyNode= nullptr;
	}

	if (hTempHeap != nullptr)
	{
		HeapDestroy(hTempHeap);
		hTempHeap = nullptr;
	}
		
	return iRet;
}

/******************************************************************************
Function Name	:	UnLoadSignatureDB
Author			:	Tushar	
Scope			:	Public
Input			:	No
Output			:   if Success then  ERR_SUCCESS
Functionality	:	Wrapper for private function UnloadTreeEx()
*******************************************************************************/
int CTreeManager::UnLoadSignatureDB(void)
{
	return UnloadTreeEx();
}

int CTreeManager::OpeNameDBEx(void)
{
	m_hNameDB = CreateFile(m_szNameDBFile,GENERIC_WRITE | GENERIC_READ,FILE_SHARE_READ, nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN, nullptr);
	if (INVALID_HANDLE_VALUE  != m_hNameDB)
	{
		m_hNameDBMap = CreateFileMapping(m_hNameDB, nullptr,PAGE_READWRITE,0x00,(0x2D * 0x2710), nullptr);
		if (nullptr != m_hNameDBMap)
		{
			m_pNameDBView = MapViewOfFile(m_hNameDBMap,FILE_MAP_ALL_ACCESS,0x00,0x00,(0x2D * 0x2710));
			SetFilePointer(m_hNameDB,0x00, nullptr,FILE_BEGIN);
			return ERR_SUCCESS;
		}		
	}
	return ERR_IN_OPENING_FILE;
}

/******************************************************************************
Function Name	:	ScanBuffEx
Author			:	Tushar	
Scope			:	Private
Input			:	unsigned char * ==>Raw Buffer To Scan
				    unsigned int	==>Size of Buffer to Scan
					CVector *		==>Start Position In Tree
					unsigned int &	==>(Out)Id of the Signature Matched
Output			:   if Success then  ERR_SUCCESS
*******************************************************************************/
int CTreeManager::ScanBuffEx(unsigned char * szBuff2Scan, unsigned int iBuffSize, CVector * pStart, int & iMatchSigID, CVector **pMatchVect)
{
	unsigned char	*pszBuff = nullptr;
	unsigned int	iBuffLen = 0;
	CVector			*pRootVect= nullptr;
	CVector			*pCurVect = nullptr;
	CNode			*pCurNode = nullptr;
	unsigned char	cChar2Check = 0x00;
	int				iCnt = 0;	
	bool			bVirFound = false;
	BYTE			bArrayofZero[256] = {0x00};
	BYTE			bArrayofNops[256] = {0x90};


	memset(bArrayofNops,0x90,256);

	{//Tushar-->Initializing Local Variable using Actual Variables
		pszBuff = szBuff2Scan;
		iBuffLen = iBuffSize;
		pCurVect = pStart;
		pRootVect = &m_TreeRoot;
		*pMatchVect = nullptr;
	}
	if (pszBuff == nullptr || pRootVect == nullptr || pCurVect == nullptr)
		return ERR_INVALID_INPUT;

	if (iBuffLen == 0)
		return ERR_ZERO_LEN_INPUT;

	for (unsigned int iCnt = 0; iCnt<iBuffLen; iCnt++)
	{
		cChar2Check = pszBuff[iCnt];

		if (cChar2Check == 0x00)
		{
			if ((iBuffLen - iCnt) > 256)
			{
				if (pszBuff[iCnt+1] == 0x00 && pszBuff[iCnt+2] == 0x00 && pszBuff[iCnt+10] ==0x00 && pszBuff[iCnt+100] ==0x00)
				{
					if (memcmp(&pszBuff[iCnt],&bArrayofZero[0x00],256) == 0x00)
					{
						iCnt+=255;
						pCurVect = pRootVect;
						continue;
					}
				}
			}
		}
		if (cChar2Check == 0x90)
		{
			if ((iBuffLen - iCnt) > 256)
			{
				if (pszBuff[iCnt+1] == 0x90 && pszBuff[iCnt+2] == 0x90 && pszBuff[iCnt+10] ==0x90 && pszBuff[iCnt+100] ==0x90)
				{
					if (memcmp(&pszBuff[iCnt],&bArrayofNops[0x00],256) == 0x00)
					{
						iCnt+=255;
						pCurVect = pRootVect;
						continue;
					}
				}
			}
		}

		while(true)
		{
			if (pCurVect == nullptr)
				break;
			pCurNode = pCurVect->m_pSuccessList;
			bVirFound = false;
			while(pCurNode)
			{
				if (pCurNode->m_cNodeChr == cChar2Check)
				{
					bVirFound = true;
					pCurVect = pCurNode->m_pSuccess;
					if (pCurVect->m_bIsFinal != 0)
					{
						iMatchSigID = pCurVect->m_iSigID;
						*pMatchVect = pCurVect;
						return iCnt;
					}
					break;
				}
				pCurNode = pCurNode->m_pNextNode;
				if (pCurNode == nullptr)
					break;
			}
			if (pCurVect == pRootVect || bVirFound == true)
				break;
			
			if (iCnt > iBuffLen || iCnt < 0)
				break;
			
			if (pCurVect == nullptr)
			{
				pCurVect = pRootVect;
				break;
			}

			if (pCurVect == pRootVect)
				break;

			if (bVirFound == true)
				break;

			if (bVirFound == false)
				pCurVect = pCurVect->m_pFailureVect;
		}
	}
	return ERR_BUFF_END;
}

/******************************************************************************
Function Name	:	ScanBuffer4Virus
Author			:	Tushar Kadam
Scope			:	Public
Input			:	unsigned char * ==>Raw Buffer To Scan
				    unsigned char *	==>(Out)Virus Name Fount
Output			:   < 0 if no Virus Found Else Virus ID 
*******************************************************************************/
int CTreeManager::ScanBuffer4Virus(unsigned char * szBuffer,unsigned int iBuffLen, char * szVirusName)
{
	unsigned char* pszBuff2Scan = nullptr;
	unsigned char* pDummy = nullptr;
	unsigned int	iBuffSize = 0;
	int				iFinalLinkID = 0;
	int				iMatchPos = 0;
	int			 iTempPos = 0;
	unsigned int	iCurBuffPos = 0;
	unsigned int	iTempCurBuffPos = 0;
	int				iRet = 0;
	int			 iDummy = 0;
	CVirNmList		objName = {0};
	DWORD			dwBytsRead=0;
	int				iFinalRet=-1;
	CVector			*pNextStartVect = nullptr;
	
	pszBuff2Scan = szBuffer;
	iBuffSize = iBuffLen;
	pNextStartVect = &m_TreeRoot;

	if (iBuffSize == 0)
		return ERR_ZERO_LEN_INPUT;
	
	if (pszBuff2Scan == nullptr)
		return ERR_INVALID_INPUT;
	
	iMatchPos = ScanBuffEx(pszBuff2Scan,iBuffSize,pNextStartVect,iFinalLinkID,&pNextStartVect);
	if (iMatchPos <=0)
		return -1;

	if (iFinalLinkID == 0)
		return -1;

	if (iMatchPos != 0 && iFinalLinkID != -1)
	{
		while(iMatchPos >= 0)
		{
			iRet = LoadnScanSecondarySigEx(iFinalLinkID,pszBuff2Scan,iBuffSize);
			if (iRet > 0)
			{
				if (INVALID_HANDLE_VALUE != m_hNameDB)
				{
					iDummy = iRet -1;
					memset(&objName,0,sizeof(CVirNmList));
					SetFilePointer(m_hNameDB,(iDummy * sizeof(CVirNmList)), nullptr,FILE_BEGIN);
					if (ReadFile(m_hNameDB,&objName,sizeof(objName),&dwBytsRead, nullptr))
					{
						sprintf_s(szVirusName,MAX_VIRUS_NAME,"%s",objName.m_szVirusName);
					}
				}
				iFinalRet =  iRet-1;
				break;
			}
			
			iFinalLinkID = 0;
			iCurBuffPos = iCurBuffPos + iMatchPos + 1;
			pDummy = pszBuff2Scan;
			pDummy+=iCurBuffPos;

			if (pNextStartVect == nullptr)
				pNextStartVect = &m_TreeRoot;

			iMatchPos = 0;
			iMatchPos = ScanBuffEx(pDummy,iBuffSize - iCurBuffPos,pNextStartVect,iFinalLinkID,&pNextStartVect);
		}
	}
	if (strlen(szVirusName) > 0)
		pNextStartVect = &m_TreeRoot;
	return iFinalRet;
}

/******************************************************************************
Function Name	:	Scan4SecSig (For Secondary Tree)
Author			:	Tushar Kadam
Scope			:	Public
Input			:	unsigned char * ==>Raw Buffer To Scan
				    unsigned int	==>Buffer Length
Output			:   < 0 if no Virus Found Else Virus ID
*******************************************************************************/
int CTreeManager::Scan4SecSig(unsigned char * szBuffer,unsigned int iBuffLen)
{
	unsigned char* pszBuff2Scan = nullptr;
	unsigned char* pDummy = nullptr;
	unsigned int	iBuffSize = 0;
	int				iFinalLinkID = -1;
	int				iMatchPos = 0;	
	int				iRet=0;
	unsigned int	iCurSigID=0;	
	typedef struct	_VIRUSFOUNDLIST
	{
		unsigned int	m_SigID;
		unsigned short	m_TotalParts; 
		unsigned short	m_PartMatched;
	}VirusFoundList;
	
	VirusFoundList objVirFList[1000];
	CVector			*pNextStartVect = nullptr;

	memset(objVirFList,0,(1000 * sizeof(VirusFoundList)));
	
	{//Tushar->Initalization of Local Parameters, using formal parameters
		pszBuff2Scan = szBuffer;
		iBuffSize = iBuffLen;
			pNextStartVect = &m_TreeRoot;
	}

	if (iBuffSize == 0)
		return ERR_ZERO_LEN_INPUT;
	
	if (pszBuff2Scan == nullptr)
		return ERR_INVALID_INPUT;
	
	iFinalLinkID = 0;
	iMatchPos = ScanBuffEx(pszBuff2Scan,iBuffSize,pNextStartVect,iFinalLinkID,&pNextStartVect);

	if (iMatchPos <= 0)
		return -1;

	if (iFinalLinkID <= 0)
		return -1;

	int				jCnt = 0;
	unsigned int	iNewID = 0;
	unsigned int	iPart = 0;
	bool			bVirFound=false;
	int				iVirusCnt=0;
	int				iCurBufPos=0;
	unsigned int	iDummy=0;	
	unsigned char	*pszDummy= nullptr;
	int				iFinalSigMatchCnt = 0;

	//10 Aug 2011 : DOS Changes
	while(iMatchPos >= 0)//DOS Changes to be Made -- Final
	{
		iFinalSigMatchCnt = m_pSigMatchLink[iFinalLinkID-1]->m_FinalSigsCnt;
		for (int iCnt = 0; iCnt < iFinalSigMatchCnt;iCnt++)
		{
			iCurSigID = *(m_pSigMatchLink[iFinalLinkID-1]->m_FinalSigs[iCnt]);
			iNewID = iCurSigID / MAX_SIG_PARTS;
			iPart = iCurSigID % MAX_SIG_PARTS;
			if (iVirusCnt == 0)
			{
				objVirFList[0].m_SigID = iNewID;
				// Modified by Rupali on 19 Jan 2011. Set m_PartMatched to 1 
				// only if 1st part of sec signature is matched.
				if(iPart == 1)
						objVirFList[0].m_PartMatched = 1;
					else
						objVirFList[0].m_PartMatched = 0;
				
				// End
				//Need to Handle Signature Count
				if (m_lTotalSigsAdded > 0 && m_pSigPartMgrLst != nullptr)
				{
					for (unsigned long kCnt = 0; kCnt < (m_lTotalSigsAdded - 1);kCnt++)
					{
						if (((*m_pSigPartMgrLst[kCnt]) / MAX_SIG_PARTS) == iNewID)
						{
							iDummy = (*m_pSigPartMgrLst[kCnt]) % MAX_SIG_PARTS;
							objVirFList[0].m_TotalParts = iDummy;
							break;
						}
					}
					if (objVirFList[jCnt].m_PartMatched == objVirFList[jCnt].m_TotalParts)
					{
						bVirFound = true;
						break;
					}
				}
				iVirusCnt++;
			}
			else
			{
				for (jCnt = 0;jCnt<iVirusCnt;jCnt++)
				{
					if (objVirFList[jCnt].m_SigID > 0)
					{
						if (iNewID == objVirFList[jCnt].m_SigID)
						{
							//Tushar ==> 11 Dec 2010 : Added this condition to Handle Part Matching Sequence
							if (iPart <= objVirFList[jCnt].m_PartMatched)
							{
								break;
							}
							// Added by Rupali on 19 Jan 2011. Added this condition to Handle Part Matching Sequence
							if (iPart - 1  == objVirFList[jCnt].m_PartMatched)
							{
								objVirFList[jCnt].m_PartMatched++;
							}
							
							// End
							if (objVirFList[jCnt].m_PartMatched == objVirFList[jCnt].m_TotalParts)
								bVirFound = true;
							break;
						}
					}
				}
				if (jCnt == iVirusCnt)
				{
					objVirFList[iVirusCnt].m_SigID = iNewID;
					
					// Modified by Rupali on 19 Jan 2011. Set m_PartMatched to 1 
					// only if 1st part of sec signature is matched.
					if(iPart == 1)
						objVirFList[iVirusCnt].m_PartMatched = 1;
					else
						objVirFList[iVirusCnt].m_PartMatched = 0;
					
					// End
					if (m_lTotalSigsAdded > 0 && m_pSigPartMgrLst != nullptr)
					{
						for (unsigned long kCnt = 0; kCnt < (m_lTotalSigsAdded - 1);kCnt++)
						{
							if (((*m_pSigPartMgrLst[kCnt]) / MAX_SIG_PARTS) == iNewID)
							{
								iDummy = (*m_pSigPartMgrLst[kCnt]) % MAX_SIG_PARTS;
								objVirFList[iVirusCnt].m_TotalParts = iDummy;
								break;
							}
						}
						if (objVirFList[jCnt].m_PartMatched == objVirFList[jCnt].m_TotalParts)
						{
							bVirFound = true;
							break;
						}
					}
					iVirusCnt++;
				}
			}
			if (bVirFound == true)
				break;
		}
		if (bVirFound == true)
			break;
		iCurBufPos = iCurBufPos + iMatchPos + 1;
		
		iFinalLinkID = 0;
		pDummy = &pszBuff2Scan[iCurBufPos];
		if (pNextStartVect == nullptr)
			pNextStartVect = &m_TreeRoot;
		iMatchPos = ScanBuffEx(pDummy,iBuffSize - iCurBufPos,pNextStartVect,iFinalLinkID,&pNextStartVect);
		//10 Aug 2011 : DOS Changes
		if (iMatchPos < 0)//DOS Changes to be Made -- Final
			break;
		if (iFinalLinkID <= 0)
			break;
	}

	if (bVirFound == true)
	{
		iDummy = iCurSigID / MAX_SIG_PARTS;
		return iDummy;
	}

	return -1;
}

/******************************************************************************
Function Name	:	LoadnScanSecondarySigEx
Author			:	Tushar Kadam
Scope			:	Private
Input			:	unsigned int	==>Final Link Matching ID
					unsigned char * ==>Raw Buffer To Scan
				    unsigned int	==>Length of Buffer
Output			:   < 0 if no Virus Found Else Virus ID
*******************************************************************************/
int CTreeManager::LoadnScanSecondarySigEx(unsigned int iFLinkID, unsigned char * szBuffer, unsigned int iBuffLen)
{
	unsigned int	iFinalLinkMatch=0;
	unsigned char	*pszBuffer= nullptr;
	unsigned int	iInputLen=0;
	unsigned int	iDummyID=0;
	DWORD			dwBytesRead=0;
	CTreeManager	*pSecTree = nullptr;
	int				iRet=0;
	bool			bIsSecTreeLoaded = false;

	{//Tushar->Initalization of Local Parameters, using formal parameters
		iFinalLinkMatch = iFLinkID;
		pszBuffer = szBuffer;
		iInputLen = iBuffLen;
	}

	
	if (iFinalLinkMatch <= 0 || pszBuffer == nullptr)
		return ERR_INVALID_INPUT;
	if (iInputLen == 0)
		return ERR_ZERO_LEN_INPUT;

	pSecTree = new CTreeManager();
	if (pSecTree == nullptr)
		return ERR_INVALID_POINTER;

	if (iFinalLinkMatch <= m_iFinalLinkCount)
	{//1
		for (unsigned int iCnt = 0;iCnt<m_pSigMatchLink[iFinalLinkMatch-1]->m_FinalSigsCnt;iCnt++)
		{
			iDummyID = *(m_pSigMatchLink[iFinalLinkMatch-1]->m_FinalSigs[iCnt]);
			iDummyID = iDummyID / MAX_SIG_PARTS;
			if (iDummyID < m_lTotalSigsAdded)
			{//2
				if (m_SecSigDB.m_bIsValidSecSigDB)
				{//3
					if (m_SecSigDB.GetSecondarySig(iDummyID) == ERR_SUCCESS)
					{
						if (strlen(m_SecSigDB.m_SecDBInfo.m_szSecSig) != 0)
						{
							pSecTree->LoadSignatureDB(m_SecSigDB.m_SecDBInfo.m_szSecSig,iDummyID);
							bIsSecTreeLoaded = true;
						}
					}
				}//3->End
			}//2->End
		}//For->End
		
		//Tushar->Loading Tree Completed. Now Sending Buffer to Scan
		if (bIsSecTreeLoaded == true)
		{
			pSecTree->LinkFailureNodes();
			iRet = pSecTree->Scan4SecSig(pszBuffer,iInputLen);
		}

	}//1->End
	else
		iRet = ERR_INVALID_INPUT;

	if (pSecTree != nullptr)
	{
		pSecTree->UnLoadSignatureDB();
		delete pSecTree;
		
		pSecTree = nullptr;
	}
	
	return iRet;
}

/******************************************************************************
Function Name	:	LoadSigDBEx
Author			:	Tushar Kadam
Scope			:	Private
Input			:	LPCTSTR : Signature and Virus Name to Add
					bMoreSigs : Boolean value to identify whether need to add more signatures
Output			:   if Success then  > 0 --> No. of signature loaded in memory
*******************************************************************************/
int CTreeManager::LoadSigDBEx(LPCTSTR pszSig2Add, LPCTSTR pszVirusName, BOOL bMoreSigs)
{
	char	szVirusName[MAX_VIRUS_NAME] = {0};
	char	szSig2Add[MAX_SZ_LEN] = {0};

	if (FALSE == m_bSecDBCreated)
		LoadNamenSecDB();

	WideCharToMultiByte(CP_UTF8, 0, pszSig2Add, _tcslen(pszSig2Add), szSig2Add, MAX_SZ_LEN, nullptr, nullptr);
	WideCharToMultiByte(CP_UTF8, 0, pszVirusName, _tcslen(pszVirusName), szVirusName, MAX_VIRUS_NAME, nullptr, nullptr);

	if(szSig2Add[strlen(szSig2Add)-1] == 0x20)
	{
		szSig2Add[strlen(szSig2Add)-1] = '\0';
	}			
	if(szSig2Add[strlen(szSig2Add)-1] == 0xA)
	{
		szSig2Add[strlen(szSig2Add)-1] = '\0';
	}
	if(szSig2Add[strlen(szSig2Add)-1] == 0xD) 
	{
		szSig2Add[strlen(szSig2Add)-1] = '\0';
	}

	if(IsValidSigEx(szVirusName,szSig2Add) > -1)
	{
		if(ERR_SUCCESS == AddSig2TreeEx(szSig2Add, szVirusName, m_lTotalSigsAdded, &m_TreeRoot))
		{
			m_lTotalSigsAdded++;
		}
	}			

	if (FALSE == bMoreSigs)
	{
		if (m_lTotalSigsAdded > 1)
			LinkFailureNodes();
	}

	return m_lTotalSigsAdded;
}

/******************************************************************************
Function Name	:	LoadSignatureDB
Author			:	Tushar	Kadam
Scope			:	Public
Input			:	char * -->Signature Db Name to be loaded
Output			:   if Success then  > 0 --> No. of signature loaded in memory
Functionality	:	If is a wrapper function for LoadSigDBEx
*******************************************************************************/
/*
int CTreeManager::LoadNamenSecDB()
{
	TCHAR		szTempPath[MAX_PATH] = {0};
	DWORD		dwRet = MAX_PATH; 

	dwRet = GetTempPath(MAX_PATH,szTempPath);
	_stprintf_s(szTempPath, MAX_PATH, _T("%sMax"), szTempPath);

	CreateDirectory(szTempPath, nullptr);

	DWORD dwTickCount = GetTickCount();
	_stprintf_s(m_szNameDBFile,MAX_PATH,_T("%s\\%4X_SPDBNM"), szTempPath, dwTickCount);

	OpeNameDBEx();

	_stprintf_s(m_SecSigDB.m_szTempDBName,MAX_PATH,_T("%s\\%4X_SPDBSEC"), szTempPath, dwTickCount);
	m_SecSigDB.OpenSecDB(0x2000);

	m_bSecDBCreated = TRUE;

	return 0x01;
}
*/

int CTreeManager::LoadNamenSecDB()
{
	TCHAR		szTempPath[MAX_PATH] = { 0 };
	DWORD		dwRet = MAX_PATH;

	dwRet = GetTempPath(MAX_PATH, szTempPath);
	_stprintf_s(szTempPath, MAX_PATH, _T("%sMax"), szTempPath);

	CreateDirectory(szTempPath, 0);

	DWORD dwTickCount = GetTickCount() + GetCurrentThreadId() + rand();
	_stprintf_s(m_szNameDBFile, MAX_PATH, _T("%s\\%4X_SPDBNM"), szTempPath, dwTickCount);

	OpeNameDBEx();

	_stprintf_s(m_SecSigDB.m_szTempDBName, MAX_PATH, _T("%s\\%4X_SPDBSEC"), szTempPath, dwTickCount);
	m_SecSigDB.OpenSecDB(0x2000);

	m_bSecDBCreated = TRUE;

	return 0x01;
}

/******************************************************************************
Function Name	:	SetDatabasePatchDownload
Author			:	Anand Srivastava
Scope			:	Private
Input			:	LPCTSTR --> Signature Db Name which failed in loading
Output			:   void
Functionality	:	Set registry to download full database patch
*******************************************************************************/
void CTreeManager::SetDatabasePatchDownload(LPCTSTR szDBPath)
{
	HKEY hKey = nullptr;
	DWORD dwRetVal = 0;
	DWORD	dwData = 1;

	if(0 == m_szProdRegKeyPath[0])
	{
		return;
	}

	dwRetVal = RegOpenKeyEx(HKEY_LOCAL_MACHINE, m_szProdRegKeyPath, 0, KEY_WRITE, &hKey);
	if(ERROR_SUCCESS != dwRetVal || nullptr == hKey)
	{
		if(hKey)
		{
			RegCloseKey(hKey);
			hKey = nullptr;
		}

		return;
	}

	dwRetVal = RegSetValueEx(hKey, _T("AutoDatabasePatch"), 0, REG_DWORD, (LPBYTE)&dwData, sizeof(dwData));
	RegCloseKey(hKey);

	if(ERROR_SUCCESS != dwRetVal)
	{
		return;
	}

	return;
}


/******************************************************************************
Function Name	:	ScanBuffer4YARA
Author			:	Tushar Kadam
Scope			:	Public
Input			:	unsigned char * ==>Raw Buffer To Scan
				    unsigned char *	==>(Out)Virus Name Fount
Output			:   < 0 if no Virus Found Else Virus ID 
*******************************************************************************/
int CTreeManager::ScanBuffer4YARA(unsigned char * szBuffer,unsigned int iBuffLen, char * szVirusName,TCHAR *pszPERule)
{
	unsigned char* pszBuff2Scan = nullptr;
	unsigned char* pDummy = nullptr;
	unsigned int	iBuffSize = 0;
	int				iFinalLinkID = 0;
	int				iMatchPos = 0;
	int			 iTempPos = 0;
	unsigned int	iCurBuffPos = 0;
	unsigned int	iTempCurBuffPos = 0;
	int				iRet = 0;
	int				iDummy = 0;
	CVirNmList		objName = {0};
	DWORD			dwBytsRead=0;
	int				iFinalRet=-1;
	CVector			*pNextStartVect = nullptr;
	unsigned int	iSigMatchedkArray[500] = { 0x00 };
	unsigned int	iTotalSigsMatched = 0x00;
	bool			bAlreadPresent = false;
	
	
	pszBuff2Scan = szBuffer;
	iBuffSize = iBuffLen;
	pNextStartVect = &m_TreeRoot;

	if (iBuffSize == 0)
		return ERR_ZERO_LEN_INPUT;
	
	if (pszBuff2Scan == nullptr)
		return ERR_INVALID_INPUT;
	
	

	iMatchPos = ScanBuffEx(pszBuff2Scan,iBuffSize,pNextStartVect,iFinalLinkID,&pNextStartVect);
	if (iMatchPos <=0)
		return -1;

	if (iFinalLinkID == 0)
		return -1;

	if (iMatchPos != 0 && iFinalLinkID != -1)
	{
		while(iMatchPos >= 0)
		{
			bAlreadPresent = false;
			for (unsigned int i = 0x00; i < iTotalSigsMatched; i++)
			{
				if (iSigMatchedkArray[i] == iFinalLinkID)
				{
					bAlreadPresent = true;
					break;
				}
			}
			if (bAlreadPresent == false)
			{
				iSigMatchedkArray[iTotalSigsMatched] = iFinalLinkID;
				iTotalSigsMatched++;
			}
			//Loading Secondary Tree is Movied to bottom for all signatures.
			iFinalLinkID = 0;
			iCurBuffPos = iCurBuffPos + iMatchPos + 1;
			pDummy = pszBuff2Scan;
			pDummy+=iCurBuffPos;

			if (pNextStartVect == nullptr)
				pNextStartVect = &m_TreeRoot;

			iMatchPos = 0;
			iMatchPos = ScanBuffEx(pDummy,iBuffSize - iCurBuffPos,pNextStartVect,iFinalLinkID,&pNextStartVect);
		}
	}

	
	iRet = LoadnScanSecondarySigExYAYA(iSigMatchedkArray,iTotalSigsMatched,pszBuff2Scan,iBuffSize);
	if (iRet > 0)
	{
		if (INVALID_HANDLE_VALUE != m_hNameDB)
		{
			iDummy = iRet -1;
			memset(&objName,0,sizeof(CVirNmList));
			SetFilePointer(m_hNameDB,(iDummy * sizeof(CVirNmList)), nullptr,FILE_BEGIN);
			if (ReadFile(m_hNameDB,&objName,sizeof(objName),&dwBytsRead, nullptr))
			{
				sprintf_s(szVirusName,MAX_VIRUS_NAME,"%s",objName.m_szVirusName);
				

				for (unsigned long iCnt = 0x00; iCnt < m_dwYaraPEListCnt; iCnt++)
				{
					if (m_pYaraPEList[iCnt]->dwSigID == iRet)
					{
						if (pszPERule)
						{
							_tcscpy_s(pszPERule,1024,m_pYaraPEList[iCnt]->szRules);
							break;
						}
					}
				}

			}
		}
		iFinalRet =  iRet-1;
	}
	
	if (strlen(szVirusName) > 0)
		pNextStartVect = &m_TreeRoot;
	return iFinalRet;
}

/******************************************************************************
Function Name	:	ScanBuffer4YARA
Author			:	Tushar Kadam
Scope			:	Public
Input			:	unsigned char * ==>Raw Buffer To Scan
				    unsigned char *	==>(Out)Virus Name Fount
Output			:   < 0 if no Virus Found Else Virus ID 
*******************************************************************************/
int CTreeManager::ScanBuffer4YARA(HANDLE pFileHandle,unsigned int iBuffLen, char * szVirusName,TCHAR *pszPERule)
{
	unsigned char	*pDummy= nullptr;
	unsigned int	iBuffSize = 0;
	int				iFinalLinkID = 0;
	int				iMatchPos = 0;
	int				iTempPos = 0;
	unsigned int	iCurBuffPos = 0;
	unsigned int	iTempCurBuffPos = 0;
	int				iRet = 0;
	int				iDummy = 0;
	CVirNmList		objName = {0};
	DWORD			dwBytsRead=0;
	int				iFinalRet=-1;
	CVector			*pNextStartVect = nullptr;
	unsigned int	iSigMatchedkArray[500] = { 0x00 };
	unsigned int	iTotalSigsMatched = 0x00;
	bool			bAlreadPresent = false;
	
	if (m_pVirtualBuffer == nullptr)
	{
		if(! AllocateVirtualBuffer())
		{
			return ERR_ZERO_LEN_INPUT;
		}
	}
	
	iBuffSize = iBuffLen;
	pNextStartVect = &m_TreeRoot;

	if (iBuffSize == 0)
		return ERR_ZERO_LEN_INPUT;
	
	
	
	SetFilePointer(pFileHandle,0x00, nullptr,FILE_BEGIN);
	DWORD	dwBytesRead = 0x00;
	DWORD	dwBytes2Read = 0x00;
	DWORD	dwTotalBytesRead = 0x00;
	
	while(true)
	{

		dwBytes2Read = dwBytesRead = 0x00;
		if ((iBuffSize - dwTotalBytesRead) >= BUFFER_GRANUALITY)
		{
			dwBytes2Read = BUFFER_GRANUALITY;
		}
		else
		{
			dwBytes2Read = iBuffSize - dwTotalBytesRead;
		}

		ReadFile(pFileHandle,m_pVirtualBuffer,dwBytes2Read,&dwBytesRead, nullptr);
		if (dwBytesRead == 0x00)
		{
			break;
		}

		dwTotalBytesRead+=dwBytesRead;

		iMatchPos = ScanBuffEx((unsigned char *)m_pVirtualBuffer,dwBytesRead,pNextStartVect,iFinalLinkID,&pNextStartVect);
		if (iMatchPos > 0 && iFinalLinkID >= 0)
		{
			while(iMatchPos >= 0)
			{
				bAlreadPresent = false;
				for (unsigned int i = 0x00; i < iTotalSigsMatched; i++)
				{
					if (iSigMatchedkArray[i] == iFinalLinkID)
					{
						bAlreadPresent = true;
						break;
					}
				}
				if (bAlreadPresent == false)
				{
					iSigMatchedkArray[iTotalSigsMatched] = iFinalLinkID;
					iTotalSigsMatched++;
				}
				//Loading Secondary Tree is Movied to bottom for all signatures.
				iFinalLinkID = 0;
				iCurBuffPos = iCurBuffPos + iMatchPos + 1;
				pDummy = (unsigned char *)m_pVirtualBuffer;
				pDummy+=iCurBuffPos;

				if (pNextStartVect == nullptr)
					pNextStartVect = &m_TreeRoot;

				iMatchPos = 0;
				iMatchPos = ScanBuffEx(pDummy,dwBytesRead - iCurBuffPos,pNextStartVect,iFinalLinkID,&pNextStartVect);
			}
		}
		if (dwBytes2Read == 0x00 || dwTotalBytesRead >= iBuffSize)
		{
			break;
		}
	}

	
	if (iBuffSize < BUFFER_GRANUALITY)
	{
		iRet = LoadnScanSecondarySigExYAYA(iSigMatchedkArray,iTotalSigsMatched,(unsigned char *)m_pVirtualBuffer,iBuffSize);
	}
	else
	{
		iRet = LoadnScanSecondarySigExYAYA(iSigMatchedkArray,iTotalSigsMatched,pFileHandle,iBuffSize);
	}
	if (iRet > 0)
	{
		if (INVALID_HANDLE_VALUE != m_hNameDB)
		{
			iDummy = iRet -1;
			memset(&objName,0,sizeof(CVirNmList));
			SetFilePointer(m_hNameDB,(iDummy * sizeof(CVirNmList)), nullptr,FILE_BEGIN);
			if (ReadFile(m_hNameDB,&objName,sizeof(objName),&dwBytsRead, nullptr))
			{
				sprintf_s(szVirusName,MAX_VIRUS_NAME,"%s",objName.m_szVirusName);
				

				for (unsigned long iCnt = 0x00; iCnt < m_dwYaraPEListCnt; iCnt++)
				{
					if (m_pYaraPEList[iCnt]->dwSigID == iRet)
					{
						if (pszPERule)
						{
							_tcscpy_s(pszPERule,1024,m_pYaraPEList[iCnt]->szRules);
							break;
						}
					}
				}

			}
		}
		iFinalRet =  iRet-1;
	}
	
	if (strlen(szVirusName) > 0)
		pNextStartVect = &m_TreeRoot;
	return iFinalRet;
}
/******************************************************************************
Function Name	:	LoadnScanSecondarySigExYAYA
Author			:	Tushar Kadam
Scope			:	Private
Input			:	unsigned int	==>Final Link Matching ID
					unsigned char * ==>Raw Buffer To Scan
				    unsigned int	==>Length of Buffer
Output			:   < 0 if no Virus Found Else Virus ID
*******************************************************************************/
int CTreeManager::LoadnScanSecondarySigExYAYA(unsigned int iFLinkIDs[],unsigned int iFLinkCnt, unsigned char * szBuffer, unsigned int iBuffLen)
{
	unsigned int	iFinalLinkMatch=0;
	unsigned char	*pszBuffer= nullptr;
	unsigned int	iInputLen=0;
	unsigned int	iDummyID=0;
	DWORD			dwBytesRead=0;
	CTreeManager	*pSecTree = nullptr;
	int				iRet=0;
	bool			bIsSecTreeLoaded = false;
	
	int				iSecSigsAdded[500] = { 0x00 };
	int				iSecSigsAddedCnt = 0x00;

	{//Tushar->Initalization of Local Parameters, using formal parameters
		
		pszBuffer = szBuffer;
		iInputLen = iBuffLen;
	}

	
	if ( pszBuffer == nullptr)
		return ERR_INVALID_INPUT;
	if (iInputLen == 0)
		return ERR_ZERO_LEN_INPUT;

	pSecTree = new CTreeManager();
	if (pSecTree == nullptr)
		return ERR_INVALID_POINTER;

	

	for (unsigned int i = 0x00; i < iFLinkCnt; i++)
	{
		

		iFinalLinkMatch = iFLinkIDs[i];
		if (iFinalLinkMatch != 0 && iFinalLinkMatch <= m_iFinalLinkCount)
		{//1
			for (unsigned int iCnt = 0;iCnt<m_pSigMatchLink[iFinalLinkMatch-1]->m_FinalSigsCnt;iCnt++)
			{
				bool	bAlreadyLoaded = false;
				iDummyID = *(m_pSigMatchLink[iFinalLinkMatch-1]->m_FinalSigs[iCnt]);
				iDummyID = iDummyID / MAX_SIG_PARTS;

				for (int iArrayCnt = 0x00; iArrayCnt < iSecSigsAddedCnt; iArrayCnt++)
				{
					if (iSecSigsAdded[iArrayCnt] == iDummyID)
					{
						bAlreadyLoaded = true;
						break;
					}
				}

				if (bAlreadyLoaded == false)
				{
					if (iDummyID < m_lTotalSigsAdded)
					{//2
						if (m_SecSigDB.m_bIsValidSecSigDB)
						{//3
							if (m_SecSigDB.GetSecondarySig(iDummyID) == ERR_SUCCESS)
							{
								if (strlen(m_SecSigDB.m_SecDBInfo.m_szSecSig) != 0)
								{
									

									pSecTree->LoadSignatureDB(m_SecSigDB.m_SecDBInfo.m_szSecSig,iDummyID);
									bIsSecTreeLoaded = true;

									iSecSigsAdded[iSecSigsAddedCnt++] = iDummyID;
								}
							}
						}//3->End
					}//2->End
				}
			}//For->End
			
		}//1->End
	}

	

	//Tushar->Loading Tree Completed. Now Sending Buffer to Scan
	if (bIsSecTreeLoaded == true)
	{
		
		pSecTree->LinkFailureNodes();
		
		iRet = pSecTree->Scan4SecSigYARA(pszBuffer,iInputLen);
		
	}

	if (pSecTree != nullptr)
	{
		pSecTree->UnLoadSignatureDB();
		delete pSecTree;
		
		pSecTree = nullptr;
	}
	
	return iRet;
}

/******************************************************************************
Function Name	:	LoadnScanSecondarySigExYAYA
Author			:	Tushar Kadam
Scope			:	Private
Input			:	unsigned int	==>Final Link Matching ID
					unsigned char * ==>Raw Buffer To Scan
				    unsigned int	==>Length of Buffer
Output			:   < 0 if no Virus Found Else Virus ID
*******************************************************************************/
int CTreeManager::LoadnScanSecondarySigExYAYA(unsigned int iFLinkIDs[],unsigned int iFLinkCnt, HANDLE pHandle, unsigned int iBuffLen)
{
	unsigned int	iFinalLinkMatch=0;
	unsigned int	iInputLen=0;
	unsigned int	iDummyID=0;
	DWORD			dwBytesRead=0;
	CTreeManager	*pSecTree = nullptr;
	int				iRet=0;
	bool			bIsSecTreeLoaded = false;
	
	int				iSecSigsAdded[500] = { 0x00 };
	int				iSecSigsAddedCnt = 0x00;

	{//Tushar->Initalization of Local Parameters, using formal parameters
		
		iInputLen = iBuffLen;
	}

	

	
	if (iInputLen == 0)
		return ERR_ZERO_LEN_INPUT;

	pSecTree = new CTreeManager();
	if (pSecTree == nullptr)
		return ERR_INVALID_POINTER;

	

	for (unsigned int i = 0x00; i < iFLinkCnt; i++)
	{
		

		iFinalLinkMatch = iFLinkIDs[i];
		if (iFinalLinkMatch != 0 && iFinalLinkMatch <= m_iFinalLinkCount)
		{//1
			for (unsigned int iCnt = 0;iCnt<m_pSigMatchLink[iFinalLinkMatch-1]->m_FinalSigsCnt;iCnt++)
			{
				bool	bAlreadyLoaded = false;
				iDummyID = *(m_pSigMatchLink[iFinalLinkMatch-1]->m_FinalSigs[iCnt]);
				iDummyID = iDummyID / MAX_SIG_PARTS;

				for (int iArrayCnt = 0x00; iArrayCnt < iSecSigsAddedCnt; iArrayCnt++)
				{
					if (iSecSigsAdded[iArrayCnt] == iDummyID)
					{
						bAlreadyLoaded = true;
						break;
					}
				}

				if (bAlreadyLoaded == false)
				{
					if (iDummyID < m_lTotalSigsAdded)
					{//2
						if (m_SecSigDB.m_bIsValidSecSigDB)
						{//3
							if (m_SecSigDB.GetSecondarySig(iDummyID) == ERR_SUCCESS)
							{
								if (strlen(m_SecSigDB.m_SecDBInfo.m_szSecSig) != 0)
								{
									

									pSecTree->LoadSignatureDB(m_SecSigDB.m_SecDBInfo.m_szSecSig,iDummyID);
									bIsSecTreeLoaded = true;

									iSecSigsAdded[iSecSigsAddedCnt++] = iDummyID;
								}
							}
						}//3->End
					}//2->End
				}
			}//For->End
			
		}//1->End
	}

	
	//Tushar->Loading Tree Completed. Now Sending Buffer to Scan
	if (bIsSecTreeLoaded == true)
	{
		pSecTree->LinkFailureNodes();
		iRet = pSecTree->Scan4SecSigYARA(pHandle,iInputLen);
	}

	if (pSecTree != nullptr)
	{
		pSecTree->UnLoadSignatureDB();
		delete pSecTree;
		
		pSecTree = nullptr;
	}
	
	return iRet;
}

/******************************************************************************
Function Name	:	Scan4SecSig (For Secondary Tree)
Author			:	Tushar Kadam
Scope			:	Public
Input			:	unsigned char * ==>Raw Buffer To Scan
				    unsigned int	==>Buffer Length
Output			:   < 0 if no Virus Found Else Virus ID
*******************************************************************************/
int CTreeManager::Scan4SecSigYARA(unsigned char * szBuffer,unsigned int iBuffLen)
{
	unsigned char* pszBuff2Scan = nullptr;
	unsigned char	*pDummy = nullptr;
	unsigned int	iBuffSize = 0;
	int				iFinalLinkID = -1;
	int				iMatchPos = 0;	
	int				iRet=0;
	unsigned int	iCurSigID=0;	
	
	
	typedef struct	_VIRUSFOUNDLIST
	{
		unsigned int	m_SigID;
		unsigned short	m_TotalParts; 
		unsigned short	m_PartMatched;
		TCHAR			szPartMatched[512];
	}VirusFoundList;
	
	VirusFoundList objVirFList[500];
	CVector			*pNextStartVect = nullptr;

	
	for (int i = 0x00; i < 500; i++)
	{
		objVirFList[i].m_SigID = 0x00;
		objVirFList[i].m_TotalParts = 0x00;
		objVirFList[i].m_PartMatched = 0x00;
		_tcscpy_s(objVirFList[i].szPartMatched,L"");
	}
	
	

	{//Tushar->Initalization of Local Parameters, using formal parameters
		pszBuff2Scan = szBuffer;
		iBuffSize = iBuffLen;
			pNextStartVect = &m_TreeRoot;
	}

	if (iBuffSize == 0)
		return ERR_ZERO_LEN_INPUT;
	
	if (pszBuff2Scan == nullptr)
		return ERR_INVALID_INPUT;
	
	

	iFinalLinkID = 0;
	iMatchPos = ScanBuffEx(pszBuff2Scan,iBuffSize,pNextStartVect,iFinalLinkID,&pNextStartVect);

	

	if (iMatchPos <= 0)
		return -1;

	if (iFinalLinkID <= 0)
		return -1;

	int				jCnt = 0;
	unsigned int	iNewID = 0;
	unsigned int	iPart = 0;
	bool			bVirFound=false;
	int				iVirusCnt=0;
	int				iCurBufPos=0;
	unsigned int	iDummy=0;	
	unsigned char	*pszDummy= nullptr;
	int				iFinalSigMatchCnt = 0;
	TCHAR			szDummy[10] = {0x00};


	
	
	//10 Aug 2011 : DOS Changes
	while(iMatchPos >= 0)//DOS Changes to be Made -- Final
	{
		iFinalSigMatchCnt = m_pSigMatchLink[iFinalLinkID-1]->m_FinalSigsCnt;

		
		
		for (int iCnt = 0; iCnt < iFinalSigMatchCnt;iCnt++)
		{
			if (m_pSigMatchLink[iFinalLinkID-1]->m_FinalSigs[iCnt] == nullptr)
			{
				continue;
			}
			iCurSigID = *(m_pSigMatchLink[iFinalLinkID-1]->m_FinalSigs[iCnt]);

			

			iNewID = iCurSigID / MAX_SIG_PARTS;
			iPart = iCurSigID % MAX_SIG_PARTS;

			
			_stprintf_s(szDummy,L";%d;",iPart);

			

			if (iVirusCnt == 0)
			{
				

				objVirFList[0].m_SigID = iNewID;
				// Modified by Rupali on 19 Jan 2011. Set m_PartMatched to 1 
				// only if 1st part of sec signature is matched.

				// End
				//Need to Handle Signature Count
				if (m_lTotalSigsAdded > 0 && m_pSigPartMgrLst != nullptr)
				{
					

					for (unsigned long kCnt = 0; kCnt < (m_lTotalSigsAdded-1);kCnt++)
					{
						

						if (((*m_pSigPartMgrLst[kCnt]) / MAX_SIG_PARTS) == iNewID)
						{
							

							iDummy = (*m_pSigPartMgrLst[kCnt]) % 100;
							objVirFList[0].m_TotalParts = iDummy;

							

							break;
						}

						
					}

					

					if (_tcsstr(objVirFList[0].szPartMatched,szDummy)== nullptr)
					{
						if (objVirFList[0].m_TotalParts >= iPart)
						{
							objVirFList[0].m_PartMatched++;
							
							_tcscat_s(objVirFList[0].szPartMatched,szDummy);
						}
					}

		

					if ((objVirFList[0].m_PartMatched == objVirFList[0].m_TotalParts) && (objVirFList[0].m_TotalParts > 0x00))
					{
						
						bVirFound = true;
						break;
					}
				}
				iVirusCnt++;

				
			}
			else
			{
				

				for (jCnt = 0;jCnt<iVirusCnt;jCnt++)
				{
					if (objVirFList[jCnt].m_SigID > 0)
					{
						if (iNewID == objVirFList[jCnt].m_SigID)
						{
							
							if (_tcsstr(objVirFList[jCnt].szPartMatched,szDummy)== nullptr)
							{
								if (objVirFList[jCnt].m_TotalParts >= iPart)
								{
									objVirFList[jCnt].m_PartMatched++;
									
									_tcscat_s(objVirFList[jCnt].szPartMatched,szDummy);
								}
							}

							
							
							if ((objVirFList[jCnt].m_PartMatched == objVirFList[jCnt].m_TotalParts) && (objVirFList[jCnt].m_TotalParts > 0x00))
							{
								
								bVirFound = true;
							}
							break;
						}
					}
				}

				

				if (jCnt == iVirusCnt)
				{
					
					objVirFList[iVirusCnt].m_SigID = iNewID;
					
					

					if (m_lTotalSigsAdded > 0 && m_pSigPartMgrLst != nullptr)
					{
						

						for (unsigned long kCnt = 0; kCnt < (m_lTotalSigsAdded-1);kCnt++)
						{
							
							if (m_pSigPartMgrLst[kCnt] == nullptr)
							{
								continue;
							}
							int	iDummySigID = *(m_pSigPartMgrLst[kCnt]);

							
							if ((iDummySigID / MAX_SIG_PARTS) == iNewID)
							{
								
								iDummy = iDummySigID % MAX_SIG_PARTS;
								objVirFList[iVirusCnt].m_TotalParts = iDummy;
								break;
							}
							
						}
						
						
						if (_tcsstr(objVirFList[iVirusCnt].szPartMatched,szDummy)== nullptr)
						{
							if (objVirFList[iVirusCnt].m_TotalParts >= iPart)
							{
								objVirFList[iVirusCnt].m_PartMatched++;
								
								_tcscat_s(objVirFList[iVirusCnt].szPartMatched,szDummy);
							}
						}

						

						if ((objVirFList[iVirusCnt].m_PartMatched == objVirFList[iVirusCnt].m_TotalParts) && (objVirFList[iVirusCnt].m_TotalParts > 0x00))
						{
							
							bVirFound = true;
							break;
						}
					}
					
					iVirusCnt++;
				}
				
			}
			if (bVirFound == true)
				break;
		}
		if (bVirFound == true)
			break;

		

		iCurBufPos = iCurBufPos + iMatchPos + 1;
		
		iFinalLinkID = 0;
		pDummy = &pszBuff2Scan[iCurBufPos];
		if (pNextStartVect == nullptr)
			pNextStartVect = &m_TreeRoot;

		

		iMatchPos = ScanBuffEx(pDummy,iBuffSize - iCurBufPos,pNextStartVect,iFinalLinkID,&pNextStartVect);

	

		//10 Aug 2011 : DOS Changes
		if (iMatchPos < 0)//DOS Changes to be Made -- Final
			break;
		if (iFinalLinkID <= 0)
			break;
	}

	if (bVirFound == true)
	{
		iDummy = iCurSigID / MAX_SIG_PARTS;
		return iDummy;
	}

	
	return -1;
}

/******************************************************************************
Function Name	:	Scan4SecSig (For Secondary Tree)
Author			:	Tushar Kadam
Scope			:	Public
Input			:	unsigned char * ==>Raw Buffer To Scan
				    unsigned int	==>Buffer Length
Output			:   < 0 if no Virus Found Else Virus ID
*******************************************************************************/
int CTreeManager::Scan4SecSigYARA(HANDLE pFileHandle,unsigned int iBuffLen)
{
	unsigned char	*pDummy= nullptr;
	unsigned int	iBuffSize = 0;
	int				iFinalLinkID = -1;
	int				iMatchPos = 0;	
	int				iRet=0;
	unsigned int	iCurSigID=0;	
	
	
	typedef struct	_VIRUSFOUNDLIST
	{
		unsigned int	m_SigID;
		unsigned short	m_TotalParts; 
		unsigned short	m_PartMatched;
		TCHAR			szPartMatched[512];
	}VirusFoundList;
	
	VirusFoundList	objVirFList[500];
	CVector			*pNextStartVect = nullptr;

	
	for (int i = 0x00; i < 500; i++)
	{
		objVirFList[i].m_SigID = 0x00;
		objVirFList[i].m_TotalParts = 0x00;
		objVirFList[i].m_PartMatched = 0x00;
		_tcscpy_s(objVirFList[i].szPartMatched,L"");
	}
	
	

	{//Tushar->Initalization of Local Parameters, using formal parameters
		iBuffSize = iBuffLen;
		
			pNextStartVect = &m_TreeRoot;
	}

	if (iBuffSize == 0)
		return ERR_ZERO_LEN_INPUT;
	
	
	
	if(pFileHandle == nullptr)
	{
		return ERR_INVALID_INPUT;
	}

	if (m_pVirtualBuffer == nullptr)
	{
		if (!AllocateVirtualBuffer())
		{
			return ERR_ZERO_LEN_INPUT;
		}
	}

	SetFilePointer(pFileHandle,0x00, nullptr,FILE_BEGIN);

	int				jCnt = 0;
	unsigned int	iNewID = 0;
	unsigned int	iPart = 0;
	bool			bVirFound=false;
	int				iVirusCnt=0;
	int				iCurBufPos=0;
	unsigned int	iDummy=0;	
	unsigned char	*pszDummy= nullptr;
	int				iFinalSigMatchCnt = 0;
	TCHAR			szDummy[10] = {0x00};

	while(true)
	{

		DWORD	dwBytesRead = 0x00;
		DWORD	dwBytes2Read = 0x00;
		DWORD	dwTotalBytesRead = 0x00;

		dwBytes2Read = dwBytesRead = 0x00;
		if ((iBuffSize - dwTotalBytesRead) >= BUFFER_GRANUALITY)
		{
			dwBytes2Read = BUFFER_GRANUALITY;
		}
		else
		{
			dwBytes2Read = iBuffSize - dwTotalBytesRead;
		}

		ReadFile(pFileHandle,m_pVirtualBuffer,dwBytes2Read,&dwBytesRead, nullptr);
		if (dwBytesRead == 0x00)
		{
			break;
		}

		dwTotalBytesRead+=dwBytesRead;

		iFinalLinkID = 0;
		iMatchPos = ScanBuffEx((unsigned char *)m_pVirtualBuffer,dwBytesRead,pNextStartVect,iFinalLinkID,&pNextStartVect);

		

		//10 Aug 2011 : DOS Changes
		while(iMatchPos > 0 && iFinalLinkID > 0)//DOS Changes to be Made -- Final
		{
			iFinalSigMatchCnt = m_pSigMatchLink[iFinalLinkID-1]->m_FinalSigsCnt;

			

			for (int iCnt = 0; iCnt < iFinalSigMatchCnt;iCnt++)
			{
				if (m_pSigMatchLink[iFinalLinkID-1]->m_FinalSigs[iCnt] == nullptr)
				{
					continue;
				}
				iCurSigID = *(m_pSigMatchLink[iFinalLinkID-1]->m_FinalSigs[iCnt]);


				iNewID = iCurSigID / MAX_SIG_PARTS;
				iPart = iCurSigID % MAX_SIG_PARTS;

				
				_stprintf_s(szDummy,L";%d;",iPart);

			

				if (iVirusCnt == 0)
				{
					

					objVirFList[0].m_SigID = iNewID;
					// Modified by Rupali on 19 Jan 2011. Set m_PartMatched to 1 
					// only if 1st part of sec signature is matched.


					
					//Need to Handle Signature Count
					if (m_lTotalSigsAdded > 0 && m_pSigPartMgrLst != nullptr)
					{
						

						for (unsigned long kCnt = 0; kCnt < (m_lTotalSigsAdded-1);kCnt++)
						{
							

							if (((*m_pSigPartMgrLst[kCnt]) / MAX_SIG_PARTS) == iNewID)
							{
								

								iDummy = (*m_pSigPartMgrLst[kCnt]) % 100;
								objVirFList[0].m_TotalParts = iDummy;

								

								break;
							}

							
						}

						

						if (_tcsstr(objVirFList[0].szPartMatched,szDummy)== nullptr)
						{
							if (objVirFList[0].m_TotalParts >= iPart)
							{
								objVirFList[0].m_PartMatched++;
								
								_tcscat_s(objVirFList[0].szPartMatched,szDummy);
							}
						}

						

						if ((objVirFList[0].m_PartMatched == objVirFList[0].m_TotalParts) && (objVirFList[0].m_TotalParts > 0x00))
						{
							
							bVirFound = true;
							break;
						}
					}
					iVirusCnt++;

					
				}
				else
				{
					

					for (jCnt = 0;jCnt<iVirusCnt;jCnt++)
					{
						if (objVirFList[jCnt].m_SigID > 0)
						{
							if (iNewID == objVirFList[jCnt].m_SigID)
							{
								
								if (_tcsstr(objVirFList[jCnt].szPartMatched,szDummy)== nullptr)
								{
									if (objVirFList[jCnt].m_TotalParts >= iPart)
									{
										objVirFList[jCnt].m_PartMatched++;
										
										_tcscat_s(objVirFList[jCnt].szPartMatched,szDummy);
									}
								}

								
								// End
								if ((objVirFList[jCnt].m_PartMatched == objVirFList[jCnt].m_TotalParts) && (objVirFList[jCnt].m_TotalParts > 0x00))
								{
									
									bVirFound = true;
								}
								break;
							}
						}
					}

					

					if (jCnt == iVirusCnt)
					{
						
						objVirFList[iVirusCnt].m_SigID = iNewID;

						if (m_lTotalSigsAdded > 0 && m_pSigPartMgrLst != nullptr)
						{
							

							for (unsigned long kCnt = 0; kCnt < (m_lTotalSigsAdded-1);kCnt++)
							{
								
								if (m_pSigPartMgrLst[kCnt] == nullptr)
								{
									continue;
								}
								int	iDummySigID = *(m_pSigPartMgrLst[kCnt]);

							
								if ((iDummySigID / MAX_SIG_PARTS) == iNewID)
								{
									
									iDummy = iDummySigID % MAX_SIG_PARTS;
									objVirFList[iVirusCnt].m_TotalParts = iDummy;
									break;
								}
								
							}

							
							if (_tcsstr(objVirFList[iVirusCnt].szPartMatched,szDummy)== nullptr)
							{
								if (objVirFList[iVirusCnt].m_TotalParts >= iPart)
								{
									objVirFList[iVirusCnt].m_PartMatched++;
								
									_tcscat_s(objVirFList[iVirusCnt].szPartMatched,szDummy);
								}
							}

							

							if ((objVirFList[iVirusCnt].m_PartMatched == objVirFList[iVirusCnt].m_TotalParts) && (objVirFList[iVirusCnt].m_TotalParts > 0x00))
							{
								
								bVirFound = true;
								break;
							}
						}
						
						iVirusCnt++;
					}
				
				}
				if (bVirFound == true)
					break;
			}
			if (bVirFound == true)
				break;

			

			iCurBufPos = iCurBufPos + iMatchPos + 1;
			
			iFinalLinkID = 0;
		
			pDummy = (unsigned char *)m_pVirtualBuffer;
			pDummy+=iCurBufPos;
			if (pNextStartVect == nullptr)
				pNextStartVect = &m_TreeRoot;

			

			iMatchPos = ScanBuffEx(pDummy,dwBytesRead - iCurBufPos,pNextStartVect,iFinalLinkID,&pNextStartVect);

		

			//10 Aug 2011 : DOS Changes
			if (iMatchPos < 0)//DOS Changes to be Made -- Final
				break;
			if (iFinalLinkID <= 0)
				break;
		}

		if (bVirFound == true)
		{
			break;
		}	
		if (dwBytes2Read == 0x00 || dwTotalBytesRead >= iBuffSize)
		{
			break;
		}
	}
	if (bVirFound == true)
	{
		iDummy = iCurSigID / MAX_SIG_PARTS;
		return iDummy;
	}
	return -1;
}

/******************************************************************************
Function Name	:	AddYARAPERules
Author			:	Tushar Kadam
Scope			:	Public
Input			:	unsigned char * ==>Raw Buffer To Scan
				    unsigned int	==>Buffer Length
Output			:   < 0 if no Virus Found Else Virus ID
*******************************************************************************/
bool CTreeManager::AddYARAPERules(TCHAR * pszSig, DWORD dwSigID)
{
	bool	bRetValue = false;
	TCHAR	szSig[MAX_SZ_LEN] = { 0x00 };
	TCHAR*	pTemp = nullptr;
	BOOL	bIsStarBased = true;

	_stprintf_s(szSig,pszSig);
	
	pTemp = _tcsrchr(szSig,L']');
	if (pTemp == nullptr)
	{
		return false;
	}

	if (_tcsstr(szSig,L"*") == nullptr)
	{
		bIsStarBased = false;
	}
	
	pTemp++;
	*pTemp = '\0';
	pTemp = nullptr;

	if (m_dwYaraPEListCnt == 0)
	{
		
		m_pYaraPEList = (MAX_YARA_PE_RULE_LIST **)Allocate_Memory(sizeof(MAX_YARA_PE_RULE_LIST *));
		m_pYaraPEList[0] = (MAX_YARA_PE_RULE_LIST*)Allocate_Memory(sizeof(MAX_YARA_PE_RULE_LIST));

		if (bIsStarBased == false)
		{
			m_pYaraPEList[0]->bOnlyRule = TRUE;
			m_pYaraPEList[0]->dwSigID = 0x00;
		}
		else
		{
			m_pYaraPEList[0]->dwSigID = dwSigID;
		}

		_tcscpy_s(m_pYaraPEList[0]->szRules,szSig); 
		
		m_dwYaraPEListCnt++;
	}
	else
	{
		if (m_dwYaraPEListCnt > 0)
		{
			m_pYaraPEList = (MAX_YARA_PE_RULE_LIST **)realloc(m_pYaraPEList,((m_dwYaraPEListCnt + 1)*sizeof(MAX_YARA_PE_RULE_LIST *)));
			
			m_pYaraPEList[m_dwYaraPEListCnt] = (MAX_YARA_PE_RULE_LIST*)Allocate_Memory(sizeof(MAX_YARA_PE_RULE_LIST));

			if (bIsStarBased == false)
			{
				m_pYaraPEList[m_dwYaraPEListCnt]->bOnlyRule = TRUE;
				m_pYaraPEList[m_dwYaraPEListCnt]->dwSigID = 0x00;
			}
			else
			{
				m_pYaraPEList[m_dwYaraPEListCnt]->dwSigID = dwSigID;
			}

			_tcscpy_s(m_pYaraPEList[m_dwYaraPEListCnt]->szRules,szSig); 

			m_dwYaraPEListCnt++;
		}
	}

	return bRetValue;
}

bool CTreeManager::AllocateVirtualBuffer()
{
	bool	bSuccess = false;
	
	m_pVirtualBuffer = VirtualAlloc(nullptr,BUFFER_GRANUALITY,MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (m_pVirtualBuffer != nullptr)
	{
		return true;
	}
	
	DWORD	dwError = GetLastError();

	return bSuccess;
}