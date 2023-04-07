#include "SemiPolyDBScn.h"

CSemiPolyDBScn::CSemiPolyDBScn(void)
{
}

CSemiPolyDBScn::~CSemiPolyDBScn(void)
{
	m_SemiPolyDBScan.UnLoadSignatureDB();
}

/******************************************************************************
Function Name	:	LoadSigDBEx
Author			:	Tushar
Scope			:	Public
Input			:	LPCTSTR ==> Signature to Add
				    LPCTSTR	==> Virus Name
				:	BOOL ==> FALSE if Last Sig to Add else TRUE
Output			:   > 1 if Signature added successfully.
*******************************************************************************/
int	CSemiPolyDBScn::LoadSigDBEx(LPCTSTR pszSig2Add, LPCTSTR pszVirusName, BOOL bMoreSigs)
{
	int		iRet = 0x00;

	iRet = m_SemiPolyDBScan.LoadSigDBEx(pszSig2Add,pszVirusName,bMoreSigs);

	return iRet;
}

/******************************************************************************
Function Name	:	ScanBuffer
Author			:	Tushar
Scope			:	Public
Input			:	unsigned char * ==>Raw Buffer To Scan
				    unsigned int	==>Buffer Length
				:	unsigned char * ==> (Ref) Output Virus Name
Output			:   < 0 if NO Virus Found Else Virus ID
*******************************************************************************/
int CSemiPolyDBScn::ScanBuffer(unsigned char * szBuffer,unsigned int iBuffLen, LPTSTR szVirusName)
{
	//USES_CONVERSION;
	int		iRet = 0x00;
	char	strVirName[MAX_PATH] = {0};

	iRet = m_SemiPolyDBScan.ScanBuffer4Virus(szBuffer,iBuffLen,strVirName);
	//_tcprintf_s(szVirusName,L"%s",A2W(strVirName));
	MultiByteToWideChar(CP_UTF8, 0, strVirName, _countof(strVirName), szVirusName, MAX_PATH);

	return iRet;
}