#include "pch.h"
#include "MaxCertScan.h"

CMaxCertScan::CMaxCertScan(void)
{
	m_pbyBuffer = NULL;
	m_csRegExpName = NULL;
	m_bInitialized = false;
	/*m_szAppDataPath = NULL;	
	m_szLocalAppDataPath = NULL;*/	
}

CMaxCertScan::~CMaxCertScan(void)
{

	if (m_pbyBuffer != NULL)
	{
		delete []m_pbyBuffer;
	}
	m_pbyBuffer = NULL;

	if(m_csRegExpName != NULL)
	{
		for(int iIndex = 0; iIndex < m_nRegExpCount; iIndex++)
		{
			delete m_csRegExpName[iIndex];
			m_csRegExpName[iIndex] = NULL;
		}
		delete m_csRegExpName;
	}
	m_csRegExpName = NULL;
	
	/*if(m_szAppDataPath != NULL)
	{
		delete m_szAppDataPath;
	}
	m_szAppDataPath = NULL;

	if(m_szLocalAppDataPath != NULL)
	{
		delete m_szLocalAppDataPath;
	}
	m_szLocalAppDataPath = NULL;*/

}


bool CMaxCertScan::CheckKnownPublisher(LPCTSTR	pszFilePath)
{
	//return CheckKnownFileName(pszFilePath);
	if(!m_bInitialized)
		return false;

	bool			bReturn = false;
	CMaxPEFile		objFile2Check;
	DWORD			dwCertRVA = 0x00, dwCertFileOffSet = 0x00, dwCertSize = 0x00;
	DWORD			dwBytesRead = 0x00;

	if (pszFilePath == NULL)
	{
		return bReturn;
	}

	if (objFile2Check.OpenFile(pszFilePath,false))
	{
		if (objFile2Check.m_bPEFile != true)
		{
			objFile2Check.CloseFile();
			return bReturn;
		}

		dwCertRVA  = objFile2Check.m_stPEHeader.DataDirectory[0x04].VirtualAddress;
		dwCertSize  = objFile2Check.m_stPEHeader.DataDirectory[0x04].Size;

		/*if (objFile2Check.Rva2FileOffset(dwCertRVA,&dwCertFileOffSet) == OUT_OF_FILE)
		{
			objFile2Check.CloseFile();
			return bReturn;
		}*/

		if (dwCertSize > 0x2000 || dwCertSize == 0x00 || dwCertRVA == 0x00)
		{
			objFile2Check.CloseFile();
			return bReturn;
		}

		if (m_pbyBuffer != NULL)
		{
			delete []m_pbyBuffer;
			m_pbyBuffer = NULL;
		}
		m_pbyBuffer = new unsigned char[dwCertSize];
		memset(&m_pbyBuffer[0x00],0x00,(sizeof(unsigned char) * dwCertSize)); 

		//objFile2Check.ReadBuffer(&m_pbyBuffer[0x00],dwCertFileOffSet,dwCertSize,dwCertSize,&dwBytesRead);
		objFile2Check.ReadBuffer(&m_pbyBuffer[0x00],dwCertRVA,dwCertSize,dwCertSize,&dwBytesRead);
		objFile2Check.CloseFile();

		CSemiPolyDBScn	polydbObj;
		TCHAR			szVirusName[MAX_PATH] = {0};

		LPCTSTR	szPub1 = (_T("5665726966696564205075626C6973686572*5665726966696564205075626C6973686572"));
		polydbObj.LoadSigDBEx(szPub1, _T("PSW.Publisher.1"), FALSE);

		if(polydbObj.ScanBuffer(&m_pbyBuffer[0x0], dwCertSize, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName) > 0)
			{
				bReturn = true;
			}
		}
		delete []m_pbyBuffer;
		m_pbyBuffer = NULL;

	}
	
	return bReturn;
}

static bool PlaceHolderMatch(const TCHAR* QS,const TCHAR* MS,int QL,int ML,char Placeholder='?')
{
  if (QL!=ML)return false;
  for (int i=0;i<QL;i++)
  {
    if (MS[i]==Placeholder)continue;
    if (MS[i]!=QS[i])return false;
  }
  return true;
}
static bool PlaceHolderMatchIgnoreCase(const TCHAR* QS,const TCHAR* MS,int QL,int ML,char Placeholder='?')
{
  if (QL!=ML)return false;
  for (int i=0;i<QL;i++)
  {
    if (MS[i]==Placeholder)continue;
    if (tolower(MS[i])!=tolower(QS[i]))return false;
  }
  return true;
}
bool wildcardMatch(const TCHAR* QueryStr, const TCHAR* MatchStr,bool IgnoreCase=false,char Wildcard='*',char Placeholder='?')
{
	bool (*const MatchFunction)(const TCHAR* QS,const TCHAR* MS,int QL,int ML,char Placeholder)=IgnoreCase ? PlaceHolderMatchIgnoreCase : PlaceHolderMatch;

  
  const int QL= _tcslen(QueryStr),ML= _tcslen(MatchStr);

	if(ML > QL)
		return false;

  const TCHAR* QS= QueryStr,*MS= MatchStr;
  if (ML==0)return QL==0;
  int QP=0;
  for (int i=0;i<ML;i++)
  {
    if (MS[i]==Placeholder)
    {
      QP++;
      continue;
    }
    if (MS[i]==Wildcard)
    {
      int WCTS=i+1;
      while (WCTS<ML && MS[WCTS]==Wildcard)WCTS++;
      if (WCTS>=ML)break;
      int WCTE=WCTS+1;
      while (WCTE<ML && MS[WCTE]!=Wildcard)WCTE++;
      int LL=WCTE-WCTS;
      if (WCTE>=ML)return MatchFunction(QS+QL-LL,MS+WCTS,(QL-QP>=LL) ? LL : (QL-QP),LL,Placeholder);
      int CLim=QL-LL-QP;
      bool Match=false;
      for (int j=0;j<=CLim;j++)
      {
        if (MatchFunction(QS+j+QP,MS+WCTS,LL,LL,Placeholder))
        {
          QP+=j+LL;
          Match=true;
          break;
        }
      }
      if (!Match)return false;
      i=WCTE-1;
      continue;
    }
    if (MS[i]!=QS[QP])return false;
    QP++;
  }
  if (QP<QL && MS[ML-1]!=Wildcard)return false;
  return true;
}

void CMaxCertScan::FilterINI(LPCTSTR pszFolderPath)
{

	if(m_csRegExpName != NULL || m_nRegExpCount > 0)
		return;

	if(GetFileAttributes(pszFolderPath) == INVALID_FILE_ATTRIBUTES)
	{
		return;
	}

	m_nRegExpCount = 0x00;
	WCHAR szRegExpCount[MAX_PATH] = {0x00};

	GetPrivateProfileString(L"Regular_Expressions", L"Count", L"0", (LPWSTR)szRegExpCount, MAX_PATH, pszFolderPath);
	m_nRegExpCount = _wtoi(szRegExpCount);
	if (m_nRegExpCount <= 0x00 || m_nRegExpCount > 0x65)
	{
		return;
	}
	m_csRegExpName = (WCHAR **)malloc(m_nRegExpCount * sizeof(WCHAR *));

	for(int nCount = 1; nCount <= m_nRegExpCount; nCount++ )
	{
		_tcscpy(szRegExpCount, L"");
		wsprintf(szRegExpCount, L"%d", nCount);
		
		if (GetPrivateProfileString(L"Regular_Expressions", (LPWSTR)szRegExpCount, L"0", (LPWSTR)szRegExpCount, MAX_PATH, pszFolderPath))
		{
			m_csRegExpName[nCount - 1] = (WCHAR *)malloc(MAX_PATH * sizeof(WCHAR));
			_tcscpy(m_csRegExpName[nCount - 1], szRegExpCount);
		}
		//memset(&szRegExpCount,0,MAX_PATH);
	}
	m_bInitialized = true;
}

bool CMaxCertScan::CheckKnownFileName(LPCTSTR	pszFilePath)
{

	//return false;

	if(!m_bInitialized || pszFilePath == NULL)
	{
		return false;
	}
	
	if (m_nRegExpCount <= 0x00 || m_csRegExpName == NULL)
	{
		return false;
	}

	for(int iPos = 0; iPos < m_nRegExpCount; iPos++)
	{
		if (m_csRegExpName[iPos] != NULL)
		{
			if(wildcardMatch(pszFilePath, m_csRegExpName[iPos], true))
			{
				return true;
			}
		}
	}
	return false;
}