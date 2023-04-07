#include "pch.h"
#include "MaxMLHeurWrapp.h"
#include "MaxDigitalSigCheck.h"
#include "MaxSHA.h"
#include "FileSig.h"
#include <atlbase.h>
#include <atlconv.h>
#include <atltime.h>

using namespace std;
using namespace cv;

#ifndef _free
#define _free(p) {if(p != NULL){ free(p); p = NULL;}}
#endif


bool GetMD5Signature32(const char *filepath, char *cMD5Signature);
//typedef PIMAGE_THUNK_DATA32             PIMAGE_THUNK_DATA_ML;

CMaxMLHeurWrapp::CMaxMLHeurWrapp(void)
{

	m_pSQLMgr = NULL;
	m_hTrojanTreeLoadingThread = NULL;
	m_hOtherTreeLoadingThread = NULL;
}

CMaxMLHeurWrapp::~CMaxMLHeurWrapp(void)
{
	UnLoadMLXML();
}


class CFileVersionInfo
{
public:	// Construction/destruction:

	CFileVersionInfo(void);
	virtual ~CFileVersionInfo(void);

public:	// Implementation:

	BOOL	Open(IN LPCTSTR lpszFileName);
	//BOOL	Open(IN HINSTANCE hInstance);
	void	Close(void);

	BOOL	QueryStringValue(IN LPCTSTR lpszString, OUT LPTSTR lpszValue, IN INT nBuf)const;
	BOOL	QueryStringValue(IN INT nIndex, OUT LPTSTR lpszValue, IN INT nBuf)const;
	
	bool Is3264BitApp(LPCTSTR szFileName);
	DWORD	GetTransByIndex(IN UINT nIndex)const;

	// To get count for ML scanner
	int GetCountForML();

public: // Static members:

//	static BOOL		GetLIDName(IN WORD wLID, OUT LPTSTR lpszName, IN INT nBuf);
//	static BOOL		GetCPName(IN WORD wCP, OUT LPCTSTR* ppszName);
	//static DWORD	InstallFile(void);

public: // Inline members

	inline LANGID	GetCurLID(void)const;
	inline WORD		GetCurCP(void)const;
	inline LANGID	GetLIDByIndex(IN UINT nIndex)const;
	inline WORD		GetCPByIndex(IN UINT nIndex)const;
	inline UINT		GetCurTransIndex(void)const;

protected:

	BOOL	GetVersionInfo(IN LPCTSTR lpszFileName);
	BOOL	QueryVersionTrans(void);

protected: // Members variables

	static LPCTSTR	 s_ppszStr[ 13];	// String names
	VS_FIXEDFILEINFO m_vsffi;			// Fixed File Info (FFI)

	LPBYTE		m_lpbyVIB;		// Pointer to version info block (VIB)
	LPDWORD		m_lpdwTrans;	// Pointer to translation array in m_lpbyVIB, LOWORD = LangID and HIWORD = CodePage
	UINT		m_nTransCur;	// Current translation index
	UINT		m_nTransCnt;	// Translations count
	BOOL		m_bValid;		// Version info is loaded

protected: //static
	static LPCTSTR	s_lpszFVI[ 7];
	
};

LPCTSTR CFileVersionInfo::s_ppszStr[] = {	_T("Comments"), _T("CompanyName"),
											_T("FileDescription"), _T("FileVersion"),
											_T("InternalName"), _T("LegalCopyright"),
											_T("LegalTrademarks"), _T("OriginalFilename"),
											_T("PrivateBuild"), _T("ProductName"),
											_T("ProductVersion"), _T("SpecialBuild"),
											_T("OLESelfRegister")};

inline LANGID CFileVersionInfo::GetCurLID(void)const
{
	return GetLIDByIndex(GetCurTransIndex());
}

inline WORD CFileVersionInfo::GetCurCP(void)const
{
	return GetCPByIndex(GetCurTransIndex());
}
inline LANGID CFileVersionInfo::GetLIDByIndex(IN UINT nIndex)const
{
	return LOWORD(GetTransByIndex(nIndex));
}

inline UINT CFileVersionInfo::GetCurTransIndex(void)const
{
	return m_nTransCur;
}
inline WORD CFileVersionInfo::GetCPByIndex(IN UINT nIndex)const
{
	return HIWORD(GetTransByIndex(nIndex));
}

CFileVersionInfo::CFileVersionInfo(void) : m_lpbyVIB(NULL)
{
	Close();
}
CFileVersionInfo::~CFileVersionInfo(void)
{
	Close();
}
void CFileVersionInfo::Close(void)
{
	m_nTransCnt  = 0;
	m_nTransCur  = 0;
	m_bValid	 = FALSE;
	m_lpdwTrans  = NULL;

	::ZeroMemory(&m_vsffi, sizeof(VS_FIXEDFILEINFO));
	if(m_lpbyVIB)
	{
		_free(m_lpbyVIB);
	}
}
bool CFileVersionInfo::Is3264BitApp(LPCTSTR szFileName)
{
	HANDLE hFile = 0;
	DWORD dwReadData = 0, dwBytesRead = 0;

	hFile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL, 0);

	if(INVALID_HANDLE_VALUE == hFile)
	{
		return (false);
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, 0x3C, 0, FILE_BEGIN))
	{
		CloseHandle(hFile);
		return (false);
	}

	if(FALSE == ReadFile(hFile, &dwReadData, sizeof(dwReadData), &dwBytesRead, 0))
	{
		CloseHandle(hFile);
		return (false);
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, dwReadData, 0, FILE_BEGIN))
	{
		CloseHandle(hFile);
		return (false);
	}

	if(FALSE == ReadFile(hFile, &dwReadData, sizeof(dwReadData), &dwBytesRead, 0))
	{
		CloseHandle(hFile);
		return (false);
	}

	if(dwReadData != 0x00004550)
	{
		CloseHandle(hFile);
		return (false);
	}

	if(FALSE == ReadFile(hFile, &dwReadData, sizeof(dwReadData), &dwBytesRead, 0))
	{
		CloseHandle(hFile);
		return (false);
	}

	CloseHandle(hFile);
	return ((0x014C == LOWORD(dwReadData)) ||(0x8664 == LOWORD(dwReadData)));
}

DWORD CFileVersionInfo::GetTransByIndex(IN UINT nIndex)const
{
	return m_lpdwTrans[ nIndex];
}
BOOL CFileVersionInfo::Open(IN LPCTSTR lpszFileName)
{
	if(lpszFileName == NULL)
	{
		return FALSE;
	}

	Close();
	if(!GetVersionInfo(lpszFileName) || !QueryVersionTrans())
	{
		Close();
	}

	return m_bValid;
};

BOOL CFileVersionInfo::GetVersionInfo(IN LPCTSTR lpszFileName)
{
	// Version: 1.0.0.1
	if(false == Is3264BitApp(lpszFileName))
	{
		return (FALSE);
	}

	DWORD dwDummy = 0;
	DWORD dwSize  = ::GetFileVersionInfoSize(const_cast< LPTSTR >(lpszFileName),
											&dwDummy // Set to 0
											);

	if(dwSize > 0)
	{
		m_lpbyVIB = (LPBYTE)malloc(dwSize);
		if(m_lpbyVIB != NULL &&
			::GetFileVersionInfo(const_cast< LPTSTR >(lpszFileName),
			0, dwSize, m_lpbyVIB))
		{
			UINT   uLen    = 0;
			LPVOID lpVSFFI = NULL;
			if(::VerQueryValue(m_lpbyVIB, _T("\\"), (LPVOID*)&lpVSFFI, &uLen))
			{
				::CopyMemory(&m_vsffi, lpVSFFI, sizeof(VS_FIXEDFILEINFO));
				m_bValid =(m_vsffi.dwSignature == VS_FFI_SIGNATURE);
			}
		}
	}
	return m_bValid;
}

BOOL CFileVersionInfo::QueryVersionTrans(void)
{
	if(m_bValid == FALSE)
	{
		return (FALSE);
	}

	UINT   uLen  = 0;
	LPVOID lpBuf = NULL;

	if(::VerQueryValue(m_lpbyVIB, _T("\\VarFileInfo\\Translation"), (LPVOID*)&lpBuf, &uLen))
	{
		m_lpdwTrans = (LPDWORD)lpBuf;
		m_nTransCnt =(uLen / sizeof(DWORD));
	}
	return (BOOL)(m_lpdwTrans != NULL);
}

int CFileVersionInfo::GetCountForML()
{
	int iRetCount = 0;
	if(QueryVersionTrans())
	{
		iRetCount++;
	}
	
	for(int i =0; i<13; i++)
	{
		TCHAR szName[MAX_PATH] = {0};
		int ulLen = MAX_PATH;
		if(QueryStringValue(i,szName,ulLen))
		{
			iRetCount++;
		}
	}
	UINT   uLen    = 0;
	LPVOID lpVSFFI = NULL;
	if(::VerQueryValue(m_lpbyVIB, _T("\\"), (LPVOID*)&lpVSFFI, &uLen))
	{
		::CopyMemory(&m_vsffi, lpVSFFI, sizeof(VS_FIXEDFILEINFO));
		if(m_vsffi.dwSignature == VS_FFI_SIGNATURE)
		{
			iRetCount++;
		}
		if(m_vsffi.dwFileFlags >=0)
		{
			iRetCount++;
		}
		if(m_vsffi.dwFileOS >=0)
		{
			iRetCount++;
		}
		if(m_vsffi.dwFileType >=0)
		{
			iRetCount++;
		}
		if(m_vsffi.dwFileVersionLS >=0)
		{
			iRetCount++;
		}
		if(m_vsffi.dwProductVersionLS >=0)
		{
			iRetCount++;
		}
		if(m_vsffi.dwStrucVersion >=0)
		{
			iRetCount++;
		}
	}
	
	return iRetCount;
}



BOOL CFileVersionInfo::QueryStringValue(IN  LPCTSTR lpszItem, OUT LPTSTR  lpszValue, 
										IN  INT     nBuf) const
{
	//strcpy(lpszItem,"CompanyName");
	if(m_bValid  == FALSE || lpszItem == NULL)
	{
		return (FALSE);
	}

	if(lpszValue != NULL && nBuf <= 0)
	{
		return (FALSE);
	}

	::ZeroMemory(lpszValue, nBuf * sizeof(TCHAR));

	TCHAR szSFI[ MAX_PATH]={0 };
	swprintf_s(szSFI, _countof(szSFI), _T("\\StringFileInfo\\%04X%04X\\%s"),
				GetCurLID(), GetCurCP(), lpszItem);

	BOOL   bRes    = FALSE;
	UINT   uLen    = 0;
	LPTSTR lpszBuf = NULL;

	if(::VerQueryValue(m_lpbyVIB, (LPTSTR)szSFI, (LPVOID*)&lpszBuf, &uLen))
	{
		if(lpszValue != NULL && nBuf > 0)
		{
			bRes = (BOOL)(::lstrcpyn(lpszValue, lpszBuf, nBuf) != NULL);
		}
		else
		{
			bRes = TRUE;
		}
	}
	return (bRes);
}


/*-------------------------------------------------------------------------------------
Function       : QueryStringValue
In Parameters  : IN  INT    nIndex,
				 OUT LPTSTR lpszValue,
				 IN  INT    nBuf
Out Parameters : BOOL
Purpose		   : Retrieves a value in a StringTable structure, and returns it in the nBuf size
				lpszValue buffer.The nIndex name must be one of the following predefined constants:
					VI_STR_COMMENTS - Comments
					VI_STR_COMPANYNAME - CompanyName
					VI_STR_FILEDESCRIPTION - FileDescription
					VI_STR_FILEVERSION - FileVersion
					VI_STR_INTERNALNAME - InternalName
					VI_STR_LEGALCOPYRIGHT - LegalCopyright
					VI_STR_LEGALTRADEMARKS - LegalTrademarks
					VI_STR_ORIGINALFILENAME - OriginalFilename
					VI_STR_PRIVATEBUILD - PrivateBuild
					VI_STR_PRODUCTNAME - ProductName
					VI_STR_PRODUCTVERSION - ProductVersion
					VI_STR_SPECIALBUILD - SpecialBuild
					VI_STR_OLESELFREGISTER - OLESelfRegister
For example: m_ver.QueryStringValue(VI_STR_SPECIALBUILD, szBuf, 512);
Author		   :  Anand
-------------------------------------------------------------------------------------*/
BOOL CFileVersionInfo::QueryStringValue(IN INT nIndex, OUT LPTSTR lpszValue, IN INT nBuf) const
{
	/*if(nIndex < VI_STR_COMMENTS || nIndex > VI_STR_OLESELFREGISTER)
	{
		ASSERT_RETURN (FALSE);
	}*/
	return QueryStringValue(s_ppszStr[ nIndex], lpszValue, nBuf);
}


/* ML Database Loading Threads */
DWORD WINAPI TrojanTreeLoadingThread(LPVOID lpParam);
DWORD WINAPI OtherTreeLoadingThread(LPVOID lpParam);

DWORD WINAPI TrojanTreeLoadingThread(LPVOID lpParam)
{
	CMaxMLHeurWrapp* pThis = (CMaxMLHeurWrapp*)lpParam;
	pThis->LoadTrojanJSON(pThis->m_szDBPath);
	return 0x00;
}

DWORD WINAPI OtherTreeLoadingThread(LPVOID lpParam)
{
	CMaxMLHeurWrapp* pThis = (CMaxMLHeurWrapp*)lpParam;
	pThis->LoadOtherJSON(pThis->m_szDBPath);
	return 0x00;
}


bool CMaxMLHeurWrapp::GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT)
{
	bool		bRetValue = FALSE;
	char		szOut[MAX_PATH] = {0x00};		

	if (pszUnicodeIN == NULL || pszAnsiOUT == NULL)
	{
		return bRetValue;
	}

	int iRetLen =  WideCharToMultiByte(CP_ACP,WC_COMPOSITECHECK,pszUnicodeIN,_tcslen(pszUnicodeIN),szOut,MAX_PATH,NULL,NULL);

	if (iRetLen > 0x00)
	{
		strcpy(pszAnsiOUT,szOut);
	}

	return bRetValue;
}

bool CMaxMLHeurWrapp::LoadTrojanJSON(LPCTSTR szDBPath)
{
	//AddLogEntry(szDBPath);
	bool dwRetVal = false;

	m_pMLPredictTree1 = new CvRTrees;
	TCHAR szTree1Path[MAX_PATH] = { 0 };
	_stprintf(szTree1Path, _T("%stree.json"), szDBPath);
	char	strTree1Path[MAX_PATH] = { 0x00 };
	GetAnsiString(szTree1Path, strTree1Path);

	m_pMLPredictTree1->load(strTree1Path);
	if (m_pMLPredictTree1->get_tree_count() > 0)
	{
		dwRetVal = true;
	}
	
	//AddLogEntry(szTree1Path);
	return dwRetVal;
}
bool CMaxMLHeurWrapp::LoadOtherJSON(LPCTSTR szDBPath)
{
	//AddLogEntry(szDBPath);
	bool dwRetVal = false;

	m_pMLPredictTree2 = new CvRTrees;
	TCHAR szTree2Path[MAX_PATH] = { 0 };
	_stprintf(szTree2Path, _T("%sOTHER.json"), szDBPath);
	char	strTree2Path[MAX_PATH] = { 0x00 };
	GetAnsiString(szTree2Path, strTree2Path);

	m_pMLPredictTree2->load(strTree2Path);
	if (m_pMLPredictTree2->get_tree_count() > 0)
	{
		dwRetVal = true;
	}

	//AddLogEntry(szTree2Path);
	return dwRetVal;
}


bool CMaxMLHeurWrapp::LoadMLXML(LPCTSTR szDBPath)
{
	bool dwRetVal = false;

	_tcscpy(m_szDBPath, szDBPath);

	/*
	DWORD	dwTrojanThreadID = 0x00;
	DWORD	dwOtherThreadID = 0x00;

	m_hTrojanTreeLoadingThread = NULL;
	m_hOtherTreeLoadingThread = NULL;
	
	m_hTrojanTreeLoadingThread = CreateThread(NULL, 0, TrojanTreeLoadingThread, (LPVOID)this, 0, &dwTrojanThreadID);

	if (m_hTrojanTreeLoadingThread != NULL)
	{
		dwRetVal = true;
	}

	m_hOtherTreeLoadingThread = CreateThread(NULL, 0, OtherTreeLoadingThread, (LPVOID)this, 0, &dwOtherThreadID);

	if (m_hOtherTreeLoadingThread != NULL)
	{
		dwRetVal = true;
	}
	*/

	
	m_pMLPredictTree1 = new CvRTrees;
	m_pMLPredictTree2 = new CvRTrees;


	TCHAR szTree1Path[MAX_PATH] = {0};
	_stprintf(szTree1Path, _T("%stree.json"),szDBPath);
	char	strTree1Path[MAX_PATH] = {0x00};	
	GetAnsiString(szTree1Path,strTree1Path);

	TCHAR szTree2Path[MAX_PATH] = {0};
	_stprintf(szTree2Path, _T("%sOTHER.json"),szDBPath);
	char	strTree2Path[MAX_PATH] = {0x00};	
	GetAnsiString(szTree2Path,strTree2Path);
	

	m_pMLPredictTree1->load(strTree1Path);
	if(m_pMLPredictTree1->get_tree_count()>0)
	{
		dwRetVal = true;
	}

	m_pMLPredictTree2->load(strTree2Path);
	if(m_pMLPredictTree2->get_tree_count()>0)
	{
		dwRetVal = true;
	}
	

	/*
	TCHAR szSQLiteDB[MAX_PATH] = {0};
	_stprintf(szSQLiteDB, _T("%sThreatIntelligence.db"),szDBPath);

	m_pSQLMgr = NULL;
	m_pSQLMgr = new CMaxSqliteMgr(szSQLiteDB);
	*/

	return dwRetVal;
}
bool CMaxMLHeurWrapp::UnLoadMLXML()
{
	bool dwRetVal = false;
	m_pMLPredictTree1->~CvRTrees();
	m_pMLPredictTree2->~CvRTrees();
	return true;
}

/*******************************************************************************************
Discription: To predict the detection
*******************************************************************************************/
float CMaxMLHeurWrapp::PredictNature(float fValues[])
{
	float result = 8;
	Mat testing_data = Mat(1, 28, CV_32FC1);

	int i=0;
	for(i=0;i<28;i++)
	{
		testing_data.at<float>(0,i) =	fValues[i];
	}
	result = m_pMLPredictTree1->predict_prob(testing_data, Mat());

	if(!fValues)
		delete []fValues;

	return result;
}

float CMaxMLHeurWrapp::PredictNatureEX(float fValues[])
{
	float result = 8;
	Mat testing_data = Mat(1, 28, CV_32FC1);

	int i=0;
	for(i=0;i<28;i++)
	{
		testing_data.at<float>(0,i) =	fValues[i];
	}
	result = m_pMLPredictTree2->predict_prob(testing_data, Mat());


	if(!fValues)
		delete []fValues;

	return result;
}
bool CMaxMLHeurWrapp::FileGetInfo(CMaxPEFile *pMaxPEFile)
{
	bool dwRetVal = false; 
	m_pMaxPEFile = pMaxPEFile;
	m_pSectionHeader = &m_pMaxPEFile->m_stSectionHeader[0];
	m_wNoOfSections = m_pMaxPEFile->m_stPEHeader.NumberOfSections;	
	return true;
} 

bool CMaxMLHeurWrapp::ScanFileEx(CMaxPEFile *pMaxPEFile)
{
	bool				dwRetVal = false;
	CMaxDigitalSigCheck objMaxDigiSign;
	bool				bFound = false;
	TCHAR				szExtenssionsToSkip[] = {L".cpl.drv.mui.ocx.scr.sys.tmp.sfx.mup.pyd"};

	if (pMaxPEFile == NULL)
	{
		return dwRetVal;
	}

	if (pMaxPEFile->m_bPEFile == false)
	{
		return dwRetVal;	
	}

	TCHAR	*pszExt = NULL;
	pszExt = (TCHAR *)_tcsrchr(pMaxPEFile->m_szFilePath,_T('.'));
	if (pszExt != NULL)
	{
		if (_tcslen(pszExt) <= 0x10)
		{
			TCHAR	szExt[0x20] = {0x00};
			_tcscpy(szExt,pszExt);
			_tcslwr(szExt);
			if (_tcsstr(szExtenssionsToSkip,szExt) != NULL)
			{
				return dwRetVal;
			}
		}
	}

	
	//bFound= objMaxDigiSign.CheckDigitalSign(pMaxPEFile->m_szFilePath);
	//if (bFound == false)
	//{	 
		//CMaxPEFile objMaxPEFile;
		//if(objMaxPEFile.OpenFile(szFilePath, false, false))
		{
			FileGetInfo(pMaxPEFile);
			dwRetVal = FeatureCalculations();
		}

		if(dwRetVal == true)
		{
			bFound= objMaxDigiSign.CheckDigitalSign(pMaxPEFile->m_szFilePath);
			if(bFound == true)
			{
				dwRetVal = false;
				
			}
			
		}
	//}

	return dwRetVal;
}

bool CMaxMLHeurWrapp::ScanFile(LPCTSTR szFilePath)
{
	bool				dwRetVal = false;
	CMaxDigitalSigCheck objMaxDigiSign;
	bool				bFound = false;
	TCHAR				szExtenssionsToSkip[] = {L".cpl.drv.mui.ocx.scr.sys.tmp.sfx.mup.pyd"};

	if (szFilePath == NULL)
	{
		return dwRetVal;
	}

	TCHAR	*pszExt = NULL;
	pszExt = (TCHAR *)_tcsrchr(szFilePath,_T('.'));
	if (pszExt != NULL)
	{
		if (_tcslen(pszExt) <= 0x10)
		{
			TCHAR	szExt[0x20] = {0x00};
			_tcscpy(szExt,pszExt);
			_tcslwr(szExt);
			if (_tcsstr(szExtenssionsToSkip,szExt) != NULL)
			{
				return dwRetVal;
			}
		}
	}

	//bFound= objMaxDigiSign.CheckDigitalSign(szFilePath);
	//if (bFound == false)
	//{	
		CMaxPEFile objMaxPEFile;
		if(objMaxPEFile.OpenFile(szFilePath, false, false))
		{
			FileGetInfo(&objMaxPEFile);
			dwRetVal = FeatureCalculations();
			objMaxPEFile.CloseFile();
		}	
	//}

		if(dwRetVal == true)
		{
			bFound= objMaxDigiSign.CheckDigitalSign(szFilePath);
			if(bFound == true)
			{
				dwRetVal = false;
				
			}
			
		}

	return dwRetVal;
}
bool CMaxMLHeurWrapp::FeatureCalculations()
{
	bool dwRetVal = false;
	if (m_pMaxPEFile->m_mlFeatureData.m_bAllFeaturesGenerated != true)
	{

		//Initializing Features
		m_dSectionMeanEntropy = 0.0;
		m_dSectionMaxEntropy = 0;		//As Entropy ranges from 0 to 8 only
		m_dSectionMinEntropy = 0;

		m_dResourceMaxEntropy = 0.0;
		m_dResourceMinEntropy = 0.0;
		m_dResourceMeanEntropy = 0.0;

		m_dResourceTotalEntropy = 0.0;
		m_dwTotalNoOfResources = 0;

		m_dwResourceMaxSize = 0;
		m_dResourceMeanSize = 0;
		m_dwResourceMinSize = 0;
		m_dwResourceTotalSize = 0;

		m_dwImportsNbDLL = 0;
		m_dwImportsNb = 0;

		m_dSectionMeanRawSize = 0;
		m_dwSectionMinRawSize = 0;

		m_dSectionMeanVirtualSize = 0;
		m_dwSectionMaxVirtualSize = 0;
		m_dwIsPackFile = 0;

		DWORD dwFileSize = m_pMaxPEFile->m_dwFileSize;

		//Checking For Invalid Sections .....Can be Optimized
		bool hasInvalidSections = false;
		if (m_wNoOfSections >= 0 && (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
		{
			if (m_wNoOfSections == 0 && (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
			{
				hasInvalidSections = true;

			}
			for (DWORD i = 0; i < m_wNoOfSections; i++)
			{
				if (m_pSectionHeader[i].PointerToRawData >= dwFileSize && m_pSectionHeader[i].SizeOfRawData != 0)
				{
					hasInvalidSections = true;
				}

			}
		}
		//*******************************

		if (hasInvalidSections == true)
			return dwRetVal;

		//DWORD dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData;
		DWORD dwOverlaySize = m_pMaxPEFile->m_dwFileSize - (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData);


		if (dwOverlaySize >
			(2 * (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData
				+ m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData)))
		{
			if (m_pMaxPEFile->m_stPEHeader.DataDirectory[0x04].Size != 0x00)
			{
				return dwRetVal;
			}
		}


		//IsPacker();
		GetEntropy();
		GetResourceEntropyEx();
		GetNoOfImportsEx();
		GetSecMinMeanRSize();
		GetSecMaxMeanVSize();
		//Freeing the buffers used
		if (m_pbyBuff)
		{
			delete[]m_pbyBuff;
			m_pbyBuff = NULL;
		}
	}
	dwRetVal = ExportFeaturesToPredictor();
	return dwRetVal;
}

/******************************************************************************
Function Name	:	IsPacker
Author			:	Swapnil Sanghai	
Description		:	Check is packed 
*******************************************************************************/
void CMaxMLHeurWrapp::IsPacker()
{
	DWORD dwSRD = m_pSectionHeader[0].SizeOfRawData;
	DWORD dwVirtualSize = m_pSectionHeader[0].Misc.VirtualSize;

	if(dwSRD == 0x00 && (dwVirtualSize-dwSRD) > 0x3000)
	{
		m_dwIsPackFile = 10;
	}
	else
	{
		m_dwIsPackFile = 5;
	}
}


//Added For ML **************************************************
/******************************************************************************
Function Name	:	Calculate_Entropy
Author			:	Harshvardhan Patel	
Description		:	Calculates Section Entropy
					Overloaded with : 
					double Calculate_Entropy(const DWORD, std::streamoff)
*******************************************************************************/
bool CMaxMLHeurWrapp::GetEntropy()
{
	//Variable Initialization
	DWORD dwTempPRD = 0; //Temporary PointerToRawData;
	DWORD dwSizeRD = 0;
	DWORD dwBytesCount[256] = {0};
	WORD wSec = 0x00;
	DWORD NoOfBytesToRead = 0;
	m_dSectionMeanEntropy = 0.0;
	m_dSectionMaxEntropy = 0;		//As Entropy ranges from 0 to 8 only
	m_dSectionMinEntropy = 10.0;		
	double dummy = 0.0;
	double TotalEntropy = 0.0;
	
	int checkOverlayCount = 0;
	if(!m_wNoOfSections)
	{
		m_dSectionMinEntropy = 0;		//Skipping Entropy Calculation Altogether
		return false;
	}

	for ( wSec = 0x00; wSec < m_wNoOfSections; wSec++)
	{
		for(int ii = 0; ii < 256; ii++)
		{
			dwBytesCount[ii] = 0;
		}
		if(m_pSectionHeader[wSec].Misc.VirtualSize != 0x00)
		{
			dwTempPRD = m_pSectionHeader[wSec].PointerToRawData;
			dwSizeRD = m_pSectionHeader[wSec].SizeOfRawData;
			if(!dwTempPRD || !dwSizeRD)
			{
				m_dSectionMinEntropy = 0.0;
				continue;
			}
	
			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}
			m_pbyBuff = new BYTE[dwSizeRD];
			if(!m_pbyBuff)
			{
				m_dSectionMinEntropy = 0;
				continue;	//Skipping Section
			}

			NoOfBytesToRead = (dwSizeRD); 
			if(GetBuffer(dwTempPRD, NoOfBytesToRead, NoOfBytesToRead))
			{
				DWORD iter = 0;
				for(iter = 0; iter < NoOfBytesToRead; ++iter)
				{	
					++dwBytesCount[static_cast<unsigned char>(m_pbyBuff[iter])];
				}
			}
			else
			{
				m_dSectionMinEntropy = 0.0;
				if(m_pbyBuff != NULL)
				{
					delete []m_pbyBuff;
					m_pbyBuff = NULL;
				}
				continue;
			}
		}
		else
		{
			return false;
		}

		std::streamoff total_length = static_cast<std::streamoff>(NoOfBytesToRead);
		dummy = GetEntropy(dwBytesCount, total_length);
		TotalEntropy += dummy;
		if(dummy > m_dSectionMaxEntropy)
			m_dSectionMaxEntropy = dummy;
		if(dummy < m_dSectionMinEntropy)
			m_dSectionMinEntropy = dummy;
	}
	
	m_dSectionMeanEntropy = (TotalEntropy)/(static_cast<double>(m_wNoOfSections));
	
	if(m_pbyBuff)
	{

		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	
	return true;
}
/******************************************************************************
Function Name	:	Calculate_Entropy
Author			:	Harshvardhan Patel
Output			:   double
Description		:	Performs Raw Calculation for Entropy
*******************************************************************************/ 
double CMaxMLHeurWrapp::GetEntropy(const DWORD bytes_count[256], std::streamoff total_length)
{
	double entropy = 0.0;

	for(DWORD i = 0; i < 256; i++)
	{
		double temp = 0;
		if(total_length)
			temp = static_cast<double>(bytes_count[i]) / total_length;
		if(temp > 0.)
			entropy -= temp * (log(temp)/log(2.0)); 
	}
	
	return entropy;
}
/******************************************************************************
Function Name	:	ParseResourceTree
Author			:	Harshvardhan Patel
Output			:   void
Description		:	Traverses the Resource Tree. Does The following calculations:
					1. Resource Min/Max Entropy
					2. Resource Min/Max Size
*******************************************************************************/ 
void CMaxMLHeurWrapp::ParseResourceTree(PIMAGE_RESOURCE_DIRECTORY pResDir)
{
	//AddLogEntry(L"Inside Parse Resource Tree:");
	WORD iter = 0x00;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResEntry = 
							reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>
							(reinterpret_cast<DWORD>(pResDir)
								+ sizeof(IMAGE_RESOURCE_DIRECTORY));
	if(!pResDir || !pResEntry )
	{
		m_dwResourceMinSize = 99;
		m_dResourceMeanEntropy = 0.0;
		return;
	}
	
	for(iter = 0x00; iter < (pResDir->NumberOfIdEntries + pResDir->NumberOfNamedEntries)
					; ++iter)
	{
		if(pResEntry->DataIsDirectory)
		{
			//Resource is a Directory
			if(!pResEntry->OffsetToDirectory)
			{
				//If Offset is 0, skip this resource
				pResEntry++;
				continue;
			}
			PIMAGE_RESOURCE_DIRECTORY pTemp = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>
									(pResEntry->OffsetToDirectory + 
									reinterpret_cast<DWORD>(m_pResDir));
			ParseResourceTree(pTemp);
		}
		else
		{
			
			//We have reached the resource
			pResEntry = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(pResEntry);
	
			if(!pResEntry->OffsetToData)
			{
				pResEntry++;
				continue;
			}

			PIMAGE_RESOURCE_DATA_ENTRY pResData = reinterpret_cast<PIMAGE_RESOURCE_DATA_ENTRY>
													(pResEntry->OffsetToData
													+ reinterpret_cast<DWORD>(m_pResDir));
			DWORD dwSizeRD = 0;
			dwSizeRD = pResData->Size;
			if(!dwSizeRD)
			{
				//AddLogEntry(L"Potentially Corrupted Resource..Skipping Resource");
				m_dwResourceMinSize = 0;
				m_dResourceMinEntropy = 0.0;
				pResEntry++;
				continue;
			}

			m_dwResourceTotalSize += dwSizeRD;

			if(dwSizeRD > m_dwResourceMaxSize)
				m_dwResourceMaxSize = dwSizeRD;
			if(dwSizeRD < m_dwResourceMinSize)
				m_dwResourceMinSize = dwSizeRD;
			
			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}
			m_pbyBuff = new BYTE[dwSizeRD];
			if(!m_pbyBuff)
			{
				//AddLogEntry(L"m_pbyBuff Alloc Error: In Parse Resource Tree..Skipping Resource");
				m_dResourceMinEntropy = 0.0;
				m_dwResourceMinSize = 0;
				pResEntry++;
				continue;
			}
			
			DWORD dwRVA2Data = pResData->OffsetToData;
			DWORD dwFileOffset = 0;
			DWORD dummy = m_pMaxPEFile->Rva2FileOffset(dwRVA2Data, &dwFileOffset);

			DWORD dwBytesCount[256] = {0};
			if(GetBuffer(dwFileOffset, dwSizeRD, dwSizeRD))
			{
				DWORD iter = 0;
				for(iter = 0; iter < dwSizeRD; ++iter)
				{	
					++dwBytesCount[static_cast<unsigned char>(m_pbyBuff[iter])];
				}
			}
			else
			{
				//AddLogEntry(L"GetBuffer Error in Parse Resource..Skipping Resource");

				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff = NULL;
				}
				pResEntry++;
				continue;
				//Throw Appropriate exception
			}
			
			std::streamoff total_length = static_cast<std::streamoff>(dwSizeRD);
			double dTempHolder = GetEntropy(dwBytesCount,dwSizeRD);
			
			if(dTempHolder > m_dResourceMaxEntropy)
				m_dResourceMaxEntropy = dTempHolder;
			if(dTempHolder < m_dResourceMinEntropy)
				m_dResourceMinEntropy = dTempHolder;
				
			m_dResourceTotalEntropy += dTempHolder;
			
			if(!m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}

			m_dwTotalNoOfResources++;
		}
		pResEntry++;
	}
}

bool CMaxMLHeurWrapp::ParseResourceTreeEx(PIMAGE_RESOURCE_DIRECTORY pResDir, DWORD dwResourceDirectory, DWORD dwOffset)
{

	DWORD	dwTotalRsrcEntry = pResDir->NumberOfIdEntries + pResDir->NumberOfNamedEntries;
	if(dwTotalRsrcEntry>0x50 || dwTotalRsrcEntry<=0)
	{
		m_dResourceMinEntropy = 0.0;
		m_dwResourceMinSize = 0;
		return false;
	}
	if(pResDir == NULL)
	{
		m_dResourceMinEntropy = 0.0;
		m_dwResourceMinSize = 0;
		return false;
	}
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pRsrc_Dir_Entry = new IMAGE_RESOURCE_DIRECTORY_ENTRY[dwTotalRsrcEntry];
	if(pRsrc_Dir_Entry == NULL)
	{
		m_dResourceMinEntropy = 0.0;
		m_dwResourceMinSize = 0;
		return false;
	}
	memset(pRsrc_Dir_Entry, 0x00, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)* dwTotalRsrcEntry);
	
	
	DWORD	dwReadOffset = dwOffset + sizeof(IMAGE_RESOURCE_DIRECTORY);
	if(!m_pMaxPEFile->ReadBuffer(pRsrc_Dir_Entry, dwReadOffset, (sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)*dwTotalRsrcEntry), (sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)*dwTotalRsrcEntry)))
	{
		delete []pRsrc_Dir_Entry;
		pRsrc_Dir_Entry = NULL;
		m_dResourceMinEntropy = 0.0;
		m_dwResourceMinSize = 0;
		return false;
	}

	DWORD dwIndex = 0x00;
	for(dwIndex = 0x00; dwIndex < dwTotalRsrcEntry; dwIndex++)
	{	
		m_dwCurruptResCounter++;

		if (m_dwCurruptResCounter == 0x1F4)
		{
			if (m_dwTotalNoOfResources == 0x00)
			{
				m_bResCurrupted = true;
			}
		}

		if(pRsrc_Dir_Entry[dwIndex].DataIsDirectory)
		{
			if(!pRsrc_Dir_Entry[dwIndex].OffsetToDirectory)
			{
				//dwIndex++;
				continue;
			}
			IMAGE_RESOURCE_DIRECTORY ResourceRoot;
			memset(&ResourceRoot, 0x00, sizeof(IMAGE_RESOURCE_DIRECTORY));
			//dwResourceDirectory + pRsrc_Dir_Entry[dwIndex].OffsetToDirectory;
			//m_pMaxPEFile->SetFilePointer(0x00);
			if(!m_pMaxPEFile->ReadBuffer(&ResourceRoot, dwResourceDirectory + pRsrc_Dir_Entry[dwIndex].OffsetToDirectory, sizeof(IMAGE_RESOURCE_DIRECTORY), sizeof(IMAGE_RESOURCE_DIRECTORY)))
			{
				m_dResourceMinEntropy = 0.0;
				m_dwResourceMinSize = 0;
				if(pRsrc_Dir_Entry != NULL)
				{
					delete []pRsrc_Dir_Entry;
					pRsrc_Dir_Entry = NULL;
				}
				return false;
			}
			if(m_dwTotalNoOfResources >=1400 || m_bResCurrupted == true)
			{
				m_dResourceMinEntropy = 0.0;
				m_dwResourceMinSize = 0;
				if(pRsrc_Dir_Entry != NULL)
				{
					delete []pRsrc_Dir_Entry;
					pRsrc_Dir_Entry = NULL;
				}
				return false;
			}

			if(!ParseResourceTreeEx(&ResourceRoot,dwResourceDirectory, dwResourceDirectory + pRsrc_Dir_Entry[dwIndex].OffsetToDirectory))
			{
				m_dResourceMinEntropy = 0.0;
				m_dwResourceMinSize = 0;
				if(pRsrc_Dir_Entry != NULL)
				{
					delete []pRsrc_Dir_Entry;
					pRsrc_Dir_Entry = NULL;
				}
				return false;
			}

		}
		else
		{
			if(!pRsrc_Dir_Entry[dwIndex].OffsetToData)
			{
				continue;
			}

			PIMAGE_RESOURCE_DATA_ENTRY pRsrc_Entry = new IMAGE_RESOURCE_DATA_ENTRY;
			if(pRsrc_Entry == NULL)
			{
				continue;
			}

			memset(pRsrc_Entry, 0x00, sizeof(IMAGE_RESOURCE_DATA_ENTRY));
			if(!m_pMaxPEFile->ReadBuffer(pRsrc_Entry, dwResourceDirectory + pRsrc_Dir_Entry[dwIndex].OffsetToDirectory, (sizeof(IMAGE_RESOURCE_DATA_ENTRY)), (sizeof(IMAGE_RESOURCE_DATA_ENTRY))))
			{
				if(pRsrc_Entry != NULL)
				{
					delete pRsrc_Entry;
					pRsrc_Entry = NULL;
				}
				m_dResourceMinEntropy = 0.0;
				m_dwResourceMinSize = 0;
				if(pRsrc_Dir_Entry != NULL)
				{
					delete []pRsrc_Dir_Entry;
					pRsrc_Dir_Entry = NULL;
				}
				return false;
			}
			DWORD dwSizeRD = 0;
			if(pRsrc_Entry->Size > 0 && pRsrc_Entry->Size < 0xA00000)
			{
				dwSizeRD = pRsrc_Entry->Size;
			}
			if(dwSizeRD <=0)
			{
				m_dwResourceMinSize = 0;
				m_dResourceMinEntropy = 0.0;
				if(pRsrc_Entry != NULL)
				{
					delete pRsrc_Entry;
					pRsrc_Entry = NULL;
				}
				if(pRsrc_Dir_Entry != NULL)
				{
					delete []pRsrc_Dir_Entry;
					pRsrc_Dir_Entry = NULL;
				}
				return false;
			}

			m_dwResourceTotalSize += dwSizeRD;

			if(dwSizeRD > m_dwResourceMaxSize)
				m_dwResourceMaxSize = dwSizeRD;
			if(dwSizeRD < m_dwResourceMinSize)
				m_dwResourceMinSize = dwSizeRD;

			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}
			m_pbyBuff = new BYTE[dwSizeRD];
			if(m_pbyBuff == NULL)
			{
				m_dResourceMinEntropy = 0.0;
				m_dwResourceMinSize = 0;
				if(pRsrc_Entry != NULL)
				{
					delete pRsrc_Entry;
					pRsrc_Entry = NULL;
				}
				if(pRsrc_Dir_Entry != NULL)
				{
					delete []pRsrc_Dir_Entry;
					pRsrc_Dir_Entry = NULL;
				}
				return false;
			}
			memset(m_pbyBuff, 0x00, sizeof(BYTE)*dwSizeRD);
			DWORD dwRVA2Data = pRsrc_Entry->OffsetToData;
			DWORD dwFileOffset = 0;
			DWORD dummy = m_pMaxPEFile->Rva2FileOffset(dwRVA2Data, &dwFileOffset);

			DWORD dwBytesCount[256] = {0};
			if(GetBuffer(dwFileOffset, dwSizeRD, dwSizeRD))
			{
				DWORD iter = 0;
				for(iter = 0; iter < dwSizeRD; ++iter)
				{	
					++dwBytesCount[static_cast<unsigned char>(m_pbyBuff[iter])];
				}
			}
			else
			{
				//m_dResourceMinEntropy = 0.0;
				//m_dwResourceMinSize = 0;

				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff = NULL;
				}

				if(pRsrc_Entry != NULL)
				{
					delete pRsrc_Entry;
					pRsrc_Entry = NULL;
				}
				continue;
				//Throw Appropriate exception
			}

			std::streamoff total_length = static_cast<std::streamoff>(dwSizeRD);
			double dTempHolder = GetEntropy(dwBytesCount,dwSizeRD);

			if(dTempHolder > m_dResourceMaxEntropy)
				m_dResourceMaxEntropy = dTempHolder;
			if(dTempHolder < m_dResourceMinEntropy)
				m_dResourceMinEntropy = dTempHolder;

			m_dResourceTotalEntropy += dTempHolder;

			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}
			if(pRsrc_Entry != NULL)
			{
				delete pRsrc_Entry;
				pRsrc_Entry = NULL;
			}
			//DWORD myOffsetToData = pResData->OffsetToData;
			m_dwTotalNoOfResources++;
		}
	}
	if(pRsrc_Dir_Entry != NULL)
	{
		delete []pRsrc_Dir_Entry;
		pRsrc_Dir_Entry = NULL;
	}
}

/******************************************************************************
Function Name	:	Calculate_Resource_Entropy
Author			:	Harshvardhan Patel
Output			:   bool
Description		:	1. Gets Address of Resource Section
					2. Calls ParseResourceTree
					3. Calculates: 
									i. Mean ResourceEntropy and MeanResourceSize
*******************************************************************************/ 
bool CMaxMLHeurWrapp::GetResourceEntropy()
{
	//AddLogEntry(L"Inside Resource Entropy");
	//Initializing Variables
	m_dResourceMaxEntropy = 0.0;
	m_dResourceMinEntropy = 10.0;		//Entropy ranges from 0 to 8
	m_dResourceMeanEntropy = 0.0;

	m_dResourceTotalEntropy = 0.0;
	m_dwTotalNoOfResources = 0;

	m_dwResourceMaxSize = 0;
	m_dResourceMeanSize = 0;
	m_dwResourceMinSize = UINT_MAX;
	m_dwResourceTotalSize = 0;

	double dTemp = 0.0;
	DWORD dwResourceDirectoryVA = m_pMaxPEFile->
								  m_stPEHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]
								  .VirtualAddress;

	WORD wSec = 0x00;

	if(!dwResourceDirectoryVA)
	{
		//AddLogEntry(L"Potentially Empty Resource");
		m_dResourceMinEntropy = 0.0;
		m_dwResourceMinSize = 0;
		return false;
	}

	bool isResourceHeaderValid = false;
	
	//Check for Invalid Resource Section *******************************************
	//Might need optimization
	for(wSec = 0x00; wSec < m_wNoOfSections; ++wSec)
	{
		if(m_pSectionHeader[wSec].VirtualAddress == dwResourceDirectoryVA && 
			!memcmp(m_pSectionHeader[wSec].Name, ".rsrc", 5))
		{
			isResourceHeaderValid = true;
			m_dwResourceOffsetLimit = (m_pSectionHeader[wSec].PointerToRawData + 
						m_pSectionHeader[wSec].SizeOfRawData);
			DWORD dummy = 0;
			if(m_pSectionHeader[wSec].PointerToRawData >= m_pMaxPEFile->m_dwFileSize)
			{
				m_dwResourceMinSize = 0;
				m_dResourceMinEntropy = 0.0;
				return false;
			}
			else if(m_pMaxPEFile->Rva2FileOffset(dwResourceDirectoryVA, &dummy) >= 
						m_dwResourceOffsetLimit)
			{
				m_dwResourceMinSize = 0;
				m_dResourceMinEntropy = 0.0;
				return false;
			}
			break;
		}
	}
	//********************************************************************************
	
	if(!isResourceHeaderValid)
	{
		m_dResourceMinEntropy = 0.0;
		m_dwResourceMinSize = 0;
		return false;
	}

	DWORD dwResourceDirectory = 0;
	DWORD no_use = m_pMaxPEFile->Rva2FileOffset(dwResourceDirectoryVA, &dwResourceDirectory);
	
	if(!dwResourceDirectory)
	{
		//AddLogEntry(L"Potentially Empty Resource");
		m_dResourceMinEntropy = 0.0;
		m_dwResourceMinSize = 0;
		return false;
	}

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	
	m_pbyBuff = new BYTE[m_pMaxPEFile->m_dwFileSize];
	if(!m_pbyBuff)
	{
		m_dResourceMinEntropy = 0.0;
		m_dwResourceMinSize = 0;
		return false;
	}

	bool test = GetBuffer(0x00,m_pMaxPEFile->m_dwFileSize,m_pMaxPEFile->m_dwFileSize);
	if(!test)
	{
		m_dResourceMinEntropy = 0.0;
		m_dwResourceMinSize = 0;
		return false;
	}

	m_pbyAuxBuff = new BYTE[m_pMaxPEFile->m_dwFileSize];
	if(!m_pbyAuxBuff)
	{
		m_dResourceMinEntropy = 0.0;
		m_dwResourceMinSize = 0;
		return false;
	}
	memcpy(m_pbyAuxBuff, m_pbyBuff, m_pMaxPEFile->m_dwFileSize);
	
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}

	PIMAGE_RESOURCE_DIRECTORY ResourceRoot = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>
								(m_pbyAuxBuff + dwResourceDirectory);
	if(ResourceRoot == NULL)
	{
		m_dResourceMinEntropy = 0.0;
		m_dwResourceMinSize = 0;
		return false;
	}

	m_pResDir = ResourceRoot;
	
	if((ResourceRoot->NumberOfNamedEntries 
			+ ResourceRoot->NumberOfIdEntries) > 0x30)
	{
		m_dResourceMinEntropy = 0.0;
		m_dwResourceMinSize = 0;
		return false;
	}

	ParseResourceTree(ResourceRoot);

	//Checks for any unhandled invalid resource section***********************
	if(m_dResourceMinEntropy == 10)
	{
		m_dResourceMinEntropy = 0;
	}
	if(m_dwResourceMinSize == UINT_MAX)
	{
		m_dwResourceMinSize = 0;
	}
	//***************************************************************************

	if(m_dwTotalNoOfResources)
		m_dResourceMeanEntropy = (m_dResourceTotalEntropy / (double)(m_dwTotalNoOfResources));
	

	if(m_dwTotalNoOfResources)
		m_dResourceMeanSize = (m_dwResourceTotalSize / (double)m_dwTotalNoOfResources);

	if(m_pbyBuff)
	{
		delete []m_pbyAuxBuff;
		m_pbyAuxBuff = NULL;
	}
	
	return true;
}

bool CMaxMLHeurWrapp::GetResourceEntropyEx()
{
	m_dResourceMaxEntropy = 0.0;
	m_dResourceMinEntropy = 10.0;
	m_dResourceMeanEntropy = 0.0;

	m_dResourceTotalEntropy = 0.0;
	m_dwTotalNoOfResources = 0;

	m_dwResourceMaxSize = 0;
	m_dResourceMeanSize = 0;
	m_dwResourceMinSize = UINT_MAX;
	m_dwResourceTotalSize = 0;

	double dTemp = 0.0;
	DWORD dwResourceDirectoryVA = m_pMaxPEFile->
								  m_stPEHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]
								  .VirtualAddress;

	WORD wSec = 0x00;

	if(!dwResourceDirectoryVA)
	{
		m_dResourceMinEntropy = 0.0;
		m_dwResourceMinSize = 0;
		return false;
	}

	bool isResourceHeaderValid = false;
	
	for(wSec = 0x00; wSec < m_wNoOfSections; ++wSec)
	{
		if(m_pSectionHeader[wSec].VirtualAddress == dwResourceDirectoryVA && 
			!memcmp(m_pSectionHeader[wSec].Name, ".rsrc", 5))
		{
			isResourceHeaderValid = true;
			m_dwResourceOffsetLimit = (m_pSectionHeader[wSec].PointerToRawData + 
						m_pSectionHeader[wSec].SizeOfRawData);
			DWORD dummy = 0;
			if(m_pSectionHeader[wSec].PointerToRawData >= m_pMaxPEFile->m_dwFileSize)
			{
				m_dwResourceMinSize = 0;
				m_dResourceMinEntropy = 0.0;
				return false;
			}
			else if(m_pMaxPEFile->Rva2FileOffset(dwResourceDirectoryVA, &dummy) >= 
						m_dwResourceOffsetLimit)
			{
				m_dwResourceMinSize = 0;
				m_dResourceMinEntropy = 0.0;
				return false;
			}
			break;
		}
	}
	
	if(!isResourceHeaderValid)
	{
		m_dResourceMinEntropy = 0.0;
		m_dwResourceMinSize = 0;
		return false;
	}
	bool iRetStatus = false;
	DWORD dwResourceDirectory = 0;
//	DWORD no_use = m_pMaxPEFile->Rva2FileOffset(dwResourceDirectoryVA, &dwResourceDirectory);


	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_pMaxPEFile->m_stPEHeader.DataDirectory[2].VirtualAddress, &dwResourceDirectory))
	{
		return iRetStatus;
	}

	IMAGE_RESOURCE_DIRECTORY ResourceRoot;
	memset(&ResourceRoot, 0x00, sizeof(IMAGE_RESOURCE_DIRECTORY));
	
	if(!m_pMaxPEFile->ReadBuffer(&ResourceRoot, dwResourceDirectory, sizeof(IMAGE_RESOURCE_DIRECTORY), sizeof(IMAGE_RESOURCE_DIRECTORY)))
	{
		return iRetStatus;
	}
	
	if(!dwResourceDirectory)
	{
		m_dResourceMinEntropy = 0.0;
		m_dwResourceMinSize = 0;
		return false;
	}

	m_pResDir = &ResourceRoot;
	
	DWORD	dwTotalRsrcEntry = ResourceRoot.NumberOfIdEntries + ResourceRoot.NumberOfNamedEntries;
	if(dwTotalRsrcEntry > 0x30 || dwTotalRsrcEntry<=0)
	{
		m_dResourceMinEntropy = 0.0;
		m_dwResourceMinSize = 0;
		return false;
	}
	if(!ParseResourceTreeEx(&ResourceRoot,dwResourceDirectory,dwResourceDirectory))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_dResourceMinEntropy = 0.0;
		m_dwResourceMinSize = 0;
		return false;
	}
	if(m_dResourceMinEntropy == 10)
	{
		m_dResourceMinEntropy = 0;
	}
	if(m_dwResourceMinSize == UINT_MAX)
	{
		m_dwResourceMinSize = 0;
	}

	if(m_dwTotalNoOfResources)
		m_dResourceMeanEntropy = (m_dResourceTotalEntropy / (double)(m_dwTotalNoOfResources));
	
	/*double Max = m_dResourceMaxEntropy;
	double Min = m_dResourceMinEntropy;

	DWORD MaxSize = m_dwResourceMaxSize;
	DWORD MinSize = m_dwResourceMinSize;*/

	if(m_dwTotalNoOfResources)
		m_dResourceMeanSize = (m_dwResourceTotalSize / (double)m_dwTotalNoOfResources);

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	
	return true;
}

/******************************************************************************
Function Name	:	CalculateNoOfImports
Author			:	Harshvardhan Patel
Output			:   void
Description		:	Calculates Number of DLL and corresponding API Calls made 
To-Do			:	Check in it handles all invalid imports sections
*******************************************************************************/ 
void CMaxMLHeurWrapp::GetNoOfImports()
{
	m_dwImportsNbDLL = 0;
	m_dwImportsNb = 0;

	DWORD dwImportDirectoryVA = m_pMaxPEFile->
								m_stPEHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
								.VirtualAddress;
	
	DWORD dummy = m_pMaxPEFile->Rva2FileOffset(dwImportDirectoryVA, &dummy);
	if(!dwImportDirectoryVA )
	{
		return;
	}
	
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	
	m_pbyBuff = new BYTE[m_pMaxPEFile->m_dwFileSize];

	if(!m_pbyBuff)
	{
		return;
	}

	bool test = GetBuffer(0x00,m_pMaxPEFile->m_dwFileSize,m_pMaxPEFile->m_dwFileSize);
	if(!test)
	{
		return;
	}

	BYTE *pImageBase = m_pbyBuff;
	DWORD dwImportDirectory = 0;
	DWORD dwFileSize = m_pMaxPEFile->m_dwFileSize;
	DWORD dum = m_pMaxPEFile->Rva2FileOffset(dwImportDirectoryVA,&dwImportDirectory);
	if(dwImportDirectory >= dwFileSize)
		return;
	PIMAGE_IMPORT_DESCRIPTOR descr = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pImageBase + dwImportDirectory);
	
	if(!descr)
	{
		return;
	}

	BYTE  *pThunk;
	DWORD  dwThunk;
	BYTE  *pHintName;

	DWORD TempOffsetHolder = 0;
	while(descr->Name != 0)
	{ 
		m_dwImportsNbDLL++;

		/*pThunk = pImageBase + descr->FirstThunk;
		dwThunk = descr->FirstThunk;
		pHintName = pImageBase;

		if(descr->OriginalFirstThunk != 0)
		{
			m_pMaxPEFile->Rva2FileOffset(descr->OriginalFirstThunk, &TempOffsetHolder);
			if(!TempOffsetHolder)
			{
				descr++;
				continue;
			}
			pHintName += TempOffsetHolder;
		}
		else
		{
			m_pMaxPEFile->Rva2FileOffset(descr->FirstThunk, &TempOffsetHolder);
			if(!TempOffsetHolder)
			{
				descr++;
				continue;
			}
			pHintName += TempOffsetHolder;
		}
		
		PIMAGE_THUNK_DATA_ML pimage_thunk_data = reinterpret_cast<PIMAGE_THUNK_DATA_ML>(pHintName);
		
		while(pimage_thunk_data->u1.AddressOfData != 0)
		{
			pimage_thunk_data++;
			m_dwImportsNb++;
		}*/
		//pDLLName = reinterpret_cast<char *>(m_dwImageBase + descr->Name);
		descr++;
	}
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

void CMaxMLHeurWrapp::GetNoOfImportsEx()
{
	m_dwImportsNbDLL = 0;
	m_dwImportsNb = 0;
	//PDWORD pImageBase = &m_dwImageBase;
	DWORD dwImportDirectoryVA = m_pMaxPEFile->
								m_stPEHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
								.VirtualAddress;


	DWORD dwImportSize =		m_pMaxPEFile->m_stPEHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	
	DWORD dummy = m_pMaxPEFile->Rva2FileOffset(dwImportDirectoryVA, &dummy);
	if(!dwImportDirectoryVA )
	{
		return;
	}

	/*WORD wSec = 0x00;
	bool isImportHeaderValid = false;
	for(wSec = 0x00; wSec < m_wNoOfSections; ++wSec)
	{
		if(m_pSectionHeader[wSec].VirtualAddress == dwImportDirectoryVA && 
			!memcmp(m_pSectionHeader[wSec].Name, ".rdata", 5))
		{
			isImportHeaderValid = true;
			break;
		}
	}

	if(!isImportHeaderValid)
		return;*/

	
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	
	DWORD dwImportDirectory = 0;
	DWORD dum = m_pMaxPEFile->Rva2FileOffset(dwImportDirectoryVA,&dwImportDirectory);
	
	DWORD FileSize = m_pMaxPEFile->m_dwFileSize;
	if(dwImportDirectory >= FileSize)
		return;

	

	DWORD dwTotalImport = sizeof(IMAGE_IMPORT_DESCRIPTOR);
	if(dwImportSize > dwTotalImport)
	{
		dwTotalImport = dwImportSize /dwTotalImport;
	}
	else
	{
		return;
	}
	if(dwTotalImport<=0)
	{
		return;
	}
	PIMAGE_IMPORT_DESCRIPTOR pImport_Descr = new IMAGE_IMPORT_DESCRIPTOR[dwTotalImport];
	if(pImport_Descr == NULL)
	{
		return;
	}
	memset(pImport_Descr, 0x00, sizeof(IMAGE_IMPORT_DESCRIPTOR)*dwTotalImport);
	
	
	if(!m_pMaxPEFile->ReadBuffer(pImport_Descr, dwImportDirectory, sizeof(IMAGE_IMPORT_DESCRIPTOR)*dwTotalImport, sizeof(IMAGE_IMPORT_DESCRIPTOR)*dwTotalImport))
	{
		if(pImport_Descr!= NULL)
		{
			delete []pImport_Descr;
			pImport_Descr=  NULL;
		}
		 m_dwImportsNb = 0;
		return;
	}
	DWORD dwTempOffsetHolder = 0;
	DWORD dwNewOffset = 0;
	DWORD dwCounter = 0x00;
	while(pImport_Descr[dwCounter].Name != 0 && dwCounter< dwTotalImport)
	{
		m_dwImportsNbDLL++;
		dwNewOffset = 0x00;

		if(pImport_Descr[dwCounter].OriginalFirstThunk != 0)
		{
			m_pMaxPEFile->Rva2FileOffset(pImport_Descr[dwCounter].OriginalFirstThunk, &dwTempOffsetHolder);
			if(!dwTempOffsetHolder)
			{
				//dwCounter++;
				//continue;
				if(pImport_Descr!= NULL)
				{
					delete []pImport_Descr;
					pImport_Descr=  NULL;
				}
				m_dwImportsNb = 0;
				m_dwImportsNbDLL = 0;
				return;
			}
			dwNewOffset += dwTempOffsetHolder;
		}
		else
		{
			m_pMaxPEFile->Rva2FileOffset(pImport_Descr[dwCounter].FirstThunk, &dwTempOffsetHolder);
			if(!dwTempOffsetHolder)
			{
				//dwCounter++;
				//continue;
				if(pImport_Descr!= NULL)
				{
					delete []pImport_Descr;
					pImport_Descr=  NULL;
				}
				m_dwImportsNb = 0;
				m_dwImportsNbDLL = 0;
				return;
			}
			dwNewOffset += dwTempOffsetHolder;
		}

		
		if(m_pMaxPEFile->m_b64bit)
		{
			//pimage_thunk_data64 = reinterpret_cast<PIMAGE_THUNK_DATA64>(pHintName);
			IMAGE_THUNK_DATA64 pimage_thunk_data64;

			DWORD dwSize = sizeof(IMAGE_THUNK_DATA64);
			memset(&pimage_thunk_data64,0,dwSize);
			if(!m_pMaxPEFile->ReadBuffer(&pimage_thunk_data64, dwNewOffset, dwSize, dwSize))
			{
				if(pImport_Descr!= NULL)
				{
					delete []pImport_Descr;
					pImport_Descr=  NULL;
				}
				m_dwImportsNb = 0;
				m_dwImportsNbDLL = 0;
				return;
			}
			while(pimage_thunk_data64.u1.AddressOfData != 0)
			{
				//pimage_thunk_data64++;
				dwNewOffset+=dwSize;
				memset(&pimage_thunk_data64,0,dwSize);
				if(!m_pMaxPEFile->ReadBuffer(&pimage_thunk_data64, dwNewOffset, dwSize, dwSize))
				{
					if(pImport_Descr!= NULL)
					{
						delete []pImport_Descr;
						pImport_Descr=  NULL;
					}
					m_dwImportsNb = 0;
					m_dwImportsNbDLL = 0;
					return;
				}
				m_dwImportsNb++;
			}
		}
		else
		{
			//pimage_thunk_data32= reinterpret_cast<PIMAGE_THUNK_DATA32>(pHintName);
			IMAGE_THUNK_DATA32 pimage_thunk_data32;
			DWORD dwSize = sizeof(IMAGE_THUNK_DATA32);
			memset(&pimage_thunk_data32,0,dwSize);
			if(!m_pMaxPEFile->ReadBuffer(&pimage_thunk_data32, dwNewOffset, dwSize, dwSize))
			{
				if(pImport_Descr!= NULL)
				{
					delete []pImport_Descr;
					pImport_Descr=  NULL;
				}
				m_dwImportsNb = 0;
				m_dwImportsNbDLL = 0;
				return;
			}
			while(pimage_thunk_data32.u1.AddressOfData != 0)
			{
				///pimage_thunk_data32++;
				dwNewOffset+=dwSize;
				memset(&pimage_thunk_data32,0,dwSize);
				if(!m_pMaxPEFile->ReadBuffer(&pimage_thunk_data32, dwNewOffset, dwSize, dwSize))
				{
					if(pImport_Descr!= NULL)
					{
						delete []pImport_Descr;
						pImport_Descr=  NULL;
					}
					m_dwImportsNb = 0;
					m_dwImportsNbDLL = 0;
					return;
				}
				m_dwImportsNb++;
			}
		}
		dwCounter++;
	}
}
/******************************************************************************
Function Name	:	Calculate_Section_Min_Mean_RawSize
Author			:	Harshvardhan Patel
Output			:   void
Description		:	Calculates Min/Mean Section RawSize
*******************************************************************************/ 
void CMaxMLHeurWrapp::GetSecMinMeanRSize()
{
	WORD wSec = 0x00;
	DWORD SizeSum = 0;
	m_dwSectionMinRawSize = MAXDWORD;
	m_dSectionMeanRawSize = 0.0;

	for(wSec = 0x00; wSec < m_wNoOfSections; ++wSec)
	{
		SizeSum += m_pSectionHeader[wSec].SizeOfRawData;
		if(m_pSectionHeader[wSec].SizeOfRawData < m_dwSectionMinRawSize)
			m_dwSectionMinRawSize = m_pSectionHeader[wSec].SizeOfRawData;
	}
	if(m_wNoOfSections)
		m_dSectionMeanRawSize =(SizeSum/(double)m_wNoOfSections);
	else
	{
		m_dwSectionMinRawSize = 0;
	}
}
/******************************************************************************
Function Name	:	Calculate_Section_Min_Mean_RawSize
Author			:	Harshvardhan Patel
Output			:   void
Description		:	Calculates Min/Mean Section VirtualSize
*******************************************************************************/ 
void CMaxMLHeurWrapp::GetSecMaxMeanVSize()
{
	WORD wSec = 0x00;
	DWORD SizeSum = 0;
	m_dwSectionMaxVirtualSize = 0;
	m_dSectionMeanVirtualSize = 0.0;

	for(wSec = 0x00; wSec < m_wNoOfSections; ++wSec)
	{
		SizeSum += m_pSectionHeader[wSec].Misc.VirtualSize;
		if(m_pSectionHeader[wSec].Misc.VirtualSize > m_dwSectionMaxVirtualSize)
			m_dwSectionMaxVirtualSize = m_pSectionHeader[wSec].Misc.VirtualSize;
	}
	if(m_wNoOfSections)
		m_dSectionMeanVirtualSize = (SizeSum/(double)m_wNoOfSections);
}

/******************************************************************************
Function Name	:	GetBuffer
Description		:	To get buffer
*******************************************************************************/ 
bool CMaxMLHeurWrapp::GetBuffer(DWORD dwOffset, DWORD dwNumberOfBytesToRead, DWORD dwMinBytesReq)
{
	DWORD m_dwNoOfBytes = 0;
	return m_pMaxPEFile->ReadBuffer(m_pbyBuff, dwOffset, dwNumberOfBytesToRead, dwMinBytesReq, &m_dwNoOfBytes);	
}

/******************************************************************************
Function Name	:	ExportFeaturesToPredictor
Author			:	Harshvardhan Patel
Output			:   bool
Description		:	Exports features to a opencv predictor
*******************************************************************************/ 
bool CMaxMLHeurWrapp::ExportFeaturesToPredictor()
{
	bool bRetVal = false;
	//AddLogEntry(L"Inside Export");
	//float featureValues[30] = {0};  //Array to store features
	float featureValues[28] = {0};  //Array to store features

	float featureValuesTree1[28] = {0};  
	float featureValuesTree2[28] = {0}; 

	bool	bReady = false;
	if (m_pMaxPEFile->m_mlFeatureData.m_bAllFeaturesGenerated)
	{
		bReady = true;
	}
	
	//featureMap["Characteristics"]
	featureValues[0] = (bReady? m_pMaxPEFile->m_mlFeatureData.m_featureValues[0] : m_pMaxPEFile->m_stPEHeader.Characteristics);

	//featureMap["MajorLinkerVersion"]
	featureValues[1] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[1] : (unsigned int)(m_pMaxPEFile->m_stPEHeader.MajorLinkerVersion));
	
	//featureMap["SizeOfCode"]
	featureValues[2] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[2] : m_pMaxPEFile->m_stPEHeader.SizeOfCode);

	//featureMap["SizeOfInitializedData"]
	featureValues[3] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[3] : m_pMaxPEFile->m_stPEHeader.SizeOfInitializedData);

	//featureMap["AddressOfEntryPoint"]
	featureValues[4] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[4] : (unsigned int)(m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint));

	//featureMap["BaseOfData"]
	//featureValues[5] = (unsigned int)(m_pMaxPEFile->m_stPEHeader.BaseOfData);



	//featureMap["MajorOperatingSystemVersion"]
	featureValues[5] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[5] : m_pMaxPEFile->m_stPEHeader.MajorOperatingSystemVersion);

	//featureMap["MajorSubsystemVersion"]
	featureValues[6] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[6] : m_pMaxPEFile->m_stPEHeader.MajorSubsystemVersion);

	//featureMap["CheckSum"]
	featureValues[7] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[7] : m_pMaxPEFile->m_stPEHeader.CheckSum);

	//featureMap["Subsystem"]
	featureValues[8] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[8] : m_pMaxPEFile->m_stPEHeader.Subsystem);

	//featureMap["DllCharacteristics"]
	featureValues[9] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[9] : m_pMaxPEFile->m_stPEHeader.DllCharacteristics);

	//featureMap["SizeOfStackReserve"]
	featureValues[10] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[10] : m_pMaxPEFile->m_stPEHeader.SizeOfStackReserve);

	//featureMap["SectionsNb"]
	featureValues[11] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[11] : m_pMaxPEFile->m_stPEHeader.NumberOfSections);

	//featureMap["SectionsMeanEntropy"]
	featureValues[12] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[12] : m_dSectionMeanEntropy);

	//featureMap["SectionsMinEntropy"]
	featureValues[13] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[13] : m_dSectionMinEntropy);

	//featureMap["SectionsMaxEntropy"]
	featureValues[14] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[14] : m_dSectionMaxEntropy);

	//featureMap["SectionsMeanRawsize"]
	featureValues[15] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[15] : m_dSectionMeanRawSize);

	//featureMap["SectionsMinRawsize"]
	featureValues[16] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[16] : m_dwSectionMinRawSize);

	//featureMap["SectionsMeanVirtualsize"]
	featureValues[17] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[17] : m_dSectionMeanVirtualSize);

	//featureMap["SectionMaxVirtualsize"]
	featureValues[18] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[18] : m_dwSectionMaxVirtualSize);

	//featureMap["ImportsNbDLL"]
	featureValues[19] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[19] : m_dwImportsNbDLL);

	//featureMap["ImportsNb"]
	//featureValues[21] = (m_dwImportsNb);

	//featureMap["ResourcesMeanEntropy"]
	featureValues[20] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[20] : m_dResourceMeanEntropy);

	//featureMap["ResourcesMinEntropy"]
	featureValues[21] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[21] : m_dResourceMinEntropy);

	//featureMap["ResourcesMaxEntropy"]
	featureValues[22] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[22] : m_dResourceMaxEntropy);

	//featureMap["ResourcesMeanSize"]
	featureValues[23] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[23] : m_dResourceMeanSize);

	//featureMap["ResourcesMinSize"]
	featureValues[24] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[24] : m_dwResourceMinSize);

	//featureMap["ResourcesMaxSize"]
	featureValues[25] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[25] : m_dwResourceMaxSize);

	//featureMap["LoadConfigurationSize"]
	featureValues[26] = (bReady ? m_pMaxPEFile->m_mlFeatureData.m_featureValues[26] : (unsigned int)(m_pMaxPEFile->m_stPEHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size));
	
	//Code to retrieve number of valid fields in VersionInformation
	int iVerInfoCount = 0;
	
	CFileVersionInfo objFileVer;
	if(objFileVer.Open(m_pMaxPEFile->m_szFilePath) != FALSE)
	{
		iVerInfoCount = objFileVer.GetCountForML();
		featureValues[27] = static_cast<float>(iVerInfoCount);
	}
	else
	{
		featureValues[27] = 0;
	}

	
	///*------------------------TROJAN NORM-----------------------------*/
	/*
	featureValuesTree1[0] = (featureValues[0] - 6313.22) / 7069.75;
	featureValuesTree1[1] = (featureValues[1] - 12.6966) / 11.4028;
	featureValuesTree1[2] = (featureValues[2] - 1.26437e+06) / 8539.28;
	featureValuesTree1[3] = (featureValues[3] - 1.46841e+06) / 8728.93;
	featureValuesTree1[4] = (featureValues[4] - 553955) / 19772.9;
	featureValuesTree1[5] = (featureValues[5] - 7.4237) / 120.054;
	featureValuesTree1[6] = (featureValues[6] - 5.5544) / 1.56119;
	featureValuesTree1[7] = (featureValues[7] - 1.62105e+07) / 21111.9;
	featureValuesTree1[8] = (featureValues[8] - 2.35629) / 0.478784;
	featureValuesTree1[9] = (featureValues[9] - 14862.9) / 15850.3;
	featureValuesTree1[10] = (featureValues[10] - 1.16423e+06) / 28249.9;
	featureValuesTree1[11] = (featureValues[11] - 4.64375) / 3.79957;
	featureValuesTree1[12] = (featureValues[12] - 3.99134) / 0.842963;
	featureValuesTree1[13] = (featureValues[13] - 1.51315) / 1.34539;
	featureValuesTree1[14] = (featureValues[14] - 6.15691) / 0.884753;
	featureValuesTree1[15] = (featureValues[15] - 187119) / 5981.37;
	featureValuesTree1[16] = (featureValues[16] - 29180.5) / 26984.3;
	featureValuesTree1[17] = (featureValues[17] - 528460) / 969.084;
	featureValuesTree1[18] = (featureValues[18] - 1.52771e+06) / 6974.43;
	featureValuesTree1[19] = (featureValues[19] - 6.76704) / 11.0649;
	featureValuesTree1[20] = (featureValues[20] - 3.21145) / 1.26111;
	featureValuesTree1[21] = (featureValues[21] - 2.40184) / 1.08166;
	featureValuesTree1[22] = (featureValues[22] - 4.21124) / 1.7987;
	featureValuesTree1[23] = (featureValues[23] - 13374.7) / 12145.8;
	featureValuesTree1[24] = (featureValues[24] - 1220.53) / 863.915;
	featureValuesTree1[25] = (featureValues[25] - 69136.6) / 14251;
	featureValuesTree1[26] = (featureValues[26] - 282150) / 43960.1;
	featureValuesTree1[27] = (featureValues[27] - 12.5704) / 6.42212;
	*/

	/*
	featureValuesTree1[0] = (featureValues[0] - 6313.2) / 7071.5;
	featureValuesTree1[1] = (featureValues[1] - 12.696) / 11.4028;
	featureValuesTree1[2] = (featureValues[2] - 1.2642e+06) / 5506.06;
	featureValuesTree1[3] = (featureValues[3] - 1.4682e+06) / 15037;
	featureValuesTree1[4] = (featureValues[4] - 553893) / 19295.6;
	featureValuesTree1[5] = (featureValues[5] - 7.42319) / 120.045;
	featureValuesTree1[6] = (featureValues[6] - 5.5542) / 1.56111;
	featureValuesTree1[7] = (featureValues[7] - 1.6208e+07) / 20306.4;
	featureValuesTree1[8] = (featureValues[8] - 2.35629) / 0.478746;
	featureValuesTree1[9] = (featureValues[9] - 14863.2) / 15850.2;
	featureValuesTree1[10] = (featureValues[10] - 1.16422e+06) / 28129.8;
	featureValuesTree1[11] = (featureValues[11] - 4.64388) / 3.79938;
	featureValuesTree1[12] = (featureValues[12] - 3.9913) / 0.842977;
	featureValuesTree1[13] = (featureValues[13] - 1.51302) / 1.34548;
	featureValuesTree1[14] = (featureValues[14] - 6.15694) / 0.884763;
	featureValuesTree1[15] = (featureValues[15] - 187100) / 6324.5;
	featureValuesTree1[16] = (featureValues[16] - 29176.3) / 26962.7;
	featureValuesTree1[17] = (featureValues[17] - 528392) / 1989.27;
	featureValuesTree1[18] = (featureValues[18] - 1.52751e+06) / 6786.1;
	featureValuesTree1[19] = (featureValues[19] - 6.76699) / 11.0641;
	featureValuesTree1[20] = (featureValues[20] - 3.21143) / 1.26126;
	featureValuesTree1[21] = (featureValues[21] - 2.40172) / 1.08174;
	featureValuesTree1[22] = (featureValues[22] - 4.2113) / 1.79889;
	featureValuesTree1[23] = (featureValues[23] - 13373.6) / 12146.3;
	featureValuesTree1[24] = (featureValues[24] - 1220.36) / 863.963;
	featureValuesTree1[25] = (featureValues[25] - 69135.1) / 14253.5;
	featureValuesTree1[26] = (featureValues[26] - 282106) / 42117.1;
	featureValuesTree1[27] = (featureValues[27] - 12.5697) / 6.42258;

	*/
	/*Released 
	featureValuesTree1[0] = (featureValues[0] - 6314.11) / 7072.67;
	featureValuesTree1[1] = (featureValues[1] - 12.6942) / 11.4024;
	featureValuesTree1[2] = (featureValues[2] - 1.264e+06) / 4596.91;
	featureValuesTree1[3] = (featureValues[3] - 1.46782e+06) / 3954.08;
	featureValuesTree1[4] = (featureValues[4] - 553947) / 19713.3;
	featureValuesTree1[5] = (featureValues[5] - 7.42226) / 120.026;
	featureValuesTree1[6] = (featureValues[6] - 5.5539) / 1.56092;
	featureValuesTree1[7] = (featureValues[7] - 1.62029e+07) / 14443.5;
	featureValuesTree1[8] = (featureValues[8] - 2.35633) / 0.478671;
	featureValuesTree1[9] = (featureValues[9] - 14860.1) / 15850.1;
	featureValuesTree1[10] = (featureValues[10] - 1.16475e+06) / 4433.88;
	featureValuesTree1[11] = (featureValues[11] - 4.64492) / 3.79954;
	featureValuesTree1[12] = (featureValues[12] - 3.99117) / 0.842981;
	featureValuesTree1[13] = (featureValues[13] - 1.51277) / 1.34562;
	featureValuesTree1[14] = (featureValues[14] - 6.15707) / 0.884659;
	featureValuesTree1[15] = (featureValues[15] - 187093) / 6380.59;
	featureValuesTree1[16] = (featureValues[16] - 29168.6) / 26963.7;
	featureValuesTree1[17] = (featureValues[17] - 528328) / 1823.65;
	featureValuesTree1[18] = (featureValues[18] - 1.52737e+06) / 9215.23;
	featureValuesTree1[19] = (featureValues[19] - 6.76675) / 11.0629;
	featureValuesTree1[20] = (featureValues[20] - 3.21121) / 1.26164;
	featureValuesTree1[21] = (featureValues[21] - 2.40152) / 1.08204;
	featureValuesTree1[22] = (featureValues[22] - 4.21103) / 1.79941;
	featureValuesTree1[23] = (featureValues[23] - 13369.9) / 12143.4;
	featureValuesTree1[24] = (featureValues[24] - 1220.02) / 864.786;
	featureValuesTree1[25] = (featureValues[25] - 69123.2) / 14166.9;
	featureValuesTree1[26] = (featureValues[26] - 282017) / 37769.4;
	featureValuesTree1[27] = (featureValues[27] - 12.5675) / 6.42394;
	*/
	//KIRAN
	featureValuesTree1[0] = (featureValues[0] - 6495.5) / 9131.47;
	featureValuesTree1[1] = (featureValues[1] - 9.67822) / 8.6244;
	featureValuesTree1[2] = (featureValues[2] - 687034) / 5908.12;
	featureValuesTree1[3] = (featureValues[3] - 1.17732e+06) / 9135.49;
	featureValuesTree1[4] = (featureValues[4] - 4.35891e+06) / 9067.86;
	featureValuesTree1[5] = (featureValues[5] - 11.9263) / 267.493;
	featureValuesTree1[6] = (featureValues[6] - 5.42214) / 11.4589;
	featureValuesTree1[7] = (featureValues[7] - 1.07962e+07) / 27423.5;
	featureValuesTree1[8] = (featureValues[8] - 1.07962e+07) / 27423.5;
	featureValuesTree1[9] = (featureValues[9] - 12261.4) / 15629;
	featureValuesTree1[10] = (featureValues[10] - 9.5287e+07) / 16408.7;
	featureValuesTree1[11] = (featureValues[11] - 4.98631) / 2.26365;
	featureValuesTree1[12] = (featureValues[12] - 4.15568) / 0.881719;
	featureValuesTree1[13] = (featureValues[13] - 1.62487) / 1.3552;
	featureValuesTree1[14] = (featureValues[14] - 6.43029) / 0.84478;
	featureValuesTree1[15] = (featureValues[15] - 226671) / 8192.99;
	featureValuesTree1[16] = (featureValues[16] - 16377.1) / 14621.1;
	featureValuesTree1[17] = (featureValues[17] - 380283) / 9543.17;
	featureValuesTree1[18] = (featureValues[18] - 1.40389e+06) / 3841.75;
	featureValuesTree1[19] = (featureValues[19] - 7.9582) / 9.57138;
	featureValuesTree1[20] = (featureValues[20] - 3.01008) / 1.63953;
	featureValuesTree1[21] = (featureValues[21] - 2.1006) / 1.24887;
	featureValuesTree1[22] = (featureValues[22] - 4.12723) / 2.22676;
	featureValuesTree1[23] = (featureValues[23] - 10736.4) / 9860.64;
	featureValuesTree1[24] = (featureValues[24] - 92390.8) / 10108.4;
	featureValuesTree1[25] = (featureValues[25] - 75433.8) / 29169.9;
	featureValuesTree1[26] = (featureValues[26] - 73629.1) / 33429.5;
	featureValuesTree1[27] = (featureValues[27] - 9.21946) / 7.53278;
	
	
	
	///*------------------------OTHER CAT NORM-----------------------------*/
	/*
	featureValuesTree2[0] = (featureValues[0] - 6601.54) / 7018.64;
	featureValuesTree2[1] = (featureValues[1] - 13.8965) / 15.0585;
	featureValuesTree2[2] = (featureValues[2] - 1.06921e+06) / 8698.6;
	featureValuesTree2[3] = (featureValues[3] - 1.6925e+06) / 9809.71;
	featureValuesTree2[4] = (featureValues[4] - 576588) / 18157.5;
	featureValuesTree2[5] = (featureValues[5] - 26.2721) / 468.745;
	featureValuesTree2[6] = (featureValues[6] - 5.63237) / 63.3574;
	featureValuesTree2[7] = (featureValues[7] - 6.12135e+06) / 19484.7;
	featureValuesTree2[8] = (featureValues[8] - 4.03871) / 104.03;
	featureValuesTree2[9] = (featureValues[9] - 15598.6) / 16068.6;
	featureValuesTree2[10] = (featureValues[10] - 973904) / 27871.2;
	featureValuesTree2[11] = (featureValues[11] - 4.60045) / 2.41057;
	featureValuesTree2[12] = (featureValues[12] - 3.83695) / 0.79461;
	featureValuesTree2[13] = (featureValues[13] - 1.35683) / 1.30523;
	featureValuesTree2[14] = (featureValues[14] - 6.07048) / 0.865363;
	featureValuesTree2[15] = (featureValues[15] - 208529) / 6641.7;
	featureValuesTree2[16] = (featureValues[16] - 20040.4) / 18303.3;
	featureValuesTree2[17] = (featureValues[17] - 417502) / 7600.65;
	featureValuesTree2[18] = (featureValues[18] - 1.54391e+06) / 5039.58;
	featureValuesTree2[19] = (featureValues[19] - 6.26498) / 9.31827;
	featureValuesTree2[20] = (featureValues[20] - 3.2499) / 1.18038;
	featureValuesTree2[21] = (featureValues[21] - 2.45419) / 0.986553;
	featureValuesTree2[22] = (featureValues[22] - 4.23819) / 1.73359;
	featureValuesTree2[23] = (featureValues[23] - 9710.72) / 9207.89;
	featureValuesTree2[24] = (featureValues[24] - 848.387) / 1045.96;
	featureValuesTree2[25] = (featureValues[25] - 50865.6) / 32722.4;
	featureValuesTree2[26] = (featureValues[26] - 120176) / 39335.3;
	featureValuesTree2[27] = (featureValues[27] - 13.1769) / 6.05582;
	*/
	/*
	featureValuesTree2[0] = (featureValues[0] - 6601.49) / 7020.26;
	featureValuesTree2[1] = (featureValues[1] - 13.8958) / 15.058;
	featureValuesTree2[2] = (featureValues[2] - 1.06909e+06) / 7327.79;
	featureValuesTree2[3] = (featureValues[3] - 1.69227e+06) / 5681.97;
	featureValuesTree2[4] = (featureValues[4] - 576528) / 17881.7;
	featureValuesTree2[5] = (featureValues[5] - 26.2689) / 468.711;
	featureValuesTree2[6] = (featureValues[6] - 5.63217) / 63.3528;
	featureValuesTree2[7] = (featureValues[7] - 6.12047e+06) / 11009.7;
	featureValuesTree2[8] = (featureValues[8] - 4.03846) / 104.023;
	featureValuesTree2[9] = (featureValues[9] - 15598.8) / 16068.7;
	featureValuesTree2[10] = (featureValues[10] - 973926) / 27980.9;
	featureValuesTree2[11] = (featureValues[11] - 4.60058) / 2.41054;
	featureValuesTree2[12] = (featureValues[12] - 3.83694) / 0.794595;
	featureValuesTree2[13] = (featureValues[13] - 1.35673) / 1.30524;
	featureValuesTree2[14] = (featureValues[14] - 6.07052) / 0.865354;
	featureValuesTree2[15] = (featureValues[15] - 208509) / 6811.86;
	featureValuesTree2[16] = (featureValues[16] - 20037.8) / 18305.1;
	featureValuesTree2[17] = (featureValues[17] - 417455) / 7821.29;
	featureValuesTree2[18] = (featureValues[18] - 1.54372e+06) / 3760.08;
	featureValuesTree2[19] = (featureValues[19] - 6.26501) / 9.31774;
	featureValuesTree2[20] = (featureValues[20] - 3.24988) / 1.18053;
	featureValuesTree2[21] = (featureValues[21] - 2.45407) / 0.986725;
	featureValuesTree2[22] = (featureValues[22] - 4.23824) / 1.73368;
	featureValuesTree2[23] = (featureValues[23] - 9710.24) / 9208.49;
	featureValuesTree2[24] = (featureValues[24] - 848.278) / 1045.93;
	featureValuesTree2[25] = (featureValues[25] - 50866.9) / 32721.9;
	featureValuesTree2[26] = (featureValues[26] - 120159) / 39301.8;
	featureValuesTree2[27] = (featureValues[27] - 13.1761) / 6.05645;
	*/

	/*Released 
	featureValuesTree2[0] = (featureValues[0] - 6602.25) / 7021.92;
	featureValuesTree2[1] = (featureValues[1] - 13.8938) / 15.057;
	featureValuesTree2[2] = (featureValues[2] - 1.06895e+06) / 4121.92;
	featureValuesTree2[3] = (featureValues[3] - 1.69186e+06) / 11115.9;
	featureValuesTree2[4] = (featureValues[4] - 576571) / 18085.9;
	featureValuesTree2[5] = (featureValues[5] - 26.2626) / 468.643;
	featureValuesTree2[6] = (featureValues[6] - 5.63188) / 63.3436;
	featureValuesTree2[7] = (featureValues[7] - 6.11871e+06) / 12404.2;
	featureValuesTree2[8] = (featureValues[8] - 4.03801) / 104.007;
	featureValuesTree2[9] = (featureValues[9] - 15595.7) / 16068.3;
	featureValuesTree2[10] = (featureValues[10] - 974468) / 31626.1;
	featureValuesTree2[11] = (featureValues[11] - 4.60156) / 2.4113;
	featureValuesTree2[12] = (featureValues[12] - 3.83687) / 0.79462;
	featureValuesTree2[13] = (featureValues[13] - 1.35654) / 1.30531;
	featureValuesTree2[14] = (featureValues[14] - 6.07066) / 0.865295;
	featureValuesTree2[15] = (featureValues[15] - 208496) / 6950.18;
	featureValuesTree2[16] = (featureValues[16] - 20033.3) / 18304.6;
	featureValuesTree2[17] = (featureValues[17] - 417428) / 7952.03;
	featureValuesTree2[18] = (featureValues[18] - 1.54359e+06) / 1825.84;
	featureValuesTree2[19] = (featureValues[19] - 6.26493) / 9.31698;
	featureValuesTree2[20] = (featureValues[20] - 3.24965) / 1.18106;
	featureValuesTree2[21] = (featureValues[21] - 2.45387) / 0.987144;
	featureValuesTree2[22] = (featureValues[22] - 4.23799) / 1.7343;
	featureValuesTree2[23] = (featureValues[23] - 9707.93) / 9205.11;
	featureValuesTree2[24] = (featureValues[24] - 848.07) / 1046.14;
	featureValuesTree2[25] = (featureValues[25] - 50861.1) / 32727.7;
	featureValuesTree2[26] = (featureValues[26] - 120124) / 39151.8;
	featureValuesTree2[27] = (featureValues[27] - 13.1739) / 6.05824;
	*/
	//KIRAN
	featureValuesTree2[0] = (featureValues[0] - 6285.28) / 9041.09;
	featureValuesTree2[1] = (featureValues[1] - 9.43357) / 9.34374;
	featureValuesTree2[2] = (featureValues[2] - 727229) / 7226.01;
	featureValuesTree2[3] = (featureValues[3] - 1.4156e+06) / 18436.8;
	featureValuesTree2[4] = (featureValues[4] - 1.12003e+06) / 7185.8;
	featureValuesTree2[5] = (featureValues[5] - 8.90038) / 176.505;
	featureValuesTree2[6] = (featureValues[6] - 5.11479) / 1.85602;
	featureValuesTree2[7] = (featureValues[7] - 1.82589e+07) / 6158.82;
	featureValuesTree2[8] = (featureValues[8] - 1.82589e+07) / 6158.82;
	featureValuesTree2[9] = (featureValues[9] - 12553.6) / 15676.9;
	featureValuesTree2[10] = (featureValues[10] - 1.21119e+06) / 4586.69;
	featureValuesTree2[11] = (featureValues[11] - 4.96682) / 2.67554;
	featureValuesTree2[12] = (featureValues[12] - 3.95196) / 1.02975;
	featureValuesTree2[13] = (featureValues[13] - 1.46373) / 1.24495;
	featureValuesTree2[14] = (featureValues[14] - 6.10084) / 1.59556;
	featureValuesTree2[15] = (featureValues[15] - 230661) / 11093.8;
	featureValuesTree2[16] = (featureValues[16] - 13140.5) / 11755.3;
	featureValuesTree2[17] = (featureValues[17] - 342196) / 8192.4;
	featureValuesTree2[18] = (featureValues[18] - 1.37213e+06) / 5704.17;
	featureValuesTree2[19] = (featureValues[19] - 7.65395) / 9.49605;
	featureValuesTree2[20] = (featureValues[20] - 2.85225) / 1.3636;
	featureValuesTree2[21] = (featureValues[21] - 1.9926) / 0.949765;
	featureValuesTree2[22] = (featureValues[22] - 3.91006) / 2.12193;
	featureValuesTree2[23] = (featureValues[23] - 11609.5) / 10884.3;
	featureValuesTree2[24] = (featureValues[24] - 84351.3) / 38812.3;
	featureValuesTree2[25] = (featureValues[25] - 70348.9) / 18296.9;
	featureValuesTree2[26] = (featureValues[26] - 200801) / 40582.4;
	featureValuesTree2[27] = (featureValues[27] - 9.38115) / 7.43142;
	

	float res = 90.0;		//Stores probablity of a file being Legitimate
	float res2 = 90.0;		//Stores probablity of a file being Legitimate
	 
	res = PredictNature(featureValuesTree1);
	if(m_bMLScanner)
	{///// for Main scanner
		if(res < .04)
		{
			bRetVal = true;
			return bRetVal;
		}
		else
		{
			
			res2 = PredictNatureEX(featureValuesTree2);
			if(res2 < .04)
			{
				bRetVal = true;
				return bRetVal;
			}
			else
			{
				bRetVal = false;
				return bRetVal;
			}
			
		}
	}
	else
	{ ///// for heuristic scanner
		if(res < .3 && m_pSQLMgr != NULL)
		{
			int		iError = 0x00;
			TCHAR	szQuery[2048] = {0x00};
			bool	bQueryStatus = false;

			
			UNSAFE_FILE_INFO oUnsafeFileInfo = {0x00};
			_stprintf(oUnsafeFileInfo.szProbability,L"%f",res);
			_stprintf(oUnsafeFileInfo.szFileSize,L"%d",m_pMaxPEFile->m_dwFileSize);
			_tcscpy(oUnsafeFileInfo.szFilePath,m_pMaxPEFile->m_szFilePath);

			TCHAR szDateTime[MAX_PATH] = {0x00};
			CTime ct = CTime::GetCurrentTime();
			_stprintf(szDateTime,L"%s",ct.Format(L"%Y-%m-%d %H:%M:%S"));
			_stprintf(oUnsafeFileInfo.szScanTime,L"%s",szDateTime);

			_CreateSHA256(oUnsafeFileInfo.szFilePath,&oUnsafeFileInfo);

			_CreatePESignature(oUnsafeFileInfo.szFilePath,&oUnsafeFileInfo);

			swprintf_s(oUnsafeFileInfo.szPESig, _countof(oUnsafeFileInfo.szPESig), L"%016I64x", oUnsafeFileInfo.ulSignature);
			
			CStringA	csFilePath(oUnsafeFileInfo.szFilePath);
			char		cMD5Signature[33] = {0};
			if(GetMD5Signature32((LPCSTR)csFilePath, cMD5Signature))
			{	
				CString csSignature(cMD5Signature);
				_tcscpy_s(oUnsafeFileInfo.szMD5, MAX_PATH, (LPCTSTR)csSignature);
			}

			_stprintf(oUnsafeFileInfo.szHuerFilePath,L"mlh_%s.zip",oUnsafeFileInfo.szMD5);

			
			_stprintf(szQuery,L"INSERT INTO ThreatIntelligence (File_Path,Huer_Path,File_MD5,File_SHA256,File_PESign,File_Size,Probability,Scan_Time) VALUES ('%s','%s','%s','%s','%s','%s','%s','%s')",oUnsafeFileInfo.szFilePath,oUnsafeFileInfo.szHuerFilePath,oUnsafeFileInfo.szMD5,oUnsafeFileInfo.szSHA256,oUnsafeFileInfo.szPESig,oUnsafeFileInfo.szFileSize,oUnsafeFileInfo.szProbability,oUnsafeFileInfo.szScanTime);
			
			
			bQueryStatus = m_pSQLMgr->ExecuteQuery(szQuery);
			
			bRetVal = true;
		}
		else
		{
			bRetVal = false;
		}
	}
	
	
	return bRetVal;
}


bool CMaxMLHeurWrapp::_CreateSHA256(LPCTSTR szFilePath,LPUNSAFE_FILE_INFO pUnsafeFileInfo)
{
	CMaxSHA256 objFileSHA;

	_tcscpy(&pUnsafeFileInfo->szSHA256[0x00],L"");
	if (objFileSHA.HashFile(szFilePath, &pUnsafeFileInfo->szSHA256[0x00]))
	{
		return true;
	}
	return false;
}

CString CMaxMLHeurWrapp::_CreateSHA256Ex(LPCTSTR szFilePath)
{
	CMaxSHA256 objFileSHA;

	TCHAR szFileSHA256[MAX_PATH] = {0x00};
	_tcscpy(&szFileSHA256[0x00],L"");
	if (objFileSHA.HashFile(szFilePath, &szFileSHA256[0x00]))
	{
		return CString(szFileSHA256);
		//return true;
	}
	return L"";
}

bool CMaxMLHeurWrapp::_CreatePESignature(LPCTSTR szFilePath, LPUNSAFE_FILE_INFO pUnsafeFileInfo)
{
	CFileSig objFileSig;
	CFileSig objFileSigForMD5;

	//objFileSigForMD5.CreateMD5Sig(pScanInfo->szFileToScan, pPEFileSigLocal->ulFullFileSignature);
	
	if(objFileSig.CreateSignature(szFilePath, pUnsafeFileInfo->ulSignature))
	{
		return true;
	}
	return false;
}