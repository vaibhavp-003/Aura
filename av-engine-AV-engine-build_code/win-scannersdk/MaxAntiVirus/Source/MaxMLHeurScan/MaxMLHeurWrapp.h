#pragma once

#include "pch.h"
#include "opencv2/ml.hpp"
#include "opencv2/core.hpp"
#include "MaxPEFile.h"
#include "MaxSqliteMgr.h"
#include "atlstr.h"

//#ifndef VER_H
//#include < WinVer.h >
//#endif
//#pragma comment(lib, "Version.lib ")

class CMaxMLHeurWrapp
{
public:
	CMaxMLHeurWrapp(void);
	~CMaxMLHeurWrapp(void);

private:
	CMaxPEFile	*m_pMaxPEFile;
	BYTE		*m_pbyBuff;
	BYTE		*m_pbyAuxBuff;			//Auxillary Buffer
	PIMAGE_RESOURCE_DIRECTORY	m_pResDir;	//Pointer to base of Resource Directory
	CvRTrees	*m_pMLPredictTree1,*m_pMLPredictTree2;
	IMAGE_SECTION_HEADER *m_pSectionHeader;
	WORD		m_wNoOfSections;
	float		PredictNature(float fValues[30]);
	float		PredictNatureEX(float fValues[30]);
	bool		FeatureCalculations();
	bool		GetResourceEntropy();
	bool		GetResourceEntropyEx();
	void		ParseResourceTree(PIMAGE_RESOURCE_DIRECTORY);
	bool		ParseResourceTreeEx(PIMAGE_RESOURCE_DIRECTORY, DWORD dwResourceDirectory =0x00, DWORD dwOffset =0x00);
	bool		GetEntropy();
	double		GetEntropy(const DWORD bytes_count[256], std::streamoff total_length);	
	void		GetNoOfImports();
	void		GetNoOfImportsEx();
	void		GetSecMinMeanRSize();
	void		GetSecMaxMeanVSize();	
	void		GetVerInfoSize();
	bool		ExportFeaturesToPredictor();
	bool		FileGetInfo(CMaxPEFile *pMaxPEFile);
	bool		GetBuffer(DWORD dwOffset, DWORD dwNumberOfBytesToRead, DWORD dwMinBytesReq);
	bool		GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT);
	void		IsPacker();


	double		m_dSectionMeanEntropy;
	double		m_dSectionMaxEntropy;
	double		m_dSectionMinEntropy;
	double		m_dResourceMinEntropy;
	double		m_dResourceMaxEntropy;
	double		m_dResourceMeanEntropy;
	double		m_dResourceTotalEntropy;
	DWORD		m_dwTotalNoOfResources;
	DWORD		m_dwResourceMaxSize;
	double		m_dResourceMeanSize;
	DWORD		m_dwResourceMinSize;
	DWORD		m_dwResourceTotalSize;
	DWORD		m_dwResourceOffsetLimit;
	DWORD		m_dwImportsNb;
	DWORD		m_dwImportsNbDLL;
	double		m_dSectionMeanRawSize;
	DWORD		m_dwSectionMinRawSize;
	double		m_dSectionMeanVirtualSize;
	DWORD		m_dwSectionMaxVirtualSize;
	DWORD		m_dwIsPackFile;

	DWORD		m_dwCurruptResCounter = 0x00;
	bool		m_bResCurrupted = false;

	CMaxSqliteMgr		*m_pSQLMgr;
	
public:
	bool m_bMLScanner;
	bool LoadMLXML(LPCTSTR szDBPath);
	bool UnLoadMLXML();
	bool ScanFile(LPCTSTR szFilePath);
	bool ScanFileEx(CMaxPEFile *pMaxPEFile);

	/*-------------Added----------------*/
	bool _CreateSHA256(LPCTSTR szFilePath,LPUNSAFE_FILE_INFO pUnsafeFileInfo);
	bool _CreatePESignature(LPCTSTR szFilePath, LPUNSAFE_FILE_INFO pUnsafeFileInfo);

	CString _CreateSHA256Ex(LPCTSTR szFilePath);

	bool LoadTrojanJSON(LPCTSTR szDBPath);
	bool LoadOtherJSON(LPCTSTR szDBPath);
	HANDLE	m_hTrojanTreeLoadingThread;
	HANDLE	m_hOtherTreeLoadingThread;

	TCHAR	m_szDBPath[MAX_PATH];
};


