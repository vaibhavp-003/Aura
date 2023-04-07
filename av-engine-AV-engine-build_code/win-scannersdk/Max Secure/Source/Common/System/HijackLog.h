/*=============================================================================
   FILE			: HijackLog.cpp
   DESCRIPTION	: Implementation of the CHijackLog class.	
   DOCUMENTS	: CommonSystem DesignDoc.doc
   AUTHOR		: Sandip Sanap
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 22/09/2006
   NOTES		:
VERSION HISTORY	: 24 Aug 2007, Avinash B : Unicode Supported
============================================================================*/

#pragma once

#include "Registry.h"  //Header file of CRegistry Class
#include "FileRW.h"
#include "CPUInfo.h"
#include "EnumProcess.h" //Header file of CEnumProcess class
#include "RegPathExpander.h"
#include "PEFileSig.h"
#include "FileSig.h"

bool GetMD5Signature32(const char *filepath, char *cMD5Signature);
bool GetMD5Signature16(const char *filepath, unsigned char bMD5Signature[16]);
bool CreateCRC64Buffer(LPBYTE byBuffer, SIZE_T cbBuffer, ULONG64& ul64CRC);

class CHijackLog
{
public:

	CStringArray  m_objStringArray,m_QueryStringArray;
	CString m_csProductVer,m_csDatabaseVer,m_csComplexSpyVer,m_csInformationVer,m_csGenKeylogVer,
			m_csRootkitremVer,m_csVirusVer,m_csFirstPriVer,m_csUpdateVersion;

	CHijackLog(void);
	~CHijackLog(void);
	void GetHijackLog(void);
	void GetAllHijackLog(void);
	void SetHijackFileName(CString);
	void WriteRegistryLog(CString);
	CString GetSignature(CString);
	void SetProdVer(CString csProdVer);
	void SetDatabaseVer(CString csDatabaseVer);
	void SetComplexSpyVer(CString csComplexSpyVer);
	void SetInformationVer(CString csInformationVer);
	void SetGenKeylogVer(CString csGenKeylogVer);
	void SetRootkitRemVer(CString csRootkitRemVer);
	CString GetExecSignature(CString csFilePath);
	void SetVirusVer(CString csVirusVer);
	void SetFirstPriVer(CString csFirstPriVer);
	void SetUpdtVer(CString csUpdtVer);
	
private:
	CFileSig * m_pobjFileSig;
	CPEFileSig * m_pobjPEFileSig;
	void PreparePESignature(WCHAR *wcsPESig, LPBYTE lpSignature);
	void PrepareFileSigForLog(WCHAR *wcsFileSig, int iLenOfbuffer, LPCWSTR filePath);
	void GetHeaderHijackLog();
	void GetFilesFromFolder(CString csFolderPath);
	void GetFilesFromProgramFilesFolder(CString csFolderPath);
	CString GetShortcutTarget(const CString LinkFileName);
	void GetRunningProcess();
	void  GetSD0(void);
	void  GetSD1(void);
	void  GetSD3(void);
	void  GetFD0(void);
	void  GetFD1(void);
	void  GetFD2(void);
	void  GetND14(void);
	void  GetOD1(void);
	void  GetOD2(void);
	void  GetOD3(void);
	void  GetSD4(void);
	void  GetSD5(void);
	void  GetSD6(void);
	void  GetSD7(void);
	void  GetSD8(void);
	void  GetSD9(void);
	void  GetSD10(void);
	void  GetSD11(void);
	void  GetSD12(void);
	void  GetSD13(void);
	void  GetSD14(void);
	void  GetSD15(void);
	void  GetSD16(void);
	void  GetSD17(void);
	void  GetSD19(void);
	void  GetSD20(void);
	void  GetSD21(void);
	void  GetSD22(void);
	void  GetSD23(void);
	void  GetSD24(void);
	void  GetSD25(void);
	void  GetSD28(void);
	void  GetSD29(void);
	void  GetSD30();
	void  GetSD31();

	bool LoadSignatureDll();
	void UnloadSignatureDll();

	bool OpenHijackLog();
	bool CloseHijackLog();
	bool CheckDirectory(CString csFolderPath);
	bool CheckValidCompanyName(CString csPath);

	CString m_csData;
	CString m_csHijackFileName;
	CRegistry m_objReg;
	CExportFileOperations m_objFileOps;
	CRegPathExpander m_objRegPathExp;

	HINSTANCE m_hSigScanDLL;
	typedef CString (*EPSIGPROC)(CString);
	EPSIGPROC GetEPSignature;
	typedef bool (*LOADDB)();
	LOADDB LoadExecInfoDb;
	typedef void (*UNLOADDB)();
	UNLOADDB UnloadExecInfoDb;
	HINSTANCE m_hInstDLL;
	typedef LRESULT (*FILESIGPROC)(CStringA, CStringA&, bool);
	FILESIGPROC m_lpfnSigProc;
}; //End of CHijackLog Class
