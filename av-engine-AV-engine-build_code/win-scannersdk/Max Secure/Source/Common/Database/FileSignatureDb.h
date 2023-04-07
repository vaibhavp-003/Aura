/*======================================================================================
FILE             : FileSignatureDb.h
ABSTRACT         : Class for handling operation realted to local sugnature db
DOCUMENTS        : 
AUTHOR           : Dipali Pawar
COMPANY          : Aura 
COPYRIGHT(NOTICE): (C) Aura
                   Created as an unpublished copyright work.  All rights reserved.
                   This document and the information it contains is confidential and
                   proprietary to Aura.  Hence, it may not be
                   used, copied, reproduced, transmitted, or stored in any form or by any
                   means, electronic, recording, photocopying, mechanical or otherwise,
                   without the prior written permission of Aura.
CREATION DATE   : 01-Sep-2007
NOTES           : Defines the class behaviors for the application
VERSION HISTORY : Version: 19.0.0.053, Dipali : Solved no disk space problem.
======================================================================================*/
#pragma once
#include "BufferToStructure.h"
#include "PEConstants.h"

class CFileSignatureDb
{
public:
	CFileSignatureDb(void);
	~CFileSignatureDb(void);

	bool LoadLocalDatabase(const TCHAR *cDriveLetter, int nScannerType);
	void UnLoadLocalDatabase();

	bool GetMD5Signature(const TCHAR *cFileName, BYTE bMD5Signature[iMAX_MD5_SIG_LEN]);
	bool GetFileSignature(const TCHAR *cFileName, PESIGCRCLOCALDB &PESigLocal, VIRUSLOCALDB &VirusLocalDB);
	bool SetFileSignature(const TCHAR *cFileName, PESIGCRCLOCALDB &PESigLocal, VIRUSLOCALDB &VirusLocalDB);

private:

	HANDLE m_hEvent;
	CStringA m_csLocalDBVersion;
	CString m_strInstallPath, m_csCurrentSettingIniPath, m_strProductKey;

	CString m_csPESigFileName, m_csVirusDBFileName;

	CBufferToStructure m_objPEFileSigLocalDB;
	CBufferToStructure m_objVirusLocalDB;

	void SaveAllDB();
	bool LoadAllDB();

	void SetInstallPath();
	void SetProductRegKey();

	CString GetAllUserAppDataPath(void);
	CString GetStringDataFromIni(TCHAR *csVal);
	void PrepareLocalDBPath(const TCHAR *cDriveLetter, int nScannerType);
};
