#pragma once

#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "wincrypt.h"
#include "wintrust.h"
#include "mscat.h"
#include "Softpub.h"

typedef BOOL (WINAPI *LPFN_CryptCATAdminAcquireContext2)(
  HCATADMIN               *phCatAdmin,
  const GUID              *pgSubsystem,
  PCWSTR                  pwszHashAlgorithm,
  PCCERT_STRONG_SIGN_PARA pStrongHashPolicy,
  DWORD                   dwFlags
);
typedef BOOL (WINAPI *LPFN_CryptCATAdminAcquireContext)(
  HCATADMIN  *phCatAdmin,
  const GUID *pgSubsystem,
  DWORD      dwFlags
);

typedef BOOL (WINAPI *LPFN_CryptCATAdminCalcHashFromFileHandle)(
  HANDLE hFile,
  DWORD  *pcbHash,
  BYTE   *pbHash,
  DWORD  dwFlags
);

typedef BOOL (WINAPI *LPFN_CryptCATAdminCalcHashFromFileHandle2)(
  HCATADMIN hCatAdmin,
  HANDLE    hFile,
  DWORD     *pcbHash,
  BYTE      *pbHash,
  DWORD     dwFlags
);

typedef BOOL (WINAPI *LPFN_CryptCATAdminReleaseContext)(
  IN HCATADMIN hCatAdmin,
  IN DWORD     dwFlags
);

typedef HCATINFO (WINAPI *LPFN_CryptCATAdminEnumCatalogFromHash)(
  HCATADMIN hCatAdmin,
  BYTE      *pbHash,
  DWORD     cbHash,
  DWORD     dwFlags,
  HCATINFO  *phPrevCatInfo
);

typedef BOOL (WINAPI *LPFN_CryptCATCatalogInfoFromContext)(
  HCATINFO     hCatInfo,
  CATALOG_INFO *psCatInfo,
  DWORD        dwFlags
);


typedef BOOL (WINAPI *LPFN_CryptCATAdminReleaseCatalogContext)(
  IN HCATADMIN hCatAdmin,
  IN HCATINFO  hCatInfo,
  IN DWORD     dwFlags
);

typedef LONG (WINAPI *LPFN_WinVerifyTrust)(
  HWND   hwnd,
  GUID   *pgActionID,
  LPVOID pWVTData
);
class CMaxDigitalSigCheck
{
	
public:
	CMaxDigitalSigCheck(void);
	~CMaxDigitalSigCheck(void);
	
	bool CheckDigitalSign(LPCTSTR pszDBPath);
	bool LoadWinTrust();
	bool UnLoadWinTrust();

private :
	HMODULE m_hWinTrust;
	bool	m_bWin7Check;
	bool	m_bSha256;
	bool	m_bDigitalScanLoaded;
	LPFN_CryptCATAdminAcquireContext2  m_lpfnCryptCATAdminAcquireContext2;
	LPFN_CryptCATAdminAcquireContext  m_lpfnCryptCATAdminAcquireContext;
	LPFN_CryptCATAdminCalcHashFromFileHandle2 m_lpfnCryptCATAdminCalcHashFromFileHandle2;
	LPFN_CryptCATAdminCalcHashFromFileHandle m_lpfnCryptCATAdminCalcHashFromFileHandle;
	LPFN_CryptCATAdminReleaseContext m_lpfnCryptCATAdminReleaseContext;
	LPFN_CryptCATAdminEnumCatalogFromHash m_lpfnCryptCATAdminEnumCatalogFromHash;
	LPFN_CryptCATCatalogInfoFromContext m_lpfnCryptCATCatalogInfoFromContext;
	LPFN_CryptCATAdminReleaseCatalogContext m_lpfnCryptCATAdminReleaseCatalogContext;
	LPFN_WinVerifyTrust m_lpfnWinVerifyTrust;
	//bool VerifySignature(LPCWSTR pwszSourceFile);
	bool	IsFileDigitallySignedEX(LPCTSTR FilePath);
	bool	IsFileDigitallySigned(LPCTSTR FilePath);
	bool	IsCatDigitallySigned(LPCTSTR FilePath);
	
	
};
