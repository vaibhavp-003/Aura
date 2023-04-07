#include "pch.h"
#include "sha2.h"
#define SIZE_HASH_BUFFER       16384
#define RH_MAX_BUFFER 2048

class CMaxSHA256
{
public:
	CMaxSHA256();
	~CMaxSHA256();

public:
	int HashFile(LPCTSTR pszFile,LPTSTR pszHash);

	sha256_ctx m_sha256;

};