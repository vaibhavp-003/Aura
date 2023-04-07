#pragma once
#include "BalBST.h"

#pragma pack(1)
typedef struct _tagFileInformation
{
	ULONG64		ulFilesize;
	ULONG64     ulPriSig48;						// 48
	ULONG64     ulPriSig64;						// 64
	ULONG64     ulPriSig;						// 128
	ULONG64     ulSecSig;						// 128
	ULONG64     ulMD5Sig;						// CRC of full file
	ULONG64     ulMD5Sig15MB;					// CRC of 15mb file size limit
	BYTE        byMD5Sig[16];					// Actual MD5 of full file (16 bytes)

	BYTE		bIsPacked : 1;					// 0 - 1
	BYTE		bUnPackSuccess : 1;				// 0 - 1
	BYTE		bPESigSuccess : 1;				// 0 - 1
	BYTE		bHasDigitalSignature : 1;		// 0 - 1
	BYTE		byTopLevelPacker : 6;			// 0 - 63
	BYTE		byNoOfUnpacks : 6;				// 0 - 63

	LPCTSTR		szVersionNo;					// version tab: version no
	LPCTSTR		szCompanyName;					// version tab: company name
	LPCTSTR		szProductName;					// version tab: product name
	LPCTSTR		szDescription;					// version tab: description
	LPCTSTR		szFullFilePath;					// full file path

	struct _tagFileInformation * pNext;
}FILE_INFO, *PFILE_INFO, *LPFILE_INFO;
#pragma pack()

const UINT	SIZE_OF_NON_POINTER_DATA_FILE_INFO = sizeof(FILE_INFO) - (sizeof(LPVOID)*6);

class CFileInfo
{

public:
	CFileInfo();
	~CFileInfo();

	bool Add(LPFILE_INFO lpFileInfo);
	bool GetFirst(LPFILE_INFO& lpFileInfo);
	bool GetNext(LPFILE_INFO& lpFileInfo);
	bool Save(LPCTSTR szFilePath);
	bool Load(LPCTSTR szFilePath);
	void RemoveAll();
	UINT GetCount();

private:

	LPBYTE			m_byBuffer;
	DWORD			m_cbBuffer;
	UINT			m_nNodesCount;
	LPFILE_INFO		m_pHead;
	LPFILE_INFO		m_pTemp;
	LPFILE_INFO		m_pTraverse;

	LPFILE_INFO GetNode(LPFILE_INFO lpFileInfo);
};
