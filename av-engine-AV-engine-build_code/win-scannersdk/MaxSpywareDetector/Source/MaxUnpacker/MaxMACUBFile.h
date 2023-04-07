#pragma once
#include "MaxPEFile.h"
#include "MacStruct.h"
#include "MaxConstant.h"
#include <stdlib.h>


class CMaxMACUBFile
{
	bool			m_bIsBigEndian;
	FAT_HEADER		m_objFATHeader;
	LPFAT_ARCH		*m_pobjFATArray;
	unsigned long	m_ulDisplacement;

	bool			InitializeUBStructs();
	bool			ConvertBEToLB(LPFAT_ARCH pFatArch);
public:
	CMaxMACUBFile(void);
	~CMaxMACUBFile(void);
    
    TCHAR	m_szTempPath[1024];
    
	bool	IsValidUBFile(CMaxPEFile *pMaxPEFile);
	bool	GetUBHeaderStructure(CMaxPEFile *pMaxPEFile);
	int		ExtractUBFile(CMaxPEFile *pMaxPEFile,int *iFileCount = NULL, bool bIsBEndian = false, unsigned long ulStartOffSet = 0x00);
	bool	SetDestDirPath(LPCTSTR pszDestPath);		
};
