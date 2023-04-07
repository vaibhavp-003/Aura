#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"


typedef struct MS_header_struct 
{ 
	BYTE magic[4];
	BYTE magic2[4]; 
	BYTE magic3[2]; 
	BYTE filesize[4]; 	
}MS_struct;


class CMSExpand: public CUnpackBase
{
	MS_struct *m_pHeader;
	DWORD m_dwHrdOffset;

public:
	CMSExpand(CMaxPEFile *pMaxPEFile);
	~CMSExpand(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);
};
