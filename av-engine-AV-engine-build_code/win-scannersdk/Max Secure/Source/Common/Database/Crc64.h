/*======================================================================================
FILE            : Crc64.h
ABSTRACT        : header file
DOCUMENTS       : Calculates the 64 bit CRC value for any given string
AUTHOR          : Dipali Pawar
COMPANY         : Aura 
COPYRIGHT NOTICE:
                 (C)Aura:
                 Created as an unpublished copyright work. All rights reserved.
                 This document and the information it contains is confidential and
                 proprietary to Aura. Hence, it may not be
                 used, copied, reproduced, transmitted, or stored in any form or by any
                 means, electronic, recording, photocopying, mechanical or otherwise,
                 without the prior written permission of Aura
CREATION DATE   :  1/July/2007
NOTES           :
VERSION HISTORY :
					04Jan 2008, Nupur
					: This class will take Ascii input and return ascii output.
					Should not be converted to unicode
======================================================================================*/
#pragma once
typedef unsigned char byte;

class CCrc64
{
public:
	CCrc64(void);
	~CCrc64(void);

	bool	m_bEnabled;
	byte	m_byFinalHash[8];
	long	uHashSize; // Hash length in bits
	long	uInternalBufferSize; // In bits
	CStringA m_csCRC64;

	bool InitModule();
	void ReleaseModule();
	void InitNewHash();
	void UpdateHash(byte pbData[], unsigned long uLength, bool bIsLastBlock);
	void FinalizeHash();
	void FormatHash(byte *pbBuffer, UINT uBytesInGroup, UINT uGroupsPerLine, UINT uIndentCount, UINT uFlags);

	CStringA GetCRC64(CStringA csText);
	CStringA GetCRC64(unsigned char *csBuffer);
	bool	GetCRC64(CStringA csText, CStringA &csOutCRC64);
	bool	GetCRC64(unsigned char * Buffer, DWORD Length, unsigned char * CRC64, DWORD Size);
	bool	GetCRC8Byte(unsigned char * Buffer, DWORD Length, BYTE * CRC64, DWORD Size);

private:

	ULONG64		m_crc64;
	static ULONG64	pCRC64Table[];
	void	Store64H(byte *pbBuffer, ULONG64 uToStore);
};
