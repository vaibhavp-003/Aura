/*======================================================================================
FILE            : Crc64.h
ABSTRACT        : header file
DOCUMENTS       : Calculates the 64 bit CRC value for any given string
AUTHOR          : Dipali Pawar
COMPANY         : Aura 
COPYRIGHT NOTICE:
                 (C)Aura:
                 Created as an unpublished copyright work.All rights reserved.
                 This document and the information it contains is confidential and
                 proprietary to Aura.Hence, it may not be
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
#include "pch.h"
#include "Crc64.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

ULONG64 CCrc64::pCRC64Table[] = {
	0x0000000000000000UL, 0x42f0e1eba9ea3693UL, 0x85e1c3d753d46d26UL,
	0xc711223cfa3e5bb5UL, 0x493366450e42ecdfUL, 0x0bc387aea7a8da4cUL,
	0xccd2a5925d9681f9UL, 0x8e224479f47cb76aUL, 0x9266cc8a1c85d9beUL,
	0xd0962d61b56fef2dUL, 0x17870f5d4f51b498UL, 0x5577eeb6e6bb820bUL,
	0xdb55aacf12c73561UL, 0x99a54b24bb2d03f2UL, 0x5eb4691841135847UL,
	0x1c4488f3e8f96ed4UL, 0x663d78ff90e185efUL, 0x24cd9914390bb37cUL,
	0xe3dcbb28c335e8c9UL, 0xa12c5ac36adfde5aUL, 0x2f0e1eba9ea36930UL,
	0x6dfeff5137495fa3UL, 0xaaefdd6dcd770416UL, 0xe81f3c86649d3285UL,
	0xf45bb4758c645c51UL, 0xb6ab559e258e6ac2UL, 0x71ba77a2dfb03177UL,
	0x334a9649765a07e4UL, 0xbd68d2308226b08eUL, 0xff9833db2bcc861dUL,
	0x388911e7d1f2dda8UL, 0x7a79f00c7818eb3bUL, 0xcc7af1ff21c30bdeUL,
	0x8e8a101488293d4dUL, 0x499b3228721766f8UL, 0x0b6bd3c3dbfd506bUL,
	0x854997ba2f81e701UL, 0xc7b97651866bd192UL, 0x00a8546d7c558a27UL,
	0x4258b586d5bfbcb4UL, 0x5e1c3d753d46d260UL, 0x1cecdc9e94ace4f3UL,
	0xdbfdfea26e92bf46UL, 0x990d1f49c77889d5UL, 0x172f5b3033043ebfUL,
	0x55dfbadb9aee082cUL, 0x92ce98e760d05399UL, 0xd03e790cc93a650aUL,
	0xaa478900b1228e31UL, 0xe8b768eb18c8b8a2UL, 0x2fa64ad7e2f6e317UL,
	0x6d56ab3c4b1cd584UL, 0xe374ef45bf6062eeUL, 0xa1840eae168a547dUL,
	0x66952c92ecb40fc8UL, 0x2465cd79455e395bUL, 0x3821458aada7578fUL,
	0x7ad1a461044d611cUL, 0xbdc0865dfe733aa9UL, 0xff3067b657990c3aUL,
	0x711223cfa3e5bb50UL, 0x33e2c2240a0f8dc3UL, 0xf4f3e018f031d676UL,
	0xb60301f359dbe0e5UL, 0xda050215ea6c212fUL, 0x98f5e3fe438617bcUL,
	0x5fe4c1c2b9b84c09UL, 0x1d14202910527a9aUL, 0x93366450e42ecdf0UL,
	0xd1c685bb4dc4fb63UL, 0x16d7a787b7faa0d6UL, 0x5427466c1e109645UL,
	0x4863ce9ff6e9f891UL, 0x0a932f745f03ce02UL, 0xcd820d48a53d95b7UL,
	0x8f72eca30cd7a324UL, 0x0150a8daf8ab144eUL, 0x43a04931514122ddUL,
	0x84b16b0dab7f7968UL, 0xc6418ae602954ffbUL, 0xbc387aea7a8da4c0UL,
	0xfec89b01d3679253UL, 0x39d9b93d2959c9e6UL, 0x7b2958d680b3ff75UL,
	0xf50b1caf74cf481fUL, 0xb7fbfd44dd257e8cUL, 0x70eadf78271b2539UL,
	0x321a3e938ef113aaUL, 0x2e5eb66066087d7eUL, 0x6cae578bcfe24bedUL,
	0xabbf75b735dc1058UL, 0xe94f945c9c3626cbUL, 0x676dd025684a91a1UL,
	0x259d31cec1a0a732UL, 0xe28c13f23b9efc87UL, 0xa07cf2199274ca14UL,
	0x167ff3eacbaf2af1UL, 0x548f120162451c62UL, 0x939e303d987b47d7UL,
	0xd16ed1d631917144UL, 0x5f4c95afc5edc62eUL, 0x1dbc74446c07f0bdUL,
	0xdaad56789639ab08UL, 0x985db7933fd39d9bUL, 0x84193f60d72af34fUL,
	0xc6e9de8b7ec0c5dcUL, 0x01f8fcb784fe9e69UL, 0x43081d5c2d14a8faUL,
	0xcd2a5925d9681f90UL, 0x8fdab8ce70822903UL, 0x48cb9af28abc72b6UL,
	0x0a3b7b1923564425UL, 0x70428b155b4eaf1eUL, 0x32b26afef2a4998dUL,
	0xf5a348c2089ac238UL, 0xb753a929a170f4abUL, 0x3971ed50550c43c1UL,
	0x7b810cbbfce67552UL, 0xbc902e8706d82ee7UL, 0xfe60cf6caf321874UL,
	0xe224479f47cb76a0UL, 0xa0d4a674ee214033UL, 0x67c58448141f1b86UL,
	0x253565a3bdf52d15UL, 0xab1721da49899a7fUL, 0xe9e7c031e063acecUL,
	0x2ef6e20d1a5df759UL, 0x6c0603e6b3b7c1caUL, 0xf6fae5c07d3274cdUL,
	0xb40a042bd4d8425eUL, 0x731b26172ee619ebUL, 0x31ebc7fc870c2f78UL,
	0xbfc9838573709812UL, 0xfd39626eda9aae81UL, 0x3a28405220a4f534UL,
	0x78d8a1b9894ec3a7UL, 0x649c294a61b7ad73UL, 0x266cc8a1c85d9be0UL,
	0xe17dea9d3263c055UL, 0xa38d0b769b89f6c6UL, 0x2daf4f0f6ff541acUL,
	0x6f5faee4c61f773fUL, 0xa84e8cd83c212c8aUL, 0xeabe6d3395cb1a19UL,
	0x90c79d3fedd3f122UL, 0xd2377cd44439c7b1UL, 0x15265ee8be079c04UL,
	0x57d6bf0317edaa97UL, 0xd9f4fb7ae3911dfdUL, 0x9b041a914a7b2b6eUL,
	0x5c1538adb04570dbUL, 0x1ee5d94619af4648UL, 0x02a151b5f156289cUL,
	0x4051b05e58bc1e0fUL, 0x87409262a28245baUL, 0xc5b073890b687329UL,
	0x4b9237f0ff14c443UL, 0x0962d61b56fef2d0UL, 0xce73f427acc0a965UL,
	0x8c8315cc052a9ff6UL, 0x3a80143f5cf17f13UL, 0x7870f5d4f51b4980UL,
	0xbf61d7e80f251235UL, 0xfd913603a6cf24a6UL, 0x73b3727a52b393ccUL,
	0x31439391fb59a55fUL, 0xf652b1ad0167feeaUL, 0xb4a25046a88dc879UL,
	0xa8e6d8b54074a6adUL, 0xea16395ee99e903eUL, 0x2d071b6213a0cb8bUL,
	0x6ff7fa89ba4afd18UL, 0xe1d5bef04e364a72UL, 0xa3255f1be7dc7ce1UL,
	0x64347d271de22754UL, 0x26c49cccb40811c7UL, 0x5cbd6cc0cc10fafcUL,
	0x1e4d8d2b65facc6fUL, 0xd95caf179fc497daUL, 0x9bac4efc362ea149UL,
	0x158e0a85c2521623UL, 0x577eeb6e6bb820b0UL, 0x906fc95291867b05UL,
	0xd29f28b9386c4d96UL, 0xcedba04ad0952342UL, 0x8c2b41a1797f15d1UL,
	0x4b3a639d83414e64UL, 0x09ca82762aab78f7UL, 0x87e8c60fded7cf9dUL,
	0xc51827e4773df90eUL, 0x020905d88d03a2bbUL, 0x40f9e43324e99428UL,
	0x2cffe7d5975e55e2UL, 0x6e0f063e3eb46371UL, 0xa91e2402c48a38c4UL,
	0xebeec5e96d600e57UL, 0x65cc8190991cb93dUL, 0x273c607b30f68faeUL,
	0xe02d4247cac8d41bUL, 0xa2dda3ac6322e288UL, 0xbe992b5f8bdb8c5cUL,
	0xfc69cab42231bacfUL, 0x3b78e888d80fe17aUL, 0x7988096371e5d7e9UL,
	0xf7aa4d1a85996083UL, 0xb55aacf12c735610UL, 0x724b8ecdd64d0da5UL,
	0x30bb6f267fa73b36UL, 0x4ac29f2a07bfd00dUL, 0x08327ec1ae55e69eUL,
	0xcf235cfd546bbd2bUL, 0x8dd3bd16fd818bb8UL, 0x03f1f96f09fd3cd2UL,
	0x41011884a0170a41UL, 0x86103ab85a2951f4UL, 0xc4e0db53f3c36767UL,
	0xd8a453a01b3a09b3UL, 0x9a54b24bb2d03f20UL, 0x5d45907748ee6495UL,
	0x1fb5719ce1045206UL, 0x919735e51578e56cUL, 0xd367d40ebc92d3ffUL,
	0x1476f63246ac884aUL, 0x568617d9ef46bed9UL, 0xe085162ab69d5e3cUL,
	0xa275f7c11f7768afUL, 0x6564d5fde549331aUL, 0x279434164ca30589UL,
	0xa9b6706fb8dfb2e3UL, 0xeb46918411358470UL, 0x2c57b3b8eb0bdfc5UL,
	0x6ea7525342e1e956UL, 0x72e3daa0aa188782UL, 0x30133b4b03f2b111UL,
	0xf7021977f9cceaa4UL, 0xb5f2f89c5026dc37UL, 0x3bd0bce5a45a6b5dUL,
	0x79205d0e0db05dceUL, 0xbe317f32f78e067bUL, 0xfcc19ed95e6430e8UL,
	0x86b86ed5267cdbd3UL, 0xc4488f3e8f96ed40UL, 0x0359ad0275a8b6f5UL,
	0x41a94ce9dc428066UL, 0xcf8b0890283e370cUL, 0x8d7be97b81d4019fUL,
	0x4a6acb477bea5a2aUL, 0x089a2aacd2006cb9UL, 0x14dea25f3af9026dUL,
	0x562e43b4931334feUL, 0x913f6188692d6f4bUL, 0xd3cf8063c0c759d8UL,
	0x5dedc41a34bbeeb2UL, 0x1f1d25f19d51d821UL, 0xd80c07cd676f8394UL,
	0x9afce626ce85b507UL};

/*--------------------------------------------------------------------------------------
Function       : CCrc64
In Parameters  : void,
Out Parameters :
Description    :
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CCrc64::CCrc64(void)
{
	m_crc64 = 0;
	m_bEnabled = true;

	uHashSize = 0;
	uInternalBufferSize = 0;
	memset(m_byFinalHash, 0, sizeof(m_byFinalHash));
	InitModule();
}

/*--------------------------------------------------------------------------------------
Function       : ~CCrc64
In Parameters  : void,
Out Parameters :
Description    :
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CCrc64::~CCrc64(void)
{
	ReleaseModule();
}

/*-------------------------------------------------------------------------------------
Function		: InitModule
In Parameters	:
Out Parameters	: -
Purpose			: Initializes the Module
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CCrc64::InitModule()
{
	uHashSize = 64;
	uInternalBufferSize = 64;
	memset(m_byFinalHash, 0, sizeof(m_byFinalHash));
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: ReleaseModule
In Parameters	:
Out Parameters	: -
Purpose			: Release the Module
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void CCrc64::ReleaseModule()
{
}

/*-------------------------------------------------------------------------------------
Function		: InitNewHash
In Parameters	:
Out Parameters	: -
Purpose			: Initializes default CRC value
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void CCrc64::InitNewHash()
{
	m_crc64 = 0xFFFFFFFFFFFFFFFFUL;
}

/*-------------------------------------------------------------------------------------
Function		: UpdateHash
In Parameters	: byte, unsigned long, bool
Out Parameters	: -
Purpose			: Calculates the Hash value - Gen: x^64 + x^4 + x^3 + x + 1
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void CCrc64::UpdateHash(byte pbData[], unsigned long uLength, bool bIsLastBlock)
{
	for(unsigned long i = 0; i < uLength; i++)
	{
		m_crc64 = pCRC64Table[(m_crc64 >> 56)^ pbData[i]] ^ (m_crc64 << 8);
	}
}

/*-------------------------------------------------------------------------------------
Function		: FinalizeHash
In Parameters	:
Out Parameters	: -
Purpose			: Stores the Value
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void CCrc64::FinalizeHash()
{
	Store64H(m_byFinalHash, ~m_crc64);
	FormatHash(m_byFinalHash,4,5,10,1);
}

/*-------------------------------------------------------------------------------------
Function		: Store64H
In Parameters	: byte *, ULONG64
Out Parameters	: -
Purpose			: Stores in byte format
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void CCrc64::Store64H(byte *pbBuffer, ULONG64 uToStore)
{
	pbBuffer[0] = (byte)(uToStore >> 56);
	pbBuffer[1] = (byte)((uToStore >> 48)& 0xff);
	pbBuffer[2] = (byte)((uToStore >> 40)& 0xff);
	pbBuffer[3] = (byte)((uToStore >> 32)& 0xff);
	pbBuffer[4] = (byte)((uToStore >> 24)& 0xff);
	pbBuffer[5] = (byte)((uToStore >> 16)& 0xff);
	pbBuffer[6] = (byte)((uToStore >>  8)& 0xff);
	pbBuffer[7] = (byte)(uToStore & 0xff);
}

/*-------------------------------------------------------------------------------------
Function		: FormatHash
In Parameters	: byte *, UINT, UINT, UINT, UINT
Out Parameters	: -
Purpose			:
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void CCrc64::FormatHash(byte *pbBuffer, UINT uBytesInGroup, UINT uGroupsPerLine, 
	UINT uIndentCount, UINT uFlags)
{
	m_csCRC64 = "";
	if(pbBuffer == NULL)
	{
		return;
	}
	byte bt;
	int i;
	UINT uCurGroup = 0;
	char aChars[] ={'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	if(uBytesInGroup == 0)
	{
		uBytesInGroup = 0xffffffffu;
	}

	int iSize = 8;//sizeof(pbBuffer);
	bt = pbBuffer[0];
	m_csCRC64.AppendChar(aChars[bt >> 4]);
	m_csCRC64.AppendChar(aChars[bt & 0x0F]);
	for(i = 1; i < iSize; i++)
	{
		bt = pbBuffer[i];
		m_csCRC64.AppendChar(aChars[bt >> 4]);
		m_csCRC64.AppendChar(aChars[bt & 0x0F]);
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetCRC64
In Parameters	: CString
Out Parameters	: CString
Purpose			: Returns 64-bit CRC for any given String
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CStringA CCrc64::GetCRC64(CStringA csText)
{
	try
	{
		byte *pbData = NULL;
		size_t size = csText.GetLength();
		pbData = new byte[size + sizeof(TCHAR)];
		unsigned long uLength = (ULONG)size;
		memset(pbData, 0, size + sizeof(TCHAR));
		memcpy_s(pbData, size + sizeof(TCHAR), csText, size);

		InitNewHash();
		UpdateHash(pbData, uLength, true);
		FinalizeHash();
		delete []pbData;
		return m_csCRC64;
	}
	catch(...)
	{
		return CStringA("");
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetCRC64
In Parameters	: CString
Out Parameters	: CString
Purpose			: Returns 64-bit CRC for any given String
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CCrc64::GetCRC64(CStringA csText, CStringA &csOutCRC64)
{
	try
	{
		byte *pbData = NULL;
		size_t size = csText.GetLength();
		pbData = new byte[size + sizeof(TCHAR)];
		unsigned long uLength = (ULONG)size;
		memset(pbData, 0, size + sizeof(TCHAR));
		memcpy_s(pbData, size + sizeof(TCHAR), csText, size);

		InitNewHash();
		UpdateHash(pbData, uLength, true);
		FinalizeHash();
		delete []pbData;
		csOutCRC64 = m_csCRC64;
		return true;
	}
	catch(...)
	{
		return false;
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetCRC64
In Parameters	: unsigned char *
Out Parameters	: CString
Purpose			: Returns 64-bit CRC for any given unsigned Char*
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CStringA CCrc64::GetCRC64(unsigned char *csBuffer)
{
	try
	{
		CStringA csTemp;
		char strCRC64Value[17] = {0};
		int iDataSize = (int)strlen((const char*)csBuffer);
		char *strBigBuffer = new char[iDataSize+1];
		ZeroMemory(strBigBuffer, iDataSize+1);
		strcpy_s(strBigBuffer, iDataSize,(const char*)csBuffer);

		if(GetCRC64((UCHAR*)strBigBuffer, iDataSize, (UCHAR*)strCRC64Value, 17))
		{
			csTemp = strCRC64Value;
		}

		delete [] strBigBuffer;
		return csTemp;
	}
	catch(...)
	{
		return CStringA("");
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetCRC64
In Parameters	: unsigned char *, DWORD, unsigned char *, DWORD
Out Parameters	: bool
Purpose			: Returns CRC Value in bytes and the size of the buffer for given bytes.
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CCrc64::GetCRC64(unsigned char * Buffer, DWORD Length, unsigned char * CRC64, DWORD Size)
{
	try
	{
		InitNewHash();
		UpdateHash(Buffer, Length, true);
		FinalizeHash();
		memcpy_s(CRC64, Size, m_csCRC64, m_csCRC64.GetLength());
		return true;
	}
	catch(...)
	{
	}
	return false;
}

bool CCrc64::GetCRC8Byte(unsigned char * Buffer, DWORD Length, BYTE * CRC64, DWORD Size)
{
	try
	{
		InitNewHash();
		UpdateHash(Buffer, Length, true);
		Store64H(m_byFinalHash, ~m_crc64);
		memcpy_s(CRC64, Size, m_byFinalHash, 8);
		return true;
	}
	catch(...)
	{
	}
	return false;
}