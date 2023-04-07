#include "pch.h"
#include <stdio.h>
#include <time.h>
#include <string.h>

#ifdef _PARTIAL_MD5_CRC64_
#include "BalBST.h"
#endif

typedef unsigned char *POINTER;
typedef unsigned short int UINT2;
typedef unsigned long int UINT4;

typedef struct
{
	UINT4 state[4];					/* state (ABCD) */
	UINT4 count[2];					/* number of bits, modulo 2^64 (lsb first) */
	unsigned char buffer[64];		/* input buffer */
} MD5_CONTEXT;

void MD5Init(MD5_CONTEXT *);
void MD5Update(MD5_CONTEXT *, unsigned char *, unsigned int);
void MD5Final(unsigned char [16], MD5_CONTEXT *);

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static void MD5Transform(UINT4 [4], unsigned char [64]);
static void Encode(unsigned char *, UINT4 *, unsigned int);
static void Decode(UINT4 *, unsigned char *, unsigned int);
static void MD5_memcpy(POINTER, POINTER, unsigned int);
static void MD5_memset(POINTER, int, unsigned int);

static unsigned char PADDING[64] = 
{
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a, b, c, d, x, s, ac) {  (a) += F ((b), (c), (d)) + (x) + (UINT4)(ac);   (a) = ROTATE_LEFT ((a), (s));  (a) += (b); }
#define GG(a, b, c, d, x, s, ac) {  (a) += G ((b), (c), (d)) + (x) + (UINT4)(ac);  (a) = ROTATE_LEFT ((a), (s));  (a) += (b);  }
#define HH(a, b, c, d, x, s, ac) {  (a) += H ((b), (c), (d)) + (x) + (UINT4)(ac);  (a) = ROTATE_LEFT ((a), (s));  (a) += (b);  }
#define II(a, b, c, d, x, s, ac) {  (a) += I ((b), (c), (d)) + (x) + (UINT4)(ac);  (a) = ROTATE_LEFT ((a), (s));  (a) += (b);  }

void MD5Init (MD5_CONTEXT *context)
{
	context->count[0] = context->count[1] = 0;
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
}

void MD5_memcpy (POINTER output,POINTER input,unsigned int len)
{
	unsigned int i;
	for ( i = 0 ; i < len ; i++ )
		output [ i ] = input [ i ] ;
}

static void Decode (UINT4 *output,unsigned char *input,unsigned int len)
{
	unsigned int i, j;
	for(i = 0, j = 0; j < len; i++, j += 4)
	{
		output[i] = ((UINT4)input[j]) | (((UINT4)input[j+1]) << 8) | (((UINT4)input[j+2]) << 16) | (((UINT4)input[j+3]) << 24);
	}
}
static void MD5_memset (POINTER output,int value,unsigned int len)
{
	unsigned int i;
	for (i = 0; i < len; i++)
	{
		((char *)output)[i] = (char)value;
	}
}

static void MD5Transform (UINT4 state[4],unsigned char block[64])
{
	UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];
	Decode (x, block, 64);

	FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
	FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
	FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
	FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
	FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
	FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
	FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
	FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
	FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
	FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
	FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

	GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
	GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
	GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
	GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
	GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
	GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
	GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
	GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
	GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
	GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
	GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
	GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

	HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
	HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
	HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
	HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
	HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
	HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
	HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
	HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
	HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
	HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

	II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
	II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
	II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
	II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
	II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
	II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
	II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
	II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
	II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
	II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	MD5_memset ((POINTER)x, 0, sizeof (x));
}

static void Encode (unsigned char *output,UINT4 *input,unsigned int len)
{
	unsigned int i, j;
	for (i = 0, j = 0; j < len; i++, j += 4)
	{
		output[j] = (unsigned char)(input[i] & 0xff);
		output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
		output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
		output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
	}
}

void MD5Update (MD5_CONTEXT *context,unsigned char *input,unsigned int inputLen)
{
	unsigned int i, index, partLen;

	index = (unsigned int)((context->count[0] >> 3) & 0x3F);
	if ((context->count[0] += ((UINT4)inputLen << 3)) < ((UINT4)inputLen << 3))
	{
		context->count[1]++;
	}
	context->count[1] += ((UINT4)inputLen >> 29);

	partLen = 64 - index;

	if (inputLen >= partLen) 
	{
		MD5_memcpy ((POINTER)&context->buffer[index], (POINTER)input, partLen);
		MD5Transform (context->state, context->buffer);

		for (i = partLen; i + 63 < inputLen; i += 64)
		{
			MD5Transform (context->state, &input[i]);
		}
		index = 0;
	}
	else
	{
		i = 0;
	}
	MD5_memcpy((POINTER)&context->buffer[index], (POINTER)&input[i],inputLen-i);
}

void MD5Final (unsigned char digest[16],MD5_CONTEXT *context)                                       /* context */
{
	unsigned char bits[8];
	unsigned int index, padLen;

	Encode (bits, context->count, 8);

	index = (unsigned int)((context->count[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	MD5Update (context, PADDING, padLen);

	MD5Update (context, bits, 8);
	Encode (digest, context->state, 16);

	MD5_memset ((POINTER)context, 0, sizeof (*context));

}

bool GetMD5Signature16(const char *filepath, unsigned char bMD5Signature[16], LARGE_INTEGER &lFileSize)
{ 
	FILE *file;
	MD5_CONTEXT context;
	int len;
	unsigned char buffer[1024] = {0};
	unsigned char digest[16] = {0};

	lFileSize.QuadPart = 0;

	if(fopen_s(&file, filepath, "rb"))
		return false;

	MD5Init(&context);
	while(len = (int)fread(buffer, 1, 1024, file))
	{
		lFileSize.QuadPart += len;
		MD5Update (&context, buffer, len);
	}
	MD5Final(digest, &context);
	fclose (file);

	memcpy(bMD5Signature, digest, 16);

	return true;
}

bool GetMD5Signature16(const char *filepath, unsigned char bMD5Signature[16])
{ 
	FILE *file;
	MD5_CONTEXT context;
	int len;
	unsigned char buffer[1024] = {0};
	unsigned char digest[16] = {0};

	if(fopen_s(&file, filepath, "rb"))
		return false;

	MD5Init(&context);
	while(len = (int)fread(buffer, 1, 1024, file))
	{
		MD5Update (&context, buffer, len);
	}
	MD5Final(digest, &context);
	fclose (file);

	memcpy(bMD5Signature, digest, 16);

	return true;
}

bool GetMD5Signature32(const char *filepath, char *cMD5Signature)
{
	FILE *file;
	MD5_CONTEXT context;
	int len;
	unsigned char buffer[1024] = {0};
	unsigned char digest[16] = {0};

	if(fopen_s(&file, filepath, "rb"))
		return false;

	MD5Init(&context);
	while(len = (int)fread(buffer, 1, 1024, file))
	{
		MD5Update (&context, buffer, len);
	}
	MD5Final(digest, &context);
	fclose (file);

	char buff[3] = {0};
	memset(cMD5Signature, 0, sizeof(cMD5Signature));
	for(int iCount=0; iCount < 16; iCount++)
	{
		sprintf_s(buff, 3, "%02x", digest[iCount]);
		strcat_s(cMD5Signature, 33, buff);
	}
	return true;
}

int MDFile(HANDLE hFile, BYTE *Signature, unsigned char *buffer, const int iSizeOfBuffer)
{ 
	MD5_CONTEXT context;
	DWORD dwReadBytes = 1;
	unsigned char digest[16] = {0};

	MD5Init (&context);
	while(ReadFile(hFile, buffer, iSizeOfBuffer, &dwReadBytes, NULL) && dwReadBytes)
	{
		MD5Update (&context, buffer, dwReadBytes);
	}
	MD5Final (digest, &context);

	memcpy_s(Signature, 16, digest, 16);
	return 1;
}

int MDFile15MBLimit(HANDLE hFile, BYTE *Signature, unsigned char *buffer, const int iSizeOfBuffer)
{ 
	MD5_CONTEXT context;
	DWORD dwReadBytes = 1;
	unsigned char digest[16] = {0};
	ULONG64 ulFileRead = 0;
	const ULONG64 ul15MBLimit = 15728640; //1048576 * 15;		//15 MB file size limit!

	MD5Init (&context);
	while(ReadFile(hFile, buffer, iSizeOfBuffer, &dwReadBytes, NULL) && dwReadBytes)
	{
		ulFileRead += dwReadBytes;
		MD5Update (&context, buffer, dwReadBytes);
		if(ulFileRead == ul15MBLimit)	// 15 MB limit		//A maximum of 240 loop's will automatically make a 15MB file signature!
		{
			break;
		}
	}
	MD5Final (digest, &context);

	memcpy_s(Signature, 16, digest, 16);
	return 1;
}

int MD5Buffer(LPBYTE byData, SIZE_T cbData, LPBYTE byMD5_16Bytes, SIZE_T cbMD5_16Bytes)
{ 
	if(cbMD5_16Bytes < 16)
	{
		return FALSE;
	}

	MD5_CONTEXT context = {0};
	MD5Init(&context);
	MD5Update(&context, byData, (UINT)cbData);
	MD5Final(byMD5_16Bytes, &context);
	return TRUE;
}

int MDFile(HANDLE hFile, LPBYTE byMD5_16Bytes, SIZE_T cbMD5_16Bytes, DWORD dwOffset)
{
	HANDLE hProcHeap = 0;
	LPBYTE byReadBuffer = 0;
	DWORD cbReadBuffer = 64 * 1024;

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, dwOffset, 0, FILE_BEGIN))
	{
		return FALSE;
	}

	hProcHeap = GetProcessHeap();
	if(NULL == hProcHeap)
	{
		return FALSE;
	}

	byReadBuffer = (LPBYTE)HeapAlloc(hProcHeap, HEAP_ZERO_MEMORY, cbReadBuffer);
	if(NULL == byReadBuffer)
	{
		return FALSE;
	}

	if(FALSE == MDFile(hFile, byMD5_16Bytes, byReadBuffer, cbReadBuffer))
	{
		HeapFree(hProcHeap, 0, byReadBuffer);
		return FALSE;
	}

	HeapFree(hProcHeap, 0, byReadBuffer);
	return TRUE;
}

/*create 2 md5s, 1st of full file and 2nd till 15mb if the file is greater than 15mb size
 if the file is smaller than 15mb and both md5 are asked for, both md5 are of full file hence same
3 optional values for full file md5
PULONG64 pulMD5_8by	-	pointer to ULONG64 which gets md5 of full file, pass null if not required
LPBYTE byMD5_16by	-	array of BYTE[16] which gets md5 of full file, pass null if not required
LPTSTR szMD5_33by	-	array of TCHARS[33] which gets md5 of full file, pass null if not required

3 optional values for 15mb file md5
PULONG64 pulMD5_15MB_8by-	pointer to ULONG64 which gets md5 of file till 15mb, pass null if not required
LPBYTE byMD5_15MB_16by	-	array of BYTE[16] which gets md5 of file till 15mb, pass null if not required
LPTSTR szMD5_15MB_33by	-	array of TCHARS[33] which gets md5 of file till 15mb, pass null if not required
*/
int GetMD5(HANDLE hFile, LPBYTE byRdBuf, SIZE_T cbRdBuf, PULONG64 pulMD5_8by, LPBYTE byMD5_16by,
		   LPTSTR szMD5_33by, LPSTR szMD5_33byA, PULONG64 pulMD5_15MB_8by, LPBYTE byMD5_15MB_16by,
		   LPTSTR szMD5_15MB_33by, LPSTR szMD5_15MB_33byA)
{
	MD5_CONTEXT Context;
	bool bMemAllocated = false, bSuccess = true, bPartialMD5Made = false;
	BYTE byMD5Part[20] = {0};
	ULONG64 ulTotalBytesToRead = 0, ulTotalBytesRead = 0, ulPartialMD5Limit = 1024 * 1024 * 15;
	DWORD dwBytesToRead = 0, dwBytesRead = 0;

	if(!pulMD5_15MB_8by && !byMD5_15MB_16by && !szMD5_15MB_33by)
	{
		bPartialMD5Made = true;
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, 0, 0, FILE_BEGIN))
	{
		return FALSE;
	}

	if(NULL == byRdBuf)
	{
		byRdBuf = (LPBYTE) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 64);
		if(NULL == byRdBuf)
		{
			return FALSE;
		}

		cbRdBuf = 1024 * 64;
		bMemAllocated = true;
	}

	ulTotalBytesToRead = GetFileSize(hFile, &dwBytesToRead);
	ulTotalBytesToRead |= ((ULONG64)dwBytesToRead)<<32;

	MD5Init(&Context);
	while(ulTotalBytesRead < ulTotalBytesToRead)
	{
		if((ulTotalBytesToRead - ulTotalBytesRead) > ((ULONG64)cbRdBuf))
		{
			dwBytesToRead = (DWORD)cbRdBuf;
		}
		else
		{
			dwBytesToRead = (DWORD)(ulTotalBytesToRead - ulTotalBytesRead);
		}

		if(!ReadFile(hFile, byRdBuf, dwBytesToRead, &dwBytesRead, 0))
		{
			bSuccess = false;
			break;
		}

		if(dwBytesToRead != dwBytesRead)
		{
			bSuccess = false;
			break;
		}

		if(!bPartialMD5Made && ((ulTotalBytesRead + dwBytesRead) >= ulPartialMD5Limit))
		{
			MD5_CONTEXT ContextPartial;
			DWORD dwRemaining = (DWORD)((ulTotalBytesRead + dwBytesRead) - ulPartialMD5Limit);

			memcpy(&ContextPartial, &Context, sizeof(Context));
			dwRemaining = dwBytesRead - dwRemaining;
			MD5Update(&ContextPartial, byRdBuf, dwRemaining);
			MD5Final(byMD5Part, &ContextPartial);
			bPartialMD5Made = true;

			if(pulMD5_15MB_8by)
			{
#ifdef _PARTIAL_MD5_CRC64_
				CreateCRC64Buffer(byMD5Part, 16, *pulMD5_15MB_8by);
#endif
			}

			if(byMD5_15MB_16by)
			{
				memcpy(byMD5_15MB_16by, byMD5Part, 16);
			}

			if(szMD5_15MB_33by)
			{
				for(int i = 0; i < 16; i++)
				{
					_stprintf_s(szMD5_15MB_33by + (i * 2), (33 * sizeof(TCHAR)) - (i * 2), _T("%02X"), byMD5Part[i]);
				}
			}

			if(szMD5_15MB_33byA)
			{
				for(int i = 0; i < 16; i++)
				{
					sprintf_s(szMD5_15MB_33byA + (i * 2), (33 * sizeof(CHAR)) - (i * 2), "%02X", byMD5Part[i]);
				}
			}

		}

		MD5Update(&Context, byRdBuf, dwBytesRead);
		ulTotalBytesRead += dwBytesRead;
	}

	if(bMemAllocated)
	{
		HeapFree(GetProcessHeap(), 0, byRdBuf);
		cbRdBuf = 0;
		byRdBuf = NULL;
	}

	return bSuccess;
}

int GetMD5(LPCTSTR szFilePath, LPBYTE byRdBuf, SIZE_T cbRdBuf, PULONG64 pulMD5_8by, LPBYTE byMD5_16by,
		   LPTSTR szMD5_33by, LPSTR szMD5_33byA, PULONG64 pulMD5_15MB_8by, LPBYTE byMD5_15MB_16by,
		   LPTSTR szMD5_15MB_33by, LPSTR szMD5_15MB_33byA)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;

	hFile = CreateFile(szFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return FALSE;
	}

	if(!GetMD5(hFile, byRdBuf, cbRdBuf, pulMD5_8by, byMD5_16by, szMD5_33by, szMD5_33byA, pulMD5_15MB_8by, byMD5_15MB_16by, szMD5_15MB_33by, szMD5_15MB_33byA))
	{
		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile);
	return TRUE;
}
