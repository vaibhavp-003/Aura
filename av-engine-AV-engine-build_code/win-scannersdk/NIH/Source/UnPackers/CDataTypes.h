/*======================================================================================
FILE             : CDataTypes.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : 
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
	CREATION DATE    : 12/25/2009 3:15:15 PM
	NOTES		     : Defins the Common Datatypes
	VERSION HISTORY  : 
	======================================================================================*/
#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>

//#include "pstdint.h"
#ifdef __cplusplus
extern "C" {
#endif

#define	HAVE_PRAGMA_PACK	1

	/**********typedef*******************/
	typedef unsigned char uint8_t;
	typedef unsigned short uint16_t;    
	typedef signed short int16_t;
	//typedef unsigned int uint32_t;
	//typedef signed int int32_t;
	typedef unsigned long long uint64_t;
	typedef unsigned char Byte;
	typedef unsigned short UInt16;
	typedef unsigned int UInt32;
	typedef UInt32 SizeT;
	typedef	long	off_t;
	/**********typedef*******************/

	extern uint8_t Debug_Flag, LeaveTemps_Flag;

	/**********Structs*******************/
	struct Max_Exe_Sections {
		uint32_t rva;
		uint32_t vsz;
		uint32_t raw;
		uint32_t rsz;
		uint32_t chr;
		uint32_t urva; /* PE - unaligned VirtualAddress */
		uint32_t uvsz; /* PE - unaligned VirtualSize */
		uint32_t uraw; /* PE - unaligned PointerToRawData */
		uint32_t ursz; /* PE - unaligned SizeOfRawData */
	};

	typedef struct {
		const char **virname;
		unsigned long int *scanned;
		const struct cl_Matcher *root;
		const struct cl_engine *engine;
		const struct cl_limits *limits;
		unsigned int options;
		unsigned int arec;
		unsigned int mrec;
		unsigned int found_possibly_unwanted;
		struct cl_dconf *dconf;
	} Max_Ctx;

	typedef struct bitset_tag
	{
		unsigned char *bitset;
		unsigned long length;
	} bitset_t;


	/**********Structs*******************/

	/**********#Define*******************/
#define WORDS_BIGENDIAN 0
#define CL_EIO		-123 /* general I/O error */

#define EC32(x) le32_to_host(x) /* Convert little endian to host */
#define EC16(x) le16_to_host(x)

	/* lower and upper bondary alignment (size vs offset) */
#define PEALIGN(o,a) (((a))?(((o)/(a))*(a)):(o))
#define PESALIGN(o,a) (((a))?(((o)/(a)+((o)%(a)!=0))*(a)):(o))

#define ReadInt32(buff) (*(const int32_t *)(buff))
#define WriteInt32(offset, value) (*(uint32_t *)(offset)=(uint32_t)(value))

#define CompareBuffer(bb, bb_size, sb, sb_size)	\
	(bb_size > 0 && sb_size > 0 && sb_size <= bb_size	\
	&& sb >= bb && sb + sb_size <= bb + bb_size && sb + sb_size > bb)

#define CompareBuffer2(bb, bb_size, sb, sb_size)	\
	(bb_size > 0 && sb_size >= 0 && sb_size <= bb_size	\
	&& sb >= bb && sb + sb_size <= bb + bb_size && sb + sb_size >= bb)

//#define MAX_ALLOCATION 184549376
#define MAX_ALLOCATION 15 * 1024 * 1024


#define le16_to_host(v)	(v)
#define le32_to_host(v)	(v)
#define le64_to_host(v)	(v)
#define	be16_to_host(v)	((v >> 8) | ((v & 0xFF) << 8))
#define	be32_to_host(v)	((v >> 24) | ((v & 0x00FF0000) >> 8) | \
	((v & 0x0000FF00) << 8) | (v << 24))
#define be64_to_host(v)	((v >> 56) | ((v & 0x00FF000000000000LL) >> 40) | \
	((v & 0x0000FF0000000000LL) >> 24) | \
	((v & 0x000000FF00000000LL) >> 8) |  \
	((v & 0x00000000FF000000LL) << 8) |  \
	((v & 0x0000000000FF0000LL) << 24) | \
	((v & 0x000000000000FF00LL) << 40) | \
	(v << 56))

#define CL_CLEAN	0   /* no virus found */
#define CL_VIRUS	1   /* virus(es) found */
#define CL_SUCCESS	CL_CLEAN
#define CL_BREAK	2
#define CL_EZIP		-104 /* zip handler error */
#define CL_ENULLARG	-111 /* null argument */
#define CL_EMEM		-114 /* memory allocation error */
#define CL_EOPEN	-115 /* file open error */
#define CL_EIO		-123 /* general I/O error */
#define CL_EFORMAT	-124 /* bad format or broken file */
#define CL_ESUPPORT	-125 /* not supported data format */
#define CL_EUNPACK 6
#define CL_ESEEK 12
#define CL_EWRITE 13

	/* used by: spin, yc (C) aCaB */
#define MAX_ROL(a,b) a = ( a << (b % (sizeof(a)<<3) ))  |  (a >> (  (sizeof(a)<<3)  -  (b % (sizeof(a)<<3 )) ) )
#define MAX_ROR(a,b) a = ( a >> (b % (sizeof(a)<<3) ))  |  (a << (  (sizeof(a)<<3)  -  (b % (sizeof(a)<<3 )) ) )
#define MAX_SRS(n,s) (((n)>>(s)) ^ (1<<(sizeof(n)*8-1-s)) - (1<<(sizeof(n)*8-1-s)))
#define MAX_SAR(n,s) n = MAX_SRS(n,s)

#define _W32_FT_OFFSET (116444736000000000ULL)
	/**********#Define*******************/

	void WarningMsg(const char *str, ...);
	void ErrorMessage(const char *str, ...);
	void DBGMessage(const char *str, ...);
	void *MaxMalloc(size_t nmemb);
	void *MaxCalloc(size_t nmemb, size_t size);
	void *MaxRealloc(void *ptr, size_t size);
	void *MaxRealloc2(void *ptr, size_t size);
	char *Max_Strdup(const char *s);
	int Max_Readn( int fd, void *buff, unsigned int count);
	unsigned int RandumNum(unsigned int max);

#ifdef __cplusplus
}
#endif
