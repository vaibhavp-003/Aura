
/*======================================================================================
FILE             : Packers.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Siddharam Pujari
COMPANY		     : Aura 
COPYRIGHT(NOTICE): (C) Aura
				    Created as an unpublished copyright work.  All rights reserved.
                    This document and the information it contains is confidential and
				    proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura.	

CREATION DATE    : 12/19/2009 4:56:49 PM
NOTES		     : Header File for All packers
VERSION HISTORY  : 
======================================================================================*/
#pragma once

#include "CDataTypes.h"
#include "LzmaDecode.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**************MEW*****************/
	int Mew_Lzma(char *, char *, uint32_t, uint32_t, uint32_t);
	int UnPackMEW(char *, char *, int, int, char **, char **);
	int UnPackMEW11(char *src, int off, int ssize, int dsize, uint32_t base, uint32_t vadd, int uselzma, void* filedesc);


	/**************FSG******************/
	int UnFSG(char *, char *, int, int, char **, char **);
	int UnPackFSG200(char *, char *, int, int, uint32_t, uint32_t, uint32_t, void *);
	int UnPackFSG133(char *, char *, int , int, struct Max_Exe_Sections *, int, uint32_t, uint32_t, void *);


	/******************************UPX*************************************/
#define FILEBUFF 8192

#define UPX_NRV2B "\x11\xdb\x11\xc9\x01\xdb\x75\x07\x8b\x1e\x83\xee\xfc\x11\xdb\x11\xc9\x11\xc9\x75\x20\x41\x01\xdb"
#define UPX_NRV2D "\x83\xf0\xff\x74\x78\xd1\xf8\x89\xc5\xeb\x0b\x01\xdb\x75\x07\x8b\x1e\x83\xee\xfc\x11\xdb\x11\xc9"
#define UPX_NRV2E "\xeb\x52\x31\xc9\x83\xe8\x03\x72\x11\xc1\xe0\x08\x8a\x06\x46\x83\xf0\xff\x74\x75\xd1\xf8\x89\xc5"
#define UPX_LZMA1 "\x56\x83\xc3\x04\x53\x50\xc7\x03\x03\x00\x02\x00\x90\x90\x90\x55\x57\x56\x53\x83"
#define UPX_LZMA2 "\x56\x83\xc3\x04\x53\x50\xc7\x03\x03\x00\x02\x00\x90\x90\x90\x90\x90\x55\x57\x56"


	int UPX_InflateLzma(char *src, uint32_t ssize, char *dst, uint32_t *dsize, uint32_t upx0, uint32_t upx1, uint32_t ep) ;
	typedef int (*UPXFUNC)(char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t);
	int UPX_Inflate2b(char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t);
	int UPX_Inflate2d(char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t);
	int UPX_Inflate2e(char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t);

	/******************************NSPACK*************************************/
	struct UNSP {
		char *src_curr;
		char *src_end;
		uint32_t bitmap;
		uint32_t oldval;
		int error;
		/* the following are not in the original structure */
		char *table;
		uint32_t tablesz;
	};
	uint32_t UnPackNSPack(char *start_of_stuff, char *dest);
	uint32_t Very_Real_UnPack(uint16_t *, uint32_t, uint32_t, uint32_t, uint32_t, char *, uint32_t, char *, uint32_t);
	uint32_t GetByte(struct UNSP *);
	int GetBit_From_Table(uint16_t *, struct UNSP *);
	uint32_t Get_100_Bits_From_Tablesize(uint16_t *, struct UNSP *, uint32_t);
	uint32_t Get_100_Bits_From_Table(uint16_t *, struct UNSP *);
	uint32_t Get_n_Bits_From_Table(uint16_t *, uint32_t, struct UNSP *);
	uint32_t Get_n_Bits_From_Tablesize(uint16_t *, struct UNSP *, uint32_t);
	uint32_t Get_bb(uint16_t *, uint32_t, struct UNSP *);
	uint32_t Get_BitMap(struct UNSP *, uint32_t);

	/******************************UPACK*************************************/
	int UnPackUPack(int, char *, uint32_t, char *, uint32_t, uint32_t, uint32_t, uint32_t, void*);

	/******************************ASPACK*************************************/
	int UnPackAsPack212(uint8_t *, unsigned int, struct Max_Exe_Sections *, uint16_t, uint32_t, uint32_t, void*);

	/******************************MISC*************************************/
	int GenTempfd(const char *dir, char *name, int *fd);
	int MaxWritten(void* fd, const void *buff, unsigned int count);
	int MaxWrittenMode(int fd, const void *buff, unsigned int count);
	const char *MemStrCompare(const char *haystack, int hs, const char *needle, int ns);
	int __snprintf(char *str,size_t count,const char *fmt,...);
	/******************************WWPACK*************************************/
	int UnPackWWPack(uint8_t *, uint32_t, uint8_t *, struct Max_Exe_Sections *, uint16_t, uint32_t, void*);

	/******************************PETITIE*************************************/
	int PETITE_Inflate2x_1to9(char *buf, uint32_t minrva, uint32_t bufsz, struct Max_Exe_Sections *sections, unsigned int sectcount, uint32_t Imagebase, uint32_t pep, void* desc, int version, uint32_t ResRva, uint32_t ResSize);

	/******************************PESPIN*************************************/
	int UnPackSpin(char *, int, struct Max_Exe_Sections *, int, uint32_t, void *);


	/******************************YODA*************************************/
	int UnPackYoda(char *, unsigned int, struct Max_Exe_Sections *, unsigned int, uint32_t, void *);


	/**********REBUILDPE*************/
	int RebuildFakePE(char *, struct Max_Exe_Sections *, int, uint32_t, uint32_t, uint32_t, uint32_t, void * );

#ifdef __cplusplus
}
#endif

