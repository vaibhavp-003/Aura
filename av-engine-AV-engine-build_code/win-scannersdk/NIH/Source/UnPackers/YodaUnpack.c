
/*======================================================================================
FILE             : YodaUnpack.c
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Siddharam Pujari
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
	CREATION DATE    : 12/19/2009 4:44:40 PM
	NOTES		     : Defines Functinality to Unpack YODA Packer
	VERSION HISTORY  : 
	======================================================================================*/

#include <string.h>
#include "Packers.h"

struct pe_image_file_hdr {
	uint32_t Magic;
	uint16_t Machine;
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp;		    /* unreliable */
	uint32_t PointerToSymbolTable;	    /* debug */
	uint32_t NumberOfSymbols;		    /* debug */
	uint16_t SizeOfOptionalHeader;	    /* == 224 */
	uint16_t Characteristics;
};

#define EC16(x) le16_to_host(x) 

/*--------------------------------------------------------------------------------------
Function       : UnPackYodaPolyEmulator
In Parameters  : char* Decryptor_offset, char* code, unsigned int ecx, 
Out Parameters : static int 
Description    : Unpacks Yoda's Poly Emulator
Author & Date  :
--------------------------------------------------------------------------------------*/
static int UnPackYodaPolyEmulator(char* Decryptor_offset, char* code, unsigned int ecx)
{
	unsigned char al;
	unsigned char cl = ecx & 0xff;
	unsigned int j,i;

	for(i=0;i<ecx;i++) /* Byte looper - Decrypts every byte and write it back */
	{
		al = code[i];

		for(j=0;j<0x30;j++)   /* Poly Decryptor "Emulator" */
		{
			switch(Decryptor_offset[j])
			{

			case '\xEB':	/* JMP short */
				j++;
				j = j + Decryptor_offset[j];
				break;

			case '\xFE':	/* DEC  AL */
				al--;
				j++;
				break;

			case '\x2A':	/* SUB AL,CL */
				al = al - cl;
				j++;
				break;

			case '\x02':	/* ADD AL,CL */
				al = al + cl;
				j++;
				break
					;
			case '\x32':	/* XOR AL,CL */
				al = al ^ cl;
				j++;
				break;
				;
			case '\x04':	/* ADD AL,num */
				j++;
				al = al + Decryptor_offset[j];
				break;
				;
			case '\x34':	/* XOR AL,num */
				j++;
				al = al ^ Decryptor_offset[j];
				break;

			case '\x2C':	/* SUB AL,num */
				j++;
				al = al - Decryptor_offset[j];
				break;


			case '\xC0':
				j++;
				if(Decryptor_offset[j]=='\xC0') /* ROL AL,num */
				{
					j++;
					MAX_ROL(al,Decryptor_offset[j]);
				}
				else			/* ROR AL,num */
				{
					j++;
					MAX_ROR(al,Decryptor_offset[j]);
				}
				break;

			case '\xD2':
				j++;
				if(Decryptor_offset[j]=='\xC8') /* ROR AL,CL */
				{
					j++;
					MAX_ROR(al,cl);
				}
				else			/* ROL AL,CL */
				{
					j++;
					MAX_ROL(al,cl);
				}
				break;

			case '\x90':
			case '\xf8':
			case '\xf9':
				break;

			default:
				DBGMessage("yC: Unhandled opcode %x\n", (unsigned char)Decryptor_offset[j]);
				return 1;
			}
		}
		cl--;
		code[i] = al;
	}
	return 0;

}

/*--------------------------------------------------------------------------------------
Function       : UnPackYoda
In Parameters  : char *fbuf, unsigned int filesize, struct Max_Exe_Sections *sections, unsigned int sectcount, uint32_t peoffset, void* desc, 
Out Parameters : int 
Description    : UNPACKS the Application which is packed by YODA Packer
Author & Date  :
--------------------------------------------------------------------------------------*/
int UnPackYoda(char *fbuf, unsigned int filesize, struct Max_Exe_Sections *sections, unsigned int sectcount, uint32_t peoffset, void* desc)
{
	uint32_t ycsect = sections[sectcount].raw;
	unsigned int i;
	struct pe_image_file_hdr *pe = (struct pe_image_file_hdr*) (fbuf + peoffset);
	char *sname = (char *)pe + EC16(pe->SizeOfOptionalHeader) + 0x18;

	DBGMessage("yodaUnPack: Decrypting Decryptor on sect %d\n", sectcount); 
	if (UnPackYodaPolyEmulator(fbuf + ycsect + 0x93, fbuf + ycsect + 0xc6 ,0xB97))
		return 1;
	filesize-=sections[sectcount].ursz;

	for(i=0;i<sectcount;i++)
	{
		uint32_t name = (uint32_t) ReadInt32(sname+i*0x28);
		if ( !sections[i].raw ||
			!sections[i].rsz ||
			name == 0x63727372 || /* rsrc */
			name == 0x7273722E || /* .rsr */
			name == 0x6F6C6572 || /* relo */
			name == 0x6C65722E || /* .rel */
			name == 0x6164652E || /* .eda */
			name == 0x6164722E || /* .rda */
			name == 0x6164692E || /* .ida */
			name == 0x736C742E || /* .tls */
			(name&0xffff) == 0x4379  /* yC */
			) continue;
		DBGMessage("YodaUnPack: Decrypting sect%d\n",i); 
		if (UnPackYodaPolyEmulator(fbuf + ycsect + 0x457, fbuf + sections[i].raw, sections[i].ursz))
			return 1;
	}

	pe->NumberOfSections=EC16(sectcount);

	memset((char *)pe + sizeof(struct pe_image_file_hdr) + 0x68, 0, 8);

	WriteInt32((char *)pe + sizeof(struct pe_image_file_hdr) + 16, ReadInt32(fbuf + ycsect + 0xa0f));

	WriteInt32((char *)pe + sizeof(struct pe_image_file_hdr) + 0x38, ReadInt32((char *)pe + sizeof(struct pe_image_file_hdr) + 0x38) - sections[sectcount].vsz);

	if (MaxWritten(desc, fbuf, filesize)==-1) {
		DBGMessage("YodaUnPack: Cannot write unpacked file\n");
		return 1;
	}
	return 0;
}
