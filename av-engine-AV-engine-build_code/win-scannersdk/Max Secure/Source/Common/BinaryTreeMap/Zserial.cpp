/*======================================================================================
   FILE			: zserial.cpp 
   ABSTRACT		: Base class for all classes serializable to standard iostreams
   DOCUMENTS	: Reffer The Design Folder (FastMap Design.Doc)
   AUTHOR		: Dipali Pawar
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C)Aura:
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				without the prior written permission of Aura
   CREATION DATE: 1/sep/2007
   NOTES		:
   VERSION HISTORY	:
					Version: 19-jan-08
					Resourec:Darshan
					Description: Added unicode and X64 support
 ======================================================================================*/

#include "zserial.h"                  

/*-------------------------------------------------------------------------------------
	Function		: zSerial
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Constructor
	Author			: Dipali
--------------------------------------------------------------------------------------*/
zSerial::zSerial()
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~zSerial
	In Parameters	: -
	Out Parameters	: -
	Purpose			: destructor
	Author			: Dipali
--------------------------------------------------------------------------------------*/
zSerial::~zSerial()
{
}

/*-------------------------------------------------------------------------------------
	Function		: Store
	In Parameters	: NQ wostream* ostrm - ostream
	Out Parameters	: int - 1/0
	Purpose			: store the object into the stream.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int zSerial::Store(NQ wostream* ostrm)
{
    return 1;       // indicate success unless overridden
}

/*-------------------------------------------------------------------------------------
	Function		: Load
	In Parameters	: NQ wostream* istrm - istream
	Out Parameters	: int - 1/0
	Purpose			: load the object from the stream.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int zSerial::Load(NQ wistream* istrm)
{
    return 1;       // indicate success unless overridden
}

/*-------------------------------------------------------------------------------------
	Function		: streamWrite
	In Parameters	: NQ wostream* strm - ostream
					  const TCHAR* addr - input
	Out Parameters	: int - 1/0
	Purpose			: variable-length write for strings.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int zSerial::streamWrite(NQ wostream* strm, const TCHAR* addr)
{
    long len = (long)(wcslen(addr) + 1);    // write null terminator too
    return streamWrite(strm, (void*)addr, len);
}

/*-------------------------------------------------------------------------------------
	Function		: streamWrite
	In Parameters	: NQ wostream* strm - ostream
					  const TCHAR* addr - input
					  long len - length
	Out Parameters	: int - 1/0
	Purpose			: fixed-length write for strings.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int zSerial::streamWrite(NQ wostream* strm, void* addr, long len)
{
    strm->write((const TCHAR*)addr, (int)len);
    return strm->good();
}

/*-------------------------------------------------------------------------------------
	Function		: streamRead
	In Parameters	: NQ wistream* strm - istream
					  void* buf - output buffer
					  long bufSize - length
	Out Parameters	: int - 1/0
	Purpose			: fixed-length read for structs etc.
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int zSerial::streamRead(NQ wistream* strm, void* buf, long bufSize)
{
    strm->read((TCHAR*)buf, (int)bufSize);
    return (strm->good() && !strm->eof()) ? 1 : 0;
}

/*-------------------------------------------------------------------------------------
	Function		: streamRead
	In Parameters	: NQ wistream* strm - istream
					  void* buf - output buffer
					  long bufSize - length
					  long& bytesRead - actual bytes read
	Out Parameters	: int - 1/0
	Purpose			: variable-length read for strings.
					  (note: getline() appears buggy for zero delimiter.)
	Author			: Dipali
--------------------------------------------------------------------------------------*/
int zSerial::streamRead(NQ wistream* strm, TCHAR* buf, long bufSize, long& bytesRead)
{
    TCHAR* ptr = (TCHAR*)buf;
    bytesRead = 0;
    int success = 1;
    int c;
    while (bufSize && success)
    {
        c = strm->get();
        success = (strm->good() && !strm->eof()) ? 1 : 0;
        if (success)
        {
            *ptr++ = c;
            bufSize--;
            bytesRead++;
            if (!c)
                break;          // encountered null terminator
        }
    }
    return success;
}
