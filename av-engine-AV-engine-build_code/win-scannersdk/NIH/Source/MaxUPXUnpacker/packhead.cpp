
/* packhead.cpp --

   This file is part of the UPX executable compressor.

   Copyright (C) 1996-2010 Markus Franz Xaver Johannes Oberhumer
   Copyright (C) 1996-2010 Laszlo Molnar
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   Markus F.X.J. Oberhumer              Laszlo Molnar
   <markus@oberhumer.com>               <ml1050@users.sourceforge.net>
 */


#include "conf.h"
#include "packer.h"
#include "MaxPEFile.h"
#include "file.h"

//extern CMaxPEFile fi->m_pInputFile.;
//extern bool fi->m_bCavityFlag;
//extern DWORD fi->m_dwCodeOffset;
//extern DWORD fi->m_dwSigOffset;
//extern bool fi->m_bLZMA;

/*************************************************************************
// PackHeader
//
// We try to be able to unpack UPX 0.7x (versions 8 & 9) and at
// least to detect older versions, so this is a little bit messy.
**************************************************************************/

PackHeader::PackHeader() :
    version(-1), format(-1)
{
}


/*************************************************************************
// simple checksum for the header itself (since version 10)
**************************************************************************/

static unsigned char get_packheader_checksum(const upx_bytep buf, int len)
{
    //assert(get_le32(buf) == UPX_MAGIC_LE32);
    //printf("1 %d\n", len);
    buf += 4;
    len -= 4;
    unsigned c = 0;
    while (len-- > 0)
        c += *buf++;
    c %= 251;
    //printf("2 %d\n", c);
    return (unsigned char) c;
}


/*************************************************************************
//
**************************************************************************/

int PackHeader::getPackHeaderSize() const
{
    if (format < 0 || version < 0)
        throwInternalError("getPackHeaderSize");

    int n = 0;
    if (version <= 3)
        n = 24;
    else if (version <= 9)
    {
        if (format == UPX_F_DOS_COM || format == UPX_F_DOS_SYS)
            n = 20;
        else if (format == UPX_F_DOS_EXE || format == UPX_F_DOS_EXEH)
            n = 25;
        else
            n = 28;
    }
    else
    {
        if (format == UPX_F_DOS_COM || format == UPX_F_DOS_SYS)
            n = 22;
        else if (format == UPX_F_DOS_EXE || format == UPX_F_DOS_EXEH)
            n = 27;
        else
            n = 32;
    }
    if (n < 20)
        throwCantUnpack("unknown header version");
    return n;
}


/*************************************************************************
// see stub/header.ash
**************************************************************************/

void PackHeader::putPackHeader(upx_bytep p)
{
    assert(get_le32(p) == UPX_MAGIC_LE32);
    if (get_le32(p+4) != UPX_MAGIC2_LE32)
    {
        //fprintf(stderr, "MAGIC2_LE32: %x %x\n", get_le32(p+4), UPX_MAGIC2_LE32);
        throwBadLoader();
    }

    int size = 0;
    int old_chksum = 0;

    // the new variable length header
    if (format < 128)
    {
        if (format == UPX_F_DOS_COM || format == UPX_F_DOS_SYS)
        {
            size = 22;
            old_chksum = get_packheader_checksum(p, size - 1);
            set_le16(p+16,u_len);
            set_le16(p+18,c_len);
            p[20] = (unsigned char) filter;
        }
        else if (format == UPX_F_DOS_EXE)
        {
            size = 27;
            old_chksum = get_packheader_checksum(p, size - 1);
            set_le24(p+16,u_len);
            set_le24(p+19,c_len);
            set_le24(p+22,u_file_size);
            p[25] = (unsigned char) filter;
        }
        else if (format == UPX_F_DOS_EXEH)
        {
            throwInternalError("invalid format");
        }
        else
        {
            size = 32;
            old_chksum = get_packheader_checksum(p, size - 1);
            set_le32(p+16,u_len);
            set_le32(p+20,c_len);
            set_le32(p+24,u_file_size);
            p[28] = (unsigned char) filter;
            p[29] = (unsigned char) filter_cto;
            assert(n_mru == 0 || (n_mru >= 2 && n_mru <= 256));
            p[30] = (unsigned char) (n_mru ? n_mru - 1 : 0);
        }
        set_le32(p+8,u_adler);
        set_le32(p+12,c_adler);
    }
    else
    {
        size = 32;
        old_chksum = get_packheader_checksum(p, size - 1);
        set_be32(p+8,u_len);
        set_be32(p+12,c_len);
        set_be32(p+16,u_adler);
        set_be32(p+20,c_adler);
        set_be32(p+24,u_file_size);
        p[28] = (unsigned char) filter;
        p[29] = (unsigned char) filter_cto;
        assert(n_mru == 0 || (n_mru >= 2 && n_mru <= 256));
        p[30] = (unsigned char) (n_mru ? n_mru - 1 : 0);
    }

    p[4] = (unsigned char) version;
    p[5] = (unsigned char) format;
    p[6] = (unsigned char) method;
    p[7] = (unsigned char) level;

    // header_checksum
    assert(size == getPackHeaderSize());
    // check old header_checksum
    if (p[size - 1] != 0)
    {
        if (p[size - 1] != old_chksum)
        {
            //printf("old_checksum: %d %d\n", p[size - 1], old_chksum);
            throwBadLoader();
        }
    }
    // store new header_checksum
    p[size - 1] = get_packheader_checksum(p, size - 1);
}


/*************************************************************************
//
**************************************************************************/

bool PackHeader::fillPackHeader(const upx_bytep buf, int blen,InputFile *fi)
{	
	
 if (fi->m_dwSigOffset < 0 || fi->m_dwSigOffset > 0x30)
	{
		BYTE byfilter_offset=0x00;;
		BYTE byBuff[0x0F]={0};
		if(fi->m_bLZMA)
		{
			if(fi->m_pInputFile.ReadBuffer(byBuff,fi->m_pInputFile.m_dwAEPMapped+fi->m_dwCodeOffset+0x04,sizeof(byBuff),sizeof(byBuff)))
			{
				u_len=*(DWORD*)&byBuff[0];
				c_len=*(DWORD*)&byBuff[0xA];
				method=0x0E;
				//fi->m_bCavityFlag=true;
				if(fi->m_pInputFile.ReadBuffer(byBuff,fi->m_pInputFile.m_dwAEPMapped+fi->m_dwCodeOffset+0x03+0xAC8,sizeof(byBuff),sizeof(byBuff)))
				{
					DWORD dwCounter=0x00;
					while(dwCounter<sizeof(byBuff)-0x03)
					{
						if(*(WORD*)&byBuff[dwCounter]==0x3F80 && byBuff[dwCounter+0x03]==0x75)
						{
							level=byBuff[dwCounter+2];
							filter=0x26;
							filter_cto=byBuff[dwCounter+2];
							fi->m_bLZMA=false;
							return true;
						}
						dwCounter++;
					}
				}
				fi->m_bLZMA=true;
				level=0x00;
				filter=0x00;
				filter_cto=0x00;
				return true;
			}
			else
			{
				return false;
			}
		}
		else if(!fi->m_pInputFile.ReadBuffer(byBuff,fi->m_pInputFile.m_dwAEPMapped+fi->m_dwCodeOffset+0x44,0x05,0x05))
		{
			return false;
		}
		
		if(byBuff[0]==0x01 && *(WORD*)&byBuff[1]==0x75DB)
		{
			byfilter_offset=0xED;
			method=0x08;
		}
		else if(byBuff[0]==0x31 && *(WORD*)&byBuff[1]==0x83C9)
		{
			byfilter_offset=0xE1;
			method=0x05;
		}
		else if(byBuff[0]==0x74 && *(WORD*)&byBuff[2]==0xC589)
		{
			byfilter_offset=0xCD;
			method=0x02;
		}		
		else
		{
			return false;
		}
		level=0x05;
		filter=0x26;
		filter_cto=0x00;
		
        if(fi->m_pInputFile.ReadBuffer(byBuff,fi->m_pInputFile.m_dwAEPMapped+fi->m_dwCodeOffset+byfilter_offset,0x01,0x01))
		{
          filter_cto=byBuff[0];
		}
		u_len = fi->m_pInputFile.m_stSectionHeader[0].Misc.VirtualSize+fi->m_pInputFile.m_stSectionHeader[1].Misc.VirtualSize;
		if(wcsstr(fi->m_pInputFile.m_szFilePath,L".tmp") != NULL && fi->m_pInputFile.m_stSectionHeader[0].SizeOfRawData != 0)
		{
			c_len = fi->m_pInputFile.m_stSectionHeader[0].Misc.VirtualSize;
		}
		else
		{
			c_len = fi->m_pInputFile.m_stSectionHeader[1].Misc.VirtualSize;
			if(c_len >= fi->m_pInputFile.m_dwFileSize)
			{
				c_len=fi->m_pInputFile.m_stSectionHeader[1].SizeOfRawData;
			}
		}
		fi->m_bCavityFlag=true;
		return true;
	}

    if (fi->m_dwSigOffset + 8 <= 0 || (int)fi->m_dwSigOffset + 8 > blen)
        throwCantUnpack("header corrupted 1");

    const upx_bytep p = &buf[fi->m_dwSigOffset];

    version = p[4];
    format = p[5];
    method = p[6];
    level = p[7];
    filter_cto = 0;

    const int size = getPackHeaderSize();
    if (fi->m_dwSigOffset + size <= 0 || fi->m_dwSigOffset + size > blen)
        throwCantUnpack("header corrupted 2");

    //
    // decode the new variable length header
    //

    int off_filter = 0;
    if (format < 128)
    {
        u_adler = get_le32(p+8);
        c_adler = get_le32(p+12);
        if (format == UPX_F_DOS_COM || format == UPX_F_DOS_SYS)
        {
            u_len = get_le16(p+16);
            c_len = get_le16(p+18);
            u_file_size = u_len;
            off_filter = 20;
        }
        else if (format == UPX_F_DOS_EXE || format == UPX_F_DOS_EXEH)
        {
            u_len = get_le24(p+16);
            c_len = get_le24(p+19);
            u_file_size = get_le24(p+22);
            off_filter = 25;
        }
        else
        {
            u_len = get_le32(p+16);
            c_len = get_le32(p+20);
			if(u_len==c_len && (fi->m_dwSigOffset!=0x20) || u_len == 0x01010101)
			{
				u_len = fi->m_pInputFile.m_stSectionHeader[0].Misc.VirtualSize + fi->m_pInputFile.m_stSectionHeader[1].Misc.VirtualSize;
				if(wcsstr(fi->m_pInputFile.m_szFilePath, L".tmp") != NULL && fi->m_pInputFile.m_stSectionHeader[0].SizeOfRawData != 0x00)
				{
					c_len = fi->m_pInputFile.m_stSectionHeader[0].Misc.VirtualSize;
				}
				else
				{
					c_len = fi->m_pInputFile.m_stSectionHeader[1].SizeOfRawData;
				}
			}

            u_file_size = get_le32(p+24);
            off_filter = 28;
            filter_cto = p[29];
            n_mru = p[30] ? 1 + p[30] : 0;
        }
    }
    else
    {
        u_len = get_be32(p+8);
        c_len = get_be32(p+12);
        u_adler = get_be32(p+16);
        c_adler = get_be32(p+20);
        u_file_size = get_be32(p+24);
        off_filter = 28;
        filter_cto = p[29];
        n_mru = p[30] ? 1 + p[30] : 0;
    }

    if (version >= 10)
        filter = p[off_filter];
    else if ((level & 128) == 0)
        filter = 0;
    else
    {
        // convert old flags to new filter id
        level &= 127;
        if (format == UPX_F_DOS_COM || format == UPX_F_DOS_SYS)
            filter = 0x06;
        else
            filter = 0x26;
    }
    level &= 15;

    //
    // now some checks
    //

    if (version == 0xff)
        throwCantUnpack("cannot unpack UPX ;-)");

    // check header_checksum
    /*if (version > 9)
        if (p[size - 1] != get_packheader_checksum(p, size - 1))
            throwCantUnpack("header corrupted 3");*/

    //
    // success
    //

    this->buf_offset = fi->m_dwSigOffset;
    return true;
}


/*
vi:ts=4:et:nowrap
*/

