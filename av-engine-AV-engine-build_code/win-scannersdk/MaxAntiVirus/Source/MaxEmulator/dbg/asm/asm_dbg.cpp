/*
 *
 *  Copyright (C) 2010-2011 Amr Thabet <amr.thabet@student.alx.edu.eg>
 *
 *  This program is free_emu software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to Amr Thabet 
 *  amr.thabet@student.alx.edu.eg
 *
 */
 
#include "pch.h"
#include "../../x86emu.h"

int AsmDebugger::AddBp(string s)
{
    bp[nbp].ptr = parser(s); 
    bp[nbp].state=BP_RUN;
    nbp++;
    return (nbp-1);
}

bool AsmDebugger::TestBp(int num, Thread& thread, ins_disasm* ins)
{
    if ((DWORD)num>=nbp)
	{
		return false;        //outside the limits
	}
	int b = 0;	
	CheckBreakPoint((MAX_DWORD)bp[num].ptr, (MAX_DWORD)&thread, (MAX_DWORD)ins, &b);
    if (b!=0)
	{
		return true;
	}
    return false;
}

bool AsmDebugger::TestBp(Thread& thread,ins_disasm* ins)
{    
    for(DWORD n = 0; n < nbp; n++)
	{
        if (bp[n].state == BP_RUN)
		{
			int b = 0;
            CheckBreakPoint((MAX_DWORD)bp[n].ptr, (MAX_DWORD)&thread, (MAX_DWORD)ins, &b);
			if (b != 0)
			{
				return true;
			}
        }        
    }
    return false;
}

AsmDebugger::AsmDebugger(Process& c)
{
   process = &c;
   func_entries = 0;
   init_funcs();
   nbp=0;
   lasterror="";
}

int AsmDebugger::ModifiedBp(string s, DWORD n)
{
	if(n >=nbp || bp[n].ptr == 0)
	{
		return -1;
	}
	else
	{
		VirtualFree((void*)bp[n].ptr, 0, MEM_RELEASE);
		bp[n].ptr = NULL;
	}

	bp[n].ptr = parser(s); 
	bp[nbp].state=BP_RUN;
	return (n);
}

AsmDebugger::~AsmDebugger()
{
	for(DWORD i=0; i<nbp; i++)
	{
		VirtualFree((void*)bp[i].ptr, 0, MEM_RELEASE);
		bp[i].ptr = NULL;
	}
}

Debugger::~Debugger()
{
}
