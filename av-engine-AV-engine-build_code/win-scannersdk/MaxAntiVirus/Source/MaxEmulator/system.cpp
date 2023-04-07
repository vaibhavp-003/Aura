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
#include "x86emu.h"

System::System()
{
	dis_entries = 0;
	dll_entries = 0;
    api_entries = 0;
	opcodes_init();
}
System::System(EnviromentVariables* v)
{
    //1.initialize the opcodes

	dis_entries = 0;

	opcodes_init();

	//2.initalize the environment variables
    init_vars(v);

    //3.initalize the API calls
    dll_entries = 0;
    api_entries = 0;

	init_apis(enVars.dllspath);
}
System::~System() 
{
     for(int i=0;i<dll_entries;i++)
	 {
		 VirtualFree((void*)DLLs[i].imagebase, 0, MEM_RELEASE);
     }
	 FreeTable();
}
int System::init_vars(EnviromentVariables* v)
{
	if (v->kernel32 != 0)
	{
		this->enVars.kernel32 = v->kernel32;
	} 
	else
	{
		this->enVars.kernel32 = 0x75EE0000;
	}

	if (v->ntdll != 0) 
	{
		this->enVars.ntdll = v->ntdll;
	} 
	else 
	{
		this->enVars.ntdll = 0x77580000;
	}
	if (v->user32 != 0) 
	{
		this->enVars.user32 = v->user32;
	}
	else 
	{
		this->enVars.user32 = 0x759D0000;
	}
	if ((dword) v->dllspath == 0)
	{
		this->enVars.dllspath = L"";
	} 
	else 
	{
		this->enVars.dllspath = v->dllspath;
	}
	if ((dword) v->MaxIterations == 0) 
	{ 
		this->enVars.MaxIterations = 10000000; //10 million iterations
	} 
	else 
	{
		this->enVars.MaxIterations = v->MaxIterations;
	}
	return 0;
}

string System::getversion() {
    return "1.20";
};

string System::getCopyrights() {
    return "Pokas x86 Emulator v. 1.10 \n \
      Copyrights � by AmrThabet @ 2010 and all rights reserved to him\n";
};
