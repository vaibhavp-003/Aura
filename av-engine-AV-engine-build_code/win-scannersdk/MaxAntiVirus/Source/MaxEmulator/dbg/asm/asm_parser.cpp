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

//global variables
//----------------
int pages=0;                //the number of pages that our buffer use (no of bytes = pages*0x1000)
MAX_DWORD mem=0;                //pointer to our buffer
int cur=0;                  //the place where we are in the buffer
//-------
//Arrays 
//------

string nums[10]={"0","1","2","3","4","5","6","7","8","9"};
string numshex[16]={"0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"};
string eip[1]={"eip"};
string num_identifier[2]={"h","b"};
string level4[2]={"&&","||"};
string level32[2]={">","<"};
string level3[4]={">=","<=","==","!="};
string level2[4]={"+","-","|","#"};
string level1[4]={"*","/","&","%"};
string level0[4]={"~","-"};
//--------------------------
MAX_DWORD AsmDebugger::parser(string s)
{
    pages = 0;
    cur = 0;
	mem = 0;
	mem = (MAX_DWORD)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);                      //the virtual place
	if(mem == 0)
	{
		return 0;
	}
    memset((char*)mem,0,0x1000);
    pages++;

	if(s.compare("") == 0)
	{
		return mem;
	}

    s = to_lower_case(s);
    add_to_buffer(process->getsystem()->assembl("push esi"));
    add_to_buffer(process->getsystem()->assembl("push edi"));
    add_to_buffer(process->getsystem()->assembl("push ecx"));
    add_to_buffer(process->getsystem()->assembl("push edx"));
#ifdef WIN64
    add_to_buffer(process->getsystem()->assembl("mov rsi,rcx"));
    add_to_buffer(process->getsystem()->assembl("mov rdi,rdx"));
#else
	add_to_buffer(process->getsystem()->assembl("mov esi,ecx"));
    add_to_buffer(process->getsystem()->assembl("mov edi,edx"));
#endif

    boolexp(s);

    add_to_buffer(process->getsystem()->assembl("pop edx"));
    add_to_buffer(process->getsystem()->assembl("pop ecx"));
    add_to_buffer(process->getsystem()->assembl("pop edi"));
    add_to_buffer(process->getsystem()->assembl("pop esi"));
    add_to_buffer(process->getsystem()->assembl("ret"));

    return mem;
};

dword AsmDebugger::boolexp(string& s)
{
	bool con = true;          //continue the loop
	boolexp2(s);
	while (con)
	{
		s=trim(s);
		int n=compare_array(s,level4,2,2);
		if (n !=0)
		{
			s=s.substr(2,s.size());
			switch(n)
			{
			case 1:
				doandbool(s);
				break;
			case 2:
				doorbool(s);
				break;
			}
		}
		else
		{
			con=false;
		}        
	}  
	return 0;
}

dword AsmDebugger::boolexp2(string& s)
{
	bool con = true;          //continue the loop
	mathexp(s);
	while (con)
	{
		s=trim(s);
		int n=compare_array(s,level3,4,2);
		if (n==0)
		{
			n = compare_array(s,level32,2,1);
			if(n > 0)
			{
				n+=4;
			}
		}
		if (n !=0)
		{
			if (n > 4)
			{
				s = s.substr(1,s.size());
			}
			else
			{
				s = s.substr(2,s.size());
			}
			switch(n)
			{
			case 1:
				dogreaterequal(s);
				break;
			case 2:
				dolowerequal(s);
				break;
			case 3:
				doequal(s);
				break;
			case 4:
				donotequal(s);
				break;
			case 5:
				dogreater(s);
				break;
			case 6:
				dolower(s);
				break;
			}
		}
		else
		{
			con=false;
		}
	}
	return 0;
}
dword AsmDebugger::mathexp(string& s)
{
	bool con = true;          //continue the loop
	mulexp(s);
	while (con)
	{
		s = trim(s);
		int n = compare_array(s,level2,4,1);
		if (n==3 && compare_array(s,level4,2,2)==2)
		{
			n=0; 
		}
		if (n !=0)
		{
			s=s.substr(1,s.size());
			switch(n)
			{
			case 1:
				doadd(s);
				break;
			case 2:
				dosub(s);
				break;
			case 3:
				door(s);
				break;
			case 4:
				doxor(s);
				break;
			}
		}
		else
		{
			con = false;
		}
	}
	return 0;
}
dword AsmDebugger::mulexp(string& s)
{
	bool con = true;          //continue the loop
	getnum(s);
	while (con)
	{
		s = trim(s);
		int n = compare_array(s,level1,4,1);
		if (n==3 && compare_array(s,level4,2,2)==1)
		{
			n = 0; 
		}
		if (n !=0)
		{
			s=s.substr(1,s.size());
			switch(n)
			{
			case 1:
				domul(s);
				break;
			case 2:
				dodiv(s);
				break;
			case 3:
				doand(s);
				break;
			case 4:
				domod(s);
				break;
			}
		}
		else
		{
			con=false;
		}
	}
	return 0;
}

dword AsmDebugger::getnum(string& s)
{
	s = trim(s);
	string s2;
	if (s.substr(0,1)=="(")
	{
		s = s.substr(1,s.size());
		boolexp(s);

		if(s.substr(0,1)==")")
		{
			s=s.substr(1,s.size());
		}
		else
		{
			lasterror=((string)"expect a ')' "); 
			throw(1);
		}
	}
	else if(compare_array(s,level0,2,1))
	{
		int n = compare_array(s,level0,2,1);
		s = s.substr(1,s.size());
		switch(n)
		{
		case 1:
			donot(s);
			break;
		case 2:
			doneg(s);
			break;
		}
	}
	else if(compare_array(s,reg32,8,3))
	{
		int n = compare_array(s,reg32,8,3)-1;
		s = s.substr(3,s.size());
		doreg32(n);
	}
	else if(compare_array(s,eip,1,3))
	{
		s = s.substr(3,s.size());
		doreg32(8);
	}
	else if(s.substr(0,2)=="__")
	{
		s = s.substr(2,s.size());
		callfunc(s);
	}
	else if (s.substr(0,1)=="'")
	{
		strfunc(s);
	}
	else if (compare_array(s,nums,10,1))
	{
		int n=1;
		if (s.substr(0,2)=="0x")
		{
			s=s.substr(n+1,s.size());
			n=0;
			while(true)
			{
				if (compare_array(s.substr(n,n+1),numshex,16,1))
				{
					n++;
				}
				else
				{
					break;
				}  
			}
			if(s.substr(0,n).size() > 7)
			{
				printf("here, error bp hit\n");
			}
			string s3;
#ifdef WIN64
			s2 = "mov eax,";
			s3 = "mov r8,";
			s2.append(s.substr(0,n));
			s3.append(s.substr(0,n));
			s2.append("h");
			s3.append("h");
			add_to_buffer(process->getsystem()->assembl(s3));
#else
			s2 = "mov eax,";
			s2.append(s.substr(0,n));
			s2.append("h");
#endif
		}
		else
		{
			while(true)
			{
				if (compare_array(s.substr(n,n+1),nums,10,1))
				{
					n++;
				}
				else if (compare_array(s.substr(n,n+1),num_identifier,2,1))
				{
					n++;
				}
				else
				{
					break;
				}
			}
			string s3;
#ifdef WIN64
			s2 = "mov eax,";
			s3 = "mov r8,";
			s2.append(s.substr(0,n));
			s3.append(s.substr(0,n));
			add_to_buffer(process->getsystem()->assembl(s3));
#else
			s2 = "mov eax,";
			s2.append(s.substr(0,n));
#endif

		}
		add_to_buffer(process->getsystem()->assembl(s2));
		s=s.substr(n,s.size());
	}
	else
	{
		lasterror=((string)"expect a number");
		throw(1);  
	}
	return 0;
}

//-------------------------------------------------------------------------------------
//do Math Functions
//-----------------
dword AsmDebugger::domul(string& s){
      add_to_buffer(process->getsystem()->assembl("push eax"));
      getnum(s);
      add_to_buffer(process->getsystem()->assembl("mov ecx,eax"));
      add_to_buffer(process->getsystem()->assembl("pop eax"));
      add_to_buffer(process->getsystem()->assembl("mul ecx"));
	  return 0;
};
dword AsmDebugger::dodiv(string& s){
      add_to_buffer(process->getsystem()->assembl("push eax"));
      getnum(s);
      add_to_buffer(process->getsystem()->assembl("or eax,eax"));
      add_to_buffer(process->getsystem()->assembl("jnz 5h"));
      add_to_buffer(process->getsystem()->assembl("pop edx"));
      add_to_buffer(process->getsystem()->assembl("pop ecx"));
      add_to_buffer(process->getsystem()->assembl("pop edi"));
      add_to_buffer(process->getsystem()->assembl("pop esi"));
      add_to_buffer(process->getsystem()->assembl("ret"));
      add_to_buffer(process->getsystem()->assembl("mov ecx,eax"));
      add_to_buffer(process->getsystem()->assembl("pop eax"));
      add_to_buffer(process->getsystem()->assembl("xor edx,edx"));
      add_to_buffer(process->getsystem()->assembl("div ecx"));
	  return 0;
};
dword AsmDebugger::domod(string& s){
      dodiv(s);
      add_to_buffer(process->getsystem()->assembl("mov eax,edx"));
	  return 0;
};
dword AsmDebugger::doand(string& s){
      add_to_buffer(process->getsystem()->assembl("push eax"));
      getnum(s);
      add_to_buffer(process->getsystem()->assembl("pop ecx"));
      add_to_buffer(process->getsystem()->assembl("and eax,ecx"));
	  return 0;
};
//-------
dword AsmDebugger::doadd(string& s){
      add_to_buffer(process->getsystem()->assembl("push eax"));
      mulexp(s);
      add_to_buffer(process->getsystem()->assembl("pop ecx"));
      add_to_buffer(process->getsystem()->assembl("add eax,ecx"));
	  return 0;
};
dword AsmDebugger::dosub(string& s){
      add_to_buffer(process->getsystem()->assembl("push eax"));
      mulexp(s);
      add_to_buffer(process->getsystem()->assembl("pop ecx"));
      add_to_buffer(process->getsystem()->assembl("sub eax,ecx"));
      add_to_buffer(process->getsystem()->assembl("neg eax"));
	  return 0;
};
dword AsmDebugger::door(string& s){
      add_to_buffer(process->getsystem()->assembl("push eax"));
      mulexp(s);
      add_to_buffer(process->getsystem()->assembl("pop ecx"));
      add_to_buffer(process->getsystem()->assembl("or eax,ecx"));
	  return 0;
};
dword AsmDebugger::doxor(string& s){
      add_to_buffer(process->getsystem()->assembl("push eax"));
      mulexp(s);
      add_to_buffer(process->getsystem()->assembl("pop ecx"));
      add_to_buffer(process->getsystem()->assembl("xor eax,ecx"));
	  return 0;
};
dword AsmDebugger::dogreaterequal(string& s){
      add_to_buffer(process->getsystem()->assembl("push eax"));
      mathexp(s);
      add_to_buffer(process->getsystem()->assembl("pop ecx"));
      add_to_buffer(process->getsystem()->assembl("xchg eax,ecx"));
      add_to_buffer(process->getsystem()->assembl("cmp eax,ecx"));
      add_to_buffer(process->getsystem()->assembl("jge 4"));
      add_to_buffer(process->getsystem()->assembl("xor eax,eax"));
      add_to_buffer(process->getsystem()->assembl("jmp 5"));
      add_to_buffer(process->getsystem()->assembl("mov eax,1"));
	  return 0;
};
dword AsmDebugger::dolowerequal(string& s){
      add_to_buffer(process->getsystem()->assembl("push eax"));
      mathexp(s);
      add_to_buffer(process->getsystem()->assembl("pop ecx"));
      add_to_buffer(process->getsystem()->assembl("xchg eax,ecx"));
      add_to_buffer(process->getsystem()->assembl("cmp eax,ecx"));
      add_to_buffer(process->getsystem()->assembl("jle 4"));
      add_to_buffer(process->getsystem()->assembl("xor eax,eax"));
      add_to_buffer(process->getsystem()->assembl("jmp 5"));
      add_to_buffer(process->getsystem()->assembl("mov eax,1"));
	  return 0;
};
dword AsmDebugger::doequal(string& s){
      add_to_buffer(process->getsystem()->assembl("push eax"));
      mathexp(s);
      add_to_buffer(process->getsystem()->assembl("pop ecx"));
      add_to_buffer(process->getsystem()->assembl("xchg eax,ecx"));
      add_to_buffer(process->getsystem()->assembl("cmp eax,ecx"));
      add_to_buffer(process->getsystem()->assembl("jz 4"));
      add_to_buffer(process->getsystem()->assembl("xor eax,eax"));
      add_to_buffer(process->getsystem()->assembl("jmp 5"));
      add_to_buffer(process->getsystem()->assembl("mov eax,1"));
	  return 0;
};
dword AsmDebugger::donotequal(string& s){
      add_to_buffer(process->getsystem()->assembl("push eax"));
      mathexp(s);
      add_to_buffer(process->getsystem()->assembl("pop ecx"));
      add_to_buffer(process->getsystem()->assembl("xchg eax,ecx"));
      add_to_buffer(process->getsystem()->assembl("cmp eax,ecx"));
      add_to_buffer(process->getsystem()->assembl("jnz 4"));
      add_to_buffer(process->getsystem()->assembl("xor eax,eax"));
      add_to_buffer(process->getsystem()->assembl("jmp 5"));
      add_to_buffer(process->getsystem()->assembl("mov eax,1"));
	  return 0;
};
dword AsmDebugger::dogreater(string& s){
      add_to_buffer(process->getsystem()->assembl("push eax"));
      mathexp(s);
      add_to_buffer(process->getsystem()->assembl("pop ecx"));
      add_to_buffer(process->getsystem()->assembl("xchg eax,ecx"));
      add_to_buffer(process->getsystem()->assembl("cmp eax,ecx"));
      add_to_buffer(process->getsystem()->assembl("jg 4"));
      add_to_buffer(process->getsystem()->assembl("xor eax,eax"));
      add_to_buffer(process->getsystem()->assembl("jmp 5"));
      add_to_buffer(process->getsystem()->assembl("mov eax,1"));
	  return 0;
};
dword AsmDebugger::dolower(string& s){
      add_to_buffer(process->getsystem()->assembl("push eax"));
      mathexp(s);
      add_to_buffer(process->getsystem()->assembl("pop ecx"));
      add_to_buffer(process->getsystem()->assembl("xchg eax,ecx"));
      add_to_buffer(process->getsystem()->assembl("cmp eax,ecx"));
      add_to_buffer(process->getsystem()->assembl("jl 4"));
      add_to_buffer(process->getsystem()->assembl("xor eax,eax"));
      add_to_buffer(process->getsystem()->assembl("jmp 5"));
      add_to_buffer(process->getsystem()->assembl("mov eax,1"));
	  return 0;
};
dword AsmDebugger::doandbool(string& s){
      add_to_buffer(process->getsystem()->assembl("or eax,eax"));
      add_to_buffer(process->getsystem()->assembl("jz 5"));
      add_to_buffer(process->getsystem()->assembl("mov eax,1"));
      add_to_buffer(process->getsystem()->assembl("push eax"));
      boolexp2(s);
      add_to_buffer(process->getsystem()->assembl("pop ecx"));
      add_to_buffer(process->getsystem()->assembl("or eax,eax"));
      add_to_buffer(process->getsystem()->assembl("jz 5"));
      add_to_buffer(process->getsystem()->assembl("mov eax,1"));
      add_to_buffer(process->getsystem()->assembl("and eax,ecx"));
	  return 0;
};
dword AsmDebugger::doorbool(string& s){
      add_to_buffer(process->getsystem()->assembl("or eax,eax"));
      add_to_buffer(process->getsystem()->assembl("jz 5"));
      add_to_buffer(process->getsystem()->assembl("mov eax,1"));
      add_to_buffer(process->getsystem()->assembl("push eax"));
      boolexp2(s);
      add_to_buffer(process->getsystem()->assembl("pop ecx"));
      add_to_buffer(process->getsystem()->assembl("or eax,eax"));
      add_to_buffer(process->getsystem()->assembl("jz 5"));
      add_to_buffer(process->getsystem()->assembl("mov eax,1"));
      add_to_buffer(process->getsystem()->assembl("or eax,ecx"));
	  return 0;
};
dword AsmDebugger::donot(string& s){
      getnum(s);
      add_to_buffer(process->getsystem()->assembl("not eax"));
	  return 0;
};
dword AsmDebugger::doneg(string& s){
      getnum(s);
      add_to_buffer(process->getsystem()->assembl("neg eax"));
	  return 0;
};



dword AsmDebugger::doreg32(int n){
       Thread* s=new Thread();
	   memset(s, 0, sizeof(Thread));
       dword n2;
       if (n==8){
          n2=(dword)&s->Eip-(dword)s;
       }else{
             n2=(dword)&s->Exx[n]-(dword)s;
       };
       string s2="mov eax,dword ptr [esi+";
       char s3[3];
       sprintf_s(s3, 3,"%i",n2);
       //s3[0]=(char)(n2+0x30);
       s3[2]=0;
       s2.append(s3);
       s2.append("]");
       add_to_buffer(process->getsystem()->assembl(s2));
	   delete s;
	  return 0;
}; 
//-------------------------------------------------------------------------------------------
dword AsmDebugger::callfunc(string& s)
{
	int n = s.find_first_of("(");
	int nfunc = 0;
	if ((DWORD)n >= s.size())
	{
		lasterror=((string)"expect '(' for fuction call");
		throw(1);
	}
	n++;               // to add "("
	string s2=s.substr(0,n);
	for (int i=0;i<func_entries;i++)
	{
		if(s2.compare(funcs[i].name)==0) 
		{           
			nfunc=i;
			goto Func_Found;
		};
	}
	lasterror=((string)"unknown function ").append(s2);
	throw(1);

Func_Found:

	s = s.substr(n,s.size());
	for(int i=0; i<funcs[nfunc].params; i++)
	{
		mathexp(s);
#ifndef WIN64
		add_to_buffer(process->getsystem()->assembl("push eax"));
#endif
		if (s.substr(0,1)!="," && s.substr(0,1)!=")")
		{
			lasterror=((string)"missing parameter(s) for function ").append(s2);
			throw(1);
		}
		else
		{
			s=s.substr(1,s.size());
		}
	}

	if (funcs[nfunc].params==0)
	{
		s=s.substr(1,s.size());
	}
#ifdef WIN64
	add_to_buffer(process->getsystem()->assembl("mov rdx,rdi"));
	add_to_buffer(process->getsystem()->assembl("mov rcx,rsi"));
#else
	add_to_buffer(process->getsystem()->assembl("push edi"));
	add_to_buffer(process->getsystem()->assembl("push esi"));
#endif


#ifdef WIN64
	string s3 = "mov rax,";
#else
	string s3 = "mov eax,";
#endif

	char s4[50];

#ifdef WIN64
	sprintf_s(s4, 50, "%016p", funcs[nfunc].dbg_func);
#else
	sprintf_s(s4, 9, "%08x", funcs[nfunc].dbg_func);
#endif

	s3.append(s4);
	s3.append("h");
	add_to_buffer(process->getsystem()->assembl(s3));

	add_to_buffer(process->getsystem()->assembl("call eax"));

#ifndef WIN64
	s3 = "add esp,0";
	char s5[20] = {0};
	sprintf_s(s5, 20, "%x",(funcs[nfunc].params+2)*4);
	s5[3]=0;
	s3.append(s5);
	s3.append("h");
	add_to_buffer(process->getsystem()->assembl(s3));
#endif
	return 0;
}

//-------------------------------------------------------------------------------------------
/*
dword AsmDebugger::strfunc(string& s)
{
	s = s.substr(1,s.size());
	int n = s.find_first_of("'",0);
	if ((DWORD)n > s.size())
	{ 
		lasterror="unclosed string ";
		lasterror.append(s);
		throw(1);
	}

	string s2=s.substr(0,n);
	MAX_DWORD ptr = (MAX_DWORD)malloc_emu(s2.size()+1);
	memset((MAX_DWORD*)ptr, 0, s2.size()+1);
	memcpy((MAX_DWORD*)ptr, s2.c_str(), s2.size());

	s = s.substr(n+1,s.size());

#ifdef WIN64
	string s3 = "mov r8,";
#else
	string s3 = "mov eax,";
#endif

	char s5[17] = {0};

#ifdef WIN64
	sprintf_s(s5, 17, "%016x", ptr);
#else
	sprintf_s(s5, 9, "%08x", ptr);
#endif

	s3.append(s5);
	s3.append("h");
	add_to_buffer(process->getsystem()->assembl(s3));
	return 0;
}
*/
dword AsmDebugger::strfunc(string& s)
{
	s = s.substr(1, s.size());
	int n = s.find_first_of("'", 0);
	if ((DWORD)n > s.size())
	{
		lasterror = "unclosed string ";
		lasterror.append(s);
		throw(1);
	}

	string s2 = s.substr(0, n);
	MAX_DWORD ptr = (MAX_DWORD)malloc_emu(s2.size() + 1);
	/*
	memset((MAX_DWORD*)ptr, 0, s2.size()+1);
	memcpy((MAX_DWORD*)ptr, s2.c_str(), s2.size());
	*/
	ptr = (MAX_DWORD)memset((void*)ptr, 0, s2.size() + 1);

	ptr = (MAX_DWORD)memcpy((void*)ptr, s2.c_str(), s2.size());

	s = s.substr(n + 1, s.size());

#ifdef WIN64
	string s3 = "mov r8,";
#else
	string s3 = "mov eax,";
#endif

	char s5[17] = { 0 };

#ifdef WIN64
	unsigned __int32  MSB_part;
	unsigned __int32  LSB_part;

	MSB_part = ptr >> 32;
	LSB_part = ptr & 0x00000000FFFFFFFF;
	sprintf_s(s5, 17, "%08x%08x", MSB_part, LSB_part);
	//sprintf_s(s5, 17, "%016x", ptr);
	//memcpy(s5, (void*)&ptr, 17);
#else
	sprintf_s(s5, 9, "%08x", ptr);
#endif

	s3.append(s5);
	s3.append("h");
	add_to_buffer(process->getsystem()->assembl(s3));
	return 0;
}

void AsmDebugger::add_to_buffer(bytes* ins)
{
      for (int i=0;i<ins->length;i++)
	  {
          ((char*)mem)[cur]=ins->s[i];
          cur++;
      }
	  free_emu(ins);
}
//-------------------------------------------------------------------------------------------
