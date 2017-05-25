// debugger.cpp : コンソール アプリケーションのエントリ ポイントを定義します。
//

#include "stdafx.h"


struct Thread
{
	DWORD id;
	HANDLE handle;
};

std::vector<Thread> gThreads;
std::mutex gThreadsLock;

Thread* FindThread(DWORD threadId)
{
	std::lock_guard<std::mutex> lock(gThreadsLock);

	auto itr = std::find_if(gThreads.begin(), gThreads.end(), [&](const Thread& p){
		return p.id == threadId;
	});
	return itr == gThreads.end() ? nullptr : &*itr;
}

void CreateThread(DWORD threadId, HANDLE hThread)
{
	Thread thread;
	thread.id = threadId;
	DuplicateHandle(GetCurrentProcess(), hThread, GetCurrentProcess(), &thread.handle, 0, FALSE, DUPLICATE_SAME_ACCESS);

	{
		std::lock_guard<std::mutex> lock(gThreadsLock);
		gThreads.push_back(thread);
	}
}

void setBreakPoint(HANDLE hThread, DWORD64 dwAddress)
{
	if(hThread == nullptr)
	{
		return;
	}

	BOOL ret;

	CONTEXT ctx = { CONTEXT_DEBUG_REGISTERS };
	ret = GetThreadContext(hThread, &ctx);
	ctx.Dr0 = dwAddress;
	const DWORD ctrlFlags = 0x00070101;
	if(dwAddress == 0)
		ctx.Dr7 &= ~ctrlFlags;
	else
		ctx.Dr7 |= ctrlFlags;
	ret = SetThreadContext(hThread, &ctx);
	ret = ret;
}

PROCESS_INFORMATION fdProcessInfo = { 0 };

ULONG_PTR reserveWatchAddr = MAXULONG_PTR;

void cbAttachDebugger()
{
	printf("Attached\n");
}

void cbMemoryBreakpoint(void* ExceptionAddress)
{
	auto debugEvent = (DEBUG_EVENT*)GetDebugData();

	auto thread = FindThread(debugEvent->dwThreadId);

	TITAN_ENGINE_CONTEXT_t titanContext;
	GetFullContextDataEx(thread->handle, &titanContext);

	CONTEXT context = { CONTEXT_ALL };
	context.MxCsr = titanContext.MxCsr;

	context.SegCs = titanContext.cs;
	context.SegDs = titanContext.ds;
	context.SegEs = titanContext.es;
	context.SegFs = titanContext.fs;
	context.SegGs = titanContext.gs;
	context.SegSs = titanContext.ss;
	context.EFlags = titanContext.eflags;

	context.Dr0 = titanContext.dr0;
	context.Dr1 = titanContext.dr1;
	context.Dr2 = titanContext.dr2;
	context.Dr3 = titanContext.dr3;
	context.Dr6 = titanContext.dr6;
	context.Dr7 = titanContext.dr7;

	context.Rax = titanContext.cax;
	context.Rcx = titanContext.ccx;
	context.Rdx = titanContext.cdx;
	context.Rbx = titanContext.cbx;
	context.Rsp = titanContext.csp;
	context.Rbp = titanContext.cbp;
	context.Rsi = titanContext.csi;
	context.Rdi = titanContext.cdi;
	context.R8 = titanContext.r8;
	context.R9 = titanContext.r9;
	context.R10 = titanContext.r10;
	context.R11 = titanContext.r11;
	context.R12 = titanContext.r12;
	context.R13 = titanContext.r13;
	context.R14 = titanContext.r14;
	context.R15 = titanContext.r15;

	context.Rip = titanContext.cip;

	context.Xmm0 = *(M128A*)&titanContext.XmmRegisters[0];
	context.Xmm1 = *(M128A*)&titanContext.XmmRegisters[1];
	context.Xmm2 = *(M128A*)&titanContext.XmmRegisters[2];
	context.Xmm3 = *(M128A*)&titanContext.XmmRegisters[3];
	context.Xmm4 = *(M128A*)&titanContext.XmmRegisters[4];
	context.Xmm5 = *(M128A*)&titanContext.XmmRegisters[5];
	context.Xmm6 = *(M128A*)&titanContext.XmmRegisters[6];
	context.Xmm7 = *(M128A*)&titanContext.XmmRegisters[7];
	context.Xmm8 = *(M128A*)&titanContext.XmmRegisters[8];
	context.Xmm9 = *(M128A*)&titanContext.XmmRegisters[9];
	context.Xmm10 = *(M128A*)&titanContext.XmmRegisters[10];
	context.Xmm11 = *(M128A*)&titanContext.XmmRegisters[11];
	context.Xmm12 = *(M128A*)&titanContext.XmmRegisters[12];
	context.Xmm13 = *(M128A*)&titanContext.XmmRegisters[13];
	context.Xmm14 = *(M128A*)&titanContext.XmmRegisters[14];
	context.Xmm15 = *(M128A*)&titanContext.XmmRegisters[15];

	context.FltSave.ControlWord = titanContext.x87fpu.ControlWord;
	context.FltSave.StatusWord = titanContext.x87fpu.StatusWord;
	context.FltSave.TagWord = titanContext.x87fpu.TagWord;
	context.FltSave.ErrorOffset = titanContext.x87fpu.ErrorOffset;
	context.FltSave.ErrorSelector = titanContext.x87fpu.ErrorSelector;
	context.FltSave.DataOffset = titanContext.x87fpu.DataOffset;
	context.FltSave.DataSelector = titanContext.x87fpu.DataSelector;

	auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, debugEvent->dwProcessId);
	auto hFile = CreateFile("memoryWrite.dmp", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	EXCEPTION_RECORD exceptionRecord = { 0 };
	exceptionRecord.ExceptionAddress = ExceptionAddress;
	exceptionRecord.ExceptionCode = EXCEPTION_BREAKPOINT;

	EXCEPTION_POINTERS exceptionPointer;
	exceptionPointer.ContextRecord = &context;
	exceptionPointer.ExceptionRecord = &exceptionRecord;

	MINIDUMP_EXCEPTION_INFORMATION exceptionInformation;
	exceptionInformation.ThreadId = debugEvent->dwThreadId;
	exceptionInformation.ExceptionPointers = &exceptionPointer;
	exceptionInformation.ClientPointers = FALSE;

	auto ret = MiniDumpWriteDump(hProcess, debugEvent->dwProcessId, hFile, MiniDumpNormal, &exceptionInformation, nullptr, nullptr);

	CloseHandle(hProcess);
	CloseHandle(hFile);
}

void cbException(EXCEPTION_DEBUG_INFO* ExceptionData)
{
	auto debugEvent = (DEBUG_EVENT*)GetDebugData();

	if(ExceptionData->ExceptionRecord.ExceptionCode == 0xe0f0f0f0)
	{
		reserveWatchAddr = ExceptionData->ExceptionRecord.ExceptionInformation[0];
	}
	else
	{
		printf("Unknown Exception 0x%0x8\n", ExceptionData->ExceptionRecord.ExceptionCode);
	}
}

void cbSystemBreakpoint(void* ExceptionData) // TODO: System breakpoint event shouldn't be dropped
{
	printf("Breakpoint 0x%p\n", ExceptionData);
}

void cbDebugEvent(DEBUG_EVENT* DebugEvent)
{
	//printf("DebugEvent 0x%08x\n", DebugEvent->dwDebugEventCode);
}

void cbStepCallback(void* titan)
{
}

void cbBreakpoint(void* titan)
{
	auto debugEvent = (DEBUG_EVENT*)GetDebugData();

	if(reserveWatchAddr != MAXULONG_PTR)
	{
		if(reserveWatchAddr != 0)
			SetHardwareBreakPoint(reserveWatchAddr, UE_DR0, UE_HARDWARE_WRITE, UE_HARDWARE_SIZE_4, cbMemoryBreakpoint);
		else
			DeleteHardwareBreakPoint(UE_DR0);
		reserveWatchAddr = MAXULONG_PTR;
	}

	SetNextDbgContinueStatus(DBG_CONTINUE);

	//printf("Breakpoint\n");
}

void cbSingleStep(void* arg)
{
	printf("SingleStep\n");
	SetNextDbgContinueStatus(DBG_CONTINUE);

}

void cbCreateProcess(CREATE_PROCESS_DEBUG_INFO* CreateProcessInfo)
{
	auto debugEvent = (DEBUG_EVENT*)GetDebugData();

	CreateThread(debugEvent->dwThreadId, CreateProcessInfo->hThread);
}

void cbCreateThread(CREATE_THREAD_DEBUG_INFO* ThreadCreate)
{
	auto debugEvent = (DEBUG_EVENT*)GetDebugData();

	CreateThread(debugEvent->dwThreadId, ThreadCreate->hThread);
}

void cbExitThread(EXIT_THREAD_DEBUG_INFO* ExitThread)
{
	auto debugEvent = (DEBUG_EVENT*)GetDebugData();

	{
		std::lock_guard<std::mutex> lock(gThreadsLock);

		auto itr = std::find_if(gThreads.begin(), gThreads.end(), [&](const Thread& q){
			return q.id == debugEvent->dwThreadId;
		});
		if(itr != gThreads.end())
		{
			CloseHandle(itr->handle);
			gThreads.erase(itr);
		}
	}
}

int main(int argc, char* argv[])
{
	/*DWORD mechProcessId = findMECH();
	if(mechProcessId == (DWORD)-1) return 0;*/
	auto ret = InitDebug(argv[1], "", argv[2]);
	SetCustomHandler(UE_CH_CREATEPROCESS, (void*)cbCreateProcess);
	SetCustomHandler(UE_CH_CREATETHREAD, (void*)cbCreateThread);
	SetCustomHandler(UE_CH_EXITTHREAD, (void*)cbExitThread);
	SetCustomHandler(UE_CH_UNHANDLEDEXCEPTION, (void*)cbException);
	SetCustomHandler(UE_CH_SYSTEMBREAKPOINT, (void*)cbSystemBreakpoint);
	SetCustomHandler(UE_CH_DEBUGEVENT, (void*)cbDebugEvent);
	SetCustomHandler(UE_CH_BREAKPOINT, (void*)cbBreakpoint);
	SetCustomHandler(UE_CH_SINGLESTEP, (void*)cbSingleStep);
	SetCustomHandler(UE_CH_ACCESSVIOLATION, (void*)cbSingleStep);

	DebugLoop();
	//AttachDebugger(mechProcessId, false, &fdProcessInfo, (void*)cbAttachDebugger);
	
	return 0;
}



#if 0

DWORD findMECH()
{
	DWORD allProc[1024];
	DWORD cbNeeded;
	int nProc;
	int i;

	// PID一覧を取得
	if(!EnumProcesses(allProc, sizeof(allProc), &cbNeeded)) {
		return (DWORD)-1;
	}

	DWORD foundProcessId = (DWORD)-1;

	int num = cbNeeded/sizeof(DWORD);
	for(i = 0; i<num; i++)
	{
		char procName[1024];

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, allProc[i]);
		if(NULL != hProcess)
		{
			HMODULE hMod;
			DWORD cbNeeded;

			if(EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
			{
				GetModuleBaseName(hProcess, hMod, procName, sizeof(procName)/sizeof(TCHAR));

				if(stricmp(procName, "mech.exe") == 0)
				{
					foundProcessId = allProc[i];
				}
			}
		}

		CloseHandle(hProcess);

		if(foundProcessId != (DWORD)-1)
		{
			break;
		}
	}

	return foundProcessId;
}


int main0(int argc, char* argv[])
{
	DWORD mechProcessId = findMECH();
	if(mechProcessId == (DWORD)-1) return 0;

	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_READ, &hToken);
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	CloseHandle(hToken);

	if(!DebugActiveProcess(mechProcessId))
	{
		return 0;
	}

	//PROCESS_INFORMATION pcInfo;
	//STARTUPINFO supInfo = { sizeof(STARTUPINFO) };
	//BOOL bResult = CreateProcess(
	//	NULL, argv[1], NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS | DEBUG_PROCESS, NULL, argv[2], &supInfo, &pcInfo);
	//if(!bResult) return 0;

	HANDLE hMainThread = nullptr;

	while(true)
	{
		DWORD dwContineStatus = DBG_CONTINUE;
		DEBUG_EVENT de;
		if(!WaitForDebugEvent(&de, INFINITE))
		{
			goto exit_process;
		}



		switch(de.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
			CloseHandle(de.u.CreateProcessInfo.hFile);
			hMainThread = OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId);
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			goto exit_process;
			break;
		case EXCEPTION_DEBUG_EVENT:
			switch(de.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_BREAKPOINT:
			{
				int a = 0;
			}
				break;
			case 0xe0f0f0f0:
				setBreakPoint(hMainThread, de.u.Exception.ExceptionRecord.ExceptionInformation[0]);
				dwContineStatus = DBG_EXCEPTION_NOT_HANDLED;
				break;
			case 0xe24c4a02:
				dwContineStatus = DBG_EXCEPTION_NOT_HANDLED;
				break;
			default:
				printf("exception %u\n", de.u.Exception.ExceptionRecord.ExceptionCode);
			}
			//printf("debugEvent\n");
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			break;
		default:
			printf("unknown %u\n", de.dwDebugEventCode);
			break;
		}

		
		if(!ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContineStatus))
		{
			break;
		}
	}

exit_process:;

	if(hMainThread != nullptr)
	{
		CloseHandle(hMainThread);
	}

    return 0;
}

#endif
