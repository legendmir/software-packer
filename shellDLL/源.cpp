#include <Windows.h>
#include"ExpVar.h"
#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
//#pragma comment(linker,"/merge:.tls=.text")
#pragma comment(linker, "/section:.text,RWE")


extern "C" _declspec(dllexport) DllExpInfo g_Info = { 0xFFFFFFFF };


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}



//获取DOS头
IMAGE_DOS_HEADER* getDosHeader(_In_  char* pFileData) {
	return (IMAGE_DOS_HEADER *)pFileData;
}

// 获取NT头
IMAGE_NT_HEADERS* getNtHeader(_In_  char* pFileData) {
	return (IMAGE_NT_HEADERS*)(getDosHeader(pFileData)->e_lfanew + (SIZE_T)pFileData);
}

//获取文件头
IMAGE_FILE_HEADER* getFileHeader(_In_  char* pFileData) {
	return &getNtHeader(pFileData)->FileHeader;
}

//获取扩展头
IMAGE_OPTIONAL_HEADER* getOptionHeader(_In_  char* pFileData) {
	return &getNtHeader(pFileData)->OptionalHeader;
}


typedef LPVOID* (WINAPI* FnGetProcAddress)(HMODULE, const char*);
FnGetProcAddress pfnGetProcAddress;

typedef HMODULE(WINAPI* FnLoadLibraryA)(const char*);
FnLoadLibraryA pfnLoadLibraryA;

typedef DWORD(WINAPI* FnMessageBoxA)(HWND, const char*, const char*, UINT);
FnMessageBoxA pfnMessageBoxA;

typedef VOID(WINAPI *FnPostQuitMessage)(int nExitCode);
FnPostQuitMessage pfnPostQuitMessage;

typedef BOOL(WINAPI *FnShowWindow)(HWND hWnd,int nCmdShow);
FnShowWindow pfnShowWindow;

typedef BOOL(WINAPI *FnTranslateMessage)(CONST MSG *lpMsg);
FnTranslateMessage pfnTranslateMessage;

typedef LRESULT(WINAPI *FnDispatchMessage)(CONST MSG *lpMsg);
FnDispatchMessage pfnDispatchMessageW;

typedef LRESULT(WINAPI *FnGetWindowtext)(HWND hWnd,LPTSTR lpString,int nMaxCount);
FnGetWindowtext pfnGetWindowtext;

typedef HWND(WINAPI *FnCreateWindowEx) (
	_In_      DWORD dwExStyle,
	_In_opt_  LPCTSTR lpClassName,
	_In_opt_  LPCTSTR lpWindowName,
	_In_      DWORD dwStyle,
	_In_      int x,
	_In_      int y,
	_In_      int nWidth,
	_In_      int nHeight,
	_In_opt_  HWND hWndParent,
	_In_opt_  HMENU hMenu,
	_In_opt_  HINSTANCE hInstance,
	_In_opt_  LPVOID lpParam
);
FnCreateWindowEx pfnCreateWindowEx;


typedef LRESULT(WINAPI *FnSendMessage)(
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
);
FnSendMessage pfnSendMessage;

typedef BOOL(WINAPI *FnGetMessage)(
	_Out_     LPMSG lpMsg,
	_In_opt_  HWND hWnd,
	_In_      UINT wMsgFilterMin,
	_In_      UINT wMsgFilterMax
);
FnGetMessage pfnGetMessage;

typedef LRESULT(WINAPI *FnDefWindowProc) (
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
);
FnDefWindowProc pfnDefWindowProc;

typedef BOOL(WINAPI *FnDestroyWindow)(
	_In_  HWND hWnd
);
FnDestroyWindow pfnDestroyWindow;

typedef ATOM(WINAPI *FnRegisterClass) (
	_In_  const WNDCLASS *lpWndClass
);
FnRegisterClass pfnRegisterClass;


typedef VOID(WINAPI *FnExitProcess) (
	_In_  UINT uExitCode
);
FnExitProcess pfnExitProcess;


typedef BOOL(WINAPI *FnVirtualProtect) (
	_In_   LPVOID lpAddress,
	_In_   SIZE_T dwSize,
	_In_   DWORD flNewProtect,
	_Out_  PDWORD lpflOldProtect
);
FnVirtualProtect pfnVirtualProtect;

typedef HMODULE(WINAPI *FnGetModuleHandleA)(
	_In_opt_  LPCTSTR lpModuleName
);
FnGetModuleHandleA pfnGetModuleHandleA;

typedef HWND(WINAPI *FnGetDlgItem) (
	_In_opt_  HWND hDlg,
	_In_      int nIDDlgItem
);
FnGetDlgItem pfnGetDlgItem;
typedef BOOL(WINAPI *FnUpdateWindow)
 (
	HWND hWnd
);
FnUpdateWindow pfnUpdateWindow;
IMAGE_SECTION_HEADER* GetSection(HMODULE hModule, char* scnName)//获取指定名字的区段
{
	// 获取区段格式
	IMAGE_DOS_HEADER*p_dos = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_NT_HEADERS*pnt = (IMAGE_NT_HEADERS*)((DWORD)hModule + p_dos->e_lfanew);
	IMAGE_SECTION_HEADER*psec = (IMAGE_SECTION_HEADER*)((DWORD)&pnt->OptionalHeader + pnt->FileHeader.SizeOfOptionalHeader);
	DWORD dwScnCount = pnt->FileHeader.NumberOfSections;
	// 获取第一个区段
	for (DWORD i = 0; i < dwScnCount;i++)
	{
		if (strcmp((char*)psec[i].Name, scnName) == 0)
		{
			return psec + i;
		}
	}
	return nullptr;
}



void getApi()
{
	// 1. 先获取kernel32的加载基址
	HMODULE hKernel32 = NULL;
	_asm
	{
		mov eax, FS:[0x30];
		mov eax, [eax + 0xc];
		mov eax, [eax + 0xc];
		mov eax, [eax];
		mov eax, [eax];
		mov eax, [eax + 0x18];
		mov hKernel32, eax;
	}
	// 2. 再获取LoadLibrayA和GetProcAddress函数的地址
	// 2.1 遍历导出表获取函数地址
	IMAGE_EXPORT_DIRECTORY* pExp = NULL;
	pExp = (IMAGE_EXPORT_DIRECTORY*)
		(getOptionHeader((char*)hKernel32)->DataDirectory[0].VirtualAddress + (DWORD)hKernel32);


	DWORD* pEAT = NULL, *pENT = NULL;
	WORD* pEOT = NULL;
	pEAT = (DWORD*)(pExp->AddressOfFunctions + (DWORD)hKernel32);
	pENT = (DWORD*)(pExp->AddressOfNames + (DWORD)hKernel32);
	pEOT = (WORD*)(pExp->AddressOfNameOrdinals + (DWORD)hKernel32);
	for (size_t i = 0; i < pExp->NumberOfNames; i++)
	{
		char* pName = pENT[i] + (char*)hKernel32;
		if (strcmp(pName, "GetProcAddress") == 0) {
			int index = pEOT[i];
			pfnGetProcAddress = (FnGetProcAddress)(pEAT[index] + (DWORD)hKernel32);
			break;
		}
	}
	// 3. 通过这两个API获取其它的API
	pfnLoadLibraryA =
		(FnLoadLibraryA)pfnGetProcAddress(hKernel32, "LoadLibraryA");
	pfnGetModuleHandleA = (FnGetModuleHandleA)pfnGetProcAddress
	(pfnLoadLibraryA("Kernel32.dll"), "GetModuleHandleA");
	pfnVirtualProtect = (FnVirtualProtect)pfnGetProcAddress
	(pfnLoadLibraryA("Kernel32.dll"), "VirtualProtect");
	pfnCreateWindowEx = (FnCreateWindowEx)pfnGetProcAddress
	(pfnLoadLibraryA("User32.dll"), "CreateWindowExW");
	pfnSendMessage= (FnSendMessage)pfnGetProcAddress
	(pfnLoadLibraryA("User32.dll"), "SendMessageW");
	pfnDefWindowProc = (FnDefWindowProc)pfnGetProcAddress
	(pfnLoadLibraryA("User32.dll"), "DefWindowProcA");
	pfnPostQuitMessage = (FnPostQuitMessage)pfnGetProcAddress
	(pfnLoadLibraryA("User32.dll"), "PostQuitMessage");
	pfnShowWindow = (FnShowWindow)pfnGetProcAddress
	(pfnLoadLibraryA("User32.dll"), "ShowWindow");
	pfnTranslateMessage = (FnTranslateMessage)pfnGetProcAddress
	(pfnLoadLibraryA("User32.dll"), "TranslateMessage");
	pfnGetMessage = (FnGetMessage)pfnGetProcAddress
	(pfnLoadLibraryA("User32.dll"), "GetMessageW");
	pfnDispatchMessageW = (FnDispatchMessage)pfnGetProcAddress
	(pfnLoadLibraryA("User32.dll"), "DispatchMessageW");
	pfnDestroyWindow = (FnDestroyWindow)pfnGetProcAddress
	(pfnLoadLibraryA("User32.dll"), "DestroyWindow");
	pfnRegisterClass = (FnRegisterClass)pfnGetProcAddress
	(pfnLoadLibraryA("User32.dll"), "RegisterClassW");
	pfnExitProcess = (FnExitProcess)pfnGetProcAddress
	(pfnLoadLibraryA("Kernel32.dll"), "ExitProcess");
	pfnGetWindowtext = (FnGetWindowtext)pfnGetProcAddress
	(pfnLoadLibraryA("User32.dll"), "GetWindowTextA");
	pfnMessageBoxA =(FnMessageBoxA)pfnGetProcAddress
	(pfnLoadLibraryA("user32.dll"), "MessageBoxA");
	pfnGetDlgItem = (FnGetDlgItem)pfnGetProcAddress
	(pfnLoadLibraryA("user32.dll"), "GetDlgItem");
	pfnUpdateWindow= (FnUpdateWindow)pfnGetProcAddress
	(pfnLoadLibraryA("user32.dll"), "UpdateWindow");
}

void decrypt()
{
	//获取本模块的句柄
	char* g_pPEbuf = (char*)pfnGetModuleHandleA(NULL);//PE
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)g_pPEbuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + g_pPEbuf);
	PIMAGE_SECTION_HEADER pSection = GetSection((HMODULE)g_pPEbuf,".text");
	//第一个区段VA（因为只有一个.text段的原因）
	char* g_FirstSecVA = pSection->VirtualAddress + g_pPEbuf;
	//得到区段大小 长度
	DWORD dwTextSize = pSection->SizeOfRawData;
	//修改区段属性 改成可读可写
	DWORD lpflOldProtect = 0;
	pfnVirtualProtect(g_FirstSecVA, dwTextSize, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
	//遍历解密
	for (DWORD i = 0; i < pSection->SizeOfRawData; i++)
	{
		g_FirstSecVA[i] = g_FirstSecVA[i] ^ 0x15;
	}
	pfnVirtualProtect(g_FirstSecVA, dwTextSize,lpflOldProtect, &lpflOldProtect);
}

LRESULT CALLBACK WindowProc( HWND hwnd, UINT uMsg,WPARAM wParam,LPARAM lParam)
{

	switch (uMsg)
	{
	case WM_CREATE:
	{
		pfnCreateWindowEx(0,L"Edit", L"", WS_CHILD | WS_VISIBLE | WS_BORDER,
			0, 0, 480, 30, hwnd, (HMENU)0x1000, 0, 0);
		pfnCreateWindowEx(0,L"Button", L"登录", WS_CHILD | WS_VISIBLE,
			120, 61, 80, 30, hwnd, (HMENU)0x1001, 0, 0);
	}
	break;
	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case 0x1001:
		{
			//这里写判断
			char EditBuff[10] = {};
			HWND hEdit = pfnGetDlgItem(hwnd, 0x1000);
			pfnGetWindowtext(hEdit, (LPTSTR)EditBuff, 200);
			if (!strcmp(EditBuff, "15PB"))
			{
				decrypt();
				pfnMessageBoxA(0,"解密成功！", 0, 0);
				pfnSendMessage(hwnd, WM_CLOSE, NULL, NULL);
				_asm
				{
					jmp g_Info.dwOep;
				}
			}
			return true;
		}
		default:
			break;
		}
	}
	break;
	case WM_DESTROY:
	{
		PostQuitMessage(0);
		return true;
	}
	break;
	default:
		break;
	}
	return pfnDefWindowProc(hwnd, uMsg, wParam, lParam);
}

void SDK(_In_ HINSTANCE hInstance)
{
	// 创建窗口的过程
	// 1. 注册窗口类
	// 2. 根据窗口类创建窗口
	// 3. 消息循环
	WNDCLASS wnd = {};
	// 下面两个是必须的
	wnd.lpszClassName = L"Shell";
	// 所有通过"Super"类创建的窗口,他们的消息回调函数都是WindowProc
	wnd.lpfnWndProc = WindowProc;
	// 注册窗口
	pfnRegisterClass(&wnd);
	HWND hWnd = pfnCreateWindowEx(0L,
		L"Shell",// 窗口类名
		L"Check",// 窗口名
		WS_OVERLAPPEDWINDOW,// 窗口风格,个性话定义Q
		300, 100,// 窗口的起始位置
		500, 300,// 窗口的宽高
		NULL,// 父窗口
		NULL,// 菜单句柄
		hInstance,// 实例句柄
		NULL);// 附加信息
	pfnShowWindow(hWnd, SW_SHOW);
	pfnUpdateWindow(hWnd);
	// 消息循环
	MSG msg = {};
	// 接收消息,分发给不同的窗口
	while (pfnGetMessage(&msg, 0, 0, 0))
	{
		pfnTranslateMessage(&msg);
		// 把不同窗口的消息分发给对应的回调函数->WindowProc
		pfnDispatchMessageW(&msg);
	}
}

void run()
{
	getApi();
	_In_ HINSTANCE hInstance = (_In_ HINSTANCE)pfnGetModuleHandleA(NULL);
	SDK(hInstance);
}
extern "C" _declspec(dllexport) _declspec(naked) void ShellEntryFun()
{
	g_Info.dwOep += 0x400000;
	run();
}
