
// 壳Dlg.cpp : 实现文件
//

#include "stdafx.h"
#include "壳.h"
#include "壳Dlg.h"
#include "afxdialogex.h"
#include "C:\\Users\\hs\\Desktop\\新建文件夹\\壳\\shellDLL\\ExpVar.h"
#include <stdlib.h>
#include "aplib.h"
#pragma comment(lib,"aPlib.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

CString g_path;

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// C壳Dlg 对话框

C壳Dlg::C壳Dlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_MY_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void C壳Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, m_file_name);
}

BEGIN_MESSAGE_MAP(C壳Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &C壳Dlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &C壳Dlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// C壳Dlg 消息处理程序

BOOL C壳Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void C壳Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void C壳Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR C壳Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

typedef struct TypeOffset
{
	WORD Offset : 12;
	WORD Type : 4;
};

typedef struct PeBuffPointer
{
	IMAGE_NT_HEADERS* pNt;
	IMAGE_SECTION_HEADER* pSec;
	IMAGE_OPTIONAL_HEADER* pOpt;
	//DWORD* pLastSec

}PeBuffPointer;
PeBuffPointer g_BuffPointer;
typedef struct _DllInfo
{
	DWORD pDllBase; // DLL的加载基址
	DWORD pDllTextSecData; // 代码段的数据
	DWORD dwTextSecSize; // 代码段的大小

	DllExpInfo* pDllExpInfo;// DLL中导出的全局变量
	void* ShellEntryFun;    // DLL中导出函数
}DllInfo;
DllInfo g_DllInfo;

IMAGE_OPTIONAL_HEADER* GetOptHeader(char* buff)
{
	IMAGE_DOS_HEADER*pdos = (IMAGE_DOS_HEADER*)(DWORD)buff;
	IMAGE_NT_HEADERS*pnt = (IMAGE_NT_HEADERS*)((DWORD)pdos + pdos->e_lfanew);
	return &pnt->OptionalHeader;
}

IMAGE_NT_HEADERS* GetNtHeader(char*buff)
{
	IMAGE_DOS_HEADER*pdos = (IMAGE_DOS_HEADER*)(DWORD)buff;
	IMAGE_NT_HEADERS*pnt = (IMAGE_NT_HEADERS*)((DWORD)pdos + pdos->e_lfanew);
	return pnt;
}
// 计算对齐大小
int aligment(int size, int aliginment) {
	return (size) % (aliginment) == 0 ? (size) : ((size) / (aliginment)+1)* (aliginment);
}

void GetBufInfo(char* pFileBuff)//获取文件BUFF的指针
{
	IMAGE_DOS_HEADER*pdos = (IMAGE_DOS_HEADER*)pFileBuff;
	g_BuffPointer.pNt = (IMAGE_NT_HEADERS*)(pdos->e_lfanew + (DWORD)pdos);
	g_BuffPointer.pOpt = (IMAGE_OPTIONAL_HEADER*)(&g_BuffPointer.pNt->OptionalHeader);
	g_BuffPointer.pSec = (IMAGE_SECTION_HEADER*)((DWORD)g_BuffPointer.pOpt + g_BuffPointer.pNt->FileHeader.SizeOfOptionalHeader);
}

IMAGE_SECTION_HEADER* GetSection( HMODULE hModule,char* scnName)//获取指定名字的区段
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

IMAGE_SECTION_HEADER* GetLastSecTion(char*pFileBuff)
{
	IMAGE_DOS_HEADER*p_dos = (IMAGE_DOS_HEADER*)pFileBuff;
	IMAGE_NT_HEADERS*pnt = (IMAGE_NT_HEADERS*)((DWORD)pFileBuff + p_dos->e_lfanew);
	IMAGE_SECTION_HEADER*psec = (IMAGE_SECTION_HEADER*)((DWORD)&pnt->OptionalHeader + pnt->FileHeader.SizeOfOptionalHeader);
	DWORD dwScnCount = pnt->FileHeader.NumberOfSections;
	// 获取第一个区段
	return psec+(dwScnCount - 1);
}

HMODULE mLoadLibrary(WCHAR*pDllName)
{
	//HMODULE hModule = LoadLibraryA(pDllName);
	HMODULE hModule = LoadLibraryEx(pDllName, NULL, DONT_RESOLVE_DLL_REFERENCES);
	g_DllInfo.pDllBase = (DWORD)hModule;
	IMAGE_SECTION_HEADER*psec = (GetSection(hModule, ".text"));
	g_DllInfo.pDllTextSecData = psec->VirtualAddress + (DWORD)hModule;
	g_DllInfo.dwTextSecSize = psec->Misc.VirtualSize;
	g_DllInfo.pDllExpInfo = (DllExpInfo*)GetProcAddress(hModule, "g_Info");
	g_DllInfo.ShellEntryFun = GetProcAddress(hModule, "ShellEntryFun");
	return hModule;
}

void AddSection(char*& pFileBuff,DWORD& dwFileSize,char* pName)
{
	IMAGE_NT_HEADERS* pnt = GetNtHeader(pFileBuff);
	IMAGE_SECTION_HEADER* psec = IMAGE_FIRST_SECTION(pnt);
	DWORD dwSecNum = pnt->FileHeader.NumberOfSections;
	pnt->FileHeader.NumberOfSections += 1;//区段+1
	memcpy(psec[dwSecNum].Name, pName, 5);//给新加区段头表赋值
	psec[dwSecNum].Misc.VirtualSize = g_DllInfo.dwTextSecSize;
	psec[dwSecNum].VirtualAddress = psec[dwSecNum - 1].VirtualAddress + 
		aligment(psec[dwSecNum - 1].SizeOfRawData, pnt->OptionalHeader.SectionAlignment);
	psec[dwSecNum].SizeOfRawData = aligment(g_DllInfo.dwTextSecSize, pnt->OptionalHeader.FileAlignment);
	psec[dwSecNum].PointerToRawData = aligment(dwFileSize, pnt->OptionalHeader.FileAlignment);
	pnt->OptionalHeader.SizeOfImage = psec[dwSecNum].VirtualAddress + aligment(psec[dwSecNum].SizeOfRawData, pnt->OptionalHeader.SectionAlignment);

	psec[dwSecNum].Characteristics = 0xE00000E0;
	DWORD dwNewSize=psec[dwSecNum].PointerToRawData + psec[dwSecNum].SizeOfRawData;
	char*pNewBuff = new char[dwNewSize] {};
	memcpy(pNewBuff, pFileBuff, dwFileSize);
	memcpy(pNewBuff + psec[dwSecNum].PointerToRawData, (char*)g_DllInfo.pDllTextSecData, psec[dwSecNum].Misc.VirtualSize);
	delete[] pFileBuff;
	pFileBuff = pNewBuff;
	dwFileSize = dwNewSize;
}

void ModDllRelocation(DWORD pNewSecRva)
{
	IMAGE_DOS_HEADER*pdos= (IMAGE_DOS_HEADER*)g_DllInfo.pDllBase;
	IMAGE_NT_HEADERS* pnt = (IMAGE_NT_HEADERS*)((DWORD)pdos + pdos->e_lfanew);
	IMAGE_BASE_RELOCATION* preloc = (IMAGE_BASE_RELOCATION*)(pnt->OptionalHeader.DataDirectory[5].VirtualAddress + (DWORD)pdos);
	while (preloc->SizeOfBlock)
	{
		TypeOffset* pTypeOffset = (TypeOffset*)((DWORD)preloc + 8);
		for (int i = 0;i < (preloc->SizeOfBlock - 8) / 2;i++)
		{
			if (pTypeOffset[i].Type == 3)
			{
				DWORD* relocBase = (DWORD*)(g_DllInfo.pDllBase + pTypeOffset[i].Offset + preloc->VirtualAddress);
				//修复重定位
				DWORD old = 0;
				VirtualProtect(relocBase, 1, PAGE_EXECUTE_READWRITE, &old);
				//*relocBase -= g_DllInfo.pDllBase;//j减去加载基址
				*relocBase -= g_DllInfo.pDllTextSecData;//减去段首VA
				*relocBase += 0x400000;//加上新的加载基址
				*relocBase += pNewSecRva;//加上新的段首RVA
				VirtualProtect(relocBase, 1, old, &old);
			}
		}
		preloc = (IMAGE_BASE_RELOCATION*)((DWORD)preloc + preloc->SizeOfBlock);
	}
}

void encypt(char*pFileBuff,DWORD dwkey)
{
	IMAGE_SECTION_HEADER*psec=GetSection(HMODULE(pFileBuff), ".text");
	for (int i = 0;i < psec->SizeOfRawData;i++)
	{
		pFileBuff[psec->PointerToRawData + i] ^= dwkey;
	}
}

void compress(char*& pFileBuff,DWORD& dwSize)
{
	IMAGE_SECTION_HEADER* psecOringin = GetSection((HMODULE)pFileBuff, ".text");//压缩前数据
	IMAGE_OPTIONAL_HEADER* pOpt = GetOptHeader(pFileBuff);
	DWORD dwPEheadSize = (DWORD)psecOringin - (DWORD)pFileBuff;
	dwPEheadSize = aligment(dwPEheadSize, pOpt->FileAlignment);
	char* pNewBuff = new char[dwSize] {};
	memcpy(pNewBuff, pFileBuff, dwPEheadSize);//拷贝PE头
	char* secBuff = pNewBuff + dwPEheadSize;
	DWORD dwSecNum = GetNtHeader(pFileBuff)->FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER* psecNew = GetSection((HMODULE)pNewBuff, ".text");
	DWORD dwNewImageSize = 0;
	DWORD dwNewFileSize = dwPEheadSize;
	for (int i = 0;i < dwSecNum-1;i++)
	{
		char* text = (char*)(psecOringin[i].PointerToRawData + (DWORD)pFileBuff);
		int SecLen = psecOringin[i].SizeOfRawData;
		if (strcmp((char*)psecNew[i].Name, ".text") == 0/* && strcmp((char*)psecNew[i].Name, ".tls") != 0*/)
		{
			char *workmem = (char*)malloc(aP_workmem_size(SecLen));
			char *compressed = (char*)malloc(aP_max_packed_size(SecLen));
			size_t outlength = aPsafe_pack(text, compressed, SecLen, workmem, NULL, NULL);
			memcpy(secBuff, compressed, outlength);//拷贝压缩
			delete[] workmem;
			delete[] compressed;
			psecNew[i].Misc.VirtualSize = outlength;
			psecNew[i].Misc.PhysicalAddress = outlength;
			psecNew[i].SizeOfRawData = aligment(psecNew[i].Misc.VirtualSize, pOpt->FileAlignment);
			if (i == 0)
			{
				psecNew[i].PointerToRawData = dwPEheadSize;
				psecNew[i].VirtualAddress = 0x11000;
			}
			else
			{
				psecNew[i].PointerToRawData = psecNew[i - 1].PointerToRawData + psecNew[i - 1].SizeOfRawData;
				psecNew[i].VirtualAddress = psecNew[i - 1].VirtualAddress + aligment(psecNew[i - 1].SizeOfRawData, pOpt->SectionAlignment);
			}
			secBuff += aligment(outlength, pOpt->FileAlignment);
			dwNewFileSize += aligment(outlength, pOpt->FileAlignment);
		}
		else
		{
			memcpy(secBuff, text, psecOringin[i].SizeOfRawData);
			secBuff += psecOringin[i].SizeOfRawData;
			dwNewFileSize += psecOringin[i].SizeOfRawData;
			psecNew[i].PointerToRawData = psecNew[i - 1].PointerToRawData + psecNew[i - 1].SizeOfRawData;
			psecNew[i].VirtualAddress = psecNew[i - 1].VirtualAddress + aligment(psecNew[i - 1].SizeOfRawData, pOpt->SectionAlignment);
		}
		if (i == dwSecNum - 2)
		{
			dwNewImageSize = psecNew[i].VirtualAddress + aligment(psecNew[i].SizeOfRawData, pOpt->SectionAlignment);
		}
	}
	IMAGE_OPTIONAL_HEADER* pNewOpt = GetOptHeader(pNewBuff);
	pNewOpt->SizeOfImage = dwNewImageSize;

	
	delete[] pFileBuff;
	secBuff = NULL;
	pFileBuff = pNewBuff;
	pNewBuff = NULL;
	dwSize = dwNewFileSize;
}

//DWORD packSection(DWORD dllBase, char* fileBuffer, char*& newFileBuffer, DWORD fileSize)
//{
//	PIMAGE_NT_HEADERS pNt = getNtHeader(fileBuffer);
//	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(fileBuffer);
//	PIMAGE_OPTIONAL_HEADER pOptionHeader = getOptionHeader(fileBuffer);
//	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNt);
//	PACK_INFO_* pPackInfo = (PACK_INFO_*)GetProcAddress((HMODULE)dllBase, "pi");
//	//获取需要压缩的区段,除开壳代码段本身,和原来的最后一个区段(包含特殊信息)
//	WORD needHandleSection = pFileHeader->NumberOfSections;
//	pPackInfo->numOfSection = needHandleSection;
//	//申请一个newBuffer
//	newFileBuffer = new char[fileSize] {};
//	DWORD nTotalSize = pOptionHeader->SizeOfHeaders;
//	//压缩区段
//	for (WORD i = 0; i < needHandleSection; i++)
//	{
//		//1.如果是文件对其大小为0,或者是.rsrc区段,则不压缩,并将其拷贝至新buffer里面,修改其pointerToRawData
//		if (pSectionHeader->SizeOfRawData == 0)
//		{
//			pSectionHeader++;
//			continue;
//		}
//		if (strcmp((char*)pSectionHeader->Name, ".rsrc") == 0)
//		{
//			memcpy(newFileBuffer + nTotalSize, fileBuffer + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
//			pSectionHeader->PointerToRawData = nTotalSize;
//			nTotalSize += pSectionHeader->SizeOfRawData;
//			pSectionHeader++;
//			continue;
//		}
//		//2.其他区段则压缩
//		//-----------------------------------------------
//		int length = pSectionHeader->SizeOfRawData;//被压缩数据的大小
//
//												   /* allocate workmem and destination memory */
//		char *workmem = new char[aP_workmem_size(length)]{};
//		char *compressed = new char[aP_max_packed_size(length)]{};
//
//		/* compress data[] to compressed[] */
//		size_t outlength = aPsafe_pack(fileBuffer + pSectionHeader->PointerToRawData, compressed, length, workmem, NULL, NULL);
//		//压缩后的实际大小
//		//------------------------------------------------
//
//		DWORD calAigment = aligment(outlength, pOptionHeader->FileAlignment);//计算压缩后的文件对齐大小
//		memcpy(newFileBuffer + nTotalSize, compressed, calAigment);
//
//		//3.修改该区段pointerToData和sizeofRawData
//		pSectionHeader->PointerToRawData = nTotalSize;
//		pPackInfo->packSectionInfo[i].sizeOfRawData = pSectionHeader->SizeOfRawData;
//		pSectionHeader->SizeOfRawData = calAigment;
//		nTotalSize += calAigment;
//		//4.填充信息结构体
//		pPackInfo->packSectionInfo[i].isPacked = true;
//		pPackInfo->packSectionInfo[i].originSize = length;
//		pPackInfo->packSectionInfo[i].size = outlength;
//		pPackInfo->packSectionInfo[i].startAddrRva = pSectionHeader->VirtualAddress;
//
//		delete[] workmem;
//		delete[] compressed;
//		pSectionHeader++;
//	}
//	//5.拷贝头
//	memcpy(newFileBuffer, fileBuffer, pOptionHeader->SizeOfHeaders);
//	return nTotalSize;
//}


void C壳Dlg::OnBnClickedButton1()//打开文件获取信息
{
	// TODO: 在此添加控件通知处理程序代码
	CFileDialog dlg(TRUE, NULL, NULL, OFN_HIDEREADONLY, _T("Describe Files (*.exe)|*.exe|All Files (*.*)|*.*||"), NULL);
	dlg.DoModal();
	g_path = dlg.GetPathName();
	m_file_name.SetWindowTextW(g_path);
}

void C壳Dlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代
	m_file_name.GetWindowTextW(g_path);
	HANDLE hFile = CreateFile(g_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ
		, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD size = GetFileSize(hFile, 0);
	char* pFileBuff = new char[size]{};
	DWORD dwSize = 0;
	ReadFile(hFile, pFileBuff, size, &dwSize, 0);
	GetBufInfo(pFileBuff);
	HMODULE hModule=mLoadLibrary(L"shellDLL");
	
	DWORD oep = GetOptHeader(pFileBuff)->AddressOfEntryPoint;
	g_DllInfo.pDllExpInfo->dwOep = oep;

	encypt(pFileBuff, 0x15);
	compress(pFileBuff, dwSize);

	IMAGE_SECTION_HEADER* pLastSec = GetLastSecTion(pFileBuff);
	DWORD pNewSecRva = pLastSec->VirtualAddress+ aligment(pLastSec->SizeOfRawData, GetOptHeader(pFileBuff)->SectionAlignment);
	ModDllRelocation(pNewSecRva);
	AddSection(pFileBuff, dwSize, ".pack");

	DWORD dwNewOep = 0;
	dwNewOep = (DWORD)g_DllInfo.ShellEntryFun;
	dwNewOep -= (GetSection(hModule, ".text")->VirtualAddress + (DWORD)hModule);
	dwNewOep += pNewSecRva;
	GetOptHeader(pFileBuff)->AddressOfEntryPoint = dwNewOep;//设置新的Oep;

	HANDLE hfileNew = CreateFileA("C:\\Users\\hs\\Desktop\\test\\packed.exe", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ
		, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwWrite = 0;
	
	if (WriteFile(hfileNew, pFileBuff, dwSize, &dwWrite, 0))
	{
		MessageBox(L"加壳成功");
	}
	delete[] pFileBuff;
}
