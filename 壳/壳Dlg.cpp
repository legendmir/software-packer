
// ��Dlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "��.h"
#include "��Dlg.h"
#include "afxdialogex.h"
#include "C:\\Users\\hs\\Desktop\\�½��ļ���\\��\\shellDLL\\ExpVar.h"
#include <stdlib.h>
#include "aplib.h"
#pragma comment(lib,"aPlib.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

CString g_path;

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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


// C��Dlg �Ի���

C��Dlg::C��Dlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_MY_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void C��Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, m_file_name);
}

BEGIN_MESSAGE_MAP(C��Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &C��Dlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &C��Dlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// C��Dlg ��Ϣ�������

BOOL C��Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void C��Dlg::OnSysCommand(UINT nID, LPARAM lParam)
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void C��Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR C��Dlg::OnQueryDragIcon()
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
	DWORD pDllBase; // DLL�ļ��ػ�ַ
	DWORD pDllTextSecData; // ����ε�����
	DWORD dwTextSecSize; // ����εĴ�С

	DllExpInfo* pDllExpInfo;// DLL�е�����ȫ�ֱ���
	void* ShellEntryFun;    // DLL�е�������
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
// ��������С
int aligment(int size, int aliginment) {
	return (size) % (aliginment) == 0 ? (size) : ((size) / (aliginment)+1)* (aliginment);
}

void GetBufInfo(char* pFileBuff)//��ȡ�ļ�BUFF��ָ��
{
	IMAGE_DOS_HEADER*pdos = (IMAGE_DOS_HEADER*)pFileBuff;
	g_BuffPointer.pNt = (IMAGE_NT_HEADERS*)(pdos->e_lfanew + (DWORD)pdos);
	g_BuffPointer.pOpt = (IMAGE_OPTIONAL_HEADER*)(&g_BuffPointer.pNt->OptionalHeader);
	g_BuffPointer.pSec = (IMAGE_SECTION_HEADER*)((DWORD)g_BuffPointer.pOpt + g_BuffPointer.pNt->FileHeader.SizeOfOptionalHeader);
}

IMAGE_SECTION_HEADER* GetSection( HMODULE hModule,char* scnName)//��ȡָ�����ֵ�����
{
	// ��ȡ���θ�ʽ
	IMAGE_DOS_HEADER*p_dos = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_NT_HEADERS*pnt = (IMAGE_NT_HEADERS*)((DWORD)hModule + p_dos->e_lfanew);
	IMAGE_SECTION_HEADER*psec = (IMAGE_SECTION_HEADER*)((DWORD)&pnt->OptionalHeader + pnt->FileHeader.SizeOfOptionalHeader);
	DWORD dwScnCount = pnt->FileHeader.NumberOfSections;
	// ��ȡ��һ������
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
	// ��ȡ��һ������
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
	pnt->FileHeader.NumberOfSections += 1;//����+1
	memcpy(psec[dwSecNum].Name, pName, 5);//���¼�����ͷ��ֵ
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
				//�޸��ض�λ
				DWORD old = 0;
				VirtualProtect(relocBase, 1, PAGE_EXECUTE_READWRITE, &old);
				//*relocBase -= g_DllInfo.pDllBase;//j��ȥ���ػ�ַ
				*relocBase -= g_DllInfo.pDllTextSecData;//��ȥ����VA
				*relocBase += 0x400000;//�����µļ��ػ�ַ
				*relocBase += pNewSecRva;//�����µĶ���RVA
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
	IMAGE_SECTION_HEADER* psecOringin = GetSection((HMODULE)pFileBuff, ".text");//ѹ��ǰ����
	IMAGE_OPTIONAL_HEADER* pOpt = GetOptHeader(pFileBuff);
	DWORD dwPEheadSize = (DWORD)psecOringin - (DWORD)pFileBuff;
	dwPEheadSize = aligment(dwPEheadSize, pOpt->FileAlignment);
	char* pNewBuff = new char[dwSize] {};
	memcpy(pNewBuff, pFileBuff, dwPEheadSize);//����PEͷ
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
			memcpy(secBuff, compressed, outlength);//����ѹ��
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
//	//��ȡ��Ҫѹ��������,�����Ǵ���α���,��ԭ�������һ������(����������Ϣ)
//	WORD needHandleSection = pFileHeader->NumberOfSections;
//	pPackInfo->numOfSection = needHandleSection;
//	//����һ��newBuffer
//	newFileBuffer = new char[fileSize] {};
//	DWORD nTotalSize = pOptionHeader->SizeOfHeaders;
//	//ѹ������
//	for (WORD i = 0; i < needHandleSection; i++)
//	{
//		//1.������ļ������СΪ0,������.rsrc����,��ѹ��,�����俽������buffer����,�޸���pointerToRawData
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
//		//2.����������ѹ��
//		//-----------------------------------------------
//		int length = pSectionHeader->SizeOfRawData;//��ѹ�����ݵĴ�С
//
//												   /* allocate workmem and destination memory */
//		char *workmem = new char[aP_workmem_size(length)]{};
//		char *compressed = new char[aP_max_packed_size(length)]{};
//
//		/* compress data[] to compressed[] */
//		size_t outlength = aPsafe_pack(fileBuffer + pSectionHeader->PointerToRawData, compressed, length, workmem, NULL, NULL);
//		//ѹ�����ʵ�ʴ�С
//		//------------------------------------------------
//
//		DWORD calAigment = aligment(outlength, pOptionHeader->FileAlignment);//����ѹ������ļ������С
//		memcpy(newFileBuffer + nTotalSize, compressed, calAigment);
//
//		//3.�޸ĸ�����pointerToData��sizeofRawData
//		pSectionHeader->PointerToRawData = nTotalSize;
//		pPackInfo->packSectionInfo[i].sizeOfRawData = pSectionHeader->SizeOfRawData;
//		pSectionHeader->SizeOfRawData = calAigment;
//		nTotalSize += calAigment;
//		//4.�����Ϣ�ṹ��
//		pPackInfo->packSectionInfo[i].isPacked = true;
//		pPackInfo->packSectionInfo[i].originSize = length;
//		pPackInfo->packSectionInfo[i].size = outlength;
//		pPackInfo->packSectionInfo[i].startAddrRva = pSectionHeader->VirtualAddress;
//
//		delete[] workmem;
//		delete[] compressed;
//		pSectionHeader++;
//	}
//	//5.����ͷ
//	memcpy(newFileBuffer, fileBuffer, pOptionHeader->SizeOfHeaders);
//	return nTotalSize;
//}


void C��Dlg::OnBnClickedButton1()//���ļ���ȡ��Ϣ
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CFileDialog dlg(TRUE, NULL, NULL, OFN_HIDEREADONLY, _T("Describe Files (*.exe)|*.exe|All Files (*.*)|*.*||"), NULL);
	dlg.DoModal();
	g_path = dlg.GetPathName();
	m_file_name.SetWindowTextW(g_path);
}

void C��Dlg::OnBnClickedButton2()
{
	// TODO: �ڴ���ӿؼ�֪ͨ��������
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
	GetOptHeader(pFileBuff)->AddressOfEntryPoint = dwNewOep;//�����µ�Oep;

	HANDLE hfileNew = CreateFileA("C:\\Users\\hs\\Desktop\\test\\packed.exe", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ
		, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwWrite = 0;
	
	if (WriteFile(hfileNew, pFileBuff, dwSize, &dwWrite, 0))
	{
		MessageBox(L"�ӿǳɹ�");
	}
	delete[] pFileBuff;
}
