// Tablacus Shell Susie Plug-in (C)2015 Gaku
// MIT Lisence
// Visual C++ 2008 Express Edition SP1
// Windows SDK v7.0
// http://www.eonet.ne.jp/~gakana/tablacus/

#include "axshell.h"

LPITEMIDLIST teILCreateFromPath(LPWSTR pszPath);

// Global Variables:
LPFNSHParseDisplayName lpfnSHParseDisplayName = NULL;
LPITEMIDLIST g_pidls[MAX_CSIDL];
BSTR		 g_bsPidls[MAX_CSIDL];
WCHAR g_pszCacheW[MAX_PATH * 4];
LPITEMIDLIST g_pidlCache = NULL;
int	g_nPidls = MAX_CSIDL;
CRITICAL_SECTION g_CriticalSection;

// Unit

HRESULT STDAPICALLTYPE teSHParseDisplayName2000(LPCWSTR pszName, IBindCtx *pbc, PIDLIST_ABSOLUTE *ppidl, SFGAOF sfgaoIn, SFGAOF *psfgaoOut)
{
	*ppidl = ILCreateFromPath(pszName);
	return *ppidl ? S_OK : E_FAIL;
}

int GetIntFromVariant(VARIANT *pv)
{
	if (pv) {
		if (pv->vt == (VT_VARIANT | VT_BYREF)) {
			return GetIntFromVariant(pv->pvarVal);
		}
		if (pv->vt == VT_I4) {
			return pv->lVal;
		}
		if (pv->vt == VT_R8) {
			return (int)(LONGLONG)pv->dblVal;
		}
		VARIANT vo;
		VariantInit(&vo);
		if SUCCEEDED(VariantChangeType(&vo, pv, 0, VT_I4)) {
			return vo.lVal;
		}
		if SUCCEEDED(VariantChangeType(&vo, pv, 0, VT_I8)) {
			return (int)vo.llVal;
		}
		if SUCCEEDED(VariantChangeType(&vo, pv, 0, VT_R8)) {
			return (int)(LONGLONG)vo.dblVal;
		}
	}
	return 0;
}

LONGLONG GetLLFromVariant(VARIANT *pv)
{
	if (pv) {
		if (pv->vt == (VT_VARIANT | VT_BYREF)) {
			return GetLLFromVariant(pv->pvarVal);
		}
		if (pv->vt == VT_I4) {
			return pv->lVal;
		}
		if (pv->vt == VT_R8) {
			return (LONGLONG)pv->dblVal;
		}
		VARIANT vo;
		VariantInit(&vo);
		if SUCCEEDED(VariantChangeType(&vo, pv, 0, VT_I8)) {
			return vo.llVal;
		}
	}
	return 0;
}

int GetIntFromVariantClear(VARIANT *pv)
{
	int i = GetIntFromVariant(pv);
	VariantClear(pv);
	return i;
}

BOOL GetShellFolder(IShellFolder **ppSF, LPCITEMIDLIST pidl)
{
	if (ILIsEmpty(pidl)) {
		SHGetDesktopFolder(ppSF);
		return TRUE;
	}
	IShellFolder *pSF;
	LPCITEMIDLIST pidlPart;
	if SUCCEEDED(SHBindToParent(pidl, IID_PPV_ARGS(&pSF), &pidlPart)) {
		pSF->BindToObject(pidlPart, NULL, IID_PPV_ARGS(ppSF));
		pSF->Release();
	}
	return (*ppSF != NULL);
}

BOOL GetStorage(IStorage **ppStorage, LPCITEMIDLIST pidl)
{
	IShellFolder *pSF;
	LPCITEMIDLIST pidlPart;
	if (ILIsEmpty(pidl)) {
		SHGetDesktopFolder(&pSF);
		pSF->QueryInterface(IID_PPV_ARGS(ppStorage));
		pSF->Release();
	} else if SUCCEEDED(SHBindToParent(pidl, IID_PPV_ARGS(&pSF), &pidlPart)) {
		pSF->BindToStorage(pidlPart, NULL, IID_PPV_ARGS(ppStorage));
		pSF->Release();
	}
	return *ppStorage != NULL;
}

susie_time_t FileTimeToSusieTime(FILETIME ft){
	LONGLONG ll = ((LONGLONG)ft.dwHighDateTime << 32) + ft.dwLowDateTime;
	return (susie_time_t)((ll - 116444736000000000) / 10000000);
}

BOOL GetFileTimeFromIDList(FILETIME *pft, IShellFolder2 *pSF2, LPITEMIDLIST pidl)
{
	BOOL bResult = FALSE;
	VARIANT v;
	VariantInit(&v);
	if FAILED(pSF2->GetDetailsEx(pidl, &PKEY_DateModified, &v)) {
		pSF2->GetDetailsEx(pidl, &PKEY_DateCreated, &v);
	}
	if (v.vt == VT_DATE) {
		SYSTEMTIME SysTime;
		if (::VariantTimeToSystemTime(v.date, &SysTime)) {
			::SystemTimeToFileTime(&SysTime, pft);
			bResult = TRUE;
		}
	}
	VariantClear(&v);
	return bResult;
}

HRESULT teGetDisplayNameBSTR(IShellFolder *pSF, PCUITEMID_CHILD pidl, SHGDNF uFlags, BSTR *pbs)
{
	STRRET strret;
	HRESULT hr = pSF->GetDisplayNameOf(pidl, uFlags, &strret);
	if SUCCEEDED(hr) {
		hr = StrRetToBSTR(&strret, pidl, pbs);
	}
	return hr;
}

HRESULT teGetDisplayNameBSTR2(IShellFolder *pSF, PCUITEMID_CHILD pidl, SHGDNF uFlags, BSTR *pbs)
{
	STRRET strret;
	HRESULT hr = pSF->GetDisplayNameOf(pidl, uFlags, &strret);
	if SUCCEEDED(hr) {
		hr = StrRetToBSTR(&strret, pidl, pbs);
		if SUCCEEDED(hr) {
			LPWSTR pwcsName;
			while (pwcsName = StrChrW(*pbs, '\\')) {
				*pwcsName = '_';
			}
			while (pwcsName = StrChrW(*pbs, ':')) {
				*pwcsName = '_';
			}
		}
	}
	return hr;
}

int ILGetCount(LPITEMIDLIST pidl)
{
	if (ILIsEmpty(pidl)) {
		return 0;
	}
	return ILGetCount(ILGetNext(pidl)) + 1;
}

BOOL teIsFileSystem(LPOLESTR bs)
{
	return lstrlen(bs) >= 3 && ((bs[0] == '\\' && bs[1] == '\\') || (bs[1] == ':' && bs[2] == '\\'));
}

VOID teSysFreeString(BSTR *pbs)
{
	if (*pbs) {
		::SysFreeString(*pbs);
		*pbs = NULL;
	}
}

BOOL teStrSameIFree(BSTR bs, LPWSTR lpstr2)
{
	BOOL b = lstrcmpi(bs, lpstr2) == 0;
	::SysFreeString(bs);
	return b;
}

VOID teCoTaskMemFree(LPVOID pv)
{
	if (pv) {
		try {
			::CoTaskMemFree(pv);
		} catch (...) {}
	}
}

HRESULT STDAPICALLTYPE teGetIDListFromObjectXP(IUnknown *punk, PIDLIST_ABSOLUTE *ppidl)
{
	IPersistFolder2 *pPF2;
	if SUCCEEDED(punk->QueryInterface(IID_PPV_ARGS(&pPF2))) {
		pPF2->GetCurFolder(ppidl);
		pPF2->Release();
		return *ppidl ? S_OK : E_FAIL;
	}
	IPersistIDList *pPI;
	if SUCCEEDED(punk->QueryInterface(IID_PPV_ARGS(&pPI))) {
		pPI->GetIDList(ppidl);
		pPI->Release();
		return *ppidl ? S_OK : E_FAIL;
	}
	FolderItem *pFI;
	if SUCCEEDED(punk->QueryInterface(IID_PPV_ARGS(&pFI))) {
		BSTR bstr;
		if SUCCEEDED(pFI->get_Path(&bstr)) {
			*ppidl = teILCreateFromPath(bstr);
			::SysFreeString(bstr);
		}
		pFI->Release();
		return *ppidl ? S_OK : E_FAIL;
	}
	return E_NOTIMPL;
}

BOOL teGetIDListFromObject(IUnknown *punk, LPITEMIDLIST *ppidl)
{
	*ppidl = NULL;
	if (!punk) {
		return FALSE;
	}
	if SUCCEEDED(teGetIDListFromObjectXP(punk, ppidl)) {
		return TRUE;
	}
	IServiceProvider *pSP;
	if SUCCEEDED(punk->QueryInterface(IID_PPV_ARGS(&pSP))) {
		IShellBrowser *pSB;
		if SUCCEEDED(pSP->QueryService(SID_SShellBrowser, IID_PPV_ARGS(&pSB))) {
			IShellView *pSV;
			if SUCCEEDED(pSB->QueryActiveShellView(&pSV)) {
				teGetIDListFromObjectXP(pSV, ppidl);
				pSV->Release();
			}
			pSB->Release();
		}
		pSP->Release();
	}
	return *ppidl != NULL;
}

LPITEMIDLIST teILCreateFromPath3(IShellFolder *pSF, LPWSTR pszPath, HWND hwnd)
{
	LPITEMIDLIST pidlResult = NULL;
	IEnumIDList *peidl = NULL;
	BSTR bstr = NULL;
	LPWSTR lpDelimiter = StrChr(pszPath, '\\');
	int nDelimiter = 0;
	if (lpDelimiter) {
		nDelimiter = (int)(lpDelimiter - pszPath);
	}
	int ashgdn[] = {SHGDN_FORADDRESSBAR | SHGDN_FORPARSING | SHGDN_INFOLDER, SHGDN_INFOLDER | SHGDN_FORPARSING};
	if SUCCEEDED(pSF->EnumObjects(hwnd, SHCONTF_FOLDERS | SHCONTF_NONFOLDERS | SHCONTF_INCLUDEHIDDEN | SHCONTF_INCLUDESUPERHIDDEN, &peidl)) {
		LPITEMIDLIST pidlPart;
		while (!pidlResult && peidl->Next(1, &pidlPart, NULL) == S_OK) {
			for (int j = 0; j < 2; j++) {
				if SUCCEEDED(teGetDisplayNameBSTR(pSF, pidlPart, ashgdn[j], &bstr)) {
					if (nDelimiter) {
						if (nDelimiter == ::SysStringLen(bstr) && StrCmpNI(const_cast<LPCWSTR>(pszPath), (LPCWSTR)bstr, nDelimiter) == 0) {
							IShellFolder *pSF1;
							if SUCCEEDED(pSF->BindToObject(pidlPart, NULL, IID_PPV_ARGS(&pSF1))) {
								pidlResult = teILCreateFromPath3(pSF1, &lpDelimiter[1], NULL);
								pSF1->Release();
							}
							::SysFreeString(bstr);
							break;
						}
						::SysFreeString(bstr);
					}
					if (teStrSameIFree(bstr, pszPath)) {
						LPITEMIDLIST pidlParent;
						if (teGetIDListFromObject(pSF, &pidlParent)) {
							pidlResult = ILCombine(pidlParent, pidlPart);
							teCoTaskMemFree(pidlParent);
						}
						break;
					}
				}
			}
			teCoTaskMemFree(pidlPart);
		}
		peidl->Release();
	}
	return pidlResult;
}

LPITEMIDLIST teILCreateFromPath2(LPITEMIDLIST pidlParent, LPWSTR pszPath, HWND hwnd)
{
	LPITEMIDLIST pidlResult = NULL;
	IShellFolder *pSF;
	if (GetShellFolder(&pSF, pidlParent)) {
		pidlResult = teILCreateFromPath3(pSF, pszPath, hwnd);
		pSF->Release();
	}
	return pidlResult;
}

HRESULT GetDisplayNameFromPidl(BSTR *pbs, LPITEMIDLIST pidl, SHGDNF uFlags)
{
	HRESULT hr = E_FAIL;
	IShellFolder *pSF;
	LPCITEMIDLIST pidlPart;

	if SUCCEEDED(SHBindToParent(pidl, IID_PPV_ARGS(&pSF), &pidlPart)) {
		hr = teGetDisplayNameBSTR(pSF, pidlPart, uFlags, pbs);
		if (hr == S_OK) {
			if (teIsFileSystem(*pbs)) {
			} else if (((uFlags & (SHGDN_FORADDRESSBAR | SHGDN_FORPARSING)) == (SHGDN_FORADDRESSBAR | SHGDN_FORPARSING))) {
				if (ILGetCount(pidl) == 1 || PathMatchSpec(*pbs, L"search-ms:*\\*")) {
					LPITEMIDLIST pidl2 = teILCreateFromPath2(g_pidls[CSIDL_DESKTOP], *pbs, NULL);
					if (!ILIsEqual(pidl, pidl2)) {
						teSysFreeString(pbs);
						hr = teGetDisplayNameBSTR(pSF, pidlPart, uFlags & (~SHGDN_FORADDRESSBAR), pbs);
					}
					teCoTaskMemFree(pidl2);
				}
			}
		}
		pSF->Release();
	}
	return hr;
}

HRESULT teILFolderExists(LPITEMIDLIST pidl)
{
	LPCITEMIDLIST pidlPart;
	IShellFolder *pSF;
	HRESULT hr = SHBindToParent(pidl, IID_PPV_ARGS(&pSF), &pidlPart);
	if FAILED(hr) {
		return hr & MAXWORD;
	}
	SFGAOF sfAttr = SFGAO_FOLDER | SFGAO_FILESYSTEM;
	if FAILED(pSF->GetAttributesOf(1, &pidlPart, &sfAttr)) {
		sfAttr = 0;
	}
	hr = sfAttr & SFGAO_FILESYSTEM ? E_FAIL : S_FALSE;
	if ((sfAttr & SFGAO_FOLDER) && FAILED(hr)) {
		IShellFolder *pSF1;
		hr = pSF->BindToObject(pidlPart, NULL, IID_PPV_ARGS(&pSF1));
		if SUCCEEDED(hr) {
			IEnumIDList *peidl = NULL;
			hr = pSF1->EnumObjects(NULL, SHCONTF_NONFOLDERS | SHCONTF_FOLDERS, &peidl);
			if (peidl) {
				LPITEMIDLIST pidlPart;
				hr = peidl->Next(1, &pidlPart, NULL);
				teCoTaskMemFree(pidlPart);
				peidl->Release();
			}
			if (hr == E_INVALID_PASSWORD || hr == E_CANCELLED) {
				hr &= MAXWORD;
			}
			pSF1->Release();
		}
	}
	pSF->Release();
	return hr;
}

HRESULT tePathIsDirectory(LPWSTR pszPath, int iUseFS)
{
	if (!(iUseFS & 2)) {
		WCHAR pszDrive[0x80];
		lstrcpyn(pszDrive, pszPath, 4);
		if (pszDrive[0] >= 'A' && pszDrive[1] == ':' && pszDrive[2] == '\\') {
			if (!GetVolumeInformation(pszDrive, NULL, 0, NULL, NULL, NULL, pszDrive, sizeof(pszDrive))) {
				return E_NOT_READY;
			}
		}
	}
	LPITEMIDLIST pidl = NULL;
	if (iUseFS) {
		lpfnSHParseDisplayName(pszPath, NULL, &pidl, 0, NULL);
	} else {
		pidl = teILCreateFromPath(pszPath);
	}
	if (pidl) {
		HRESULT hr = teILFolderExists(pidl);
		teCoTaskMemFree(pidl);
		return hr;
	}
	return E_FAIL;
}

BOOL GetCSIDLFromPath(int *i, LPWSTR pszPath)
{
	int n = lstrlen(pszPath);
	if (n <= 3 && pszPath[0] >= '0' && pszPath[0] <= '9') {
		swscanf_s(pszPath, L"%d", i);
		return (*i <= 9 && n == 1) || (*i >= 10 && *i <= 99 && n == 2) || (*i >= 100 && *i < MAX_CSIDL);
	}
	return FALSE;
}

LPITEMIDLIST teILCreateFromPath(LPWSTR pszPath)
{
	LPITEMIDLIST pidl = NULL;
	BSTR bstr = NULL;
	int n;

	if (pszPath) {
		BSTR bsPath2 = NULL;
		if (pszPath[0] == _T('"')) {
			bsPath2 = ::SysAllocStringLen(pszPath, lstrlen(pszPath) + 1);
			PathUnquoteSpaces(bsPath2);
			pszPath = bsPath2;
		}
		BSTR bsPath3 = NULL;
		if (PathMatchSpec(pszPath, L"search-ms:*&crumb=location:*")) {
			LPWSTR lp1, lp2;
			lp1 = StrChr(pszPath, ':');
			while (lp2 = StrChr(lp1 + 1, ':')) {
				lp1 = lp2;
			}
			lp1 -= 4;
			BSTR bs = ::SysAllocString(lp1);
			bs[0] = 'f';
			bs[1] = 'i';
			bs[2] = 'l';
			bs[3] = 'e';
			DWORD dwLen = ::SysStringLen(bs);
			bsPath3 = ::SysAllocStringLen(NULL, dwLen);
			if SUCCEEDED(PathCreateFromUrl(bs, bsPath3, &dwLen, 0)) {
				pszPath = bsPath3;
			}
		} else if (PathMatchSpec(pszPath, L"*\\..\\*;*\\..;*\\.\\*;*\\.;*%*%*")) {
			DWORD dwLen = lstrlen(pszPath) + MAX_PATH;
			bsPath3 = ::SysAllocStringLen(NULL, dwLen);
			if (PathSearchAndQualify(pszPath, bsPath3, dwLen)) {
				pszPath = bsPath3;
			}
		} else if (lstrlen(pszPath) == 1 && pszPath[0] >= 'A') {
			bsPath3 = ::SysAllocStringLen(L"?:\\", 4);
			bsPath3[0] = pszPath[0];
			pszPath = bsPath3;
		}
		if (GetCSIDLFromPath(&n, pszPath)) {
			pidl = ::ILClone(g_pidls[n]);
			pszPath = NULL;
		}
		if (pszPath) {
			if (PathMatchSpec(pszPath, L"\\\\*\\*")) {
				LPWSTR lpDelimiter = StrChr(&pszPath[2], '\\');
				BSTR bsServer = ::SysAllocStringLen(pszPath, int(lpDelimiter - pszPath));
				LPITEMIDLIST pidlServer;
				if SUCCEEDED(lpfnSHParseDisplayName(bsServer, NULL, &pidlServer, 0, NULL)) {
					pidl = teILCreateFromPath2(pidlServer, &lpDelimiter[1], 0);
					teCoTaskMemFree(pidlServer);
				}
				::SysFreeString(bsServer);
			}
			if (!pidl) {
				lpfnSHParseDisplayName(pszPath, NULL, &pidl, 0, NULL);
				if (pidl) {
/*					if (tePathIsNetworkPath(pszPath) && PathIsRoot(pszPath) && FAILED(tePathIsDirectory(pszPath, 0, 3))) {
						teILFreeClear(&pidl);
					}*/
				} else if (PathGetDriveNumber(pszPath) >= 0 && !PathIsRoot(pszPath)) {
					WCHAR pszDrive[4];
					lstrcpyn(pszDrive, pszPath, 4);
					int n = GetDriveType(pszDrive);
					if (n == DRIVE_NO_ROOT_DIR && SUCCEEDED(tePathIsDirectory(pszDrive, 0))) {
						lpfnSHParseDisplayName(pszPath, NULL, &pidl, 0, NULL);
					}
				}
			}
/*/// To parse too much.
			if (pidl == NULL && PathMatchSpec(pszPath, L"::{*")) {  
				int nSize = lstrlen(pszPath) + 6;
				BSTR bsPath4 = ::SysAllocStringLen(L"shell:", nSize);
				lstrcat(bsPath4, pszPath);
				lpfnSHParseDisplayName(bsPath4, NULL, &pidl, 0, NULL);
				::SysFreeString(bsPath4);
			}
//*/
			if (pidl == NULL && !teIsFileSystem(pszPath)) {
				for (int i = 0; i < g_nPidls; i++) {
					if (g_pidls[i]) {
						if (!lstrcmpi(bstr, g_bsPidls[i])) {
							pidl = ILClone(g_pidls[i]);
							break;
						}
					}
				}
				if (!pidl) {
					pidl = teILCreateFromPath2(g_pidls[CSIDL_DESKTOP], pszPath, NULL);
					if (!pidl) {
						pidl = teILCreateFromPath2(g_pidls[CSIDL_DRIVES], pszPath, NULL);
					}
				}
			}
		}
		teSysFreeString(&bsPath3);
		teSysFreeString(&bsPath2);
	}
	return pidl;
}

// Initialize & Finalize
BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason) {
		case DLL_PROCESS_ATTACH:
			lpfnSHParseDisplayName = (LPFNSHParseDisplayName)GetProcAddress(GetModuleHandle(L"shell32.dll"), "SHParseDisplayName");
			if (!lpfnSHParseDisplayName) {
				lpfnSHParseDisplayName = teSHParseDisplayName2000;
			}
			for (int i = MAX_CSIDL; i--;) {
				SHGetFolderLocation(NULL, i, NULL, NULL, &g_pidls[i]);
				g_bsPidls[i] = NULL;
				if (g_pidls[i]) {
					IShellFolder *pSF;
					LPCITEMIDLIST pidlPart;
					if SUCCEEDED(SHBindToParent(g_pidls[i], IID_PPV_ARGS(&pSF), &pidlPart)) {
						teGetDisplayNameBSTR(pSF, pidlPart, SHGDN_FORADDRESSBAR | SHGDN_FORPARSING, &g_bsPidls[i]);
						pSF->Release();
					}
				} else if (g_nPidls == i + 1) {
					g_nPidls--;
				}
				InitializeCriticalSection(&g_CriticalSection);
			}
			break;
		case DLL_PROCESS_DETACH:
			while (g_nPidls--) {
				teCoTaskMemFree(g_pidls[g_nPidls]);
				teSysFreeString(&g_bsPidls[g_nPidls]);
			}
			teCoTaskMemFree(g_pidlCache);
			DeleteCriticalSection(&g_CriticalSection);
			break;
	}
	return TRUE;
}

VOID GetPathInfoX(LPWSTR pszBufW, LPSTR pszBufA, LPWSTR pszOutW, BOOL bMemory)
{
	if (bMemory) {
		StrCpyNW(pszOutW, pszBufW ? pszBufW : (LPWSTR)pszBufA, MAX_PATH * 4);
	} else {
		::ZeroMemory(pszOutW, MAX_PATH * 4);
		HANDLE hFile = pszBufW ?
			CreateFileW(pszBufW, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL) :
			CreateFileA(pszBufA, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);		
		if (hFile != INVALID_HANDLE_VALUE) {
			DWORD dwSize;
			ReadFile(hFile, pszOutW, MAX_PATH * 4, &dwSize, NULL);
			CloseHandle(hFile);
		}
	}
}

int GetArchiveSF(LPWSTR pBufW, IShellFolder2 **ppSF2)
{
	int nResult = SPI_FILE_READ_ERROR;
	LPWSTR lpFileNameW = NULL;
	int n = FILE_HEADER_SIZE;
	if (pBufW[0] = 0xfeff && !StrCmpNIW(&pBufW[1], _T(FILE_HEADER)L":", n + 1)) {
		lpFileNameW = &pBufW[n + 2];
	}


	EnterCriticalSection(&g_CriticalSection);
	try {
		if (g_pidlCache && !lstrcmpi(lpFileNameW, g_pszCacheW)) {
			IShellFolder *pSF;
			if (GetShellFolder(&pSF, g_pidlCache)) {
				if SUCCEEDED(pSF->QueryInterface(IID_PPV_ARGS(ppSF2))) {
					nResult = SPI_ALL_RIGHT;
				}
				pSF->Release();
			}
		}
		if (nResult != SPI_ALL_RIGHT) {
			LPITEMIDLIST pidl = teILCreateFromPath(lpFileNameW);
			if (pidl) {
				teCoTaskMemFree(g_pidlCache);
				IShellFolder *pSF;
				if (GetShellFolder(&pSF, pidl)) {
					if SUCCEEDED(pSF->QueryInterface(IID_PPV_ARGS(ppSF2))) {
						g_pidlCache = pidl;
						lstrcpyn(g_pszCacheW, lpFileNameW, MAX_PATH * 4);
						pidl = NULL;
						nResult = SPI_ALL_RIGHT;
					} 
					pSF->Release();
				} 
				teCoTaskMemFree(pidl);
			}
		}
	}
	catch (...) {
		nResult = SPI_OTHER_ERROR;
	}
	LeaveCriticalSection(&g_CriticalSection);
	return nResult;
}

VOID SF2SusieInfoW(IShellFolder2 *pSF2, LPITEMIDLIST pidl, int i, SUSIE_FINFOTW *pInfo)
{
	BSTR bsName;
	teGetDisplayNameBSTR2(pSF2, pidl, SHGDN_INFOLDER | SHGDN_FORADDRESSBAR, &bsName);
	LPWSTR pwcsName = bsName;
	WCHAR pszNameW[MAX_PATH * 4];
	pInfo->position = i;
	VARIANT v;
	VariantInit(&v);
	pSF2->GetDetailsEx(pidl, &PKEY_Size, &v);
#ifdef _WIN64
	pInfo->filesize = GetLLFromVariant(&v);
#else
	LARGE_INTEGER cbSize;
	cbSize.QuadPart = GetLLFromVariant(&v);
	if (cbSize.HighPart) {
		pInfo->filesize = 0xffffffff;
	} else {
		pInfo->filesize = cbSize.LowPart;
	}
#endif
	VariantClear(&v);
	FILETIME ft;
	if (GetFileTimeFromIDList(&ft, pSF2, pidl)) {
		pInfo->timestamp = FileTimeToSusieTime(ft);
	} else {
		pInfo->timestamp = 0;
	}
	pInfo->path[0] = NULL;
	SFGAOF dwSFGAO = SFGAO_FOLDER;
	pSF2->GetAttributesOf(1, (LPCITEMIDLIST *)&pidl, &dwSFGAO);

	if (dwSFGAO & SFGAO_FOLDER) {
		strcpy_s((char *)pInfo->method, 8, "Folder");
		BSTR bs;
		teGetDisplayNameBSTR(pSF2, pidl, SHGDN_FORADDRESSBAR | SHGDN_FORPARSING, &bs);
		pInfo->filesize = ::SysStringByteLen(bs) + 4 + FILE_HEADER_SIZE * sizeof(WCHAR);
		::SysFreeString(bs);
		lstrcpy(pszNameW, pwcsName);
		lstrcat(pszNameW, L"."_T(SUSIE_EXT));
		pwcsName = pszNameW;
	} else {
		strcpy_s((char *)pInfo->method, 8, "File");
	}
	pInfo->compsize = pInfo->filesize;
	lstrcpyn(pInfo->filename, pwcsName, 200);
	pInfo->crc = 0;
	::SysFreeString(bsName);
}

VOID SF2SusieInfoA(IShellFolder2 *pSF2, LPITEMIDLIST pidl, int i, SUSIE_FINFO *pInfo)
{
	SUSIE_FINFOTW InfoW;
	SF2SusieInfoW(pSF2, pidl, i, &InfoW);
	memcpy(pInfo->method, InfoW.method, 8);
	pInfo->position = InfoW.position;
	pInfo->compsize = InfoW.compsize;
	pInfo->filesize = InfoW.filesize;
	pInfo->timestamp = InfoW.timestamp;
	int nLenA = WideCharToMultiByte(CP_ACP, 0, InfoW.path, lstrlen(InfoW.path), pInfo->path, 200, NULL, NULL);
	pInfo->path[nLenA] = NULL;
	nLenA = WideCharToMultiByte(CP_ACP, 0, InfoW.filename, lstrlen(InfoW.filename), pInfo->filename, 200, NULL, NULL);
	pInfo->filename[nLenA] = NULL;
	pInfo->crc = InfoW.crc;
}

VOID GetLocalMemFromIDList(HLOCAL *phMem, LPITEMIDLIST pidl, DWORD *pdwWriteByte)
{
	BSTR bs;
	if SUCCEEDED(GetDisplayNameFromPidl(&bs, pidl, SHGDN_FORADDRESSBAR | SHGDN_FORPARSING)) {
		*pdwWriteByte = ::SysStringByteLen(bs) + 4 + FILE_HEADER_SIZE * sizeof(WCHAR);;
		*phMem = LocalAlloc(LMEM_FIXED, *pdwWriteByte);
		if (*phMem) {
			LPWSTR lp = (LPWSTR)LocalLock(*phMem);
			if (lp) {
				try {
					lp[0] = 0xfeff;
					lstrcpy(&lp[1], _T(FILE_HEADER)L":");
					CopyMemory(&lp[5], bs, ::SysStringByteLen(bs));
				} catch (...) {}
				LocalUnlock(*phMem);
			}
		}
		::SysFreeString(bs);
	}
}

int GetArchiveInfoX(LPWSTR lpBufW, HLOCAL *lphInf, BOOL bWideChar)
{
	IShellFolder2 *pSF2 = NULL;
	int nResult = GetArchiveSF(lpBufW, &pSF2);
	if (nResult != SPI_ALL_RIGHT) {
		return nResult;
	}
	SUSIE_FINFO		*ppInfo;
	SUSIE_FINFOTW	*ppInfoW;
	IEnumIDList *peidl = NULL;
	if SUCCEEDED(pSF2->EnumObjects(NULL, SHCONTF_FOLDERS | SHCONTF_NONFOLDERS | SHCONTF_INCLUDEHIDDEN | SHCONTF_INCLUDESUPERHIDDEN, &peidl)) {
		int nCount = 0;
		LPITEMIDLIST pidlPart;
		while (peidl->Next(1, &pidlPart, NULL) == S_OK) {
			teCoTaskMemFree(pidlPart);
			nCount++;
		}
		int nAlloc = bWideChar ? (nCount + 1) * sizeof(SUSIE_FINFOTW) : (nCount + 1) * sizeof(SUSIE_FINFO);
		*lphInf = LocalAlloc(LMEM_FIXED, nAlloc);
		if (*lphInf) {
			ppInfoW = (SUSIE_FINFOTW *)LocalLock(*lphInf);
			if (ppInfoW) {
				ppInfo = (SUSIE_FINFO *)ppInfoW;
				try {
					::ZeroMemory(ppInfo, nAlloc);
					if (peidl->Reset() != S_OK) {
						peidl->Release();
						if FAILED(pSF2->EnumObjects(NULL, SHCONTF_FOLDERS | SHCONTF_NONFOLDERS | SHCONTF_INCLUDEHIDDEN | SHCONTF_INCLUDESUPERHIDDEN, &peidl)) {
							peidl = NULL;
						}
					}
					if (peidl) {
						for (int i = 0; i < nCount && peidl->Next(1, &pidlPart, NULL) == S_OK; i++) {
							if (bWideChar) {
								SF2SusieInfoW(pSF2, pidlPart, i, &ppInfoW[i]);
							} else {
								SF2SusieInfoA(pSF2, pidlPart, i, &ppInfo[i]);
							}
							teCoTaskMemFree(pidlPart);
						}
					}
					LocalUnlock(*lphInf);
				} catch (...) {
					nResult = SPI_OTHER_ERROR;
				}
			} else {
				nResult = SPI_NO_MEMORY;
			}
		} else {
			nResult = SPI_NO_MEMORY;
		}
		if (peidl) {
			peidl->Release();
		}
	}
	pSF2->Release();
	return nResult;
}

int GetFileInfoX(LPWSTR buf, LONG_PTR len, LPVOID filename, unsigned int flag, LPVOID lpInfo, BOOL bWideChar)
{
	WCHAR pszNameW[MAX_PATH * 4];
	WCHAR pszName2W[MAX_PATH * 4];
	IShellFolder2 *pSF2 = NULL;
	int nResult = GetArchiveSF(buf, &pSF2);
	if (nResult == SPI_ALL_RIGHT) {
		nResult = SPI_OUT_OF_ORDER;
		if (bWideChar) {
			lstrcpy((LPWSTR)pszNameW, (LPCWSTR)filename);
		} else {
			int nLenA = MultiByteToWideChar(CP_ACP, 0, (LPSTR)filename, strlen((LPSTR)filename), (LPWSTR)pszNameW, MAX_PATH * 4);
			pszNameW[nLenA] = NULL;
		}
		IEnumIDList *peidl = NULL;
		if SUCCEEDED(pSF2->EnumObjects(NULL, SHCONTF_FOLDERS | SHCONTF_NONFOLDERS | SHCONTF_INCLUDEHIDDEN | SHCONTF_INCLUDESUPERHIDDEN, &peidl)) {
			LPITEMIDLIST pidlPart;
			BSTR bsName;
			for (int i = 0; i < peidl->Next(1, &pidlPart, NULL) == S_OK; i++) {
				teGetDisplayNameBSTR2(pSF2, pidlPart, SHGDN_INFOLDER | SHGDN_FORADDRESSBAR, &bsName);
				SFGAOF dwSFGAO = SFGAO_FOLDER;
				pSF2->GetAttributesOf(1, (LPCITEMIDLIST *)&pidlPart, &dwSFGAO);
				LPWSTR pszName0W = bsName;
				if (dwSFGAO & SFGAO_FOLDER) {
					lstrcpy(pszName2W, pszName0W);
					lstrcat(pszName2W, L"."_T(SUSIE_EXT));
					pszName0W = pszName2W;
				}
				if (lstrcmpi(pszNameW, pszName0W) == 0) {
					if (bWideChar) {
						SF2SusieInfoW(pSF2, pidlPart, i, (SUSIE_FINFOTW *)lpInfo);
					} else {
						SF2SusieInfoA(pSF2, pidlPart, i, (SUSIE_FINFO *)lpInfo);
					}
					nResult = SPI_ALL_RIGHT;
					break;
				}
				teSysFreeString(&bsName);
				CoTaskMemFree(pidlPart);
			}
			peidl->Release();
		}
		pSF2->Release();
	}
	return nResult;
}

int GetFileX(LPWSTR src, LONG_PTR len, PVOID dest, unsigned int flag, SUSIE_PROGRESS progressCallback, LONG_PTR lData, BOOL bWideChar)
{
 	WCHAR pszNameW[MAX_PATH * 4];
	DWORD dwWriteByte = 0;
	HLOCAL hMem = NULL;
	IStream *pStream = NULL;
	IShellFolder2 *pSF2 = NULL;
	FILETIME ft;
	ft.dwLowDateTime = 0;
	ULONGLONG llSize = 0;
	if (flag & 0x600) {
		return SPI_NO_FUNCTION;
	}
 	int nResult = GetArchiveSF(src, &pSF2);
	if (nResult == SPI_ALL_RIGHT) {
		nResult = SPI_OUT_OF_ORDER;
		IEnumIDList *peidl = NULL;
		if SUCCEEDED(pSF2->EnumObjects(NULL, SHCONTF_FOLDERS | SHCONTF_NONFOLDERS | SHCONTF_INCLUDEHIDDEN | SHCONTF_INCLUDESUPERHIDDEN, &peidl)) {
			LPITEMIDLIST pidlPart;
			for (int i = 0; i < len && peidl->Next(1, &pidlPart, NULL) == S_OK; i++) {
				teCoTaskMemFree(pidlPart);
			}
			if (peidl->Next(1, &pidlPart, NULL) == S_OK) {
				if (!(flag & 0x100)) {
					BSTR bs;
					teGetDisplayNameBSTR2(pSF2, pidlPart, SHGDN_FORADDRESSBAR | SHGDN_INFOLDER, &bs);
					lstrcpy(pszNameW, bs);
					::SysFreeString(bs);
				}
				SFGAOF dwSFGAO = SFGAO_FOLDER;
				pSF2->GetAttributesOf(1, (LPCITEMIDLIST *)&pidlPart, &dwSFGAO);
				if (dwSFGAO & SFGAO_FOLDER) {
					LPITEMIDLIST pidlParent;
					teGetIDListFromObject(pSF2, &pidlParent);
					LPITEMIDLIST pidlFull = ILCombine(pidlParent, pidlPart);
					GetLocalMemFromIDList(&hMem, pidlFull, &dwWriteByte);
					::CoTaskMemFree(pidlFull);
					::CoTaskMemFree(pidlParent);
					if (!(flag & 0x100)) {
						lstrcat(pszNameW, L"."_T(SUSIE_EXT));
					}
				} else {
					VARIANT v;
					VariantInit(&v);
					pSF2->GetDetailsEx(pidlPart, &PKEY_Size, &v);
					llSize = GetLLFromVariant(&v);
					if (llSize > 0xffffffff && (flag & 0x100)) {
						nResult = SPI_NO_MEMORY;
					} else if (progressCallback && progressCallback(0, 100, lData)) {
						nResult = SPI_ABORT;
					} else if SUCCEEDED(pSF2->BindToStorage(pidlPart, NULL, IID_PPV_ARGS(&pStream))) {
						if (flag & 0x100) {
							DWORD dwSize = (DWORD)llSize;
							hMem = LocalAlloc(LMEM_FIXED, dwSize);
							if (hMem) {
								PVOID pv = LocalLock(hMem);
								if (pv) {
									try {
										pStream->Read(pv, dwSize, &dwWriteByte);
									} catch (...) {}
									LocalUnlock(hMem);
								} else {
									LocalFree(hMem);
									hMem = NULL;
									nResult = SPI_NO_MEMORY;
								}
							} else {
								nResult = SPI_NO_MEMORY;
							}
							pStream->Release();
							pStream = NULL;
						} else {
							GetFileTimeFromIDList(&ft, pSF2, pidlPart);
						}
					}
				}
				teCoTaskMemFree(pidlPart);
			}
		}
		pSF2->Release();
	}
	if (hMem || pStream) {
		if (flag & 0x100) {
			*((HLOCAL *)dest) = hMem;
			nResult = progressCallback && progressCallback(100, 100, lData) ? SPI_ABORT : SPI_ALL_RIGHT;
		} else {
			WCHAR pszPathW[MAX_PATH * 4];
			if (bWideChar) {
				lstrcpy((LPWSTR)pszPathW, (LPCWSTR)dest);
			} else {
				int nLenA = MultiByteToWideChar(CP_ACP, 0, (LPSTR)dest, strlen((LPSTR)dest), (LPWSTR)pszPathW, MAX_PATH * 4);
				pszPathW[nLenA] = NULL;
			}
			PathAppend(pszPathW, pszNameW);
			HANDLE hFile = CreateFileW((LPCWSTR)pszPathW, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile != INVALID_HANDLE_VALUE) {
				ULONG uRead = dwWriteByte;
				if (hMem) {
					PVOID pv = LocalLock(hMem);
					if (pv) {
						try {
							WriteFile(hFile, pv, uRead, &dwWriteByte, NULL);
						} catch (...) {
							nResult = SPI_FILE_WRITE_ERROR;
						}
						LocalUnlock(hMem);
					}
					nResult = progressCallback && progressCallback(100, 100, lData) ? SPI_ABORT : SPI_ALL_RIGHT;
				} else if (pStream) {
					try {
						nResult = SPI_ALL_RIGHT;
						BYTE lpData[SIZE_BUFF];
						ULONGLONG llWrited = 0;
						while (SUCCEEDED(pStream->Read(lpData, SIZE_BUFF, &uRead)) && uRead) {
							if (progressCallback && llSize) {
								if (progressCallback((int)(llWrited * 100 / llSize), 100, lData)) {
									nResult = SPI_ABORT;
									break;
								}
							}
							WriteFile(hFile, lpData, uRead, &dwWriteByte, NULL);
							llWrited += dwWriteByte;
						}
					} catch (...) {
						nResult = SPI_FILE_WRITE_ERROR;
					}
				}
				if (ft.dwLowDateTime) {
					SetFileTime(hFile, NULL, NULL, &ft);
				}
				CloseHandle(hFile);
			}
			if (hMem) {
				LocalFree(hMem);
			}
			if (pStream) {
				pStream->Release();
			}
		}
	}
	return nResult;
}

// DLL Exports

int __stdcall GetPluginInfoW(int infono, LPWSTR buf, int buflen)
{
	switch (infono){
		case 0:
			lstrcpyn(buf, L"00AM", buflen);
			break;
		case 1:
			lstrcpyn(buf, L"Tablacus Shell Susie Plug-in 1.00 Gaku", buflen);
			break;
		case 2:
			lstrcpyn(buf, L"*."_T(SUSIE_EXT), buflen);
			break;
		case 3:
			lstrcpyn(buf, L"shell", buflen);
			break;
		default:
			buf[0] = NULL;
			break;
	}
	return lstrlen(buf);
}

int __stdcall GetPluginInfo(int infono, LPSTR buf, int buflen)
{
	WCHAR bufW[64];
	int nLenW = GetPluginInfoW(infono, bufW, 80);
	int nLenA = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)bufW, nLenW, buf, 64, NULL, NULL);
	buf[nLenA] = NULL;
	return nLenA;
}

int __stdcall IsSupportedW(LPCWSTR filename, void *dw)
{
	LPWSTR pBufW = NULL;
	WCHAR pszBufW[MAX_PATH * 4];

	if ((DWORD_PTR)dw & ~(DWORD_PTR)0xffff) {
		pBufW = (LPWSTR)dw;
	} else {
		DWORD dwSize;
		if (ReadFile((HANDLE)dw, pszBufW, MAX_PATH * 4, &dwSize, NULL)) {
			pBufW = pszBufW;
		}
	}
	return pBufW[0] = 0xfeff && !StrCmpNIW(&pBufW[1], _T(FILE_HEADER)L":", FILE_HEADER_SIZE + 1); 
}

int __stdcall IsSupported(LPCSTR filename, void *dw)
{
	return IsSupportedW(NULL, dw);
/*// IsSupportedWではファイル名で判断していないので変換不要
	if (!filename) {
		return IsSupportedW(NULL, dw);
	}
	WCHAR filenameW[MAX_PATH * 4];
	int nLenA = MultiByteToWideChar(CP_ACP, 0, filename, strlen(filename), (LPWSTR)filenameW, MAX_PATH * 4);
	filenameW[nLenA] = NULL;
	return IsSupportedW(filenameW, dw);*/
}

int __stdcall GetArchiveInfoW(LPCWSTR buf, LONG_PTR len, unsigned int flag, HLOCAL *lphInf)
{
	if (flag & 6) {
		return SPI_NO_FUNCTION;
	}
	WCHAR pszBufW[MAX_PATH * 4];
	GetPathInfoX((LPWSTR)buf, NULL, pszBufW, flag & 1);
	return GetArchiveInfoX(pszBufW, lphInf, TRUE);
}

int __stdcall GetArchiveInfo(LPCSTR buf, LONG_PTR len, unsigned int flag, HLOCAL *lphInf)
{
	if (flag & 6) {
		return SPI_NO_FUNCTION;
	}
	WCHAR pszBufW[MAX_PATH * 4];
	GetPathInfoX(NULL, (LPSTR)buf, pszBufW, flag & 1);
	return GetArchiveInfoX(pszBufW, lphInf, FALSE);
}

int __stdcall GetFileInfoW(LPCWSTR buf, LONG_PTR len, LPCWSTR filename, unsigned int flag, SUSIE_FINFOTW *lpInfo)
{
	WCHAR pszBufW[MAX_PATH * 4];
	GetPathInfoX((LPWSTR)buf, NULL, pszBufW, flag & 7);
	return GetFileInfoX(pszBufW, len, (LPVOID)filename, flag, lpInfo, TRUE);
}

int __stdcall GetFileInfo(LPCSTR buf, LONG_PTR len, LPCSTR filename, unsigned int flag, SUSIE_FINFO *lpInfo)
{
	WCHAR pszBufW[MAX_PATH * 4];
	GetPathInfoX(NULL, (LPSTR)buf, pszBufW, flag & 7);
	return GetFileInfoX(pszBufW, len, (LPVOID)filename, flag, lpInfo, FALSE);
}

int __stdcall GetFileW(LPCWSTR src, LONG_PTR len, LPWSTR dest, unsigned int flag, SUSIE_PROGRESS progressCallback, LONG_PTR lData)
{
	WCHAR pszBufW[MAX_PATH * 4];
	GetPathInfoX((LPWSTR)src, NULL, pszBufW, flag & 7);
	return GetFileX(pszBufW, len, dest, flag, progressCallback, lData, TRUE);
}

int __stdcall GetFile(LPCSTR src, LONG_PTR len, LPSTR dest, unsigned int flag, SUSIE_PROGRESS progressCallback, LONG_PTR lData)
{
	WCHAR pszBufW[MAX_PATH * 4];
	GetPathInfoX(NULL, (LPSTR)src, pszBufW, flag & 7);
	return GetFileX(pszBufW, len, dest, flag, progressCallback, lData, FALSE);
}

/*
int __stdcall ConfigurationDlg(HWND parent, int fnc)
{
	MessageBox(0,0,0,0);
	return SPI_ALL_RIGHT;
}
*/