#define WIN32_LEAN_AND_MEAN
#pragma comment(lib, "legacy_stdio_definitions.lib")

#ifdef WIN64
#define PASSTHRU __stdcall
#define EXPDECL 
#else
#define PASSTHRU __stdcall
#define EXPDECL __declspec(dllexport)
#endif
#define LABEL "security_buster 0.3 (c) 2022-2023 Haruka"

#include <windows.h>
#include "config.h"
#include "dprintf.h"
#include <winhttp.h>

HINSTANCE hLThis = NULL;
FARPROC p[67];
HINSTANCE hOriginalDll = NULL;
FARPROC PA = NULL;
int ASMJmpToPA();

static struct buster_config config;
static const wchar_t* redir_scheme = L"http";

// Hook definitions

typedef BOOL(__stdcall* __E__4__orig)(HINTERNET, LPCWSTR, DWORD, DWORD);
__E__4__orig WinHttpAddRequestHeaders_orig;
typedef BOOL(__stdcall* __E__6__orig)();
__E__6__orig WinHttpCheckPlatform_orig;
typedef BOOL(__stdcall* __E__7__orig)(HINTERNET);
__E__7__orig WinHttpCloseHandle_orig;
typedef HINTERNET(__stdcall* __E__8__orig)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
__E__8__orig WinHttpConnect_orig;
typedef BOOL(__stdcall* __E__20__orig)(LPCWSTR, DWORD, DWORD, LPURL_COMPONENTS);
__E__20__orig WinHttpCrackUrl_orig;
typedef DWORD(__stdcall* __E__21__orig)(HINTERNET, HINTERNET*);
__E__21__orig WinHttpCreateProxyResolver_orig;
typedef void(__stdcall* __E__25__orig)(WINHTTP_PROXY_RESULT_EX*);
__E__25__orig WinHttpFreeProxyResultEx_orig;
typedef BOOL(__stdcall* __E__28__orig)(PWINHTTP_CURRENT_USER_IE_PROXY_CONFIG);
__E__28__orig WinHttpGetIEProxyConfigForCurrentUser_orig;
typedef BOOL(__stdcall* __E__31__orig)(HINTERNET, PCWSTR, WINHTTP_AUTOPROXY_OPTIONS*, DWORD, BYTE*, DWORD_PTR);
__E__31__orig WinHttpGetProxyForUrlEx2_orig;
typedef DWORD(__stdcall* __E__34__orig)(HINTERNET, WINHTTP_PROXY_RESULT_EX*);
__E__34__orig WinHttpGetProxyResultEx_orig;
typedef HINTERNET (__stdcall* __E__37__orig)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
__E__37__orig WinHttpOpen_orig;
typedef HINTERNET(__stdcall* __E__38__orig)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
__E__38__orig WinHttpOpenRequest_orig;
typedef BOOL(__stdcall* __E__42__orig)(HINTERNET, LPDWORD);
__E__42__orig WinHttpQueryDataAvailable_orig;
typedef BOOL(__stdcall* __E__43__orig)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
__E__43__orig WinHttpQueryHeaders_orig;
typedef BOOL(__stdcall* __E__45__orig)(HINTERNET, LPVOID, DWORD, LPDWORD);
__E__45__orig WinHttpReadData_orig;
typedef BOOL(__stdcall* __E__48__orig)(HINTERNET, LPVOID);
__E__48__orig WinHttpReceiveResponse_orig;
typedef BOOL(__stdcall* __E__51__orig)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
__E__51__orig WinHttpSendRequest_orig;
typedef BOOL(__stdcall* __E__54__orig)(HINTERNET, DWORD, LPVOID, DWORD);
__E__54__orig WinHttpSetOption_orig;
typedef WINHTTP_STATUS_CALLBACK(__stdcall* __E__55__orig)(HINTERNET, WINHTTP_STATUS_CALLBACK, DWORD, DWORD_PTR);
__E__55__orig WinHttpSetStatusCallback_orig;
typedef BOOL(__stdcall* __E__56__orig)(HINTERNET, int, int, int, int);
__E__56__orig WinHttpSetTimeouts_orig;
typedef BOOL(__stdcall* __E__65__orig)(HINTERNET, LPCVOID, DWORD, LPDWORD);
__E__65__orig WinHttpWriteData_orig;


BOOL WINAPI DllMain(HINSTANCE hInst,DWORD reason,LPVOID unk)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		dprintf(LABEL" loading...\n");
		load_config(&config);

		hLThis = hInst;
#ifdef _WIN64
		hOriginalDll = LoadLibraryA("C:\\Windows\\system32\\winhttp.dll");
#else
		hOriginalDll = LoadLibraryA("C:\\Windows\\SysWOW64\\winhttp.dll");
#endif
		if (!hOriginalDll) {
			dprintf("LoadLibraryA FAILED: %ld\n", GetLastError());
			return 0;
		}

		p[0] = GetProcAddress(hOriginalDll, "DllCanUnloadNow");
		p[1] = GetProcAddress(hOriginalDll, "DllGetClassObject");
		p[2] = GetProcAddress(hOriginalDll, "Private1");
		p[3] = GetProcAddress(hOriginalDll, "SvchostPushServiceGlobals");
		p[4] = GetProcAddress(hOriginalDll, "WinHttpAddRequestHeaders");
		p[5] = GetProcAddress(hOriginalDll, "WinHttpAutoProxySvcMain");
		p[6] = GetProcAddress(hOriginalDll, "WinHttpCheckPlatform");
		p[7] = GetProcAddress(hOriginalDll, "WinHttpCloseHandle");
		p[8] = GetProcAddress(hOriginalDll, "WinHttpConnect");
		p[9] = GetProcAddress(hOriginalDll, "WinHttpConnectionDeletePolicyEntries");
		p[10] = GetProcAddress(hOriginalDll, "WinHttpConnectionDeleteProxyInfo");
		p[11] = GetProcAddress(hOriginalDll, "WinHttpConnectionFreeNameList");
		p[12] = GetProcAddress(hOriginalDll, "WinHttpConnectionFreeProxyInfo");
		p[13] = GetProcAddress(hOriginalDll, "WinHttpConnectionFreeProxyList");
		p[14] = GetProcAddress(hOriginalDll, "WinHttpConnectionGetNameList");
		p[15] = GetProcAddress(hOriginalDll, "WinHttpConnectionGetProxyInfo");
		p[16] = GetProcAddress(hOriginalDll, "WinHttpConnectionGetProxyList");
		p[17] = GetProcAddress(hOriginalDll, "WinHttpConnectionSetPolicyEntries");
		p[18] = GetProcAddress(hOriginalDll, "WinHttpConnectionSetProxyInfo");
		p[19] = GetProcAddress(hOriginalDll, "WinHttpConnectionUpdateIfIndexTable");
		p[20] = GetProcAddress(hOriginalDll, "WinHttpCrackUrl");
		p[21] = GetProcAddress(hOriginalDll, "WinHttpCreateProxyResolver");
		p[22] = GetProcAddress(hOriginalDll, "WinHttpCreateUrl");
		p[23] = GetProcAddress(hOriginalDll, "WinHttpDetectAutoProxyConfigUrl");
		p[24] = GetProcAddress(hOriginalDll, "WinHttpFreeProxyResult");
		p[25] = GetProcAddress(hOriginalDll, "WinHttpFreeProxyResultEx");
		p[26] = GetProcAddress(hOriginalDll, "WinHttpFreeProxySettings");
		p[27] = GetProcAddress(hOriginalDll, "WinHttpGetDefaultProxyConfiguration");
		p[28] = GetProcAddress(hOriginalDll, "WinHttpGetIEProxyConfigForCurrentUser");
		p[29] = GetProcAddress(hOriginalDll, "WinHttpGetProxyForUrl");
		p[30] = GetProcAddress(hOriginalDll, "WinHttpGetProxyForUrlEx");
		p[31] = GetProcAddress(hOriginalDll, "WinHttpGetProxyForUrlEx2");
		p[32] = GetProcAddress(hOriginalDll, "WinHttpGetProxyForUrlHvsi");
		p[33] = GetProcAddress(hOriginalDll, "WinHttpGetProxyResult");
		p[34] = GetProcAddress(hOriginalDll, "WinHttpGetProxyResultEx");
		p[35] = GetProcAddress(hOriginalDll, "WinHttpGetProxySettingsVersion");
		p[36] = GetProcAddress(hOriginalDll, "WinHttpGetTunnelSocket");
		p[37] = GetProcAddress(hOriginalDll, "WinHttpOpen");
		p[38] = GetProcAddress(hOriginalDll, "WinHttpOpenRequest");
		p[39] = GetProcAddress(hOriginalDll, "WinHttpPacJsWorkerMain");
		p[40] = GetProcAddress(hOriginalDll, "WinHttpProbeConnectivity");
		p[41] = GetProcAddress(hOriginalDll, "WinHttpQueryAuthSchemes");
		p[42] = GetProcAddress(hOriginalDll, "WinHttpQueryDataAvailable");
		p[43] = GetProcAddress(hOriginalDll, "WinHttpQueryHeaders");
		p[44] = GetProcAddress(hOriginalDll, "WinHttpQueryOption");
		p[45] = GetProcAddress(hOriginalDll, "WinHttpReadData");
		p[46] = GetProcAddress(hOriginalDll, "WinHttpReadProxySettings");
		p[47] = GetProcAddress(hOriginalDll, "WinHttpReadProxySettingsHvsi");
		p[48] = GetProcAddress(hOriginalDll, "WinHttpReceiveResponse");
		p[49] = GetProcAddress(hOriginalDll, "WinHttpResetAutoProxy");
		p[50] = GetProcAddress(hOriginalDll, "WinHttpSaveProxyCredentials");
		p[51] = GetProcAddress(hOriginalDll, "WinHttpSendRequest");
		p[52] = GetProcAddress(hOriginalDll, "WinHttpSetCredentials");
		p[53] = GetProcAddress(hOriginalDll, "WinHttpSetDefaultProxyConfiguration");
		p[54] = GetProcAddress(hOriginalDll, "WinHttpSetOption");
		p[55] = GetProcAddress(hOriginalDll, "WinHttpSetStatusCallback");
		p[56] = GetProcAddress(hOriginalDll, "WinHttpSetTimeouts");
		p[57] = GetProcAddress(hOriginalDll, "WinHttpTimeFromSystemTime");
		p[58] = GetProcAddress(hOriginalDll, "WinHttpTimeToSystemTime");
		p[59] = GetProcAddress(hOriginalDll, "WinHttpWebSocketClose");
		p[60] = GetProcAddress(hOriginalDll, "WinHttpWebSocketCompleteUpgrade");
		p[61] = GetProcAddress(hOriginalDll, "WinHttpWebSocketQueryCloseStatus");
		p[62] = GetProcAddress(hOriginalDll, "WinHttpWebSocketReceive");
		p[63] = GetProcAddress(hOriginalDll, "WinHttpWebSocketSend");
		p[64] = GetProcAddress(hOriginalDll, "WinHttpWebSocketShutdown");
		p[65] = GetProcAddress(hOriginalDll, "WinHttpWriteData");
		p[66] = GetProcAddress(hOriginalDll, "WinHttpWriteProxySettings");

		WinHttpAddRequestHeaders_orig = (__E__4__orig)p[4];
		WinHttpCheckPlatform_orig = (__E__6__orig)p[6];
		WinHttpCloseHandle_orig = (__E__7__orig)p[7];
		WinHttpConnect_orig = (__E__8__orig)p[8];
		WinHttpCrackUrl_orig = (__E__20__orig)p[20];
		WinHttpCreateProxyResolver_orig = (__E__21__orig)p[21];
		WinHttpFreeProxyResultEx_orig = (__E__25__orig)p[25];
		WinHttpGetIEProxyConfigForCurrentUser_orig = (__E__28__orig)p[28];
		WinHttpGetProxyForUrlEx2_orig = (__E__31__orig)p[31];
		WinHttpGetProxyResultEx_orig = (__E__34__orig)p[34];
		WinHttpOpen_orig = (__E__37__orig)p[37];
		WinHttpOpenRequest_orig = (__E__38__orig)p[38];
		WinHttpQueryDataAvailable_orig = (__E__42__orig)p[42];
		WinHttpQueryHeaders_orig = (__E__43__orig)p[43];
		WinHttpReadData_orig = (__E__45__orig)p[45];
		WinHttpReceiveResponse_orig = (__E__48__orig)p[48];
		WinHttpSendRequest_orig = (__E__51__orig)p[51];
		WinHttpSetOption_orig = (__E__54__orig)p[54];
		WinHttpSetStatusCallback_orig = (__E__55__orig)p[55];
		WinHttpSetTimeouts_orig = (__E__56__orig)p[56];
		WinHttpWriteData_orig = (__E__65__orig)p[65];

		dprintf("security_buster: initialization successful\n");
	}

	if (reason == DLL_PROCESS_DETACH)
	{
		FreeLibrary(hOriginalDll);
		return 1;
	}

	return 1;
}

EXPDECL HINTERNET PASSTHRU PROXY_WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved) {
	dprintf("security_buster: WinHttpConnect ptr=%ld, server=%S:%d\n", hSession, pswzServerName, nServerPort);
	HINTERNET handle = WinHttpConnect_orig(hSession, pswzServerName, nServerPort, dwReserved);
	dprintf("security_buster: WinHttpConnect result: ptr=%ld, ret=%ld\n", handle, GetLastError());
	return handle;
}

EXPDECL BOOL PASSTHRU PROXY_WinHttpCrackUrl(LPCWSTR pwszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTS lpUrlComponents) {
	if (!config.enable || (!config.strip_https && config.redirect_host == NULL)) {
		return WinHttpCrackUrl_orig(pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
	}

	BOOL ret = WinHttpCrackUrl_orig(pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
	dprintf("security_buster: network request: %S\n", lpUrlComponents->lpszHostName);
	if (ret) {
		if (config.strip_https) {
			dprintf("security_buster: https2http\n");
			lpUrlComponents->lpszScheme = (wchar_t*)redir_scheme;
			lpUrlComponents->dwSchemeLength = (DWORD)wcslen(redir_scheme);
			lpUrlComponents->nScheme = 1;
			lpUrlComponents->nPort = 80;
		}
		if (wcslen(config.redirect_host) > 0) {
			dprintf("security_buster: %S -> %S\n", lpUrlComponents->lpszHostName, config.redirect_host);
			if (config.heap_alloc) {
				dprintf("security_buster: Reallocating host name\n");
				size_t nChars = (wcslen(config.redirect_host) + 1);
				LPVOID mem = HeapAlloc(GetProcessHeap(), 0, nChars * sizeof(wchar_t));
				if (mem == NULL) {
					dprintf("security_buster: HeapAlloc failed: %ld\n", GetLastError());
				}
				else {
					if (wcscpy_s((wchar_t*)mem, nChars, config.redirect_host)) {
						dprintf("security_buster: wcscpy_s failed: %ld\n", GetLastError());
					}
					else {
						lpUrlComponents->lpszHostName = (LPWSTR)mem;
					}
				}
			}
			else {
				lpUrlComponents->lpszHostName = config.redirect_host;
				lpUrlComponents->dwHostNameLength = (DWORD)wcslen(config.redirect_host);
			}
		}
		if (config.redirect_port != 0) {
			dprintf("security_buster: port %d -> %d\n", lpUrlComponents->nPort, config.redirect_port);
			lpUrlComponents->nPort = config.redirect_port;

		}
	}
	else {
		dprintf("security_buster: WinHttpCrackUrl failed: %ld\n", GetLastError());
	}

	return ret;
}

EXPDECL HINTERNET PASSTHRU PROXY_WinHttpOpen(LPCWSTR pszAgentW, DWORD   dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD   dwFlags) {
	dprintf("security_buster: Starting (agent=%S, flags=%d)\n", pszAgentW, dwFlags);
	HINTERNET handle = WinHttpOpen_orig(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags);
	if (handle == NULL) {
		dprintf("security_buster: Initialization ERROR: %ld\n", GetLastError());
	}
	return handle;
}

EXPDECL BOOL PASSTHRU PROXY_WinHttpSetOption(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength) {
	if (!config.enable || !config.bypass_verification) {
		return WinHttpSetOption_orig(hInternet, dwOption, lpBuffer, dwBufferLength);
	}

	if (dwOption == 31) {
		dprintf("security_buster: disabling verification\n");
		int dwFlags = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
		int* ptr = (int*)lpBuffer;
		(*ptr) |= dwFlags;
		return WinHttpSetOption_orig(hInternet, dwOption, ptr, dwBufferLength);
	}

	return WinHttpSetOption_orig(hInternet, dwOption, lpBuffer, dwBufferLength);
}

#pragma region unhooked
EXPDECL void PASSTHRU PROXY_DllCanUnloadNow() {
	PA = p[0];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_DllGetClassObject() {
	PA = p[1];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_Private1() {
	PA = p[2];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_SvchostPushServiceGlobals() {
	PA = p[3];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL BOOL PASSTHRU PROXY_WinHttpAddRequestHeaders(HINTERNET a, LPCWSTR b, DWORD c, DWORD d) {
	return WinHttpAddRequestHeaders_orig(a, b, c, d);
}
EXPDECL void PASSTHRU PROXY_WinHttpAutoProxySvcMain() {
	PA = p[5];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL BOOL PASSTHRU PROXY_WinHttpCheckPlatform() {
	return WinHttpCheckPlatform_orig();
}
EXPDECL BOOL PASSTHRU PROXY_WinHttpCloseHandle(HINTERNET a) {
	return WinHttpCloseHandle_orig(a);
}
EXPDECL void PASSTHRU PROXY_WinHttpConnectionDeletePolicyEntries() {
	PA = p[9];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpConnectionDeleteProxyInfo() {
	PA = p[10];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpConnectionFreeNameList() {
	PA = p[11];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpConnectionFreeProxyInfo() {
	PA = p[12];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpConnectionFreeProxyList() {
	PA = p[13];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpConnectionGetNameList() {
	PA = p[14];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpConnectionGetProxyInfo() {
	PA = p[15];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpConnectionGetProxyList() {
	PA = p[16];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpConnectionSetPolicyEntries() {
	PA = p[17];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpConnectionSetProxyInfo() {
	PA = p[18];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpConnectionUpdateIfIndexTable() {
	PA = p[19];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL DWORD PASSTHRU PROXY_WinHttpCreateProxyResolver(HINTERNET a, HINTERNET *b) {
	return WinHttpCreateProxyResolver_orig(a, b);
}
EXPDECL void PASSTHRU PROXY_WinHttpCreateUrl() {
	PA = p[22];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpDetectAutoProxyConfigUrl() {
	PA = p[23];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpFreeProxyResult() {
	PA = p[24];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpFreeProxyResultEx(WINHTTP_PROXY_RESULT_EX* a) {
	WinHttpFreeProxyResultEx_orig(a);
}
EXPDECL void PASSTHRU PROXY_WinHttpFreeProxySettings() {
	PA = p[26];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpGetDefaultProxyConfiguration() {
	PA = p[27];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL BOOL PASSTHRU PROXY_WinHttpGetIEProxyConfigForCurrentUser(PWINHTTP_CURRENT_USER_IE_PROXY_CONFIG a) {
	return WinHttpGetIEProxyConfigForCurrentUser_orig(a);
}
EXPDECL void PASSTHRU PROXY_WinHttpGetProxyForUrl() {
	PA = p[29];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpGetProxyForUrlEx() {
	PA = p[30];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL BOOL PASSTHRU PROXY_WinHttpGetProxyForUrlEx2(HINTERNET hResolver,
	PCWSTR pcwszUrl,
	WINHTTP_AUTOPROXY_OPTIONS* pAutoProxyOptions,
	DWORD cbInterfaceSelectionContext,
	BYTE* pInterfaceSelectionContext,
	DWORD_PTR pContext) {
	return WinHttpGetProxyForUrlEx2_orig(hResolver, pcwszUrl, pAutoProxyOptions, cbInterfaceSelectionContext, pInterfaceSelectionContext, pContext);
}
EXPDECL void PASSTHRU PROXY_WinHttpGetProxyForUrlHvsi() {
	PA = p[32];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpGetProxyResult() {
	PA = p[33];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL DWORD PASSTHRU PROXY_WinHttpGetProxyResultEx(HINTERNET hResolver, WINHTTP_PROXY_RESULT_EX* pProxyResultEx) {
	return WinHttpGetProxyResultEx_orig(hResolver, pProxyResultEx);
}
EXPDECL void PASSTHRU PROXY_WinHttpGetProxySettingsVersion() {
	PA = p[35];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpGetTunnelSocket() {
	PA = p[36];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL HINTERNET PASSTHRU PROXY_WinHttpOpenRequest(
	 HINTERNET hConnect,
	 LPCWSTR   a,
	 LPCWSTR   b,
	 LPCWSTR   c,
	 LPCWSTR   d,
	 LPCWSTR* e,
	 DWORD     f) {
	HINTERNET handle = WinHttpOpenRequest_orig(hConnect, a, b, c, d, e, f);
	dprintf("security_buster: WinHttpOpenRequest: ret=%ld, err=%ld\n", handle, GetLastError());
	return handle;
}
EXPDECL void PASSTHRU PROXY_WinHttpPacJsWorkerMain() {
	PA = p[39];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpProbeConnectivity() {
	PA = p[40];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpQueryAuthSchemes() {
	PA = p[41];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL BOOL PASSTHRU PROXY_WinHttpQueryDataAvailable(HINTERNET a, LPDWORD b) {
	return WinHttpQueryDataAvailable_orig(a, b);
}
EXPDECL BOOL PASSTHRU PROXY_WinHttpQueryHeaders(HINTERNET a, DWORD b, LPCWSTR c, LPVOID d, LPDWORD e, LPDWORD f) {
	return WinHttpQueryHeaders_orig(a, b, c, d, e, f);
}
EXPDECL void PASSTHRU PROXY_WinHttpQueryOption() {
	PA = p[44];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL BOOL PASSTHRU PROXY_WinHttpReadData(HINTERNET a, LPVOID b, DWORD c, LPDWORD d) {
	return WinHttpReadData_orig(a, b, c, d);
}
EXPDECL void PASSTHRU PROXY_WinHttpReadProxySettings() {
	PA = p[46];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpReadProxySettingsHvsi() {
	PA = p[47];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL BOOL PASSTHRU PROXY_WinHttpReceiveResponse(HINTERNET a, LPVOID b) {
	return WinHttpReceiveResponse_orig(a, b);
}
EXPDECL void PASSTHRU PROXY_WinHttpResetAutoProxy() {
	PA = p[49];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpSaveProxyCredentials() {
	PA = p[50];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL BOOL PASSTHRU PROXY_WinHttpSendRequest(HINTERNET a, LPCWSTR b, DWORD c, LPVOID d, DWORD e, DWORD f, DWORD_PTR g) {
	return WinHttpSendRequest_orig(a, b, c, d, e, f, g);
}
EXPDECL void PASSTHRU PROXY_WinHttpSetCredentials() {
	PA = p[52];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpSetDefaultProxyConfiguration() {
	PA = p[53];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL WINHTTP_STATUS_CALLBACK PASSTHRU PROXY_WinHttpSetStatusCallback(HINTERNET a, WINHTTP_STATUS_CALLBACK b, DWORD c, DWORD_PTR d) {
	return WinHttpSetStatusCallback_orig(a, b, c, d);
}
EXPDECL BOOL PASSTHRU PROXY_WinHttpSetTimeouts(HINTERNET a, int b, int c, int d, int e) {
	return WinHttpSetTimeouts_orig(a, b, c, d, e);
}
EXPDECL void PASSTHRU PROXY_WinHttpTimeFromSystemTime() {
	PA = p[57];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpTimeToSystemTime() {
	PA = p[58];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpWebSocketClose() {
	PA = p[59];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpWebSocketCompleteUpgrade() {
	PA = p[60];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpWebSocketQueryCloseStatus() {
	PA = p[61];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpWebSocketReceive() {
	PA = p[62];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpWebSocketSend() {
	PA = p[63];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL void PASSTHRU PROXY_WinHttpWebSocketShutdown() {
	PA = p[64];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
EXPDECL BOOL PASSTHRU PROXY_WinHttpWriteData(HINTERNET a, LPCVOID b, DWORD c, LPDWORD d) {
	return WinHttpWriteData_orig(a, b, c, d);
}
EXPDECL void PASSTHRU PROXY_WinHttpWriteProxySettings() {
	PA = p[66];
	dprintf("security_buster: unimplemented: %s\n", __func__);
	ASMJmpToPA();
}
#pragma region unhooked