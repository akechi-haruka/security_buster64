#include "config.h"
#include <windows.h>
#include "dprintf.h"

void load_config(struct buster_config* config) {
	config->enable = GetPrivateProfileIntA("Configuration", "Enable", 1, CONFIG_FILE);
	config->bypass_verification = GetPrivateProfileIntA("Configuration", "BypassSSLVerification", 1, CONFIG_FILE);
	config->strip_https = GetPrivateProfileIntA("Configuration", "StripHTTPS", 0, CONFIG_FILE);
	GetPrivateProfileStringW(L"Configuration", L"RedirectedHost", NULL, config->redirect_host, MAX_STR, CONFIG_FILE_W);
	config->redirect_port = GetPrivateProfileIntA("Configuration", "RedirectedPort", 0, CONFIG_FILE);
	config->heap_alloc = GetPrivateProfileIntA("Configuration", "HostIsHeapAllocated", 1, CONFIG_FILE);
}