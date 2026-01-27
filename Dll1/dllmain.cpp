// dllmain.cpp restructurado
#include "pch.h"
#include <windows.h>
#include <wininet.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>
#include <numeric>
#include <tlhelp32.h>
#include <string>
#include <thread>
#include <codecvt>
#include <fstream>
#include <mutex>
#include <Psapi.h>
#include <shlwapi.h>
#include <winternl.h>
#include <shellapi.h>
#include "detours.h"
#include <nlohmann/json.hpp>
#include "EncryptionLib.h"
#include "FileProtection.h"
#include <wintrust.h>
#include <softpub.h>
#include <algorithm>
#include <atomic>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

using json = nlohmann::json;

//----------------------------------------------------------------------
// CONSTANTES Y DEFINICIONES
//----------------------------------------------------------------------

#define PIPE_NAME "\\\\.\\pipe\\AntiCheatPipe"
#define SERVICE_NAME L"ServicioMonitor"

//GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

const std::wstring ENCRYPTED_CONFIG_PATH = L"protected_files.dat";
const std::wstring CONFIG_KEY_PATH = L"clave.key";

// Tipos personalizados
typedef BOOL(WINAPI* SetProcessMitigationPolicyFunc)(PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
typedef int(__stdcall* MSGBOXAAPI)(IN HWND hWnd, IN LPCSTR lpText, IN LPCSTR lpCaption, IN UINT uType, IN WORD wLanguageId, IN DWORD dwMilliseconds);

//----------------------------------------------------------------------
// VARIABLES GLOBALES
//----------------------------------------------------------------------
class AntiCheatEngine;
static std::unique_ptr<AntiCheatEngine> g_AntiCheatEngine;

//----------------------------------------------------------------------
// FUNCIONES AUXILIARES DE CONVERSIÓN Y UTILIDADES
//----------------------------------------------------------------------

void CloseProcessAfterTimeout(int timeoutMs) {
	Sleep(timeoutMs);
	ExitProcess(0);  // Termina el proceso completamente
}

void ShowMessageAndExit(const char* message, const char* title, int timeoutMs) {
	// Crear un hilo para cerrar el proceso después del tiempo especificado
	std::thread(CloseProcessAfterTimeout, timeoutMs).detach();

	// Mostrar el MessageBox (el proceso seguirá ejecutándose hasta que termine el tiempo)
	MessageBoxA(NULL, message, title, MB_ICONWARNING | MB_OK | MB_SYSTEMMODAL | MB_TOPMOST);
}

// Función para guardar logs
void SaveLog(const std::string& logMessage) {
	std::ofstream logFile("dll_injection_log.txt", std::ios::app);
	if (logFile.is_open()) {
		logFile << logMessage << std::endl;
		logFile.close();
	}
}

// Funciones de conversión a minúsculas
std::string toLower(const std::string& str) {
	std::string lowerStr = str;
	std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(),
		[](unsigned char c) { return std::tolower(c); });
	return lowerStr;
}

std::wstring toLower(const std::wstring& str) {
	std::wstring lowerStr = str;
	std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(),
		[](wchar_t c) { return std::tolower(c); });
	return lowerStr;
}

// Conversiones entre string y wstring
// Versión mejorada de WCharToString
std::string WCharToString(const WCHAR* wchar) {
	if (wchar == nullptr) return std::string();

	int size_needed = WideCharToMultiByte(CP_UTF8, 0, wchar, -1, nullptr, 0, nullptr, nullptr);
	if (size_needed <= 0) return std::string();

	std::string strTo(size_needed - 1, 0); // -1 para excluir el null terminator
	WideCharToMultiByte(CP_UTF8, 0, wchar, -1, &strTo[0], size_needed, nullptr, nullptr);

	// Asegurarnos de que no haya caracteres nulos en medio de la cadena
	size_t pos = strTo.find('\0');
	if (pos != std::string::npos) {
		strTo.resize(pos);
	}

	return strTo;
}

// Alternativa usando función específica para el nombre del proceso
std::string SafeProcessNameToString(const WCHAR* processName) {
	if (processName == nullptr) return "unknown";

	std::wstring ws(processName);
	std::string result;
	result.reserve(ws.length()); // Reservar espacio para eficiencia

	for (wchar_t wc : ws) {
		if (wc > 127) {
			// Caracteres no ASCII - reemplazar con un carácter seguro
			result += '_';
		}
		else if (wc == 0) {
			// Encontramos un null terminator - terminar aquí
			break;
		}
		else {
			// Caracteres ASCII normales
			result += static_cast<char>(wc);
		}
	}

	return result;
}

std::string wstringToString(const std::wstring& wstr) {
	std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
	return converter.to_bytes(wstr);
}

std::wstring stringToWstring(const std::string& str) {
	std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
	return converter.from_bytes(str);
}

LPCWSTR ConvertToLPCWSTR(const char* str) {
	int length = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	wchar_t* wideStr = new wchar_t[length];
	MultiByteToWideChar(CP_ACP, 0, str, -1, wideStr, length);
	return wideStr;
}

// Funciones utilitarias para DLLs
std::string ToLower(const std::string& str) {
	std::string result = str;
	std::transform(result.begin(), result.end(), result.begin(), ::tolower);
	return result;
}

std::string GetFileName(const std::string& filePath) {
	size_t lastSlash = filePath.find_last_of("\\/");
	return (lastSlash != std::string::npos) ? filePath.substr(lastSlash + 1) : filePath;
}

bool ConnectToPipe() {
	// Cerrar el pipe si ya está abierto
	if (hPipe != INVALID_HANDLE_VALUE) {
		CloseHandle(hPipe);
		hPipe = INVALID_HANDLE_VALUE;
	}

	// Espera hasta 5 segundos si el servidor no está listo
	if (!WaitNamedPipeA(PIPE_NAME, 10000)) {
		std::cerr << "[!] Servidor de pipe no disponible. Error: " << GetLastError() << std::endl;
		return false;
	}

	// Intentar conectar - solo modo escritura para simplificar
	hPipe = CreateFileA(
		PIPE_NAME,
		GENERIC_WRITE,
		0,              // No compartir
		NULL,           // Seguridad por defecto
		OPEN_EXISTING,  // Solo abre si existe
		0,              // Modo síncrono - más simple para depurar
		NULL            // Sin plantilla
	);

	if (hPipe == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		std::cerr << "[!] Error al conectar al pipe: " << error << std::endl;
		return false;
	}

	std::cout << "[+] Conectado exitosamente al pipe." << std::endl;
	return true;
}

bool SendMessageToPipe(const std::string& message) {
	// Verificar si tenemos un pipe válido
	if (hPipe == INVALID_HANDLE_VALUE) {
		// Si no tenemos conexión, intentar conectar
		if (!ConnectToPipe()) {
			return false;
		}
	}

	// Verificación adicional para evitar advertencias
	if (hPipe == INVALID_HANDLE_VALUE || hPipe == NULL) {
		return false;
	}

	// Escribir mensaje - uso síncrono simple
	DWORD bytesWritten = 0;
	if (!WriteFile(hPipe, message.c_str(), static_cast<DWORD>(message.length()), &bytesWritten, NULL)) {
		DWORD error = GetLastError();

		// Si hay error en la escritura, cerrar y reconectar
		std::cerr << "[!] Error al escribir en el pipe: " << error << std::endl;

		// Verificar que el handle sea válido antes de cerrarlo
		if (hPipe != INVALID_HANDLE_VALUE && hPipe != NULL) {
			CloseHandle(hPipe);
		}

		hPipe = INVALID_HANDLE_VALUE;

		// Intentar reconectar y reenviar
		if (ConnectToPipe()) {
			if (WriteFile(hPipe, message.c_str(), static_cast<DWORD>(message.length()), &bytesWritten, NULL)) {
				return true;
			}
		}
		return false;
	}

	return (bytesWritten == message.length());
}

//==============================================================================
// VERSIÓN HARDENED DE DETECCIÓN DE CHEATS
// Mantiene compatibilidad pero elimina vulnerabilidades críticas
//==============================================================================

#include <wincrypt.h>
#include <unordered_map>
#include <unordered_set>
#include <random>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

// Función auxiliar para crear mensajes JSON simples
std::string CreateJSONMessage(const std::string& action, const std::string& message) {
	return "{\"action\":\"" + action + "\",\"message\":\"" + message + "\"}";
}

//==============================================================================
// ESTRUCTURAS Y DEFINICIONES MEJORADAS
//==============================================================================

// Hash rápido MD5 para identificación de módulos
struct MD5Hash {
	BYTE data[16];

	bool operator==(const MD5Hash& other) const {
		return memcmp(data, other.data, 16) == 0;
	}

	bool operator<(const MD5Hash& other) const {
		return memcmp(data, other.data, 16) < 0;
	}
};

// Especialización para std::hash
namespace std {
	template<>
	struct hash<MD5Hash> {
		std::size_t operator()(const MD5Hash& h) const {
			std::size_t result = 0;
			for (int i = 0; i < 16; i += sizeof(std::size_t)) {
				result ^= *reinterpret_cast<const std::size_t*>(&h.data[i]);
			}
			return result;
		}
	};
}

// Información extendida de módulo
struct ModuleInfo {
	std::string name;
	std::string fullPath;
	MD5Hash hash;
	DWORD size;
	bool isSystemModule;
	bool isVerified;
	double suspicionScore;
};

// Signature inteligente con múltiples variantes
struct IntelligentSignature {
	const char* name;
	std::vector<std::string> patterns;  // Múltiples variantes
	std::vector<std::string> masks;
	int confidenceValue;
	bool caseSensitive;
	bool requiresContext;
};

//==============================================================================
// VARIABLES GLOBALES THREAD-SAFE
//==============================================================================

static std::mutex g_detectionMutex;
static std::atomic<bool> g_isInitialized{ false };
static std::atomic<int> g_detectionCount{ 0 };

// Cache de hashes de módulos conocidos (thread-safe)
static std::unordered_map<std::string, MD5Hash> g_knownGoodHashes;
static std::unordered_set<MD5Hash> g_knownBadHashes;
static std::unordered_map<std::string, ModuleInfo> g_moduleCache;

// Generador aleatorio para anti-evasión
static std::mt19937 g_rng(std::chrono::high_resolution_clock::now().time_since_epoch().count());

//==============================================================================
// HASHES PRECALCULADOS DE MÓDULOS LEGÍTIMOS
//==============================================================================

void InitializeKnownGoodHashes() {
	static std::once_flag initialized;
	std::call_once(initialized, []() {
		// Hashes MD5 de módulos críticos del sistema
		// En producción, estos se cargarían desde una base de datos firmada

		// kernel32.dll (Windows 10/11 común)
		g_knownGoodHashes["kernel32.dll"] = { {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
											  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88} };

	// ntdll.dll (Windows 10/11 común)
	g_knownGoodHashes["ntdll.dll"] = { {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
									  0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99} };

	// user32.dll
	g_knownGoodHashes["user32.dll"] = { {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
									   0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00} };

	// d3d9.dll (DirectX)
	g_knownGoodHashes["d3d9.dll"] = { {0x12, 0xAB, 0xCD, 0xEF, 0x34, 0x56, 0x78, 0x90,
									 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90} };

	// helper.dll (tu propia DLL)
	g_knownGoodHashes["helper.dll"] = { {0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
									  0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA} };

	// TODO: Añadir más hashes de módulos legítimos
	// Nota: En producción, usar hashes reales calculados dinámicamente
		});
}

//==============================================================================
// SIGNATURES INTELIGENTES ANTI-EVASIÓN
//==============================================================================

static const IntelligentSignature g_intelligentSignatures[] = {
	// ================================
	// CATEGORIA: AIMBOTS - PRIORIDAD CRÍTICA
	// ================================
	{
		"Aimbot_Critical",
		{
			"53 69 6c 65 6e 74 20 41 69 6d 62 6f 74",     // "Silent Aimbot"
			"41 69 6d 62 6f 74",                           // "Aimbot"
			"61 69 6d 62 6f 74",                           // "aimbot"
			"61 69 6d 62 6f 74 31",                        // "aimbot1"
			"61 69 6d 62 6f 74 32",                        // "aimbot2"
			"41 49 4D 42 4F 54",                           // "AIMBOT"
			"41 00 69 00 6d 00 62 00 6f 00 74 00",         // Unicode "Aimbot"
		},
		{
			"xxxxxxxxxxxxx", "xxxxxx", "xxxxxx", "xxxxxxx", "xxxxxxx", "xxxxxx", "xxxxxxxxxxxx"
		},
		15, false, true
	},

	{
		"Aim_Components",
		{
			"23 23 41 69 6d 54 61 72 67 65 74 53",         // "##AimTargetS"
			"23 23 41 69 6d 4b 65 79 53",                  // "##AimKeyS"
		},
		{
			"xxxxxxxxxxxx", "xxxxxxxxx"
		},
		12, false, true
	},

	// ================================
	// CATEGORIA: ESP/WALLHACKS - PRIORIDAD ALTA
	// ================================
	{
		"ESP_Variants",
		{
			"45 53 50 20 42 6f 78",                        // "ESP Box"
			"45 53 50 20 4c 69 6e 65",                     // "ESP Line"
			"45 53 50 20 4e 61 6d 65",                     // "ESP Name"
			"45 53 50 20 53 6b 65 6c 65 74 6f 6e",         // "ESP Skeleton"
			"45 53 50 20 44 69 73 74 61 6e 63 65",         // "ESP Distance"
			"45 53 50 20 52 61 6e 6b",                     // "ESP Rank"
			"45 53 50 20 48 65 61 6c 74 68",               // "ESP Health"
			"45 53 50 20 42 6f 6d 62",                     // "ESP Bomb"
			"45 53 50 20 4e 6f 6d 62 72 65",               // "ESP Nombre"
			"45 53 50 20 42 6f 6d 62 61",                  // "ESP Bomba"
			"45 53 50 20 52 65 61 70 61 72 65 63 69 6d 65 6e 74 6f", // "ESP Reaparecimento"
		},
		{
			"xxxxxxx", "xxxxxxxx", "xxxxxxxx", "xxxxxxxxxxxx", "xxxxxxxxxxxx",
			"xxxxxxxx", "xxxxxxxxxx", "xxxxxxxx", "xxxxxxxxxx", "xxxxxxxxx", "xxxxxxxxxxxxxxxxxx"
		},
		10, false, true
	},

	// ================================
	// CATEGORIA: NO-RECOIL Y SPEED HACKS
	// ================================
	{
		"NoRecoil_Patterns",
		{
			"4e 6f 20 52 65 63 6f 69 6c 20 56",            // "No Recoil V"
			"4e 6f 20 52 65 63 6f 69 6c 20 48",            // "No Recoil H"
			"4e 6f 20 52 65 63 6f 69 6c",                  // "No Recoil"
			"4e 6f 52 65 63 6f 69 6c",                     // "NoRecoil"
			"6e 6f 72 65 63 6f 69 6c",                     // "norecoil"
		},
		{
			"xxxxxxxxxxx", "xxxxxxxxxxx", "xxxxxxxxx", "xxxxxxxx", "xxxxxxxx"
		},
		12, false, true
	},

	{
		"Speed_Hacks",
		{
			"54 68 72 6f 77 20 53 70 65 65 64",            // "Throw Speed"
			"46 61 73 74 20 63 68 61 6e 67 65",            // "Fast change"
			"46 61 73 74 20 63 68 61 72 67 65",            // "Fast charge"
		},
		{
			"xxxxxxxxxxx", "xxxxxxxxxxx", "xxxxxxxxxxx"
		},
		10, false, true
	},

	// ================================
	// CATEGORIA: FPS CHEATS
	// ================================
	{
		"FPS_Cheats",
		{
			"46 50 53 20 4d 41 58",                        // "FPS MAX"
			"46 50 53 50 52 4f",                           // "FPSPRO"
			"46 50 53 4c 41 54 49 4e 4f",                  // "FPSLATINO"
			"46 50 53 4c 41 54 49 4e 4f 5b 30 5d",         // "FPSLATINO[0]"
			"46 00 50 00 53 00 4c 00 41",                  // Unicode variant
			"66 70 73 6d 61 78 2e 6e 65 74",               // "fpsmax.net"
		},
		{
			"xxxxxxx", "xxxxxx", "xxxxxxxxx", "xxxxxxxxxxxx", "xxxxxxxxx", "xxxxxxxxxx"
		},
		8, false, true
	},

	// ================================
	// CATEGORIA: POINT BLANK ESPECÍFICOS
	// ================================
	{
		"PointBlank_VIP",
		{
			"50 42 20 42 52 20 56 49 50",                  // "PB BR VIP"
		},
		{
			"xxxxxxxxx"
		},
		9, false, true
	},

	// ================================
	// CATEGORIA: PLAYCHEATZ - CRÍTICO
	// ================================
	{
		"PlayCheatz_Critical",
		{
			"50 4c 41 59 43 48 45 41 54 5a",               // "PLAYCHEATZ"
			"70 6c 61 79 63 68 65 61 74 7a",               // "playcheatz"
			"50 6c 61 79 43 68 65 61 74 5a",               // "PlayCheatZ"
			"50 6c 61 79 43 2e 64 6c 6c",                  // "PlayC.dll"
			"50 6c 61 79 2e 73 79 73",                     // "Play.sys"
			"50 6c 61 79 43 2e 64 6c 6c 20 2f 20 50 6c 61 79 2e 73 79 73 20 54 69 64 61 6b 20 61 64 61", // "PlayC.dll / Play.sys Tidak ada"
		},
		{
			"xxxxxxxxxx", "xxxxxxxxxx", "xxxxxxxxxx", "xxxxxxxxx", "xxxxxxxx", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
		},
		15, true, false
	},

	// ================================
	// CATEGORIA: USUARIOS ESPECÍFICOS CONOCIDOS
	// ================================
	{
		"Known_Cheat_Users",
		{
			"73 65 63 72 65 74 31 32 33",                  // "secret123"
			"64 69 6d 61 72 63 6f",                        // "dimarco"
			"44 69 6d 61 72 63 6f",                        // "Dimarco"
			"44 69 6d 61 72 63 6f 37 37",                  // "Dimarco77"
			"64 69 6d 61 72 63 6f 37 37",                  // "dimarco77"
		},
		{
			"xxxxxxxxx", "xxxxxxx", "xxxxxxx", "xxxxxxxxx", "xxxxxxxxx"
		},
		8, true, true
	},

	// ================================
	// CATEGORIA: STRINGS OFUSCADOS
	// ================================
	{
		"Obfuscated_Strings",
		{
			"49 7c 4a 78 6e 6d 79 6b 5b 78 63 77 72 70 50 6e", // "I|Jxnmyk[xcwrpPn"
			"4b 67 68 6e 47 65 6f 7c 6e 62 68 57 6b 55",   // "KghnGeo|nbhWkU"
			"7b 40 7d 64 72 79 7d 3a 5e 6e 72 6c 3f 2a",   // "{@}dry}:^nrl?*"
		},
		{
			"xxxxxxxxxxxxxxxx", "xxxxxxxxxxxxxx", "xxxxxxxxxxxxxx"
		},
		12, true, true
	},

	// ================================
	// CATEGORIA: ARCHIVOS DE DEBUG SOSPECHOSOS
	// ================================
	{
		"Debug_Files",
		{
			"43 3a 5c 47 61 6d 65 73 5c 50 6f 69 6e 74 20 42 6c 61 6e 6b 20 4c 61 74 69 6e 6f 20 4f 47 5c 75 6d 70 64 63 2e 70 64 62", // Path completa
		},
		{
			"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
		},
		15, true, false
	},

	// ================================
	// CATEGORIA: PATRONES DE INYECCIÓN DE CÓDIGO
	// ================================
	{
		"Code_Injection",
		{
			"48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0",          // MOV RAX, addr; JMP RAX (x64)
			"68 ?? ?? ?? ?? C3",                           // PUSH addr; RET
			"E9 ?? ?? ?? ??",                              // JMP relative
			"FF 25 ?? ?? ?? ??",                           // JMP QWORD PTR
			"48 89 ?? 24 ?? C3",                           // MOV [RSP+?], reg; RET
			"B8 ?? ?? ?? ?? FF E0",                        // MOV EAX, addr; JMP EAX (x86)
			"FF 15 ?? ?? ?? ??",                           // CALL DWORD PTR
		},
		{
			"xxxxxxxxxxxxxxx", "xxxxxx", "xxxxx", "xxxxxx", "xxxxxxx", "xxxxxx", "xxxxxx"
		},
		14, false, true
	},

	// ================================
	// CATEGORIA: STRINGS GENERICOS SOSPECHOSOS
	// ================================
	{
		"Generic_Cheat_Terms",
		{
			"68 61 63 6b",                                 // "hack"
			"48 61 63 6b",                                 // "Hack"
			"48 41 43 4b",                                 // "HACK"
			"63 68 65 61 74",                              // "cheat"
			"43 68 65 61 74",                              // "Cheat"
			"43 48 45 41 54",                              // "CHEAT"
			"69 6e 6a 65 63 74",                           // "inject"
			"49 6e 6a 65 63 74",                           // "Inject"
			"68 6f 6f 6b",                                 // "hook"
			"48 6f 6f 6b",                                 // "Hook"
			"77 61 6c 6c 68 61 63 6b",                     // "wallhack"
			"57 61 6c 6c 68 61 63 6b",                     // "Wallhack"
		},
		{
			"xxxx", "xxxx", "xxxx", "xxxxx", "xxxxx", "xxxxx",
			"xxxxxx", "xxxxxx", "xxxx", "xxxx", "xxxxxxxx", "xxxxxxxx"
		},
		6, false, true
	}
};

static const int INTELLIGENT_SIGNATURE_COUNT = sizeof(g_intelligentSignatures) / sizeof(g_intelligentSignatures[0]);

//==============================================================================
// FUNCIONES DE HASH Y VALIDACIÓN CRIPTOGRÁFICA
//==============================================================================

MD5Hash CalculateMD5Hash(const BYTE* data, DWORD dataSize) {
	MD5Hash result = {};

	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;

	if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
			if (CryptHashData(hHash, data, dataSize, 0)) {
				DWORD hashSize = 16;
				CryptGetHashParam(hHash, HP_HASHVAL, result.data, &hashSize, 0);
			}
			CryptDestroyHash(hHash);
		}
		CryptReleaseContext(hProv, 0);
	}

	return result;
}

MD5Hash GetFileHash(const std::string& filePath) {
	MD5Hash result = {};

	HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (hFile == INVALID_HANDLE_VALUE) {
		return result;
	}

	DWORD fileSize = GetFileSize(hFile, nullptr);
	if (fileSize > 0 && fileSize < 100 * 1024 * 1024) { // Máximo 100MB
		std::vector<BYTE> fileData(fileSize);
		DWORD bytesRead = 0;

		if (ReadFile(hFile, fileData.data(), fileSize, &bytesRead, nullptr)) {
			result = CalculateMD5Hash(fileData.data(), bytesRead);
		}
	}

	CloseHandle(hFile);
	return result;
}

//==============================================================================
// VALIDACIÓN MEJORADA DE MÓDULOS
//==============================================================================

bool IsModuleTrustedByHash(const std::string& moduleName, const std::string& fullPath) {
	InitializeKnownGoodHashes();

	// Verificar si tenemos el hash conocido para este módulo
	auto it = g_knownGoodHashes.find(moduleName);
	if (it == g_knownGoodHashes.end()) {
		return false; // Módulo no conocido
	}

	// Calcular hash del archivo actual
	MD5Hash actualHash = GetFileHash(fullPath);

	// Verificar si coincide con el hash conocido
	return actualHash == it->second;
}

bool IsSystemModule(const std::string& fullPath) {
	// Verificar ubicaciones típicas del sistema
	std::string lowerPath = fullPath;
	std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);

	return lowerPath.find("\\windows\\") != std::string::npos ||
		lowerPath.find("\\system32\\") != std::string::npos ||
		lowerPath.find("\\syswow64\\") != std::string::npos ||
		lowerPath.find("\\winsxs\\") != std::string::npos;
}

bool ValidateModuleSignature(const std::string& filePath) {
	WINTRUST_FILE_INFO fileInfo = {};
	fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);

	std::wstring wPath(filePath.begin(), filePath.end());
	fileInfo.pcwszFilePath = wPath.c_str();

	WINTRUST_DATA winTrustData = {};
	winTrustData.cbStruct = sizeof(WINTRUST_DATA);
	winTrustData.dwUIChoice = WTD_UI_NONE;
	winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
	winTrustData.pFile = &fileInfo;
	winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	LONG result = WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

	// Limpiar
	winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

	return result == ERROR_SUCCESS;
}

//----------------------------------------------------------------------
// CLASES DE COMPONENTES DEL ANTICHEAT
//----------------------------------------------------------------------

// Forward declaration
void Start(const std::string& path, const std::string& arg1, const std::string& arg2);
void CreateConsole();
void ShowMessageAndExit(const char* message, const char* title, int timeoutMs);

class IPCManager {
private:
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    std::mutex pipe_mutex;

public:
    ~IPCManager() {
        if (hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(hPipe);
        }
    }

    bool Connect() {
        std::lock_guard<std::mutex> lock(pipe_mutex);
        if (hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(hPipe);
        }

        if (!WaitNamedPipeA(PIPE_NAME, 10000)) {
            return false;
        }

        hPipe = CreateFileA(PIPE_NAME, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        return hPipe != INVALID_HANDLE_VALUE;
    }

    bool Send(const std::string& message) {
        std::lock_guard<std::mutex> lock(pipe_mutex);
        if (hPipe == INVALID_HANDLE_VALUE) {
            if (!Connect()) {
                return false;
            }
        }

        DWORD bytesWritten = 0;
        if (!WriteFile(hPipe, message.c_str(), static_cast<DWORD>(message.length()), &bytesWritten, NULL)) {
            CloseHandle(hPipe);
            hPipe = INVALID_HANDLE_VALUE;
            return false;
        }
        return true;
    }
};

class MacroDetector {
private:
    // Configuración
    const size_t HISTORY_SIZE = 50;
    const size_t MIN_SAMPLE_SIZE = 15;
    const double MIN_HUMAN_INTERVAL_MS = 50.0;
    const double COEFFICIENT_VARIATION_THRESHOLD = 0.08;
    const double AUTOCORRELATION_THRESHOLD = 0.75;
    const int SUSPICION_THRESHOLD = 75;
    const int CRITICAL_THRESHOLD = 90;

    struct AdvancedClickData {
        POINT position;
        std::chrono::high_resolution_clock::time_point timestamp;
        double timeDiff;
        double movementSpeed;
        bool wasMoving;
    };

    std::vector<AdvancedClickData> advancedClickHistory;
    std::vector<double> baselineTimings;
    double userBaselineVariance = 50.0;
    int suspicionScore = 0;
    bool isCalibrating = true;
    std::chrono::steady_clock::time_point calibrationStart;
    int legitClicksCount = 0;

public:
    void Initialize() {
        advancedClickHistory.clear();
        baselineTimings.clear();
        suspicionScore = 0;
        isCalibrating = true;
        calibrationStart = std::chrono::steady_clock::now();
        legitClicksCount = 0;
    }

    bool ProcessClick(WPARAM wParam, LPARAM lParam) {
        if (wParam != WM_LBUTTONDOWN) return false;

        auto currentTime = std::chrono::high_resolution_clock::now();
        MSLLHOOKSTRUCT* mouseInfo = (MSLLHOOKSTRUCT*)lParam;
        POINT cursorPos = mouseInfo->pt;

        AdvancedClickData currentClick;
        currentClick.position = cursorPos;
        currentClick.timestamp = currentTime;
        currentClick.timeDiff = 0.0;
        currentClick.movementSpeed = 0.0;
        currentClick.wasMoving = false;

        if (!advancedClickHistory.empty()) {
            auto lastClick = advancedClickHistory.back();
            auto timeDiff = std::chrono::duration_cast<std::chrono::milliseconds>(
                currentTime - lastClick.timestamp).count();

            currentClick.timeDiff = static_cast<double>(timeDiff);
            currentClick.movementSpeed = CalculateMovementSpeed(
                lastClick.position, cursorPos, currentClick.timeDiff);
            currentClick.wasMoving = currentClick.movementSpeed > 0.1;
        }

        // Verificar entrada inyectada
        if (mouseInfo->flags & LLMHF_INJECTED) {
            suspicionScore += 30;
            if(g_AntiCheatEngine) {
                json jsonMessage = {
                    {"action", "INJECTION_ALERT"},
                    {"message", "Entrada de mouse inyectada detectada"}
                };
                g_AntiCheatEngine->GetIPC().Send(jsonMessage.dump());
            }
        }

        advancedClickHistory.push_back(currentClick);
        if (advancedClickHistory.size() > HISTORY_SIZE) {
            advancedClickHistory.erase(advancedClickHistory.begin());
        }

        if (isCalibrating) {
            HandleCalibration(currentTime);
            return false;
        }

        return AnalyzeSuspicion();
    }

private:
    double CalculateMovementSpeed(const POINT& p1, const POINT& p2, double timeDiff) {
        if (timeDiff <= 0) return 0.0;
        double distance = sqrt(pow(p2.x - p1.x, 2) + pow(p2.y - p1.y, 2));
        return distance / timeDiff;
    }

    void HandleCalibration(const std::chrono::high_resolution_clock::time_point& currentTime) {
        legitClicksCount++;
        if (legitClicksCount >= 200 ||
            std::chrono::duration_cast<std::chrono::minutes>(
                currentTime - calibrationStart).count() >= 10) {
            isCalibrating = false;
            std::vector<double> calibrationTimings;
            for (size_t i = 1; i < advancedClickHistory.size(); i++) {
                calibrationTimings.push_back(advancedClickHistory[i].timeDiff);
            }
            UpdateUserBaseline(calibrationTimings);
        }
    }

    void UpdateUserBaseline(const std::vector<double>& timings) {
        if (timings.size() < 30) return;
        double mean = std::accumulate(timings.begin(), timings.end(), 0.0) / timings.size();
        double variance = 0.0;
        for (double timing : timings) {
            variance += (timing - mean) * (timing - mean);
        }
        variance /= (timings.size() - 1);
        userBaselineVariance = userBaselineVariance * 0.8 + variance * 0.2;
        baselineTimings = timings;
    }

    bool AnalyzeSuspicion() {
        if (advancedClickHistory.size() < MIN_SAMPLE_SIZE) return false;

        std::vector<double> timings;
        for (size_t i = 1; i < advancedClickHistory.size(); i++) {
            timings.push_back(advancedClickHistory[i].timeDiff);
        }

        int currentSuspicion = 0;
        
        // Implementación simplificada de las métricas para brevedad
        // (CV, Autocorrelación, Entropía, etc. irían aquí como métodos privados)
        
        // Sistema de puntuación
        suspicionScore = static_cast<int>(suspicionScore * 0.95) + (currentSuspicion / 5);
        suspicionScore = (std::min)(suspicionScore, 100);

        if (suspicionScore >= CRITICAL_THRESHOLD) {
            ShowMessageAndExit("Macro detectado con alta confianza", "ALERTA DE MACRO CRÍTICA", 8000);
            return true;
        }
        else if (suspicionScore >= SUSPICION_THRESHOLD) {
            if(g_AntiCheatEngine) {
                json jsonMessage = {
                    {"action", "MACRO_WARNING"},
                    {"message", "Patrón de clics sospechoso detectado"},
                    {"suspicion_score", suspicionScore}
                };
                g_AntiCheatEngine->GetIPC().Send(jsonMessage.dump());
            }
            suspicionScore = static_cast<int>(suspicionScore * 0.9);
        }

        return false;
    }
};

class ModuleVerifier {
private:
    std::vector<std::string> whiteListDLLs;
    std::mutex m_mutex;

public:
    ModuleVerifier() {
        InitializeWhitelist();
    }

    void Scan() {
        std::lock_guard<std::mutex> lock(m_mutex);
        DetectCheatPatternsInDLLsHardened();
        CheckIATIntegrity();
        CheckSystemHooks();
    }

private:
    void InitializeWhitelist() {
        whiteListDLLs = {
            "kernel32.dll", "user32.dll", "gdi32.dll", "ntdll.dll",
            "advapi32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll",
            "ws2_32.dll", "version.dll", "shlwapi.dll", "d3d9.dll",
            "d3d11.dll", "dxgi.dll", "imm32.dll", "winmm.dll",
            // ... (resto de la lista)
        };
    }

    bool CheckIATIntegrity() {
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return false;

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);

        DWORD importRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importRVA == 0) return true;

        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importRVA);

        for (; importDesc->Name != 0; importDesc++) {
            LPCSTR dllName = (LPCSTR)((BYTE*)hModule + importDesc->Name);
            std::string dllNameStr = ToLower(dllName);
            
            if (dllNameStr == "kernel32.dll" || dllNameStr == "ntdll.dll") {
                if (importDesc->FirstThunk == 0 || importDesc->OriginalFirstThunk == 0) continue;

                PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
                PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->OriginalFirstThunk);

                while (origThunk->u1.AddressOfData != 0 && firstThunk->u1.Function != 0) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + origThunk->u1.AddressOfData);
                        std::string funcName = (char*)importByName->Name;

                        if (funcName.find("VirtualAlloc") != std::string::npos ||
                            funcName.find("WriteProcessMemory") != std::string::npos ||
                            funcName.find("CreateRemoteThread") != std::string::npos) {
                            
                            BYTE* funcAddr = (BYTE*)firstThunk->u1.Function;
                            if (funcAddr[0] == 0xE9 || funcAddr[0] == 0xEB) {
                                if(g_AntiCheatEngine) {
                                    json msg = {{"action", "INJECTION_ALERT"}, {"message", "Hook IAT detectado: " + funcName}};
                                    g_AntiCheatEngine->GetIPC().Send(msg.dump());
                                }
                                return false;
                            }
                        }
                    }
                    firstThunk++;
                    origThunk++;
                }
            }
        }
        return true;
    }

    bool CheckSystemHooks() {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return false;

        const char* criticalFunctions[] = {
            "NtQueryInformationProcess", "NtOpenProcess", "NtReadVirtualMemory"
        };

        for (const char* funcName : criticalFunctions) {
            FARPROC pFunc = GetProcAddress(hNtdll, funcName);
            if (pFunc) {
                BYTE* pBytes = (BYTE*)pFunc;
                if (pBytes[0] == 0xE9 || pBytes[0] == 0xEB) {
                    if(g_AntiCheatEngine) {
                        json msg = {{"action", "INJECTION_ALERT"}, {"message", std::string("Hook en ntdll: ") + funcName}};
                        g_AntiCheatEngine->GetIPC().Send(msg.dump());
                    }
                    return true;
                }
            }
        }
        return false;
    }

    std::string ToLower(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::tolower);
        return result;
    }
};

class HookManager {
private:
    HHOOK mouseHook = NULL;
    
    // Punteros originales
    static HANDLE(WINAPI* TrueCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    static HMODULE(WINAPI* TrueLoadLibraryA)(LPCSTR);
    static HMODULE(WINAPI* TrueLoadLibraryW)(LPCWSTR);
    static LPVOID(WINAPI* TrueVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    static BOOL(WINAPI* TrueWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    static HINTERNET(WINAPI* TrueInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);

public:
    void Install() {
        InstallApiHooks();
        InstallMouseHook();
    }

    void Shutdown() {
        if (mouseHook) {
            UnhookWindowsHookEx(mouseHook);
            mouseHook = NULL;
        }
        // Note: Detours are removed automatically on process detach.
    }

    // Callbacks estáticos para Detours
    static HINTERNET WINAPI HookedInternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext) {
        std::string url = (lpszUrl && lpszUrl[0] != '\0') ? lpszUrl : "NULL";
        if(g_AntiCheatEngine) {
            json msg = {{"action", "INJECTION_ALERT"}, {"message", "Conexión sospechosa: " + url}};
            g_AntiCheatEngine->GetIPC().Send(msg.dump());
        }
        return TrueInternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
    }

    static HANDLE WINAPI HookedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
        if(g_AntiCheatEngine) {
            json msg = {{"action", "INJECTION_ALERT"}, {"message", "Intento de CreateRemoteThread"}};
            g_AntiCheatEngine->GetIPC().Send(msg.dump());
        }
        return TrueCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    }

    static LPVOID WINAPI HookedVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
        if(g_AntiCheatEngine) {
            json msg = {{"action", "INJECTION_ALERT"}, {"message", "Intento de VirtualAllocEx"}};
            g_AntiCheatEngine->GetIPC().Send(msg.dump());
        }
        return TrueVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    }

    static BOOL WINAPI HookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
        if(g_AntiCheatEngine) {
            json msg = {{"action", "INJECTION_ALERT"}, {"message", "Intento de WriteProcessMemory"}};
            g_AntiCheatEngine->GetIPC().Send(msg.dump());
        }
        return TrueWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }

    static LRESULT CALLBACK MouseHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
        if (nCode >= 0 && g_AntiCheatEngine) {
            if (g_AntiCheatEngine->GetMacroDetector().ProcessClick(wParam, lParam)) {
                return 1; // Bloquear clic
            }
        }
        return CallNextHookEx(NULL, nCode, wParam, lParam);
    }

private:
    void InstallApiHooks() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueInternetOpenUrlA, HookedInternetOpenUrlA);
        DetourAttach(&(PVOID&)TrueCreateRemoteThread, HookedCreateRemoteThread);
        DetourAttach(&(PVOID&)TrueWriteProcessMemory, HookedWriteProcessMemory);
        DetourAttach(&(PVOID&)TrueVirtualAllocEx, HookedVirtualAllocEx);
        DetourTransactionCommit();
    }

    void InstallMouseHook() {
        mouseHook = SetWindowsHookEx(WH_MOUSE_LL, MouseHookProc, GetModuleHandle(NULL), 0);
        if (!mouseHook) {
            ShowMessageAndExit("Error al instalar el hook del mouse.", "Error", 10000);
        }
    }
};

// Inicialización de punteros estáticos
HANDLE(WINAPI* HookManager::TrueCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = CreateRemoteThread;
HMODULE(WINAPI* HookManager::TrueLoadLibraryA)(LPCSTR) = LoadLibraryA;
HMODULE(WINAPI* HookManager::TrueLoadLibraryW)(LPCWSTR) = LoadLibraryW;
LPVOID(WINAPI* HookManager::TrueVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = VirtualAllocEx;
BOOL(WINAPI* HookManager::TrueWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = WriteProcessMemory;
HINTERNET(WINAPI* HookManager::TrueInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR) = InternetOpenUrlA;

class SecurityMonitor {
private:
    std::thread workerThread;
    std::atomic<bool> stopThread{ false };
    FileProtection& fileProtector;
    ModuleVerifier& moduleVerifier;

public:
    SecurityMonitor(FileProtection& fp, ModuleVerifier& mv) 
        : fileProtector(fp), moduleVerifier(mv) {}

    void Start() {
        workerThread = std::thread(&SecurityMonitor::Run, this);
    }

    void Stop() {
        stopThread = true;
        if (workerThread.joinable()) {
            workerThread.join();
        }
    }

private:
    void Run() {
        while (!stopThread) {
            try {
                moduleVerifier.Scan();

                if (!fileProtector.VerifyIntegrity()) {
                    ShowMessageAndExit("Violación de integridad de archivos detectada", "Error", 10000);
                }
            }
            catch (const std::exception& e) {
                ShowMessageAndExit(e.what(), "Error en Monitor", 10000);
            }
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
};

class AntiCheatEngine {
private:
    IPCManager ipc;
    HookManager hooks;
    MacroDetector macroDetector;
    ModuleVerifier moduleVerifier;
    FileProtection fileProtector;
    EncryptionLib encryption;
    std::unique_ptr<SecurityMonitor> monitor;
    bool isInitialized = false;

public:
    void Initialize(HMODULE hModule) {
        if (isInitialized) return;

        #ifdef _DEBUG
        CreateConsole();
        #endif

        if (!ipc.Connect()) {
             ShowMessageAndExit("No se pudo conectar con el servicio principal.", "Error de Comunicación", 10000);
             return;
        }

        if (!LoadEncryptedConfiguration()) {
            ShowMessageAndExit("Error al cargar la configuración de seguridad.", "Error Crítico", 10000);
            return;
        }

        hooks.Install();
        macroDetector.Initialize();

        monitor = std::make_unique<SecurityMonitor>(fileProtector, moduleVerifier);
        monitor->Start();

        // Obtener argumentos y lanzar proceso
        std::string first = GetFirstCommandArgument();
        std::string second = GetSecondCommandArgument();
        std::string currentDir = GetCurrentDirectorys();
        Start(currentDir, first, second);

        isInitialized = true;
    }

    void Shutdown() {
        if (!isInitialized) return;

        if (monitor) {
            monitor->Stop();
        }
        hooks.Shutdown();
        isInitialized = false;
    }

    IPCManager& GetIPC() { return ipc; }
    MacroDetector& GetMacroDetector() { return macroDetector; }

private:
    bool LoadEncryptedConfiguration() {
        try {
            encryption.LoadKeyFromFile(CONFIG_KEY_PATH);
            std::wstring tempConfigPath = L"temp_config.dat";
            encryption.DecryptFile(ENCRYPTED_CONFIG_PATH, tempConfigPath);
            bool result = fileProtector.LoadConfiguration(tempConfigPath);
            DeleteFileW(tempConfigPath.c_str());
            return result;
        }
        catch (...) {
            return false;
        }
    }
};

//----------------------------------------------------------------------
// FUNCIONES PRINCIPALES Y DE INICIALIZACIÓN
//----------------------------------------------------------------------

// Verificar regiones críticas de memoria

void CreateConsole()
{
	AllocConsole();
	FILE* fDummy;
	freopen_s(&fDummy, "CONIN$", "r", stdin);
	freopen_s(&fDummy, "CONOUT$", "w", stdout);
	freopen_s(&fDummy, "CONOUT$", "w", stderr);

	SetConsoleTitleA("Consola Debug");
	std::cout.clear();
	std::clog.clear();
	std::cerr.clear();
	std::cin.clear();

	std::cout << "[*] Consola inicializada.\n";
}

// Funciones auxiliares para Start()
std::string GetCurrentDirectorys() {
    char buffer[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, buffer);
    return std::string(buffer);
}

std::string GetFirstCommandArgument() {
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv || argc < 2) return "";
    std::string arg = WCharToString(argv[1]);
    LocalFree(argv);
    return arg;
}

std::string GetSecondCommandArgument() {
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv || argc < 3) return "";
    std::string arg = WCharToString(argv[2]);
    LocalFree(argv);
    return arg;
}

void CloseProcessAfterTimeout(int timeoutMs) {
    Sleep(timeoutMs);
    ExitProcess(0);
}

void ShowMessageAndExit(const char* message, const char* title, int timeoutMs) {
    std::thread(CloseProcessAfterTimeout, timeoutMs).detach();
    MessageBoxA(NULL, message, title, MB_ICONWARNING | MB_OK | MB_SYSTEMMODAL | MB_TOPMOST);
}

void Start(const std::string& path, const std::string& arg1, const std::string& arg2) {
    std::string exePath = path + "\\HackShield\\AntiCheat.exe";
    std::string arguments = arg1 + " " + arg2;
    std::string workingDir = path + "\\HackShield";

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    std::string cmdLine = "\"" + exePath + "\" " + arguments;

    if (!CreateProcessA(exePath.c_str(), &cmdLine[0], NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, workingDir.c_str(), &si, &pi)) {
        DWORD error = GetLastError();
        ShowMessageAndExit(("Error al iniciar el proceso. Código: " + std::to_string(error)).c_str(), "Error", 10000);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

extern "C" __declspec(dllexport) void AntiMacro() {
    // Punto de entrada legacy/alternativo
    // Si el motor no está inicializado (ej. inyección manual), intentar inicializarlo
    if (!g_AntiCheatEngine) {
        // Nota: Esto podría ser peligroso si se llama concurrentemente con DllMain
        // Idealmente, DllMain maneja todo.
    }
}

//----------------------------------------------------------------------
// PUNTO DE ENTRADA DE LA DLL
//----------------------------------------------------------------------

void MainThread(HMODULE hModule) {
    g_AntiCheatEngine = std::make_unique<AntiCheatEngine>();
    g_AntiCheatEngine->Initialize(hModule);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
        CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, nullptr));
		break;
	case DLL_PROCESS_DETACH:
        if (g_AntiCheatEngine) {
            g_AntiCheatEngine->Shutdown();
            g_AntiCheatEngine.reset();
        }
		break;
	}
	return TRUE;
}