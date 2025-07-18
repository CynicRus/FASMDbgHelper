#include <windows.h>
#include <Psapi.h>
#include <ShObjIdl.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <optional>
#include "fasm_fas.h"
#include "bridgemain.h"
#include "_plugins.h"

#include "_scriptapi_argument.h"
#include "_scriptapi_assembler.h"
#include "_scriptapi_bookmark.h"
#include "_scriptapi_comment.h"
#include "_scriptapi_debug.h"
#include "_scriptapi_flag.h"
#include "_scriptapi_function.h"
#include "_scriptapi_gui.h"
#include "_scriptapi_label.h"
#include "_scriptapi_memory.h"
#include "_scriptapi_misc.h"
#include "_scriptapi_module.h"
#include "_scriptapi_pattern.h"
#include "_scriptapi_register.h"
#include "_scriptapi_stack.h"
#include "_scriptapi_symbol.h"

#include "DeviceNameResolver/DeviceNameResolver.h"
#include "jansson/jansson.h"
#include "lz4/lz4file.h"
#include "TitanEngine/TitanEngine.h"
#include "XEDParse/XEDParse.h"

#ifdef _WIN64
#pragma comment(lib, "x64dbg.lib")
#pragma comment(lib, "x64bridge.lib")
#pragma comment(lib, "DeviceNameResolver/DeviceNameResolver_x64.lib")
#pragma comment(lib, "jansson/jansson_x64.lib")
#pragma comment(lib, "lz4/lz4_x64.lib")
#pragma comment(lib, "TitanEngine/TitanEngine_x64.lib")
#pragma comment(lib, "XEDParse/XEDParse_x64.lib")
#else
#pragma comment(lib, "x32dbg.lib")
#pragma comment(lib, "x32bridge.lib")
#pragma comment(lib, "DeviceNameResolver/DeviceNameResolver_x86.lib")
#pragma comment(lib, "jansson/jansson_x86.lib")
#pragma comment(lib, "lz4/lz4_x86.lib")
#pragma comment(lib, "TitanEngine/TitanEngine_x86.lib")
#pragma comment(lib, "XEDParse/XEDParse_x86.lib")
#endif //_WIN64

// Plugin SDK definitions
#define PLUGIN_NAME "FASMDbgHelper"
#define PLUGIN_VERSION 1

//#define DEBUG

#ifdef DEBUG
#define DPRINTF(x, ...) _plugin_logprintf("[" PLUGIN_NAME "] " x, __VA_ARGS__)
#define DPUTS(x) _plugin_logprintf("[" PLUGIN_NAME "] %s\n", x)
#else
#define DPRINTF(x, ...)
#define DPUTS(x)
#endif

// Plugin SDK definitions
#define PLUG_EXPORT extern "C" __declspec(dllexport)
static int pluginHandle;
static HWND hwndDlg;
static int menuHandleLabelsBinary;
static int menuHandleAbout;

// Menu entry IDs
enum MenuAction {
    MA_LABELS_BINARY = 1001,
    MA_ABOUT = 1004
};

// Structure to hold symbol information
struct Symbol {
    std::string name;
    duint offset;
};

// Forward declarations
static bool LoadFASHeader(HANDLE in, void*& mem, DWORD& fileSize, fasHead*& fhead);
static bool ParseSymbols(void* mem, const fasHead* fhead, DWORD fileSize, duint modBase, std::vector<Symbol>& loadedSymbols);
static bool GetSymbolName(void* mem, const fasHead* fhead, DWORD fileSize, const fasSym& sym, std::string& name);

// Get current EIP/RIP
duint GetCurrentEIP() {
    DPUTS("Entering GetCurrentEIP");
    REGDUMP registers;
    DPUTS("Calling DbgIsDebugging before DbgGetRegDumpEx");
    if (!DbgIsDebugging()) {
        DPUTS("DbgIsDebugging returned false");
        return 0;
    }
    DPUTS("Calling DbgGetRegDumpEx");
    if (DbgGetRegDumpEx(&registers, sizeof(REGDUMP))) {
        DPRINTF("DbgGetRegDumpEx succeeded, cip = 0x%llX", registers.regcontext.cip);
        if (registers.regcontext.cip == 0) {
            DPUTS("Warning: cip is 0, invalid instruction pointer");
        }
        return registers.regcontext.cip;
    }
    DPUTS("DbgGetRegDumpEx failed");
    return 0;
}

// Binary parsing based on ZFasConv
std::vector<Symbol> ParseFASFileBinary(const std::filesystem::path& path) {
    DPUTS("Entering ParseFASFileBinary");
    DPRINTF("File path: %s", path.string().c_str());
    std::vector<Symbol> loadedSymbols;

    void* mem = nullptr;
    DWORD fileSize = 0;
    fasHead* fhead = nullptr;

    // Open and read file
    HANDLE in = CreateFileA(path.string().c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (in == INVALID_HANDLE_VALUE) {
        DPUTS("Failed to open .fas file (binary mode)");
        MessageBoxA(NULL, "Failed to open .fas file in binary mode.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        return loadedSymbols;
    }

    // Load header and allocate memory
    if (!LoadFASHeader(in, mem, fileSize, fhead)) {
        CloseHandle(in);
        return loadedSymbols;
    }
    CloseHandle(in); // Close file handle immediately after reading

    // Get module base
    duint modBase = 0;
    char moduleName[MAX_PATH] = "";
    auto* dbgFuncs = DbgFunctions();
    DPRINTF("DbgFunctions() returned 0x%p", dbgFuncs);
    if (!dbgFuncs) {
        DPUTS("DbgFunctions() returned nullptr");
        VirtualFree(mem, 0, MEM_RELEASE);
        MessageBoxA(NULL, "Failed to get DbgFunctions. SDK may be incompatible.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        return loadedSymbols;
    }

    duint currentEIP = GetCurrentEIP();
    if (currentEIP) {
        DPUTS("Calling DbgGetModuleAt");
        if (DbgGetModuleAt(currentEIP, moduleName)) {
            DPRINTF("DbgGetModuleAt succeeded, module name: %s", moduleName);
            DPUTS("Calling DbgFunctions()->ModBaseFromName");
            modBase = dbgFuncs->ModBaseFromName(moduleName);
            DPRINTF("DbgFunctions()->ModBaseFromName returned 0x%llX", modBase);
        }
        else {
            DPUTS("DbgGetModuleAt failed");
        }
    }
    else {
        DPUTS("Warning: cip is 0, invalid instruction pointer");
    }

    if (!modBase) {
        DPUTS("Failed to get module base address");
        VirtualFree(mem, 0, MEM_RELEASE);
        MessageBoxA(NULL, "Failed to get module base address.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        return loadedSymbols;
    }

    // Parse symbols (for labels)
    if (!ParseSymbols(mem, fhead, fileSize, modBase, loadedSymbols)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return loadedSymbols;
    }

    VirtualFree(mem, 0, MEM_RELEASE);
    DPRINTF("ParseFASFileBinary: Loaded %zu symbols", loadedSymbols.size());
    if (loadedSymbols.empty()) {
        DPUTS("No symbols loaded from .fas file");
        MessageBoxA(NULL, "No symbols were loaded from the .fas file. Check the file format or contents.", PLUGIN_NAME, MB_OK | MB_ICONWARNING);
    }
    return loadedSymbols;
}

static bool LoadFASHeader(HANDLE in, void*& mem, DWORD& fileSize, fasHead*& fhead) {
    fileSize = GetFileSize(in, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize < sizeof(fasHead)) {
        DPUTS("Failed to get .fas file size or file too small");
        MessageBoxA(NULL, "Failed to get .fas file size or file too small.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        return false;
    }
    DPRINTF("File size: %u bytes", fileSize);

    mem = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        DPUTS("Failed to allocate memory");
        MessageBoxA(NULL, "Failed to allocate memory for .fas file.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        return false;
    }

    DWORD bytesRead;
    if (!ReadFile(in, mem, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        VirtualFree(mem, 0, MEM_RELEASE);
        DPUTS("Failed to read .fas file");
        MessageBoxA(NULL, "Failed to read .fas file.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        return false;
    }

    fhead = static_cast<fasHead*>(mem);
    DPRINTF("FAS file signature read: 0x%08X", fhead->magic);
    if (fhead->magic != FAS_MAGIC) {
        VirtualFree(mem, 0, MEM_RELEASE);
        DPRINTF("Invalid .fas file signature, expected: 0x%08X, got: 0x%08X", FAS_MAGIC, fhead->magic);
        MessageBoxA(NULL, "Invalid .fas file signature.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        return false;
    }
    DPRINTF("FAS file signature verified: 0x%08X", fhead->magic);

    // Validate offsets and sizes for symbols only
    if (fhead->oSym > fileSize || fhead->oStr > fileSize || fhead->oSrc > fileSize ||
        fhead->lSym > fileSize - fhead->oSym || fhead->lStr > fileSize - fhead->oStr ||
        fhead->lSrc > fileSize - fhead->oSrc) {
        VirtualFree(mem, 0, MEM_RELEASE);
        DPUTS("Invalid offsets or sizes in .fas header");
        MessageBoxA(NULL, "Invalid offsets or sizes in .fas header.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        return false;
    }

    // Log header details
    DPRINTF("Header: oStr=0x%X, lStr=0x%X, oSym=0x%X, lSym=0x%X, oSrc=0x%X, lSrc=0x%X",
        fhead->oStr, fhead->lStr, fhead->oSym, fhead->lSym, fhead->oSrc, fhead->lSrc);
    return true;
}

static bool ParseSymbols(void* mem, const fasHead* fhead, DWORD fileSize, duint modBase, std::vector<Symbol>& loadedSymbols) {
    DPUTS("Parsing symbols");
    fasSym* sym = reinterpret_cast<fasSym*>(static_cast<BYTE*>(mem) + fhead->oSym);
    char* strtable = static_cast<char*>(mem) + fhead->oStr;
    char* prepsrc = static_cast<char*>(mem) + fhead->oSrc;
    uint32_t symCount = fhead->lSym / sizeof(fasSym);
    DPRINTF("Symbol table length: %u bytes, %u symbols", fhead->lSym, symCount);

    for (uint32_t i = 0; i < symCount; ++i) {
        if (fhead->oSym + (i + 1) * sizeof(fasSym) > fileSize) {
            DPRINTF("Symbol %u out of bounds, stopping parsing", i);
            break;
        }
        // Filter symbols: defined, not assembly-time variable, relocatable label
        if (!(sym[i].flags & FAS_SYM_DEFINED) || (sym[i].flags & FAS_SYM_ASMVAR) || !(sym[i].flags & FAS_SYM_RLABEL)) {
            continue;
        }
        // Skip anonymous symbols
        if (sym[i].name == 0) {
            DPRINTF("Skipping anonymous symbol %u", i);
            continue;
        }
        // Skip negative value symbols
        if (sym[i].flags & 0x200) { // Negative number (Table 2.1)
            DPRINTF("Skipping negative symbol %u", i);
            continue;
        }
        // Skip special markers
        if (sym[i].flags & 0x400) { // Special marker (Table 2.1)
            DPRINTF("Skipping special marker symbol %u", i);
            continue;
        }
        // Check absolute value (Table 2.2)
        if (sym[i].type != 0) { // Only absolute values supported
            DPRINTF("Skipping non-absolute symbol %u, type=0x%X", i, sym[i].type);
            continue;
        }
        // Get symbol name
        std::string label;
        if (!GetSymbolName(mem, fhead, fileSize, sym[i], label)) {
            DPRINTF("Failed to get name for symbol %u", i);
            continue;
        }
        // Check macro-generated symbols
        if (sym[i].src < fhead->lSrc) {
            fasSrc* src = reinterpret_cast<fasSrc*>(prepsrc + sym[i].src);
            if (src->line & FAS_SRC_MACROG && src->origin < fhead->lSrc) {
                fasSrc* origin = reinterpret_cast<fasSrc*>(prepsrc + src->origin);
                if (origin->origin == 4 && strncmp(reinterpret_cast<char*>(origin) + 8, "proc", 4) != 0) {
                    DPRINTF("Skipping macro-generated symbol: %s (not 'proc')", label.c_str());
                    continue;
                }
            }
        }
        else {
            DPRINTF("Invalid src offset for symbol %u: 0x%X", i, sym[i].src);
            continue;
        }
        loadedSymbols.push_back({ label, static_cast<duint>(sym[i].value - modBase) });
        DPRINTF("Added symbol: %s at offset 0x%llX", label.c_str(), static_cast<duint>(sym[i].value - modBase));
    }
    return true;
}

static bool GetSymbolName(void* mem, const fasHead* fhead, DWORD fileSize, const fasSym& sym, std::string& name) {
    char label[256] = { 0 };
    if (sym.name & FAS_SYM_STRTAB) {
        uint32_t name_offset = sym.name ^ FAS_SYM_STRTAB;
        if (name_offset >= fhead->lStr || fhead->oStr + name_offset >= fileSize) {
            DPRINTF("Invalid string table offset for symbol: 0x%X", name_offset);
            return false;
        }
        strncpy_s(label, static_cast<char*>(mem) + fhead->oStr + name_offset, sizeof(label) - 1);
        DPRINTF("Symbol name from string table: %s", label);
    }
    else {
        if (sym.name >= fhead->lSrc || fhead->oSrc + sym.name >= fileSize) {
            DPRINTF("Invalid preprocessed source offset for symbol: 0x%X", sym.name);
            return false;
        }
        char* stroffset = static_cast<char*>(mem) + fhead->oSrc + sym.name;
        int len = static_cast<BYTE>(*stroffset);
        if (len >= sizeof(label) || sym.name + 1 + len > fhead->lSrc || fhead->oSrc + sym.name + 1 + len > fileSize) {
            DPRINTF("Invalid preprocessed source length for symbol: offset=0x%X, len=%d", sym.name, len);
            return false;
        }
        memcpy(label, stroffset + 1, len);
        label[len] = '\0';
        DPRINTF("Symbol name from preprocessed source: %s", label);
    }
    name = label;
    return true;
}

void LoadSymbolsAndSource(duint modBase, const std::vector<Symbol>& loadedSymbols) {
    DPUTS("Entering LoadSymbolsAndSource");
    DPRINTF("Module base: 0x%llX, Symbols count: %zu", modBase, loadedSymbols.size());
    if (loadedSymbols.empty()) {
        DPUTS("No symbols to load");
        MessageBoxA(NULL, "No symbols to load.", PLUGIN_NAME, MB_OK | MB_ICONWARNING);
        return;
    }

    int successCount = 0;
    for (const auto& sym : loadedSymbols) {
        duint address = modBase + sym.offset;
        DPUTS("Calling DbgSetLabelAt");
        bool success = DbgSetLabelAt(address, sym.name.c_str());
        DPRINTF("Setting label: %s at 0x%llX, Success: %d", sym.name.c_str(), address, success);
        if (success) {
            successCount++;
            DPRINTF("Set label %s at 0x%llX", sym.name.c_str(), address);
        }
        else {
            DPRINTF("Failed to set label %s at 0x%llX", sym.name.c_str(), address);
        }
    }

    DPRINTF("Successfully set %d/%zu labels", successCount, loadedSymbols.size());
    if (successCount > 0) {
        DPUTS("Labels loaded successfully");
        MessageBoxA(NULL, "Labels loaded successfully.", PLUGIN_NAME, MB_OK | MB_ICONINFORMATION);
    }
    else {
        DPUTS("No labels were set");
        MessageBoxA(NULL, "No labels were set. Check the .fas file and module base address.", PLUGIN_NAME, MB_OK | MB_ICONWARNING);
    }
}


// Helper function to select file using IFileOpenDialog and load symbols
bool LoadSymbolsFromFile() {
    DPUTS("Entering LoadSymbolsFromFile");

    // Initialize COM
    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        DPRINTF("CoInitialize failed, HRESULT=0x%X", hr);
        MessageBoxA(NULL, "Failed to initialize COM.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        return false;
    }

    // Create IFileOpenDialog
    IFileOpenDialog* pFileOpen = NULL;
    hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pFileOpen));
    if (FAILED(hr)) {
        DPRINTF("CoCreateInstance failed, HRESULT=0x%X", hr);
        MessageBoxA(NULL, "Failed to create file open dialog.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        CoUninitialize();
        return false;
    }

    // Set file filter
    COMDLG_FILTERSPEC fileTypes[] = {
        { L"FASM Symbol Files (*.fas)", L"*.fas" },
        { L"All Files (*.*)", L"*.*" }
    };
    hr = pFileOpen->SetFileTypes(2, fileTypes);
    if (FAILED(hr)) {
        DPRINTF("SetFileTypes failed, HRESULT=0x%X", hr);
        pFileOpen->Release();
        CoUninitialize();
        return false;
    }

    // Set default extension
    hr = pFileOpen->SetDefaultExtension(L"fas");
    if (FAILED(hr)) {
        DPRINTF("SetDefaultExtension failed, HRESULT=0x%X", hr);
    }

    // Get module base and path
    DPUTS("Calling GetCurrentEIP");
    duint imageBase = 0;
    char moduleName[MAX_PATH] = "";
    duint currentEIP = GetCurrentEIP();
    auto* dbgFuncs = DbgFunctions();
    DPRINTF("DbgFunctions() returned 0x%p", dbgFuncs);
    if (!dbgFuncs) {
        DPUTS("DbgFunctions() returned nullptr");
        pFileOpen->Release();
        CoUninitialize();
        MessageBoxA(NULL, "Failed to get DbgFunctions. SDK may be incompatible.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
        return false;
    }

    if (currentEIP) {
        DPUTS("Calling DbgGetModuleAt");
        if (DbgGetModuleAt(currentEIP, moduleName)) {
            DPRINTF("DbgGetModuleAt succeeded, module name: %s", moduleName);
            DPUTS("Calling DbgFunctions()->ModBaseFromName");
            imageBase = dbgFuncs->ModBaseFromName(moduleName);
            DPRINTF("DbgFunctions()->ModBaseFromName returned 0x%llX", imageBase);
        }
        else {
            DPUTS("DbgGetModuleAt failed");
        }
    }
    else {
        DPUTS("Warning: cip is 0, invalid instruction pointer");
    }

    if (!imageBase) {
       DPUTS("No process to add fas info");
       MessageBoxA(NULL, "Well - if you don't debug anything - you don't need .fas file ;-)", PLUGIN_NAME, MB_OK | MB_ICONINFORMATION);
       pFileOpen->Release();
       CoUninitialize();
       return false;
    }

    char modulePath[MAX_PATH] = "";
    char initialDir[MAX_PATH] = "";
    DPUTS("Calling DbgFunctions()->ModPathFromAddr");
    if (!dbgFuncs->ModPathFromAddr(imageBase, modulePath, MAX_PATH)) {
        DPUTS("DbgFunctions()->ModPathFromAddr failed");
        return false;
    }
    else if (strlen(modulePath) > 0) {
        DPRINTF("Module path: %s", modulePath);
        // Set initial directory
        strncpy_s(initialDir, modulePath, MAX_PATH);
        char* lastSlash = strrchr(initialDir, '\\');
        if (lastSlash) *lastSlash = '\0';
        DPRINTF("Initial directory: %s", initialDir);
        // Convert to wide string for COM
        std::wstring wInitialDir = std::wstring(initialDir, initialDir + strlen(initialDir));
        IShellItem* pFolder = NULL;
        if (SUCCEEDED(SHCreateItemFromParsingName(wInitialDir.c_str(), NULL, IID_PPV_ARGS(&pFolder)))) {
            pFileOpen->SetFolder(pFolder);
            pFolder->Release();
        }
    }

    // Show the dialog
    HWND hwnd = GuiGetWindowHandle();
    DPRINTF("Opening file dialog, GuiGetWindowHandle=0x%p, IsWindow(GuiGetWindowHandle)=%d", hwnd, IsWindow(hwnd));
    hr = pFileOpen->Show(hwnd && IsWindow(hwnd) ? hwnd : NULL);
    if (FAILED(hr)) {
        DPRINTF("IFileOpenDialog::Show failed, HRESULT=0x%X", hr);
        DPUTS("No file selected");
        pFileOpen->Release();
        CoUninitialize();
        return false;
    }

    // Get the selected file
    IShellItem* pItem = NULL;
    hr = pFileOpen->GetResult(&pItem);
    if (SUCCEEDED(hr)) {
        PWSTR pszFilePath = NULL;
        hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
        if (SUCCEEDED(hr)) {
            // Convert wide string to narrow string
            char filePath[MAX_PATH] = "";
            WideCharToMultiByte(CP_ACP, 0, pszFilePath, -1, filePath, MAX_PATH, NULL, NULL);
            DPRINTF("Selected file: %s", filePath);
            CoTaskMemFree(pszFilePath);

            // Parse the file
            DPUTS("Calling ParseFASFileBinary");
            auto loadedSymbols = ParseFASFileBinary(filePath);
            if (!loadedSymbols.empty()) {
                DPRINTF("Loaded %zu symbols", loadedSymbols.size());
                // Get module base (second call)
                DPUTS("Calling GetCurrentEIP (second call)");
                duint modBase = 0;
                currentEIP = GetCurrentEIP();
                if (currentEIP) {
                    DPUTS("Calling DbgGetModuleAt (second call)");
                    if (DbgGetModuleAt(currentEIP, moduleName)) {
                        DPRINTF("DbgGetModuleAt (second call) succeeded, module name: %s", moduleName);
                        DPUTS("Calling DbgFunctions()->ModBaseFromName (second call)");
                        modBase = dbgFuncs->ModBaseFromName(moduleName);
                        DPRINTF("DbgFunctions()->ModBaseFromName (second call) returned 0x%llX", modBase);
                    }
                    else {
                        DPUTS("DbgGetModuleAt (second call) failed");
                    }
                }
            
                if (modBase) {
                    DPRINTF("Calling LoadSymbolsAndSource with modBase=0x%llX", modBase);
                    LoadSymbolsAndSource(modBase, loadedSymbols);
                }
                else {
                    DPUTS("Failed to get module base address");
                    MessageBoxA(NULL, "Failed to get module base address.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
                }
            }
            else {
                DPUTS("Failed to parse .fas file");
            }
        }
        else {
            DPRINTF("GetDisplayName failed, HRESULT=0x%X", hr);
        }
        pItem->Release();
    }
    else {
        DPRINTF("GetResult failed, HRESULT=0x%X", hr);
        DPUTS("No file selected");
    }

    pFileOpen->Release();
    CoUninitialize();
    return true;
}

// Menu callback
PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info) {
    DPRINTF("CBMENUENTRY called with cbType=%d, hEntry=%d", cbType, info ? info->hEntry : -1);
    if (cbType != CB_MENUENTRY) {
        DPUTS("Invalid cbType, exiting CBMENUENTRY");
        return;
    }

    if (!info) {
        DPUTS("Invalid menu entry info");
        return;
    }

    DPRINTF("Comparing hEntry=%d with MA_LABELS_BINARY=%d, MA_ABOUT=%d",
        info->hEntry, MA_LABELS_BINARY, MA_ABOUT);

    switch (info->hEntry) {
    case MA_LABELS_BINARY:
        DPUTS("Selected: Load Labels");
		// Check if debugger is active
        DPUTS("Calling DbgIsDebugging");
        if (!DbgIsDebugging()) {
           DPUTS("No process is being debugged");
           MessageBoxA(NULL, "No process is being debugged. Please start debugging a process first.", PLUGIN_NAME, MB_OK | MB_ICONERROR);
           return;
        }
        LoadSymbolsFromFile();
        break;

    case MA_ABOUT:
        DPRINTF("Showing About dialog, hwndDlg=0x%p", hwndDlg);
        MessageBoxA(NULL, "FASMDbgHelper Plugin v1.0 by CynicRus\nLoad FASM symbols as labels\n", PLUGIN_NAME, MB_OK | MB_ICONINFORMATION);
        break;

    default:
        DPRINTF("Unknown menu entry: %d", info->hEntry);
        break;
    }
    GuiUpdateDisassemblyView();
}

// Plugin initialization
PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct) {
    DPUTS("pluginit called");
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, sizeof(initStruct->pluginName));
    pluginHandle = initStruct->pluginHandle;
    DPRINTF("Plugin initialized: handle=%d, version=%d, sdkVersion=%d", pluginHandle, PLUGIN_VERSION, PLUG_SDKVERSION);
    return true;
}

// Plugin setup (add menu items)
PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct) {
    hwndDlg = setupStruct->hwndDlg;
    menuHandleLabelsBinary = _plugin_menuaddentry(setupStruct->hMenu, MA_LABELS_BINARY, "Load Labels");
    menuHandleAbout = _plugin_menuaddentry(setupStruct->hMenu, MA_ABOUT, "About");
}

// Plugin cleanup
PLUG_EXPORT bool plugstop() {
    _plugin_menuclear(pluginHandle);
    return true;
}

// DLL entry point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    return TRUE;
}