cmake_minimum_required(VERSION 3.15)
project(FASMDbgHelper LANGUAGES CXX)

# Установка стандарта C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Определение корневой папки x64dbg
set(X64DBG_ROOT "G:/ReverseEngeneering/x64dbg" CACHE PATH "Path to x64dbg root directory")

# Определение архитектуры сборки (x64 или Win32)
if(CMAKE_GENERATOR_PLATFORM MATCHES "x64")
    set(ARCH "x64")
    set(PLUGIN_SUFFIX ".dp64")
    set(X64DBG_LIBS x64dbg x64bridge)
    set(THIRD_PARTY_LIBS DeviceNameResolver_x64 jansson_x64 lz4_x64 TitanEngine_x64 XEDParse_x64)
    set(LINKER_FLAGS "/MACHINE:X64")
elseif(CMAKE_GENERATOR_PLATFORM MATCHES "Win32")
    set(ARCH "x86")
    set(PLUGIN_SUFFIX ".dp32")
    set(X64DBG_LIBS x32dbg x32bridge)
    set(THIRD_PARTY_LIBS DeviceNameResolver_x86 jansson_x86 lz4_x86 TitanEngine_x86 XEDParse_x86)
    set(LINKER_FLAGS "/MACHINE:X86")
else()
    message(FATAL_ERROR "Unsupported architecture. Use -A x64 or -A Win32.")
endif()

# Папка для вывода плагина
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/x64dbg/release/${ARCH}/plugins")

# Исходные файлы
set(SOURCES
    FASMDbgHelper.cpp
    fasm_fas.h
)

# Путь к заголовкам x64dbg plugin SDK
include_directories("${X64DBG_ROOT}/pluginsdk")

# Путь к библиотекам x64dbg и сторонним библиотекам
link_directories("${X64DBG_ROOT}/pluginsdk" "${X64DBG_ROOT}/pluginsdk/DeviceNameResolver" 
                 "${X64DBG_ROOT}/pluginsdk/jansson" "${X64DBG_ROOT}/pluginsdk/lz4" 
                 "${X64DBG_ROOT}/pluginsdk/TitanEngine" "${X64DBG_ROOT}/pluginsdk/XEDParse")

# Создание плагина как разделяемой библиотеки
add_library(FASMDbgHelper SHARED ${SOURCES})

# Линковка с необходимыми библиотеками
target_link_libraries(FASMDbgHelper PRIVATE comdlg32 ${X64DBG_LIBS} ${THIRD_PARTY_LIBS})

# Установка имени и расширения для плагина
set_target_properties(FASMDbgHelper PROPERTIES
    OUTPUT_NAME "FASMDbgHelper"
    SUFFIX "${PLUGIN_SUFFIX}"
)

# Установка флагов компиляции
target_compile_options(FASMDbgHelper PRIVATE /W4 /EHsc /MD /D WINDOWS_IGNORE_PACKING_MISMATCH)
if(DEBUG)
    target_compile_definitions(FASMDbgHelper PRIVATE DEBUG)
endif()

# Установка флагов компоновщика
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")