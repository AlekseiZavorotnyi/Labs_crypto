cmake_minimum_required(VERSION 3.28.3)
project(Labs_crypto)

set(CMAKE_CXX_STANDARD 20)

# Сообщение о конфигурации
message(STATUS "Configuring Crypto Labs project with GMP...")
message(STATUS "Project source dir: ${CMAKE_SOURCE_DIR}")

# Находим все исходные файлы (исключая временные build файлы)
file(GLOB_RECURSE ALL_SOURCES CONFIGURE_DEPENDS
        ${CMAKE_SOURCE_DIR}/Lab1/src/*.cpp
        ${CMAKE_SOURCE_DIR}/Lab1/src/*/*.cpp
        ${CMAKE_SOURCE_DIR}/Lab1/src/*/*/*.cpp
)

# Исключаем файлы из build директорий
list(FILTER ALL_SOURCES EXCLUDE REGEX ".*cmake-build.*")
list(FILTER ALL_SOURCES EXCLUDE REGEX ".*build.*")

# Отладочная информация
message(STATUS "Found ${ALL_SOURCES} source files:")
foreach(src ${ALL_SOURCES})
    message(STATUS "  ${src}")
endforeach()

# Разделяем на библиотечные файлы и main файлы
set(LIB_SOURCES)
set(MAIN_SOURCES)

foreach(src ${ALL_SOURCES})
    get_filename_component(FNAME ${src} NAME)
    if(FNAME MATCHES "^main_.*\\.cpp$")
        list(APPEND MAIN_SOURCES ${src})
        message(STATUS "Main file: ${src}")
    else()
        list(APPEND LIB_SOURCES ${src})
    endif()
endforeach()

# Создаем статическую библиотеку из всех не-main файлов
if(LIB_SOURCES)
    add_library(crypto_core STATIC ${LIB_SOURCES})

    # Указываем все include директории
    target_include_directories(crypto_core PUBLIC
            ${CMAKE_SOURCE_DIR}/Lab1/include
            ${CMAKE_SOURCE_DIR}/Lab1/include/CipherModes
            ${CMAKE_SOURCE_DIR}/Lab1/include/DEAL
            ${CMAKE_SOURCE_DIR}/Lab1/include/DES
            ${CMAKE_SOURCE_DIR}/Lab1/include/Interfaces
            ${CMAKE_SOURCE_DIR}/Lab1/include/PaddingModes
            ${CMAKE_SOURCE_DIR}/Lab1/include/RSA
    )

    # Связываем с GMP
    target_link_libraries(crypto_core PRIVATE gmp gmpxx)

    # Опции компиляции
    target_compile_options(crypto_core PRIVATE
            -Wall -Wextra -pedantic -Werror
    )

    message(STATUS "Created static library 'crypto_core' with ${LIB_SOURCES} files")
else()
    message(WARNING "No library source files found!")
endif()

# Создаем исполняемые файлы из main файлов
foreach(main_src ${MAIN_SOURCES})
    get_filename_component(EXE_NAME ${main_src} NAME_WE)

    add_executable(${EXE_NAME} ${main_src})

    # Include директории для исполняемого файла
    target_include_directories(${EXE_NAME} PRIVATE
            ${CMAKE_SOURCE_DIR}/Lab1/include
            ${CMAKE_SOURCE_DIR}/Lab1/include/CipherModes
            ${CMAKE_SOURCE_DIR}/Lab1/include/DEAL
            ${CMAKE_SOURCE_DIR}/Lab1/include/DES
            ${CMAKE_SOURCE_DIR}/Lab1/include/Interfaces
            ${CMAKE_SOURCE_DIR}/Lab1/include/PaddingModes
            ${CMAKE_SOURCE_DIR}/Lab1/include/RSA
    )

    # Линкуем с библиотекой (если она создана)
    if(TARGET crypto_core)
        target_link_libraries(${EXE_NAME} PRIVATE crypto_core)
    else()
        # Если библиотеки нет, линкуем напрямую с GMP
        target_link_libraries(${EXE_NAME} PRIVATE gmp gmpxx)
    endif()

    # Опции компиляции
    target_compile_options(${EXE_NAME} PRIVATE
            -Wall -Wextra -pedantic -Werror
    )

    message(STATUS "Created executable: ${EXE_NAME}")
endforeach()

# Если нет main файлов, создаем один по умолчанию
if(NOT MAIN_SOURCES AND TARGET crypto_core)
    message(STATUS "No main files found, creating default executable...")

    add_executable(crypto_lab_default ${CMAKE_BINARY_DIR}/default_main.cpp)

    file(WRITE ${CMAKE_BINARY_DIR}/default_main.cpp
            "#include <iostream>\n#include <gmp.h>\n#include \"DES/DES.h\"\n\nint main() {\n    std::cout << \"Crypto Labs Project\" << std::endl;\n    std::cout << \"GMP version: \" << gmp_version << std::endl;\n    std::cout << \"Build successful!\" << std::endl;\n    return 0;\n}")

    target_include_directories(crypto_lab_default PRIVATE
            ${CMAKE_SOURCE_DIR}/Lab1/include
            ${CMAKE_SOURCE_DIR}/Lab1/include/CipherModes
            ${CMAKE_SOURCE_DIR}/Lab1/include/DEAL
            ${CMAKE_SOURCE_DIR}/Lab1/include/DES
            ${CMAKE_SOURCE_DIR}/Lab1/include/Interfaces
            ${CMAKE_SOURCE_DIR}/Lab1/include/PaddingModes
            ${CMAKE_SOURCE_DIR}/Lab1/include/RSA
    )

    if(TARGET crypto_core)
        target_link_libraries(crypto_lab_default PRIVATE crypto_core)
    else()
        target_link_libraries(crypto_lab_default PRIVATE gmp gmpxx)
    endif()

    message(STATUS "Created default executable: crypto_lab_default")
endif()