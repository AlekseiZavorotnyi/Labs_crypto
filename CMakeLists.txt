cmake_minimum_required(VERSION 3.28.3)
project(Labs_crypto)

set(CMAKE_CXX_STANDARD 20)

find_path(GMP_INCLUDE_DIR gmp.h
        PATHS
        /usr/include
        /usr/local/include
        /opt/local/include
        /usr/include/x86_64-linux-gnu
)

# Ищем библиотеки GMP (основная и C++)
find_library(GMP_LIBRARY NAMES gmp
        PATHS
        /usr/lib
        /usr/lib64
        /usr/local/lib
        /opt/local/lib
        /usr/lib/x86_64-linux-gnu
)

find_library(GMPXX_LIBRARY NAMES gmpxx
        PATHS
        /usr/lib
        /usr/lib64
        /usr/local/lib
        /opt/local/lib
        /usr/lib/x86_64-linux-gnu
)

# Проверяем, что всё найдено
if(NOT GMP_INCLUDE_DIR)
    message(FATAL_ERROR "GMP header (gmp.h) not found! Install with: sudo apt install libgmp-dev")
endif()

if(NOT GMP_LIBRARY)
    message(FATAL_ERROR "GMP library (libgmp) not found!")
endif()

if(NOT GMPXX_LIBRARY)
    message(WARNING "GMP C++ library (libgmpxx) not found. Install with: sudo apt install libgmpxx4-dev")
    # Можно работать без C++ интерфейса, но лучше установить
endif()

message(STATUS "Found GMP include dir: ${GMP_INCLUDE_DIR}")
message(STATUS "Found GMP library: ${GMP_LIBRARY}")
message(STATUS "Found GMPXX library: ${GMPXX_LIBRARY}")

# ========== ТВОЙ ОРИГИНАЛЬНЫЙ КОД ==========

# Пути к заголовочным файлам
include_directories(
        ${CMAKE_SOURCE_DIR}/include
        ${GMP_INCLUDE_DIR}  # Добавляем заголовки GMP
)

# Соберём список всех исходников рекурсивно
file(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS
        ${CMAKE_SOURCE_DIR}/src/*.cpp
)

# Создаём статическую библиотеку
add_library(crypto_core STATIC ${SRC_FILES})

# Указываем include-директории для библиотеки
target_include_directories(crypto_core PUBLIC
        ${CMAKE_SOURCE_DIR}/include
        ${GMP_INCLUDE_DIR}
)

# Связываем GMP с нашей библиотекой
target_link_libraries(crypto_core PRIVATE
        ${GMP_LIBRARY}
        ${GMPXX_LIBRARY}  # C++ интерфейс
)

# Основной исполняемый файл
add_executable(lab1 ${CMAKE_SOURCE_DIR}/src/main_lab1.cpp)
add_executable(lab2 ${CMAKE_SOURCE_DIR}/src/main_lab2.cpp)

# Линкуем с нашей библиотекой
target_link_libraries(lab1 PRIVATE crypto_core)
target_link_libraries(lab2 PRIVATE crypto_core)

# Дополнительно: включаем предупреждения
if (MSVC)
    target_compile_options(crypto_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(crypto_core PRIVATE -Wall -Wextra -pedantic -Werror)
endif()