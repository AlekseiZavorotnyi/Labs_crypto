cmake_minimum_required(VERSION 3.28.3)
project(Labs_crypto)

set(CMAKE_CXX_STANDARD 20)

# Пути к заголовочным файлам
include_directories(${CMAKE_SOURCE_DIR}/Lab1/include)

# Соберём список всех исходников рекурсивно
file(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS
        ${CMAKE_SOURCE_DIR}/Lab1/src/*.cpp
)

# Создаём статическую библиотеку
add_library(crypto_core STATIC ${SRC_FILES})

# Указываем include-директории для библиотеки
target_include_directories(crypto_core PUBLIC ${CMAKE_SOURCE_DIR}/Lab1/include)

# Основной исполняемый файл
add_executable(crypt_main ${CMAKE_SOURCE_DIR}/Lab1/src/main.cpp)

# Линкуем с нашей библиотекой
target_link_libraries(crypt_main PRIVATE crypto_core)

# Дополнительно: включаем предупреждения
if (MSVC)
    target_compile_options(crypto_core PRIVATE /W4 /permissive-)
else()
    #target_compile_options(crypto_core PRIVATE -Wall -Wextra -pedantic -Werror -fsanitize=address -g)
    target_compile_options(crypto_core PRIVATE -Wall -Wextra -pedantic -Werror)
endif()