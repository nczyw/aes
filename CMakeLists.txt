cmake_minimum_required(VERSION 3.27)
#工程名字
project(AES LANGUAGES CXX C)
#使用C++ 17编译 , GCC对C++23支持不是很好
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD_REQUIRED ON)

#设置静态库编译文件
set(TARGET_DIR ${CMAKE_CURRENT_LIST_DIR}/../target/)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${TARGET_DIR}/target/)

#设置动态库文件目录
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${TARGET_DIR}/target/)


#设置可执行库文件目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${TARGET_DIR}/target/)

#设置编译类型
# Debug Release RelWithDebInfo MinSizeRel
set(Build_Type Release)
set(CMAKE_BUILD_TYPE ${Build_Type}) #Mingw编译器使用
set(CMAKE_CONFIGURATION_TYPES ${Build_Type})


#设置头文件目录
include_directories(
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/aes/inc
    ${CMAKE_CURRENT_LIST_DIR}/aes/inc/aesni
    ${CMAKE_CURRENT_LIST_DIR}/base64/inc
)
#获取编译器型号，MSVC不开启硬件加速，代码只支持GCC编译时，开启硬件加速
set (Compiler ${CMAKE_CXX_COMPILER_ID})
if(Compiler MATCHES "MSVC")
    set(AES_ENABLE_AESNI  OFF)
else()
    set(AES_ENABLE_AESNI  ON)
endif()
if(AES_ENABLE_AESNI)
    message("Enable AES-NI")
    add_definitions(-DUSE_INTEL_AES_IF_AVAILABLE)
    set(AESNI
        ${CMAKE_CURRENT_LIST_DIR}/aes/inc/aesni/aesni-enc-cbc.h
        ${CMAKE_CURRENT_LIST_DIR}/aes/inc/aesni/aesni-enc-ecb.h
        ${CMAKE_CURRENT_LIST_DIR}/aes/inc/aesni/aesni-key-exp.h
        ${CMAKE_CURRENT_LIST_DIR}/aes/inc/aesni/aesni-key-init.h
    )
else()
    set(AESNI "")
endif()
#设置AES_头文件
set(AES_Headers
    ${CMAKE_CURRENT_LIST_DIR}/aes/inc/aes.hpp
    ${CMAKE_CURRENT_LIST_DIR}/base64/inc/base64.hpp
    ${CMAKE_CURRENT_LIST_DIR}/aes/inc/exaes.hpp
)
#设置AES_源文件
set(AES_Sources
    ${CMAKE_CURRENT_LIST_DIR}/aes/src/aes.cpp
    ${CMAKE_CURRENT_LIST_DIR}/base64/src/base64.cpp
    ${CMAKE_CURRENT_LIST_DIR}/aes/src/exaes.cpp
)
#合并工程文件
set(AES_Project 
    ${AESNI}
    ${AES_Headers}
    ${AES_Sources}
)
# msvc要使用utf-8 with BOM，使用下面的代码改变为utf-8
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/source-charset:utf-8>") 

#生成库文件
set(LibName ${CMAKE_PROJECT_NAME})
add_library(${LibName} SHARED
    ${AES_Project}
)
#生成可执行文件
add_executable(${CMAKE_PROJECT_NAME}Test
    ${CMAKE_CURRENT_LIST_DIR}/main.cpp
)
target_link_libraries(${CMAKE_PROJECT_NAME}Test PRIVATE
    ${LibName}
)
if(AES_ENABLE_AESNI)
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag(-maes CXX_COMPILER_HAS_FLAG_MAES)
    check_cxx_compiler_flag("/arch:AVX" CXX_COMPILER_HAS_ARCH_AVX)
    IF(CXX_COMPILER_HAS_ARCH_AVX)
	    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /arch:AVX")
    ENDIF()
    target_compile_options(${LibName}
        PRIVATE
        $<$<BOOL:${CXX_COMPILER_HAS_FLAG_MAES}>:-maes>
    )
endif()


#设置需要导出的头文件
set(IncludeFile 
    ${CMAKE_CURRENT_LIST_DIR}/aes/inc/exaes.hpp
    ${CMAKE_CURRENT_LIST_DIR}/aes/inc/aes.hpp
)
#设置编译输出目录
set(CMAKE_INSTALL_PREFIX ${TARGET_DIR}/install)

install(TARGETS ${LibName} ${CMAKE_PROJECT_NAME}Test
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
    RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
)
install(FILES ${IncludeFile} DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
