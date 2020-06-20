# CMakeList.txt : CMake project for helloLibevent, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.11)

project ("HelloCoturn" VERSION 0.0.1)



include(./cmake/checkBuildType.cmake)

#-------------------------------------
#  spdlog settings
#-------------------------------------
include(./cmake/utils.cmake)


include(./.SET_LOCAL_PATH.cmake)


# --------------------------------------------------------------------------
# specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "-D__STDC_CONSTANT_MACROS")



if(MSVC)
    SET(CMAKE_CXX_FLAGS "/EHsc")  # deal with MSVC Warning C4530
endif(MSVC)

#-------------------------------------
#  config.h.in settings
#-------------------------------------


option(BOOST_DATE_TIME_NO_LIB  "disable boost::Date_time in asio" ON)
option(BOOST_REGEX_NO_LIB  "disable boost::regex in asio" ON)

set(CPPHTTPLIB_THREAD_POOL_COUNT 64)

set(SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE)
set(LOG_FILE_NAME "application.log")
set(CA_CERT_FILE "./resources/ca-bundle.crt")

configure_file(
	"./cmake/config.h.in" 
	"${PROJECT_SOURCE_DIR}/include/config.h"
	@ONLY
)

add_subdirectory("modules/hash")
add_subdirectory("modules/ice8445")
