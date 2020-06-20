

project ("ice8445")

message(" ===================== ${PROJECT_NAME} Information ======================")



add_executable( ${PROJECT_NAME} 
	"sendAllocationReq.cpp" 
)

target_include_directories( ${PROJECT_NAME} 
	PRIVATE 
	  ${CMAKE_SOURCE_DIR}/include
		${PROJECT_SOURCE_DIR}/include
)

target_link_libraries( ${PROJECT_NAME} 
	PRIVATE 
		${CMAKE_THREAD_LIBS_INIT}
		${CMAKE_DL_LIBS}
		hash_library
)
