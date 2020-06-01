


add_executable(allocation_module 
	"sendAllocationReq.cpp" 
)

target_include_directories( allocation_module
	PRIVATE 
		${PROJECT_SOURCE_DIR}/include
)


target_link_libraries( allocation_module
	PRIVATE 
		${CMAKE_THREAD_LIBS_INIT}
		${CMAKE_DL_LIBS}
)
