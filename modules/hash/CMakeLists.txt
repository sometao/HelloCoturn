

project ("hash_library")


add_library(${PROJECT_NAME} 
	"src/md5.cpp"
	"src/sha1.cpp"
	"src/crc32.cpp"
)



target_include_directories( ${PROJECT_NAME} 
	PUBLIC 
		${PROJECT_SOURCE_DIR}/include
)

