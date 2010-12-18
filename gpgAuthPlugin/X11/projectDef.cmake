#/**********************************************************\ 
# Auto-generated X11 project definition file for the
# gpgAuth project
#\**********************************************************/

# X11 template platform definition CMake file
# Included from ../CMakeLists.txt

# remember that the current source dir is the project root; this file is in ${PLATFORM_NAME}/
file (GLOB PLATFORM RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    ${PLATFORM_NAME}/[^.]*.cpp
    ${PLATFORM_NAME}/[^.]*.h
    ${PLATFORM_NAME}/[^.]*.cmake
    )

SOURCE_GROUP(${PLATFORM_NAME} FILES ${PLATFORM})

# use this to add preprocessor definitions
add_definitions(
    -D_FILE_OFFSET_BITS=64
    -DCMAKE_BUILD_TYPE=MinSizeRel
)

set (SOURCES
    ${SOURCES}
    ${PLATFORM}
    )

add_x11_plugin(${PROJNAME} SOURCES)

# add library dependencies here; leave ${PLUGIN_INTERNAL_DEPS} there unless you know what you're doing!
target_link_libraries(${PROJNAME}
    ${PLUGIN_INTERNAL_DEPS}
    -lgpgme
    -lgpg-error
#    /usr/lib/libgpgme.a
#    /lib/libgpg-error.a
    )

add_dependencies(${PROJNAME}
    ${PLUGIN_INTERNAL_DEPS}
    )
