#/**********************************************************\ 
# Auto-generated X11 project definition file for the
# gpgAuth project
#\**********************************************************/

# X11 template platform definition CMake file
# Included from ../CMakeLists.txt

# This is needed for firebreath versions prior to 1.2.0 - 
#   once I migrate the code for 1.2.0 this should go away.
find_package(Boost COMPONENTS thread REQUIRED)

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
)

set (SOURCES
    ${SOURCES}
    ${PLATFORM}
    )

add_x11_plugin(${PROJNAME} SOURCES)

# add library dependencies here; leave ${PLUGIN_INTERNAL_DEPS} there unless you know what you're doing!
target_link_libraries(${PROJNAME}
    ${PLUGIN_INTERNAL_DEPS}
    # Remove for firebreath version 1.2.0 or greater
    ${Boost_THREAD_LIBRARY}
    -lgpgme
    -lgpg-error
    )

add_dependencies(${PROJNAME}
    ${PLUGIN_INTERNAL_DEPS}
    )
