# CMAKE generated file: DO NOT EDIT!
# Generated by "NMake Makefiles" Generator, CMake Version 3.20

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE
NULL=nul
!ENDIF
SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = "C:\Program Files\JetBrains\CLion 2021.1.1\bin\cmake\win\bin\cmake.exe"

# The command to remove a file.
RM = "C:\Program Files\JetBrains\CLion 2021.1.1\bin\cmake\win\bin\cmake.exe" -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = C:\Users\picci\OneDrive\Desktop\crypto_openSSL\openSSL_CBC

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = C:\Users\picci\OneDrive\Desktop\crypto_openSSL\openSSL_CBC\cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles\openSSL_CBC.dir\depend.make
# Include the progress variables for this target.
include CMakeFiles\openSSL_CBC.dir\progress.make

# Include the compile flags for this target's objects.
include CMakeFiles\openSSL_CBC.dir\flags.make

CMakeFiles\openSSL_CBC.dir\main.c.obj: CMakeFiles\openSSL_CBC.dir\flags.make
CMakeFiles\openSSL_CBC.dir\main.c.obj: ..\main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\picci\OneDrive\Desktop\crypto_openSSL\openSSL_CBC\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/openSSL_CBC.dir/main.c.obj"
	C:\PROGRA~2\MICROS~2\2019\COMMUN~1\VC\Tools\MSVC\1429~1.300\bin\Hostx64\x64\cl.exe @<<
 /nologo $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) /FoCMakeFiles\openSSL_CBC.dir\main.c.obj /FdCMakeFiles\openSSL_CBC.dir\ /FS -c C:\Users\picci\OneDrive\Desktop\crypto_openSSL\openSSL_CBC\main.c
<<

CMakeFiles\openSSL_CBC.dir\main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/openSSL_CBC.dir/main.c.i"
	C:\PROGRA~2\MICROS~2\2019\COMMUN~1\VC\Tools\MSVC\1429~1.300\bin\Hostx64\x64\cl.exe > CMakeFiles\openSSL_CBC.dir\main.c.i @<<
 /nologo $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E C:\Users\picci\OneDrive\Desktop\crypto_openSSL\openSSL_CBC\main.c
<<

CMakeFiles\openSSL_CBC.dir\main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/openSSL_CBC.dir/main.c.s"
	C:\PROGRA~2\MICROS~2\2019\COMMUN~1\VC\Tools\MSVC\1429~1.300\bin\Hostx64\x64\cl.exe @<<
 /nologo $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) /FoNUL /FAs /FaCMakeFiles\openSSL_CBC.dir\main.c.s /c C:\Users\picci\OneDrive\Desktop\crypto_openSSL\openSSL_CBC\main.c
<<

# Object files for target openSSL_CBC
openSSL_CBC_OBJECTS = \
"CMakeFiles\openSSL_CBC.dir\main.c.obj"

# External object files for target openSSL_CBC
openSSL_CBC_EXTERNAL_OBJECTS =

openSSL_CBC.exe: CMakeFiles\openSSL_CBC.dir\main.c.obj
openSSL_CBC.exe: CMakeFiles\openSSL_CBC.dir\build.make
openSSL_CBC.exe: "C:\Program Files\OpenSSL-Win64\lib\VC\libssl64MDd.lib"
openSSL_CBC.exe: "C:\Program Files\OpenSSL-Win64\lib\VC\libcrypto64MDd.lib"
openSSL_CBC.exe: CMakeFiles\openSSL_CBC.dir\objects1.rsp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=C:\Users\picci\OneDrive\Desktop\crypto_openSSL\openSSL_CBC\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable openSSL_CBC.exe"
	"C:\Program Files\JetBrains\CLion 2021.1.1\bin\cmake\win\bin\cmake.exe" -E vs_link_exe --intdir=CMakeFiles\openSSL_CBC.dir --rc=C:\PROGRA~2\WI3CF2~1\10\bin\100190~1.0\x64\rc.exe --mt=C:\PROGRA~2\WI3CF2~1\10\bin\100190~1.0\x64\mt.exe --manifests -- C:\PROGRA~2\MICROS~2\2019\COMMUN~1\VC\Tools\MSVC\1429~1.300\bin\Hostx64\x64\link.exe /nologo @CMakeFiles\openSSL_CBC.dir\objects1.rsp @<<
 /out:openSSL_CBC.exe /implib:openSSL_CBC.lib /pdb:C:\Users\picci\OneDrive\Desktop\crypto_openSSL\openSSL_CBC\cmake-build-debug\openSSL_CBC.pdb /version:0.0 /machine:x64 /debug /INCREMENTAL /subsystem:console  "C:\Program Files\OpenSSL-Win64\lib\VC\libssl64MDd.lib" "C:\Program Files\OpenSSL-Win64\lib\VC\libcrypto64MDd.lib" kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib 
<<

# Rule to build all files generated by this target.
CMakeFiles\openSSL_CBC.dir\build: openSSL_CBC.exe
.PHONY : CMakeFiles\openSSL_CBC.dir\build

CMakeFiles\openSSL_CBC.dir\clean:
	$(CMAKE_COMMAND) -P CMakeFiles\openSSL_CBC.dir\cmake_clean.cmake
.PHONY : CMakeFiles\openSSL_CBC.dir\clean

CMakeFiles\openSSL_CBC.dir\depend:
	$(CMAKE_COMMAND) -E cmake_depends "NMake Makefiles" C:\Users\picci\OneDrive\Desktop\crypto_openSSL\openSSL_CBC C:\Users\picci\OneDrive\Desktop\crypto_openSSL\openSSL_CBC C:\Users\picci\OneDrive\Desktop\crypto_openSSL\openSSL_CBC\cmake-build-debug C:\Users\picci\OneDrive\Desktop\crypto_openSSL\openSSL_CBC\cmake-build-debug C:\Users\picci\OneDrive\Desktop\crypto_openSSL\openSSL_CBC\cmake-build-debug\CMakeFiles\openSSL_CBC.dir\DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles\openSSL_CBC.dir\depend

