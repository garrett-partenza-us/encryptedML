# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.26

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

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

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /opt/homebrew/Cellar/cmake/3.26.4/bin/cmake

# The command to remove a file.
RM = /opt/homebrew/Cellar/cmake/3.26.4/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/garrett.partenza/Desktop/Homo/seal

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/garrett.partenza/Desktop/Homo/seal/build

# Include any dependencies generated for this target.
include CMakeFiles/MyProject.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/MyProject.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/MyProject.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/MyProject.dir/flags.make

CMakeFiles/MyProject.dir/src/example.cpp.o: CMakeFiles/MyProject.dir/flags.make
CMakeFiles/MyProject.dir/src/example.cpp.o: /Users/garrett.partenza/Desktop/Homo/seal/src/example.cpp
CMakeFiles/MyProject.dir/src/example.cpp.o: CMakeFiles/MyProject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/garrett.partenza/Desktop/Homo/seal/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/MyProject.dir/src/example.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/MyProject.dir/src/example.cpp.o -MF CMakeFiles/MyProject.dir/src/example.cpp.o.d -o CMakeFiles/MyProject.dir/src/example.cpp.o -c /Users/garrett.partenza/Desktop/Homo/seal/src/example.cpp

CMakeFiles/MyProject.dir/src/example.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/MyProject.dir/src/example.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/garrett.partenza/Desktop/Homo/seal/src/example.cpp > CMakeFiles/MyProject.dir/src/example.cpp.i

CMakeFiles/MyProject.dir/src/example.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/MyProject.dir/src/example.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/garrett.partenza/Desktop/Homo/seal/src/example.cpp -o CMakeFiles/MyProject.dir/src/example.cpp.s

CMakeFiles/MyProject.dir/src/interface.cpp.o: CMakeFiles/MyProject.dir/flags.make
CMakeFiles/MyProject.dir/src/interface.cpp.o: /Users/garrett.partenza/Desktop/Homo/seal/src/interface.cpp
CMakeFiles/MyProject.dir/src/interface.cpp.o: CMakeFiles/MyProject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/garrett.partenza/Desktop/Homo/seal/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/MyProject.dir/src/interface.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/MyProject.dir/src/interface.cpp.o -MF CMakeFiles/MyProject.dir/src/interface.cpp.o.d -o CMakeFiles/MyProject.dir/src/interface.cpp.o -c /Users/garrett.partenza/Desktop/Homo/seal/src/interface.cpp

CMakeFiles/MyProject.dir/src/interface.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/MyProject.dir/src/interface.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/garrett.partenza/Desktop/Homo/seal/src/interface.cpp > CMakeFiles/MyProject.dir/src/interface.cpp.i

CMakeFiles/MyProject.dir/src/interface.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/MyProject.dir/src/interface.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/garrett.partenza/Desktop/Homo/seal/src/interface.cpp -o CMakeFiles/MyProject.dir/src/interface.cpp.s

CMakeFiles/MyProject.dir/src/linear_regression.cpp.o: CMakeFiles/MyProject.dir/flags.make
CMakeFiles/MyProject.dir/src/linear_regression.cpp.o: /Users/garrett.partenza/Desktop/Homo/seal/src/linear_regression.cpp
CMakeFiles/MyProject.dir/src/linear_regression.cpp.o: CMakeFiles/MyProject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/garrett.partenza/Desktop/Homo/seal/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/MyProject.dir/src/linear_regression.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/MyProject.dir/src/linear_regression.cpp.o -MF CMakeFiles/MyProject.dir/src/linear_regression.cpp.o.d -o CMakeFiles/MyProject.dir/src/linear_regression.cpp.o -c /Users/garrett.partenza/Desktop/Homo/seal/src/linear_regression.cpp

CMakeFiles/MyProject.dir/src/linear_regression.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/MyProject.dir/src/linear_regression.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/garrett.partenza/Desktop/Homo/seal/src/linear_regression.cpp > CMakeFiles/MyProject.dir/src/linear_regression.cpp.i

CMakeFiles/MyProject.dir/src/linear_regression.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/MyProject.dir/src/linear_regression.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/garrett.partenza/Desktop/Homo/seal/src/linear_regression.cpp -o CMakeFiles/MyProject.dir/src/linear_regression.cpp.s

CMakeFiles/MyProject.dir/src/main.cpp.o: CMakeFiles/MyProject.dir/flags.make
CMakeFiles/MyProject.dir/src/main.cpp.o: /Users/garrett.partenza/Desktop/Homo/seal/src/main.cpp
CMakeFiles/MyProject.dir/src/main.cpp.o: CMakeFiles/MyProject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/garrett.partenza/Desktop/Homo/seal/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/MyProject.dir/src/main.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/MyProject.dir/src/main.cpp.o -MF CMakeFiles/MyProject.dir/src/main.cpp.o.d -o CMakeFiles/MyProject.dir/src/main.cpp.o -c /Users/garrett.partenza/Desktop/Homo/seal/src/main.cpp

CMakeFiles/MyProject.dir/src/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/MyProject.dir/src/main.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/garrett.partenza/Desktop/Homo/seal/src/main.cpp > CMakeFiles/MyProject.dir/src/main.cpp.i

CMakeFiles/MyProject.dir/src/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/MyProject.dir/src/main.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/garrett.partenza/Desktop/Homo/seal/src/main.cpp -o CMakeFiles/MyProject.dir/src/main.cpp.s

# Object files for target MyProject
MyProject_OBJECTS = \
"CMakeFiles/MyProject.dir/src/example.cpp.o" \
"CMakeFiles/MyProject.dir/src/interface.cpp.o" \
"CMakeFiles/MyProject.dir/src/linear_regression.cpp.o" \
"CMakeFiles/MyProject.dir/src/main.cpp.o"

# External object files for target MyProject
MyProject_EXTERNAL_OBJECTS =

bin/MyProject: CMakeFiles/MyProject.dir/src/example.cpp.o
bin/MyProject: CMakeFiles/MyProject.dir/src/interface.cpp.o
bin/MyProject: CMakeFiles/MyProject.dir/src/linear_regression.cpp.o
bin/MyProject: CMakeFiles/MyProject.dir/src/main.cpp.o
bin/MyProject: CMakeFiles/MyProject.dir/build.make
bin/MyProject: CMakeFiles/MyProject.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/garrett.partenza/Desktop/Homo/seal/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking CXX executable bin/MyProject"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/MyProject.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/MyProject.dir/build: bin/MyProject
.PHONY : CMakeFiles/MyProject.dir/build

CMakeFiles/MyProject.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/MyProject.dir/cmake_clean.cmake
.PHONY : CMakeFiles/MyProject.dir/clean

CMakeFiles/MyProject.dir/depend:
	cd /Users/garrett.partenza/Desktop/Homo/seal/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/garrett.partenza/Desktop/Homo/seal /Users/garrett.partenza/Desktop/Homo/seal /Users/garrett.partenza/Desktop/Homo/seal/build /Users/garrett.partenza/Desktop/Homo/seal/build /Users/garrett.partenza/Desktop/Homo/seal/build/CMakeFiles/MyProject.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/MyProject.dir/depend

