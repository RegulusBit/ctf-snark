# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.9

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/reza/CLion/clion-2017.3.3/bin/cmake/bin/cmake

# The command to remove a file.
RM = /home/reza/CLion/clion-2017.3.3/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/reza/development/zkp/libsnark-tutorial-original

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug

# Utility rule file for ContinuousUpdate.

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/ContinuousUpdate.dir/progress.make

depends/libsnark/libsnark/CMakeFiles/ContinuousUpdate:
	cd /home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug/depends/libsnark/libsnark && /home/reza/CLion/clion-2017.3.3/bin/cmake/bin/ctest -D ContinuousUpdate

ContinuousUpdate: depends/libsnark/libsnark/CMakeFiles/ContinuousUpdate
ContinuousUpdate: depends/libsnark/libsnark/CMakeFiles/ContinuousUpdate.dir/build.make

.PHONY : ContinuousUpdate

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/ContinuousUpdate.dir/build: ContinuousUpdate

.PHONY : depends/libsnark/libsnark/CMakeFiles/ContinuousUpdate.dir/build

depends/libsnark/libsnark/CMakeFiles/ContinuousUpdate.dir/clean:
	cd /home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/ContinuousUpdate.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/ContinuousUpdate.dir/clean

depends/libsnark/libsnark/CMakeFiles/ContinuousUpdate.dir/depend:
	cd /home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/reza/development/zkp/libsnark-tutorial-original /home/reza/development/zkp/libsnark-tutorial-original/depends/libsnark/libsnark /home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug /home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug/depends/libsnark/libsnark /home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug/depends/libsnark/libsnark/CMakeFiles/ContinuousUpdate.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/libsnark/CMakeFiles/ContinuousUpdate.dir/depend

