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

# Include any dependencies generated for this target.
include depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/depend.make

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/progress.make

# Include the compile flags for this target's objects.
include depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/flags.make

depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.o: depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/flags.make
depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.o: ../depends/libsnark/libsnark/common/routing_algorithms/tests/test_routing_algorithms.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.o"
	cd /home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug/depends/libsnark/libsnark && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.o -c /home/reza/development/zkp/libsnark-tutorial-original/depends/libsnark/libsnark/common/routing_algorithms/tests/test_routing_algorithms.cpp

depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.i"
	cd /home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug/depends/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/reza/development/zkp/libsnark-tutorial-original/depends/libsnark/libsnark/common/routing_algorithms/tests/test_routing_algorithms.cpp > CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.i

depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.s"
	cd /home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug/depends/libsnark/libsnark && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/reza/development/zkp/libsnark-tutorial-original/depends/libsnark/libsnark/common/routing_algorithms/tests/test_routing_algorithms.cpp -o CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.s

depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.o.requires:

.PHONY : depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.o.requires

depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.o.provides: depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.o.requires
	$(MAKE) -f depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/build.make depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.o.provides.build
.PHONY : depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.o.provides

depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.o.provides.build: depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.o


# Object files for target common_routing_algorithms_test
common_routing_algorithms_test_OBJECTS = \
"CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.o"

# External object files for target common_routing_algorithms_test
common_routing_algorithms_test_EXTERNAL_OBJECTS =

depends/libsnark/libsnark/common_routing_algorithms_test: depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.o
depends/libsnark/libsnark/common_routing_algorithms_test: depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/build.make
depends/libsnark/libsnark/common_routing_algorithms_test: depends/libsnark/libsnark/libsnark.a
depends/libsnark/libsnark/common_routing_algorithms_test: depends/libsnark/depends/libff/libff/libff.a
depends/libsnark/libsnark/common_routing_algorithms_test: /usr/lib/x86_64-linux-gnu/libgmp.so
depends/libsnark/libsnark/common_routing_algorithms_test: /usr/lib/x86_64-linux-gnu/libgmp.so
depends/libsnark/libsnark/common_routing_algorithms_test: /usr/lib/x86_64-linux-gnu/libgmpxx.so
depends/libsnark/libsnark/common_routing_algorithms_test: depends/libsnark/depends/libzm.a
depends/libsnark/libsnark/common_routing_algorithms_test: depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable common_routing_algorithms_test"
	cd /home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug/depends/libsnark/libsnark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/common_routing_algorithms_test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/build: depends/libsnark/libsnark/common_routing_algorithms_test

.PHONY : depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/build

depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/requires: depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/common/routing_algorithms/tests/test_routing_algorithms.cpp.o.requires

.PHONY : depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/requires

depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/clean:
	cd /home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/common_routing_algorithms_test.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/clean

depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/depend:
	cd /home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/reza/development/zkp/libsnark-tutorial-original /home/reza/development/zkp/libsnark-tutorial-original/depends/libsnark/libsnark /home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug /home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug/depends/libsnark/libsnark /home/reza/development/zkp/libsnark-tutorial-original/cmake-build-debug/depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/libsnark/CMakeFiles/common_routing_algorithms_test.dir/depend
