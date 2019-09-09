cmake_minimum_required(VERSION 3.12)
project(PcapEditor)

set(CMAKE_CXX_STANDARD 14)

link_libraries(pcap)

add_executable(PcapEditor PcapEditor.cpp PcapEditor.h)
