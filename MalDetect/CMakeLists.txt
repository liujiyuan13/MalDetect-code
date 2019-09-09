cmake_minimum_required(VERSION 3.12)
project(MalDetect)

set(CMAKE_CXX_STANDARD 14)

link_libraries(pcap crypto)

add_executable(MalDetect_cpp MalDetect.cpp MalDetect.h
        src/traffic.h src/traffic.cpp src/values.h
        src/onlinerf.h src/onlinerf.cpp
        src/classifier.h src/classifier.cpp
        src/data.h src/data.cpp
        src/hyperparameters.h src/hyperparameters.cpp
        src/onlinetree.h src/onlinetree.cpp
        src/utilities.h src/utilities.cpp
        src/onlinenode.h src/onlinenode.cpp
        src/randomtest.h src/randomtest.cpp)