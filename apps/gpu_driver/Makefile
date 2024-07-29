PROGS = libzphook_basic.so

CXX = g++

CLEANFILES = $(PROGS) *.o *.d

SRCDIR ?= ./

NO_MAN=
CXXFLAGS = -O3 -pipe -std=c++2a -g
CXXFLAGS += -Werror -Wall -Wno-unused-function
CXXFLAGS += -Wextra
CXXFLAGS += -shared -fPIC

C_SRCS = main.cpp
OBJS = $(C_SRCS:.cpp=.o)

.PHONY: all
all: $(PROGS)

$(PROGS): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)
