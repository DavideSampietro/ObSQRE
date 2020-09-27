NAME = s3ref

CC = gcc
CXX = g++

CFLAGS = -Wall $(INCDIR) -O2
CXXFLAGS = -std=c++11

LDFLAGS = -L$(SGX_SDK)/lib64 -lsgx_tcrypto -L../../libs -lwolfssl

INCDIR = -I./include -I$(SGX_SDK)/include -I../../includes

FILESRCS = $(wildcard ./src/*.c*)
FILESRCS += ../../src/misc/obl_string.c
OBJECTS = $(addsuffix .o, $(basename $(FILESRCS)))

all: $(NAME)
	@mv $(NAME) ../../

$(NAME): $(OBJECTS)
	$(CXX) $^ -o $@ $(CFLAGS) $(CXXFLAGS) $(LDFLAGS)

objects: $(OBJECTS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

%.o: %.cpp
	$(CXX) -c $< -o $@ $(CFLAGS) $(CXXFLAGS)

clean:
	@rm -rfv $(OBJECTS) ../../$(NAME)
