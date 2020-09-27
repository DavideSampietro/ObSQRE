CC = gcc
CXX = g++

CFLAGS = -Wall $(INC) -march=sandybridge -mrdrnd -mrdseed -mpopcnt -mavx2 -O2
CXXFLAGS = -std=c++11

LDFLAGS = ../../libs/libwolfssl.a -L$(SGX_SDK)/lib64 -lsgx_tcrypto

INCDIR = ../../ ../../includes $(SGX_SDK)/include
INC = $(addprefix -I, $(INCDIR))

FILESRCS = $(wildcard ./*.c*)
FILESRCS += ../misc/obl_string.c
OBJECTS = $(addsuffix .o, $(basename $(FILESRCS)))

TESTSRCS = $(wildcard ./tests/*.c*)
TESTOBJ = $(addsuffix .o, $(basename $(TESTSRCS)))
TEST = $(basename $(TESTSRCS))

BENCHSRCS = $(wildcard ./benchmarks/*.c*)
BENCHOBJ = $(addsuffix .o, $(basename $(BENCHSRCS)))
BENCH = $(basename $(BENCHSRCS))

STATICLIB = ../../libs/libobl.a

.PHONY = static objects all clean benchmarks

all: $(TEST) $(BENCH)
	@cp $(TEST) $(BENCH) ../../

benchmarks: $(BENCH)
	@cp $(BENCH) ../../

static: $(STATICLIB)

# target specific variables
enclave_static: CFLAGS += -DSGX_ENCLAVE_ENABLED -fPIC
enclave_static: $(STATICLIB)

$(STATICLIB): $(OBJECTS)
	@ar rcs $(STATICLIB) $^
	@echo "AR  => $@"

objects: $(OBJECTS)

$(TEST): $(TESTOBJ) $(OBJECTS)
	@$(CXX) $@.o $(OBJECTS) -o $@ $(CFLAGS) $(CXXFLAGS) $(LDFLAGS)
	@echo "LD  => $@"

$(BENCH): $(BENCHOBJ) $(OBJECTS)
	@$(CXX) $@.o $(OBJECTS) -o $@ $(CFLAGS) $(CXXFLAGS) $(LDFLAGS)
	@echo "LD  => $@"

#$(NAME): $(OBJECTS)
#	$(CXX) $^ -o $@ $(CFLAGS) $(CXXFLAGS) $(LDFLAGS)

%.o: %.c
	@$(CC) -c $< -o $@ $(CFLAGS)
	@echo "CC  => $@"

%.o: %.cpp
	@$(CXX) -c $< -o $@ $(CFLAGS) $(CXXFLAGS)
	@echo "CXX => $@"

clean:
	@rm -rfv $(OBJECTS) $(BENCHOBJ) $(TESTOBJ) $(addprefix "../../", $(notdir $(TEST))) $(addprefix "../../", $(notdir $(BENCH))) $(STATICLIB)
	@rm -rfv $(TEST) $(BENCH) 
