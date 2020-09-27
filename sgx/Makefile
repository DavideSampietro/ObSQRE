#
# Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

CC=$(shell find /usr/bin -name gcc* | grep gcc-[0-9] | sort -r | head -1)
CXX=$(shell find /usr/bin -name g++* | grep g++-[0-9] | sort -r | head -1)

######## Modify these variables in order to build your project ########

App_Folder := ./host
App_Name := subtol_srv
App_Sources := $(wildcard ./host/src/*.c*) $(wildcard ./host/src/*/*.c*)
App_Include_Paths := -I./host/include -I../includes -I../includes/asio
App_Link_Flags :=

Enclave_Folder := ./trusted
Enclave_Basename := subtol
Enclave_Sources := $(wildcard ./trusted/src/*.c*) $(wildcard ./trusted/*/*.c*) $(wildcard ./trusted/src/*/*.c*)
Enclave_Include_Paths := -I./trusted/include -I../ -I../includes
Enclave_Link_Flags := -L../libs -lobl -lwolfssl
Enclave_Name := $(addsuffix .so, $(Enclave_Basename))

######## SGX SDK Settings ########

SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0
SGX_PRERELEASE ?= 1

ifndef SGX_SDK
$(error Please run "source [SGX_INSTALL_PATH]/sgxsdk/environment" to compile)
endif

SGX_COMMON_FLAGS := -m64 -march=sandybridge -mrdrnd -mrdseed
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
SGX_COMMON_FLAGS += -O0 -g
else
SGX_COMMON_FLAGS += -O2
endif

# disabled -Wconversion to kill the warnings from asio
SGX_COMMON_FLAGS +=	-Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
							-Waddress -Wsequence-point -Wformat-security \
							-Wmissing-include-dirs -Wundef -Wfloat-equal \
							-Wcast-align -Wcast-qual -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
# added ASIO_STANDALONE and BOOST_VERSION=0 to use standalone asio lib and turn off compiler
# warnings -Wundef
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11 -DASIO_STANDALONE -DBOOST_VERSION=0 -DRAPIDJSON_HAS_STDSTRING

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Include_Paths += -I$(App_Folder)
App_Include_Paths += -I$(SGX_SDK)/include

App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags)
App_Link_Flags += -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lsgx_ukey_exchange -lpthread

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Objects := $(addsuffix .o, $(basename $(App_Sources)))

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Crypto_Library_Name := sgx_tcrypto

Enclave_Include_Paths += -I$(Enclave_Folder)
Enclave_Include_Paths += -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector-strong
Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++

Enclave_Link_Flags += -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,--version-script=$(Enclave_Folder)/$(Enclave_Basename).lds

Enclave_Objects := $(addsuffix .o, $(basename $(Enclave_Sources)))

Signed_Enclave_Name := $(addsuffix .signed.so, $(Enclave_Basename))
Enclave_Config_File := $(Enclave_Folder)/$(addsuffix .config.xml, $(Enclave_Basename))

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif

.PHONY: all target run
all: .config_$(Build_Mode)_$(SGX_ARCH)
	@$(MAKE) target

ifeq ($(Build_Mode), HW_RELEASE)
target:  $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."


else
target: $(App_Name) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif

endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Objects) $(App_Folder)/$(Enclave_Basename)_u.* $(Enclave_Objects) $(Enclave_Folder)/$(Enclave_Basename)_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)

######## App Objects ########

$(App_Folder)/$(Enclave_Basename)_u.h: $(SGX_EDGER8R) $(Enclave_Folder)/$(Enclave_Basename).edl
	@cd $(App_Folder) && $(SGX_EDGER8R) --untrusted ../$(Enclave_Folder)/$(Enclave_Basename).edl --search-path ../$(Enclave_Folder) --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(App_Folder)/$(Enclave_Basename)_u.c: $(App_Folder)/$(Enclave_Basename)_u.h

$(App_Folder)/$(Enclave_Basename)_u.o: $(App_Folder)/$(Enclave_Basename)_u.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(App_Folder)/%.o: $(App_Folder)/%.cpp  $(App_Folder)/$(Enclave_Basename)_u.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): $(App_Folder)/$(Enclave_Basename)_u.o $(App_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########

$(Enclave_Folder)/$(Enclave_Basename)_t.h: $(SGX_EDGER8R) $(Enclave_Folder)/$(Enclave_Basename).edl
	@cd $(Enclave_Folder) && $(SGX_EDGER8R) --trusted ../$(Enclave_Folder)/$(Enclave_Basename).edl --search-path ../$(Enclave_Folder) --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(Enclave_Folder)/$(Enclave_Basename)_t.c: $(Enclave_Folder)/$(Enclave_Basename)_t.h

$(Enclave_Folder)/$(Enclave_Basename)_t.o: $(Enclave_Folder)/$(Enclave_Basename)_t.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Enclave_Folder)/%.o: $(Enclave_Folder)/%.cpp $(Enclave_Folder)/$(Enclave_Basename)_t.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Folder)/%.o: $(Enclave_Folder)/%.c $(Enclave_Folder)/$(Enclave_Basename)_t.h
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(Enclave_Name): $(Enclave_Folder)/$(Enclave_Basename)_t.o $(Enclave_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Folder)/$(Enclave_Basename)_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Objects) $(App_Folder)/$(Enclave_Basename)_u.* $(Enclave_Objects) $(Enclave_Folder)/$(Enclave_Basename)_t.*
