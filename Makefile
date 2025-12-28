# Makefile
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

include $(SGX_SDK)/buildenv.mk

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_FLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_FLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_FLAGS += -O0 -g
else
        SGX_COMMON_FLAGS += -O2
endif

App_Cpp_Files := App/App.cpp 
App_Include_Paths := -IApp -I$(SGX_SDK)/include

# 注意：这里加了 -lcrypto 和 -Wno-deprecated-declarations
App_C_Flags := $(SGX_COMMON_FLAGS) -fPIC -Wno-attributes $(App_Include_Paths) -Wno-deprecated-declarations

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_FLAGS) -L$(SGX_LIBRARY_PATH) -lURTS_Library_Name -lpthread -lcrypto

ifneq ($(SGX_MODE), HW)
	App_Link_Flags := $(subst -lURTS_Library_Name,-lsgx_urts_sim,$(App_Link_Flags))
else
	App_Link_Flags := $(subst -lURTS_Library_Name,-lsgx_urts,$(App_Link_Flags))
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

Enclave_Cpp_Files := Enclave/Enclave.cpp
Enclave_Include_Paths := -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

Enclave_C_Flags := $(SGX_COMMON_FLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++

Enclave_Link_Flags := $(SGX_COMMON_FLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -lTRTS_Library_Name -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lService_Library_Name -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections

ifneq ($(SGX_MODE), HW)
	Enclave_Link_Flags := $(subst -lTRTS_Library_Name,-lsgx_trts_sim,$(Enclave_Link_Flags))
	Enclave_Link_Flags := $(subst -lService_Library_Name,-lsgx_tservice_sim,$(Enclave_Link_Flags))
else
	Enclave_Link_Flags := $(subst -lTRTS_Library_Name,-lsgx_trts,$(Enclave_Link_Flags))
	Enclave_Link_Flags := $(subst -lService_Library_Name,-lsgx_tservice,$(Enclave_Link_Flags))
endif

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml

.PHONY: all clean run

all: app $(Signed_Enclave_Name)

run: all
	@./app

App/Enclave_u.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include

App/Enclave_u.o: App/Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@

App/%.o: App/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@

app: App/Enclave_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)

Enclave/Enclave_t.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@

Enclave/%.o: Enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@

$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)

clean:
	@rm -f app enclave.so enclave.signed.so App/*.o App/Enclave_u.* Enclave/*.o Enclave/Enclave_t.*