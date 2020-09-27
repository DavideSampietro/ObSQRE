# Compilation of wolfCrypt for Intel SGX

Since **wolfCrypt** is rich with features, you may want to prune the ones that are not needed.
The result will be a lightweight ar-file containing:

- AES-CTR and AES-GCM
- several SHA-x
- PBKDF2

More algorithms and functionalities may be plugged-in by modifying the configuration script. To get a comprehensive list
of features, run `./configure --help` in the cloned repository and change `wolfssl-configure.sh` accordingly.

On x86-64, wolfCrypt uses the `CPUID` instruction to infer the instruction set extensions supported by the current platform.
Since such instruction is illegal in SGXv1, causing `SIGILL`, it is necessary to specify by hand the flags that will be
set.
Please modify `wolfcrypt/src/cpuid.c` by commenting out the unsupported flags in the function
```c
void cpuid_set_flags(void)
```
The list of the features supported by your platform may be retrieved via the command `cat /proc/cpuinfo`.

To compile wolfCrypt for **ObSQRE**, perform the following steps:

1. `git clone https://github.com/wolfSSL/wolfssl.git` and `cd` to it
2. Checkout the correct WolfSSL commit: `git checkout 0694eafb5ed78403e4aabf7b3bd9db522313609c`
3. Copy `wolfssl-configure.sh` and `wolfcrypt_sgx.patch` from the current directory to wolfssl
4. Run `./autogen.sh`
5. Configure the library via `./wolfssl-configure.sh`
6. Apply the patch via `git am < wolfcrypt_sgx.patch`
7. `make`
8. Copy the generated ar-file into subtol folder: `cp src/.libs/libwolfssl.a <ObSQRE-folder>/libs`
