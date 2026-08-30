#  corecrypto

Welcome to the NeoDarwin `corecrypto` project. This is the home for an open-source and free (as in beer) implementation/alternative to the Apple library used across their many platforms.

## Disclaimers

This project, is in no part, derived from any Apple source code that pertains to the actual functioning of the library. All code in the form of `.c` files have been cleanly implemented, with no code copy-pasted from Apple's own source code.

Any APIs referenced or re-implemented by this project, [have been written through analysis of header files](https://en.wikipedia.org/wiki/Google_LLC_v._Oracle_America,_Inc.#Decision) and have been written to serve interoperability with any binaries or client applications that make use of the corecrypto API.

## Getting Started

`corecrypto` aims to eventually be the backbone for all of modern Darwin's needs, and therefore, aims to be compatible with as low as macOS 10.15 Catalina, to macOS 26.6 Tahoe.

> [!NOTE]
> No. This does not mean use it as a system library or kernel extension on a real copy of macOS. Do not file an issue if it's broken on a real macOS installation.

Any older, and there would need to be major works done in the Kernel PRNG to ensure compatibility with macOS 10.13 High Sierra and 10.14 Mojave.

To build `corecrypto` natively, you can either use the provided CMake, or alternatively, use the included Xcode project.

The Xcode project covers select targets, such as:
- `corecrypto.kext`
- `libcorecrypto.dylib`
- `libcorecrypto.a`
- `cc_boot_post`

As of writing, the kernel extension does not build under CMake.

> [!CAUTION]
> The kernel extension uses the CFBundleIdentifier `dev.neodarwin.kec.corecrypto`
>
> For reasons that many Darwin developers will know, this will obviously cause a stock kernel to panic.
>
> You will have to whitelist the `dev.neodarwin` prefix for KEC use.

> [!WARNING]
> For arm64, SDK modification may be required (running installhdrs from XNU) to build the kernel extension properly. 
> This will depend on your target OS, and your SDK.

In all, this project will install the following to the destination:
- `/usr/libexec/cc_boot_post`
- `/usr/local/lib/libcorecrypto.a`
- `/usr/lib/system/libcorecrypto.dylib`
- `/System/Library/Extensions/corecrypto.kext`

## Contributing

Contributions are welcome! All contributions, however, including new files, are expected to be licensed under the Mozilla Public License 2.0, as is common with the rest of the project's self-written code. This project is meant to faciliate free and open source Darwin, and to do so, we need to maintain the weak copyleft nature of the project.

As is standard with the NeoDarwin policy, this project does not welcome AI-generated code, and is highly discouraged especially more so since Apple has released their source code to GitHub under their Internal Use Only license. We want to avoid any legal trouble here.

## Acknowledgements

In several areas of the codebase, pre-existing implementations of the cryptographic primitives have been used to mirror Apple's `corecrypto`, and to assist development.

The license terms can be viewed at the beginning of each file respectively.

The following files make use of code from an earlier revision of LibTomCrypt:
- ccaes_ltc_ecb_decrypt.c
- ccaes_ltc_ecb_encrypt.c
- ccaes_ltc_init.c
- ccaes_ltc_tab.c
- ccdes_ltc_common.c
- ltc_des_common.c
- ccmd2_ltc.c
- ccmd4_ltc.c
- ccmd5_ltc.c
- ccsha1_ltc.c
- ccsha224_initial_state.c
- ccsha256_initial_state.c
- ccsha256_K.c
- ccsha256_ltc_compress.c
- ccsha384_initial_state.c
- ccsha512_initial_state.c
- ccsha512_K.c
- ccsha512_ltc_compress.c

The following files make use of code by Brian Gladman:
- aescrypt.c
- aeskey.c
- aestab.c
    
The following files make use of code by Eric Young:
- ccsha1_eay.c
