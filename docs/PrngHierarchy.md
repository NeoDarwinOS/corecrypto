# How does the PRNG in userspace and kernelspace work?

## corecrypto_kext's contribution

Within xnu, there are two registration interfaces for corecrypto:
- register_crypto_functions
- register_and_init_prng

As of Darwin 19, it is up to corecrypto to pass a buffer to XNU which is of the PRNG's state.

register_and_init_prng is the interface which establishes /dev/urandom, which acts as the global entropy source for all userspace ccrng instances, and the kernel corecrypto's own ccrng.

The KPRNG, is fed data by an entropy buffer managed by the kernel, which is populated by 'samples', which are derived from timing jitter.

On x86, this is a timestamp from the TSC counter, collected after `interrupt()` (see osfmk/i386/trap.c) has finished running. On ARM, the same interrupt based collection is used, however the source of entropy is from a call to `ml_get_timebase`.

This jitter is then used by the KPRNG to reseed itself when required.

## ccrng

ccrng is backed by a CTR_CRBG (see SP800-90A) construction, backed by AES and using a 256-bit key
