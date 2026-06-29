
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(CORECRYPTO_ALLOWED_COMPONENTS cc;ccn;ccmode;ccasn1;ccdigest)
  set(CORECRYPTO_SHARED_COMPONENTS
      cc
      ccaes
      ccasn1
      ccdigest
      ccmode
      ccn
      ccsha1
      )
  set(CORECRYPTO_STATIC_COMPONENTS cc;ccn;ccmode)
  set(CORECRYPTO_MICRO_COMPONENTS
      cc
      ccasn1
      ccdigest
      ccsha1
      )
  message("CoreCrypto: Using Linux configuration for build.")
endif()

set(CORECRYPTO_cc_PUBLIC_HEADERS
    corecrypto/cc_config.h
    corecrypto/cc_error.h
    corecrypto/cc.h
    )

set(CORECRYPTO_cc_SOURCES
    cc_abort.c
    cc_clear.c
    cc_cmp_safe.c
    cc_copy.c
    cc_try_abort.c
    cc_xor.c
    )

set(CORECRYPTO_ccn_PUBLIC_HEADERS
    corecrypto/ccn.h
    )

set(CORECRYPTO_ccn_SOURCES
    )

set(CORECRYPTO_ccmode_PUBLIC_HEADERS
    corecrypto/ccmode.h
    corecrypto/ccmode_impl.h
    )

set(CORECRYPTO_ccmode_SOURCES
    cbc/cccbc_block_size.c
    cbc/cccbc_context_size.c
    cbc/cccbc_init.c
    cbc/cccbc_one_shot.c
    cbc/cccbc_set_iv.c
    cbc/cccbc_update.c
    cbc/ccmode_cbc_decrypt.c
    cbc/ccmode_cbc_encrypt.c
    cbc/ccmode_cbc_init.c
    cbc/ccmode_factory_cbc_decrypt.c
    cbc/ccmode_factory_cbc_encrypt.c
    ecb/ccecb_block_size.c
    ecb/ccecb_context_size.c
    ecb/ccecb_init.c
    ecb/ccecb_one_shot.c
    ecb/ccecb_update.c
    )

set(CORECRYPTO_ccasn1_PUBLIC_HEADERS
    corecrypto/ccasn1.h
    )

set(CORECRYPTO_ccasn1_SOURCES
    ccoid_equal.c
    ccoid_size.c
    )

set(CORECRYPTO_ccdigest_PUBLIC_HEADERS
    corecrypto/ccdigest.h
    )

set(CORECRYPTO_ccdigest_SOURCES
    ccdigest.c
    ccdigest_final.c
    ccdigest_final_64be.c
    ccdigest_final_64le.c
    ccdigest_init.c
    ccdigest_oid_equal.c
    ccdigest_oid_lookup.c
    ccdigest_update.c
    )

set(CORECRYPTO_ccsha1_PUBLIC_HEADERS
    corecrypto/ccsha1.h
    )

set(CORECRYPTO_ccsha1_SOURCES
    ccsha1_di.c
    ccsha1_eay.c
    ccsha1_initial_state.c
    ccsha1_ltc.c
    )

set(CORECRYPTO_ccaes_PUBLIC_HEADERS
    corecrypto/ccaes.h
    )

set(CORECRYPTO_ccaes_SOURCES
    ltc/ccaes_ltc_ecb_decrypt.c
    ltc/ccaes_ltc_ecb_encrypt.c
    ltc/ccaes_ltc_init.c
    ltc/ccaes_ltc_tab.c
    ccaes_ecb_decrypt_mode.c
    ccaes_ecb_encrypt_mode.c
    )
