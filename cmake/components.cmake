
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(CORECRYPTO_ALLOWED_COMPONENTS cc;ccn;ccmode;ccasn1;ccdigest)
  set(CORECRYPTO_SHARED_COMPONENTS
      cc
      ccaes
      ccasn1
      ccchacha20poly1305
      ccdigest
      ccdrbg
      cchmac
      cckprng
      ccmd5
      ccmode
      ccn
      ccpost
      ccrc4
      ccrng
      ccrsa
      ccsha1
      ccsha2
      cczp
      )
  set(CORECRYPTO_STATIC_COMPONENTS cc;ccn;ccmode)
  set(CORECRYPTO_MICRO_COMPONENTS
      cc
      ccasn1
      ccdigest
      ccsha1
      ccsha2
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
    ctr/ccctr_block_size.c
    ctr/ccctr_context_size.c
    ctr/ccctr_init.c
    ctr/ccctr_one_shot.c
    ctr/ccctr_setctr.c
    ctr/ccctr_update.c
    ctr/ccmode_ctr_crypt.c
    ctr/ccmode_ctr_init.c
    ctr/ccmode_ctr_setctr.c
    ctr/ccmode_factory_ctr_crypt.c
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
    gladman/aescrypt.c
    gladman/aeskey.c
    gladman/aestab.c
    gladman/ccaes_gladman_cbc_decrypt.c
    gladman/ccaes_gladman_cbc_encrypt.c
    ltc/ccaes_ltc_ecb_decrypt.c
    ltc/ccaes_ltc_ecb_encrypt.c
    ltc/ccaes_ltc_init.c
    ltc/ccaes_ltc_tab.c
    ccaes_cbc_decrypt_mode.c
    ccaes_cbc_encrypt_mode.c
    ccaes_ctr_crypt_mode.c
    ccaes_ecb_decrypt_mode.c
    ccaes_ecb_encrypt_mode.c
)

set(CORECRYPTO_cchmac_PUBLIC_HEADERS
    corecrypto/cchmac.h
)

set(CORECRYPTO_cchmac_SOURCES
    cchmac.c
    cchmac_final.c
    cchmac_init.c
    cchmac_update.c
)

set(CORECRYPTO_ccdrbg_PUBLIC_HEADERS
    corecrypto/ccdrbg.h
    corecrypto/ccdrbg_impl.h
)

set(CORECRYPTO_ccdrbg_SOURCES
    ccdrbg.c
    ccdrbg_nistctr.c
)

set(CORECRYPTO_ccsha2_PUBLIC_HEADERS
    corecrypto/ccsha2.h
)

set(CORECRYPTO_ccsha2_SOURCES
    ccsha2_selectors.c
    ccsha224_initial_state.c
    ccsha224_ltc_di.c
    ccsha256_K.c
    ccsha256_ltc_compress.c
    ccsha256_initial_state.c
    ccsha256_ltc_di.c
    ccsha512_final.c
    ccsha512_K.c
    ccsha384_initial_state.c
    ccsha384_ltc_di.c
    ccsha512_224_initial_state.c
    ccsha512_224_ltc_di.c
    ccsha512_256_initial_state.c
    ccsha512_256_ltc_di.c
    ccsha512_ltc_compress.c
    ccsha512_initial_state.c
    ccsha512_ltc_di.c
)

set(CORECRYPTO_ccpost_PUBLIC_HEADERS
    corecrypto/ccpost.h
)

set(CORECRYPTO_ccpost_SOURCES
    ccpost_aes_cbc_validate.c
    ccpost_aes_ctr_validate.c
    ccpost_aes_ecb_validate.c
    ccpost_validate.c
)

set(CORECRYPTO_ccmd5_PUBLIC_HEADERS
    corecrypto/ccmd5.h
)

set(CORECRYPTO_ccmd5_SOURCES
    ccmd5_di.c
    ccmd5_ltc.c
)
