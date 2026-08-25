
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

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
endif()
