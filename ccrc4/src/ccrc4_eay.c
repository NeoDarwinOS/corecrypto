/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/* crypto/rc4/rc4.h */
/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <corecrypto/ccrc4.h>

//
// THIS FILE NEEDS A FORMAT. BADLY.
//

typedef uint32_t eay_RC4_INT;

typedef struct rc4_key_st {
    eay_RC4_INT x,y;
    eay_RC4_INT data[256];
} RC4_KEY;

static void eay_RC4_set_key(ccrc4_ctx *skey, size_t keylen, const void *keydata)
    {
        register eay_RC4_INT tmp;
        register int id1,id2;
        register eay_RC4_INT *d;
        unsigned int i;
        size_t len = keylen;
        const unsigned char *data = keydata;
        RC4_KEY *key=(RC4_KEY *)skey;
        
        d= &(key->data[0]);
        key->x = 0;
        key->y = 0;
        id1=id2=0;

#define SK_LOOP(d,n) { \
        tmp=d[(n)]; \
        id2 = (data[id1] + tmp + id2) & 0xff; \
        if (++id1 == len) id1=0; \
        d[(n)]=d[id2]; \
        d[id2]=tmp; }

#if defined(OPENSSL_CPUID_OBJ) && !defined(OPENSSL_NO_ASM)
# if    defined(__i386)   || defined(__i386__)   || defined(_M_IX86) || \
    defined(__INTEL__) || \
    defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64)
    if (sizeof(RC4_INT) > 1) {
        /*
         * Unlike all other x86 [and x86_64] implementations,
         * Intel P4 core [including EM64T] was found to perform
         * poorly with wider RC4_INT. Performance improvement
         * for IA-32 hand-coded assembler turned out to be 2.8x
         * if re-coded for RC4_CHAR! It's however inappropriate
         * to just switch to RC4_CHAR for x86[_64], as non-P4
         * implementations suffer from significant performance
         * losses then, e.g. PIII exhibits >2x deterioration,
         * and so does Opteron. In order to assure optimal
         * all-round performance, let us [try to] detect P4 at
         * run-time by checking upon HTT bit in CPU capability
         * vector and set up compressed key schedule, which is
         * recognized by correspondingly updated assembler
         * module...
         *                <appro@fy.chalmers.se>
         */
        if (OPENSSL_ia32cap_P & (1<<28)) {
            unsigned char *cp=(unsigned char *)d;

            for (i=0;i<256;i++) cp[i]=i;
            for (i=0;i<256;i++) SK_LOOP(cp,i);
            /* mark schedule as compressed! */
            d[256/sizeof(RC4_INT)]=-1;
            return;
        }
    }
# endif
#endif
    for (i=0; i < 256; i++) d[i]=i;
    for (i=0; i < 256; i+=4)
        {
        SK_LOOP(d,i+0);
        SK_LOOP(d,i+1);
        SK_LOOP(d,i+2);
        SK_LOOP(d,i+3);
        }
    }

static void eay_RC4(ccrc4_ctx *skey, size_t len, const void *in, void *out)
{
        register eay_RC4_INT *d;
        register eay_RC4_INT x,y,tx,ty;
        size_t i;
        const unsigned char *indata = in;
        unsigned char *outdata = out;
        RC4_KEY *key = (RC4_KEY *)skey;
        
        x=key->x;
        y=key->y;
        d=key->data;

#if defined(RC4_CHUNK)
    /*
     * The original reason for implementing this(*) was the fact that
     * pre-21164a Alpha CPUs don't have byte load/store instructions
     * and e.g. a byte store has to be done with 64-bit load, shift,
     * and, or and finally 64-bit store. Peaking data and operating
     * at natural word size made it possible to reduce amount of
     * instructions as well as to perform early read-ahead without
     * suffering from RAW (read-after-write) hazard. This resulted
     * in ~40%(**) performance improvement on 21064 box with gcc.
     * But it's not only Alpha users who win here:-) Thanks to the
     * early-n-wide read-ahead this implementation also exhibits
     * >40% speed-up on SPARC and 20-30% on 64-bit MIPS (depending
     * on sizeof(eay_RC4_INT)).
     *
     * (*)    "this" means code which recognizes the case when input
     *    and output pointers appear to be aligned at natural CPU
     *    word boundary
     * (**)    i.e. according to 'apps/openssl speed rc4' benchmark,
     *    crypto/rc4/rc4speed.c exhibits almost 70% speed-up...
     *
     * Cavets.
     *
     * - RC4_CHUNK="unsigned long long" should be a #1 choice for
     *   UltraSPARC. Unfortunately gcc generates very slow code
     *   (2.5-3 times slower than one generated by Sun's WorkShop
     *   C) and therefore gcc (at least 2.95 and earlier) should
     *   always be told that RC4_CHUNK="unsigned long".
     *
     *                    <appro@fy.chalmers.se>
     */

# define RC4_STEP    ( \
            x=(x+1) &0xff,    \
            tx=d[x],    \
            y=(tx+y)&0xff,    \
            ty=d[y],    \
            d[y]=tx,    \
            d[x]=ty,    \
            (RC4_CHUNK)d[(tx+ty)&0xff]\
            )

    if ( ( ((size_t)indata  & (sizeof(RC4_CHUNK)-1)) |
           ((size_t)outdata & (sizeof(RC4_CHUNK)-1)) ) == 0 )
        {
        RC4_CHUNK ichunk,otp;
        const union { long one; char little; } is_endian = {1};

        /*
         * I reckon we can afford to implement both endian
         * cases and to decide which way to take at run-time
         * because the machine code appears to be very compact
         * and redundant 1-2KB is perfectly tolerable (i.e.
         * in case the compiler fails to eliminate it:-). By
         * suggestion from Terrel Larson <terr@terralogic.net>
         * who also stands for the is_endian union:-)
         *
         * Special notes.
         *
         * - is_endian is declared automatic as doing otherwise
         *   (declaring static) prevents gcc from eliminating
         *   the redundant code;
         * - compilers (those I've tried) don't seem to have
         *   problems eliminating either the operators guarded
         *   by "if (sizeof(RC4_CHUNK)==8)" or the condition
         *   expressions themselves so I've got 'em to replace
         *   corresponding #ifdefs from the previous version;
         * - I chose to let the redundant switch cases when
         *   sizeof(RC4_CHUNK)!=8 be (were also #ifdefed
         *   before);
         * - in case you wonder "&(sizeof(RC4_CHUNK)*8-1)" in
         *   [LB]ESHFT guards against "shift is out of range"
         *   warnings when sizeof(RC4_CHUNK)!=8
         *
         *            <appro@fy.chalmers.se>
         */
        if (!is_endian.little)
            {    /* BIG-ENDIAN CASE */
# define BESHFT(c)    (((sizeof(RC4_CHUNK)-(c)-1)*8)&(sizeof(RC4_CHUNK)*8-1))
            for (;len&-sizeof(RC4_CHUNK);len-=sizeof(RC4_CHUNK))
                {
                ichunk  = *(RC4_CHUNK *)indata;
                otp  = RC4_STEP<<BESHFT(0);
                otp |= RC4_STEP<<BESHFT(1);
                otp |= RC4_STEP<<BESHFT(2);
                otp |= RC4_STEP<<BESHFT(3);
                if (sizeof(RC4_CHUNK)==8)
                    {
                    otp |= RC4_STEP<<BESHFT(4);
                    otp |= RC4_STEP<<BESHFT(5);
                    otp |= RC4_STEP<<BESHFT(6);
                    otp |= RC4_STEP<<BESHFT(7);
                    }
                *(RC4_CHUNK *)outdata = otp^ichunk;
                indata  += sizeof(RC4_CHUNK);
                outdata += sizeof(RC4_CHUNK);
                }
            if (len)
                {
                RC4_CHUNK mask=(RC4_CHUNK)-1, ochunk;

                ichunk = *(RC4_CHUNK *)indata;
                ochunk = *(RC4_CHUNK *)outdata;
                otp = 0;
                i = BESHFT(0);
                mask <<= (sizeof(RC4_CHUNK)-len)<<3;
                switch (len&(sizeof(RC4_CHUNK)-1))
                    {
                    case 7:    otp  = RC4_STEP<<i, i-=8;
                    case 6:    otp |= RC4_STEP<<i, i-=8;
                    case 5:    otp |= RC4_STEP<<i, i-=8;
                    case 4:    otp |= RC4_STEP<<i, i-=8;
                    case 3:    otp |= RC4_STEP<<i, i-=8;
                    case 2:    otp |= RC4_STEP<<i, i-=8;
                    case 1:    otp |= RC4_STEP<<i, i-=8;
                    case 0: ; /*
                           * it's never the case,
                           * but it has to be here
                           * for ultrix?
                           */
                    }
                ochunk &= ~mask;
                ochunk |= (otp^ichunk) & mask;
                *(RC4_CHUNK *)outdata = ochunk;
                }
            key->x=x;
            key->y=y;
            return;
            }
        else
            {    /* LITTLE-ENDIAN CASE */
# define LESHFT(c)    (((c)*8)&(sizeof(RC4_CHUNK)*8-1))
            for (;len&-sizeof(RC4_CHUNK);len-=sizeof(RC4_CHUNK))
                {
                ichunk  = *(RC4_CHUNK *)indata;
                otp  = RC4_STEP;
                otp |= RC4_STEP<<8;
                otp |= RC4_STEP<<16;
                otp |= RC4_STEP<<24;
                if (sizeof(RC4_CHUNK)==8)
                    {
                    otp |= RC4_STEP<<LESHFT(4);
                    otp |= RC4_STEP<<LESHFT(5);
                    otp |= RC4_STEP<<LESHFT(6);
                    otp |= RC4_STEP<<LESHFT(7);
                    }
                *(RC4_CHUNK *)outdata = otp^ichunk;
                indata  += sizeof(RC4_CHUNK);
                outdata += sizeof(RC4_CHUNK);
                }
            if (len)
                {
                RC4_CHUNK mask=(RC4_CHUNK)-1, ochunk;

                ichunk = *(RC4_CHUNK *)indata;
                ochunk = *(RC4_CHUNK *)outdata;
                otp = 0;
                i   = 0;
                mask >>= (sizeof(RC4_CHUNK)-len)<<3;
                switch (len&(sizeof(RC4_CHUNK)-1))
                    {
                    case 7:    otp  = RC4_STEP,    i+=8;
                    case 6:    otp |= RC4_STEP<<i, i+=8;
                    case 5:    otp |= RC4_STEP<<i, i+=8;
                    case 4:    otp |= RC4_STEP<<i, i+=8;
                    case 3:    otp |= RC4_STEP<<i, i+=8;
                    case 2:    otp |= RC4_STEP<<i, i+=8;
                    case 1:    otp |= RC4_STEP<<i, i+=8;
                    case 0: ; /*
                           * it's never the case,
                           * but it has to be here
                           * for ultrix?
                           */
                    }
                ochunk &= ~mask;
                ochunk |= (otp^ichunk) & mask;
                *(RC4_CHUNK *)outdata = ochunk;
                }
            key->x=x;
            key->y=y;
            return;
            }
        }
#endif
#define LOOP(in,out) \
        x=((x+1)&0xff); \
        tx=d[x]; \
        y=(tx+y)&0xff; \
        d[x]=ty=d[y]; \
        d[y]=tx; \
        (out) = d[(tx+ty)&0xff]^ (in);

#ifndef RC4_INDEX
#define RC4_LOOP(a,b,i)    LOOP(*((a)++),*((b)++))
#else
#define RC4_LOOP(a,b,i)    LOOP(a[i],b[i])
#endif

    i=len>>3;
    if (i)
        {
        for (;;)
            {
            RC4_LOOP(indata,outdata,0);
            RC4_LOOP(indata,outdata,1);
            RC4_LOOP(indata,outdata,2);
            RC4_LOOP(indata,outdata,3);
            RC4_LOOP(indata,outdata,4);
            RC4_LOOP(indata,outdata,5);
            RC4_LOOP(indata,outdata,6);
            RC4_LOOP(indata,outdata,7);
#ifdef RC4_INDEX
            indata+=8;
            outdata+=8;
#endif
            if (--i == 0) break;
            }
        }
    i=len&0x07;
    if (i)
        {
        for (;;)
            {
            RC4_LOOP(indata,outdata,0); if (--i == 0) break;
            RC4_LOOP(indata,outdata,1); if (--i == 0) break;
            RC4_LOOP(indata,outdata,2); if (--i == 0) break;
            RC4_LOOP(indata,outdata,3); if (--i == 0) break;
            RC4_LOOP(indata,outdata,4); if (--i == 0) break;
            RC4_LOOP(indata,outdata,5); if (--i == 0) break;
            RC4_LOOP(indata,outdata,6); if (--i == 0) break;
            }
        }
    key->x=x;
    key->y=y;
    }

const struct ccrc4_info ccrc4_eay = {
    .size = sizeof(RC4_KEY),
    .init = &eay_RC4_set_key,
    .crypt = &eay_RC4
};
