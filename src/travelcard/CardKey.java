/*
  JavaCard implementation of Travel Card specification MTS7

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

package travelcard;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.*;
import javacardx.crypto.*;

public final class CardKey {

    protected final byte[] certificate;
    protected short certificate_length;

    protected final byte[] attributes;
    protected byte attributes_length;

    private KeyPair keys;

    private final Cipher cipher_rsa_pkcs1;

    protected CardKey() {

        cipher_rsa_pkcs1 = Cipher.getInstance(Cipher.CIPHER_RSA, Cipher.PAD_PKCS1, false);

        certificate = new byte[Constants.cardholderCertificateMaxLength()];
        certificate_length = 0;

        attributes = new byte[Constants.ALGORITHM_ATTRIBUTES_MAX_LENGTH];
        attributes_length = 0;

        reset(true);
    }

    private final void resetKeys(final boolean isRegistering) {
        if(keys != null) {
            keys.getPrivate().clearKey();
            keys.getPublic().clearKey();
            keys = null;
        }

        if(certificate_length > 0) {
            certificate_length = (short)0;
            Util.arrayFillNonAtomic(certificate, (short)0, certificate_length, (byte)0);
        }

    }

    protected final void reset(final boolean isRegistering) {
        resetKeys(isRegistering);

        Common.beginTransaction(isRegistering);
        if(attributes_length > 0) {
            Util.arrayFillNonAtomic(attributes, (short)0, attributes_length, (byte)0);
            attributes_length = (byte)0;
        }

            Util.arrayCopyNonAtomic(Constants.ALGORITHM_ATTRIBUTES_DEFAULT, (short)0,
                                    attributes, (short)0,
                                    (short)Constants.ALGORITHM_ATTRIBUTES_DEFAULT.length);
            attributes_length = (byte)Constants.ALGORITHM_ATTRIBUTES_DEFAULT.length;

        Common.commitTransaction(isRegistering);
    }

    protected final boolean isInitialized() {
        return (keys != null) && keys.getPrivate().isInitialized() && keys.getPublic().isInitialized();
    }

    protected final void setCertificate(final byte[] buf, final short off, final short len) {
        if((len < 0) ||
           (len > Constants.cardholderCertificateMaxLength())) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }

        JCSystem.beginTransaction();
        if(certificate_length > 0) {
            Util.arrayFillNonAtomic(certificate, (short)0, certificate_length, (byte)0);
        }
        Util.arrayCopyNonAtomic(buf, off, certificate, (short)0, len);
        certificate_length = len;
        JCSystem.commitTransaction();
    }

    protected final void setAttributes(final ECCurves ec,
                                       final byte[] buf, final short off, final short len) {
        if((len < Constants.ALGORITHM_ATTRIBUTES_MIN_LENGTH) ||
           (len > Constants.ALGORITHM_ATTRIBUTES_MAX_LENGTH)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }

        switch(buf[off]) {
        case 0x01:
            if((Util.getShort(buf, (short)(off + 1)) < 2048) ||
               (Util.getShort(buf, (short)(off + 3)) != 0x11) ||
               (buf[(short)(off + 5)] < 0) || (buf[(short)(off + 5)] > 3)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
            break;

        case 0x12:
        case 0x13:
            if(len < 2) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
            final byte delta = (buf[(short)(len - 1)] == (byte)0xff) ? (byte)1 : (byte)0;
            final ECParams params = ec.findByOid(buf, (short)(off + 1), (byte)(len - 1 - delta));
            if(params == null) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
            break;

        default:
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        resetKeys(false);

        JCSystem.beginTransaction();
        if(attributes_length > 0) {
            Util.arrayFillNonAtomic(attributes, (short)0, attributes_length, (byte)0);
        }
        Util.arrayCopyNonAtomic(buf, off, attributes, (short)0, len);
        attributes_length = (byte)len;
        JCSystem.commitTransaction();
    }


    protected final boolean isRsa() {
        return (attributes[0] == 1);
    }

    protected final short rsaModulusBitSize() {
        return Util.getShort(attributes, (short)1);
    }

    protected final short rsaExponentBitSize() {
        return Util.getShort(attributes, (short)3);
    }

    protected final boolean isEc() {
        return ((attributes[0] == (byte)0x12) ||
                (attributes[0] == (byte)0x13));
    }

    protected final ECParams ecParams(final ECCurves ec) {
        final byte delta = (attributes[(short)(attributes_length - 1)] == (byte)0xff) ? (byte)1 : (byte)0;
        return ec.findByOid(attributes, (short)1, (byte)(attributes_length - 1 - delta));
    }


    private final KeyPair generateRSA() {
        final PrivateKey priv = (PrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, rsaModulusBitSize(), false);
        final RSAPublicKey pub = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, rsaModulusBitSize(), false);

        if((priv == null) || (pub == null)) {
            return null;
        }

        pub.setExponent(Constants.RSA_EXPONENT, (short)0, (byte)Constants.RSA_EXPONENT.length);

        return new KeyPair(pub, priv);
    }


    private final KeyPair generateEC(final ECCurves ec) {

        final ECParams params = ecParams(ec);

        final ECPrivateKey priv = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, params.nb_bits, false);
        final ECPublicKey pub = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, params.nb_bits, false);

        if((priv == null) || (pub == null)) {
            return null;
        }

        params.setParams(priv);
        params.setParams(pub);

        return new KeyPair(pub, priv);
    }


    protected final void generate(final ECCurves ec) {

        KeyPair nkeys = null;

        if(isRsa()) {
            nkeys = generateRSA();
        } else if(isEc()) {
            nkeys = generateEC(ec);
        }

        if(nkeys == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        nkeys.genKeyPair();

        if(!nkeys.getPublic().isInitialized() || !nkeys.getPrivate().isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        resetKeys(false);

        keys = nkeys;
    }

    protected final short writePublicKeyDo(final byte[] buf, short off) {

        if(!isInitialized()) {
            ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
            return 0;
        }

        final PublicKey pub = keys.getPublic();

        off = Util.setShort(buf, off, (short)0x7f49);

        if(isRsa()) {

            final RSAPublicKey rsapub = (RSAPublicKey)pub;
            final short modulus_size = Common.bitsToBytes(rsaModulusBitSize());
            final short exponent_size = Common.bitsToBytes(rsaExponentBitSize());

            final short mlensize = (short)((modulus_size > (short)0xff) ? 3 : 2);

            final short flen =
                (short)(1 + mlensize + modulus_size +
                        1 + 1 + exponent_size);

            off = Common.writeLength(buf, off, flen);

            buf[off++] = (byte)0x81;
            off = Common.writeLength(buf, off, modulus_size);
            off += rsapub.getModulus(buf, off);

            buf[off++] = (byte)0x82;
            off = Common.writeLength(buf, off, exponent_size);
            off += rsapub.getExponent(buf, off);

            return off;

        } else if(isEc()) {

            final ECPublicKey ecpub = (ECPublicKey)pub;
            final short qsize = (short)(1 + 2 * (short)((ecpub.getSize() / 8) + (((ecpub.getSize() % 8) == 0) ? 0 : 1)));
            short rsize = (short)(1 + qsize);

            if(qsize > 0x7f) {
                rsize = (short)(rsize + 2);
            } else {
                rsize = (short)(rsize + 1);
            }

            off = Common.writeLength(buf, off, rsize);

            buf[off++] = (byte)0x86;

            off = Common.writeLength(buf, off, qsize);

            off += ecpub.getW(buf, off);

            return off;

        }

        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return off;
    }




    protected final short sign(final byte[] buf, final short lc,
                               final boolean forAuth) {

        if(!isInitialized()) {
            ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
            return 0;
        }

        final PrivateKey priv = keys.getPrivate();

        short off = 0;

        byte[] sha_header = null;

        if(isRsa()) {

            if(lc > (short)(((short)(Common.bitsToBytes(rsaModulusBitSize()) * 2)) / 5)) { 
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return 0;
            }

            byte alg;

            if(lc == MessageDigest.LENGTH_SHA) {
                alg = MessageDigest.ALG_SHA;
            } else if(lc == MessageDigest.LENGTH_SHA_224) {
                alg = MessageDigest.ALG_SHA_224;
            } else if(lc == MessageDigest.LENGTH_SHA_256) {
                alg = MessageDigest.ALG_SHA_256;
            } else if(lc == MessageDigest.LENGTH_SHA_384) {
                alg = MessageDigest.ALG_SHA_384;
            } else if(lc == MessageDigest.LENGTH_SHA_512) {
                alg = MessageDigest.ALG_SHA_512;
            } else {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return 0;
            }
						
						final Signature sig = Signature.getInstance(alg, Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1, false);
						sig.init(priv, Signature.MODE_SIGN);
						
            off = sig.signPreComputedHash(buf, (short)0, lc,
                                          buf, lc);

	          return Util.arrayCopyNonAtomic(buf, (short)lc,
	                                         buf, (short)0,
	                                         off);

        } else if(isEc()) {

            byte alg;

            if(lc == MessageDigest.LENGTH_SHA) {
                alg = Signature.ALG_ECDSA_SHA;
            } else if(lc == MessageDigest.LENGTH_SHA_224) {
                alg = Signature.ALG_ECDSA_SHA_224;
            } else if(lc == MessageDigest.LENGTH_SHA_256) {
                alg = Signature.ALG_ECDSA_SHA_256;
            } else if(lc == MessageDigest.LENGTH_SHA_384) {
                alg = Signature.ALG_ECDSA_SHA_384;
            } else if(lc == MessageDigest.LENGTH_SHA_512) {
                alg = Signature.ALG_ECDSA_SHA_512;
            } else {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return 0;
            }

            final Signature sig = Signature.getInstance(alg, false);
            sig.init(priv, Signature.MODE_SIGN);

            final short sig_size = sig.signPreComputedHash(buf, (short)0, lc,
                                                           buf, lc);

            off = (short)(lc + 1);
            if((buf[off] & (byte)0x80) != (byte)0) {
                ++off;
            }
            ++off;

            if((buf[off++] != (byte)0x02)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            if((buf[off] & (byte)0x80) != (byte)0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            final short r_size = Util.makeShort((byte)0, buf[off++]);
            final short r_off = off;

            off += r_size;

            if((buf[off++] != (byte)0x02)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            if((buf[off] & (byte)0x80) != (byte)0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            final short s_size = Util.makeShort((byte)0, buf[off++]);
            final short s_off = off;

            off = (short)(lc + sig_size);

            if(r_size < s_size) {
                off = Util.arrayFillNonAtomic(buf, off, (short)(s_size - r_size), (byte)0);
            }

            off = Util.arrayCopyNonAtomic(buf, r_off,
                                          buf, off, r_size);

            if(s_size < r_size) {
                off = Util.arrayFillNonAtomic(buf, off, (short)(r_size - s_size), (byte)0);
            }

            off = Util.arrayCopyNonAtomic(buf, s_off,
                                          buf, off, s_size);

            off = Util.arrayCopyNonAtomic(buf, (short)(lc + sig_size),
                                          buf, (short)0,
                                          (short)(off - lc - sig_size));

            Util.arrayFillNonAtomic(buf, off, (short)(lc + sig_size - off), (byte)0);

            return off;
        }

        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return 0;
    }

}
