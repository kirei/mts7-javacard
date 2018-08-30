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

public final class Constants {

    protected static final short INTERNAL_BUFFER_MAX_LENGTH =
        (short)((short)0x500);

    protected static final short APDU_MAX_LENGTH = (short)0x100;

    protected static final short TAG_AID = (short)0x004f;
    protected static final short TAG_LIFE_CYCLE_STATUS = (short)0x008a;
    protected static final short TAG_CARDHOLDER_RELATED_DATA = (short)0x0065;
    protected static final short TAG_APPLICATION_RELATED_DATA = (short)0x006e;
    protected static final short TAG_SECURITY_SUPPORT_TEMPLATE = (short)0x007a;
    protected static final short TAG_CARDHOLDER_CERTIFICATE = (short)0x7f21;
    protected static final short TAG_ALGORITHM_ATTRIBUTES_AUT = (short)0x00c3;
    protected static final short TAG_EXTENDED_LENGTH_INFORMATION = (short)0x7f66;

    protected static final short CRT_AUTHENTICATION_KEY = (short)0xa400;

    protected static final byte CLA_MASK_CHAINING = (byte)0x10;

    protected static final byte INS_GET_DATA = (byte)0xCA;
    protected static final byte INS_GET_NEXT_DATA = (byte)0xCC;
    protected static final byte INS_PUT_DATA_DA = (byte)0xDA;
    protected static final byte INS_PUT_DATA_DB = (byte)0xDB;
    protected static final byte INS_GENERATE_ASYMMETRIC_KEY_PAIR = (byte)0x47;
    protected static final byte INS_INTERNAL_AUTHENTICATE = (byte)0x88;
    protected static final byte INS_GET_RESPONSE = (byte)0xC0;

    protected static final short SW_MEMORY_FAILURE = (short)0x6581;
    protected static final short SW_CHAINING_ERROR = (short)0x6883;
    protected static final short SW_REFERENCE_DATA_NOT_FOUND = (short)0x6A88;

    protected static final byte LCS_BYTE = (byte)0x00;
		 /* no information given - CL1 */

    protected static final short cardholderCertificateMaxLength() {
        return (short)0x0480;
    }

    protected static final byte ALGORITHM_ATTRIBUTES_MIN_LENGTH = 6;
    protected static final byte ALGORITHM_ATTRIBUTES_MAX_LENGTH = 13;

    protected static final byte[] ALGORITHM_ATTRIBUTES_DEFAULT = {
      (byte)0x01, /* RSA */
      (byte)0x08, (byte)0x00, /* 2048 bits modulus */
      (byte)0x00, (byte)0x11, /* 65537 = 17 bits public exponent */
      (byte)0x03 /* crt form with modulus */
    };

    protected static final byte[] ALGORITHM_ATTRIBUTES_RSA = {
        (byte)0x01, /* RSA */
        (byte)0x08, (byte)0x00, /* 2048 bits modulus */
        (byte)0x00, (byte)0x11, /* 65537 = 17 bits public exponent */
        (byte)0x03 /* crt form with modulus */
    };

    protected static final byte[] ALGORITHM_ATTRIBUTES_EC = {
        (byte)0x12, (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D,
        (byte)0x03, (byte)0x01, (byte)0x07
    };

    protected static final byte[] RSA_EXPONENT = { (byte)0x01, (byte)0x00, (byte)0x01 };

}
