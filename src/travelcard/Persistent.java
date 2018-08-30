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

public final class Persistent {

    protected boolean isTerminated;

    protected final CardKey[] card_keys;
    protected static final byte CARD_KEYS_OFFSET_AUT = 0;
    private static final byte CARD_KEYS_LENGTH = CARD_KEYS_OFFSET_AUT + 1;

    protected final byte[] digital_signature_counter;

    protected Persistent() {

        digital_signature_counter = new byte[3];
        card_keys = new CardKey[CARD_KEYS_LENGTH];
        for(byte i = 0; i < card_keys.length; ++i) {
            card_keys[i] = new CardKey();
        }
        reset(true);
    }

    protected void reset(final boolean isRegistering) {
        for(byte i = 0; i < card_keys.length; ++i) {
            card_keys[i].reset(isRegistering);
        }

        Util.arrayFillNonAtomic(digital_signature_counter, (short)0,
                                (short)digital_signature_counter.length, (byte)0);

        isTerminated = false;
    }
}
