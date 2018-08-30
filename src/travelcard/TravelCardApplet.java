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

public final class TravelCardApplet extends Applet {

    private final ECCurves ec;
    private final Persistent data;

    private final Transients transients;

    private final RandomData random_data;

    public TravelCardApplet() {
        random_data = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        ec = new ECCurves();

        data = new Persistent();
        transients = new Transients();
    }

    public static final void install(byte[] buf, short off, byte len) {
        new TravelCardApplet().register();
    }

    private final CardKey currentTagOccurenceToKey() {
        switch(transients.currentTagOccurrence()) {
        case 0:
            return data.card_keys[Persistent.CARD_KEYS_OFFSET_AUT];
        default:
            ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
            return null;
        }
    }

    private final void prepareChainingInput(final byte[] apdubuf) {
        short tmp;

        tmp = transients.outputLength();
        if(tmp > 0) {
            Util.arrayFillNonAtomic(transients.buffer, transients.outputStart(), tmp, (byte)0);
        }
        transients.setChainingOutput(false);
        transients.setOutputStart((short)0);
        transients.setOutputLength((short)0);

        if(transients.chainingInput()) {
            if((apdubuf[ISO7816.OFFSET_INS] != transients.chainingInputIns()) ||
               (apdubuf[ISO7816.OFFSET_P1] != transients.chainingInputP1()) ||
               (apdubuf[ISO7816.OFFSET_P2] != transients.chainingInputP2())) {
                transients.setChainingInput(false);
                transients.setChainingInputLength((short)0);
                ISOException.throwIt(Constants.SW_CHAINING_ERROR);
                return;
            }
            if((apdubuf[ISO7816.OFFSET_CLA] & Constants.CLA_MASK_CHAINING) != Constants.CLA_MASK_CHAINING) {
                transients.setChainingInput(false);
            }
        } else {
            tmp = transients.chainingInputLength();
            if(tmp > 0) {
                Util.arrayFillNonAtomic(transients.buffer, (short)0, tmp, (byte)0);
            }
            transients.setChainingInputLength((short)0);

            if((apdubuf[ISO7816.OFFSET_CLA] & Constants.CLA_MASK_CHAINING) == Constants.CLA_MASK_CHAINING) {
                transients.setChainingInputIns(apdubuf[ISO7816.OFFSET_INS]);
                transients.setChainingInputP1(apdubuf[ISO7816.OFFSET_P1]);
                transients.setChainingInputP2(apdubuf[ISO7816.OFFSET_P2]);
                transients.setChainingInput(true);
            }
        }
    }

    private final void receiveData(final APDU apdu) {
        final byte[] apdubuf = apdu.getBuffer();

        short blen = apdu.setIncomingAndReceive();

        final short lc = apdu.getIncomingLength();
        final short offcdata = apdu.getOffsetCdata();

        short off = transients.chainingInputLength();

        if((short)(off + lc) > Constants.INTERNAL_BUFFER_MAX_LENGTH) {
            transients.setChainingInput(false);
            transients.setChainingInputLength((short)0);
            ISOException.throwIt(Constants.SW_MEMORY_FAILURE);
            return;
        }

        while(blen > 0) {
            off = Util.arrayCopyNonAtomic(apdubuf, offcdata,
                                          transients.buffer, off,
                                          blen);
            blen = apdu.receiveBytes(offcdata);
        }

        transients.setChainingInputLength(off);
    }

    private final short processGetData(final byte p1, final byte p2) {

        final short tag = Util.makeShort(p1, p2);
        short off = 0;
        short tlen = 0;

        if(transients.currentTag() == 0) {
            transients.setCurrentTag(tag);
            transients.setCurrentTagOccurrence((byte)0);
        } else if(transients.currentTag() != tag) {
            transients.setCurrentTagOccurrence((byte)0);
        }

        final byte[] buf = transients.buffer;
        CardKey k;

        switch(tag) {

        case Constants.TAG_APPLICATION_RELATED_DATA:

            final byte aid_length = JCSystem.getAID().getBytes(buf, off);

            buf[off++] = (byte)Constants.TAG_APPLICATION_RELATED_DATA;
            off = Common.writeLength(buf, off, (short)(1 + 1 + aid_length + 2 + 1 + 18));

            buf[off++] = (byte)Constants.TAG_AID;
            off = Common.writeLength(buf, off, aid_length);
            off += JCSystem.getAID().getBytes(buf, off);

            buf[off++] = (byte)Constants.TAG_LIFE_CYCLE_STATUS;
            buf[off++] = (byte)0x01;
            buf[off++] = (byte)Constants.LCS_BYTE;

            buf[off++] = (byte)Constants.TAG_SECURITY_SUPPORT_TEMPLATE;
            buf[off++] = (byte)(data.digital_signature_counter.length + 2);
            buf[off++] = (byte)0x93;
            buf[off++] = (byte)data.digital_signature_counter.length;
            off = Util.arrayCopyNonAtomic(data.digital_signature_counter,
                    (short)0, buf, off,
                    (byte)data.digital_signature_counter.length);

            off = Util.setShort(buf, off,
                    Constants.TAG_EXTENDED_LENGTH_INFORMATION);
            off = Common.writeLength(buf, off, (short)8);
            buf[off++] = (byte)0x02;
            buf[off++] = (byte)0x02;
            off = Util.setShort(buf, off, Constants.APDU_MAX_LENGTH);
            buf[off++] = (byte)0x02;
            buf[off++] = (byte)0x02;
            off = Util.setShort(buf, off, Constants.APDU_MAX_LENGTH); 

            break;

        case Constants.TAG_CARDHOLDER_CERTIFICATE:
            k = currentTagOccurenceToKey();

            if(k == null) {
                ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
                return 0;
            }

            off = Util.arrayCopyNonAtomic(k.certificate, (short)0,
                                          buf, off,
                                          k.certificate_length);
            break;

        default:
            ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
            return 0;
        }

        return off;
    }

    private final short processGetNextData(final byte p1, final byte p2) {

        if(Util.makeShort(p1, p2) != Constants.TAG_CARDHOLDER_CERTIFICATE) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            return 0;
        }

        final CardKey k = currentTagOccurenceToKey();

        if(k == null) {
            ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
            return 0;
        }

        transients.setCurrentTagOccurrence((byte)(transients.currentTagOccurrence() + 1));

        return Util.arrayCopyNonAtomic(k.certificate, (short)0,
                                       transients.buffer, (short)0,
                                       k.certificate_length);
    }

    private final void processPutData(final short lc,
                                      final byte p1, final byte p2,
                                      final boolean isOdd) {

        final byte[] buf = transients.buffer;

        CardKey k = null;

            final short tag = Util.makeShort(p1, p2);

            if(transients.currentTag() == 0) {
                transients.setCurrentTag(tag);
                transients.setCurrentTagOccurrence((byte)0);
            } else if(transients.currentTag() != tag) {
                transients.setCurrentTagOccurrence((byte)0);
            }

            switch(tag) {

            case Constants.TAG_CARDHOLDER_CERTIFICATE:
                k = currentTagOccurenceToKey();
                if(k == null) {
                    ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
                    return;
                }
                k.setCertificate(buf, (short)0, lc);
                break;

            default:
                ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
                return;
            }
    }

    private final short processGenerateAsymmetricKeyPair(final short lc,
                                                         final byte p1, final byte p2) {

        final byte[] buf = transients.buffer;

        if(((p1 != (byte)0x80) && (p1 != (byte)0x81)) ||
           (p2 != 0)) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            return 0;
        }

        if(lc != 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return 0;
        }

        boolean do_reset = false;
        CardKey pkey;

        switch(Util.makeShort(buf[0], buf[1])) {
        case Constants.CRT_AUTHENTICATION_KEY:
            pkey = data.card_keys[Persistent.CARD_KEYS_OFFSET_AUT];
            break;

        default:
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return 0;
        }

        if(p1 == (byte)0x80) {

            pkey.generate(ec);

            if(do_reset) {
                JCSystem.beginTransaction();
                Util.arrayFillNonAtomic(data.digital_signature_counter, (short)0,
                                        (byte)data.digital_signature_counter.length, (byte)0);
                JCSystem.commitTransaction();
            }
        }

        return pkey.writePublicKeyDo(buf, (short)0);
    }

    private final short processInternalAuthenticate(final short lc,
                                                    final byte p1, final byte p2) {

        byte i = 0;
        JCSystem.beginTransaction();
        while(data.digital_signature_counter[(byte)(data.digital_signature_counter.length - i - 1)] == (byte)0xff) {
            ++i;
        }
        if(i < data.digital_signature_counter.length) {
            ++data.digital_signature_counter[(byte)(data.digital_signature_counter.length - i - 1)];
            if(i > 0) {
                --i;
                Util.arrayFillNonAtomic(data.digital_signature_counter,
                                        (short)(data.digital_signature_counter.length - i - 1),
                                        (byte)(i + 1), (byte)0);
            }
        }
        JCSystem.commitTransaction();

        if(p2 == (byte)0x00) {
            switch(p1) {
            case (byte)0x00:
                return data.card_keys[Persistent.CARD_KEYS_OFFSET_AUT].sign(transients.buffer, lc, true);
            }
        }

        ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        return 0;
    }


    private final void clearConnection() {
        transients.clear();
    }

    public final void process(final APDU apdu) {

        final byte[] apdubuf = apdu.getBuffer();
        short cp = 0;
        
        if(apdu.isISOInterindustryCLA() && selectingApplet()) {

            clearConnection();
          
            cp = processGetData((byte)0x00, (byte)0x6e);            

            short off = transients.outputStart();

            final byte[] fmd = { (byte)0x64, (byte)cp };

            Util.arrayCopyNonAtomic(fmd, (short)0,
                                    apdubuf, (short)0, (short)2);

            Util.arrayCopyNonAtomic(transients.buffer, off,
                                    apdubuf, (short)2, cp);

            apdu.setOutgoing();
            apdu.setOutgoingLength((short)(cp + fmd.length));
            apdu.sendBytes((short)0, (short)(cp + fmd.length));
            
            return;
        }


        final byte p1 = apdubuf[ISO7816.OFFSET_P1];
        final byte p2 = apdubuf[ISO7816.OFFSET_P2];


        short available_le = 0;
        short sw = (short)0x9000;

        if(((apdubuf[ISO7816.OFFSET_CLA] & Constants.CLA_MASK_CHAINING) != Constants.CLA_MASK_CHAINING) &&
           (apdubuf[ISO7816.OFFSET_INS] == Constants.INS_GET_RESPONSE)) {

            if(transients.chainingInput() || !transients.chainingOutput()) {
                ISOException.throwIt(Constants.SW_CHAINING_ERROR);
                return;
            }

            if((p1 != 0) || (p2 != 0)) {
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                return;
            }

            available_le = transients.outputLength();

        } else if((apdubuf[ISO7816.OFFSET_CLA] & Constants.CLA_MASK_CHAINING) == Constants.CLA_MASK_CHAINING) {

            prepareChainingInput(apdubuf);
            receiveData(apdu);

        } else {

            prepareChainingInput(apdubuf);
            receiveData(apdu);

            short lc = transients.chainingInputLength();
            
            try {

                switch(apdubuf[ISO7816.OFFSET_INS]) {
                case Constants.INS_GET_DATA:
                    available_le = processGetData(p1, p2);
                    break;

                case Constants.INS_GET_NEXT_DATA:
                    available_le = processGetNextData(p1, p2);
                    break;

                case Constants.INS_PUT_DATA_DA:
                    processPutData(lc, p1, p2, false);
                    break;

                case Constants.INS_PUT_DATA_DB:
                    processPutData(lc, p1, p2, true);
                    break;

                case Constants.INS_GENERATE_ASYMMETRIC_KEY_PAIR:
                    available_le = processGenerateAsymmetricKeyPair(lc, p1, p2);
                    break;

                case Constants.INS_INTERNAL_AUTHENTICATE:
                    available_le = processInternalAuthenticate(lc, p1, p2);
                    break;

                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                    return;
                }

            } catch (ISOException e) {
                sw = e.getReason();
            }

            transients.setOutputLength(available_le);
        }



        if(available_le > 0) {

            short resp_le = available_le;

            if(apdu.getCurrentState() != APDU.STATE_OUTGOING) {
                resp_le = apdu.setOutgoing();
                if((resp_le == (short)0) || (available_le < resp_le)) {
                    resp_le = available_le;
                }
            }

            if(resp_le > Constants.APDU_MAX_LENGTH) {
                resp_le = Constants.APDU_MAX_LENGTH;
            }

            short off = transients.outputStart();

            Util.arrayCopyNonAtomic(transients.buffer, off,
                                    apdubuf, (short)0, resp_le);

            apdu.setOutgoingLength(resp_le);
            apdu.sendBytes((short)0, resp_le);

            Util.arrayFillNonAtomic(transients.buffer, off, resp_le, (byte)0);

            available_le -= resp_le;
            off += resp_le;

            if(available_le > 0) {
                transients.setChainingOutput(true);
                transients.setOutputLength(available_le);
                transients.setOutputStart(off);

                if(available_le > (short)0x00ff) {
                    available_le = (short)0x00ff;
                }

                sw = (short)(ISO7816.SW_BYTES_REMAINING_00 | available_le);

            } else {
                transients.setChainingOutput(false);
                transients.setOutputLength((short)0);
                transients.setOutputStart((short)0);
            }
        }

        ISOException.throwIt(sw);
    }
}
