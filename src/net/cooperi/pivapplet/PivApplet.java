/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Alex Wilson <alex@cooperi.net>
 */

package net.cooperi.pivapplet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.framework.APDUException;
import javacard.framework.SystemException;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyAgreement;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.RandomData;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacard.security.SecretKey;
import javacard.security.MessageDigest;
import javacardx.crypto.Cipher;
import javacardx.apdu.ExtendedLength;

#if APPLET_EXTLEN
public class PivApplet extends Applet implements ExtendedLength
#else
public class PivApplet extends Applet
#endif
{
	private static final byte[] PIV_AID = {
	    (byte)0xa0, (byte)0x00, (byte)0x00, (byte)0x03, (byte)0x08,
	    (byte)0x00, (byte)0x00, (byte)0x10, (byte)0x00, (byte)0x01,
	    (byte)0x00
	};

	private static final byte[] APP_NAME = {
	    'P', 'i', 'v', 'A', 'p', 'p', 'l', 'e', 't'
	};

	private static final byte[] DEFAULT_ADMIN_KEY = {
	    (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04,
	    (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
	    (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04,
	    (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
	    (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04,
	    (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08
	};

	private static final byte[] DEFAULT_PIN = {
	    '1', '2', '3', '4', '5', '6', (byte)0xFF, (byte)0xFF
	};
	private static final byte[] DEFAULT_PUK = {
	    '1', '2', '3', '4', '5', '6', '7', '8'
	};

	private static final byte[] CARD_ID_FIXED = {
	    /* GSC-RID: GSC-IS data model */
	    (byte)0xa0, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x16,
	    /* Manufacturer: ff (unknown) */
	    (byte)0xff,
	    /* Card type: JavaCard */
	    (byte)0x02
	};

	private static final byte[] YKPIV_VERSION = {
	    (byte)5, (byte)0, (byte)0
	};

	/* Standard PIV commands we support. */
	private static final byte INS_VERIFY = (byte)0x20;
	private static final byte INS_CHANGE_PIN = (byte)0x24;
	private static final byte INS_RESET_PIN = (byte)0x2C;
	private static final byte INS_GEN_AUTH = (byte)0x87;
	private static final byte INS_GET_DATA = (byte)0xCB;
	private static final byte INS_PUT_DATA = (byte)0xDB;
	private static final byte INS_GEN_ASYM = (byte)0x47;
	private static final byte INS_GET_RESPONSE = (byte)0xC0;

	/* YubicoPIV extensions we support. */
	private static final byte INS_SET_MGMT = (byte)0xff;
	private static final byte INS_IMPORT_ASYM = (byte)0xfe;
	private static final byte INS_GET_VER = (byte)0xfd;
	private static final byte INS_RESET = (byte)0xfb;
	private static final byte INS_SET_PIN_RETRIES = (byte)0xfa;
	private static final byte INS_ATTEST = (byte)0xf9;
	private static final byte INS_GET_SERIAL = (byte)0xf8;

	/* Our own private extensions. */
	private static final byte INS_SG_DEBUG = (byte)0xe0;

	/* ASSERT: tag.end() was called but tag has bytes left. */
	protected static final short SW_TAG_END_ASSERT = (short)0x6F60;
	protected static final short SW_DATA_END_ASSERT = (short)0x6F63;
	/* ASSERT: SGList#startReserve() ran out of Buffers. */
	protected static final short SW_RESERVE_FAILURE = (short)0x6F61;
	/* ASSERT: SGList#skip */
	protected static final short SW_SKIPPED_OVER_WPTR = (short)0x6F62;
	protected static final short SW_BAD_REWRITE = (short)0x6F64;

	private static final boolean USE_EXT_LEN = false;

	private SGList incoming = null;
	private SGList outgoing = null;
	private APDUStream apduStream = null;
	private Buffer tempBuf = null;
	private Buffer outBuf = null;

	private byte[] challenge = null;
	private byte[] iv = null;
	private byte[] certSerial = null;

	private byte[] guid = null;
	private byte[] cardId = null;
	private byte[] serial = null;
	private byte[] fascn = null;
	private byte[] expiry = null;

	private TlvReader tlv = null;
	private TlvWriter wtlv = null;

	private OwnerPIN pivPin = null;
	private OwnerPIN pukPin = null;

	private RandomData randData = null;
	private Cipher tripleDes = null;
	private Cipher rsaPkcs1 = null;
	private Signature ecdsaP256Sha = null;
	private Signature ecdsaP256Sha256 = null;
	private Signature rsaSha = null;
	private Signature rsaSha256 = null;
	private KeyAgreement ecdh = null;
	private KeyAgreement ecdhSha = null;

	private static final byte MAX_SLOTS = (byte)17;

	private static final byte SLOT_9A = (byte)0;
	private static final byte SLOT_9B = (byte)1;
	private static final byte SLOT_9C = (byte)2;
	private static final byte SLOT_9D = (byte)3;
	private static final byte SLOT_9E = (byte)4;
	private static final byte SLOT_82 = (byte)5;
	private static final byte SLOT_8C = (byte)15;
	private static final byte SLOT_F9 = (byte)16;
	private PivSlot[] slots = null;
	private byte retiredKeys = 0;

	private static final byte SLOT_MIN_HIST = SLOT_82;
	private static final byte MIN_HIST_SLOT = (byte)0x82;
	private static final byte MAX_HIST_SLOT = (byte)0x8C;

	private static final byte PIV_ALG_DEFAULT = (byte)0x00;
	private static final byte PIV_ALG_3DES = (byte)0x03;
	private static final byte PIV_ALG_RSA1024 = (byte)0x06;
	private static final byte PIV_ALG_RSA2048 = (byte)0x07;
	private static final byte PIV_ALG_AES128 = (byte)0x08;
	private static final byte PIV_ALG_AES192 = (byte)0x0A;
	private static final byte PIV_ALG_AES256 = (byte)0x0C;
	private static final byte PIV_ALG_ECCP256 = (byte)0x11;
	private static final byte PIV_ALG_ECCP384 = (byte)0x14;

	private static final byte PIV_ALG_ECCP256_SHA1 = (byte)0xf0;
	private static final byte PIV_ALG_ECCP256_SHA256 = (byte)0xf1;

	private static final byte GA_TAG_WITNESS = (byte)0x80;
	private static final byte GA_TAG_CHALLENGE = (byte)0x81;
	private static final byte GA_TAG_RESPONSE = (byte)0x82;
	private static final byte GA_TAG_EXP = (byte)0x85;

	private static final byte TAG_CERT_9E = (byte)0x01;
	private static final byte TAG_CHUID = (byte)0x02;
	private static final byte TAG_FINGERPRINTS = (byte)0x03;
	private static final byte TAG_CERT_9A = (byte)0x05;
	private static final byte TAG_SECOBJ = (byte)0x06;
	private static final byte TAG_CARDCAP = (byte)0x07;
	private static final byte TAG_FACE = (byte)0x08;
	private static final byte TAG_PRINTED_INFO = (byte)0x09;
	private static final byte TAG_CERT_9C = (byte)0x0A;
	private static final byte TAG_CERT_9D = (byte)0x0B;
	private static final byte TAG_KEYHIST = (byte)0x0C;
	private static final byte TAG_CERT_82 = (byte)0x0D;
	private static final byte TAG_CERT_8C = (byte)0x17;

	private static final byte TAG_MAX = TAG_CERT_8C;
	private File[] files = null;

	private static final byte TAG_YK_PIVMAN = (byte)0x00;
	private static final byte TAG_YK_ATTEST = (byte)0x01;
	private static final byte YK_TAG_MAX = TAG_YK_ATTEST;
	private File[] ykFiles = null;

	private static final byte ALG_EC_SVDP_DH_PLAIN = (byte)3;
	private static final byte ALG_EC_SVDP_DHC_PLAIN = (byte)4;
	private static final byte ALG_RSA_SHA_256_PKCS1 = (byte)40;

	public static void
	install(byte[] info, short off, byte len)
	{
		final PivApplet applet = new PivApplet();
		applet.register();
	}

#if APPLET_USE_RESET_MEM
	private static final boolean useResetMem = true;
#else
	private static final boolean useResetMem = false;
#endif

	protected
	PivApplet()
	{
		randData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		tripleDes = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);

#if PIV_SUPPORT_RSA
		rsaPkcs1 = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, useResetMem);

#if YKPIV_ATTESTATION
		try {
			rsaSha = Signature.getInstance(
			    Signature.ALG_RSA_SHA_PKCS1, useResetMem);
		} catch (CryptoException ex) {
			if (ex.getReason() != CryptoException.NO_SUCH_ALGORITHM)
				throw (ex);
		}
		try {
			rsaSha256 = Signature.getInstance(
			    ALG_RSA_SHA_256_PKCS1, useResetMem);
		} catch (CryptoException ex) {
			if (ex.getReason() != CryptoException.NO_SUCH_ALGORITHM)
				throw (ex);
		}
#endif
#endif

#if PIV_SUPPORT_EC
		try {
			ecdh = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN,
			    useResetMem);
		} catch (CryptoException ex) {
			if (ex.getReason() != CryptoException.NO_SUCH_ALGORITHM)
				throw (ex);
		}

		if (ecdh == null) {
			try {
				ecdh = KeyAgreement.getInstance(
				    ALG_EC_SVDP_DHC_PLAIN, useResetMem);
			} catch (CryptoException ex) {
				if (ex.getReason() !=
				    CryptoException.NO_SUCH_ALGORITHM)
					throw (ex);
			}
		}

		if (ecdh == null) {
			try {
				ecdhSha = KeyAgreement.getInstance(
				    KeyAgreement.ALG_EC_SVDP_DH, useResetMem);
			} catch (CryptoException ex) {
				if (ex.getReason() !=
				    CryptoException.NO_SUCH_ALGORITHM)
					throw (ex);
			}
		}

		try {
			ecdsaP256Sha = Signature.getInstance(
			    Signature.ALG_ECDSA_SHA, useResetMem);
		} catch (CryptoException ex) {
			if (ex.getReason() != CryptoException.NO_SUCH_ALGORITHM)
				throw (ex);
		}
		try {
			ecdsaP256Sha256 = Signature.getInstance(
			    ECParams.ALG_ECDSA_SHA_256, useResetMem);
		} catch (CryptoException ex) {
			if (ex.getReason() != CryptoException.NO_SUCH_ALGORITHM)
				throw (ex);
		}
#endif

		challenge = JCSystem.makeTransientByteArray((short)16,
		    JCSystem.CLEAR_ON_DESELECT);
		iv = JCSystem.makeTransientByteArray((short)16,
		    JCSystem.CLEAR_ON_DESELECT);

		guid = new byte[16];
		randData.generateData(guid, (short)0, (short)16);
		cardId = new byte[21];
		Util.arrayCopy(CARD_ID_FIXED, (short)0, cardId, (short)0,
		    (short)CARD_ID_FIXED.length);
		randData.generateData(cardId, (short)CARD_ID_FIXED.length,
		    (short)(21 - (short)CARD_ID_FIXED.length));

		serial = new byte[4];
		randData.generateData(serial, (short)0, (short)4);
		serial[0] |= (byte)0x80;

		certSerial = new byte[16];
		fascn = new byte[25];
		expiry = new byte[] { '2', '0', '5', '0', '0', '1', '0', '1' };

		slots = new PivSlot[MAX_SLOTS];
		for (byte i = SLOT_9A; i <= SLOT_9E; ++i)
			slots[i] = new PivSlot((byte)((byte)0x9A + i));
		for (byte i = SLOT_82; i <= SLOT_8C; ++i)
			slots[i] = new PivSlot((byte)((byte)0x82 + i));
#if YKPIV_ATTESTATION
		slots[SLOT_F9] = new PivSlot((byte)0xF9);
#endif

		files = new File[TAG_MAX + 1];
		ykFiles = new File[YK_TAG_MAX + 1];

		incoming = new SGList();
		outgoing = new SGList();
		apduStream = new APDUStream();

		tempBuf = new Buffer();
		outBuf = new Buffer();

		tlv = new TlvReader();
		wtlv = new TlvWriter(incoming);

		/* Initialize the admin key */
		DESKey dk = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
		    KeyBuilder.LENGTH_DES3_3KEY, false);
		slots[SLOT_9B].sym = dk;
		dk.setKey(DEFAULT_ADMIN_KEY, (short)0);
		slots[SLOT_9B].symAlg = PIV_ALG_3DES;
		/*
		 * Allow the admin key to be "used" (for auth) without a
		 * PIN VERIFY command first.
		 */
		slots[SLOT_9B].pinPolicy = PivSlot.P_NEVER;

		pivPin = new OwnerPIN((byte)5, (byte)8);
		pivPin.update(DEFAULT_PIN, (short)0, (byte)8);
		pukPin = new OwnerPIN((byte)3, (byte)8);
		pukPin.update(DEFAULT_PUK, (short)0, (byte)8);

		files[TAG_CERT_9A] = new File();
		slots[SLOT_9A].cert = files[TAG_CERT_9A];

		files[TAG_CERT_9C] = new File();
		slots[SLOT_9C].cert = files[TAG_CERT_9C];
		slots[SLOT_9C].pinPolicy = PivSlot.P_ALWAYS;

		files[TAG_CERT_9D] = new File();
		slots[SLOT_9D].cert = files[TAG_CERT_9D];

		files[TAG_CERT_9E] = new File();
		slots[SLOT_9E].cert = files[TAG_CERT_9E];
		slots[SLOT_9E].pinPolicy = PivSlot.P_NEVER;

		files[TAG_FINGERPRINTS] = new File();
		files[TAG_FINGERPRINTS].contact = File.P_PIN;

		files[TAG_FACE] = new File();
		files[TAG_FACE].contact = File.P_PIN;

		files[TAG_PRINTED_INFO] = new File();
		files[TAG_PRINTED_INFO].contact = File.P_PIN;

#if YKPIV_ATTESTATION
		ykFiles[TAG_YK_ATTEST] = new File();
		slots[SLOT_F9].cert = ykFiles[TAG_YK_ATTEST];
#endif

#if PIV_STRICT_CONTACTLESS
		files[TAG_CERT_9A].contactless = File.P_NEVER;
		files[TAG_CERT_9C].contactless = File.P_NEVER;
		files[TAG_CERT_9D].contactless = File.P_NEVER;
		files[TAG_FINGERPRINTS].contactless = File.P_NEVER;
		files[TAG_PRINTED_INFO].contactless = File.P_PIN;
		files[TAG_FACE].contactless = File.P_PIN;
#endif

		initCARDCAP();
		initCHUID();
		initKEYHIST();
#if YKPIV_ATTESTATION
		initAttestation();
#endif
	}

	public void
	process(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		final byte ins = buffer[ISO7816.OFFSET_INS];
		final byte chainBit =
		    (byte)(buffer[ISO7816.OFFSET_CLA] & (byte)0x10);

		if (!apdu.isISOInterindustryCLA()) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			return;
		}

		if (selectingApplet()) {
			sendSelectResponse(apdu);
			return;
		}

		/*
		 * Slots that are marked as "PIN always" only work when the
		 * APDU directly before them was VERIFY.
		 *
		 * If we process any other type of APDU, we set the flag
		 * AFTER_VERIFY and then before the next APDU we lock them
		 * here. The VERIFY command unsets the flag.
		 */
		if (chainBit == 0)
			lockPINAlwaysSlots();

		switch (ins) {
		case INS_GET_DATA:
			processGetData(apdu);
			break;
		case INS_GEN_AUTH:
			processGeneralAuth(apdu);
			break;
		case INS_PUT_DATA:
			processPutData(apdu);
			break;
		case INS_CHANGE_PIN:
			processChangePin(apdu);
			break;
		case INS_VERIFY:
			processVerify(apdu);
			break;
		case INS_GEN_ASYM:
			processGenAsym(apdu);
			break;
		case INS_RESET_PIN:
			processResetPin(apdu);
			break;
		case INS_SET_PIN_RETRIES:
			processSetPinRetries(apdu);
			break;
		case INS_RESET:
			processReset(apdu);
			break;
		case INS_GET_VER:
			processGetVersion(apdu);
			break;
		case INS_IMPORT_ASYM:
			processImportAsym(apdu);
			break;
		case INS_SET_MGMT:
			processSetMgmtKey(apdu);
			break;
		case INS_SG_DEBUG:
			processSGDebug(apdu);
			break;
		case INS_GET_RESPONSE:
			continueResponse(apdu);
			break;
#if YKPIV_ATTESTATION
		case INS_ATTEST:
			processAttest(apdu);
			break;
#endif
		case INS_GET_SERIAL:
			processGetSerial(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private boolean
	isContact()
	{
		final byte media = (byte)(
		    APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
		if (media == APDU.PROTOCOL_MEDIA_DEFAULT)
			return (true);
		if (media == APDU.PROTOCOL_MEDIA_USB)
			return (true);
		return (false);
	}

	private void
	lockPINAlwaysSlots()
	{
		for (short idx = (short)0; idx < MAX_SLOTS; ++idx) {
			final PivSlot slot = slots[idx];
			if (slot == null)
				continue;
			if (slot.pinPolicy != PivSlot.P_ALWAYS)
				continue;
			if (slot.flags[PivSlot.F_UNLOCKED] &&
			    slot.flags[PivSlot.F_AFTER_VERIFY]) {
				slot.flags[PivSlot.F_UNLOCKED] = false;
			} else if (slot.flags[PivSlot.F_UNLOCKED]) {
				slot.flags[PivSlot.F_AFTER_VERIFY] = true;
			}
		}
	}

	private void
	processGetVersion(APDU apdu)
	{
		short len = 0;
		final short le;
		final byte[] buffer = apdu.getBuffer();

		le = apdu.setOutgoing();
		buffer[len++] = YKPIV_VERSION[0];
		buffer[len++] = YKPIV_VERSION[1];
		buffer[len++] = YKPIV_VERSION[2];

		len = le > 0 ? (le > len ? len : le) : len;
		apdu.setOutgoingLength(len);
		apdu.sendBytes((short)0, len);
	}

	private void
	processGetSerial(APDU apdu)
	{
		short len = 0;
		final short le;
		final byte[] buffer = apdu.getBuffer();

		le = apdu.setOutgoing();
		buffer[len++] = serial[0];
		buffer[len++] = serial[1];
		buffer[len++] = serial[2];
		buffer[len++] = serial[3];

		len = le > 0 ? (le > len ? len : le) : len;
		apdu.setOutgoingLength(len);
		apdu.sendBytes((short)0, len);
	}

#if YKPIV_ATTESTATION
	private void
	processAttest(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		final byte key = buffer[ISO7816.OFFSET_P1];
		final PivSlot slot;

		if (key >= (byte)0x9A && key <= (byte)0x9E) {
			final byte idx = (byte)(key - (byte)0x9A);
			slot = slots[idx];
		} else if (key >= MIN_HIST_SLOT && key <= MAX_HIST_SLOT) {
			final byte idx = (byte)(SLOT_MIN_HIST +
			    (byte)(key - MIN_HIST_SLOT));
			slot = slots[idx];
		} else {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		if (slot == null) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		if (buffer[ISO7816.OFFSET_P2] != (byte)0x00) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		writeAttestationCert(slot);

		sendOutgoing(apdu);
	}
#endif

	private void
	processSGDebug(APDU apdu)
	{
		short len = (short)0;
		short i = (short)0;
		final short le;
		final byte[] buffer = apdu.getBuffer();

		le = apdu.setOutgoing();
		len = Util.setShort(buffer, len, incoming.state[SGList.WPTR_BUF]);
		len = Util.setShort(buffer, len, incoming.state[SGList.WPTR_OFF]);
		for (i = 0; i < SGList.MAX_BUFS; ++i) {
			if (incoming.buffers[i].data == null)
				break;
			buffer[len++] = (byte)i;
			byte status = (byte)0;
			if (incoming.buffers[i].isDynamic)
				status |= (byte)0x01;
			if (incoming.buffers[i].isTransient)
				status |= (byte)0x02;
			buffer[len++] = status;
			len = Util.setShort(buffer, len,
			    (short)incoming.buffers[i].data.length);
			len = Util.setShort(buffer, len,
			    incoming.buffers[i].state[Buffer.OFFSET]);
			len = Util.setShort(buffer, len,
			    incoming.buffers[i].state[Buffer.LEN]);
		}

		len = le > 0 ? (le > len ? len : le) : len;
		apdu.setOutgoingLength(len);
		apdu.sendBytes((short)0, len);
	}

	private void
	sendSelectResponse(APDU apdu)
	{
		outgoing.reset();
		wtlv.start(outgoing);

		wtlv.push((byte)0x61);

		wtlv.push((byte)0x4F);
		wtlv.write(PIV_AID, (short)0, (short)PIV_AID.length);
		wtlv.pop();

		wtlv.push((byte)0x79);
		wtlv.push((byte)0x4F);
		wtlv.write(PIV_AID, (short)0, (short)PIV_AID.length);
		wtlv.pop();
		wtlv.pop();

		wtlv.push((byte)0x50);
		wtlv.write(APP_NAME, (short)0, (short)APP_NAME.length);
		wtlv.pop();

		wtlv.push((byte)0xAC);
		wtlv.push((byte)0x80);
		wtlv.writeByte(PIV_ALG_3DES);
		wtlv.pop();
#if PIV_SUPPORT_RSA
		wtlv.push((byte)0x80);
		wtlv.writeByte(PIV_ALG_RSA1024);
		wtlv.pop();
		wtlv.push((byte)0x80);
		wtlv.writeByte(PIV_ALG_RSA2048);
		wtlv.pop();
#endif
#if PIV_SUPPORT_EC
		if (ecdsaP256Sha != null || ecdsaP256Sha256 != null) {
			wtlv.push((byte)0x80);
			wtlv.writeByte(PIV_ALG_ECCP256);
			wtlv.pop();
		}
#if !PIV_USE_EC_PRECOMPHASH
		if (ecdsaP256Sha != null) {
			wtlv.push((byte)0x80);
			wtlv.writeByte(PIV_ALG_ECCP256_SHA1);
			wtlv.pop();
		}
		if (ecdsaP256Sha256 != null) {
			wtlv.push((byte)0x80);
			wtlv.writeByte(PIV_ALG_ECCP256_SHA256);
			wtlv.pop();
		}
#endif
#endif
		wtlv.push((byte)0x06);
		wtlv.pop();
		wtlv.pop();

		wtlv.pop();
		wtlv.end();

		sendOutgoing(apdu);
	}

	private void
	sendOutgoing(APDU apdu)
	{
		final short len = outgoing.available();
		if (len < 1) {
			ISOException.throwIt(
			    ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			return;
		}

		final short le = apdu.setOutgoing();
		final byte[] buf = apdu.getBuffer();

		short toSend = len;
		if (le > 0 && toSend > le)
			toSend = le;
		if (toSend > (short)0xFF)
			toSend = (short)0xFF;

		final short rem = (short)(len - toSend);
		final byte wantNext =
		    rem > (short)0xFF ? (byte)0xFF : (byte)rem;

		apdu.setOutgoingLength(toSend);
		outgoing.read(buf, (short)0, toSend);
		apdu.sendBytes((short)0, toSend);

		if (rem > 0) {
			ISOException.throwIt(
			    (short)(ISO7816.SW_BYTES_REMAINING_00 |
			    ((short)wantNext & (short)0x00ff)));
		} else {
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
		}
	}

	private void
	continueResponse(APDU apdu)
	{
		sendOutgoing(apdu);
	}

	private boolean
	receiveChain(APDU apdu)
	{
		final byte[] buf = apdu.getBuffer();
		final byte chainBit =
		    (byte)(buf[ISO7816.OFFSET_CLA] & (byte)0x10);

		if (incoming.atEnd())
			incoming.reset();

		short recvLen = apdu.setIncomingAndReceive();
#if APPLET_EXTLEN
		final short cdata = apdu.getOffsetCdata();
#else
		final short cdata = ISO7816.OFFSET_CDATA;
#endif

		while (recvLen > 0) {
			incoming.write(buf, cdata, recvLen);
			recvLen = apdu.receiveBytes(cdata);
		}

		if (chainBit != 0) {
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
			return (false);
		}

		return (true);
	}

	private void
	processGenAsym(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		short lc, len, cLen;
		byte tag, alg = (byte)0xFF;
		final byte key;
		final PivSlot slot;

		if (buffer[ISO7816.OFFSET_P1] != (byte)0x00) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		key = buffer[ISO7816.OFFSET_P2];

		if (key >= (byte)0x9A && key <= (byte)0x9E) {
			final byte idx = (byte)(key - (byte)0x9A);
			slot = slots[idx];
		} else if (key >= MIN_HIST_SLOT && key <= MAX_HIST_SLOT) {
			final byte idx = (byte)(SLOT_MIN_HIST +
			    (byte)(key - MIN_HIST_SLOT));
			slot = slots[idx];
		} else if (key == (byte)0xF9) {
			slot = slots[SLOT_F9];
		} else {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		if (slot == null) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		if (!slots[SLOT_9B].flags[PivSlot.F_UNLOCKED]) {
			ISOException.throwIt(
			    ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return;
		}

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength()) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}

#if APPLET_EXTLEN
		apduStream.reset(apdu.getOffsetCdata(), lc);
#else
		apduStream.reset(ISO7816.OFFSET_CDATA, lc);
#endif
		tlv.start(apduStream);

		if (tlv.readTag() != (byte)0xAC) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		while (!tlv.atEnd()) {
			tag = tlv.readTag();
			switch (tag) {
			case (byte)0x80:
				if (tlv.tagLength() != 1) {
					ISOException.throwIt(
					    ISO7816.SW_WRONG_DATA);
					return;
				}
				alg = tlv.readByte();
				tlv.end();
				break;
			case (byte)0x81:
				tlv.skip();
				break;
			case (byte)0xab:
				if (tlv.tagLength() != 1) {
					ISOException.throwIt(
					    ISO7816.SW_WRONG_DATA);
					return;
				}
				tag = tlv.readByte();
				if (tag != (byte)0x00 && tag != (byte)0x01) {
					ISOException.throwIt(
					    ISO7816.SW_FUNC_NOT_SUPPORTED);
					return;
				}
				tlv.end();
				break;
			case (byte)0xaa:
				if (tlv.tagLength() != 1) {
					ISOException.throwIt(
					    ISO7816.SW_WRONG_DATA);
					return;
				}
				tag = tlv.readByte();
				switch (tag) {
				case PivSlot.P_DEFAULT:
					if (key == (byte)0x9e) {
						slot.pinPolicy =
						    PivSlot.P_NEVER;
					} else if (key == (byte)0x9c) {
						slot.pinPolicy =
						    PivSlot.P_ALWAYS;
					} else {
						slot.pinPolicy =
						    PivSlot.P_ONCE;
					}
					break;
				case PivSlot.P_NEVER:
				case PivSlot.P_ONCE:
				case PivSlot.P_ALWAYS:
					slot.pinPolicy = tag;
					break;
				default:
					ISOException.throwIt(
					    ISO7816.SW_FUNC_NOT_SUPPORTED);
					return;
				}
				tlv.end();
				break;
			}
		}

		tlv.end();

		if (alg == (byte)0xFF) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		switch (alg) {
#if PIV_SUPPORT_RSA
		case PIV_ALG_RSA1024:
			if (slot.asym == null || slot.asymAlg != alg) {
				slot.asym = new KeyPair(KeyPair.ALG_RSA_CRT,
				    (short)1024);
			}
			slot.asymAlg = alg;
			break;
		case PIV_ALG_RSA2048:
			if (slot.asym == null || slot.asymAlg != alg) {
				slot.asym = new KeyPair(KeyPair.ALG_RSA_CRT,
				    (short)2048);
			}
			slot.asymAlg = alg;
			break;
#endif
#if PIV_SUPPORT_EC
		case PIV_ALG_ECCP256:
			if (ecdsaP256Sha == null && ecdsaP256Sha256 == null) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
			ECPrivateKey ecPriv;
			ECPublicKey ecPub;
			if (slot.asym == null || slot.asymAlg != alg) {
				ecPriv = (ECPrivateKey)KeyBuilder.buildKey(
				    KeyBuilder.TYPE_EC_FP_PRIVATE,
				    (short)256, false);
				ecPub = (ECPublicKey)KeyBuilder.buildKey(
				    KeyBuilder.TYPE_EC_FP_PUBLIC,
				    (short)256, false);
				slot.asym = new KeyPair(
				    (PublicKey)ecPub, (PrivateKey)ecPriv);
				ECParams.setCurveParameters(ecPriv);
				ECParams.setCurveParameters(ecPub);
			}
			slot.asymAlg = alg;
			break;
#endif
		default:
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		slot.asym.genKeyPair();
		slot.imported = false;

		outgoing.reset();
		wtlv.start(outgoing);

		switch (alg) {
#if PIV_SUPPORT_RSA
		case PIV_ALG_RSA1024:
		case PIV_ALG_RSA2048:
			RSAPublicKey rpubk =
			    (RSAPublicKey)slot.asym.getPublic();

			wtlv.push64k((short)0x7F49);

			wtlv.push64k((byte)0x81);
			wtlv.startReserve((short)257, tempBuf);
			cLen = rpubk.getModulus(tempBuf.data, tempBuf.offset());
			wtlv.endReserve(cLen);
			wtlv.pop();

			wtlv.push((byte)0x82);
			wtlv.startReserve((short)9, tempBuf);
			cLen = rpubk.getExponent(tempBuf.data, tempBuf.offset());
			wtlv.endReserve(cLen);
			wtlv.pop();
			break;
#endif
#if PIV_SUPPORT_EC
		case PIV_ALG_ECCP256:
			ECPublicKey epubk =
			    (ECPublicKey)slot.asym.getPublic();

			wtlv.push((short)0x7F49);

			wtlv.push((byte)0x86);
			wtlv.startReserve((short)33, tempBuf);
			cLen = epubk.getW(tempBuf.data, tempBuf.offset());
			wtlv.endReserve(cLen);
			wtlv.pop();
			break;
#endif
		default:
			return;
		}

		wtlv.pop();
		wtlv.end();

		sendOutgoing(apdu);
	}

	private void
	processImportAsym(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		final byte key, alg;
		short lc, len;
		byte tag;
		final PivSlot slot;

		alg = buffer[ISO7816.OFFSET_P1];
		key = buffer[ISO7816.OFFSET_P2];

		if (!slots[SLOT_9B].flags[PivSlot.F_UNLOCKED]) {
			ISOException.throwIt(
			    ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return;
		}

		if (key >= (byte)0x9A && key <= (byte)0x9E) {
			final byte idx = (byte)(key - (byte)0x9A);
			slot = slots[idx];
		} else if (key >= MIN_HIST_SLOT && key <= MAX_HIST_SLOT) {
			final byte idx = (byte)(SLOT_MIN_HIST +
			    (byte)(key - MIN_HIST_SLOT));
			slot = slots[idx];
		} else {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		if (slot == null) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		if (!receiveChain(apdu))
			return;

		tlv.start(incoming);

		switch (alg) {
#if PIV_SUPPORT_RSA
		case PIV_ALG_RSA1024:
			if (slot.asym == null || slot.asymAlg != alg) {
				slot.asym = new KeyPair(KeyPair.ALG_RSA_CRT,
				    (short)1024);
			}
			slot.asymAlg = alg;
			break;
		case PIV_ALG_RSA2048:
			if (slot.asym == null || slot.asymAlg != alg) {
				slot.asym = new KeyPair(KeyPair.ALG_RSA_CRT,
				    (short)2048);
			}
			slot.asymAlg = alg;
			break;
#endif
#if PIV_SUPPORT_EC
		case PIV_ALG_ECCP256:
			if (ecdsaP256Sha == null && ecdsaP256Sha256 == null) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
			ECPrivateKey ecPriv;
			ECPublicKey ecPub;
			if (slot.asym == null || slot.asymAlg != alg) {
				ecPriv = (ECPrivateKey)KeyBuilder.buildKey(
				    KeyBuilder.TYPE_EC_FP_PRIVATE,
				    (short)256, false);
				ecPub = (ECPublicKey)KeyBuilder.buildKey(
				    KeyBuilder.TYPE_EC_FP_PUBLIC,
				    (short)256, false);
				slot.asym = new KeyPair(
				    (PublicKey)ecPub, (PrivateKey)ecPriv);
				ECParams.setCurveParameters(ecPriv);
				ECParams.setCurveParameters(ecPub);
			}
			slot.asymAlg = alg;
			break;
#endif
		default:
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		slot.imported = true;

		switch (alg) {
#if PIV_SUPPORT_RSA
		case PIV_ALG_RSA1024:
		case PIV_ALG_RSA2048:
			final RSAPublicKey rpubk =
			    (RSAPublicKey)slot.asym.getPublic();
			final RSAPrivateCrtKey rprivk =
			    (RSAPrivateCrtKey)slot.asym.getPrivate();
			rpubk.clearKey();
			rprivk.clearKey();

			while (!tlv.atEnd()) {
				tag = tlv.readTag();
				final short tlen = tlv.tagLength();
				switch (tag) {
				case (byte)0x01:
					tlv.read(tempBuf, tlen);
					rprivk.setP(tempBuf.data,
					    tempBuf.offset(), tlen);
					tlv.end();
					break;
				case (byte)0x02:
					tlv.read(tempBuf, tlen);
					rprivk.setQ(tempBuf.data,
					    tempBuf.offset(), tlen);
					tlv.end();
					break;
				case (byte)0x03:
					tlv.read(tempBuf, tlen);
					rprivk.setDP1(tempBuf.data,
					    tempBuf.offset(), tlen);
					tlv.end();
					break;
				case (byte)0x04:
					tlv.read(tempBuf, tlen);
					rprivk.setDQ1(tempBuf.data,
					    tempBuf.offset(), tlen);
					tlv.end();
					break;
				case (byte)0x05:
					tlv.read(tempBuf, tlen);
					rprivk.setPQ(tempBuf.data,
					    tempBuf.offset(), tlen);
					tlv.end();
					break;
				case (byte)0xaa:
					if (tlv.tagLength() != 1) {
						tlv.abort();
						ISOException.throwIt(
						    ISO7816.SW_WRONG_DATA);
						return;
					}
					tag = tlv.readByte();
					tlv.end();
					switch (tag) {
					case PivSlot.P_DEFAULT:
						if (key == (byte)0x9e) {
							slot.pinPolicy =
							    PivSlot.P_NEVER;
						} else if (key == (byte)0x9c) {
							slot.pinPolicy =
							    PivSlot.P_ALWAYS;
						} else {
							slot.pinPolicy =
							    PivSlot.P_ONCE;
						}
						break;
					case PivSlot.P_NEVER:
					case PivSlot.P_ONCE:
					case PivSlot.P_ALWAYS:
						slot.pinPolicy = tag;
						break;
					default:
						tlv.abort();
						ISOException.throwIt(
						    ISO7816.
						    SW_FUNC_NOT_SUPPORTED);
						return;
					}
					break;
				case (byte)0xab:
					if (tlv.tagLength() != 1) {
						tlv.abort();
						ISOException.throwIt(
						    ISO7816.SW_WRONG_DATA);
						return;
					}
					final byte touchPolicy = tlv.readByte();
					tlv.end();
					if (touchPolicy != (byte)0x00 &&
					    touchPolicy != (byte)0x01) {
						tlv.abort();
						ISOException.throwIt(
						    ISO7816.
						    SW_FUNC_NOT_SUPPORTED);
						return;
					}
					break;
				default:
					tlv.abort();
					ISOException.throwIt(
					    ISO7816.SW_WRONG_DATA);
					return;
				}
			}
			break;
#endif
#if PIV_SUPPORT_EC
		case PIV_ALG_ECCP256:
			final ECPublicKey epubk =
			    (ECPublicKey)slot.asym.getPublic();
			final ECPrivateKey eprivk =
			    (ECPrivateKey)slot.asym.getPrivate();
			epubk.clearKey();
			eprivk.clearKey();

			while (!tlv.atEnd()) {
				tag = tlv.readTag();
				final short tlen = tlv.tagLength();
				switch (tag) {
				case (byte)0x06:
					tlv.read(tempBuf, tlen);
					eprivk.setS(tempBuf.data,
					    tempBuf.offset(), tlen);
					tlv.end();
					break;
				case (byte)0xaa:
					if (tlv.tagLength() != 1) {
						tlv.abort();
						ISOException.throwIt(
						    ISO7816.SW_WRONG_DATA);
						return;
					}
					tag = tlv.readByte();
					tlv.end();
					switch (tag) {
					case PivSlot.P_DEFAULT:
						if (key == (byte)0x9e) {
							slot.pinPolicy =
							    PivSlot.P_NEVER;
						} else if (key == (byte)0x9c) {
							slot.pinPolicy =
							    PivSlot.P_ALWAYS;
						} else {
							slot.pinPolicy =
							    PivSlot.P_ONCE;
						}
						break;
					case PivSlot.P_NEVER:
					case PivSlot.P_ONCE:
					case PivSlot.P_ALWAYS:
						slot.pinPolicy = tag;
						break;
					default:
						tlv.abort();
						ISOException.throwIt(
						    ISO7816.
						    SW_FUNC_NOT_SUPPORTED);
						return;
					}
					break;
				case (byte)0xab:
					if (tlv.tagLength() != 1) {
						tlv.abort();
						ISOException.throwIt(
						    ISO7816.SW_WRONG_DATA);
						return;
					}
					final byte touchPolicy = tlv.readByte();
					tlv.end();
					if (touchPolicy != (byte)0x00 &&
					    touchPolicy != (byte)0x01) {
						tlv.abort();
						ISOException.throwIt(
						    ISO7816.
						    SW_FUNC_NOT_SUPPORTED);
						return;
					}
					break;
				default:
					tlv.abort();
					ISOException.throwIt(
					    ISO7816.SW_WRONG_DATA);
					return;
				}
			}
			break;
#endif
		default:
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		tlv.finish();

		if (!slot.asym.getPrivate().isInitialized()) {
			slot.asym.getPrivate().clearKey();
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}
	}

	private void
	processSetMgmtKey(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		short lc, len, off;

		if (buffer[ISO7816.OFFSET_P1] != (byte)0xFF ||
		    buffer[ISO7816.OFFSET_P2] != (byte)0xFF) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		if (!slots[SLOT_9B].flags[PivSlot.F_UNLOCKED]) {
			ISOException.throwIt(
			    ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return;
		}

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength()) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}
		if (lc != 27) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

#if APPLET_EXTLEN
		off = apdu.getOffsetCdata();
#else
		off = ISO7816.OFFSET_CDATA;
#endif
		final byte alg = buffer[off++];
		final byte key = buffer[off++];
		final byte keyLen = buffer[off++];

		if (alg != PIV_ALG_3DES || key != (byte)0x9b ||
		    keyLen != (byte)24) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		final DESKey dk = (DESKey)slots[SLOT_9B].sym;
		dk.setKey(buffer, off);
	}

	private void
	processGeneralAuth(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		final byte key;
		byte alg, tag, wanted = 0;
		short lc, le, len, cLen;
		final PivSlot slot;
		final Cipher ci;
		final Signature si;

		alg = buffer[ISO7816.OFFSET_P1];
		key = buffer[ISO7816.OFFSET_P2];

		if (key >= (byte)0x9A && key <= (byte)0x9E) {
			final byte idx = (byte)(key - (byte)0x9A);
			slot = slots[idx];
		} else if (key >= MIN_HIST_SLOT && key <= MAX_HIST_SLOT) {
			final byte idx = (byte)(SLOT_MIN_HIST +
			    (byte)(key - MIN_HIST_SLOT));
			slot = slots[idx];
		} else {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		if (slot == null) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		if (slot.pinPolicy != PivSlot.P_NEVER &&
		    !slot.flags[PivSlot.F_UNLOCKED]) {
			ISOException.throwIt(
			    ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return;
		}

		if (!isContact() && slot.cert != null &&
		    slot.cert.contactless == File.P_NEVER) {
			ISOException.throwIt(
			    ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return;
		}

		if (!receiveChain(apdu))
			return;

		tlv.start(incoming);

		if (tlv.readTag() != (byte)0x7C) {
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		switch (alg) {
		case PIV_ALG_DEFAULT:
		case PIV_ALG_3DES:
			alg = PIV_ALG_3DES;
			if (slot.symAlg != alg || slot.sym == null) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				return;
			}
			len = (short)8;
			break;
		case PIV_ALG_AES128:
			if (slot.symAlg != alg || slot.sym == null) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				return;
			}
			len = (short)16;
			break;
		case PIV_ALG_RSA1024:
		case PIV_ALG_RSA2048:
		case PIV_ALG_ECCP256:
			if (slot.asymAlg != alg || slot.asym == null) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				return;
			}
			len = (short)0;
			break;
		case PIV_ALG_ECCP256_SHA1:
		case PIV_ALG_ECCP256_SHA256:
			if (slot.asymAlg != PIV_ALG_ECCP256 ||
			    slot.asym == null) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				return;
			}
			len = (short)0;
			break;
		default:
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		switch (alg) {
		case PIV_ALG_3DES:
			ci = tripleDes;
			break;
		case PIV_ALG_RSA1024:
		case PIV_ALG_RSA2048:
			ci = rsaPkcs1;
			if (ci == null) {
				tlv.abort();
				ISOException.throwIt(
				    ISO7816.SW_FUNC_NOT_SUPPORTED);
				return;
			}
			break;
		default:
			ci = null;
			break;
		}

		/*
		 * First, scan through the TLVs to figure out what the host
		 * actually wants from us.
		 */
		while (!tlv.atEnd()) {
			tag = tlv.readTag();
			if (tlv.tagLength() == 0) {
				wanted = tag;
				break;
			}
			tlv.skip();
		}

		/* Now rewind, let's figure out what to do */
		tlv.rewind();
		tlv.readTag(); /* The 0x7C outer tag */

		tag = tlv.readTag();
		if (tag == wanted) {
			tlv.skip();
			if (!tlv.atEnd())
				tag = tlv.readTag();
		}

		if (wanted == (byte)0) {
			if (key != (byte)0x9b) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				return;
			}

			byte comp = -1;
			if (tag == GA_TAG_RESPONSE) {
				ci.init(slot.sym, Cipher.MODE_DECRYPT, iv,
				    (short)0, len);
				tlv.read(tempBuf, len);
				incoming.startReserve(len, outBuf);
				cLen = ci.doFinal(tempBuf.data, tempBuf.offset(),
				    len, outBuf.data, outBuf.offset());

				if (tlv.tagLength() == 0) {
					comp = Util.arrayCompare(outBuf.data,
					    outBuf.offset(), challenge,
					    (short)0, cLen);
					tlv.end();
				}

			} else if (tag == GA_TAG_WITNESS) {
				if (tlv.tagLength() == len) {
					tlv.read(tempBuf, len);
					comp = Util.arrayCompare(tempBuf.data,
					    tempBuf.offset(), challenge,
					    (short)0, len);
					tlv.end();
				}

			} else {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}

			if (comp == 0) {
				slot.flags[PivSlot.F_UNLOCKED] = true;
			} else {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}

			if (tlv.atEnd()) {
				tlv.end();
				tlv.finish();
				ISOException.throwIt(ISO7816.SW_NO_ERROR);
				return;
			}
			tag = tlv.readTag();
			if (tag == GA_TAG_CHALLENGE)
				wanted = GA_TAG_RESPONSE;
		}

		switch (wanted) {
		case GA_TAG_CHALLENGE:
			if (key != (byte)0x9b) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				return;
			}
			/*
			 * The host is asking us for a challenge value
			 * for them to encrypt and return in a RESPONSE
			 */
			outgoing.reset();
			wtlv.start(outgoing);

			randData.generateData(challenge, (short)0, len);
			/*for (byte i = 0; i < (byte)len; ++i)
				challenge[i] = (byte)(i + 1);*/

			wtlv.push((byte)0x7C);

			wtlv.push(GA_TAG_CHALLENGE);
			wtlv.write(challenge, (short)0, len);
			wtlv.pop();

			wtlv.pop();

			wtlv.end();
			sendOutgoing(apdu);
			break;

		case GA_TAG_WITNESS:
			if (key != (byte)0x9b) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
				return;
			}

			outgoing.reset();
			wtlv.start(outgoing);

			randData.generateData(challenge, (short)0, len);
			/*for (byte i = 0; i < (byte)len; ++i)
				challenge[i] = (byte)(i + 1);*/

			wtlv.push((byte)0x7C);

			wtlv.push(GA_TAG_WITNESS);
			ci.init(slot.sym, Cipher.MODE_ENCRYPT, iv,
			    (short)0, len);
			wtlv.startReserve(len, tempBuf);
			cLen = ci.doFinal(challenge, (short)0, len,
			    tempBuf.data, tempBuf.offset());
			wtlv.endReserve(cLen);
			wtlv.pop();

			wtlv.pop();
			wtlv.end();
			sendOutgoing(apdu);
			break;

		case GA_TAG_RESPONSE:
			if (tag == GA_TAG_EXP) {
#if PIV_SUPPORT_EC
				KeyAgreement ag;

				if (alg == PIV_ALG_ECCP256_SHA1) {
					ag = ecdhSha;
				} else if (alg == PIV_ALG_ECCP256) {
					ag = ecdh;
				} else {
					tlv.abort();
					ISOException.throwIt(
					    ISO7816.SW_WRONG_DATA);
					return;
				}
				if (ag == null) {
					tlv.abort();
					ISOException.throwIt(
					    ISO7816.SW_FUNC_NOT_SUPPORTED);
					return;
				}

				incoming.steal((short)257, outBuf);

				cLen = tlv.read(tempBuf, tlv.tagLength());
				tlv.end();

				ag.init(slot.asym.getPrivate());
				cLen = ag.generateSecret(tempBuf.data,
				    tempBuf.offset(), cLen,
				    outBuf.data, outBuf.offset());

				outgoing.reset();
				wtlv.start(outgoing);

				wtlv.push((byte)0x7C, (short)(cLen + 4));
				wtlv.push(GA_TAG_RESPONSE, cLen);
				wtlv.write(outBuf.data, outBuf.offset(), cLen);
				wtlv.pop();

				wtlv.pop();
				wtlv.end();
				sendOutgoing(apdu);
				break;
#endif
			}
			if (tag != GA_TAG_CHALLENGE) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
			final short sLen = tlv.tagLength();
			cLen = tlv.tagLength();
			switch (alg) {
			case PIV_ALG_RSA1024:
				cLen = (short)128;
				break;
			case PIV_ALG_RSA2048:
				cLen = (short)256;
				break;
			case PIV_ALG_ECCP256:
			case PIV_ALG_ECCP256_SHA1:
			case PIV_ALG_ECCP256_SHA256:
				cLen = (short)256;
				break;
			}
			incoming.steal(cLen, outBuf);

			if (slot.symAlg == alg) {
				tlv.read(tempBuf, sLen);
				tlv.end();
				ci.init(slot.sym, Cipher.MODE_ENCRYPT,
				    iv, (short)0, len);
				cLen = ci.doFinal(tempBuf.data,
				    tempBuf.offset(), sLen,
				    outBuf.data, outBuf.offset());

#if PIV_SUPPORT_RSA
			} else if (slot.asymAlg == alg && (
			    alg == PIV_ALG_RSA1024 || alg == PIV_ALG_RSA2048)) {
				tlv.read(tempBuf, sLen);
				tlv.end();
				ci.init(slot.asym.getPrivate(),
				    Cipher.MODE_ENCRYPT);
				cLen = ci.doFinal(tempBuf.data,
				    tempBuf.offset(), sLen,
				    outBuf.data, outBuf.offset());
#endif

#if PIV_SUPPORT_EC

#if PIV_USE_EC_PRECOMPHASH
			} else if (slot.asymAlg == alg &&
			    alg == PIV_ALG_ECCP256) {
				if (sLen == 20) {
					si = ecdsaP256Sha;
				} else if (sLen == 32) {
					si = ecdsaP256Sha256;
				} else {
					tlv.abort();
					ISOException.throwIt(
					    ISO7816.SW_WRONG_DATA);
					return;
				}
				tlv.read(tempBuf, sLen);
				tlv.end();

				si.init(slot.asym.getPrivate(),
				    Signature.MODE_SIGN);
				cLen = si.signPreComputedHash(tempBuf.data,
				    tempBuf.offset(), sLen,
				    outBuf.data, outBuf.offset());
#endif

			} else if (slot.asymAlg == PIV_ALG_ECCP256) {
				switch (alg) {
				case PIV_ALG_ECCP256_SHA256:
					si = ecdsaP256Sha256;
					break;
				case PIV_ALG_ECCP256_SHA1:
					si = ecdsaP256Sha;
					break;
				default:
					tlv.abort();
					ISOException.throwIt(
					    ISO7816.SW_WRONG_DATA);
					return;
				}

				si.init(slot.asym.getPrivate(),
				    Signature.MODE_SIGN);
				short done = (short)0;
				while (done < sLen) {
					final short read =
					    tlv.readPartial(tempBuf, sLen);
					si.update(tempBuf.data, tempBuf.offset(),
					    read);
					done += read;
				}
				tlv.end();
				cLen = si.sign(null, (short)0, (short)0,
				    outBuf.data, outBuf.offset());
#endif
			} else {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}

			outgoing.reset();
			wtlv.start(outgoing);

			wtlv.push((byte)0x7C, (short)(cLen + 4));
			wtlv.push(GA_TAG_RESPONSE, cLen);
			wtlv.write(outBuf.data, outBuf.offset(), cLen);
			wtlv.pop();

			wtlv.pop();
			wtlv.end();
			sendOutgoing(apdu);
			break;

		default:
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		tlv.end();
		tlv.finish();
	}

	private void
	processVerify(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		short lc, pinOff, idx;
		final OwnerPIN pin;

		if (buffer[ISO7816.OFFSET_P1] != (byte)0x00 &&
		    buffer[ISO7816.OFFSET_P1] != (byte)0xFF) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		switch (buffer[ISO7816.OFFSET_P2]) {
		case (byte)0x80:
			pin = pivPin;
			break;
		case (byte)0x81:
			pin = pukPin;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength()) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}
#if APPLET_EXTLEN
		pinOff = apdu.getOffsetCdata();
#else
		pinOff = ISO7816.OFFSET_CDATA;
#endif

		if (lc == 0 && pin.isValidated()) {
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
			return;
		} else if (lc == 0) {
			ISOException.throwIt((short)(
			    (short)0x63C0 | pin.getTriesRemaining()));
			return;
		}

		if (lc != 8) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		if (!pin.check(buffer, pinOff, (byte)8)) {
			if (pukPin.getTriesRemaining() == 0) {
				for (idx = (short)0; idx < MAX_SLOTS; ++idx) {
					final PivSlot slot = slots[idx];
					if (slot == null)
						continue;
					if (slot.asym == null)
						continue;
					slot.asym.getPrivate().clearKey();
				}
			}
			ISOException.throwIt((short)(
			    (short)0x63C0 | pin.getTriesRemaining()));
			return;
		}

		for (idx = (short)0; idx < MAX_SLOTS; ++idx) {
			final PivSlot slot = slots[idx];
			if (slot == null)
				continue;
			if (idx == SLOT_9B)
				continue;
			slot.flags[PivSlot.F_UNLOCKED] = true;
			slot.flags[PivSlot.F_AFTER_VERIFY] = false;
		}
	}

	private void
	processChangePin(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		short lc, oldPinOff, newPinOff, idx;
		final OwnerPIN pin;

		if (buffer[ISO7816.OFFSET_P1] != (byte)0x00) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		switch (buffer[ISO7816.OFFSET_P2]) {
		case (byte)0x80:
			pin = pivPin;
			break;
		case (byte)0x81:
			pin = pukPin;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength()) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}

#if APPLET_EXTLEN
		oldPinOff = apdu.getOffsetCdata();
#else
		oldPinOff = ISO7816.OFFSET_CDATA;
#endif
		if (lc != 16) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		if (!pin.isValidated() &&
		    !pin.check(buffer, oldPinOff, (byte)8)) {
			ISOException.throwIt((short)(
			    (short)0x63C0 | pin.getTriesRemaining()));
			return;
		}

		newPinOff = (short)(oldPinOff + 8);
		for (idx = newPinOff; idx < (short)(newPinOff + 6); ++idx) {
			if (buffer[idx] < (byte)0x30 ||
			    buffer[idx] > (byte)0x39) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
		}
		for (; idx < (short)(newPinOff + 8); ++idx) {
			if (buffer[idx] != (byte)0xFF && (
			    buffer[idx] < (byte)0x30 ||
			    buffer[idx] > (byte)0x39)) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
		}
		pin.update(buffer, newPinOff, (byte)8);
	}

	private void
	processResetPin(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		short lc, pukOff, newPinOff, idx;
		final OwnerPIN pin;

		if (buffer[ISO7816.OFFSET_P1] != (byte)0x00) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		switch (buffer[ISO7816.OFFSET_P2]) {
		case (byte)0x80:
			pin = pivPin;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength()) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}

#if APPLET_EXTLEN
		pukOff = apdu.getOffsetCdata();
#else
		pukOff = ISO7816.OFFSET_CDATA;
#endif
		if (lc != 16) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		if (!pukPin.isValidated() &&
		    !pukPin.check(buffer, pukOff, (byte)8)) {
			ISOException.throwIt((short)(
			    (short)0x63C0 | pukPin.getTriesRemaining()));
			return;
		}

		newPinOff = (short)(pukOff + 8);
		for (idx = newPinOff; idx < (short)(newPinOff + 6); ++idx) {
			if (buffer[idx] < (byte)0x30 ||
			    buffer[idx] > (byte)0x39) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
		}
		for (; idx < (short)(newPinOff + 8); ++idx) {
			if (buffer[idx] != (byte)0xFF && (
			    buffer[idx] < (byte)0x30 ||
			    buffer[idx] > (byte)0x39)) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}
		}
		pin.update(buffer, newPinOff, (byte)8);
		pin.resetAndUnblock();
	}

	private void
	processSetPinRetries(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		final byte pinTries = buffer[ISO7816.OFFSET_P1];
		final byte pukTries = buffer[ISO7816.OFFSET_P2];

		if (!slots[SLOT_9B].flags[PivSlot.F_UNLOCKED]) {
			ISOException.throwIt(
			    ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return;
		}

		if (!pivPin.isValidated()) {
			ISOException.throwIt(
			    ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return;
		}

		pivPin = new OwnerPIN(pinTries, (byte)8);
		pivPin.update(DEFAULT_PIN, (short)0, (byte)8);
		pukPin = new OwnerPIN(pukTries, (byte)8);
		pukPin.update(DEFAULT_PUK, (short)0, (byte)8);
	}

	private void
	processReset(APDU apdu)
	{
		byte idx;

		if (pivPin.getTriesRemaining() > (byte)0 ||
		    pukPin.getTriesRemaining() > (byte)0) {
			ISOException.throwIt(
			    ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return;
		}

		for (idx = (byte)0; idx < MAX_SLOTS; ++idx) {
			final PivSlot slot = slots[idx];
			if (slot == null)
				continue;
			if (slot.asym != null)
				slot.asym.getPrivate().clearKey();
			slot.asymAlg = (byte)-1;
			slot.imported = false;
			if (slot.cert != null) {
				slot.cert.len = (short)0;
			}
		}

		for (idx = (byte)0; idx < TAG_MAX; ++idx) {
			final File file = files[idx];
			if (file == null)
				continue;
			file.len = (short)0;
		}

		final DESKey dk = (DESKey)slots[SLOT_9B].sym;
		dk.setKey(DEFAULT_ADMIN_KEY, (short)0);

		pivPin = new OwnerPIN((byte)5, (byte)8);
		pivPin.update(DEFAULT_PIN, (short)0, (byte)8);
		pukPin = new OwnerPIN((byte)3, (byte)8);
		pukPin.update(DEFAULT_PUK, (short)0, (byte)8);

		randData.generateData(guid, (short)0, (short)16);

		randData.generateData(cardId, (short)CARD_ID_FIXED.length,
		    (short)(21 - (short)CARD_ID_FIXED.length));

		randData.generateData(serial, (short)0, (short)4);
		serial[0] |= (byte)0x80;

		initCARDCAP();
		initCHUID();
		initKEYHIST();
#if YKPIV_ATTESTATION
		initAttestation();
#endif

		try {
			JCSystem.requestObjectDeletion();
		} catch (Exception e) {
			incoming.gcBlewUp = true;
		}
	}

	private void
	processPutData(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		short lc;
		byte tag;
		PivSlot slot;

		if (buffer[ISO7816.OFFSET_P1] != (byte)0x3F ||
		    buffer[ISO7816.OFFSET_P2] != (byte)0xFF) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		if (!receiveChain(apdu))
			return;
		tlv.start(incoming);

		if (tlv.readTag() != (byte)0x5C) {
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		if (!slots[SLOT_9B].flags[PivSlot.F_UNLOCKED]) {
			tlv.abort();
			ISOException.throwIt(
			    ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return;
		}

		final short taglen = tlv.tagLength();

		if (taglen == (short)3) {
			final byte tag0 = tlv.readByte();
			final byte tag1 = tlv.readByte();
			final byte tag2 = tlv.readByte();
			final File file;

			if (tag0 != (short)0x5F) {
				ISOException.throwIt(
				    ISO7816.SW_FUNC_NOT_SUPPORTED);
				return;
			}

			if (tag1 == (byte)0xFF) {
				if (tag2 < 0 || tag2 > YK_TAG_MAX) {
					file = null;
				} else {
					if (ykFiles[tag2] == null)
						ykFiles[tag2] = new File();
					file = ykFiles[tag2];
				}
			} else if (tag1 == (byte)0xC1) {
				if (tag2 < 0 || tag2 > TAG_MAX) {
					file = null;
				} else {
					if (files[tag2] == null)
						files[tag2] = new File();
					file = files[tag2];
				}
			} else {
				file = null;
			}
			tlv.end();

			if (file == null) {
				ISOException.throwIt(
				    ISO7816.SW_FUNC_NOT_SUPPORTED);
				return;
			}

			if (tlv.readTag() != (byte)0x53) {
				tlv.abort();
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				return;
			}

			boolean needGC = false;
			final short len = tlv.tagLength();
			if (file.data == null)
				file.data = new byte[len];
			if (file.data.length < len) {
				file.data = new byte[len];
				needGC = true;
			}
			file.len = tlv.read(file.data, (short)0, len);
			tlv.end();
			tlv.finish();

			if (needGC && !incoming.gcBlewUp) {
				try {
					JCSystem.requestObjectDeletion();
				} catch (Exception e) {
					incoming.gcBlewUp = true;
				}
			}
			incoming.cullNonTransient();

		} else {
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
		}
	}

	private void
	processGetData(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		short lc;
		byte tag;

		if (buffer[ISO7816.OFFSET_P1] != (byte)0x3F ||
		    buffer[ISO7816.OFFSET_P2] != (byte)0xFF) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		lc = apdu.setIncomingAndReceive();
		if (lc != apdu.getIncomingLength()) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}

#if APPLET_EXTLEN
		apduStream.reset(apdu.getOffsetCdata(), lc);
#else
		apduStream.reset(ISO7816.OFFSET_CDATA, lc);
#endif
		tlv.start(apduStream);

		tag = tlv.readTag();
		if (tag != (byte)0x5C) {
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
		}

		final short taglen = tlv.tagLength();

		if (taglen == (short)3) {
			final byte tag0 = tlv.readByte();
			final byte tag1 = tlv.readByte();
			final byte tag2 = tlv.readByte();
			final File file;

			if (tag0 != (short)0x5F) {
				ISOException.throwIt(
				    ISO7816.SW_FILE_NOT_FOUND);
				return;
			}

			if (tag1 == (byte)0xFF) {
				if (tag2 < 0 || tag2 > YK_TAG_MAX) {
					file = null;
				} else {
					file = ykFiles[tag2];
				}
			} else if (tag1 == (byte)0xC1) {
				if (tag2 < 0 || tag2 > TAG_MAX) {
					file = null;
				} else {
					file = files[tag2];
				}
			} else {
				file = null;
			}
			tlv.end();
			tlv.finish();

			if (file == null || file.data == null ||
			    file.len == 0) {
				ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
				return;
			}

			final byte policy;
			if (isContact())
				policy = file.contact;
			else
				policy = file.contactless;

			if (policy == File.P_NEVER) {
				ISOException.throwIt(
				    ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				return;
			}

			if (policy == File.P_PIN && !pivPin.isValidated()) {
				ISOException.throwIt(
				    ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				return;
			}

			outgoing.reset();
			wtlv.start(outgoing);
			wtlv.push((byte)0x53, file.len);
			wtlv.write(file.data, (short)0, file.len);
			wtlv.pop();
			wtlv.end();
			sendOutgoing(apdu);

		} else if (taglen == (short)1 &&
		    tlv.readByte() == (byte)0x7E) {
			tlv.end();
			tlv.finish();
			/* The special discovery object */
			sendDiscoveryObject(apdu);

		} else {
			tlv.abort();
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		}
	}

	private void
	sendDiscoveryObject(APDU apdu)
	{
		outgoing.reset();
		wtlv.start(outgoing);

		wtlv.push((byte)0x7E);

		/* AID */
		wtlv.push((byte)0x4F);
		wtlv.write(PIV_AID, (short)0, (short)PIV_AID.length);
		wtlv.pop();

		/* PIN policy */
		wtlv.push((short)0x5F2F);
		wtlv.writeByte((byte)0x40);	/* PIV pin only, no others */
		wtlv.writeByte((byte)0x00);	/* RFU, since no global PIN */
		wtlv.pop();

		wtlv.pop();
		wtlv.end();
		sendOutgoing(apdu);
	}

	private void
	initCARDCAP()
	{
		outgoing.reset();
		wtlv.start(outgoing);

		/* Card Identifier */
		wtlv.push((byte)0xF0);
		wtlv.write(cardId, (short)0, (short)cardId.length);
		wtlv.pop();

		/* Container version number */
		wtlv.push((byte)0xF1);
		wtlv.writeByte((byte)0x21);
		wtlv.pop();
		wtlv.push((byte)0xF2);
		wtlv.writeByte((byte)0x21);
		wtlv.pop();

		wtlv.push((byte)0xF3);
		wtlv.pop();

		wtlv.push((byte)0xF4);
		wtlv.pop();

		/* Data Model Number */
		wtlv.push((byte)0xF5);
		wtlv.writeByte((byte)0x10);
		wtlv.pop();

		wtlv.push((byte)0xF6);
		wtlv.pop();

		wtlv.push((byte)0xF7);
		wtlv.pop();

		wtlv.push((byte)0xFA);
		wtlv.pop();

		wtlv.push((byte)0xFB);
		wtlv.pop();

		wtlv.push((byte)0xFC);
		wtlv.pop();

		wtlv.push((byte)0xFD);
		wtlv.pop();

		wtlv.push((byte)0xFE);
		wtlv.pop();

		wtlv.end();

		final short len = outgoing.available();

		if (files[TAG_CARDCAP] == null)
			files[TAG_CARDCAP] = new File();
		final File f = files[TAG_CARDCAP];
		f.len = len;
		if (f.data == null || f.data.length < len)
			f.data = new byte[len];
		outgoing.read(f.data, (short)0, len);
	}

	private void
	initCHUID()
	{
		outgoing.reset();
		wtlv.start(outgoing);

		/* FASC-N identifier */
		wtlv.push((byte)0x30);
		wtlv.write(fascn, (short)0, (short)fascn.length);
		wtlv.pop();

		/* Card GUID */
		wtlv.push((byte)0x34);
		wtlv.write(guid, (short)0, (short)guid.length);
		wtlv.pop();

		/* Expiry date */
		wtlv.push((byte)0x35);
		wtlv.write(expiry, (short)0, (short)expiry.length);
		wtlv.pop();

		/* Issuer signature */
		wtlv.push((byte)0x3E);
		wtlv.pop();

		wtlv.push((byte)0xFE);
		wtlv.pop();

		wtlv.end();

		final short len = outgoing.available();

		if (files[TAG_CHUID] == null)
			files[TAG_CHUID] = new File();
		final File f = files[TAG_CHUID];
		f.len = len;
		if (f.data == null || f.data.length < len)
			f.data = new byte[len];
		outgoing.read(f.data, (short)0, len);
	}

	private void
	initKEYHIST()
	{
		outgoing.reset();
		wtlv.start(outgoing);

		wtlv.push((byte)0xC1);
		wtlv.writeByte(retiredKeys);
		wtlv.pop();

		wtlv.push((byte)0xC2);
		wtlv.writeByte((byte)0);
		wtlv.pop();

		wtlv.push((byte)0xFE);
		wtlv.pop();

		wtlv.end();

		final short len = outgoing.available();

		if (files[TAG_KEYHIST] == null)
			files[TAG_KEYHIST] = new File();
		final File f = files[TAG_KEYHIST];
		f.len = len;
		if (f.data == null || f.data.length < len)
			f.data = new byte[len];
		outgoing.read(f.data, (short)0, len);
	}

#if YKPIV_ATTESTATION
	private void
	initAttestation()
	{
		final PivSlot atslot = slots[SLOT_F9];

#if PIV_SUPPORT_EC
		if (ecdsaP256Sha != null || ecdsaP256Sha256 != null) {
			atslot.asymAlg = PIV_ALG_ECCP256;
			final ECPrivateKey ecPriv;
			final ECPublicKey ecPub;
			ecPriv = (ECPrivateKey)KeyBuilder.buildKey(
			    KeyBuilder.TYPE_EC_FP_PRIVATE,
			    (short)256, false);
			ecPub = (ECPublicKey)KeyBuilder.buildKey(
			    KeyBuilder.TYPE_EC_FP_PUBLIC,
			    (short)256, false);
			atslot.asym = new KeyPair(
			    (PublicKey)ecPub, (PrivateKey)ecPriv);
			ECParams.setCurveParameters(ecPriv);
			ECParams.setCurveParameters(ecPub);
		} else {
			return;
		}
		atslot.asym.genKeyPair();
		atslot.imported = false;

		try {
			writeAttestationCert(atslot);
		} catch (Exception ex) {
			/* Ignore it, we just won't make a self-signed one */
			outgoing.reset();
			incoming.reset();
			incoming.cullNonTransient();
			return;
		}

		final short len = outgoing.available();
		final File file = atslot.cert;

		if (file.data == null || file.data.length < len)
			file.data = new byte[len];
		file.len = outgoing.read(file.data, (short)0, len);

		outgoing.reset();
		incoming.reset();
		incoming.cullNonTransient();
#endif
	}

	private static final byte ASN1_SEQ = (byte)0x30;
	private static final byte ASN1_SET = (byte)0x31;
	private static final byte ASN1_INTEGER = (byte)0x02;
	private static final byte ASN1_NULL = (byte)0x05;
	private static final byte ASN1_OID = (byte)0x06;
	private static final byte ASN1_UTF8STRING = (byte)0x0c;
	private static final byte ASN1_GENTIME = (byte)0x18;
	private static final byte ASN1_BITSTRING = (byte)0x03;
	private static final byte ASN1_OCTETSTRING = (byte)0x04;

	private static final byte ASN1_APP_0 = (byte)0xA0;
	private static final byte ASN1_APP_3 = (byte)0xA3;

#if PIV_SUPPORT_RSA
	private static final byte[] OID_RSA = {
	    (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0x86, (byte)0xF7,
	    (byte)0x0D, (byte)0x01, (byte)0x01, (byte)0x01
	};
	private static final byte[] OID_RSA_SHA = {
	    (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0x86, (byte)0xF7,
	    (byte)0x0D, (byte)0x01, (byte)0x01, (byte)0x05
	};
	private static final byte[] OID_RSA_SHA256 = {
	    (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0x86, (byte)0xF7,
	    (byte)0x0D, (byte)0x01, (byte)0x01, (byte)0x0B
	};
#endif
#if PIV_SUPPORT_EC
	private static final byte[] OID_ECDSA_SHA = {
	    (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D,
	    (byte)0x04, (byte)0x01
	};
	private static final byte[] OID_ECDSA_SHA256 = {
	    (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D,
	    (byte)0x04, (byte)0x03, (byte)0x02
	};
#endif

	private static final byte[] OID_CN = {
	    (byte)0x55, (byte)0x04, (byte)0x03
	};
#if PIV_SUPPORT_EC
	private static final byte[] OID_ECPUBKEY = {
	    (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D,
	    (byte)0x02, (byte)0x01
	};
	private static final byte[] OID_SECP256 = {
	    (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D,
	    (byte)0x03, (byte)0x01, (byte)0x07
	};
#endif
	private static final byte[] OID_YUBICOX = {
	    (byte)0x2B, (byte)0x06, (byte)0x01, (byte)0x04, (byte)0x01,
	    (byte)0x82, (byte)0xC4, (byte)0x0A, (byte)0x03
	};

	private static final byte[] X509_NOTBEFORE = {
	    '2', '0', '1', '8', '0', '1', '0', '1',
	    '0', '0', '0', '0', '0', '0', 'Z'
	};
	private static final byte[] X509_NOTAFTER = {
	    '2', '0', '5', '0', '0', '1', '0', '1',
	    '0', '0', '0', '0', '0', '0', 'Z'
	};

	private static final byte[] CN_STRING = {
	    'P', 'I', 'V', 'A', 'p', 'p', 'l', 'e', 't', ' ',
	    'A', 't', 't', 'e', 's', 't', 'a', 't', 'i', 'o', 'n'
	};

	private void
	writeHex(byte val)
	{
		final byte lowNybble = (byte)(val & (byte)0x0F);
		final byte highNybble = (byte)((byte)(val >> 4) & (byte)0xF);
		final byte hexLow;
		if (lowNybble <= (byte)9)
			hexLow = (byte)('0' + lowNybble);
		else
			hexLow = (byte)('A' + (byte)(lowNybble - (byte)0xA));
		final byte hexHigh;
		if (highNybble <= (byte)9)
			hexHigh = (byte)('0' + highNybble);
		else
			hexHigh = (byte)('A' + (byte)(highNybble - (byte)0xA));
		wtlv.writeByte(hexHigh);
		wtlv.writeByte(hexLow);
	}

	private void
	writeX509CertInfo(PivSlot slot)
	{
		short len;
		final PivSlot atslot = slots[SLOT_F9];

		wtlv.push64k(ASN1_SEQ);

		/* Version */
		wtlv.push(ASN1_APP_0);
		wtlv.push(ASN1_INTEGER);
		wtlv.writeByte((byte)0x02);
		wtlv.pop();
		wtlv.pop();

		/* Serial */
		wtlv.push(ASN1_INTEGER);
		wtlv.write(certSerial, (short)0, (short)certSerial.length);
		wtlv.pop();

		/* Signature alg */
		wtlv.push(ASN1_SEQ);
#if PIV_SUPPORT_RSA
		if (atslot.asymAlg == PIV_ALG_RSA1024 ||
		    atslot.asymAlg == PIV_ALG_RSA2048) {
			wtlv.push(ASN1_OID);
			if (rsaSha256 != null) {
				wtlv.write(OID_RSA_SHA256, (short)0,
				    (short)OID_RSA_SHA256.length);
			} else if (rsaSha != null) {
				wtlv.write(OID_RSA_SHA, (short)0,
				    (short)OID_RSA_SHA.length);
			}
			wtlv.pop();
			wtlv.push(ASN1_NULL);
			wtlv.pop();
		}
#endif
#if PIV_SUPPORT_EC
		if (atslot.asymAlg == PIV_ALG_ECCP256) {
			wtlv.push(ASN1_OID);
			if (ecdsaP256Sha256 != null) {
				wtlv.write(OID_ECDSA_SHA256, (short)0,
				    (short)OID_ECDSA_SHA256.length);
			} else if (ecdsaP256Sha != null) {
				wtlv.write(OID_ECDSA_SHA, (short)0,
				    (short)OID_ECDSA_SHA.length);
			}
			wtlv.pop();
		}
#endif
		wtlv.pop();

		/* Issuer */
		wtlv.push(ASN1_SEQ);
		wtlv.push(ASN1_SET);
		wtlv.push(ASN1_SEQ);
		wtlv.push(ASN1_OID);
		wtlv.write(OID_CN, (short)0, (short)OID_CN.length);
		wtlv.pop();
		wtlv.push(ASN1_UTF8STRING);
		wtlv.write(CN_STRING, (short)0, (short)CN_STRING.length);
		wtlv.pop();
		wtlv.pop();
		wtlv.pop();
		wtlv.pop();

		/* Validity */
		wtlv.push(ASN1_SEQ);
		wtlv.push(ASN1_GENTIME);
		wtlv.write(X509_NOTBEFORE, (short)0,
		    (short)X509_NOTBEFORE.length);
		wtlv.pop();
		wtlv.push(ASN1_GENTIME);
		wtlv.write(X509_NOTAFTER, (short)0,
		    (short)X509_NOTAFTER.length);
		wtlv.pop();
		wtlv.pop();

		/* Subject */
		wtlv.push(ASN1_SEQ);
		wtlv.push(ASN1_SET);
		wtlv.push(ASN1_SEQ);
		wtlv.push(ASN1_OID);
		wtlv.write(OID_CN, (short)0, (short)OID_CN.length);
		wtlv.pop();
		wtlv.push(ASN1_UTF8STRING);
		wtlv.write(CN_STRING, (short)0, (short)CN_STRING.length);
		if (slot.id != (byte)0xF9) {
			wtlv.writeByte((byte)' ');
			writeHex(slot.id);
		}
		wtlv.pop();
		wtlv.pop();
		wtlv.pop();
		wtlv.pop();

		/* Public key */
#if PIV_SUPPORT_EC
		if (slot.asymAlg == PIV_ALG_ECCP256) {
			final ECPublicKey ecpub =
			    (ECPublicKey)slot.asym.getPublic();
			wtlv.push(ASN1_SEQ);
			/* Alg info */
			wtlv.push(ASN1_SEQ);
			wtlv.push(ASN1_OID);
			wtlv.write(OID_ECPUBKEY, (short)0,
			    (short)OID_ECPUBKEY.length);
			wtlv.pop();
			wtlv.push(ASN1_OID);
			wtlv.write(OID_SECP256, (short)0,
			    (short)OID_SECP256.length);
			wtlv.pop();
			wtlv.pop();
			/* Key material */
			wtlv.push(ASN1_BITSTRING);
			wtlv.writeByte((byte)0x00);	/* no borrowed bits */
			wtlv.startReserve((short)33, tempBuf);
			len = ecpub.getW(tempBuf.data, tempBuf.offset());
			wtlv.endReserve(len);
			wtlv.pop();
		}
#endif
#if PIV_SUPPORT_RSA
		if (slot.asymAlg == PIV_ALG_RSA1024 ||
		    slot.asymAlg == PIV_ALG_RSA2048) {
			final RSAPublicKey rpubk =
			    (RSAPublicKey)slot.asym.getPublic();
			wtlv.push64k(ASN1_SEQ);

			/* Alg info */
			wtlv.push(ASN1_SEQ);
			wtlv.push(ASN1_OID);
			wtlv.write(OID_RSA, (short)0, (short)OID_RSA.length);
			wtlv.pop();
			wtlv.push(ASN1_NULL);
			wtlv.pop();
			wtlv.pop();

			/* Key material */
			wtlv.push64k(ASN1_BITSTRING);
			wtlv.writeByte((byte)0x00);	/* no borrowed bits */
			wtlv.push64k(ASN1_SEQ);

			/* Modulus */
			wtlv.push64k(ASN1_INTEGER);
			wtlv.startReserve((short)257, tempBuf);
			len = rpubk.getModulus(tempBuf.data, tempBuf.offset());
			wtlv.endReserve(len);
			wtlv.pop();

			/* Exponent */
			wtlv.push(ASN1_INTEGER);
			wtlv.startReserve((short)9, tempBuf);
			len = rpubk.getExponent(tempBuf.data, tempBuf.offset());
			wtlv.endReserve(len);
			wtlv.pop();

			wtlv.pop();
			wtlv.pop();
		}
#endif
		wtlv.pop();

		/* Extensions */
		wtlv.push(ASN1_APP_3);
		wtlv.push(ASN1_SEQ);

		wtlv.push(ASN1_SEQ);
		wtlv.push(ASN1_OID);
		wtlv.write(OID_YUBICOX, (short)0, (short)OID_YUBICOX.length);
		wtlv.writeByte((byte)0x03);
		wtlv.pop();
		wtlv.push(ASN1_OCTETSTRING);
		wtlv.writeByte(YKPIV_VERSION[0]);
		wtlv.writeByte(YKPIV_VERSION[1]);
		wtlv.writeByte(YKPIV_VERSION[2]);
		wtlv.pop();
		wtlv.pop();

		wtlv.push(ASN1_SEQ);
		wtlv.push(ASN1_OID);
		wtlv.write(OID_YUBICOX, (short)0, (short)OID_YUBICOX.length);
		wtlv.writeByte((byte)0x08);
		wtlv.pop();
		wtlv.push(ASN1_OCTETSTRING);
		wtlv.writeByte(slot.pinPolicy);
		wtlv.writeByte((byte)0x01);
		wtlv.pop();
		wtlv.pop();

		wtlv.pop();
		wtlv.pop();

		wtlv.pop();
	}

	private void
	writeAttestationCert(PivSlot slot)
	{
		final PivSlot atslot = slots[SLOT_F9];
		final Signature si;
		short avail, len;

		if (atslot.asymAlg == PIV_ALG_RSA1024 ||
		    atslot.asymAlg == PIV_ALG_RSA2048) {
			if (rsaSha256 != null)
				si = rsaSha256;
			else
				si = rsaSha;
		} else if (atslot.asymAlg == PIV_ALG_ECCP256) {
			if (ecdsaP256Sha256 != null)
				si = ecdsaP256Sha256;
			else
				si = ecdsaP256Sha;
		} else {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		if (si == null) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}

		randData.generateData(certSerial, (short)0,
		    (short)certSerial.length);
		certSerial[0] = (byte)(certSerial[0] & (byte)0x7F);

		outgoing.reset();
		wtlv.start(outgoing);
		writeX509CertInfo(slot);
		wtlv.end();

		si.init(atslot.asym.getPrivate(), Signature.MODE_SIGN);

		avail = outgoing.available();
		while (avail > 0) {
			final short read = outgoing.readPartial(tempBuf, avail);
			si.update(tempBuf.data, tempBuf.offset(), read);
			avail -= read;
		}

		outgoing.reset();
		wtlv.start(outgoing);

		if (slot.id == (byte)0xF9)
			wtlv.push64k((byte)0x70);

		wtlv.push64k(ASN1_SEQ);
		writeX509CertInfo(slot);

		wtlv.push(ASN1_SEQ);
#if PIV_SUPPORT_EC
		if (atslot.asymAlg == PIV_ALG_ECCP256) {
			wtlv.push(ASN1_OID);
			if (ecdsaP256Sha256 != null) {
				wtlv.write(OID_ECDSA_SHA256, (short)0,
				    (short)OID_ECDSA_SHA256.length);
			} else if (ecdsaP256Sha != null) {
				wtlv.write(OID_ECDSA_SHA, (short)0,
				    (short)OID_ECDSA_SHA.length);
			}
			wtlv.pop();
		}
#endif
#if PIV_SUPPORT_RSA
		if (atslot.asymAlg == PIV_ALG_RSA1024 ||
		    atslot.asymAlg == PIV_ALG_RSA2048) {
			wtlv.push(ASN1_OID);
			if (rsaSha256 != null) {
				wtlv.write(OID_RSA_SHA256, (short)0,
				    (short)OID_RSA_SHA256.length);
			} else if (rsaSha != null) {
				wtlv.write(OID_RSA_SHA, (short)0,
				    (short)OID_RSA_SHA.length);
			}
			wtlv.pop();
			wtlv.push(ASN1_NULL);
			wtlv.pop();
		}
#endif
		wtlv.pop();

		wtlv.push64k(ASN1_BITSTRING);
		wtlv.writeByte((byte)0x00);	/* no borrowed bits */
		wtlv.startReserve((short)257, tempBuf);
		len = si.sign(null, (short)0, (short)0, tempBuf.data,
		    tempBuf.offset());
		wtlv.endReserve(len);
		wtlv.pop();

		wtlv.pop();
		if (slot.id == (byte)0xF9)
			wtlv.pop();
		wtlv.end();
	}
#endif
}
