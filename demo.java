package demo; 
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.*;

public class demo extends Applet {
    final static byte CLA_APPLET = (byte) 0xA0;     
    final static byte INS_REGISTER = (byte) 0x01; 
    final static byte INS_VERIFY = (byte) 0x02;

    // final static byte INS_GET_INFO = (byte) 0x03; 
    final static byte INS_CHANGE_PIN = (byte) 0x04;
    final static byte INS_UNBLOCK_PIN = (byte) 0x05;
    final static byte INS_GET_CARD_ID = (byte) 0x06;

    final static byte INS_WRITE_IMAGE = (byte) 0x10;
    final static byte INS_READ_IMAGE = (byte) 0x11;

    final static byte PIN_TRY_LIMIT = (byte) 0x03; 
    final static byte MAX_PIN_SIZE = (byte) 0x06;

	// AES
    final static byte INS_SET_INFO = (byte) 0x21;
    final static byte INS_GET_INFO_SECURE = (byte) 0x22;

    // Card info & PIN
    private OwnerPIN pin;     
    private byte[] userData; 
    private short userDataLen; 
    final static short MAX_DATA_SIZE = (short) 256;
    
    // Image
    private byte[] avatarImage; 
    final static short MAX_IMAGE_SIZE = (short) 4096;
    private short currentImageSize;
    
    // RSA
    private byte[] cardID; // Luu ID ngau nhien (8 bytes)
    private KeyPair keyPair;
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;
    
    // AES
    private AESKey aesKey; // Object contains AES key
    private Cipher aesCipher; // Encrypt/decrypt machine
    private MessageDigest sha; // Ham bam SHA tao tu PIN
    private byte[] tempBuffer; // Temporary memory to calculate HASH

    public static void install(byte[] bArray, short bOffset, byte bLength) {         
        new demo().register(bArray, (short) (bOffset + 1), bArray[bOffset]);     
    }

    protected demo() {
		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);                  
        userData = new byte[MAX_DATA_SIZE];         
        userDataLen = 0;
        cardID = new byte[8];

        // Init RSA
        try {
            keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
            publicKey = (RSAPublicKey) keyPair.getPublic();
            privateKey = (RSAPrivateKey) keyPair.getPrivate();
        } catch (CryptoException e) {
            // X lý li nu th không h tr RSA (thng th JCOP u h tr)
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        
        // Init mang anh
        // Cap phat mang lon de tranh phan manh bo nho
        try {
            avatarImage = new byte[MAX_IMAGE_SIZE];
            currentImageSize = 0;
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL); 
        }
        
        // Init AES ENGINE
        try {
            // 1. Init empty AES Key object (AES 128 bit)
            aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            
            // 2. Create Cipher AES (ECB mode, no padding - done on middleware)
            // Use ECB for more simpler
            aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            
            // 3. Create SHA hash (SHA-256 or SHA-1 based on card)
            sha = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
            
            // 4. Temporary Buffer holds the hash result (SHA-256 -> 32 bytes)
            tempBuffer = new byte[32];
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
    }     

    public void process(APDU apdu) {         
        if (selectingApplet()) { return; }         
        byte[] buf = apdu.getBuffer();                  
        
        if (buf[ISO7816.OFFSET_CLA] != CLA_APPLET) {             
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);         
        }         
        
        switch (buf[ISO7816.OFFSET_INS]) {             
            case INS_REGISTER:                 
                registerUser(apdu);                 
                break;             
            case INS_VERIFY:                 
                verifyPin(apdu);                 
                break;             
            // case INS_GET_INFO:                 
                // getInfo(apdu);                 
                // break;
            case INS_CHANGE_PIN:
                changePin(apdu);
                break;
            case INS_UNBLOCK_PIN:
                resetPin(apdu);
                break;
			case INS_GET_CARD_ID:
				getCardID(apdu);
				break;
				
			// Ghi anh
            case INS_WRITE_IMAGE:
                writeImage(apdu);
                break;
                
            // Doc anh
            case INS_READ_IMAGE:
                readImage(apdu);
                break;
                
            case INS_SET_INFO: 
            	setInfoSecure(apdu); 
            	break;
            
            case INS_GET_INFO_SECURE: 
            	getInfoSecure(apdu); 
            	break;
            default:                 
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);         
        }     
    }     
    
    // c ID
    private void getCardID(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 9);
        
        // gui truoc 8 bytes ID
        apdu.sendBytesLong(cardID, (short) 0, (short) 8);
        
        // Gui byte thu 9: Trang thai PIN
        // 0x00: Active, 0x01: Blocked
        byte[] status = new byte[1];
        if (pin.getTriesRemaining() == 0) {
            status[0] = 0x01; // Blocked
        } else {
            status[0] = 0x00; // Active
        }
        apdu.sendBytesLong(status, (short) 0, (short) 1);
    }

    private void changePin(APDU apdu) {
        if (!pin.isValidated()) {
             ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        
        // 1. Parse old PIN
        byte oldPinLen = buf[ISO7816.OFFSET_CDATA];
        short oldPinOffset = (short)(ISO7816.OFFSET_CDATA + 1);
        
        // 2. Parse new PIN
        byte newPinLen = buf[oldPinOffset + oldPinLen];
        short newPinOffset = (short)(oldPinOffset + oldPinLen + 1);
        
        // Validate length
        if (newPinLen > MAX_PIN_SIZE || newPinLen < 1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // 3. Verify old PIN
        if (pin.check(buf, oldPinOffset, oldPinLen) == false) {
             ISOException.throwIt((short) (0x63C0 | pin.getTriesRemaining()));
        }

        // ========================================================
        // LOGIC RE-ENCRYPTION
        // ========================================================
        
        // A. Use old PIN to decrypt current data (Ciphertext -> Plaintext)
        // Only process if data is existed (userDataLen > 0)
        if (userDataLen > 0) {
            genAESKey(buf, oldPinOffset, oldPinLen);
            aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
            // decrypt (In-place): userData -> userData
            aesCipher.doFinal(userData, (short) 0, userDataLen, userData, (short) 0);
        }

        // B. Update PIN
        pin.update(buf, newPinOffset, newPinLen);
        
        // C. Use new PIN to encrypt data (Plaintext -> Ciphertext)
        if (userDataLen > 0) {
            genAESKey(buf, newPinOffset, newPinLen);
            aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
            // encrypt (In-place): userData -> userData
            aesCipher.doFinal(userData, (short) 0, userDataLen, userData, (short) 0);
        }
        
        // Delete key from RAM
        aesKey.clearKey();
    }
    
    private void resetPin(APDU apdu) {
        byte[] defaultPIN = {(byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34, (byte)0x35, (byte)0x36};
        pin.update(defaultPIN, (short)0, (byte)6);
        pin.resetAndUnblock();
        
        // Vì d liu c c mã hóa bng PIN c (ã quên), nên nó gi là vô ngha.
        // Xóa i  tránh gii mã sai.
        Util.arrayFillNonAtomic(userData, (short) 0, MAX_DATA_SIZE, (byte) 0x00);
        userDataLen = 0;
    }
    
    private void registerUser(APDU apdu) {         
        byte[] buf = apdu.getBuffer();         
        short len = apdu.setIncomingAndReceive(); 

        // Get PIN length from first byte
        byte pinLen = buf[ISO7816.OFFSET_CDATA];                  
        if (pinLen > MAX_PIN_SIZE || pinLen <= 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                
        // Set PIN
        pin.update(buf, (short)(ISO7816.OFFSET_CDATA + 1), pinLen);
        
        // Generate random ID
        RandomData rng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        rng.generateData(cardID, (short) 0, (short) 8);
        
        // Generate RSA
        keyPair.genKeyPair(); 
        
        // Return: [CardID] + [RSA Public Key]
        short outOffset = 0;
        Util.arrayCopy(cardID, (short) 0, buf, outOffset, (short) 8);
        outOffset += 8;
        
        short modLen = publicKey.getModulus(buf, (short)(outOffset + 2));
        Util.setShort(buf, outOffset, modLen); 
        outOffset += 2;
        outOffset += modLen;
        
        short expLen = publicKey.getExponent(buf, (short)(outOffset + 2));
        Util.setShort(buf, outOffset, expLen); 
        outOffset += 2;
        outOffset += expLen;

        apdu.setOutgoing();
        apdu.setOutgoingLength(outOffset);
        apdu.sendBytes((short)0, outOffset);
    }
    
    // Input: array PIN
    // Logic: Hash(PIN) -> Use first 16 byte to make AES Key
    private void genAESKey(byte[] input, short offset, short length) {
        // Bm PIN
        sha.reset();
        sha.doFinal(input, offset, length, tempBuffer, (short) 0);
        
        // Set Key cho i tng AESKey (Ly 16 bytes u ca Hash)
        aesKey.setKey(tempBuffer, (short) 0);
    }

    private void verifyPin(APDU apdu) {         
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt((short) 0x6983);
        }
        if (pin.check(buf, ISO7816.OFFSET_CDATA, (byte)len) == false) {
            ISOException.throwIt((short) (0x63C0 | pin.getTriesRemaining()));
        }
    }     

	// --- Encrypt ---		
    // APDU: [PIN_LEN] [PIN] [DATA_PADDED...]
    private void setInfoSecure(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        
        // 1. Split PIN
        byte pinLen = buf[ISO7816.OFFSET_CDATA];
        if (pinLen > MAX_PIN_SIZE || pinLen <= 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        // 2. Verify PIN
        if (pin.check(buf, (short)(ISO7816.OFFSET_CDATA + 1), pinLen) == false) {
            ISOException.throwIt((short) 0x6300); // Sai PIN
        }
        
        // 3. Gen AES key from input PIN
        genAESKey(buf, (short)(ISO7816.OFFSET_CDATA + 1), pinLen);
        
        // 4. Prepare data for encrypting
        // Data start after PIN
        short dataOffset = (short)(ISO7816.OFFSET_CDATA + 1 + pinLen);
        short dataLen = (short)(len - 1 - pinLen);
        
        // Validate data length (/// 16)
        if (dataLen % 16 != 0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        if (dataLen > MAX_DATA_SIZE) ISOException.throwIt(ISO7816.SW_FILE_FULL);
        
        // 5. Encrypt
        // Init Cipher with Mode Encrypt and generated Key
        aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
        
        // Encrypting directly from buffer to userData
        // Input: buf[dataOffset] ...
        // Output: userData[0] ...
        aesCipher.doFinal(buf, dataOffset, dataLen, userData, (short) 0);
        
        // Save the actual length
        userDataLen = dataLen;
        
        // delete key from RAM (Optional, aesKey is transient-like)
        aesKey.clearKey();
    }

    // --- DECRYPT ---
    // APDU: [PIN_LEN] [PIN]
    private void getInfoSecure(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        
        // 1. Split PIN
        byte pinLen = buf[ISO7816.OFFSET_CDATA];
        
        // 2. Verify PIN
        if (pin.check(buf, (short)(ISO7816.OFFSET_CDATA + 1), pinLen) == false) {
            ISOException.throwIt((short) 0x6300);
        }
        
        // 3. generate AES key from PIN
        genAESKey(buf, (short)(ISO7816.OFFSET_CDATA + 1), pinLen);
        
        // 4. (Decrypt)
        // Init Cipher Mode Decrypt
        aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
        
        // Input: userData[0] ...
        // Output: buf[0] ...
        // *** userDataLen > 0
        if (userDataLen <= 0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        
        aesCipher.doFinal(userData, (short) 0, userDataLen, buf, (short) 0);
        
        // 5. return plain text
        apdu.setOutgoing();
        apdu.setOutgoingLength(userDataLen);
        apdu.sendBytes((short)0, userDataLen);
        
        aesKey.clearKey();
    }
    
    // Ghi anh (CHUNKING RECEIVER)
    private void writeImage(APDU apdu) {
        // Can pin de ghi anh ?
        // if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        
        // Lay Offset tu P1 va P2 (P1 = High Byte, P2 = Low Byte)
        // Day la vi tri bat dau ghi trong mang avatarImage
        short p1 = (short) (buf[ISO7816.OFFSET_P1] & 0xFF);
        short p2 = (short) (buf[ISO7816.OFFSET_P2] & 0xFF);
        short offset = (short) ((p1 << 8) | p2);
        
        // Kiem tra tran bo nho
        if ((short)(offset + len) > MAX_IMAGE_SIZE) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        
        // copy data tu buffer APDU vao mang avatarImage
        Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, avatarImage, offset, len);
        
        // Cap nhat kich thuoc anh thuc te
        if ((short)(offset + len) > currentImageSize) {
            currentImageSize = (short)(offset + len);
        }
    }
    
    // Doc anh
    private void readImage(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        
        // Ly Offset tu P1, P2
        short p1 = (short) (buf[ISO7816.OFFSET_P1] & 0xFF);
        short p2 = (short) (buf[ISO7816.OFFSET_P2] & 0xFF);
        short offset = (short) ((p1 << 8) | p2);
        
        // Tinh so byte co the gui ve
        short bytesToSend = (short) 240; // Default 240 bytes
        if ((short)(offset + bytesToSend) > currentImageSize) {
            bytesToSend = (short)(currentImageSize - offset);
        }
        
        if (bytesToSend <= 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        apdu.setOutgoing();
        apdu.setOutgoingLength(bytesToSend);
        apdu.sendBytesLong(avatarImage, offset, bytesToSend);
    }
}