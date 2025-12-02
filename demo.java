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
    final static byte INS_GET_INFO = (byte) 0x03; 
    final static byte INS_CHANGE_PIN = (byte) 0x04;
    final static byte INS_UNBLOCK_PIN = (byte) 0x05;
    final static byte INS_GET_CARD_ID = (byte) 0x06;

    final static byte PIN_TRY_LIMIT = (byte) 0x03; 
    final static byte MAX_PIN_SIZE = (byte) 0x06;  
    
    private OwnerPIN pin;     
    private byte[] userData; 
    private short userDataLen; 
    final static short MAX_DATA_SIZE = (short) 256;
    
    // Khai báo bin RSA và lu ID th
    private byte[] cardID; // Lu ID ngu nhiên (8 bytes)
    private KeyPair keyPair;
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;     

    public static void install(byte[] bArray, short bOffset, byte bLength) {         
        new demo().register(bArray, (short) (bOffset + 1), bArray[bOffset]);     
    }     

    protected demo() {
		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);                  
        userData = new byte[MAX_DATA_SIZE];         
        userDataLen = 0;
        cardID = new byte[8];
        
        // Khi to KeyPair RSA (Dùng 1024 bit cho nh th gi lp)
        // Nu th tht mnh, có th i lên LENGTH_RSA_2048
        try {
            keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
            publicKey = (RSAPublicKey) keyPair.getPublic();
            privateKey = (RSAPrivateKey) keyPair.getPrivate();
        } catch (CryptoException e) {
            // X lý li nu th không h tr RSA (thng th JCOP u h tr)
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
            case INS_GET_INFO:                 
                getInfo(apdu);                 
                break;
            case INS_CHANGE_PIN:
                changePin(apdu);
                break;
            case INS_UNBLOCK_PIN:
resetPin(apdu);
                break;
			case INS_GET_CARD_ID:
				getCardID(apdu);
				break;
            default:                 
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);         
        }     
    }     
    
    // c ID
    private void getCardID(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 8);
        apdu.sendBytesLong(cardID, (short) 0, (short) 8);
    }

    private void changePin(APDU apdu) {
        if (!pin.isValidated()) {
             ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        byte[] buf = apdu.getBuffer();
        byte len = (byte)apdu.setIncomingAndReceive();
        
        if (len > MAX_PIN_SIZE || len < 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        pin.update(buf, ISO7816.OFFSET_CDATA, len);
    }
    
    private void resetPin(APDU apdu) {
        byte[] defaultPIN = {(byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34, (byte)0x35, (byte)0x36};
        pin.update(defaultPIN, (short)0, (byte)6);
        pin.resetAndUnblock();
    }
    
    private void registerUser(APDU apdu) {         
        byte[] buf = apdu.getBuffer();         
        short len = apdu.setIncomingAndReceive(); 

		// -- Lu thông tin th --
        byte pinLen = buf[ISO7816.OFFSET_CDATA];                  
        if (pinLen > MAX_PIN_SIZE || pinLen <= 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                
        // Cp nht PIN
        pin.update(buf, (short)(ISO7816.OFFSET_CDATA + 1), pinLen);
        
		// Lu ttin user
        short dataOffset = (short)(ISO7816.OFFSET_CDATA + 1 + pinLen);         
        short dataLen = (short)(len - 1 - pinLen);                  
        if (dataLen > MAX_DATA_SIZE) ISOException.throwIt(ISO7816.SW_FILE_FULL);         
        Util.arrayCopy(buf, dataOffset, userData, (short)0, dataLen);         
        userDataLen = dataLen;
        
        // 2. T sinh Card ID ngu nhiên (8 bytes)
        RandomData rng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        rng.generateData(cardID, (short) 0, (short) 8);
        
        // Sinh khóa RSA và Tr v Public Key
        keyPair.genKeyPair(); // tn thi gian nht
        
        // -- Chun b d liu tr v --
        
        short outOffset = 0;
        
        // Copy CardID vào buffer
        Util.arrayCopy(cardID, (short) 0, buf, outOffset, (short) 8);
        outOffset += 8;
        
        // Copy Modulus
        short modLen = publicKey.getModulus(buf, (short)(outOffset + 2));
        Util.setShort(buf, outOffset, modLen); // Ghi  dài Mod
        outOffset += 2;
        outOffset += modLen;
        
        // Copy Exponent
        short expLen = publicKey.getExponent(buf, (short)(outOffset + 2));
        Util.setShort(buf, outOffset, expLen); // Ghi  dài Exp
        outOffset += 2;
        outOffset += expLen;

        // Gi tt c v Swing
        apdu.setOutgoing();
apdu.setOutgoingLength(outOffset);
        apdu.sendBytes((short)0, outOffset);
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

    private void getInfo(APDU apdu) {         
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);         
        apdu.setOutgoing();         
        apdu.setOutgoingLength(userDataLen);                  
        apdu.sendBytesLong(userData, (short)0, userDataLen);     
    } 
}