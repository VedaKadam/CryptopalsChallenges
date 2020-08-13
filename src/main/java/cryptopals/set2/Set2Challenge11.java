package cryptopals.set2;

import cryptopals.set1.Set1Challenge7;
import cryptopals.set1.Set1Challenge8;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class Set2Challenge11 {


    public static void main(String[] args) throws FileNotFoundException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException {

        Scanner s = new Scanner(new File("/Users/veda.kadam/CryptopalsHexToBase64/src/main/resources/inputC11.txt"));

        String plaintext ="";
        while(s.hasNextLine()){
            plaintext += s.nextLine();
        }
        challenge11(plaintext);
    }



    public static byte[] randomBytes(int len){
        byte[] bytes = new byte[len];
        Random random = new Random();
        random.nextBytes(bytes);
        return bytes;
    }



    public static void challenge11(String plaintext) throws NoSuchAlgorithmException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeyException {
        //Arranging
        int keyLength = 16;
        int max = 10;
        int min = 5;
        int plaintextPaddingLength = (int) (Math.random() * ((max - min) + 1 ) ) + min;

        byte [] key = randomBytes(keyLength);
        byte [] initVector = randomBytes(keyLength);
        byte[] extraPaddingForStartAndEnd = randomBytes(plaintextPaddingLength);
        byte[] plaintextWithExtraPadding = new byte[plaintext.getBytes().length + 2*plaintextPaddingLength];

        //Prepend random bytes to plaintext byte array
        System.arraycopy(extraPaddingForStartAndEnd, 0, plaintextWithExtraPadding, 0, plaintextPaddingLength);

        //Add plaintext in middle
        System.arraycopy(plaintext.getBytes(), 0, plaintextWithExtraPadding, plaintextPaddingLength, plaintext.getBytes().length);
        //TODO: generate different end padding
        //Append random bytes to plaintext
        System.arraycopy(extraPaddingForStartAndEnd, 0, plaintextWithExtraPadding, plaintextWithExtraPadding.length - plaintextPaddingLength, plaintextPaddingLength);

        //Decide mode of encryption: 0=ECB , 1=CBC
        boolean encryptionMode = new Random().nextBoolean();
        byte[] plaintextFinal = Set2Challenge9.paddingPKCS7(plaintextWithExtraPadding);
        String boolToInt = encryptionMode? "CBC" : "ECB";
        System.out.println("Encryption mode = " + boolToInt);


        encryptionForChallenge11(encryptionMode, plaintextFinal, key, initVector);

    }

    public static void encryptionForChallenge11(boolean encryptionMode, byte[] plaintext, byte[] key, byte[] initVector) throws NoSuchAlgorithmException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeyException {

        byte[] cipherBytes = new byte[0];
        if(!encryptionMode){ //ECB
            cipherBytes = Set1Challenge7.encryptAESInECBModeNoPadding(plaintext, key);
        }
        else { //CBC
            cipherBytes = Set2Challenge10.encryptUsingCustomAESCBCNoPadding(plaintext, key, initVector);
        }
        detectECBOrCBC(key, cipherBytes);
    }

    public static void detectECBOrCBC(byte[] key, byte[] cipherBytes) {
        String result = "";
        result = Set1Challenge8.breakAESInECB16ByteKey(Hex.encodeHexString(cipherBytes), key.length);
        if (result.equals("")) {
            System.out.println("CBC used");
        }
        else{
            System.out.println("ECB used");
        }
    }


}
