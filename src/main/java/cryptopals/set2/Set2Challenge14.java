package cryptopals.set2;

import cryptopals.set1.Set1Challenge7;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Set2Challenge14 {

    private static final int keyLength = 16;
    private static final int max = 15;
    private static final int min = 1;
    private static final int randomStringLength = (int) (Math.random() * ((max - min) + 1 ) ) + min;

    private static final byte [] key = Set2Challenge11.randomBytes(keyLength);
    private static final byte [] randomString = Set2Challenge11.randomBytes(randomStringLength);
    public static int blockSize;
    public static int prependedStringLength;
    public static int appendedStringLength;

    public static String randomStringPadding = "";
    public static int j = 0;
    public static int finalJ;


    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {

        blockSize = findBlockSize14();
        System.out.println("Blocksize: " + blockSize);


        System.out.println("Prepended string length: "+ randomString.length);
        prependedStringLength = findPrependedStringSize();
        appendedStringLength = findUnknownStringSize14();
        System.out.println("Prepended string length using findPrependedStringSize(): " + prependedStringLength);
        System.out.println("Unknown string length: "+ appendedStringLength);

        String decrypted = byteAtATimeECBDecryption();
        System.out.println("Decrypted string is: \n" + decrypted);

    }

    public static String byteAtATimeECBDecryption() throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
        byte[] targetByteBlock = new byte[16];
        String plaintext = Set2Challenge12.craftMyString(0, blockSize);
        String plaintextForDictionary = plaintext;
        String decryptedStringBlock = "";
        StringBuilder finalString = new StringBuilder();

        j = ((prependedStringLength/16)*16)+16;
        randomStringPadding = Set2Challenge12.craftMyString(prependedStringLength%16 , blockSize+ 1);

        finalJ = j;
        int size = appendedStringLength + prependedStringLength + randomStringPadding.length();
        for( ; j<=size; j+=blockSize ){
            decryptedStringBlock = "";
            for(int i=0; i<blockSize; i++ ){
                Map<String, Integer> dictionary = createDictionary14(plaintextForDictionary, blockSize);
                String plaintextToSend = randomStringPadding + plaintext;
                byte[] ciphertext = encrypt14(plaintextToSend.getBytes());
                System.arraycopy(ciphertext, j, targetByteBlock, 0, blockSize);

                int byteValue = dictionary.get(Arrays.toString(targetByteBlock));

                plaintext = Set2Challenge12.craftMyString(i+1, blockSize);
                decryptedStringBlock += new String( new byte[] { (byte) byteValue});
                if(j == 0){
                    plaintextForDictionary = plaintext + decryptedStringBlock;
                }
                else{
                    plaintextForDictionary = plaintextForDictionary.substring(1) + new String( new byte[] { (byte) byteValue});
                }
                if(j==(size/blockSize)*16){
                    if(i> size%blockSize){
                        break;
                    }
                }

            }

            finalString.append(decryptedStringBlock);
            plaintextForDictionary = decryptedStringBlock.substring(1);
            plaintext = Set2Challenge12.craftMyString(0, blockSize);
        }

        return finalString.toString();

    }

    public static byte[] encrypt14(byte[] plaintext) throws NoSuchAlgorithmException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeyException {

        byte[] prependedPlaintext = Set2Challenge12.appendToString(randomString, plaintext);
        String unknownString = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
                "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
                "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
                "YnkK";
        final byte[] unknownStringBytes = Base64.getDecoder().decode(unknownString);
        byte[] combinedPlaintext = Set2Challenge12.appendToString(prependedPlaintext, unknownStringBytes);
        byte[] plaintextPadded = Set2Challenge9.paddingPKCS7(combinedPlaintext);
        return Set1Challenge7.encryptAESInECBModeNoPadding(plaintextPadded, key);

    }

    public static int findPrependedStringSize() throws IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException {
        int stringSize = 0;

        String myString = "";
        byte[] ciphertext1 = encrypt14(myString.getBytes());
        byte[] ciphertext1Block = new byte[16];
        byte[] ciphertext2Block = new byte[16];

        myString += "A";
        byte[] ciphertext2 = encrypt14(myString.getBytes());

        //check in which block we have to add our string
        for(int i=0 ; i< ciphertext1.length ; i=i+16 ){

            System.arraycopy(ciphertext1, i, ciphertext1Block, 0, blockSize );
            System.arraycopy(ciphertext2, i, ciphertext2Block, 0, blockSize );
            if(Arrays.equals(ciphertext1Block, ciphertext2Block)){
                stringSize = i+16;
            }
            else{
                break;
            }
        }

        //check how many 'A's do we have to add in the unequal block
        for(int i=0; i<blockSize ; i++){
            ciphertext1 = ciphertext2;
            myString += "A";
            ciphertext2 = encrypt14(myString.getBytes());

            System.arraycopy(ciphertext1, stringSize, ciphertext1Block, 0, blockSize );
            System.arraycopy(ciphertext2, stringSize, ciphertext2Block, 0, blockSize );

            if(Arrays.equals(ciphertext1Block, ciphertext2Block)){
                stringSize += blockSize - myString.length() + 1;
                break;
            }
        }
        return stringSize;


    }

    public static int findBlockSize14() throws IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException {
        int blockSize = 0;
        String identicalChar = "";

        byte[] previousCiphertext = encrypt14(identicalChar.getBytes());
        for(int i=0; i<256 ; i++){
            identicalChar += "A";
            byte[] ciphertext = encrypt14(identicalChar.getBytes());
            if(i!=0 && previousCiphertext.length != ciphertext.length){
                blockSize = ciphertext.length-previousCiphertext.length;
                break;
            }
            previousCiphertext = ciphertext;

        }
        return blockSize;

    }

    public static int findUnknownStringSize14() throws IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException {
        int size = 0;

        String myString = "";
        byte[] ciphertext1 = encrypt14(myString.getBytes());
        for(int i=0 ; ; i++){
            myString += "A";
            byte[] ciphertext2 = encrypt14(myString.getBytes());
            if(ciphertext1.length != ciphertext2.length){
                size = encrypt14("".getBytes()).length-myString.length()-1;
                break;
            }
            ciphertext1 = ciphertext2;

        }
        return size-prependedStringLength;
    }

    public static Map<String, Integer> createDictionary14(String knownText, int blockSize) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {

        Map<String, Integer> dictionary = new HashMap<>();
        knownText = randomStringPadding + knownText;

        byte[] mapKey = new byte[knownText.length()+1];

        System.arraycopy(knownText.getBytes(), 0, mapKey, 0, knownText.length());

        for(int i=0; i<256; i++){
            mapKey[knownText.length()] = (byte) i;
            byte[] mapKeyEncrypted = encrypt14(mapKey);
            byte[] mapKeyEncryptedBlock = new byte[blockSize];
            System.arraycopy(mapKeyEncrypted, finalJ,  mapKeyEncryptedBlock, 0, blockSize );

            dictionary.put(Arrays.toString(mapKeyEncryptedBlock), i);
        }
        return dictionary;
    }


}
