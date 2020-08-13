package cryptopals.set2;

import cryptopals.set1.Set1Challenge7;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Set2Challenge12 {

    private static final int keyLength = 16;
    private static final byte [] key = Set2Challenge11.randomBytes(keyLength);
    public static int blockSize;

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {

        String myString = "";

        //Find blockSize
        blockSize = findBlockSizeC12();
        System.out.println("Block size: " + blockSize);

        int size = findUnknownStringSize();
        System.out.println("Unknown string length: "+ size);
        //Test if encryption is ECB


        System.out.println(byteAtATimeECBDecryption());

    }



    public static String byteAtATimeECBDecryption() throws IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException {

        byte[] targetByteBlock = new byte[16];
        String plaintext = craftMyString(0, blockSize);
        String plaintextForDictionary = plaintext;
        String decryptedStringBlock = "";
        StringBuilder finalString = new StringBuilder();

        int size = findUnknownStringSize();
        for(int j= 0 ; j<=size; j+=blockSize ){
            decryptedStringBlock = "";
            for(int i=0; i<blockSize; i++ ){
                Map<String, Integer> dictionary = createDictionary(plaintextForDictionary, blockSize);
                byte[] ciphertext = encryptAESWithUnknownString(plaintext.getBytes());
                System.arraycopy(ciphertext, j, targetByteBlock, 0, blockSize);

                int byteValue = dictionary.get(Arrays.toString(targetByteBlock));

                plaintext = craftMyString(i+1, blockSize);
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
            plaintext = craftMyString(0, blockSize);
        }

        return finalString.toString();

    }


    public static Map<String, Integer> createDictionary(String knownText, int blockSize) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {

        Map<String, Integer> dictionary = new HashMap<>();
        byte[] mapKey = new byte[blockSize];

        System.arraycopy(knownText.getBytes(), 0, mapKey, 0, blockSize-1);

        for(int i=0; i<256; i++){
            mapKey[blockSize-1] = (byte) i;
            byte[] mapKeyEncrypted = encryptAESWithUnknownString(mapKey);
            byte[] mapKeyEncryptedBlock = new byte[blockSize];
            System.arraycopy(mapKeyEncrypted, 0,  mapKeyEncryptedBlock, 0, blockSize );

            dictionary.put(Arrays.toString(mapKeyEncryptedBlock), i);
        }
        return dictionary;
    }

    public static byte[] encryptAESWithUnknownString(byte[] plaintext) throws NoSuchAlgorithmException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeyException {
        String unknownString = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
                "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
                "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
                "YnkK";
        final byte[] unknownStringBytes = Base64.getDecoder().decode(unknownString);
        byte[] combinedPlaintext = appendToString(plaintext, unknownStringBytes);
        byte[] plaintextPadded = Set2Challenge9.paddingPKCS7(combinedPlaintext);
        return Set1Challenge7.encryptAESInECBModeNoPadding(plaintextPadded, key);

    }

    public static String craftMyString(int decreasedCount, int blockSize) {
        String myString = "";
        for(int i = 0; i<blockSize-1-decreasedCount ; i++){
            myString +="A";
        }

        return myString;
    }

    public static int findBlockSizeC12() throws IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException {
        int blockSize = 0;
        String identicalChar = "A";
        byte[] previousCiphertext = new byte[0];
        for(int i=0; i<256 ; i++){
            byte[] ciphertext = encryptAESWithUnknownString(identicalChar.getBytes());

            if(i!=0 && previousCiphertext[0] == ciphertext[0] && previousCiphertext[1] == ciphertext[1]){
                blockSize = identicalChar.length()-1;
                break;
            }
            previousCiphertext = ciphertext;
            identicalChar += "A";
        }
        return blockSize;
    }

    public static int findUnknownStringSize() throws IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException {
        int size = 0;

        String myString = "";
        byte[] ciphertext1 = encryptAESWithUnknownString(myString.getBytes());
        for(int i=0 ; ; i++){
            myString += "A";
            byte[] ciphertext2 = encryptAESWithUnknownString(myString.getBytes());
            if(ciphertext1.length != ciphertext2.length){
                size = encryptAESWithUnknownString("".getBytes()).length-myString.length()-1;
                break;
            }
            ciphertext1 = ciphertext2;

        }
        return size;
    }

    public static byte[] appendToString(byte[] mainString, byte[] stringToAppend){
        //Arranging
        byte[] plaintextWithUnknownStringBytes = new byte[mainString.length + stringToAppend.length];

        //Make plaintext bytes
        System.arraycopy(mainString, 0, plaintextWithUnknownStringBytes, 0, mainString.length);
        System.arraycopy(stringToAppend, 0, plaintextWithUnknownStringBytes, mainString.length, stringToAppend.length);
        return plaintextWithUnknownStringBytes;

    }



}
