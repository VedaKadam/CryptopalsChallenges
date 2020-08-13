package cryptopals.set2;

import cryptopals.set1.Set1Challenge5;
import cryptopals.set1.Set1Challenge7;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Set2Challenge10 {


    public static void main(String[] args) throws FileNotFoundException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidAlgorithmParameterException {

        Scanner s = new Scanner( new File("/Users/veda.kadam/CryptopalsHexToBase64/src/main/resources/inputC10.txt"));

        String plaintext ="";
        while(s.hasNextLine()){
            plaintext += s.nextLine();
        }

        String key = "YELLOW SUBMARINE";
        byte[] initVector = new byte[16];
        byte[] plaintextDecode = Base64.getDecoder().decode(plaintext);


        byte[] decryptedBytes = decryptUsingCustomAESCBCNoPadding(plaintextDecode, key.getBytes(), initVector);
        String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);
        System.out.println(decrypted);

    }

    public static byte[] encryptUsingCustomAESCBCNoPadding(byte[] plaintext, byte[] key, byte[] initVector) throws IllegalBlockSizeException, InvalidKeyException, NoSuchAlgorithmException, BadPaddingException, NoSuchPaddingException {

        List<byte[]> plaintextBlockList = dividePlaintextInBlocks(plaintext, key);
        List<byte[]> ciphertextBlockList = XORIVAndEncryptWithAES(plaintextBlockList, key, initVector);
        return getBytesFromList(ciphertextBlockList);
    }

    public static byte[] decryptUsingCustomAESCBCNoPadding(byte[] plaintext, byte[] key, byte[] initVector) throws IllegalBlockSizeException, InvalidKeyException, NoSuchAlgorithmException, BadPaddingException, NoSuchPaddingException {

        List<byte[]> ciphertextBlockList = dividePlaintextInBlocks(plaintext, key);
        List<byte[]> plaintextRecoveredBlockList = XORIVAndDecryptWithAES(ciphertextBlockList, key, initVector);
        return getBytesFromList(plaintextRecoveredBlockList);
    }





    //divide the plaintext in size of key blocks
    public static List<byte[]> dividePlaintextInBlocks(byte[] plaintext, byte[] key){

        List<byte[]> byteArrayList = new ArrayList<>();
        for(int i = 0, j=0; i<plaintext.length ; i+=key.length){
            byte[] oneBlock = new byte[key.length];
            System.arraycopy(plaintext, i, oneBlock, 0, key.length);
            byteArrayList.add(j, oneBlock);
            j++;
        }
        return byteArrayList;
    }

    //XOR them with IV: use repeating key xor function and encrypt
    public static List<byte[]> XORIVAndEncryptWithAES(List<byte[]> plaintextBlockBytes, byte[] key, byte[] initVector) throws BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException {

        List<byte[]> ciphertextBlockBytes = new ArrayList<>();
        for(int i = 0; i<plaintextBlockBytes.size() ; i++){
            byte[] XORedWithIVBlock = Set1Challenge5.repeatingKeyXOR(initVector, plaintextBlockBytes.get(i));
            initVector = Set1Challenge7.encryptAESInECBModeNoPadding(XORedWithIVBlock, key);
            ciphertextBlockBytes.add(initVector);
        }
        return ciphertextBlockBytes;
        }

    public static List<byte[]> XORIVAndDecryptWithAES(List<byte[]> ciphertextBlockList, byte[] key, byte[] initVector) throws BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException {

        List<byte[]> plaintextBlockList = new ArrayList<>();
        byte[] XORedWithIVBlock;
        int i = 0;
        for(; i<ciphertextBlockList.size() ; i++){
            byte[] initVectorUpdated = Set1Challenge7.decryptAESInECBModeNoPadding(ciphertextBlockList.get(i), key);
            if(i==0){
                XORedWithIVBlock = Set1Challenge5.repeatingKeyXOR(initVectorUpdated, initVector);
            }
            else{
                XORedWithIVBlock = Set1Challenge5.repeatingKeyXOR(initVectorUpdated, ciphertextBlockList.get(i-1));
            }
            plaintextBlockList.add(XORedWithIVBlock);
        }
        return plaintextBlockList;

    }

    private static byte[] getBytesFromList(List<byte[]> blockList) {
        byte[] bytes = new byte[blockList.size()*blockList.get(0).length];
        for(int j=0; j<blockList.size() ; j++){
            System.arraycopy(blockList.get(j), 0, bytes, j*16, 16);
        }
        return bytes;
    }







    //Encrypt using AES CBC mode in build
    public static byte[] encryptAESInCBCMode(byte[] plaintextBytes, byte[] keyBytes, byte [] ivBytes) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        return (cipher.doFinal(plaintextBytes));

    }

    //Decrypt using AES CBC mode in build
    public static byte[] decryptAESInCBCMode(byte[] ciphertextBytes, byte[] keyBytes, byte [] ivBytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        return (cipher.doFinal(ciphertextBytes));

    }






}
