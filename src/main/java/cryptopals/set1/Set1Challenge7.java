package cryptopals.set1;

import cryptopals.set2.Set2Challenge9;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;

public class Set1Challenge7 {

    public static void main(String[] args) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, FileNotFoundException {

        Scanner s = new Scanner(new File("/Users/veda.kadam/CryptopalsHexToBase64/src/main/resources/inputC7Base64.txt"));
        String ciphertextBase64 = "";
        while(s.hasNextLine()){
            ciphertextBase64 += s.nextLine();
        }

        byte[] ciphertextDecodedBytes = Base64.getDecoder().decode(ciphertextBase64);
        System.out.println(ciphertextDecodedBytes.length);
        String keyString = "YELLOW SUBMARINE";
        byte[] plaintextBytes = decryptAESInECBModeNoPadding(ciphertextDecodedBytes, keyString.getBytes());
        System.out.println(new String(plaintextBytes, StandardCharsets.UTF_8));
        testing();
    }

    public static void testing() throws NoSuchAlgorithmException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeyException {

        String plaintext = "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP";
        String key = "YELLOW SUBMARINE";

        byte[] ciphertextBytes = encryptAESInECBModeNoPadding(plaintext.getBytes(),key.getBytes());
        byte[] plaintextBytes = decryptAESInECBModeNoPadding(ciphertextBytes, key.getBytes());
        System.out.println("\n\n\n");
        System.out.println(new String(plaintextBytes, StandardCharsets.UTF_8));
    }

    public static byte[] decryptAESInECBModeNoPadding(byte[] ciphertextBytes, byte[] keyBytes) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {

        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(ciphertextBytes);
    }

    public static byte[] encryptAESInECBModeNoPadding(byte[] plaintextBytes, byte[] keyBytes) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plaintextBytes);
    }

    public static byte[] encryptAESinECBWithPadding(byte[] plaintext, byte[] key) throws NoSuchAlgorithmException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeyException {

        byte[] plaintextPadded = Set2Challenge9.paddingPKCS7(plaintext);
        return Set1Challenge7.encryptAESInECBModeNoPadding(plaintextPadded, key);

    }

    public static byte[] decryptAESinECBWithPadding(byte[] ciphertext, byte[] key) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] plaintextPadded = Set1Challenge7.decryptAESInECBModeNoPadding(ciphertext, key);
        return Set2Challenge9.removePKCS7(plaintextPadded);
    }


}
