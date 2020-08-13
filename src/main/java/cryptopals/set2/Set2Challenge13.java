package cryptopals.set2;


import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import cryptopals.set1.Set1Challenge7;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLOutput;

public class Set2Challenge13 {

    private static final int keyLength = 16;
    private static final byte [] key = Set2Challenge11.randomBytes(keyLength);

    public static void main(String[] args) throws IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException {

        String getUserEncryption = "attac@atk.com";
        System.out.println("Length of getUserEncryption: " + getUserEncryption.length());
        int blockSize = Set2Challenge12.findBlockSizeC12();
        System.out.println("Blocksize: " + blockSize);

        byte[] userEncryption = encryptC13(getUserEncryption);
        byte[] admin = Set2Challenge9.paddingPKCS7("admin".getBytes());
        String getAdminEncryption = "fke@zz.com" + new String(admin);
        System.out.println("Length of getAdminEncryption: " +getAdminEncryption.length());
        byte[] adminEncryption = encryptC13(getAdminEncryption);

        System.arraycopy(adminEncryption, blockSize, userEncryption, userEncryption.length-blockSize, blockSize);
        System.out.println(decryptC13(userEncryption));
    }

    public static String profileFor(String email){
        if(email.contains("@") && email.contains(".")){
            return "email=" + email + "&uid=10&role=user";
        }
        System.out.println("INVALID EMAIL ADDRESS");
            return "INVALID EMAIL ADDRESS";

    }

    public static String parse(String encoded){

        JsonObject myJsonObject = new JsonObject();

        while(true){
            int indexOfEqualSign = encoded.indexOf("=");
            if(!encoded.contains("&")){
                myJsonObject.addProperty(encoded.substring(0, indexOfEqualSign), encoded.substring(indexOfEqualSign+1));
                break;
            }
            else{
                int indexOfAmpercentSign = encoded.indexOf("&");
                myJsonObject.addProperty(encoded.substring(0, indexOfEqualSign), encoded.substring(indexOfEqualSign+1, indexOfAmpercentSign));
                encoded = encoded.substring(indexOfAmpercentSign+1);

            }

        }

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String jsonOutput = gson.toJson(myJsonObject);

        return jsonOutput;
    }

    public static byte[] encryptC13(String plaintext) throws IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException {

        String encodedPlaintext = profileFor(plaintext);
        return Set1Challenge7.encryptAESinECBWithPadding(encodedPlaintext.getBytes(), key);

    }

    public static String decryptC13(byte[] ciphertext) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {

        byte[] ciphertextUnpadded = Set1Challenge7.decryptAESinECBWithPadding(ciphertext, key);
        return parse(new String(ciphertextUnpadded));

    }



}
