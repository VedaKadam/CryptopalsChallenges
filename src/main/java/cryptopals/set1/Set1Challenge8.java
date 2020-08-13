package cryptopals.set1;

import org.apache.commons.codec.DecoderException;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.util.*;

public class Set1Challenge8 {

    public static void main(String[] args) throws FileNotFoundException, DecoderException, UnsupportedEncodingException {



        Scanner s = new Scanner(new File("/Users/veda.kadam/CryptopalsHexToBase64/src/main/resources/inputC8Hex.txt"));
        String ciphertext = "";
        String result = "";
        while(s.hasNextLine()){
            ciphertext = s.nextLine();
            result = breakAESInECB16ByteKey( ciphertext, 16);
            if(result != ""){
                System.out.println(ciphertext);
                break;
            }

        }

        System.out.println(breakAESInECB16ByteKey(ciphertext, 16));

    }



    public static String breakAESInECB16ByteKey(String ciphertext, int keySize) {

        for(int i=0; i+keySize < ciphertext.length()-1; i=i+keySize) {
            String substringOfCiphertext = ciphertext.substring(i, i + keySize);
            for (int j=i+keySize; j+keySize < ciphertext.length(); j=j+keySize) {

                if (substringOfCiphertext.equals(ciphertext.substring(j, j+keySize))) {
                    return substringOfCiphertext;
                }

            }

        }


        return "";
    }
}
