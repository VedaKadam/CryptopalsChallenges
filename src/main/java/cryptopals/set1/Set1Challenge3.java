package cryptopals.set1;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.nio.charset.StandardCharsets;
import java.util.*;

public class Set1Challenge3 {

    public static void main(String[] args) throws DecoderException {


        //Challenge 3
        String ciphertextHex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        byte[] ciphertextBytes = Hex.decodeHex(ciphertextHex);
        System.out.println("SET 1 CHALLENGE 3 COMPLETE: "+ doChallenge3(ciphertextBytes));
    }
    public static String  decryptTheMessage(char key, byte[] ciphertextBytes) throws DecoderException {

        //byte[] ciphertextBytes = Hex.decodeHex(ciphertextHex);

        byte [] output = new byte[ciphertextBytes.length];
        for( int r = 0 ; r < ciphertextBytes.length ; r++)
            output[r] = (byte)(((byte)key)^ciphertextBytes[r]);

        return new String(output, StandardCharsets.UTF_8);
    }

    public static int score (String plaintextCandidate){
        int score = 0;
        //TODO: Convert to stream mechanics

        for (char x : plaintextCandidate.toCharArray()) {
            if ((x >= 'A' && x <= 'Z') || (x >= 'a' && x <= 'z') || (x == ' ')){
                score++;
            }

        }

        return  score;

    }

    public static String doChallenge3(byte[] ciphertextBytes) throws DecoderException {

        Map<Character, Integer> keyScores = new HashMap<>();
        //TODO: Can decode the hex_input before passing to other methods

        //Define the key space
        List<Character> keySpace = new ArrayList<>();
        for (int j= 0; j <256 ; j++){
            keySpace.add((char) j);
        }

        //Iterate through the key space
        for(char keyCandidate : keySpace) {

            //Evaluate each possible key
            String plaintextCandidate = decryptTheMessage(keyCandidate, ciphertextBytes);
            //Score that candidate
            int score = score(plaintextCandidate);

            keyScores.put(keyCandidate, score);

        }

        //Select best candidate

        Optional<Map.Entry<Character, Integer>> bestCandidate = keyScores.entrySet().stream().max(Comparator.comparing(Map.Entry::getValue));

        return decryptTheMessage(bestCandidate.get().getKey(), ciphertextBytes);


    }

}
