package cryptopals.set1;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import static cryptopals.set1.Set1Challenge3.doChallenge3;
import static cryptopals.set1.Set1Challenge3.score;

public class Set1Challenge4 {

    public static void main(String[] args) throws IOException, DecoderException {

        //Input data from file
        Scanner s = new Scanner(new File("/Users/veda.kadam/CryptopalsHexToBase64/src/main/resources/inputHex.txt"));
        List<String> inputHex = new ArrayList<>();
        while(s.hasNextLine()){
            inputHex.add(s.nextLine());
        }


        int alphabetScore = 0;
        String bestCandidate = "";
        for (String encodedStringHex : inputHex)
        {
            byte[] ciphertextBytes = Hex.decodeHex(encodedStringHex);
            String almostBestCandidate = doChallenge3(ciphertextBytes);
            //System.out.println(almostBestCandidate + "   " +score(almostBestCandidate));
            if(score(almostBestCandidate) > alphabetScore){
                alphabetScore = score(almostBestCandidate);
                bestCandidate = almostBestCandidate;
            }
        }

        System.out.println("SET 1 CHALLENGE 4 COMPLETE: " + bestCandidate);

    }

}
