package cryptopals.set1;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

public class Set1Challenge1 {

    public static void main(String[] args) throws DecoderException {

        //Challenge 1
        String HEX_INPUT = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        String EXPECTED_OUTPUT = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        String RECEIVED_OUTPUT = HexToBinary(HEX_INPUT);
        if ( RECEIVED_OUTPUT.equals(EXPECTED_OUTPUT) )
            System.out.println("SET 1 CHALLENGE 1 COMPLETE ");

        Path currentRelativePath = Paths.get("");
        String currentPathString = currentRelativePath.toString();
        String currentPathAbsoluteString = currentRelativePath.toAbsolutePath().toString();

        System.out.println("Current relative path: " + currentPathString);
        System.out.println("Current absolute path: " + currentPathAbsoluteString);




    }

    public static String HexToBinary(String to_convert) throws DecoderException {

        byte [] convert = Hex.decodeHex(to_convert);
        return Base64.getEncoder().encodeToString(convert);

    }
}
