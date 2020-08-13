package cryptopals.set1;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class Set1Challenge2 {

    public static void main(String[] args) throws DecoderException {

        //Challenge 2
        String HEX_INPUT = "1c0111001f010100061a024b53535009181c";
        String XOR_INPUT = "686974207468652062756c6c277320657965";
        String EXPECTED_OUTPUT = "746865206b696420646f6e277420706c6179";
        String RECEIVED_OUTPUT = FixedXOR(HEX_INPUT, XOR_INPUT);
        if ( RECEIVED_OUTPUT.equals(EXPECTED_OUTPUT) )
            System.out.println("SET 1 CHALLENGE 2 COMPLETE ");
    }

    public static String FixedXOR(String inputHex1, String inputHex2) throws DecoderException {

        byte[] inputToXor1 = Hex.decodeHex(inputHex1);
        byte[] inputToXor2 = Hex.decodeHex(inputHex2);

        if (inputToXor1.length == inputToXor2.length)
        {
            byte[] output = new byte[inputToXor1.length];

            for( int i = 0 ; i < inputToXor1.length ; i ++)
                output[i] = (byte)(inputToXor1[i]^inputToXor2[i]);
            return Hex.encodeHexString(output);

        }
        else
            return "INVALID";


    }


}
