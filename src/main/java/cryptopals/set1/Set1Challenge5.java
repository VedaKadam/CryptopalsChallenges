package cryptopals.set1;

import org.apache.commons.codec.binary.Hex;

public class Set1Challenge5 {

    public static void main(String[] args) {

        String key = "ICE";
        String plaintext = "Burning 'em, if you ain't quick and nimble\n" +
                "I go crazy when I hear a cymbal";
        String expectedCiphertext = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        String ciphertext = Hex.encodeHexString(repeatingKeyXOR(convertStringtoBytes(key), convertStringtoBytes(plaintext)));
        if (ciphertext.equals(expectedCiphertext)){
            System.out.println("SET 1 CHALLENGE 5 COMPLETE ");
        }
    }

    // Make the key ICE in bytes
    public static byte[] convertStringtoBytes(String variableString){
        byte[] variableBytes = variableString.getBytes();
        return variableBytes;
    }

    // XOR sequentially

    public static byte[] repeatingKeyXOR (byte[] key, byte[] plaintext){

        byte [] ciphertext = new byte[plaintext.length];
        for(int i=0, j=0; i < plaintext.length; i++, j++){
            if(j >= key.length){
                j=0;
            }
            ciphertext[i] = (byte)(key[j]^plaintext[i]);
        }
        return ciphertext;
    }




}
