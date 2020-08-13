package cryptopals.set1;

import org.apache.commons.codec.DecoderException;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static cryptopals.set1.Set1Challenge3.score;

public class Set1Challenge6 {



    public static void main(String[] args) throws FileNotFoundException, DecoderException {

        Scanner s = new Scanner(new File("/Users/veda.kadam/CryptopalsHexToBase64/src/main/resources/inputBase64.txt"));
        String ciphertext = "";

        while(s.hasNextLine()){
            ciphertext += s.nextLine();
        }

        byte[] ciphertextDecodedBytes = Base64.getDecoder().decode(ciphertext);
        int[] probableKeys = guessKeySizeForCiphertext(ciphertextDecodedBytes);
        //System.out.println(Arrays.toString(probableKeys));
        String finalKey = findKey(createTransposeCiphertextBlocks(probableKeys[0],ciphertextDecodedBytes), probableKeys[0]);
        System.out.println("Key: " +finalKey+"\n");
        String plaintext = decryptTheMessage(finalKey.getBytes(), ciphertextDecodedBytes);
        System.out.println("Plaintext: \n" + plaintext);
    }

    //Calculates and returns hamming distance
    public static long hammingDistance(byte[] stringOneBytes, byte[] stringTwoBytes)
    {
        if(stringOneBytes.length != stringTwoBytes.length){
            throw new IllegalArgumentException("Length of arguments is unequal.");
        }
        byte[] xorOutputBytes = new byte[stringOneBytes.length];
        String xorOutputString = "";
        for(int i = 0; i< stringOneBytes.length; i++){
            xorOutputBytes[i] = (byte)(stringOneBytes[i]^stringTwoBytes[i]);
            xorOutputString += Integer.toBinaryString((xorOutputBytes[i]+256)%256);
        }

        long count = xorOutputString.chars().filter(ch -> ch == '1').count();
        return count;
    }

    public static double hammingDistanceNormalized(byte[] a, byte[] b) {
        return hammingDistance(a, b) / (double) a.length;
    }

    //Checks hamming distance between chunks of ciphertext of given key size
    public static double calculateHammingDistanceForKeySize (int keySize, byte[] cipherText){

        double sumHammingDistance = 0;
        int j = 0;
        for(int i = 0; i+2*keySize-1<cipherText.length; i=i+2*keySize){
            sumHammingDistance += hammingDistanceNormalized(Arrays.copyOfRange(cipherText, i, i+keySize), Arrays.copyOfRange(cipherText, i+keySize, i+2*keySize));
            j++;

            //Used for testCalculateHammingDistanceForKeySize()
            /*if (j==1){
                break;
            }*/

        }
        return sumHammingDistance/(double) j;
    }

    //iterates through possible key size values and returns key size of lowest associated hamming distance
    public static int[] guessKeySizeForCiphertext(byte[] ciphertextBytes){

        Map<Integer, Double> keySizeAndHammingDistance = new HashMap<>();
        for(int j=2; j<=40; j++){
            double hammingDistance = calculateHammingDistanceForKeySize(j, ciphertextBytes);
            keySizeAndHammingDistance.put(j,hammingDistance);
        }

        LinkedHashMap<Integer, Double> sortedMap = new LinkedHashMap<>();
        keySizeAndHammingDistance.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByValue())
                .forEachOrdered(x -> sortedMap.put(x.getKey(), x.getValue()));

        int[] probableKeys = new int[5];
        Iterator<Map.Entry<Integer, Double>> iteratorOfSortedMap = sortedMap.entrySet().iterator();
        for(int i=0; i <5 ; i++){
            probableKeys[i] = iteratorOfSortedMap.next().getKey();
        }
        return probableKeys;
    }

    //find key for given key size
    public static byte[][] createTransposeCiphertextBlocks(int keySize, byte[] ciphertextBytes) throws DecoderException {

        //System.out.println(ciphertextBytes.length);
        /*if(ciphertextBytes.length % keySize == 0){

        }*/
        byte[][] transposeCiphertext = new byte[keySize][(ciphertextBytes.length/keySize)+1];

        for(int i=0; i<keySize; i++){
            for(int j=0;j*keySize+i<ciphertextBytes.length; j++){
                transposeCiphertext[i][j] = ciphertextBytes[j*keySize+i];
            }
        }
      return transposeCiphertext;
    }

    public static String findKey(byte[][] transposeCiphertext, int keySize) throws DecoderException {
        String finalKey = "";
        for(int i=0; i<transposeCiphertext.length; i++){
            Map<Character, Integer> keyScores = new HashMap<>();

            //Define the key space
            List<Character> keySpace = new ArrayList<>();
            for (int j= 0; j <256 ; j++){
                keySpace.add((char) j);
            }

            //Iterate through the key space
            for(char keyCandidate : keySpace) {

                //Evaluate each possible key
                String plaintextCandidate = Set1Challenge3.decryptTheMessage(keyCandidate, transposeCiphertext[i]);
                //Score that candidate
                int score = score(plaintextCandidate);
                keyScores.put(keyCandidate, score);

            }

            Optional<Map.Entry<Character, Integer>> bestCandidate = keyScores.entrySet().stream().max(Comparator.comparing(Map.Entry::getValue));

           finalKey += bestCandidate.get().getKey();
        }
        return finalKey;
    }
    public static String decryptTheMessage(byte[] keyBytes, byte[] ciphertextBytes ) {


        byte [] output = new byte[ciphertextBytes.length];
        for( int r = 0, i=0; r < ciphertextBytes.length ; r++){
            output[r] = (byte)(keyBytes[i]^ciphertextBytes[r]);

            if(i<keyBytes.length-1){
                i++;
            }
            else{
                i=0;
            }
        }


        return new String(output, StandardCharsets.UTF_8);



    }





}
