package cryptopals.set2;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Scanner;

public class Set2Challenge9 {

    public static void main(String[] args) {

        Scanner s = new Scanner(System.in);
        //System.out.println("Enter input: ");
        //String input = s.nextLine();
        String input = "YELLOW";
        //System.out.println("Enter block size: ");
        int blockSize = 16;

        System.out.println("Input string size: " + input.getBytes().length +"B");
        System.out.println("Block size: "+ blockSize + "B") ;
        byte[] inputPaddedBytes = paddingPKCS7(input.getBytes());
        System.out.println(new String(inputPaddedBytes, StandardCharsets.UTF_8));
        System.out.println(inputPaddedBytes.length);
        byte[] paddingRemoved = removePKCS7(inputPaddedBytes);
        System.out.println(new String(paddingRemoved, StandardCharsets.UTF_8));
        System.out.println(paddingRemoved.length);


    }

    public static byte[] paddingPKCS7(byte[] input){

        int blockSize = 16;
        int paddingLength = 0;
        if (blockSize > input.length){
            paddingLength = blockSize - input.length;
        }
        else if(blockSize == input.length){
            paddingLength = blockSize;
        }
        else{
            paddingLength = blockSize - (input.length % blockSize);
        }
        if(paddingLength==0){
            paddingLength = blockSize;
        }
        byte[] inputPaddedBytes = new byte[input.length + paddingLength];
        System.arraycopy(input, 0, inputPaddedBytes, 0, input.length);

        for(int i=input.length; i<inputPaddedBytes.length; i++){
            inputPaddedBytes[i] = (byte) paddingLength;
        }

        return inputPaddedBytes;

    }

    public static byte[] removePKCS7(byte[] input){

        int paddingLength = input[input.length-1];

        byte[] inputWithoutPadding = new byte[input.length-paddingLength];
        System.arraycopy(input, 0, inputWithoutPadding, 0, input.length-paddingLength);

        return inputWithoutPadding;

    }

}



