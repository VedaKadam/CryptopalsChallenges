package cryptopals.set2;

public class Set2Challenge15 {

    public static void main(String[] args) {

        byte[] plaintext = Set2Challenge9.paddingPKCS7(Set2Challenge11.randomBytes(15));
        System.out.println(validPadding(plaintext));

        String wrongPaddingPlaintext = "ICE ICE BABY";
        byte[] wrongPaddingBytes = new byte[1*16];
        System.arraycopy(wrongPaddingPlaintext.getBytes(), 0, wrongPaddingBytes, 0, wrongPaddingPlaintext.length());

        for(int i = wrongPaddingPlaintext.length(); i < 16; i++){

            wrongPaddingBytes[i] = (byte)4;

        }

        System.out.println(validPadding(wrongPaddingBytes));


    }

    public static boolean validPadding(byte[] plaintext){

        int blockSize = 16;
        int length = plaintext.length;
        if(length%blockSize == 0)
        {
            int lastByte = plaintext[length-1];
            int oneByte = plaintext[length-2];
            int count = 1;
            for(int j = length-3 ; oneByte == lastByte ; j-- ){
                count++;
                oneByte = plaintext[j];

            }
            if(count == lastByte){
                return true;
            }
        }

        return false;

    }


}
