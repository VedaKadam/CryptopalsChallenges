package cryptopals.set2

import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4.class)
class Set2Challenge10Test extends GroovyTestCase {

    @Test
    void testDividePlaintextInBlocks(){
        //Arrange
        //def blockString = ('A'..'P').collect { it }.join("")
        def blockString1 = "ABCDEFGHIJKLMNOP"
        def blockString2 = "PONMABCDEFGHIJKL"
        def blockString = blockString1 + blockString2
        def otherBlockString = "ABCDEFGHIJKLMNOP"
        //assert blockString == otherBlockString

        int repetitions = 2
        byte[] plaintext = (blockString).bytes
        System.out.println("Before dividing, byte[] has ${plaintext.length} bytes")

        byte[] key = "YELLOW SUBMARINE".bytes

        //Act
        def list = Set2Challenge10.dividePlaintextInBlocks(plaintext, key)
        System.out.println("Divided into ${list.size()} blocks")

        //System.out.println("${list.class.name}")

        //Assert
        assert list.size() == repetitions
        //System.out.println(list.class.methods)
        assert list.get(0) == (blockString1).bytes
        assert list.get(1) == (blockString2).bytes
        assert blockString.bytes.length == plaintext.length
    }

    @Test
    void testXORIVAndEncryptWithAES(){

        //def blockString = ('A'..'P').collect { it }.join("")
        def blockString = "ABCDEFGHIJKLMNOPPONMABCDEFGHIJKL"
        int repetitions = 1
        byte[] plaintext = (blockString).bytes
        List<byte[]> myList = new ArrayList<>()
        myList.add(plaintext)
        myList.add(plaintext)

        byte[] key = "YELLOW SUBMARINE".bytes
        byte[] initVector = new byte[16];
        def cipherList = Set2Challenge10.XORIVAndEncryptWithAES(myList, key, initVector);







    }

    private def returnUnknownObject() {
        if (Math.random().next().intValue() > 0) {
            return "This is a string"
        } else {
            return ["This", "is", "a", "list"]
        }
    }


}
