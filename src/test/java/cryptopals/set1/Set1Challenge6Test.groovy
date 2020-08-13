package cryptopals.set1

import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4.class)
class Set1Challenge6Test extends GroovyTestCase {

    @Test
    void testShouldPrintHello() {

        System.out.println("Hello");
        assert "hello"

    }

    @Test
    void testHammingDistance() {

        //Arrange
        String exampleStringOne = "this is a test";
        String exampleStringTwo = "wokka wokka!!!";

        long distance = Set1Challenge6.hammingDistance(exampleStringOne.getBytes(), exampleStringTwo.getBytes());

        assert distance == 37

    }

    @Test
    void testCalculateHammingDistanceShouldHandleUnevenStrings() {
        // Arrange
        byte[] little = ([0x01] * 4) as byte[]
        byte[] larger = ([0x02] * 8) as byte[]

        // Act
        def msg1 = shouldFail(IllegalArgumentException) {
            long hammingDistance = Set1Challenge6.hammingDistance(larger, little)
            System.out.println("HD: $hammingDistance")
        }
        System.out.println("Expected exception: $msg1")

        def msg2 = shouldFail(IllegalArgumentException) {
            long hammingDistance = Set1Challenge6.hammingDistance(little, larger)
            System.out.println("HD: $hammingDistance")
        }
        System.out.println("Expected exception: $msg2")

        // Assert
        assert msg1 =~ "Length"
        assert msg2 =~ "Length"
    }

    @Test
    void testShouldCalculateNormalizedHammingDistance() {
        // Arrange
        byte zero = 0x00
        byte fifteen = 0x0f // 4 bits different from 0

        def results = [:]

        // Act
        (1..5).each { int i ->
            byte[] allZeros = (zero * i) as byte[]
            byte[] allFifteens = (fifteen * i) as byte[]

            results[i] = Set1Challenge6.hammingDistanceNormalized(allZeros, allFifteens)
            System.out.println("Normalized HD for $i: ${results[i]}")
        }

        // Assert
        assert results.every { it.value == 4.0 }
    }

}
