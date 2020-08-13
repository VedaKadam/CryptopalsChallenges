package cryptopals.set2

import groovy.json.JsonSlurper
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4.class)
class Set2Challenge13Test extends GroovyTestCase {

    @Test
    void testParse() {

        //Arrange
        String encodedString = "email=veda@veda.com&uid=7&role=intern"
        def expectedOutput = [email: "veda@veda.com", uid: "7", role: "intern"]

        //Act
        def jsonParser = new JsonSlurper();
        def output = jsonParser.parseText(Set2Challenge13.parse(encodedString))

        //Assert
        assert output.email == expectedOutput.email
        assert output.uid == expectedOutput.uid
        assert output.role == expectedOutput.role
        println(output)
    }


}
