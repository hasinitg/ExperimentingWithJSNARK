package examples.generators;

import circuit.auxiliary.LongElement;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.SHA256Gadget;
import examples.gadgets.rsa.RSAEncryptionV1_5_Gadget;
import examples.generators.rsa.RSAUtil;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

public class SHA_RSA_CircuitGenerator extends CircuitGenerator {

    private String inputStr;
    private Wire[] privateInputMessage;
    private Wire[] randomness;
    private Wire[] cipherText;

    private LongElement rsaModulus;
    private int plainTextLength = 64;
    private int rsaKeyLength;

    //static String expectedDigest = "aeacdd7013805404b62e0701cd09aeab2a4994c519d7f1d7cf7a295a5d8201ad";

    public SHA_RSA_CircuitGenerator(String circuitName, String inputString, int plainTextLength, int rsaKeyLength){
        super(circuitName);
        this.inputStr = inputString;
        this.plainTextLength = plainTextLength;
        this.rsaKeyLength = rsaKeyLength;
    }

    @Override
    protected void buildCircuit() {
        privateInputMessage = createProverWitnessWireArray(plainTextLength);

        for(int i = 0; i < plainTextLength;i++){
            privateInputMessage[i].restrictBitLength(8);
        }

        //SHA-256 part of the circuit
        Wire[] digest = new SHA256Gadget(privateInputMessage, 8, 64, false,
                false).getOutputWires();
        makeOutputArray(digest, "Output digest");

        //RSA part of the circuit
        randomness = createProverWitnessWireArray(RSAEncryptionV1_5_Gadget
                .getExpectedRandomnessLength(rsaKeyLength, plainTextLength));

        rsaModulus = createLongElementInput(rsaKeyLength);

        RSAEncryptionV1_5_Gadget rsaEncryptionV1_5_Gadget = new RSAEncryptionV1_5_Gadget(rsaModulus, privateInputMessage,
                randomness, rsaKeyLength);
        rsaEncryptionV1_5_Gadget.checkRandomnessCompliance();
        Wire[] cipherTextInBytes = rsaEncryptionV1_5_Gadget.getOutputWires(); // in bytes

        // do some grouping to reduce VK Size
        cipherText = new WireArray(cipherTextInBytes).packWordsIntoLargerWords(8, 30);
        makeOutputArray(cipherText,
                "Output cipher text");

    }

    @Override
    public void generateSampleInput(CircuitEvaluator evaluator) {
        for(int i = 0; i < privateInputMessage.length; i++){
            evaluator.setWireValue(privateInputMessage[i], inputStr.charAt(i));
        }

        try {

            // to make sure that the implementation is working fine,
            // encrypt with the underlying java implementation for RSA
            // Encryption in a sample run,
            // extract the randomness (after decryption manually), then run the
            // circuit with the extracted randomness

            SecureRandom random = new SecureRandom();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(rsaKeyLength, random);
            KeyPair pair = generator.generateKeyPair();
            Key pubKey = pair.getPublic();
            //((RSAPublicKey)pubKey).getPublicExponent();
            BigInteger modulus = ((RSAPublicKey) pubKey).getModulus();

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            evaluator.setWireValue(this.rsaModulus, modulus,
                    LongElement.BITWIDTH_PER_CHUNK);

            Key privKey = pair.getPrivate();

            cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
            byte[] cipherText = cipher.doFinal(inputStr.getBytes());
//			System.out.println("ciphertext : " + new String(cipherText));
            byte[] cipherTextPadded = new byte[cipherText.length + 1];
            System.arraycopy(cipherText, 0, cipherTextPadded, 1, cipherText.length);
            cipherTextPadded[0] = 0;

            byte[][] result = RSAUtil.extractRSARandomness1_5(cipherText,
                    (RSAPrivateKey) privKey);
            // result[0] contains the plaintext (after decryption)
            // result[1] contains the randomness

            boolean check = Arrays.equals(result[0], inputStr.getBytes());
            if (!check) {
                throw new RuntimeException(
                        "Randomness Extraction did not decrypt right");
            }

            byte[] sampleRandomness = result[1];
            for (int i = 0; i < sampleRandomness.length; i++) {
                evaluator.setWireValue(randomness[i], (sampleRandomness[i]+256)%256);
            }

        } catch (Exception e) {
            System.err
                    .println("Error while generating sample input for circuit");
            e.printStackTrace();
        }

    }

    public static void main(String[] args) {
        String inputStr = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl";
        int plainTextLength = 64;
        int rsaKeyLength = 1024;
        SHA_RSA_CircuitGenerator circuitGenerator = new SHA_RSA_CircuitGenerator("PrivIdEx-1", inputStr,
                plainTextLength, rsaKeyLength);
        circuitGenerator.generateCircuit();
        circuitGenerator.evalCircuit();
        circuitGenerator.prepFiles();
        circuitGenerator.runLibsnark();

//        CircuitEvaluator evaluator = circuitGenerator.getCircuitEvaluator();
//        String outDigest = "";
//        int beginIndex = 0;
//        int endIndex = 8;
//        for (Wire w : circuitGenerator.getOutWires()) {
//            String ss = expectedDigest.substring(beginIndex, endIndex);
//            System.out.println(ss);
//
//            BigInteger ex = new BigInteger(ss, 16);
//            if(evaluator.getWireValue(w).equals(ex)){
//                System.out.println("true");
//            }
//
//            outDigest = evaluator.getWireValue(w).toString(16);
//            System.out.println(outDigest);
//
//            beginIndex +=8;
//            endIndex +=8;
//        }
//        System.out.println("Finish");
//        System.out.println(outDigest);
    }
}
