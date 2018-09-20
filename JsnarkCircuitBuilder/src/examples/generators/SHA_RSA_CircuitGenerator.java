package examples.generators;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.blockciphers.SymmetricEncryptionCBCGadget;
import examples.gadgets.hash.SHA256Gadget;
import util.Util;

import java.math.BigInteger;

public class SHA_RSA_CircuitGenerator extends CircuitGenerator {

    /*Inputs to the SHA256 gadget*/
    private Wire[] plainTextWiresToSHA256;
    private int plainTextWordSizeForSHA256; //in 8-bits words

    /*Inputs,outputs of the symmetric CBC gadget*/
    private Wire[] plainTextWiresToSymEncr;// as 64 bit words
    private int plainTextWordSizeForSymEncr; //in 64 bit words
    private Wire[] keyBitsWires; //128 bits
    private Wire[] ivBitsWires; //128 bits
    private final int keyIVSize = 128;
    private Wire[] cipherText;

    /*Inputs to the circuit*/
    private String plainTextInHex; //in hex
    private String keyString; //in hex
    private String ivString; //in hex

    //currently only speck cipher is supported in CBC mode. therefore we hardcode it here.
    String cipherName = "speck128";

    //todo: write a test case
    public SHA_RSA_CircuitGenerator(String circuitName, String plainText, String key, String iv) {
        super(circuitName);
        this.plainTextInHex = plainText;
        //todo: check the constraints on plaintext size
        this.keyString = key;
        this.ivString = iv;
    }

    @Override
    protected void buildCircuit() {
        //SHA-256 sub circuit logic
        plainTextWordSizeForSHA256 = plainTextInHex.length() / 2;
        plainTextWiresToSHA256 = createProverWitnessWireArray(plainTextWordSizeForSHA256);
        Wire[] digest = new SHA256Gadget(plainTextWiresToSHA256, 8, plainTextWordSizeForSHA256,
                false, true, "").getOutputWires();
        makeOutputArray(digest);

        //Symmetric CBC sub circuit logic
        plainTextWordSizeForSymEncr = (plainTextInHex.length() * 4) / 64;
        plainTextWiresToSymEncr = createProverWitnessWireArray(plainTextWordSizeForSymEncr);
        keyBitsWires = createProverWitnessWireArray(keyIVSize);
        ivBitsWires = createProverWitnessWireArray(keyIVSize);
        Wire[] plainTextBits = new WireArray(plainTextWiresToSymEncr).getBits(64).asArray();
        cipherText = new SymmetricEncryptionCBCGadget(plainTextBits, keyBitsWires, ivBitsWires, cipherName).getOutputWires();
        makeOutputArray(cipherText);
    }

    @Override
    public void generateSampleInput(CircuitEvaluator evaluator) {
        //set input wires of SHA-256 sub circuit
        for (int i = 0; i < plainTextWordSizeForSHA256; i++) {
            String word = plainTextInHex.substring(i * 2, i * 2 + 2);
            evaluator.setWireValue(plainTextWiresToSHA256[i], new BigInteger(word, 16));
        }

        //set input wires of Symmetric CBC sub circuit
        for (int i = 0; i < plainTextWordSizeForSymEncr; i++) {
            String inputSubString = plainTextInHex.substring(i * 16, i * 16 + 16);
            evaluator.setWireValue(plainTextWiresToSymEncr[i], new BigInteger(inputSubString, 16));
        }
        //convert hex representations of key and iv to binary reqpresentation
        String binaryKey = new BigInteger(keyString, 16).toString(2);
        int binaryKeyLength = binaryKey.length();
        if (binaryKeyLength != 128) {
            int paddingLength = 128 - binaryKeyLength;
            for (int i = 0; i < paddingLength; i++) {
                binaryKey = "0" + binaryKey;
            }
        }
        String binaryIV = new BigInteger(ivString, 16).toString(2);
        int binaryIVLength = binaryIV.length();
        if (binaryIVLength != 128) {
            int paddingLength = 128 - binaryIVLength;
            for (int i = 0; i < paddingLength + 1; i++) {
                binaryIV = "0" + binaryIV;
            }
        }
        for (int j = 0; j < 128; j++) {
            evaluator.setWireValue(keyBitsWires[j], new BigInteger(binaryKey.substring(j, j + 1), 2));
            evaluator.setWireValue(ivBitsWires[j], new BigInteger(binaryIV.substring(j, j + 1), 2));
        }
    }

    public static void main(String[] args) {
        String plainText = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl";
        //we assume plaintextInHex to be of size in multiples of 16 (i.e: original string to be in size in multiples of 8)
        //this is because, for the symmetric encryption gadget, input size is 64bit words (=16 hex, =8 chars)
        String plainTextInHex = Util.stringToHex(plainText);
        //key and iv was obtained from Speck256 test at: https://github.com/inmcm/Simon_Speck_Ciphers/blob/master/Python/simonspeckciphers/speck/speck.py
        String key = "1f1e1d1c1b1a19181716151413121110";
        String iv = "0f0e0d0c0b0a09080706050403020100";

        SHA_RSA_CircuitGenerator circuitGenerator = new SHA_RSA_CircuitGenerator("PrivIdEx-1", plainTextInHex,
                key, iv);
        circuitGenerator.generateCircuit();
        circuitGenerator.evalCircuit();
        circuitGenerator.prepFiles();
        circuitGenerator.runLibsnark();
    }
}
