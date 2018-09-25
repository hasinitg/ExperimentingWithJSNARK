package examples.generators.blockciphers;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.blockciphers.SymmetricEncryptionCBCGadget;
import util.Util;

import java.math.BigInteger;

public class SymmetricCBCCircuitGenerator extends CircuitGenerator {

    /*Inputs/outputs of internal gadgets*/
    private Wire[] plainTextToSymEncr;// as 64 bit words
    private Wire[] keyBits; //128 bits
    private Wire[] ivBits; //128 bits
    private Wire[] cipherText;

    /*Inputs to the circuit*/
    private String inputString;
    private int plainTextSize; //as 64bit words
    private String keyString;
    private String ivString;

    //currently only speck cipher is supported in CBC mode. therefore we hardcode it here.
    String cipherName = "speck128";

    /**
     * @param circuitName
     * @param plainText                 : given as hex string
     * @param plainTextSizeIn64BitWords
     * @param key                       : given as hex string
     * @param iv                        : given as hex string
     */
    public SymmetricCBCCircuitGenerator(String circuitName, String plainText, int plainTextSizeIn64BitWords,
                                        String key, String iv) {
        super(circuitName);
        this.inputString = plainText;
        this.plainTextSize = plainTextSizeIn64BitWords;
        this.keyString = key;
        this.ivString = iv;
    }

    @Override
    protected void buildCircuit() {
        plainTextToSymEncr = createProverWitnessWireArray(plainTextSize);
        keyBits = createProverWitnessWireArray(128);
        ivBits = createInputWireArray(128);
        Wire[] plainTextBits = new WireArray(plainTextToSymEncr).getBits(64).asArray();
        //Wire[] plainTextBits = new WireArray(plainTextToSymEncr).getBits(16).asArray();
        cipherText = new SymmetricEncryptionCBCGadget(plainTextBits, keyBits, ivBits,
                cipherName).getOutputWires();
        makeOutputArray(cipherText);
    }

    @Override
    public void generateSampleInput(CircuitEvaluator evaluator) {
        for (int i = 0; i < plainTextSize; i++) {
            String inputSubString = inputString.substring(i * 16, i * 16 + 16);
            //String inputSubString = inputString.substring(i * 2, i * 2 + 2);
            evaluator.setWireValue(plainTextToSymEncr[i], new BigInteger(inputSubString, 16));
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
            evaluator.setWireValue(keyBits[j], new BigInteger(binaryKey.substring(j, j + 1), 2));
            evaluator.setWireValue(ivBits[j], new BigInteger(binaryIV.substring(j, j + 1), 2));
        }

    }

    public static void main(String[] args) {
        //plaintext is hard coded here:
        String plainText = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl";
        String plainTextInHex = Util.stringToHex(plainText);
        //we assume plaintextInHex to be of size in multiples of 16 (i.e: original string to be in size in multiples of 8)
        //this is because, for the symmetric encryption gadget, input size is 64bit words (=16 hex, =8 chars)
        int plainTextSizeIn64BitWords = (plainTextInHex.length() * 4) / 64;
        //int plainTextSizeIn64BitWords = plainTextInHex.length() / 2;
        //key and iv was obtained from Speck256 test at: https://github.com/inmcm/Simon_Speck_Ciphers/blob/master/Python/simonspeckciphers/speck/speck.py
        String key = "1f1e1d1c1b1a19181716151413121110";
        String iv = "0f0e0d0c0b0a09080706050403020100";

        SymmetricCBCCircuitGenerator circuitGen = new SymmetricCBCCircuitGenerator("CBC", plainTextInHex,
                plainTextSizeIn64BitWords, key, iv);
        circuitGen.generateCircuit();
        circuitGen.evalCircuit();
        circuitGen.prepFiles();
        circuitGen.runLibsnark();


    }

}
