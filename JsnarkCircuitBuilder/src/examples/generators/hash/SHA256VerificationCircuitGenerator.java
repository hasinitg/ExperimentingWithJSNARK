package examples.generators.hash;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hash.SHA256Gadget;
import examples.tests.RandomTester;

import java.math.BigInteger;

public class SHA256VerificationCircuitGenerator extends CircuitGenerator {
    private Wire[] privateInput;
    private String inputStr = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl";

    //private String expectedDigest = "aeacdd7013805404b62e0701cd09aeab2a4994c519d7f1d7cf7a295a5d8201ad";
    private String expectedDigest = "2fcd5a0d60e4c941381fcc4e00a4bf8be422c3ddfafb93c809e8d1e2bfffae8e";

    public SHA256VerificationCircuitGenerator(String circuitName){
        super(circuitName);
    }

    @Override
    protected void buildCircuit() {
        privateInput = createProverWitnessWireArray(64);
        Wire[] digest = new SHA256Gadget(privateInput, 8, 64, false,
                false).getOutputWires();
//        privateInput = createProverWitnessWireArray(8);
//        Wire[] digest = new SHA256Gadget(privateInput, 64, 64, false,
//                false).getOutputWires();
        makeOutputArray(digest);
        int beginIndex = 0;
        int endIndex = 8;
        for(int i =0; i<8; i++){
            String ss = expectedDigest.substring(beginIndex, endIndex);
            addEqualityAssertion(digest[i], new BigInteger(ss, 16));
            beginIndex +=8;
            endIndex +=8;
        }
    }

    @Override
    public void generateSampleInput(CircuitEvaluator evaluator) {
        for(int i = 0; i < privateInput.length; i++){
            evaluator.setWireValue(privateInput[i], inputStr.charAt(i));
        }

//        String hex = RandomTester.charToHex(inputStr, inputStr.length());
//        int numOfWords = hex.length()/16;//assume multiple of 16s
//        int beginIndex = 0;
//        int endIndex = 16;
//        for(int i=0;i<numOfWords;i++){
//            String word = hex.substring(beginIndex, endIndex);
//            evaluator.setWireValue(privateInput[i], new BigInteger(word, 16));
//            beginIndex += 16;
//            endIndex +=16;
//        }

    }

    public static void main(String[] args) {

        SHA256VerificationCircuitGenerator circuitGenerator = new SHA256VerificationCircuitGenerator("SHA256-V");
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
