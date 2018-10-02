package examples.generators.hash;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hash.SHA256Gadget;
import examples.tests.RandomTester;
import util.Util;

import java.math.BigInteger;

public class SHA256Tester extends CircuitGenerator {

    Wire[] inputWires;
    String inputString;
    public SHA256Tester(String circName, String inputString) {
        super(circName);
        this.inputString  = inputString;
    }

    @Override
    protected void buildCircuit() {
        inputWires = createProverWitnessWireArray(inputString.length());
        //inputWires = createProverWitnessWireArray((inputString.length()*8)/64);
        Wire[] digest = new SHA256Gadget(inputWires, 8, inputString.length(),
                false, false, "").getOutputWires();
//        Wire[] digest = new SHA256Gadget(inputWires, 64, inputString.length(),
//                false, false, "").getOutputWires();
        makeOutputArray(digest);
    }

    @Override
    public void generateSampleInput(CircuitEvaluator evaluator) {
//        for (int i = 0; i < inputString.length(); i++) {
//            //evaluator.setWireValue(inputWires[i], inputString.charAt(i));
//            String ss = inputString.substring(i, i+2);
//            evaluator.setWireValue(inputWires[i], new BigInteger(ss, 16));
//        }
        String hex = RandomTester.charToHex(inputString, inputString.length());
        int numOfWords = hex.length()/2;//assume multiple of 16s
        //int numOfWords = hex.length()/16;//assume multiple of 16s
        int beginIndex = 0;
        int endIndex = 2;
        //int endIndex = 16;
        for(int i=0;i<numOfWords;i++){
            String word = hex.substring(beginIndex, endIndex);
            evaluator.setWireValue(inputWires[i], new BigInteger(word, 16));
            beginIndex += 2;
            //beginIndex += 16;
            endIndex +=2;
            //endIndex +=16;
        }
    }

    public static void main(String[] args) {
        String inputString = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl";
        //this is what you get if padding true
        String expectedDigest = "2fcd5a0d60e4c941381fcc4e00a4bf8be422c3ddfafb93c809e8d1e2bfffae8e";
        //this is what you get if padding false
        String expectedDigest1 = "aeacdd7013805404b62e0701cd09aeab2a4994c519d7f1d7cf7a295a5d8201ad";


        SHA256Tester tester = new SHA256Tester("Test", inputString);

        tester.generateCircuit();
        tester.evalCircuit();
//        tester.prepFiles();
//        tester.runLibsnark();
        CircuitEvaluator evaluator = tester.getCircuitEvaluator();

        String outDigest = "";
        for(Wire w : tester.getOutWires()) {
            outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 8);
        }
        System.out.println(outDigest);
    }
}
