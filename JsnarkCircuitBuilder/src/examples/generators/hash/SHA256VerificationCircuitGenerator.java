package examples.generators.hash;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hash.SHA256Gadget;

import java.math.BigInteger;

public class SHA256VerificationCircuitGenerator extends CircuitGenerator {
    private Wire[] privateInput;
    private String inputStr = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl";
    private String expectedDigest = "aeacdd7013805404b62e0701cd09aeab2a4994c519d7f1d7cf7a295a5d8201ad";

    public SHA256VerificationCircuitGenerator(String circuitName){
        super(circuitName);
    }

    @Override
    protected void buildCircuit() {
        privateInput = createProverWitnessWireArray(64);
        Wire[] digest = new SHA256Gadget(privateInput, 8, 64, false,
                false).getOutputWires();
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
    }

    public static void main(String[] args) {

        SHA256VerificationCircuitGenerator circuitGenerator = new SHA256VerificationCircuitGenerator("SHA256-V");
        circuitGenerator.generateCircuit();
        circuitGenerator.evalCircuit();
        circuitGenerator.prepFiles();
        circuitGenerator.runLibsnark();
    }
}
