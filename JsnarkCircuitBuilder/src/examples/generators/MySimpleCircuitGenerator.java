package examples.generators;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;

public class MySimpleCircuitGenerator extends CircuitGenerator {

    private Wire[] privateInputs;

    public MySimpleCircuitGenerator(String circuitName) {
        super(circuitName);
    }

    @Override
    protected void buildCircuit() {
        //publicInput = createInputWire();
        Wire constantInput = createConstantWire(7);
        privateInputs = createProverWitnessWireArray(2);
        Wire intermediate = privateInputs[0].add(privateInputs[1]);
        addEqualityAssertion(constantInput, intermediate);

        //following line does not make any difference.
        //makeOutput(constantInput);
    }

    @Override
    public void generateSampleInput(CircuitEvaluator evaluator) {
        evaluator.setWireValue(privateInputs[0], 2);
        evaluator.setWireValue(privateInputs[1], 5);
    }

    public static void main(String[] args) {
        MySimpleCircuitGenerator myGen = new MySimpleCircuitGenerator("zcash_blog_example");
        myGen.generateCircuit();
        myGen.evalCircuit();
        myGen.evalCircuit();
        myGen.prepFiles();
        myGen.runLibsnark();
    }
}
