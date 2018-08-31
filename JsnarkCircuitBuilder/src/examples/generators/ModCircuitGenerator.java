package examples.generators;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.math.ModComputationalGadget;

public class ModCircuitGenerator extends CircuitGenerator {

    private Wire integer;
    private Wire modulo;
    private Wire remainder;

    public ModCircuitGenerator(String circuitName) {
        super(circuitName);
    }
    @Override
    protected void buildCircuit() {
        integer = createInputWire();
        modulo = createProverWitnessWire();
        remainder = createInputWire();

        ModComputationalGadget mod = new ModComputationalGadget(integer, modulo);
        Wire result = mod.getOutputWires()[0];
        addEqualityAssertion(remainder, result);
    }

    @Override
    public void generateSampleInput(CircuitEvaluator evaluator) {
        evaluator.setWireValue(integer, 13);
        evaluator.setWireValue(modulo, 7);
        evaluator.setWireValue(remainder, 6);
    }

    public static void main(String[] args) {
        ModCircuitGenerator modCircuit = new ModCircuitGenerator("ModCircuit");
        modCircuit.generateCircuit();
        modCircuit.evalCircuit();
        modCircuit.prepFiles();
        modCircuit.runLibsnark();

    }
}
