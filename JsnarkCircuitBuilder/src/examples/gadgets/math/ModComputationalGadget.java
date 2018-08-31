package examples.gadgets.math;

import circuit.eval.CircuitEvaluator;
import circuit.eval.Instruction;
import circuit.operations.Gadget;
import circuit.structure.Wire;

import java.math.BigInteger;

public class ModComputationalGadget extends Gadget {

    private final Wire a;
    private final Wire b;
    private Wire r;

    public ModComputationalGadget(Wire a,  Wire b, String...desc) {
        super(desc);
        this.a = a;
        this.b = b;
        buildCircuit();
    }

    private void buildCircuit() {

        r = generator.createConstantWire(BigInteger.ZERO, "mod result");
        CircuitEvaluator eval = generator.getCircuitEvaluator();
        BigInteger aValue = eval.getWireValue(a);
        BigInteger bValue = eval.getWireValue(b);
        BigInteger rValue = aValue.mod(bValue);
        eval.setWireValue(r, rValue);
//        // notes about how to use this code block can be found in FieldDivisionGadget
//        generator.specifyProverWitnessComputation(new Instruction() {
//
//            @Override
//            public void evaluate(CircuitEvaluator evaluator) {
//                BigInteger aValue = evaluator.getWireValue(a);
//                BigInteger bValue = evaluator.getWireValue(b);
//                BigInteger rValue = aValue.mod(bValue);
//                evaluator.setWireValue(r, rValue);
//                //BigInteger qValue = aValue.divide(bValue);
//                //evaluator.setWireValue(q, qValue);
//            }
//
//        });

    }

    @Override
    public Wire[] getOutputWires() {
        return new Wire[] {r};
    }
}
