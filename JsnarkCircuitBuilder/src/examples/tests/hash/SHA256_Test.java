/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.tests.hash;

import circuit.config.Config;
import examples.tests.RandomTester;
import junit.framework.TestCase;

import org.junit.Test;

import util.Util;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hash.SHA256Gadget;

import java.math.BigInteger;

/**
 * Tests SHA256 standard cases.
 * 
 */

public class SHA256_Test extends TestCase {

	@Test
	public void testCase1() {

		String inputStr = "";
		String expectedDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

		CircuitGenerator generator = new CircuitGenerator("SHA2_Test1") {

			Wire[] inputWires;

			@Override
			protected void buildCircuit() {
				inputWires = createInputWireArray(inputStr.length());
				Wire[] digest = new SHA256Gadget(inputWires, 8, inputStr.length(), false, true, "").getOutputWires();
				makeOutputArray(digest);
			}

			@Override
			public void generateSampleInput(CircuitEvaluator e) {
				// no input needed
			}
		};

		generator.generateCircuit();
		generator.evalCircuit();
		CircuitEvaluator evaluator = generator.getCircuitEvaluator();

		String outDigest = "";
		for (Wire w : generator.getOutWires()) {
			outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 8);
		}
		assertEquals(outDigest, expectedDigest);

	}

	@Test
	public void testCase2() {

		String inputStr = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
		String expectedDigest = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

		CircuitGenerator generator = new CircuitGenerator("SHA2_Test2") {

			Wire[] inputWires;

			@Override
			protected void buildCircuit() {
				inputWires = createInputWireArray(inputStr.length());
				Wire[] digest = new SHA256Gadget(inputWires, 8, inputStr.length(), false, true, "").getOutputWires();
				makeOutputArray(digest);
			}

			@Override
			public void generateSampleInput(CircuitEvaluator e) {
				for (int i = 0; i < inputStr.length(); i++) {
					e.setWireValue(inputWires[i], inputStr.charAt(i));
				}
			}
		};

		generator.generateCircuit();
		generator.evalCircuit();
		CircuitEvaluator evaluator = generator.getCircuitEvaluator();

		String outDigest = "";
		for (Wire w : generator.getOutWires()) {
			outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 8);
		}
		assertEquals(outDigest, expectedDigest);

	}

	@Test
	public void testCase3() {

		String inputStr = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
		String expectedDigest = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1";

		CircuitGenerator generator = new CircuitGenerator("SHA2_Test3") {

			Wire[] inputWires;

			@Override
			protected void buildCircuit() {
				inputWires = createInputWireArray(inputStr.length());
				Wire[] digest = new SHA256Gadget(inputWires, 8, inputStr.length(), false, true, "").getOutputWires();
				makeOutputArray(digest);
			}

			@Override
			public void generateSampleInput(CircuitEvaluator e) {
				for (int i = 0; i < inputStr.length(); i++) {
					e.setWireValue(inputWires[i], inputStr.charAt(i));
				}
			}
		};

		generator.generateCircuit();
		generator.evalCircuit();
		CircuitEvaluator evaluator = generator.getCircuitEvaluator();

		String outDigest = "";
		for (Wire w : generator.getOutWires()) {
			outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 8);
		}
		assertEquals(outDigest, expectedDigest);

	}

	@Test
	public void testCase4() {

		String inputStr = "abc";
		String expectedDigest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

		CircuitGenerator generator = new CircuitGenerator("SHA2_Test4") {

			Wire[] inputWires;

			@Override
			protected void buildCircuit() {
				inputWires = createInputWireArray(inputStr.length());
				Wire[] digest = new SHA256Gadget(inputWires, 8, inputStr.length(), false, true, "").getOutputWires();
				makeOutputArray(digest);
			}

			@Override
			public void generateSampleInput(CircuitEvaluator e) {
				for (int i = 0; i < inputStr.length(); i++) {
					e.setWireValue(inputWires[i], inputStr.charAt(i));
				}
			}
		};

		generator.generateCircuit();
		generator.evalCircuit();
		CircuitEvaluator evaluator = generator.getCircuitEvaluator();

		String outDigest = "";
		for (Wire w : generator.getOutWires()) {
			outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 8);
		}
		assertEquals(outDigest, expectedDigest);
	}

	@Test
	public void testCase5() {

		String inputStr = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl";
		String expectedDigest = "2fcd5a0d60e4c941381fcc4e00a4bf8be422c3ddfafb93c809e8d1e2bfffae8e";

		// Testing different settings of the bitWidthPerInputElement parameter
		// wordSize = # of bytes per input wire

		//for (int wordSize = 1; wordSize <= Config.LOG2_FIELD_PRIME / 8 - 1; wordSize++) {

		final int numBytesPerInputWire = 8;
		final int numHexDigitsPerInputWire = 16;
		String inputStrInHex = RandomTester.charToHex(inputStr, inputStr.length());

		CircuitGenerator generator = new CircuitGenerator("SHA2_Test5") {

				Wire[] inputWires;
				@Override
				protected void buildCircuit() {
					inputWires = createInputWireArray((inputStrInHex.length()/2)/ numBytesPerInputWire
							+ ((inputStrInHex.length()/2) % numBytesPerInputWire != 0 ? 1 : 0));
					Wire[] digest = new SHA256Gadget(inputWires, 8 * numBytesPerInputWire,
							inputStrInHex.length()/2, false, true, "")
							.getOutputWires();
					makeOutputArray(digest);
				}

				@Override
				public void generateSampleInput(CircuitEvaluator e) {
					for (int i = 0; i < inputWires.length; i++) {
						BigInteger sum = BigInteger.ZERO;
						for (int j = i * numHexDigitsPerInputWire; j < (i + 1) * numHexDigitsPerInputWire
								&& j < inputStrInHex.length()-2; j+=2) {
							String substring = inputStrInHex.substring(j, j+2);
							BigInteger v = new BigInteger(substring, 16);
//							BigInteger v = BigInteger.valueOf(inputStr
//									.charAt(j));
							sum = sum.add(v.shiftLeft((Math.floorDiv(j, 2) % numBytesPerInputWire) * 8));
						}
						e.setWireValue(inputWires[i], sum);
					}
				}
			};

			generator.generateCircuit();
			generator.evalCircuit();
			CircuitEvaluator evaluator = generator.getCircuitEvaluator();

			String outDigest = "";
			for (Wire w : generator.getOutWires()) {
				outDigest += Util.padZeros(
						evaluator.getWireValue(w).toString(16), 8);
			}
			assertEquals(expectedDigest, outDigest);

		//}

	}
}
