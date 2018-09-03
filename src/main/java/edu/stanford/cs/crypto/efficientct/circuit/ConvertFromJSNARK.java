package edu.stanford.cs.crypto.efficientct.circuit;

import circuit.eval.Instruction;
import circuit.operations.primitive.AddBasicOp;
import circuit.structure.CircuitGenerator;
import edu.stanford.cs.crypto.efficientct.algebra.BouncyCastleECPoint;

public class ConvertFromJSNARK {

    public ArithmeticCircuit<BouncyCastleECPoint> convertFrom(CircuitGenerator generator) {

        generator.prepFiles();

        for (Instruction e : generator.getEvaluationQueue().keySet()) {
            if (e instanceof AddBasicOp) {
                AddBasicOp add = (AddBasicOp) e;
                add.getInputs()[0].getWireId();
            }
        }
        return null;
    }
}
