package edu.stanford.cs.crypto.efficientct.circuit;

import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.Verifier;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;

public class CircuitNPVerifier implements Verifier<Object, ArithmeticCircuit, CircuitWitness> {
    @Override
    public void verify(Object params, ArithmeticCircuit input, CircuitWitness proof) throws VerificationFailedException {
        equal(proof.getL().hadamard(proof.getR()), proof.getO(), "Hada failed");
        FieldVector lhs = proof.getL().matrixVectorProduct(input.getlWeights()).add(proof.getR().matrixVectorProduct(input.getrWeights())).add(proof.getO().matrixVectorProduct(input.getoWeights()));
        FieldVector rhs = FieldVector.from(proof.getCommitments().map(PeddersenCommitment::getX)).matrixVectorProduct(input.getCommitmentWeights()).add(input.getCs());
        for (int i = 0; i < lhs.size(); ++i) {
            equal(lhs.get(i), rhs.get(i), "Constraint " + i + " failed");

        }
    }
}
