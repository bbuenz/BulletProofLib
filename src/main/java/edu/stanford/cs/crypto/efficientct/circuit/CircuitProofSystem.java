package edu.stanford.cs.crypto.efficientct.circuit;

import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.ProofSystem;
import edu.stanford.cs.crypto.efficientct.Verifier;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProofSystem;

public class CircuitProofSystem implements ProofSystem<GeneratorParams, ArithmeticCircuit, CircuitWitness, CircuitProof, CircuitProver, CircuitVerifier> {
    @Override
    public CircuitProver getProver() {
        return new CircuitProver();
    }

    @Override
    public CircuitVerifier getVerifier() {
        return new CircuitVerifier();
    }
}
