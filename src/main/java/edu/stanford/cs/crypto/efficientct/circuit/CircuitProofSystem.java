package edu.stanford.cs.crypto.efficientct.circuit;

import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.ProofSystem;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;

public class CircuitProofSystem<T extends GroupElement<T>> implements ProofSystem<GeneratorParams<T>, ArithmeticCircuit<T>, CircuitWitness<T>, CircuitProof<T>, CircuitProver<T>, CircuitVerifier<T>> {
    @Override
    public CircuitProver<T> getProver() {
        return new CircuitProver<>();
    }

    @Override
    public CircuitVerifier<T> getVerifier() {
        return new CircuitVerifier<>();
    }
}
