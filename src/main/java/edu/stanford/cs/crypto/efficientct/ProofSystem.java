package edu.stanford.cs.crypto.efficientct;

/**
 * Created by buenz on 6/28/17.
 */
public interface ProofSystem<PP, PI, W, P, PR extends Prover<PP, PI, W, P>, V extends Verifier<PP, PI, P>> {
    PR getProver();

    V getVerifier();
}
