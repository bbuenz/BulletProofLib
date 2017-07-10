package edu.stanford.cs.crypto.efficientct;

/**
 * Created by buenz on 6/29/17.
 */
public interface Prover <PP ,I,W,P>{
    P generateProof(PP parameter,I input,W witness);

}
