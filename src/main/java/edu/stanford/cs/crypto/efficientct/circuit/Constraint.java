package edu.stanford.cs.crypto.efficientct.circuit;

import java.math.BigInteger;

public class Constraint {
    public enum Operation {
        ADD,
        MULT;
    }

    public int inputLeft;
    public int inputRight;
    public Operation operation;

}
