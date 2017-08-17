package edu.stanford.cs.crypto.efficientct;

import edu.stanford.cs.crypto.efficientct.util.ECConstants;

import java.math.BigInteger;

/**
 * Created by buenz on 7/7/17.
 */
public class FieldPolynomial {
    private final BigInteger[] coefficients;


    public FieldPolynomial(BigInteger... coefficients) {
        this.coefficients = coefficients;
    }

    public BigInteger eval(BigInteger x) {
        BigInteger evalValue = BigInteger.ZERO;
        BigInteger pow = BigInteger.ONE;
        for (int i = 0; i < coefficients.length; i++) {
            BigInteger coefficient = coefficients[i];
            evalValue = evalValue.add(coefficient.multiply(pow));
            pow = pow.multiply(x).mod(ECConstants.P);
        }
        return evalValue;
    }

    public BigInteger[] getCoefficients() {
        return coefficients;
    }


}
