package edu.stanford.cs.crypto.efficientct.linearalgebra;

import org.apache.commons.math3.Field;
import org.apache.commons.math3.FieldElement;
import org.apache.commons.math3.exception.MathArithmeticException;
import org.apache.commons.math3.exception.NullArgumentException;

import java.math.BigInteger;

/**
 * Created by buenz on 7/2/17.
 */
public class IntegerFieldElement implements FieldElement<IntegerFieldElement> {

    /**
     * Underlying BigDecimal.
     */
    private final BigInteger d;
    /**
     * Size of field
     */

    private final BigInteger q;
    private final IntegerField field;

    /**
     * @param d
     * @param fieldSize
     */
    public IntegerFieldElement(BigInteger d, BigInteger fieldSize) {
        this.d = d;
        this.q = fieldSize;
        field = new IntegerField(q);
    }


    @Override
    public IntegerFieldElement add(IntegerFieldElement a) throws NullArgumentException {
        return new IntegerFieldElement(d.add(a.d).mod(q), q);
    }

    @Override
    public IntegerFieldElement subtract(IntegerFieldElement a) throws NullArgumentException {
        return new IntegerFieldElement(d.subtract(a.d).mod(q), q);
    }

    @Override
    public IntegerFieldElement negate() {
        return new IntegerFieldElement(d.negate().mod(q), q);
    }

    @Override
    public IntegerFieldElement multiply(int n) {
        return new IntegerFieldElement(d.multiply(BigInteger.valueOf(n)).mod(q), q);
    }

    @Override
    public IntegerFieldElement multiply(IntegerFieldElement a) throws NullArgumentException {
        return new IntegerFieldElement(d.multiply(a.d).mod(q), q);
    }

    @Override
    public IntegerFieldElement divide(IntegerFieldElement a) throws NullArgumentException, MathArithmeticException {
        return new IntegerFieldElement(d.multiply(a.d.modInverse(q)).mod(q), q);
    }

    @Override
    public IntegerFieldElement reciprocal() throws MathArithmeticException {
        return new IntegerFieldElement(d.modInverse(q), q);
    }

    @Override
    public Field<IntegerFieldElement> getField() {
        return field;
    }
}
