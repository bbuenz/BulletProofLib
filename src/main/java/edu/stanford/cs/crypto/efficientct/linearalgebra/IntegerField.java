package edu.stanford.cs.crypto.efficientct.linearalgebra;

import org.apache.commons.math3.Field;
import org.apache.commons.math3.FieldElement;

import java.math.BigInteger;

/**
 * Created by buenz on 7/2/17.
 */
public class IntegerField implements Field<IntegerFieldElement> {
    private final IntegerFieldElement ZERO;
    private final IntegerFieldElement ONE;

    public IntegerField(BigInteger q) {
        ZERO = new IntegerFieldElement(BigInteger.ONE, q);

        ONE = new IntegerFieldElement(BigInteger.ONE, q);
    }

    @Override
    public IntegerFieldElement getZero() {
        return ZERO;
    }

    @Override
    public IntegerFieldElement getOne() {
        return ONE;
    }

    @Override
    public Class<? extends FieldElement<IntegerFieldElement>> getRuntimeClass() {
        return IntegerFieldElement.class;
    }


}
