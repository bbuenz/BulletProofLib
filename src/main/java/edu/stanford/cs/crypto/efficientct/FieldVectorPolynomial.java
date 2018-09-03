package edu.stanford.cs.crypto.efficientct;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Created by buenz on 7/6/17.
 */
public class FieldVectorPolynomial {
    private final VectorX<FieldVector> coefficients;

    public FieldVectorPolynomial(VectorX<FieldVector> coefficients) {
        this.coefficients = coefficients;
    }

    public FieldVectorPolynomial(FieldVector... coefficients) {
        this.coefficients = VectorX.of(coefficients);
    }

    public FieldVector evaluate(BigInteger x) {
        return coefficients.zipWithIndex().filter(t -> t.v1 != null).map(tup -> tup.map2(Long::intValue).map2(x::pow).map(FieldVector::times)).reduce(FieldVector::add).get();
    }

    public FieldPolynomial innerProduct(FieldVectorPolynomial other) {
        BigInteger[] newCoefficients = new BigInteger[coefficients.size() + other.coefficients.size() - 1];
        Arrays.fill(newCoefficients, BigInteger.ZERO);
        for (int i = 0; i < coefficients.size(); ++i) {
            FieldVector aCoefficient = coefficients.get(i);
            if (aCoefficient != null) {
                for (int j = 0; j < other.coefficients.size(); ++j) {
                    FieldVector b = other.coefficients.get(j);
                    if (b != null) {
                        newCoefficients[i + j] = newCoefficients[i + j].add(aCoefficient.innerPoduct(b));
                    }

                }
            }
        }
        return new FieldPolynomial(newCoefficients);
    }
}
