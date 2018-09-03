package edu.stanford.cs.crypto.efficientct.circuit.parsing;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.circuit.ArithmeticCircuit;
import edu.stanford.cs.crypto.efficientct.algebra.BouncyCastleECPoint;
import edu.stanford.cs.crypto.efficientct.algebra.Group;
import edu.stanford.cs.crypto.efficientct.algebra.Secp256k1;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class CircuitParser {
    public ArithmeticCircuit<BouncyCastleECPoint> parse(Path file) throws IOException {
        List<String> lines = Files.readAllLines(file);
        Group<BouncyCastleECPoint> curve = new Secp256k1();
        // int n = Integer.parseInt(lines.get(0));
        int Q = Integer.parseInt(lines.get(1));
        List<FieldVector> leftWeights = new ArrayList<>(Q);
        for (int q = 0; q < Q; ++q) {
            VectorX<BigInteger> row = VectorX.of(lines.get(q + 2).split(",")).map(String::trim).map(BigInteger::new);
            leftWeights.add(FieldVector.from(row, curve.groupOrder()));
        }
        List<FieldVector> rightWeights = new ArrayList<>(Q);
        for (int q = 0; q < Q; ++q) {
            VectorX<BigInteger> row = VectorX.of(lines.get(q + 2 + Q).split(",")).map(String::trim).map(BigInteger::new);
            rightWeights.add(FieldVector.from(row, curve.groupOrder()));
        }
        List<FieldVector> outputWeights = new ArrayList<>(Q);
        for (int q = 0; q < Q; ++q) {
            VectorX<BigInteger> row = VectorX.of(lines.get(q + 2 + Q * 2).split(",")).map(String::trim).map(BigInteger::new);
            outputWeights.add(FieldVector.from(row, curve.groupOrder()));
        }
        VectorX<BigInteger> cs = VectorX.fill(Q, BigInteger.ZERO);
        VectorX<BouncyCastleECPoint> commitments = VectorX.empty();
        return new ArithmeticCircuit<>(VectorX.fromIterable(leftWeights), VectorX.fromIterable(rightWeights), VectorX.fromIterable(outputWeights), VectorX.empty(), cs, new GeneratorVector<>(VectorX.empty(), curve));

    }
}
