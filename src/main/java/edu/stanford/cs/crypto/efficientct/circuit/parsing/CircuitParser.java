package edu.stanford.cs.crypto.efficientct.circuit.parsing;

import com.google.gson.JsonObject;
import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.circuit.ArithmeticCircuit;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;

import java.io.BufferedReader;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CircuitParser {
    public static void main(String[] args) throws IOException {
        List<String> lines = Files.readAllLines(Paths.get(args[0]));
       // int n = Integer.parseInt(lines.get(0));
        int Q = Integer.parseInt(lines.get(1));
        List<FieldVector> leftWeights = new ArrayList<>(Q);
        for (int q = 0; q < Q; ++q) {
            VectorX<BigInteger> row = VectorX.of(lines.get(q + 2).split(",")).map(String::trim).map(BigInteger::new);
            leftWeights.add(FieldVector.from(row));
        }
        List<FieldVector> rightWeights = new ArrayList<>(Q);
        for (int q = 0; q < Q; ++q) {
            VectorX<BigInteger> row = VectorX.of(lines.get(q + 2+Q).split(",")).map(String::trim).map(BigInteger::new);
            rightWeights.add(FieldVector.from(row));
        }
        List<FieldVector> outputWeights = new ArrayList<>(Q);
        for (int q = 0; q < Q; ++q) {
            VectorX<BigInteger> row = VectorX.of(lines.get(q + 2+Q*2).split(",")).map(String::trim).map(BigInteger::new);
            outputWeights.add(FieldVector.from(row));
        }
        VectorX<BigInteger> cs = VectorX.fill(Q, BigInteger.ZERO);
        new ArithmeticCircuit(VectorX.fromIterable(leftWeights), VectorX.fromIterable(rightWeights), VectorX.fromIterable(outputWeights), VectorX.empty(), cs, GeneratorVector.from(VectorX.empty()));
    }
}
