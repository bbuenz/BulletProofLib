package edu.stanford.cs.crypto.efficientct;

import java.io.Serializable;

/**
 * Created by buenz on 7/10/17.
 */
public interface Proof extends Serializable {
    byte[] serialize();

}
