package edu.stanford.cs.crypto.efficientct.zetherprover;

import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;

public class ZetherStatement<T extends GroupElement<T>> {
    private final T balanceCommitNewL;
    private final T balanceCommitNewR;
    private final T outL;
    private final T inL;
    private final T inOutR;
    private final T y;
    private final T yBar;


    public ZetherStatement(T balanceCommitNewL, T balanceCommitNewR, T outL, T inL, T inOutR, T y, T yBar) {
        this.balanceCommitNewL = balanceCommitNewL;
        this.balanceCommitNewR = balanceCommitNewR;
        this.outL = outL;
        this.inL = inL;
        this.inOutR = inOutR;
        this.y = y;
        this.yBar = yBar;
    }

    public T getBalanceCommitNewL() {
        return balanceCommitNewL;
    }

    public T getBalanceCommitNewR() {
        return balanceCommitNewR;
    }

    public T getOutL() {
        return outL;
    }

    public T getInL() {
        return inL;
    }

    public T getInOutR() {
        return inOutR;
    }

    public T getY() {
        return y;
    }

    public T getyBar() {
        return yBar;
    }
}
