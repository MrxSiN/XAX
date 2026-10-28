package xax;
public abstract class Base {
    protected int seed;
    protected Base(int s) { seed = s; }
    protected abstract void run();
    public int hash() { return seed * 31; }
    public interface Shape { double area(); default int sides() { return 0; } }
}
