package xax;
public class Ops extends Base implements Runnable, Comparable<Ops> {
    static long counter = 5L;
    static final String TEXT = "héllo 世界 end";
    int value; double weight; float ratio; long big; byte b; char c; short s; boolean flag; Object ref; int[] ints; long[] longs;
    public Ops(int v) { super(v); value = v; }
    public void run() { value++; }
    public int compareTo(Ops o) { return value - o.value; }
    public synchronized int sync(int a) { return a + value; }
    public native int nat(int a);
    static int table(int k) {
        switch (k) { case 0: return 10; case 1: return 11; case 2: return 13; case 3: return 17; case 5: return 19; default: return -1; }
    }
    static int lookup(int k) {
        switch (k) { case -100000: return 1; case 7: return 2; case 1 << 20: return 3; default: return 4; }
    }
    static long longs(long a, long b, int sh) {
        long r = a * b + a / (b | 1) - a % (b | 1);
        r ^= a << sh; r |= b >> sh; r &= a >>> sh;
        if (a < b) r = -r;
        if (a == b) r += 0x123456789ABCDEFL;
        return r + 0x7FFF_FFFF_FFFFL + Long.MIN_VALUE;
    }
    static double doubles(double x, float y, int i, long l) {
        double d = x * y + i / 3.5 - l % 7.0;
        float f = (float) d + y * 2.5f;
        int back = (int) f + (int) x + (int) l;
        long lb = (long) f + (long) x + i;
        if (d > 1.0) d = -d;
        if (f < 0.5f || d != d) f = 1e30f;
        return d + f + back + lb + (short) back + (byte) lb + (char) back + 1e300 + Double.MIN_VALUE;
    }
    int arrays(int n) {
        int[] a = new int[n]; long[] la = new long[n]; double[] da = new double[n]; float[] fa = new float[n];
        byte[] ba = new byte[n]; char[] ca = new char[n]; short[] sa = new short[n]; boolean[] za = new boolean[n]; String[] st = new String[n];
        int[][] grid = new int[n][];
        for (int i = 0; i < n; i++) {
            a[i] = i; la[i] += i; da[i] = i * 0.5; fa[i] = i; ba[i] = (byte) i; ca[i] = (char) i; sa[i] = (short) i; if (i % 2 == 0) za[i] = true;
            st[i] = TEXT; grid[i] = a; a[i] += 3; la[i] <<= 2; ints = a; longs = la;
        }
        int total = 0;
        for (int i = 0; i < n; i++) total += a[i] + (int) la[i] + (int) da[i] + (int) fa[i] + ba[i] + ca[i] + sa[i] + ca.length + grid[i].length;
        return total + st.length;
    }
    long fields() {
        counter++; big += counter; weight *= 2; ratio -= 1f; b++; c += 2; s--; if (flag) flag = false; else flag = true;
        long x = big; this.big = x = counter = x + 1;
        ref = this; Object o = ref;
        if (o instanceof Ops) { ((Ops) o).value++; }
        if (o != null && ref == o) value = 0;
        if (flag) x++;
        return x;
    }
    static int wide(int a) {
        int v0=a,v1=a,v2=a,v3=a,v4=a,v5=a,v6=a,v7=a,v8=a,v9=a,v10=a,v11=a,v12=a,v13=a,v14=a,v15=a,v16=a,v17=a,v18=a,v19=a;
        long w0=a,w1=a,w2=a,w3=a,w4=a,w5=a,w6=a,w7=a,w8=a,w9=a,w10=a,w11=a,w12=a,w13=a,w14=a,w15=a,w16=a,w17=a,w18=a,w19=a;
        double d0=a,d1=a,d2=a,d3=a,d4=a,d5=a,d6=a,d7=a,d8=a,d9=a,d10=a,d11=a,d12=a,d13=a,d14=a,d15=a,d16=a,d17=a,d18=a,d19=a;
        long[] e0=new long[1],e1=e0,e2=e0,e3=e0,e4=e0,e5=e0,e6=e0,e7=e0,e8=e0,e9=e0,e10=e0,e11=e0,e12=e0,e13=e0,e14=e0,e15=e0,e16=e0,e17=e0,e18=e0,e19=e0;
        long x0=a,x1=a,x2=a,x3=a,x4=a,x5=a,x6=a,x7=a,x8=a,x9=a,x10=a,x11=a,x12=a,x13=a,x14=a,x15=a,x16=a,x17=a,x18=a,x19=a;
        long y0=a,y1=a,y2=a,y3=a,y4=a,y5=a,y6=a,y7=a,y8=a,y9=a,y10=a,y11=a,y12=a,y13=a,y14=a,y15=a,y16=a,y17=a,y18=a,y19=a;
        long z0=a,z1=a,z2=a,z3=a,z4=a,z5=a,z6=a,z7=a,z8=a,z9=a,z10=a,z11=a,z12=a,z13=a,z14=a,z15=a,z16=a,z17=a,z18=a,z19=a;
        int far = a; far += 1000; far += 70000;
        e19[0] += 5; e19[0]++; z19 = y19 * x19 + w19; d19 = d18 / d17;
        if (far > z19) far = (int) (z19 + y0 + x0 + w0 + v0 + d0 + d19);
        return far + v19 + (int) e19[0] + (int) z19;
    }
    static int dups(long[] arr, int[] ia, Ops o, int i) {
        long q = arr[i]++; int p = ia[i]--; long r = (o.big += 3); int t = (o.value *= 2); long u = (counter += 7);
        return (int) (q + p + r + t + u);
    }
    void frames(int n) {
        int k = 0;
        while (k < n) { long w = k; double d = w; if (d > 3) { int z = 2; k += z; } k++; }
        for (int i = 0; i < n; i++) { if (i == 3) continue; String sx = TEXT; if (sx == null) return; }
        Object o = null; if (n > 0) o = this;
        value = 2; if (o == null) value = 1;
    }
    static Class<?> klass() { return Ops[].class; }
    public String toString() { return new StringBuilder().append(value).append(TEXT).toString(); }
}
