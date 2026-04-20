package ECC;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Represents a point on an elliptic curve over the finite field GF(p).
 *
 * <p>The special singleton {@link #INFINITY} represents the <em>point at infinity</em>,
 * i.e. the identity element of the elliptic-curve group.  It is characterised by
 * both coordinates being {@code null}.
 *
 * <p>Curve equation: y² ≡ x³ + ax + b (mod p)
 */
public class Point {

    /** The point at infinity — identity element of the elliptic-curve group. */
    public static final Point INFINITY = new Point(null, null);

    /** x-coordinate, or {@code null} for the point at infinity. */
    public final BigInteger x;

    /** y-coordinate, or {@code null} for the point at infinity. */
    public final BigInteger y;

    /**
     * Constructs a finite point {@code (x, y)}.
     *
     * @param x x-coordinate
     * @param y y-coordinate
     */
    public Point(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    /**
     * Convenience constructor that accepts {@code long} values.
     *
     * @param x x-coordinate
     * @param y y-coordinate
     */
    public Point(long x, long y) {
        this(BigInteger.valueOf(x), BigInteger.valueOf(y));
    }

    /**
     * Returns {@code true} if this point is the point at infinity.
     *
     * @return {@code true} iff both coordinates are {@code null}
     */
    public boolean isInfinity() {
        return x == null && y == null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Point)) return false;
        Point other = (Point) o;
        return Objects.equals(x, other.x) && Objects.equals(y, other.y);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x, y);
    }

    @Override
    public String toString() {
        return isInfinity() ? "∞" : "(" + x + ", " + y + ")";
    }
}

