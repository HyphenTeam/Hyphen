//! Q32.32 fixed-point arithmetic.
//!
//! Consensus code cannot use floating point: rounding modes, fused
//! multiply-add contraction and NaN payloads are not portable, so the same
//! program can produce two different answers on two hosts. Every operation here
//! is integer-only and exactly reproducible.
//!
//! A value is a signed 64-bit integer with 32 fractional bits. Multiplication
//! truncates toward negative infinity (arithmetic shift), division truncates
//! toward zero, and saturation clamps to the representable range instead of
//! wrapping. Those three rules are the whole numeric contract; anything that
//! depends on another rounding rule must not reach consensus.

/// Number of fractional bits in a Q32.32 value.
pub const FRAC_BITS: u32 = 32;

/// Q32.32 representation of `1.0`.
pub const ONE: i64 = 1 << FRAC_BITS;

/// Largest Q32.32 value the type can represent.
pub const MAX: i64 = i64::MAX;

/// Smallest Q32.32 value the type can represent.
pub const MIN: i64 = i64::MIN;

/// Converts an integer to Q32.32, saturating on overflow.
pub const fn from_int(value: i64) -> i64 {
    value.saturating_mul(ONE)
}

/// Rounds a Q32.32 value to the nearest integer, truncating halfway cases
/// toward positive infinity.
pub fn to_int(value: i64) -> i64 {
    value.saturating_add(ONE / 2) >> FRAC_BITS
}

/// Q32.32 multiplication: `(a * b) >> 32`, saturating instead of wrapping.
pub fn mul(a: i64, b: i64) -> i64 {
    let product = ((a as i128) * (b as i128)) >> FRAC_BITS;
    clamp_i128(product)
}

/// Q32.32 division: `(a << 32) / b`, truncated toward zero.
///
/// Returns `None` for a zero divisor and for a quotient outside the
/// representable range, so callers cannot accidentally observe a saturated
/// value on a path that assumed a real result.
pub fn div(a: i64, b: i64) -> Option<i64> {
    if b == 0 {
        return None;
    }
    let quotient = ((a as i128) << FRAC_BITS) / (b as i128);
    i64::try_from(quotient).ok()
}

fn clamp_i128(value: i128) -> i64 {
    if value > i64::MAX as i128 {
        i64::MAX
    } else if value < i64::MIN as i128 {
        i64::MIN
    } else {
        value as i64
    }
}

/// Saturating addition.
pub fn add(a: i64, b: i64) -> i64 {
    a.saturating_add(b)
}

/// Saturating subtraction.
pub fn sub(a: i64, b: i64) -> i64 {
    a.saturating_sub(b)
}

/// Integer square root, exact for every `u64`.
pub fn isqrt(value: u64) -> u64 {
    if value < 2 {
        return value;
    }
    let mut lower = 1u64;
    let mut upper = value;
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        match middle.checked_mul(middle) {
            Some(square) if square <= value => lower = middle + 1,
            Some(_) => upper = middle,
            None => upper = middle,
        }
    }
    lower - 1
}

/// Fixed-point `tanh` through the Padé (3,2) approximant
/// `x * (27 + x^2) / (27 + 9 * x^2)`, saturated to `±1` outside `±3`.
///
/// The exact transcendental function is not representable in integer
/// arithmetic. The approximant is chosen because it is odd, monotone on
/// `[-3, 3]`, bounded by `±1`, and needs only multiplies, adds and one
/// division, so the forward pass and the verifier compute identical activations
/// on every target.
pub fn tanh(x: i64) -> i64 {
    const LIMIT: i64 = 3 * ONE;
    if x >= LIMIT {
        return ONE;
    }
    if x <= -LIMIT {
        return -ONE;
    }
    let squared = mul(x, x);
    let numerator = (x as i128) * ((27 * ONE + squared) as i128);
    let denominator = (27 * ONE + 9 * squared) as i128;
    (numerator / denominator) as i64
}

/// Derivative of [`tanh`] evaluated at the activation output, `1 - t^2`.
///
/// This is the true derivative of `tanh` in the activation output, not the
/// derivative of the rational approximant. Training uses it as a descent
/// direction; verification never does, so the difference cannot affect
/// consensus.
pub fn tanh_grad(output: i64) -> i64 {
    let squared = mul(output, output);
    (ONE - squared).clamp(0, ONE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_times_one_is_one() {
        assert_eq!(mul(ONE, ONE), ONE);
    }

    #[test]
    fn multiplication_truncates_toward_negative_infinity() {
        assert_eq!(mul(-ONE - ONE / 2, ONE), -ONE - ONE / 2);
        assert_eq!(mul(1, 1), 0);
        assert_eq!(mul(-1, 1), -1);
    }

    #[test]
    fn multiplication_saturates_instead_of_wrapping() {
        assert_eq!(mul(MAX, MAX), MAX);
        assert_eq!(mul(MIN, MAX), MIN);
    }

    #[test]
    fn division_reports_zero_and_overflow() {
        assert_eq!(div(ONE, 0), None);
        assert_eq!(div(ONE, ONE), Some(ONE));
        assert_eq!(div(ONE, 2 * ONE), Some(ONE / 2));
        assert_eq!(div(MAX, 1), None);
    }

    #[test]
    fn integer_square_root_is_exact() {
        for value in 0..1024u64 {
            let root = isqrt(value);
            assert!(root * root <= value);
            assert!((root + 1) * (root + 1) > value);
        }
        assert_eq!(isqrt(u64::MAX), 4_294_967_295);
    }

    #[test]
    fn tanh_is_odd_bounded_and_monotone() {
        assert_eq!(tanh(0), 0);
        assert_eq!(tanh(3 * ONE), ONE);
        assert_eq!(tanh(-3 * ONE), -ONE);
        let mut previous = -ONE;
        for step in -300..=300i64 {
            let value = tanh(step * ONE / 100);
            assert!((-ONE..=ONE).contains(&value));
            assert!(value >= previous, "tanh must not decrease");
            assert_eq!(tanh(-step * ONE / 100), -value);
            previous = value;
        }
        assert_eq!(tanh(ONE), 3_340_530_119);
        assert!((tanh(ONE) - 3_270_712_278).abs() < ONE / 50);
    }

    #[test]
    fn tanh_gradient_is_bounded() {
        assert_eq!(tanh_grad(0), ONE);
        assert_eq!(tanh_grad(ONE), 0);
        assert_eq!(tanh_grad(2 * ONE), 0);
    }
}
