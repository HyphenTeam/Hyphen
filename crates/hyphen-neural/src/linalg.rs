//! Dense linear algebra for the Levenberg–Marquardt step.
//!
//! The systems are tiny (`input_dim <= 32`), so a plain Gaussian elimination
//! with partial pivoting is both faster and easier to audit than anything
//! clever. Values are Q32.32 held in `i128`, so intermediate products do not
//! lose precision even though the interface stays fixed-point.

use crate::fixed::FRAC_BITS;

/// Solves `matrix * x = rhs` in place for a row-major `n x n` matrix.
///
/// `rhs` is overwritten with the solution. Returns `false` for a singular or
/// ill-conditioned system, which the caller answers by increasing damping.
pub fn solve(matrix: &mut [i128], rhs: &mut [i128], n: usize) -> bool {
    if n == 0 || matrix.len() < n * n || rhs.len() < n {
        return false;
    }
    for column in 0..n {
        // Partial pivoting: pick the largest magnitude in the column.
        let mut pivot_row = column;
        let mut pivot_magnitude = matrix[column * n + column].unsigned_abs();
        for row in column + 1..n {
            let magnitude = matrix[row * n + column].unsigned_abs();
            if magnitude > pivot_magnitude {
                pivot_magnitude = magnitude;
                pivot_row = row;
            }
        }
        if pivot_magnitude == 0 {
            return false;
        }
        if pivot_row != column {
            for index in 0..n {
                matrix.swap(column * n + index, pivot_row * n + index);
            }
            rhs.swap(column, pivot_row);
        }
        let pivot = matrix[column * n + column];
        for row in column + 1..n {
            let factor = scale_div(matrix[row * n + column], pivot);
            if factor == 0 {
                continue;
            }
            for index in column..n {
                let product = scale_mul(factor, matrix[column * n + index]);
                matrix[row * n + index] = matrix[row * n + index].saturating_sub(product);
            }
            let product = scale_mul(factor, rhs[column]);
            rhs[row] = rhs[row].saturating_sub(product);
        }
    }

    for row in (0..n).rev() {
        let mut accumulator = rhs[row];
        for column in row + 1..n {
            accumulator =
                accumulator.saturating_sub(scale_mul(matrix[row * n + column], rhs[column]));
        }
        let pivot = matrix[row * n + row];
        if pivot == 0 {
            return false;
        }
        rhs[row] = scale_div(accumulator, pivot);
    }
    true
}

/// Q32.32 multiplication in `i128`.
pub fn scale_mul(left: i128, right: i128) -> i128 {
    (left.saturating_mul(right)) >> FRAC_BITS
}

/// Q32.32 division in `i128`, truncated toward zero.
pub fn scale_div(left: i128, right: i128) -> i128 {
    if right == 0 {
        return 0;
    }
    (left << FRAC_BITS) / right
}

/// Converts a Q32.32 `i64` into the `i128` working type.
pub const fn widen(value: i64) -> i128 {
    value as i128
}

/// Narrows an `i128` Q32.32 value back to `i64`, saturating.
pub fn narrow(value: i128) -> i64 {
    if value > i64::MAX as i128 {
        i64::MAX
    } else if value < i64::MIN as i128 {
        i64::MIN
    } else {
        value as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: i128 = 1 << FRAC_BITS;

    #[test]
    fn solves_a_two_by_two_system() {
        // [1 2; 3 4] x = [5; 11]  =>  x = [1; 2]
        let mut matrix = [ONE, 2 * ONE, 3 * ONE, 4 * ONE];
        let mut rhs = [5 * ONE, 11 * ONE];
        assert!(solve(&mut matrix, &mut rhs, 2));
        // Fixed-point elimination truncates, so the solution is exact only to a
        // few ulps. The prover's convergence test owns the real accuracy bound.
        assert!((rhs[0] - ONE).abs() <= 4, "x0 = {}", rhs[0]);
        assert!((rhs[1] - 2 * ONE).abs() <= 4, "x1 = {}", rhs[1]);
    }

    #[test]
    fn rejects_a_singular_system() {
        let mut matrix = [ONE, 2 * ONE, 2 * ONE, 4 * ONE];
        let mut rhs = [ONE, ONE];
        assert!(!solve(&mut matrix, &mut rhs, 2));
    }

    #[test]
    fn rejects_bad_shapes() {
        let mut matrix = [ONE];
        let mut rhs = [ONE];
        assert!(!solve(&mut matrix, &mut rhs, 0));
        assert!(!solve(&mut [ONE], &mut [ONE], 2));
    }

    #[test]
    fn narrowing_saturates() {
        assert_eq!(narrow(i128::MAX), i64::MAX);
        assert_eq!(narrow(i128::MIN), i64::MIN);
        assert_eq!(narrow(7), 7);
    }
}
