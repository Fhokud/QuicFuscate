#![cfg(feature = "rust-tests")]

use quicfuscate::accelerate::memory;

fn reference_transpose(input: &[f32], rows: usize, cols: usize) -> Vec<f32> {
    let mut out = vec![0f32; rows * cols];
    for r in 0..rows {
        for c in 0..cols {
            out[c * rows + r] = input[r * cols + c];
        }
    }
    out
}

#[test]
fn transpose_twice_is_identity_f32() {
    // Create a non-square matrix to exercise edges
    let rows = 7;
    let cols = 9;
    let mut m: Vec<f32> = (0..(rows * cols)).map(|x| x as f32 + 0.5).collect();
    let orig = m.clone();

    // First transpose
    memory::transpose_matrix(&mut m, rows, cols);
    // Now transpose back
    memory::transpose_matrix(&mut m, cols, rows);

    assert_eq!(m, orig);
}

#[test]
fn transpose_matrix_square_8x8_matches_reference() {
    let rows = 8usize;
    let cols = 8usize;
    let mut data: Vec<f32> = (0..rows * cols).map(|v| v as f32).collect();
    let expected = reference_transpose(&data, rows, cols);

    memory::transpose_matrix(&mut data, rows, cols);

    assert_eq!(data, expected);
}

#[test]
fn transpose_matrix_square_6x6_matches_reference() {
    let rows = 6usize;
    let cols = 6usize;
    let mut data: Vec<f32> = (0..rows * cols).map(|v| v as f32).collect();
    let expected = reference_transpose(&data, rows, cols);

    memory::transpose_matrix(&mut data, rows, cols);

    assert_eq!(data, expected);
}
