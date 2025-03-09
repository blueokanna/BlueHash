//! Utility functions used in the BlueHash algorithm.
// <Author: BlueOkanna>
// <Email: blueokanna@gmail.com>
/// Converts a slice of bytes into a 64-bit unsigned integer.
///
/// # Arguments
///
/// * `chunk` - A slice of bytes to be converted into a u64 value.
///
/// # Returns
///
/// The resulting 64-bit unsigned integer.
pub fn to_u64(chunk: &[u8]) -> u64 {
    chunk.iter().fold(0, |acc, &b| (acc << 8) | b as u64)
}
