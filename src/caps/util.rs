#[inline]
pub const fn combine_raw_u32s(lower: u32, upper: u32) -> u64 {
    ((upper as u64) << 32) + (lower as u64)
}
