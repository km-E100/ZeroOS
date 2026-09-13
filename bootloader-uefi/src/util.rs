#[allow(dead_code)]
pub fn align_up(value: u64, align: u64) -> u64 {
    let mask = align - 1;
    (value + mask) & !mask
}

#[allow(dead_code)]
pub fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}
