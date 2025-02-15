#[repr(C)]
#[derive(Clone)]
pub struct Bool32(u32);

impl Bool32 {
    pub const FALSE: Self = Self(0);
    pub const TRUE: Self = Self(1);

    pub fn new(value: bool) -> Self {
        Self(value as u32)
    }
}

impl From<bool> for Bool32 {
    fn from(value: bool) -> Self {
        Self::new(value)
    }
}

impl From<Bool32> for bool {
    fn from(value: Bool32) -> Self {
        value.0 != 0
    }
}
