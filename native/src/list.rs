#[repr(C)]
#[derive(Clone, Debug)]
pub struct UnsafeList<T> {
    pub ptr: *mut T,
    pub len: u32,
}
