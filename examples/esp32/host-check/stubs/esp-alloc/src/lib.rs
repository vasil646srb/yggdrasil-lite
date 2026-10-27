//! Host stub of esp_alloc::HEAP (free()/used()).
pub struct EspHeap;
impl EspHeap {
    pub fn free(&self) -> usize { 1000 }
    pub fn used(&self) -> usize { 2000 }
}
pub static HEAP: EspHeap = EspHeap;
