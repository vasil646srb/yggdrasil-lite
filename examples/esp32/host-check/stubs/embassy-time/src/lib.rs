//! Host stub of embassy-time::Instant.
#[derive(Clone, Copy)]
pub struct Instant(std::time::Instant);
#[derive(Clone, Copy)]
pub struct Duration(std::time::Duration);
impl Duration {
    pub fn as_millis(&self) -> u64 { self.0.as_millis() as u64 }
}
impl Instant {
    pub fn now() -> Self { Instant(std::time::Instant::now()) }
    pub fn as_millis(&self) -> u64 { self.0.elapsed().as_millis() as u64 }
    pub fn elapsed(&self) -> Duration { Duration(self.0.elapsed()) }
}
