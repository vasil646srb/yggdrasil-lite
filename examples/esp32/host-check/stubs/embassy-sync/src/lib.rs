//! Host stub: same names/signatures as embassy-sync for the parts the device uses.
pub mod blocking_mutex {
    pub mod raw {
        pub struct CriticalSectionRawMutex;
    }
}
pub mod mutex {
    use std::marker::PhantomData;
    pub struct Mutex<M, T> {
        inner: std::sync::Mutex<T>,
        _m: PhantomData<M>,
    }
    impl<M, T> Mutex<M, T> {
        pub const fn new(value: T) -> Self {
            Self { inner: std::sync::Mutex::new(value), _m: PhantomData }
        }
        pub async fn lock(&self) -> std::sync::MutexGuard<'_, T> {
            self.inner.lock().unwrap()
        }
    }
}
