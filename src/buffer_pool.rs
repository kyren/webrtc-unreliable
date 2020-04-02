use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
};

/// Shared pool of reusable Vec<u8> buffers.
///
/// Send and lock-free, but will panic if accessed from multiple threads at one time.
#[derive(Clone, Debug)]
pub struct BufferPool(Arc<Mutex<Vec<OwnedBuffer>>>);

impl BufferPool {
    pub fn new() -> BufferPool {
        BufferPool(Arc::new(Mutex::new(Vec::new())))
    }

    /// Acquire a buffer from the pool and return a handle to it, the buffer is guaranteed to have
    /// length zero.
    ///
    /// The buffer will be returned to the pool when the handle is dropped, unless it is converted
    /// to an `OwnedBuffer`.
    pub fn acquire(&self) -> BufferHandle {
        let mut buffer = self.0.try_lock().unwrap().pop().unwrap_or_default();
        buffer.0.clear();
        BufferHandle(self, Some(buffer))
    }

    /// Adopt an owned buffer, returning a handle that will return the owned buffer to the pool on
    /// drop.
    pub fn adopt(&self, buffer: OwnedBuffer) -> BufferHandle {
        BufferHandle(self, Some(buffer))
    }

    fn release(&self, buffer: OwnedBuffer) {
        self.0.try_lock().unwrap().push(buffer);
    }
}

/// A handle to a pooled buffer which will return the buffer to the pool on drop.
pub struct BufferHandle<'a>(&'a BufferPool, Option<OwnedBuffer>);

impl<'a> BufferHandle<'a> {
    /// Convert this buffer handle into an `OwnedBuffer`, which does not borrow the `BufferPool` and
    /// will not automatically return the buffer to the pool on drop.
    pub fn into_owned(mut self) -> OwnedBuffer {
        self.1.take().unwrap()
    }
}

impl<'a> Deref for BufferHandle<'a> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.1.as_ref().unwrap().0
    }
}

impl<'a> DerefMut for BufferHandle<'a> {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.1.as_mut().unwrap().0
    }
}

impl<'a> Drop for BufferHandle<'a> {
    fn drop(&mut self) {
        if let Some(owned) = self.1.take() {
            self.0.release(owned);
        }
    }
}

/// An buffer that has been taken out of a `BufferPool` and is no longer owned by it.
///
/// It is an opaque type for transferring ownership of buffers, in order to access the inner buffer
/// it must first be returned to the pool.  By preventing the use of the buffer without returning
/// ownership to the pool first, this wrapper type makes it less likely that owned buffers will be
/// dropped without being returned to the pool.
#[derive(Debug, Default)]
pub struct OwnedBuffer(Vec<u8>);
