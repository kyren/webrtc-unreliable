use std::{
    mem,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use crossbeam::queue::SegQueue;

/// Sharable pool of Vec<u8> buffers where buffers are returned to the pool on drop.
#[derive(Clone, Debug)]
pub struct BufferPool(Arc<Pool>);

impl BufferPool {
    pub fn new() -> BufferPool {
        BufferPool(Arc::new(Pool::new()))
    }

    /// Acquire a buffer from the pool, or construct a new one if one is not available.  Returned
    /// buffers always have len == 0, but will have the capacity from their previous use.
    pub fn acquire(&self) -> PooledBuffer {
        let mut buffer = self.0.pop().ok().unwrap_or_default();
        buffer.clear();
        PooledBuffer(buffer, self.0.clone())
    }
}

/// A wrapper around a pooled Vec<u8> buffer.  On drop, the buffer is returned to its source pool
/// *without* its capacity being changed.
#[derive(Debug)]
pub struct PooledBuffer(Vec<u8>, Arc<Pool>);

impl Deref for PooledBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        self.1.push(mem::replace(&mut self.0, Vec::new()));
    }
}

type Pool = SegQueue<Vec<u8>>;
