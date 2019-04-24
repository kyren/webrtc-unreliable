use std::{
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
    ptr,
    sync::Arc,
};

use crossbeam::queue::{ArrayQueue, SegQueue};

#[derive(Clone, Debug)]
pub struct Pool<T>(Arc<PoolQueue<T>>);

impl<T> Pool<T>
where
    T: Default,
{
    pub fn new_unbounded() -> Pool<T> {
        Pool(Arc::new(PoolQueue::new_unbounded()))
    }

    pub fn new_bounded(max_size: usize) -> Pool<T> {
        Pool(Arc::new(PoolQueue::new_bounded(max_size)))
    }

    pub fn checkout(&self) -> Checkout<T> {
        Checkout(
            ManuallyDrop::new(self.0.pop().unwrap_or_default()),
            self.0.clone(),
        )
    }
}

#[derive(Debug)]
pub struct Checkout<T>(ManuallyDrop<T>, Arc<PoolQueue<T>>);

impl<T> Deref for Checkout<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for Checkout<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> Drop for Checkout<T> {
    fn drop(&mut self) {
        self.1.push(unsafe { ptr::read(&mut *self.0) })
    }
}

#[derive(Debug)]
enum PoolQueue<T> {
    Unbounded(SegQueue<T>),
    Bounded(ArrayQueue<T>),
}

impl<T> PoolQueue<T> {
    fn new_unbounded() -> PoolQueue<T> {
        PoolQueue::Unbounded(SegQueue::new())
    }

    fn new_bounded(max_size: usize) -> PoolQueue<T> {
        PoolQueue::Bounded(ArrayQueue::new(max_size))
    }

    fn pop(&self) -> Option<T> {
        match self {
            PoolQueue::Unbounded(queue) => queue.pop().ok(),
            PoolQueue::Bounded(queue) => queue.pop().ok(),
        }
    }

    fn push(&self, t: T) {
        match self {
            PoolQueue::Unbounded(queue) => {
                let _ = queue.push(t);
            }
            PoolQueue::Bounded(queue) => {
                let _ = queue.push(t);
            }
        }
    }
}
