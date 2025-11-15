use std::cmp::Ordering;

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub struct Serial(u32);

impl Serial {
    pub fn increment(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }
}

impl PartialOrd for Serial {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let distance = self.0.abs_diff(other.0);
        if distance < u32::MAX / 2 {
            self.0.partial_cmp(&other.0)
        } else {
            other.0.partial_cmp(&self.0)
        }
    }
}
