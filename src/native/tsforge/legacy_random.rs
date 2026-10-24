//! Compatibility with the seeded .NET Framework System.Random algorithm.
//! Only used to reproduce MAS's five-character PKEY2005 suffix, never security entropy.
//! Algorithm reference: vendor/dotnet-reference/Random.cs.
//! Copyright (c) Microsoft Corporation; MIT notice in vendor/dotnet-reference/LICENSE.txt.
pub struct LegacyRandom {
    state: [i32; 56],
    next: usize,
    other: usize,
}
impl LegacyRandom {
    pub fn new(seed: i32) -> Self {
        let magnitude = if seed == i32::MIN {
            i32::MAX
        } else {
            seed.abs()
        };
        let mut state = [0i32; 56];
        let mut previous = 161803398i32.wrapping_sub(magnitude);
        state[55] = previous;
        let mut current = 1i32;
        for index in 1..55 {
            let slot = 21 * index % 55;
            state[slot] = current;
            current = previous.wrapping_sub(current);
            if current < 0 {
                current = current.wrapping_add(i32::MAX);
            }
            previous = state[slot];
        }
        for _ in 0..4 {
            for index in 1..56 {
                state[index] = state[index].wrapping_sub(state[1 + (index + 30) % 55]);
                if state[index] < 0 {
                    state[index] = state[index].wrapping_add(i32::MAX);
                }
            }
        }
        Self {
            state,
            next: 0,
            other: 21,
        }
    }
    pub fn next24(&mut self) -> usize {
        self.next = self.next % 55 + 1;
        self.other = self.other % 55 + 1;
        let mut value = self.state[self.next].wrapping_sub(self.state[self.other]);
        if value == i32::MAX {
            value -= 1;
        }
        if value < 0 {
            value = value.wrapping_add(i32::MAX);
        }
        self.state[self.next] = value;
        (f64::from(value) * (1.0 / f64::from(i32::MAX)) * 24.0) as usize
    }
}

#[test]
fn seeded_sequences_match_compatibility_vectors() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/tsforge/key2005.json")).unwrap();
    for fixture in fixtures["random"].as_array().unwrap() {
        let mut random = LegacyRandom::new(fixture["seed"].as_i64().unwrap() as i32);
        let actual: Vec<_> = (0..128).map(|_| random.next24()).collect();
        let expected: Vec<_> = fixture["values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as usize)
            .collect();
        assert_eq!(actual, expected);
    }
}
