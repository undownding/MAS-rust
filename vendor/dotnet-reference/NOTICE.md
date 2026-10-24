# .NET Framework seeded Random reference

Source: https://github.com/microsoft/referencesource/tree/ec9fa9ae770d522a5b5f0607898044b7478574a3
License: MIT, Copyright (c) Microsoft Corporation; see LICENSE.txt.

Random.cs is a reference copy, never built or executed by MAS Rust.
src/native/tsforge/legacy_random.rs reimplements its seeded subtractive algorithm
for MAS PKEY2005 compatibility. The Python fixture generator implements the same
reference algorithm. Windows CI additionally checks fixtures against the actual
.NET Framework System.Random implementation. Neither implementation supplies
cryptographic randomness or replaces the OS RNG used for store encryption.
