# zk-SNARK System in Rust

## Overview

This project implements a zk-SNARK (Zero-Knowledge Succinct Non-Interactive Argument of Knowledge) system in Rust. It allows for the creation, proof generation, and verification of cryptographic proofs based on custom arithmetic circuits. This project provides a simple yet powerful system to demonstrate zk-SNARKs in practice, focusing on the conversion of custom circuits into R1CS (Rank-1 Constraint Systems), and the generation and verification of proofs.

## Features

- **Custom Circuit Parsing**: Parse circuits from a custom text format into an internal representation.
- **R1CS Conversion**: Convert parsed circuits into R1CS constraints that can be used in a zk-SNARK system.
- **Proof Generation**: Generate zero-knowledge proofs based on the provided circuit and inputs.
- **Proof Verification**: Verify the correctness of generated zk-SNARK proofs.
- **Arithmetic Gate Support**: Supports gates like Add, Mul, Sub, Eq, Xor, and Hash.
  
## Project Structure

- `src/` – Contains the main logic of the zk-SNARK system, including circuit parsing, R1CS conversion, proof generation, and verification.
- `examples/` – Example zk-SNARK circuits for testing the system.
- `tests/` – Unit tests for the system to ensure correctness and functionality.
- `Cargo.toml` – Rust project configuration file.

## Requirements

- **Rust** (latest stable version)
- **Cargo** (Rust's package manager and build tool)

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/arxane/zk-framework.git
   cd zk-snark-rust
2. **Build the project:**

    ```bash
    cargo build --release
3. **Run the project:**

    ```bash
    cargo run -- ./path/to/your/circuit.txt

## Example Circuit

    inputs: a=3, b=5, c=7, d=2
    outputs: result=16, intermediate=10

    gates:
        add a b sum_ab
        add c d sum_cd
        mul sum_ab sum_cd mul_ab_cd
        sub mul_ab_cd a result
        eq result 16 result_check
        add sum_ab sum_cd intermediate
        eq intermediate 10 intermediate_check


## Contributing

Contributions are welcome! Feel free to fork the repository, create a branch, and submit a pull request with improvements, bug fixes, or new features.

Please ensure that any changes are properly tested and documented.

## Acknowledgements
