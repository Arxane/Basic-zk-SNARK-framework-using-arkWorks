# Zero-Knowledge Circuit Framework

A Rust-based framework for creating and verifying zero-knowledge proofs using Groth16 zk-SNARKs. This framework allows you to define arithmetic circuits and generate/verify zero-knowledge proofs for them.

## Personal Note

This project was created as a learning exercise to:
- Practice and improve my Rust programming skills
- Explore the fascinating world of cryptography and zero-knowledge proofs
- Understand the practical implementation of zk-SNARKs
- Learn about circuit-based computation and constraint systems

While the implementation may not be production-ready, it serves as a good starting point for understanding zero-knowledge proofs and their implementation in Rust. Feel free to use this as a reference or learning resource!

## Note on Legacy Code

The codebase contains some legacy code and terminology from its initial development as an asset transfer system. You may notice:
- References to "transfer", "sender", "receiver" in variable names and comments
- Functions related to balance checking and transfers
- Some unused fields in structs

These are remnants of the original implementation and are not used in the current circuit-based functionality. They can be safely ignored or removed in future refactoring.

## Features

- Circuit definition using a simple text-based format
- Support for basic arithmetic operations (add, subtract, multiply)
- Support for boolean operations (XOR)
- Support for equality checks
- Support for constant values
- Groth16 zk-SNARK proof generation and verification
- R1CS (Rank-1 Constraint System) conversion
- Witness computation

## Circuit File Format

Circuits are defined in a simple text format. Here's an example:

```
name simple_arithmetic
input x 5
input y 3
input transfer_amount_public 5
output result 16
output check 1
const one 1
const two 2
const sixteen 16

add x y sum
add sum two result
sub result sixteen diff
mul diff diff check
```

### Supported Operations

- `input <name> <value>` - Define an input variable
- `output <name> <value>` - Define an expected output
- `const <name> <value>` - Define a constant
- `add <a> <b> <result>` - Addition: result = a + b
- `sub <a> <b> <result>` - Subtraction: result = a - b
- `mul <a> <b> <result>` - Multiplication: result = a * b
- `xor <a> <b> <result>` - XOR operation (inputs must be 0 or 1)
- `eq <a> <b> <result>` - Equality check: result = 1 if a == b, 0 otherwise

## Usage

1. Create a circuit file (e.g., `circuit.txt`) using the format described above
2. Run the program:
```bash
cargo run -- circuit.txt
```

The program will:
1. Parse the circuit
2. Convert it to an R1CS system
3. Generate Groth16 proving and verifying keys
4. Compute the witness
5. Generate a zero-knowledge proof
6. Verify the proof

## Example Output

```
Parsing circuit from: circuit.txt
Parsed Circuit: "simple_arithmetic"
Converting circuit to R1CS system...
Circuit parsed: simple_arithmetic (4 constraints, 6 variables)
Public input names (excluding implicit '1'): ["x", "y", "transfer_amount_public"]
Generating Groth16 proving and verifying keys (setup)...
Keys generated successfully.
Computing witness for the circuit instance...
Witness computed with 6 assignments.
Generating Groth16 proof...
Proof generated.
Verifying proof with public inputs: [...]
Verification Result: true
Proof is VALID!
```

## Dependencies

- ark-bls12-381
- ark-groth16
- ark-ff
- ark-ec
- ark-relations
- ark-std
- ark-crypto-primitives
- ark-serialize

## Project Structure

- `src/main.rs` - Main program entry point
- `src/lib.rs` - Core library functionality
- `src/parser.rs` - Circuit file parsing
- `circuit.txt` - Example valid circuit
- `invalid_circuit.txt` - Example invalid circuit

## Building

```bash
cargo build
```

## Running Tests

```bash
cargo test
```

## Overview

This project implements a zero-knowledge proof system using zk-SNARKs (Zero-Knowledge Succinct Non-Interactive Arguments of Knowledge). It allows users to define arithmetic circuits and generate proofs that verify the correctness of computations without revealing the inputs.

The framework is built on top of [ArkWorks](https://github.com/arkworks-rs), a Rust library for zero-knowledge proof systems, specifically using the Groth16 protocol.

## Prerequisites

- Rust (latest stable version)
- Cargo (Rust's package manager)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Arxane/Basic-zk-SNARK-framework-using-arkWorks.git
cd Basic-zk-SNARK-framework-using-arkWorks
```

2. Build the project:
```bash
cargo build
```

## How It Works

1. **Circuit Parsing**: The framework parses the circuit definition file into an internal representation.

2. **R1CS Conversion**: The circuit is converted into a Rank-1 Constraint System (R1CS), which is the format required for zk-SNARKs.

3. **Witness Computation**: The framework computes a witness that satisfies all constraints in the circuit.

4. **Proof Generation**: Using the Groth16 protocol, a zero-knowledge proof is generated.

5. **Verification**: The proof is verified against the public inputs and constraints.

## Technical Details

The framework uses:
- ArkWorks' Groth16 implementation for proof generation and verification
- BLS12-381 curve for cryptographic operations
- R1CS (Rank-1 Constraint System) for circuit representation

## Citations

If you use this project in your research, please cite:

1. Groth, J. (2016). "On the Size of Pairing-based Non-interactive Arguments". In: Fischlin, M., Coron, JS. (eds) Advances in Cryptology – EUROCRYPT 2016. EUROCRYPT 2016. Lecture Notes in Computer Science, vol 9666. Springer, Berlin, Heidelberg.

2. Ben-Sasson, E., et al. (2014). "Succinct Non-Interactive Zero Knowledge for a von Neumann Architecture". In: USENIX Security Symposium.

3. ArkWorks Team. (2023). "ArkWorks: A Rust Library for Zero-Knowledge Proof Systems". GitHub Repository.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- The ArkWorks team for their excellent zero-knowledge proof library
- The zk-SNARK research community for their foundational work
