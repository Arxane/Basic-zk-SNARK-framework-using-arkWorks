# zk-Framework

A zero-knowledge proof framework built using ArkWorks, implementing zk-SNARKs for arithmetic circuit verification.

## Overview

This project implements a zero-knowledge proof system using zk-SNARKs (Zero-Knowledge Succinct Non-Interactive Arguments of Knowledge). It allows users to define arithmetic circuits and generate proofs that verify the correctness of computations without revealing the inputs.

The framework is built on top of [ArkWorks](https://github.com/arkworks-rs), a Rust library for zero-knowledge proof systems, specifically using the Groth16 protocol.

## Features

- Arithmetic circuit definition and parsing
- Witness computation
- Proof generation using Groth16 protocol
- Proof verification
- Support for basic arithmetic operations (add, mul, sub)
- Equality constraints
- Constant definitions
- Input/output variable handling

## Prerequisites

- Rust (latest stable version)
- Cargo (Rust's package manager)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/zk-framework.git
cd zk-framework
```

2. Build the project:
```bash
cargo build
```

## Usage

### Defining a Circuit

Circuits are defined in a text file using a simple domain-specific language. Here's an example:

```
name simple_arithmetic
input x 5
input y 3
output result 16
const one 1
const two 2
const sixteen 16

mul x two x_times_two
mul y two y_times_two
add x_times_two y_times_two sum
sub sum two result
eq sum sixteen check
```

#### Circuit Syntax

- `name <circuit_name>`: Defines the circuit name
- `input <var_name> <value>`: Declares an input variable
- `output <var_name> <value>`: Declares an output variable
- `const <name> <value>`: Defines a constant
- `add <a> <b> <result>`: Addition operation
- `mul <a> <b> <result>`: Multiplication operation
- `sub <a> <b> <result>`: Subtraction operation
- `eq <a> <b> <result>`: Equality check

### Running the Framework

To run a circuit:

```bash
cargo run -- <path_to_circuit_file>
```

For example:
```bash
cargo run -- circuit.txt
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
