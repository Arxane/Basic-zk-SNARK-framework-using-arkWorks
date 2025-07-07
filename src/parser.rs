use std::fs; //for reading the file
use std::collections::HashMap; //for storing inputs and outputs
use crate::{Gate, Circuit}; 

pub fn parse_circuit(file_path: &str) -> Result<Circuit, std::io::Error> {
    // Open the file and wrap it with a buf reader
    let content = fs::read_to_string(file_path).expect("Cannot read circuit file");

    // Storing circuit parts
    let mut circuit_name_from_file = String::new();
    let mut inputs = HashMap::new();
    let mut outputs = HashMap::new();
    let mut gates = Vec::new();

    let mut sender = String::new();
    let mut receiver = String::new();
    let mut transfer_amount = 0;

    // Parsing line by line
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//"){
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.as_slice() {
            ["name", cn ] => {
                circuit_name_from_file = cn.to_string();
            }
            ["input", var, val] => {
                let value = val.parse::<i32>().expect("Inavlid input value");
                inputs.insert(var.to_string(), value);
            }
            ["output", var, val] => {
                let value = val.parse::<i32>().expect("Invalid output value");
                outputs.insert(var.to_string(), value);
            }
            ["sender", s] => {
                sender = s.to_string();
            }
            ["receiver", r] => {
                receiver = r.to_string();
            }
            ["amount", amt] => {
                transfer_amount = amt.parse::<i32>().expect("Invalid transfer amount");
            }
            ["add", a, b, c] => {
                gates.push(Gate::Add(a.to_string(), b.to_string(), c.to_string(), None));
            }
            ["mul", a, b, c] => {
                gates.push(Gate::Mul(a.to_string(), b.to_string(), c.to_string(), None));
            }
            ["sub", a, b, c] => {
                gates.push(Gate::Sub(a.to_string(), b.to_string(), c.to_string(), None));
            }
            ["eq", a, b, out] => {
                gates.push(Gate::Eq(a.to_string(), b.to_string(), out.to_string()));
            }
            ["const", name, val] => {
                let value = val.parse::<i32>().expect("Invalid constant value");
                gates.push(Gate::Const(name.to_string(), value));
            }
            ["xor", a, b, c] => {
                gates.push(Gate::Xor(a.to_string(), b.to_string(), c.to_string()));
            }
            ["hash", input, output] => {
                gates.push(Gate::Hash(input.to_string(), output.to_string()));
            }
            _ => {
                panic!("Unknown or malformed line: {}", line);
            }
        }
    }

    Ok(Circuit {
        name: circuit_name_from_file,
        inputs,
        outputs,
        gates,
        sender,
        receiver,
        transfer_amount,
    })
}
