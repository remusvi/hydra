use std::{fs, path::PathBuf};
use std::io;

use goblin::Object;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};

const HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;


fn main() {
    println!("Hello, world!");
    let mut path = String::new();
    path = String::from("/Users/adafaralph/dev/reverse_eng/hydra/dummy_binary/hello_x86.elf");

    //io::stdin().read_line(&mut path);

    //println!("DEBUG path bytes: {:?}", path.as_bytes());

    let path = path.to_string();
    let bitness: Option<u32> = Some(64);
    dissassembly_test(path, bitness);
}


fn get_bin_starting_address(file_path: &str) -> Result<u64, Box<dyn std::error::Error>>{
    let buf = fs::read(file_path)?;

    match Object::parse(&buf)? {
        Object::Elf(elf) => {
            Ok(elf.entry)
        }
        Object::PE(pe) => {
            let image_base = pe.image_base as u64;
            Ok(image_base + pe.entry as u64)

        }
        _ => Err("Unknown or unsupported object format".into())
    }
}

fn dissassembly_test(path: String, bit_type: Option<u32>) -> std::io::Result<()>{
    println!("called dissassembly");
    let bytes: Vec<u8> = match fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                println!("Failed to read file: {e}");
                return Err(e);
            }
    };
    let bitness = bit_type.unwrap_or(64);
    print!("getting starting addr");
    let ip = get_bin_starting_address(&path).unwrap();

    let mut line = String::new();

    let mut output: Vec<String>;

    print!("setting up formatter");

    let mut formatter = NasmFormatter::new();

    formatter.options_mut().set_digit_separator("`");
    formatter.options_mut().set_first_operand_char_index(10);


    let mut instruction = Instruction::default();

    print!("gettind decoder");
    let mut decoder = Decoder::with_ip(bitness, EXAMPLE_CODE, ip.clone(), DecoderOptions::NONE);

    println!("starting decoding soon");
    while decoder.can_decode() {
        println!("decoding");
        decoder.decode_out(&mut instruction);

        line.clear();
        formatter.format(&instruction, &mut line);
        print!("{:016X} ", instruction.ip());
        let start_index = (instruction.ip() - &ip) as usize;
        let instr_bytes = &bytes[start_index..start_index + instruction.len()];
        for b in instr_bytes.iter() {
            print!("{:02X}", b);
        }
        if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
            for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
                print!("  ");
            }
        }
        println!(" {}", line);
    }

    Ok(())
}



// /*
// This method produces the following output:
// 00007FFAC46ACDA4 48895C2410           mov       [rsp+10h],rbx
// 00007FFAC46ACDA9 4889742418           mov       [rsp+18h],rsi
// 00007FFAC46ACDAE 55                   push      rbp
// 00007FFAC46ACDAF 57                   push      rdi
// 00007FFAC46ACDB0 4156                 push      r14
// 00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]
// 00007FFAC46ACDBA 4881EC00020000       sub       rsp,200h
// 00007FFAC46ACDC1 488B0518570A00       mov       rax,[rel 7FFA`C475`24E0h]
// 00007FFAC46ACDC8 4833C4               xor       rax,rsp
// 00007FFAC46ACDCB 488985F0000000       mov       [rbp+0F0h],rax
// 00007FFAC46ACDD2 4C8B052F240A00       mov       r8,[rel 7FFA`C474`F208h]
// 00007FFAC46ACDD9 488D05787C0400       lea       rax,[rel 7FFA`C46F`4A58h]
// 00007FFAC46ACDE0 33FF                 xor       edi,edi
// */
// #[allow(dead_code)]
// pub(crate) fn how_to_disassemble() {
//     let bytes = EXAMPLE_CODE;
//     let mut decoder =
//         Decoder::with_ip(EXAMPLE_CODE_BITNESS, bytes, EXAMPLE_CODE_RIP, DecoderOptions::NONE);

//     // Formatters: Masm*, Nasm*, Gas* (AT&T) and Intel* (XED).
//     // For fastest code, see `SpecializedFormatter` which is ~3.3x faster. Use it if formatting
//     // speed is more important than being able to re-assemble formatted instructions.
//     let mut formatter = NasmFormatter::new();

//     // Change some options, there are many more
//     formatter.options_mut().set_digit_separator("`");
//     formatter.options_mut().set_first_operand_char_index(10);

//     // String implements FormatterOutput
//     let mut output = String::new();

//     // Initialize this outside the loop because decode_out() writes to every field
//     let mut instruction = Instruction::default();

//     // The decoder also implements Iterator/IntoIterator so you could use a for loop:
//     //      for instruction in &mut decoder { /* ... */ }
//     // or collect():
//     //      let instructions: Vec<_> = decoder.into_iter().collect();
//     // but can_decode()/decode_out() is a little faster:
//     while decoder.can_decode() {
//         // There's also a decode() method that returns an instruction but that also
//         // means it copies an instruction (40 bytes):
//         //     instruction = decoder.decode();
//         decoder.decode_out(&mut instruction);

//         // Format the instruction ("disassemble" it)
//         output.clear();
//         formatter.format(&instruction, &mut output);

//         // Eg. "00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]"
//         print!("{:016X} ", instruction.ip());
//         let start_index = (instruction.ip() - EXAMPLE_CODE_RIP) as usize;
//         let instr_bytes = &bytes[start_index..start_index + instruction.len()];
//         for b in instr_bytes.iter() {
//             print!("{:02X}", b);
//         }
//         if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
//             for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
//                 print!("  ");
//             }
//         }
//         println!(" {}", output);
//     }
// }

// const HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;
// const EXAMPLE_CODE_BITNESS: u32 = 64;
const EXAMPLE_CODE_RIP: u64 = 0x0000_7FFA_C46A_CDA4;
static EXAMPLE_CODE: &[u8] = &[
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x55, 0x57, 0x41, 0x56, 0x48, 0x8D,
    0xAC, 0x24, 0x00, 0xFF, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0x00, 0x02, 0x00, 0x00, 0x48, 0x8B, 0x05,
    0x18, 0x57, 0x0A, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x85, 0xF0, 0x00, 0x00, 0x00, 0x4C, 0x8B,
    0x05, 0x2F, 0x24, 0x0A, 0x00, 0x48, 0x8D, 0x05, 0x78, 0x7C, 0x04, 0x00, 0x33, 0xFF,
];
