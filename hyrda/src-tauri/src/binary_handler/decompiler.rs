use std::fs;
use goblin::{Object, mach};
use capstone::prelude::*;

#[allow(dead_code)]
pub fn decompile_bin() {
    let path = String::from("/Users/adafaralph/dev/reverse_eng/hydra/dummy_binary/hello_arm64");
    let is_aarch64 = true; // Set to true if targeting 64-bit ARM
    let _ = disassembly_test(path, is_aarch64);
}


fn get_bounds(file_path: &str) -> Result<(u64, usize, usize), Box<dyn std::error::Error>>{
    let buf = fs::read(file_path);

    match Object::parse(&buf)? {
        Object::Elf(elf) => {
            let entry = elf.entry;

            for p in &elf.program_headers{
                if p.p_type = goblin::elf::program_header::PT_LOAD {
                    let start_va = p.p_vaddr;
                    let end_va = p.p_vaddr + p.p_memsz;
                }

                if (entry >= start_va && entry < end_va) || ((p.p_flags & goblin::elf::program_header::PF_X) != 0) {
                    if entry >= start_va && entry < end_va {
                        let file_offset_adjustment = entry - start_va;
                        return Ok((
                            entry,
                            (p.p_offset + file_offset_adjustment) as usize,
                            (p.p_filesz - file_offset_adjustment) as usize,
                        ));
                    }
                }
            }
        }
        Object::Mach(mach) => {
            match mach{
                goblin::mach::Mach::Binary(macho) => {
                    for segment in &macho.segments {
                        if segment.name()? == "__TEXT" {
                            for section in segment.sections()? {
                                let (sec, _data) = section;
                                if sec.name()? == "__text"{
                                    return Ok((sec.addr, sec.offset as usize, sec.size as usize))
                                }
                            }
                        }
                        return Ok((
                            segment.vmaddr,
                            segment.fileoff as usize,
                            sgment.filsize as usize,
                        ));
                    }
                }
            }
        }
        _ => Err("Unsoported bin format")
    }


}

fn disassembly_test(path: String, is_aarch64: bool) -> std::io::Result<()> {
    println!("Called disassembly");
    let bytes: Vec<u8> = fs::read(&path)?;


    let (entry_va, file_offset, file_size) = match get_code_bounds(&path) {
            Ok(res) => res,
            Err(e) => {
                println!("Failed to parse binary bounds: {}", e); // Prints the exact string from Err(...)
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()));
            }
        };

    println!("entry va assinged");

    let is_thumb = (entry_va & 1) != 0;

    let clean_entry_va = entry_va & !1;

    let cs = if is_aarch64 {
            Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
        } else if is_thumb {
            Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Thumb)
                .detail(true)
                .build()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
        } else {
            Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .detail(true)
                .build()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
        };

    println!("determineed bitness");

    if file_offset + file_size > bytes.len() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Segment bounds exceed file size"));
    }

    let code_bytes = &bytes[file_offset..file_offset + file_size];
    let instructions = cs.disasm_all(code_bytes, entry_va)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

   // print!("{}", instructions);

    for i in instructions.as_ref() {
        print!("{:016X} ", i.address());

        let instr_bytes = i.bytes();
        for b in instr_bytes.iter() {
            print!("{:02X}", b);
        }

        if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
            for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
                print!("  ");
            }
        }

        let mnemonic = i.mnemonic().unwrap_or("");
        let op_str = i.op_str().unwrap_or("");
        println!(" {mnemonic} {op_str}");
    }

    Ok(())
}
