use anyhow::{Context, Result};
use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use walkdir::WalkDir;

fn main() -> Result<()> {
	let args: Vec<String> = env::args().collect();
	if args.len() < 2 {
		println!("Usage: {} <path_to_directory_with_dlls>", args[0]);
		return Ok(());
	}

	let target_dir = &args[1];
	let output_filename = "hashes.txt";

	let mut file = OpenOptions::new()
		.create(true)
		.write(true)
		.append(true)
		.open(output_filename)
		.context("Failed to open output file for appending")?;

	println!("[*] recursively scanning directory: {}", target_dir);

	for entry in WalkDir::new(target_dir).into_iter().filter_map(|e| e.ok()) {
		let path = entry.path();

		if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("dll") {
			println!("\n[*] Analyzing {}...", path.display());

			if let Err(e) = process_dll(&path, &mut file) {
				println!("[-] Failed to process {}: {}", path.display(), e);
			}
		}
	}

	println!(
		"\n[+] All done! Results appended to {} in your current directory.",
		output_filename
	);
	Ok(())
}

fn process_dll(dll_path: &Path, file: &mut File) -> Result<()> {
	let buffer = fs::read(dll_path)?;

	let pe = match PE::parse(&buffer) {
		Ok(pe) => pe,
		Err(_) => {
			println!("[-] Not a valid PE file, skipping.");
			return Ok(());
		}
	};

	let target_names = ["GetCommandLineA", "GetCommandLineW", "CommandLine"];
	let image_base = pe.image_base as u64;
	let mut target_iat_addresses = Vec::new();

	for import in pe.imports.iter() {
		let name = import.name.to_string();
		if target_names.iter().any(|&t| name.contains(t)) {
			let iat_va = image_base + import.offset as u64;
			target_iat_addresses.push((name, iat_va));
		}
	}

	if target_iat_addresses.is_empty() {
		println!("[-] No CommandLine imports found.");
		return Ok(());
	}

	let bitness = if pe.is_64 { 64 } else { 32 };
	let mut extracted_hashes: HashSet<u64> = HashSet::new();

	for section in pe.sections {
		let is_executable =
			(section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE) != 0;
		if !is_executable {
			continue;
		}

		let start = section.pointer_to_raw_data as usize;
		let size = section.size_of_raw_data as usize;
		if start + size > buffer.len() {
			continue;
		}

		let section_data = &buffer[start..start + size];
		let section_va = image_base + section.virtual_address as u64;

		let mut decoder = Decoder::with_ip(bitness, section_data, section_va, DecoderOptions::NONE);
		let mut instruction = Instruction::default();

		while decoder.can_decode() {
			decoder.decode_out(&mut instruction);
			let mut referenced_addr = None;

			if instruction.is_ip_rel_memory_operand() {
				referenced_addr = Some(instruction.ip_rel_memory_address());
			} else {
				let disp = instruction.memory_displacement64();
				if disp != 0 {
					referenced_addr = Some(disp);
				}
			}

			if let Some(addr) = referenced_addr {
				for (_name, iat_va) in &target_iat_addresses {
					if addr == *iat_va {
						let next_ip = instruction.next_ip();
						let scan_offset = (next_ip - section_va) as usize;
						if scan_offset >= section_data.len() {
							continue;
						}

						let mut fwd_decoder = Decoder::with_ip(
							bitness,
							&section_data[scan_offset..],
							next_ip,
							DecoderOptions::NONE,
						);
						let mut fwd_instr = Instruction::default();
						let mut last_rdx_imm: Option<u64> = None;
						let mut instructions_scanned = 0;

						while fwd_decoder.can_decode() && instructions_scanned < 30 {
							fwd_decoder.decode_out(&mut fwd_instr);
							instructions_scanned += 1;

							if fwd_instr.mnemonic() == Mnemonic::Mov {
								let op0 = fwd_instr.op0_register();
								if op0 == Register::EDX || op0 == Register::RDX {
									if fwd_instr.op1_kind() == OpKind::Immediate32
										|| fwd_instr.op1_kind() == OpKind::Immediate64
									{
										last_rdx_imm = Some(fwd_instr.immediate64());
									}
								}
							}

							if fwd_instr.mnemonic() == Mnemonic::Call {
								let is_indirect_call = fwd_instr.op0_kind() == OpKind::Memory
									|| fwd_instr.op0_kind() == OpKind::Register;
								if is_indirect_call {
									if let Some(hash) = last_rdx_imm {
										extracted_hashes.insert(hash);
									}
									break;
								}
							}
						}
					}
				}
			}
		}
	}

	if !extracted_hashes.is_empty() {
		let filename = dll_path.file_name().unwrap_or_default().to_string_lossy();
		writeln!(file, "======== {} ========", filename)?;
		for hash in &extracted_hashes {
			writeln!(file, "{}", hash)?;
		}
		println!("[+] Found and exported {} hashes.", extracted_hashes.len());
	} else {
		println!("[-] No hashes extracted.");
	}

	Ok(())
}
