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

	// Check for the debug flag
	let debug_mode = args.contains(&"-debug".to_string());

	// Find the first argument that isn't the executable itself and isn't the -debug flag
	let target_dir = match args.iter().skip(1).find(|arg| *arg != "-debug") {
		Some(dir) => dir,
		None => {
			println!("Usage: {} <path_to_directory_with_dlls> [-debug]", args[0]);
			return Ok(());
		}
	};

	let output_filename = "hashes.txt";

	let mut file = OpenOptions::new()
		.create(true)
		.write(true)
		.append(true)
		.open(output_filename)
		.context("Failed to open output file for appending")?;

	println!("[*] Recursively scanning directory: {}", target_dir);
	if debug_mode {
		println!("[*] Debug mode enabled. Addresses will be logged.");
	}

	for entry in WalkDir::new(target_dir).into_iter().filter_map(|e| e.ok()) {
		let path = entry.path();

		if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("dll") {
			println!("\n[*] Analyzing {}...", path.display());

			if let Err(e) = process_dll(&path, &mut file, debug_mode) {
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

fn process_dll(dll_path: &Path, file: &mut File, debug_mode: bool) -> Result<()> {
	let buffer = fs::read(dll_path)?;

	let pe = match PE::parse(&buffer) {
		Ok(pe) => pe,
		Err(_) => {
			println!("[-] Not a valid PE file, skipping.");
			return Ok(());
		}
	};

	let target_names = ["CommandLine"];
	let ignored_names = [
		"GetCommandLineW",
		"GetCommandLineA",
		"CommandLineToArgvW",
		"CommandLineToArgvA",
	];
	let image_base = pe.image_base as u64;
	let mut target_iat_addresses = Vec::new();

	for import in pe.imports.iter() {
		let name = import.name.to_string();

		let contains_target = target_names.iter().any(|&t| name.contains(t));
		let is_ignored_api = ignored_names.iter().any(|&i| name.contains(i));

		// Only add it to our scan list if it has our target string BUT is NOT the Windows API
		if contains_target && !is_ignored_api {
			let iat_va = image_base + import.offset as u64;
			target_iat_addresses.push((name, iat_va));
		}
	}

	if target_iat_addresses.is_empty() {
		println!("[-] No valid custom CommandLine imports found. Skipping.");
		return Ok(());
	}

	let bitness = if pe.is_64 { 64 } else { 32 };
	// We now store a tuple of (hash, instruction_pointer)
	let mut extracted_hashes: HashSet<(u64, u64)> = HashSet::new();

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
						// Store the tuple of (Immediate_Value, Instruction_Pointer)
						let mut last_rdx_imm: Option<(u64, u64)> = None;
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
										last_rdx_imm =
											Some((fwd_instr.immediate64(), fwd_instr.ip()));
									}
								}
							}

							if fwd_instr.mnemonic() == Mnemonic::Call {
								let is_indirect_call = fwd_instr.op0_kind() == OpKind::Memory
									|| fwd_instr.op0_kind() == OpKind::Register;
								if is_indirect_call {
									if let Some((hash, ip)) = last_rdx_imm {
										extracted_hashes.insert((hash, ip));
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
		for (hash, addr) in &extracted_hashes {
			if debug_mode {
				writeln!(file, "{}, // 0x{:X}", hash, addr)?;
			} else {
				writeln!(file, "{}", hash)?;
			}
		}
		println!("[+] Found and exported {} hashes.", extracted_hashes.len());
	} else {
		println!("[-] No hashes extracted.");
	}

	Ok(())
}
