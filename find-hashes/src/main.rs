use anyhow::{Context, Result};
use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

fn main() -> Result<()> {
	let mut target_dir = String::new();
	let mut base_dir_arg = String::new();
	let mut output_dir_arg = String::from("./hashes");
	let mut debug_mode = false;

	let mut exclude_patterns: Vec<String> = vec!["import_scripts".to_string(), "csdm".to_string()];

	let mut args = env::args().skip(1);
	while let Some(arg) = args.next() {
		match arg.as_str() {
			"-debug" => debug_mode = true,
			"--base" => {
				if let Some(base) = args.next() {
					base_dir_arg = base;
				} else {
					println!("[-] Error: --base requires a directory name or path argument.");
					return Ok(());
				}
			}
			"--out" | "-o" => {
				if let Some(out) = args.next() {
					output_dir_arg = out;
				} else {
					println!("[-] Error: --out requires a directory path argument.");
					return Ok(());
				}
			}
			"--exclude" | "-e" => {
				if let Some(pattern) = args.next() {
					exclude_patterns.push(pattern);
				} else {
					println!("[-] Error: --exclude requires a pattern argument.");
					return Ok(());
				}
			}
			_ => {
				if target_dir.is_empty() {
					target_dir = arg;
				}
			}
		}
	}

	if target_dir.is_empty() || base_dir_arg.is_empty() {
		println!(
			"Usage: <executable> <target_dir> --base <base_folder> [--out <output_dir>] [--exclude <pattern>]... [-debug]"
		);
		println!(
			"Example: executable \"C:\\..\\game\\bin\\win64\" --base game --out ./my_results --exclude custom_folder"
		);
		println!("Note: Hardcoded exclusions: {:?}", exclude_patterns);
		return Ok(());
	}

	let target_dir_path = Path::new(&target_dir);

	println!("[*] Recursively scanning directory: {}", target_dir);
	println!("[*] Base directory set to: {}", base_dir_arg);
	println!("[*] Output directory set to: {}", output_dir_arg);
	println!("[*] Excluding paths containing: {:?}", exclude_patterns);
	if debug_mode {
		println!("[*] Debug mode enabled. Addresses will be logged.");
	}

	let out_path = Path::new(&output_dir_arg);
	if out_path.exists() {
		println!("[*] Clearing existing .txt files in output directory...");
		for entry in WalkDir::new(out_path).into_iter().filter_map(|e| e.ok()) {
			let path = entry.path();
			if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("txt") {
				fs::remove_file(path).with_context(|| {
					format!("Failed to delete old output file: {}", path.display())
				})?;
			}
		}
	} else {
		fs::create_dir_all(out_path).context("Failed to create output directory")?;
	}
	// ---------------------------------------------------------------------

	for entry in WalkDir::new(target_dir_path)
		.into_iter()
		.filter_map(|e| e.ok())
	{
		let path = entry.path();

		if path.is_file()
			&& matches!(
				path.extension().and_then(|s| s.to_str()),
				Some("dll" | "exe")
			) {
			let path_str = path.to_string_lossy();
			let should_exclude = exclude_patterns
				.iter()
				.any(|pattern| path_str.contains(pattern));

			if should_exclude {
				println!("[*] Skipping {} (matches exclude pattern)", path.display());
				continue;
			}

			println!("\n[*] Analyzing {}...", path.display());

			if let Err(e) = process_dll(
				&path,
				target_dir_path,
				&base_dir_arg,
				&output_dir_arg,
				debug_mode,
			) {
				println!("[-] Failed to process {}: {}", path.display(), e);
			}
		}
	}

	println!(
		"\n[+] All done! Results saved to the {} directory.",
		output_dir_arg
	);
	Ok(())
}

fn process_dll(
	dll_path: &Path,
	target_dir: &Path,
	base_dir_arg: &str,
	output_dir_arg: &str,
	debug_mode: bool,
) -> Result<()> {
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

	let mut extracted_hashes: HashMap<u64, Vec<u64>> = HashMap::new();

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
						let mut reg_state: HashMap<Register, (u64, u64)> = HashMap::new();
						let mut instructions_scanned = 0;
						while fwd_decoder.can_decode() && instructions_scanned < 60 {
							fwd_decoder.decode_out(&mut fwd_instr);
							instructions_scanned += 1;

							if fwd_instr.mnemonic() == Mnemonic::Mov {
								let op0 = fwd_instr.op0_register();

								if op0 != Register::None {
									let base_op0 = get_base_register(op0);
									if fwd_instr.op1_kind() == OpKind::Immediate32
										|| fwd_instr.op1_kind() == OpKind::Immediate64
									{
										// We found a direct immediate move
										reg_state.insert(
											base_op0,
											(fwd_instr.immediate64(), fwd_instr.ip()),
										);
									} else if fwd_instr.op1_kind() == OpKind::Register {
										// We found a register-to-register move (e.g. MOV RDX, RAX)
										let base_op1 = get_base_register(fwd_instr.op1_register());
										if let Some(&val_ip) = reg_state.get(&base_op1) {
											reg_state.insert(base_op0, val_ip);
										} else {
											reg_state.remove(&base_op0);
										}
									} else {
										reg_state.remove(&base_op0);
									}
								}
							}
							if fwd_instr.mnemonic() == Mnemonic::Call {
								let is_indirect_call = fwd_instr.op0_kind() == OpKind::Memory
									|| fwd_instr.op0_kind() == OpKind::Register;
								if is_indirect_call {
									let arg_regs =
										[Register::RCX, Register::RDX, Register::R8, Register::R9];
									let ignored_hashes = [
										1024u64,
										1056u64,
										1136u64,
										1248u64,
										1500u64,
										2048u64,
										2992u64,
										3024u64,
										4096u64,
										5000u64,
										8192u64,
										8400u64,
										27015u64,
										27020u64,
										27021u64,
										32767u64,
										32768u64,
										65536u64,
										81920u64,
										95000u64,
										100000u64,
										131097u64,
										331522u64,
										624820u64,
										624821u64,
										624822u64,
										1048576u64,
										2097152u64,
										2279720u64,
										3120232u64,
										8393104u64,
										231313132u64,
										269354392u64,
										1313166403u64,
										1313166419u64,
										1380142404u64,
										1380143954u64,
										2147483647u64,
										2147483648u64,
										3221225672u64,
										4278190335u64,
										4278255360u64,
										4278255615u64,
										4294901760u64,
										4294934656u64,
										4294966297u64,
										4294967040u64,
										4294967294u64,
										4294967295u64,
										418564367478u64,
										474080965238u64,
										500152235126u64,
										111546415280246u64,
										281474976907284u64,
										13778779262078472358u64,
									];

									for reg in &arg_regs {
										if let Some(&(hash, ip)) = reg_state.get(reg) {
											if hash > 1000 && !ignored_hashes.contains(&hash) {
												extracted_hashes.entry(hash).or_default().push(ip);
											}
										}
									}
								}
								let volatile_regs = [
									Register::RAX,
									Register::RCX,
									Register::RDX,
									Register::R8,
									Register::R9,
									Register::R10,
									Register::R11,
								];
								for reg in &volatile_regs {
									reg_state.remove(reg);
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

		let mut relative_out_path = PathBuf::new();
		let base_path_arg = Path::new(base_dir_arg);

		if base_path_arg.is_absolute() && dll_path.starts_with(base_path_arg) {
			if let Ok(stripped) = dll_path.strip_prefix(base_path_arg) {
				relative_out_path = stripped.to_path_buf();
			}
		} else {
			let mut is_base_dir = false;
			for component in dll_path.components() {
				if component.as_os_str() == base_dir_arg {
					is_base_dir = true;
				}
				if is_base_dir {
					relative_out_path.push(component);
				}
			}
		}

		if relative_out_path.as_os_str().is_empty() {
			if let Ok(stripped) = dll_path.strip_prefix(target_dir) {
				relative_out_path = stripped.to_path_buf();
			} else {
				relative_out_path = PathBuf::from(&*filename);
			}
		}

		let mut new_filename = relative_out_path
			.file_name()
			.unwrap_or_default()
			.to_os_string();
		new_filename.push(".txt");
		relative_out_path.set_file_name(new_filename);

		let final_out_path = Path::new(output_dir_arg).join(relative_out_path);

		if let Some(parent) = final_out_path.parent() {
			if !parent.as_os_str().is_empty() {
				fs::create_dir_all(parent).context(format!(
					"Failed to create directories for: {}",
					parent.display()
				))?;
			}
		}

		let mut file = OpenOptions::new()
			.create(true)
			.write(true)
			.truncate(true)
			.open(&final_out_path)
			.context(format!(
				"Failed to open output file: {}",
				final_out_path.display()
			))?;

		let mut sorted_hashes: Vec<_> = extracted_hashes.into_iter().collect();
		sorted_hashes.sort_unstable_by_key(|(hash, _)| *hash);

		let hash_count = sorted_hashes.len();

		for (hash, mut addrs) in sorted_hashes {
			addrs.sort_unstable();
			addrs.dedup();

			if debug_mode {
				let addr_strings: Vec<String> =
					addrs.iter().map(|a| format!("0x{:X}", a)).collect();
				writeln!(file, "{}, // Found at: {}", hash, addr_strings.join(", "))?;
			} else {
				writeln!(file, "{}", hash)?;
			}
		}

		println!(
			"[+] Found and exported {} unique hashes to {}.",
			hash_count,
			final_out_path.display()
		);
	} else {
		println!("[-] No hashes extracted.");
	}

	Ok(())
}

fn get_base_register(reg: Register) -> Register {
	match reg {
		Register::AL | Register::AH | Register::AX | Register::EAX | Register::RAX => Register::RAX,
		Register::CL | Register::CH | Register::CX | Register::ECX | Register::RCX => Register::RCX,
		Register::DL | Register::DH | Register::DX | Register::EDX | Register::RDX => Register::RDX,
		Register::BL | Register::BH | Register::BX | Register::EBX | Register::RBX => Register::RBX,
		Register::SPL | Register::SP | Register::ESP | Register::RSP => Register::RSP,
		Register::BPL | Register::BP | Register::EBP | Register::RBP => Register::RBP,
		Register::SIL | Register::SI | Register::ESI | Register::RSI => Register::RSI,
		Register::DIL | Register::DI | Register::EDI | Register::RDI => Register::RDI,
		Register::R8L | Register::R8W | Register::R8D | Register::R8 => Register::R8,
		Register::R9L | Register::R9W | Register::R9D | Register::R9 => Register::R9,
		Register::R10L | Register::R10W | Register::R10D | Register::R10 => Register::R10,
		Register::R11L | Register::R11W | Register::R11D | Register::R11 => Register::R11,
		Register::R12L | Register::R12W | Register::R12D | Register::R12 => Register::R12,
		Register::R13L | Register::R13W | Register::R13D | Register::R13 => Register::R13,
		Register::R14L | Register::R14W | Register::R14D | Register::R14 => Register::R14,
		Register::R15L | Register::R15W | Register::R15D | Register::R15 => Register::R15,
		_ => reg,
	}
}
