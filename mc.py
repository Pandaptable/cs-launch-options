import os
import re
import subprocess
import sys
from pathlib import Path


def run_cmmc(args):
	"""Run cmmc.exe with the provided arguments and return the output."""
	cmd = ["./cmmc.exe"] + args

	max_display = 5
	if len(cmd) > max_display:
		display_cmd = cmd[:max_display] + [f"... (and {len(cmd) - max_display} more)"]
	else:
		display_cmd = cmd

	print(f"[*] Executing: {' '.join(display_cmd)}")

	try:
		result = subprocess.run(cmd, capture_output=True, text=True, check=True)
		return result.stdout
	except FileNotFoundError:
		print("[-] Error: cmmc.exe not found in the current directory.")
		sys.exit(1)
	except subprocess.CalledProcessError as e:
		print(f"[-] Error running cmmc.exe: {e}")
		sys.exit(1)


def process_output(output_text, target_dir_path):
	target_dir = Path(target_dir_path)
	if not target_dir.is_dir():
		print(f"[-] Error: Directory '{target_dir}' not found. Please ensure the directory exists.")
		sys.exit(1)

	mappings = {}
	for line in output_text.splitlines():
		if ":" not in line:
			continue

		parts = line.split(":", 1)
		hash_val = parts[0].strip()
		opt_val = parts[1].strip()

		if hash_val and opt_val:
			mappings[hash_val] = opt_val

	if not mappings:
		print("[-] No valid hashes provided by cmmc.exe. Exiting.")
		sys.exit(0)

	print(f"[*] Compiled {len(mappings)} mappings. Updating files in {target_dir}...")

	line_pattern = re.compile(r"^(\d+)(.*)", re.DOTALL)

	txt_files = list(target_dir.rglob("*.txt"))
	if not txt_files:
		print(f"[-] No .txt files found in {target_dir}.")
		sys.exit(1)

	updated_files_count = 0
	successful_mappings = set()

	for txt_file in txt_files:
		with open(txt_file, "r", encoding="utf-8", newline="") as f:
			lines = f.readlines()

		file_modified = False
		new_lines = []

		for line in lines:
			match = line_pattern.match(line)
			if match:
				line_hash = match.group(1)
				remainder = match.group(2)

				if line_hash in mappings:
					opt_val = mappings[line_hash]
					new_line = f"{opt_val}, {line_hash}{remainder}"
					new_lines.append(new_line)
					file_modified = True
					successful_mappings.add(opt_val)
					continue

			new_lines.append(line)

		if file_modified:
			with open(txt_file, "w", encoding="utf-8", newline="") as f:
				f.writelines(new_lines)
			updated_files_count += 1

	if successful_mappings:
		print(f"[*] The following {len(successful_mappings)} launch options resulted in mappings:")
		for opt in sorted(successful_mappings):
			print(f"{opt}")
	else:
		print("[-] None of the provided launch options resulted in mappings to the files.")

	print(f"[+] Finished. Updated {updated_files_count} files using {len(mappings)} mappings.")


def main():
	args = sys.argv[1:]
	if not args:
		print("Usage: python mc.py [-d <target_dir>] [-f <file> ...] [string1 string2 ...]")
		sys.exit(1)

	target_dir_arg = "./hashes"

	if "-d" in args:
		idx = args.index("-d")
		if idx + 1 < len(args):
			target_dir_arg = args[idx + 1]
			del args[idx : idx + 2]
		else:
			print("[-] Error: Missing directory path after -d.")
			sys.exit(1)

	cmmc_args = []

	i = 0
	while i < len(args):
		if args[i] == "-f":
			if i + 1 < len(args):
				input_file = args[i + 1]
				if not os.path.isfile(input_file):
					print(f"[-] Error: File '{input_file}' not found.")
					sys.exit(1)
				print(f"[*] Reading arguments from file: {input_file}")
				with open(input_file, "r", encoding="utf-8") as f:
					cmmc_args.extend(f.read().split())
				# Remove the -f flag and filename from args
				del args[i : i + 2]
			else:
				print("[-] Error: Missing file argument after -f.")
				sys.exit(1)
		else:
			i += 1

	cmmc_args.extend(args)

	if not cmmc_args:
		print("[-] Error: No cmmc arguments provided.")
		sys.exit(1)

	MAX_CHARS = 30000
	all_outputs = []
	current_batch = []
	current_length = 0

	print(f"[*] Processing {len(cmmc_args)} arguments in batches...")
	for arg in cmmc_args:
		if current_length + len(arg) + 1 > MAX_CHARS:
			all_outputs.append(run_cmmc(current_batch))
			current_batch = []
			current_length = 0

		current_batch.append(arg)
		current_length += len(arg) + 1

	if current_batch:
		all_outputs.append(run_cmmc(current_batch))

	combined_output = "\n".join(all_outputs)
	process_output(combined_output, target_dir_arg)


if __name__ == "__main__":
	main()
