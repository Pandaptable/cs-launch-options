import argparse
import os
import re
import subprocess
import sys


def run_bruteforce(executable_path, hashes, max_length):
	chunk_size = 64

	for i in range(0, len(hashes), chunk_size):
		chunk = hashes[i : i + chunk_size]
		cmd = [executable_path] + chunk

		batch_num = (i // chunk_size) + 1
		total_batches = (len(hashes) + chunk_size - 1) // chunk_size
		print("\n=======================================================")
		print(f"[*] Starting Batch {batch_num}/{total_batches} ({len(chunk)} hashes)")
		print("=======================================================\n")

		p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

		line_buffer = ""
		while True:
			char = p.stderr.read(1)

			if not char and p.poll() is not None:
				break

			if char:
				sys.stderr.write(char)
				sys.stderr.flush()

				if char == "\n" or char == "\r":
					if "--- Checking Length" in line_buffer:
						match = re.search(r"Checking Length (\d+)", line_buffer)
						if match:
							current_len = int(match.group(1))

							if current_len > max_length:
								print(f"\n\n[!] Max configured length ({max_length}) exceeded.")
								print("[!] Killing CUDA process directly...")

								p.kill()
								p.wait()

								break

					line_buffer = ""
				else:
					line_buffer += char

		if p.poll() is None:
			p.terminate()
			p.wait()

	print("\n[*] All batches completed.")


def main():
	parser = argparse.ArgumentParser(description="Monitor and manage CUDA hash bruteforcer.")
	parser.add_argument("-e", "--executable", required=True, help="Path to the compiled CUDA executable")
	parser.add_argument("-l", "--max-length", required=True, type=int, help="Maximum string length to bruteforce up to")

	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("-f", "--hash-file", help="Text file containing hashes (one per line)")
	group.add_argument("-H", "--hashes", nargs="+", help="List of hashes passed directly via command line")

	args = parser.parse_args()

	if not os.path.exists(args.executable):
		print(f"Error: Executable not found at {args.executable}")
		sys.exit(1)

	hash_list = []

	if args.hash_file:
		if not os.path.exists(args.hash_file):
			print(f"Error: Hash file not found at {args.hash_file}")
			sys.exit(1)
		with open(args.hash_file, "r") as f:
			hash_list = [line.strip() for line in f if line.strip()]
	else:
		hash_list = args.hashes

	if not hash_list:
		print("Error: No hashes provided.")
		sys.exit(1)

	run_bruteforce(args.executable, hash_list, args.max_length)


if __name__ == "__main__":
	main()
