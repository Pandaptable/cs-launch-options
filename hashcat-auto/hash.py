import os
import subprocess
import sys

EXTRAS = ["--outfile-format", "2", "--quiet", "--keep-guessing", "--self-test-disable"]
output = []
cache = {}


def hashcat(cmd_args, h):
	exe_path = os.path.abspath(os.path.join("hashcat", "hashcat.exe"))

	try:
		p = subprocess.Popen(
			[exe_path] + cmd_args,
			stdout=subprocess.PIPE,
			stderr=subprocess.DEVNULL,
			cwd="hashcat",
			shell=False,
			text=True,
			encoding="utf-8",
			errors="replace",
		)

		found_line = None
		if p.stdout:
			for line in p.stdout:
				clean_line = line.strip()
				if not clean_line or clean_line.startswith("Failed"):
					continue
				found_line = f"{clean_line}, {h}"
				break

		p.wait()
		return found_line
	except FileNotFoundError:
		print(f"Error: Could not find {exe_path}")
		return None


def main():
	if not os.path.exists("hashes.txt"):
		print("Error: hashes.txt not found.")
		return
	with open("hashes.txt", "r") as f:
		for line in f:
			line = line.strip()
			if not line:
				continue

			if line.startswith("=") or "," in line:
				output.append(line)
				continue
			try:
				h = int(line.split(", ", 1)[-1].strip())
			except ValueError:
				output.append(line)
				continue
			if h in cache:
				found = cache[h]
				output.append(found if found else line)
				continue
			found = None
			prefixes = ["save_", "disable_", "enable_", "hide_", "show_", "ignore_", "valve_"]

			for prefix in prefixes:
				if found:
					break

				prependstring = f"-{prefix}"
				prepend_rule = "".join(f"^{c}" for c in prependstring[::-1])

				args = ["-m", "25700", "-a", "0", "-j", prepend_rule, f"{h:08x}:31415926", "word-list.txt"] + EXTRAS

				found = hashcat(args, h)
			if found:
				print(found)
				output.append(found)
			else:
				print(line)
				output.append(line)

			cache[h] = found
	with open("hashes2.txt", "w") as f:
		for line in output:
			f.write(line + "\n")


if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		sys.exit(0)
