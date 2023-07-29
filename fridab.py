#!/usr/bin/env python

from frida_tools.repl import REPLApplication
from os import path

__version__ = "0.1.0"
AFTERBURNER_SCRIPT = '${AFTERBURNER_SCRIPT}'

def _append_script(orig: str, script: str, name: str) -> str:
	return orig + "\n✄\n" + str(len(script)) + " " + name + "\n✄\n" + script

class FridaB(REPLApplication):
	def _create_repl_script(self) -> str:
		result = super()._create_repl_script()
		additional_scripts = ""

		# The rc gets appended AFTER the afterburner but BEFORE any user scripts
		try:
			with open(path.expanduser("~/.fridarc.js"), "r") as f:
				contents = f.read()
				additional_scripts = _append_script(additional_scripts, contents, "~/.fridarc.js")
				self._print("Loaded \033[93m~/.fridarc.js\033[00m")
		except FileNotFoundError:
			pass

		try:
			contents = AFTERBURNER_SCRIPT
			if not contents or contents == '${AFTERBURNER_SCRIPT}':
				with open(path.abspath("dist/bundle.js"), "r") as f:
					contents = f.read()

			additional_scripts = _append_script(additional_scripts, contents, "/frida-afterburner.js")
			self._print(f"\033[91mAfterburner\033[00m v{__version__} \033[92menabled\033[00m")
		except FileNotFoundError:
			pass

		repl_script_start = result.index("\n✄\n") + 3

		try:
			repl_script_end = result.index("\n✄\n", repl_script_start + 1)
			result = result[:repl_script_end] + additional_scripts + result[repl_script_end:]
		except ValueError:
			result += additional_scripts

		return result

def main() -> None:
	app = FridaB()
	app.run()


if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		pass
