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

		try:
			with open(path.expanduser("~/.fridarc.js"), "r") as f:
				contents = f.read()
				result = _append_script(result, contents, "~/.fridarc.js")
				self._print("Loaded \033[93m~/.fridarc.js\033[00m")
		except FileNotFoundError:
			pass

		try:
			contents = AFTERBURNER_SCRIPT
			if not contents or contents == '${AFTERBURNER_SCRIPT}':
				with open(path.abspath("dist/bundle.js"), "r") as f:
					contents = f.read()

			result = _append_script(result, contents, "/frida-afterburner.js")
			self._print("\033[91mAfterburner\033[00m \033[92menabled\033[00m")
		except FileNotFoundError:
			pass

		# print(result)
		return result

def main() -> None:
	app = FridaB()
	app.run()


if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		pass
