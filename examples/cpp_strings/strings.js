/** @typedef {import('../../src/index.ts')} */
if (!global.AFTERBURNER) throw new Error("Afterburner is not loaded! Please check out https://github.com/dzervas/frida-afterburner");

Module.findExportByName(null, "_Z10ret_stringB5cxx11v").onLeave((retval) => {
	console.warn("std::string: " + retval.readStdString());
});

Module.findExportByName(null, "_Z11ret_bstringB5cxx11v").onLeave((retval) => {
	console.warn("std::string: " + retval.readStdString());
});

Module.findExportByName(null, "_Z11ret_wstringB5cxx11v").onLeave((retval) => {
	console.warn("std::string: " + retval.readStdWString());
});

Module.findExportByName(null, "_Z12ret_bwstringB5cxx11v").onLeave((retval) => {
	console.warn("std::string: " + retval.readStdWString());
});
