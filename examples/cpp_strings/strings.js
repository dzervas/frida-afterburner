import { CXX } from "../../dist/cxx";

// const c_strAddr = Module.findExportByName(null, "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv");
// const wc_strAddr = Module.findExportByName(null, "_ZNKSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEE5c_strEv");

// const c_str = new NativeFunction(c_strAddr, "pointer", ["pointer"]);
// const wc_str = new NativeFunction(wc_strAddr, "pointer", ["pointer"]);

// console.log(JSON.stringify(Process.getModuleByName("main").enumerateExports()))
Interceptor.attach(Module.findExportByName(null, "_Z10ret_stringB5cxx11v"), {
	onLeave: function (retval) {
		// console.log("> ret_string: " + retval.rea);
		var str = c_str(retval).readStdString();
		console.log("std::string: " + str);
	}
});

Interceptor.attach(Module.findExportByName(null, "_Z11ret_bstringB5cxx11v"), {
	onLeave: function (retval) {
		var str = c_str(retval).readStdString();
		console.log("std::basic_string<char>: " + str);
	}
});

Interceptor.attach(Module.findExportByName(null, "_Z11ret_wstringB5cxx11v"), {
	onLeave: function (retval) {
		var str = wc_str(retval).readWStdString();
		console.log("std::wstring: " + str);
	}
});

Interceptor.attach(Module.findExportByName(null, "_Z12ret_bwstringB5cxx11v"), {
	onLeave: function (retval) {
		var str = wc_str(retval).readWStdString();
		console.log("std::basic_string<wchar_t>: " + str);
	}
});
