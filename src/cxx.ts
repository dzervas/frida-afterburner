// import { demangle } from "demangle";
import { Utils } from "./utils";

export class CXX {
	// public static demangle(name: string): string {
	// 	console.log("demangle", name);
	// 	return demangle(name);
	// }

	public static readStdString(address: NativePointer): string | null {
		let c_str = Utils.getSymbolNativeFunctionAlt("_ZNKSt7__cxx*basic_stringIcSt11char_traitsIcESaIcEE5c_strEv", "?c_str@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBADDXZ", "pointer", ["pointer"]);
		return c_str(address).readUtf8String();
	}

	public static readStdWString(address: NativePointer): string | null {
		let c_str = Utils.getSymbolNativeFunctionAlt("_ZNKSt7__cxx*basic_stringIcSt11char_traitsIwESaIcEE5c_strEv", "?c_str@?$basic_string@_WU?$char_traits@_WU@std@@V?$allocator@_W@2@@std@@QEBAPEB_WXZ", "pointer", ["pointer"]);
		return c_str(address).readUtf16String();
	}
}

Object.defineProperties(NativePointer.prototype, {
	"readStdString": {
		enumerable: true,
		value: function (this: NativePointer) { return CXX.readStdString(this); },
	},
	"readStdWString": {
		enumerable: true,
		value: function (this: NativePointer) { return CXX.readStdWString(this); },
	},
});
