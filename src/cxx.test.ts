import { expect } from "chai";
import { CXX } from './cxx';
import "mocha";


describe("CXX Tests", () => {
	// it("should demangle GCC function names", () => {
	// 	expect(CXX.demangle("_Z3FooIidEvi")).equal("void Foo<int, double>(int)");
	// 	expect(CXX.demangle("_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv")).equal("std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::c_str() const");
	// });
	// it("should demangle LLVM function names", () => {
	// 	expect(CXX.demangle("_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv")).equal("std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::c_str() const");
	// });
	// it("should demangle MSVC function names", () => {
	// 	expect(CXX.demangle("?c_str@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBADDXZ")).equal("public: char __cdecl std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> >::c_str(char)const __ptr64");
	// });
});
