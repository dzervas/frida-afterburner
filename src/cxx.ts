// import { demangle } from "demangle";
import { Utils } from "./utils";
import { defineStruct, } from "./struct";

export const TypeDescriptorStruct = defineStruct({
	pVFTable: 'pointer',
	spare: 'pointer',
	name: 'pointer',
});

export const PMDStruct = defineStruct({
	mdisp: 'i32',
	pdisp: 'i32',
	vdisp: 'i32',
});

export const CatchableTypeStruct = defineStruct({
	properties: 'u32',
	pType: TypeDescriptorStruct,
	thisDisplacement: PMDStruct,
	sizeOrOffset: 'i32',
	copyFunction: 'pointer',
});

export const CatchableTypeArrayStruct = defineStruct({
	nCatchableTypes: 'i32',
	catchableTypeArray: [CatchableTypeStruct],
});

export const ThrowInfoStruct = defineStruct({
	attributes: 'u32',
	pmfnUnwind: 'pointer',
	pForwardCompat: 'pointer',
	pCatchableTypeArray: CatchableTypeArrayStruct,
	// pThrowInfo: 'pointer',
});

export class CxxException {
	public address: NativePointer;
	public throwInfo: InstanceType<typeof ThrowInfoStruct>;

	constructor(address: NativePointer) {
		this.address = address;
		this.throwInfo = new ThrowInfoStruct();
	}

	get name(): string | null {
		this.throwInfo.read(this.address);
		return this.throwInfo.pCatchableTypeArray.catchableTypeArray[0].pType.name.readUtf8String();
	}

	public static getExceptionOffset(exception: NativePointer): number {
		let typeInfo = exception.readPointer();
		let typeInfoOffset = typeInfo.add(0xC).readU32();
		return typeInfoOffset;
	}

	public static getExceptionType(exception: NativePointer): NativePointer {
		let typeInfo = exception.readPointer();
		let typeInfoType = typeInfo.add(0x10).readPointer();
		return typeInfoType;
	}

	public static getExceptionTypeName(exception: NativePointer): string | null {
		let typeInfo = exception.readPointer();
		let typeInfoType = typeInfo.add(0x10).readPointer();
		let typeInfoTypeName = typeInfoType.add(0x8).readPointer().readUtf8String();
		return typeInfoTypeName;
	}

	public static getExceptionTypeOffset(exception: NativePointer): number {
		let typeInfo = exception.readPointer();
		let typeInfoType = typeInfo.add(0x10).readPointer();
		let typeInfoTypeOffset = typeInfoType.add(0xC).readU32();
		return typeInfoTypeOffset;
	}

	public static getExceptionTypeCopyFunction(exception: NativePointer): NativePointer {
		let typeInfo = exception.readPointer();
		let typeInfoType = typeInfo.add(0x10).readPointer();
		let typeInfoTypeCopyFunction = typeInfoType.add(0x14).readPointer();
		return typeInfoTypeCopyFunction;
	}

	public static getExceptionTypeDestructorFunction(exception: NativePointer): NativePointer {
		let typeInfo = exception.readPointer();
		let typeInfoType = typeInfo.add(0x10).readPointer();
		let typeInfoTypeDestructorFunction = typeInfoType.add(0x18).readPointer();
		return typeInfoTypeDestructorFunction;
	}

	public static getExceptionTypeProperties(exception: NativePointer): number {
		let typeInfo = exception.readPointer();
		let typeInfoType = typeInfo.add(0x10).readPointer();
		let typeInfoTypeProperties = typeInfoType.add(0x4).readU32();
		return typeInfoTypeProperties;
	}

	public static getExceptionTypeSize(exception: NativePointer): number {
		let typeInfo = exception.readPointer();
		let typeInfoType = typeInfo.add(0x10).readPointer();
		let typeInfoTypeSize = typeInfoType.add(0x10).readU32();
		return typeInfoTypeSize;
	}
}

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

	public static handleEcxeptions(callback: ((code: number, flags: number, nargs: number, args: NativePointer) => void)): InvocationListener {
		// let handler = new NativeCallback((code: number, flags: number, nargs: number, args: NativePointer) => {
		// 	callback(code, flags, nargs, args);
		// }, "void", ["int", "int", "int", "pointer"]);

		// let __cxa_begin_catch = Utils.getSymbolNativeFunctionAlt("__cxa_begin_catch", "?__cxa_begin_catch@@YAPAXXZ", "pointer", []);
		// let __cxa_end_catch = Utils.getSymbolNativeFunctionAlt("__cxa_end_catch", "?__cxa_end_catch@@YAXXZ", "void", []);
		// let __cxa_rethrow = Utils.getSymbolNativeFunctionAlt("__cxa_rethrow", "?__cxa_rethrow@@YAXXZ", "void", []);
		// let __cxa_throw = Utils.getSymbolNativeFunctionAlt("__cxa_throw", "?__cxa_throw@@YAXPEAX0PFPAX0@Z1@Z", "void", ["pointer", "pointer", "pointer", "pointer"]);

		// let listener = Interceptor.attach(__cxa_begin_catch, handler);
		// Interceptor.attach(__cxa_end_catch, () => {
		// 	listener.detach();
		// });
		// Interceptor.attach(__cxa_rethrow, () => {
		// 	listener.detach();
		// });
		let listener: InvocationListener;

		if (Process.platform === "windows") {
			let __CxxThrowException = Utils.getSymbolNativeFunctionAlt("__CxxThrowException", "?__CxxThrowException@@YAXPEAXPEAU__s__ThrowInfo@@@Z", "void", ["pointer", "pointer"]);
			let __CxxFrameHandler3 = Utils.getSymbolNativeFunctionAlt("__CxxFrameHandler3", "?__CxxFrameHandler3@@YAXPEAXPEAU_EXCEPTION_RECORD@@PEAU_OBJECT@@PEAU_CONTEXT@@@Z", "void", ["pointer", "pointer", "pointer", "pointer"]);
			let __CxxFrameHandler4 = Utils.getSymbolNativeFunctionAlt("__CxxFrameHandler4", "?__CxxFrameHandler4@@YAXPEAXPEAU_EXCEPTION_RECORD@@PEAU_OBJECT@@PEAU_CONTEXT@@PEAPEAU__s__ThrowInfo@@@Z", "void", ["pointer", "pointer", "pointer", "pointer", "pointer"]);

			listener = Interceptor.attach(__CxxThrowException, {
				onEnter: (args) => {
					let exception = args[0];
					let throwInfo = args[1];

					let throwInfoType = throwInfo.readPointer();
					let attributes = throwInfo.add(0x4).readU32();
					let pmfnUnwind = throwInfo.add(0x8).readPointer();
					let pForwardCompat = throwInfo.add(0xC).readPointer();
					let pCatchableTypeArray = throwInfo.add(0x10).readPointer();
					// let pThrowInfo = throwInfo.add(0x14).readPointer();

					let catchableTypeArray = pCatchableTypeArray.readPointer();
					let nCatchableTypes = pCatchableTypeArray.add(0x4).readU32();

					let catchableType = catchableTypeArray.readPointer();
					let properties = catchableType.add(0x4).readU32();
					let pType = catchableType.add(0x8).readPointer();
					let thisDisplacement = catchableType.add(0xC).readU32();
					let sizeOrOffset = catchableType.add(0x10).readU32();
					let copyFunction = catchableType.add(0x14).readPointer();
					let destructorFunction = catchableType.add(0x18).readPointer();
					// let pForwardCompat = catchableType.add(0x1C).readPointer();

					let type = pType.readPointer();
					let name = type.add(0x8).readPointer().readUtf8String();
					let offset = sizeOrOffset - thisDisplacement;

					console.log("throwInfoType", throwInfoType);
					console.log("attributes", attributes);
					console.log("pmfnUnwind", pmfnUnwind);
					console.log("pForwardCompat", pForwardCompat);
					console.log("pCatchableTypeArray", pCatchableTypeArray);
					console.log("catchableTypeArray", catchableTypeArray);
					console.log("nCatchableTypes", nCatchableTypes);

					console.log("catchableType", catchableType);
					console.log("properties", properties);
					console.log("pType", pType);
					console.log("type", type);
					console.log("name", name);
					console.log("offset", offset);

					console.log("copyFunction", copyFunction);
					console.log("destructorFunction", destructorFunction);
					console.log("pForwardCompat", pForwardCompat);

					// console.log("exception", exception);
					// console.log("throwInfo", throwInfo);
				},
				onLeave: (retval) => {
					// console.log("retval", retval);
				}
			});
		} else if (Process.platform === "linux" || Process.platform === "qnx" || Process.platform === "darwin") {
			let __cxa_throw = Utils.getSymbolNativeFunctionAlt("__cxa_throw", "?__cxa_throw@@YAXPEAX0PFPAX0@Z1@Z", "void", ["pointer", "pointer", "pointer", "pointer"]);
			let __cxa_begin_catch = Utils.getSymbolNativeFunctionAlt("__cxa_begin_catch", "?__cxa_begin_catch@@YAPAXXZ", "pointer", []);
			let __cxa_end_catch = Utils.getSymbolNativeFunctionAlt("__cxa_end_catch", "?__cxa_end_catch@@YAXXZ", "void", []);
			let __cxa_rethrow = Utils.getSymbolNativeFunctionAlt("__cxa_rethrow", "?__cxa_rethrow@@YAXXZ", "void", []);

			listener = Interceptor.attach(__cxa_throw, {
				onEnter: (args) => {
					let exception = args[0];
					let throwInfo = args[1];

					let throwInfoType = throwInfo.readPointer();
					let attributes = throwInfo.add(0x4).readU32();
					let pmfnUnwind = throwInfo.add(0x8).readPointer();
					let pForwardCompat = throwInfo.add(0xC).readPointer();
					let pCatchableTypeArray = throwInfo.add(0x10).readPointer();
					let pThrowInfo = throwInfo.add(0x14).readPointer();
					let catchableTypeArray = pCatchableTypeArray.readPointer();
					let nCatchableTypes = pCatchableTypeArray.add(0x4).readU32();

					let catchableType = catchableTypeArray.readPointer();
					let properties = catchableType.add(0x4).readU32();
					let pType = catchableType.add(0x8).readPointer();
					let thisDisplacement = catchableType.add(0xC).readU32();
					let sizeOrOffset = catchableType.add(0x10).readU32();
					let copyFunction = catchableType.add(0x14).readPointer();
					let type = pType.readPointer();
					let name = type.add(0x8).readPointer().readUtf8String();
					let offset = sizeOrOffset - thisDisplacement;

					console.log("throwInfoType", throwInfoType);
					console.log("attributes", attributes);
					console.log("pmfnUnwind", pmfnUnwind);
					console.log("pForwardCompat", pForwardCompat);
					console.log("pCatchableTypeArray", pCatchableTypeArray);
					console.log("catchableTypeArray", catchableTypeArray);
					console.log("nCatchableTypes", nCatchableTypes);

					console.log("catchableType", catchableType);
					console.log("properties", properties);
					console.log("pType", pType);
					console.log("type", type);
					console.log("name", name);
					console.log("offset", offset);

					console.log("copyFunction", copyFunction);

					// console.log("exception", exception);
					// console.log("throwInfo", throwInfo);
				},
				onLeave: (retval) => {
					// console.log("retval", retval);
				}
			});
		} else {
			throw new Error("Unsupported platform");
		}

		return listener;
	}

	// TODO: Handle OS X exceptions
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
