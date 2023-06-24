export class Utils {
	public static filterExports(search: string): {[key: string]: NativePointer} {
		const resolver = new ApiResolver("module");
		const matches = resolver.enumerateMatches(`exports:*!${search}`);

		return Object.assign({}, ...matches.map(m => ({[m.name]: m.address})));
	}

	public static findExport(search: string): {name: string, address: NativePointer} {
		let unixSearchExports = this.filterExports(search);

		return {
			name: Object.keys(unixSearchExports)[0],
			address: Object.values(unixSearchExports)[0]
		};
	}

	public static getExport(search: string): {name: string, address: NativePointer} {
		let unixSearchExports = this.filterExports(search);


		if (Object.keys(unixSearchExports).length > 1) {
			throw new Error("Found more than one match for export " + search);
		}
		if (Object.keys(unixSearchExports).length < 1) {
			throw new Error("Could not find export " + search);
		}

		return {
			name: Object.keys(unixSearchExports)[0],
			address: Object.values(unixSearchExports)[0]
		};
	}

	public static getExportedNativeFunctionAlt<RetType extends NativeFunctionReturnType, ArgTypes extends NativeFunctionArgumentType[] | []>
		(search: string, altSearch: string, ret: RetType, args: ArgTypes):
		NativeFunction<
			GetNativeFunctionReturnValue<RetType>,
			ResolveVariadic<Extract<GetNativeFunctionArgumentValue<ArgTypes>, unknown[]>>
	> {
		let funcPtr: NativePointer;

		try {
			funcPtr = Utils.getExport(search).address;
		} catch (e) {
			try {
				funcPtr = Utils.getExport(altSearch).address;
			} catch (e) {
				throw new Error("Failed to resolve std::string::c_str().");
			}
		}

		return new NativeFunction(funcPtr, ret, args);
	}
}

Process["__proto__"]["filterExports"] = Utils.filterExports;
Process["__proto__"]["findExport"] = Utils.findExport;
Process["__proto__"]["getExport"] = Utils.getExport;
Process["__proto__"]["getExportedNativeFunctionAlt"] = Utils.getExportedNativeFunctionAlt;
