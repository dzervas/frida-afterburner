import { SymbolNativePointer } from "./symbol";

export class Utils {
	public static filterSymbols(search: string): {[key: string]: NativePointer} {
		const resolver = new ApiResolver("module");
		let matches: ApiResolverMatch[] = [];

		try {
			matches = resolver.enumerateMatches(`exports:*!${search}`);
		} catch (e) {
			matches = resolver.enumerateMatches(`imports:*!${search}`);
		}

		return Object.assign({}, ...matches.map(m => ({[m.name]: m.address})));
	}

	public static findSymbol(search: string): SymbolNativePointer {
		let unixSearchExports = this.filterSymbols(search);

		return new SymbolNativePointer(Object.values(unixSearchExports)[0], Object.keys(unixSearchExports)[0]);
	}

	public static getSymbol(search: string): SymbolNativePointer {
		let unixSearchExports = this.filterSymbols(search);


		if (Object.keys(unixSearchExports).length > 1) {
			throw new Error("Found more than one match for export " + search);
		}
		if (Object.keys(unixSearchExports).length < 1) {
			throw new Error("Could not find export " + search);
		}

		return new SymbolNativePointer(Object.values(unixSearchExports)[0], Object.keys(unixSearchExports)[0]);
	}

	public static getSymbolNativeFunctionAlt<RetType extends NativeFunctionReturnType, ArgTypes extends NativeFunctionArgumentType[] | []>
		(search: string, altSearch: string, ret: RetType, args: ArgTypes):
		NativeFunction<
			GetNativeFunctionReturnValue<RetType>,
			ResolveVariadic<Extract<GetNativeFunctionArgumentValue<ArgTypes>, unknown[]>>
	> {
		let funcPtr: SymbolNativePointer;

		try {
			funcPtr = Utils.getSymbol(search);
		} catch (e) {
			try {
				funcPtr = Utils.getSymbol(altSearch);
			} catch (e) {
				throw new Error(`Failed to resolve ${search} or ${altSearch}`);
			}
		}

		return funcPtr.getFunction(ret, args);
	}
}

Process["__proto__"]["filterSymbols"] = Utils.filterSymbols;
Process["__proto__"]["findSymbol"] = Utils.findSymbol;
Process["__proto__"]["getSymbol"] = Utils.getSymbol;
Process["__proto__"]["getSymbolNativeFunctionAlt"] = Utils.getSymbolNativeFunctionAlt;
NativePointer["__proto__"]["attach"] = function (this: NativePointer, onEnter: ((this: InvocationContext, args: InvocationArguments) => void) | undefined, onLeave: ((this: InvocationContext, retval: InvocationReturnValue) => void) | undefined) {
	return Interceptor.attach(this, {
		onEnter: onEnter,
		onLeave: onLeave
	});
};
NativeFunction["__proto__"]["attach"] = function <RetType extends NativeFunctionReturnType, ArgTypes extends NativeFunctionArgumentType[] | []>(this: NativeFunction<GetNativeFunctionReturnValue<RetType>, ResolveVariadic<Extract<GetNativeFunctionArgumentValue<ArgTypes>, unknown[]>>>, onEnter: ((this: InvocationContext, args: InvocationArguments) => void) | undefined, onLeave: ((this: InvocationContext, retval: InvocationReturnValue) => void) | undefined) {
	console.log("asdf")
	return Interceptor.attach(this, {
		onEnter: onEnter,
		onLeave: onLeave
	});
};
