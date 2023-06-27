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

Object.defineProperties(Process, {
	"filterSymbols": {
		enumerable: true,
		value: function (this: typeof Process, search: string): {[key: string]: NativePointer} { return Utils.filterSymbols(search); }
	},
	"findSymbol": {
		enumerable: true,
		value: function (this: typeof Process, search: string): SymbolNativePointer { return Utils.findSymbol(search); }
	},
	"getSymbol": {
		enumerable: true,
		value: function (this: typeof Process, search: string): SymbolNativePointer { return Utils.getSymbol(search); }
	},
	"getSymbolNativeFunctionAlt": {
		enumerable: true,
		value: function <RetType extends NativeFunctionReturnType, ArgTypes extends NativeFunctionArgumentType[] | []>(this: typeof Process, search: string, altSearch: string, ret: RetType, args: ArgTypes): NativeFunction<GetNativeFunctionReturnValue<RetType>, ResolveVariadic<Extract<GetNativeFunctionArgumentValue<ArgTypes>, unknown[]>>> { return Utils.getSymbolNativeFunctionAlt(search, altSearch, ret, args); }
	}
});

Object.defineProperties(NativePointer.prototype, {
	"attach": {
		enumerable: true,
		value: function (this: NativePointer, onEnter: ((this: InvocationContext, args: InvocationArguments) => void) | undefined, onLeave: ((this: InvocationContext, retval: InvocationReturnValue) => void) | undefined): InvocationListener { return Interceptor.attach(this, { onEnter: onEnter, onLeave: onLeave }); }
	},
	"onEnter": {
		enumerable: true,
		value: function (this: NativePointer, onEnter: ((this: InvocationContext, args: InvocationArguments) => void) | undefined): InvocationListener { return Interceptor.attach(this, { onEnter: onEnter }); }
	},
	"onLeave": {
		enumerable: true,
		value: function (this: NativePointer, onLeave: ((this: InvocationContext, retval: InvocationReturnValue) => void) | undefined): InvocationListener { return Interceptor.attach(this, { onLeave: onLeave }); }
	},
	"replace": {
		enumerable: true,
		value: function (this: NativePointer, replacement: NativePointerValue): void { Interceptor.replace(this, replacement); }
	},
	"replaceCb": {
		enumerable: true,
		value: function <RetType extends NativeCallbackReturnType, ArgTypes extends NativeCallbackArgumentType[] | []>(this: NativePointer, callback: NativeCallbackImplementation<
			GetNativeCallbackReturnValue<RetType>,
			RecursiveValuesOf<NativeCallbackArgumentTypeMap>[]
		>, retType: RetType, argTypes: ArgTypes, abi?: NativeABI): void { Interceptor.replace(this, new NativeCallback(callback, retType, argTypes, abi)); }
	},
	"revert": {
		enumerable: true,
		value: function (this: NativePointer): void { Interceptor.revert(this); }
	},
});
