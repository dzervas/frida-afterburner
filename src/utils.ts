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

declare global {
	interface Process {
		filterSymbols(search: string): {[key: string]: NativePointer};
		findSymbol(search: string): SymbolNativePointer;
		getSymbol(search: string): SymbolNativePointer;
		getSymbolNativeFunctionAlt<RetType extends NativeFunctionReturnType, ArgTypes extends NativeFunctionArgumentType[] | []>(search: string, altSearch: string, ret: RetType, args: ArgTypes): NativeFunction<GetNativeFunctionReturnValue<RetType>, ResolveVariadic<Extract<GetNativeFunctionArgumentValue<ArgTypes>, unknown[]>>>;
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

declare global {
	interface NativePointer {
		attach(onEnter: ((this: InvocationContext, args: InvocationArguments) => void) | undefined | null, onLeave: ((this: InvocationContext, retval: InvocationReturnValue) => void) | undefined | null): InvocationListener;
		onEnter(onEnter: ((this: InvocationContext, args: InvocationArguments) => void) | undefined): InvocationListener;
		onLeave(onLeave: ((this: InvocationContext, retval: InvocationReturnValue) => void) | undefined): InvocationListener;
		trace(name: string): InvocationListener;
		replace(replacement: NativePointerValue): void;
		replaceCb<RetType extends NativeCallbackReturnType, ArgTypes extends NativeCallbackArgumentType[] | []>(callback: NativeCallbackImplementation<
			GetNativeCallbackReturnValue<RetType>,
			RecursiveValuesOf<NativeCallbackArgumentTypeMap>[]
		>, retType: RetType, argTypes: ArgTypes, abi?: NativeABI): void;
		revert(): void;
	}
}

Object.defineProperties(NativePointer.prototype, {
	attach: {
		enumerable: true,
		value: function (this: NativePointer, onEnter: ((this: InvocationContext, args: InvocationArguments) => void) | undefined | null, onLeave: ((this: InvocationContext, retval: InvocationReturnValue) => void) | undefined | null): InvocationListener {
			return Interceptor.attach(this, {
				onEnter: onEnter ? onEnter : undefined,
				onLeave: onLeave ? onLeave : undefined
			});
		}
	},
	// TODO: Give the ability to "chain" onEnter and onLeave like a builder with a "detach" method in the return value
	// TODO: Maybe define more events and give a generic "on" function that takes a string and a callback
	onEnter: {
		enumerable: true,
		value: function (this: NativePointer, onEnter: ((this: InvocationContext, args: InvocationArguments) => void) | undefined): InvocationListener { return this.attach(onEnter, null); }
	},
	onLeave: {
		enumerable: true,
		value: function (this: NativePointer, onLeave: ((this: InvocationContext, retval: InvocationReturnValue) => void) | undefined): InvocationListener { return this.attach(null, onLeave); }
	},
	// TODO: Add detach method that detaches only listeners of this function
	// TODO: Add "untrace" method
	trace: {
		enumerable: true,
		value: function (this: NativePointer, name: string) : InvocationListener {
			return this.attach(
				() => console.log(`[${new Date}] ===> ${name}`),
				(retval) => console.log(`[${new Date}] <=== ${name} -> ${retval}`)
			);
		}
	},
	replace: {
		enumerable: true,
		value: function (this: NativePointer, replacement: NativePointerValue): void { Interceptor.replace(this, replacement); }
	},
	replaceCb: {
		enumerable: true,
		value: function <RetType extends NativeCallbackReturnType, ArgTypes extends NativeCallbackArgumentType[] | []>(this: NativePointer, callback: NativeCallbackImplementation<
			GetNativeCallbackReturnValue<RetType>,
			RecursiveValuesOf<NativeCallbackArgumentTypeMap>[]
		>, retType: RetType, argTypes: ArgTypes, abi?: NativeABI): void { this.replace(new NativeCallback(callback, retType, argTypes, abi)); }
	},
	revert: {
		enumerable: true,
		value: function (this: NativePointer): void { Interceptor.revert(this); }
	},
});
