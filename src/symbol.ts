export class SymbolNativeFunction<RetType extends NativeFunctionReturnType, ArgTypes extends NativeFunctionArgumentType[] | []> extends NativeFunction<RetType, ArgTypes> {
	public name: string = "";

	constructor(ptr: NativeFunction<GetNativeFunctionReturnValue<RetType>, ResolveVariadic<Extract<GetNativeFunctionArgumentValue<ArgTypes>, unknown[]>>>, name: string) {
		super(ptr);
		this.name = name;
	}

	public getFunction<RetType extends NativeFunctionReturnType, ArgTypes extends NativeFunctionArgumentType[] | []>
		(this, ret: RetType, args: ArgTypes):
		NativeFunction<
			GetNativeFunctionReturnValue<RetType>,
			ResolveVariadic<Extract<GetNativeFunctionArgumentValue<ArgTypes>, unknown[]>>
	> {
		return new NativeFunction(this, ret, args);
	}

	public trace(this): InvocationListener { return super.trace(this.name); }
}


export class SymbolNativePointer extends NativePointer {
	public name: string = "";

	constructor(ptr: NativePointer, name: string) {
		super(ptr);
		this.name = name;
	}

	public getFunction<RetType extends NativeFunctionReturnType, ArgTypes extends NativeFunctionArgumentType[] | []>
		(this, ret: RetType, args: ArgTypes):
		NativeFunction<
			GetNativeFunctionReturnValue<RetType>,
			ResolveVariadic<Extract<GetNativeFunctionArgumentValue<ArgTypes>, unknown[]>>
	> {
		return new NativeFunction(this, ret, args);
	}

	public trace(this): InvocationListener { return super.trace(this.name); }
}
