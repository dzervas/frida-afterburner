export class SymbolNativePointer extends NativePointer {
	public name: string = "";

	constructor(ptr: NativePointer, name: string) {
		super(ptr);
		this.name = name;
	}

	public attach(this, onEnter: ((this: InvocationContext, args: InvocationArguments) => void) | undefined, onLeave: ((this: InvocationContext, retval: InvocationReturnValue) => void) | undefined): InvocationListener {
		// let obj: InvocationListenerCallbacks | InstructionProbeCallback;

		return Interceptor.attach(this, {
			onEnter: onEnter ? onEnter : undefined,
			onLeave: onLeave ? onLeave : undefined
		});
	}

	public getFunction<RetType extends NativeFunctionReturnType, ArgTypes extends NativeFunctionArgumentType[] | []>
		(this, ret: RetType, args: ArgTypes):
		NativeFunction<
			GetNativeFunctionReturnValue<RetType>,
			ResolveVariadic<Extract<GetNativeFunctionArgumentValue<ArgTypes>, unknown[]>>
	> {
		return new NativeFunction(this, ret, args);
	}
}
