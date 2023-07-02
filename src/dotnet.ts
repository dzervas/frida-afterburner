const CLRHost = {
	bindToRuntime: function () {
		const kernel32 = Process.getModuleByName('kernel32.dll');
		const kernel32_loadlibraryw = Module.getExportByName("kernel32.dll", 'LoadLibraryW');
		const loadLibraryW = new NativeFunction(kernel32_loadlibraryw, 'pointer', ['pointer']);

		const mscoreePath = Memory.allocUtf16String('mscoree.dll');
		const mscoreeModule = loadLibraryW(mscoreePath);

		const corBindToRuntimeEx = Module.getExportByName("mscoree.dll", 'CorBindToRuntimeEx');
		const clr = new NativeFunction(corBindToRuntimeEx, 'int', ['pointer', 'pointer', 'int', 'pointer', 'pointer', 'pointer']);

		const version = Memory.allocUtf16String('v4.0.30319'); // Replace with the desired CLR version
		const flavor = Memory.allocUtf16String('wks'); // Replace with the desired build flavor
		const startupFlags = 0; // Replace with any required startup flags

		// const CLSID_CLRRuntimeInfo = '{BD39D1D2-BA2F-486A-89B0-B4B0CB466891}';
		// const IID_ICLRRuntimeHost = '{90F1A06C-7712-4762-86B5-7A5EBA6BDB02}';
		// Define the CLSID and IID values as structs
		const CLSID_CLRRuntimeInfo = Memory.alloc(16);
		CLSID_CLRRuntimeInfo.add(0).writeU32(0xBD39D1D2);
		CLSID_CLRRuntimeInfo.add(4).writeU16(0xBA2F);
		CLSID_CLRRuntimeInfo.add(6).writeU16(0x486A);
		CLSID_CLRRuntimeInfo.add(8).writeU8(0x89);
		CLSID_CLRRuntimeInfo.add(9).writeU8(0xB0);
		CLSID_CLRRuntimeInfo.add(10).writeByteArray([0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91]);

		const IID_ICLRRuntimeHost = Memory.alloc(16);
		IID_ICLRRuntimeHost.add(0).writeU32(0x90F1A06C);
		IID_ICLRRuntimeHost.add(4).writeU16(0x7712);
		IID_ICLRRuntimeHost.add(6).writeU16(0x4762);
		IID_ICLRRuntimeHost.add(8).writeByteArray([0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02]);

		const clsid = Memory.alloc(Process.pointerSize);
		clsid.writePointer(CLSID_CLRRuntimeInfo);

		const iid = Memory.alloc(Process.pointerSize);
		iid.writePointer(IID_ICLRRuntimeHost);

		const ppv = Memory.alloc(Process.pointerSize);

		const result = clr(version, flavor, startupFlags, clsid, iid, ppv);
		if (result !== 0) {
		console.log('Failed to bind to CLR: ' + result.toString());
		return null;
		}

		return ppv.readPointer();
	},

	getInterface: function (runtimeHost, clsid, iid) {
		const getInterface = new NativeFunction(runtimeHost.add(Process.pointerSize * 2).readPointer(), 'int', ['pointer', 'pointer', 'pointer']);
		const ppv = Memory.alloc(Process.pointerSize);

		const result = getInterface(runtimeHost, clsid, ppv);
		if (result !== 0) {
		console.log('Failed to get CLR interface: ' + result.toString());
		return null;
		}

		return ppv.readPointer();
	},

	dumpCLRCode: function (clrRuntimeHost) {
		const getCLRAssemblyEnum = new NativeFunction(clrRuntimeHost.add(Process.pointerSize * 6).readPointer(), 'int', ['pointer', 'pointer']);
		const getNextCLRAssembly = new NativeFunction(clrRuntimeHost.add(Process.pointerSize * 7).readPointer(), 'int', ['pointer', 'pointer']);
		const getAssemblyPath = new NativeFunction(clrRuntimeHost.add(Process.pointerSize * 19).readPointer(), 'int', ['pointer', 'uint', 'pointer', 'pointer']);

		const assembliesPtr = Memory.alloc(Process.pointerSize);
		const result = getCLRAssemblyEnum(clrRuntimeHost, assembliesPtr);

		if (result !== 0) {
			console.log('Failed to get CLR assembly enumerator: ' + result.toString());
			return;
		}

		const assemblies = assembliesPtr.readPointer();
		const assemblyPtr = Memory.alloc(Process.pointerSize);

		while (getNextCLRAssembly(assemblies, assemblyPtr) === 0) {
			const assembly = assemblyPtr.readPointer();
			const pathSizePtr = Memory.alloc(4);
			const pathResult = getAssemblyPath(assembly, 0, pathSizePtr, ptr(0));

			if (pathResult === 0) {
				const pathSize = pathSizePtr.readUInt();
				const pathBuffer = Memory.alloc(pathSize);
				const finalPathResult = getAssemblyPath(assembly, pathSize, ptr(0), pathBuffer);

				if (finalPathResult === 0) {
					const assemblyPath = pathBuffer.readUtf16String();
					console.log('CLR Assembly Path: ' + assemblyPath);

					// Perform code dumping logic for the assembly
					// ...

					pathBuffer.dispose();
				}
			}

			Memory.free(pathSizePtr);
		}
	}
};

function DumpIT() {
	const runtimeHost = CLRHost.bindToRuntime();
	if (runtimeHost === null) console.error("Failed to bind to CLR");
	const clsid_CLRRuntimeHost = Memory.alloc(Process.pointerSize);
	const riid_ICLRRuntimeHost = Memory.alloc(Process.pointerSize);

	// GUIDs for CLRRuntimeHost interface
	clsid_CLRRuntimeHost.writeByteArray([0x94, 0xEA, 0x24, 0x23, 0x01, 0x63, 0xC6, 0x45, 0xB2, 0xA7, 0x27, 0x68, 0x59, 0x6C, 0x2C, 0x5F]);
	riid_ICLRRuntimeHost.writeByteArray([0xCB, 0x2F, 0x20, 0x31, 0xD0, 0x87, 0x6B, 0x87, 0xD2, 0x31, 0x6E, 0x49, 0x74, 0x51, 0x8F, 0x62]);

	const clrRuntimeHost = CLRHost.getInterface(runtimeHost, clsid_CLRRuntimeHost, riid_ICLRRuntimeHost);
	if (clrRuntimeHost !== null) {
		const clsid_CLRRuntimeHost = Memory.alloc(Process.pointerSize);
		const riid_ICLRRuntimeHost = Memory.alloc(Process.pointerSize);

		// GUIDs for CLRRuntimeHost interface
		clsid_CLRRuntimeHost.writeByteArray([0x94, 0xEA, 0x24, 0x23, 0x01, 0x63, 0xC6, 0x45, 0xB2, 0xA7, 0x27, 0x68, 0x59, 0x6C, 0x2C, 0x5F]);
		riid_ICLRRuntimeHost.writeByteArray([0xCB, 0x2F, 0x20, 0x31, 0xD0, 0x87, 0x6B, 0x87, 0xD2, 0x31, 0x6E, 0x49, 0x74, 0x51, 0x8F, 0x62]);

		const clrRuntimeHost = CLRHost.getInterface(runtimeHost, clsid_CLRRuntimeHost, riid_ICLRRuntimeHost);
		if (clrRuntimeHost !== null) {
			const start = new NativeFunction(clrRuntimeHost.add(Process.pointerSize * 10).readPointer(), 'int', ['pointer']);
			const result = start(clrRuntimeHost);


			if (result === 0) {
				console.log('CLR started successfully');
				CLRHost.dumpCLRCode(clrRuntimeHost);
			} else {
				console.log('Failed to start CLR: ' + result.toString());
			}
		}
	}
}
