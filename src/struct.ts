// Struct constructor type
export type StructCtor<O> = { new(): O; };

// Possible types of the struct fields - primitive, not sub-stracts and/or arrays
export interface Field {
	pointer: NativePointer,
	u8: number,
	i8: number,
	u16: number,
	i16: number,
	u32: number,
	i32: number,
	u64: bigint,
	i64: bigint,
	float: number,
	double: bigint,
	// function: NativeFunction,
};
// Size of each datatype
export const FieldTypeSize: { [K in keyof Field]: number } = {
	pointer: Process.pointerSize,
	u8: 1,
	i8: 1,
	u16: 2,
	i16: 2,
	u32: 4,
	i32: 4,
	u64: 8,
	i64: 8,
	float: 4,
	double: 8,
	// function: Process.pointerSize,
	// nativefunction: Process.pointerSize,
	// bytearray: Process.pointerSize,
};
// Type of the fields of the struct - primitive, sub-structs and arrays
export type NestedField = keyof Field | (keyof Field)[] | StructCtor<any> | StructCtor<any>[];
// Actual type of a struct schema { whatever: <NestedField> }
export type StructSchema<T> = Record<keyof T, NestedField>;

// Internal definition of a field - its name, type and offset
export interface FieldDef {
	type: NestedField;
	name: string;
	offset: number;
}

export interface StructI<T extends StructSchema<T>> {
	readonly fields: FieldDef[];
	read(address: NativePointer): void;
	write(address: NativePointer): void;
	dump(address: NativePointer): ArrayBuffer | null;
	get length(): number;
	toString(): string;
}

export class Struct<T extends StructSchema<T>> implements StructI<T> {

	public readonly fields: FieldDef[];
	// public static Schema: StructFieldsType<any> = {};

	constructor(config: T, offset: number = 0) {
		let schema: FieldDef[] = [];
		let currentOffset = offset;

		for (const field in config) {
			const fieldType = config[field];
			if (fieldType instanceof Struct) {
				currentOffset += fieldType.length;
			// } else if (Array.isArray(fieldType) && (fieldType).every(value => value instanceof Struct)) {
			// 	currentOffset += (fieldType).reduce((total, nestedStruct) => total + nestedStruct.length, 0);
			// } else if (Array.isArray(fieldType) && (fieldType).every(value => value keyof Type)) {
			// 	currentOffset += (fieldType).reduce((total, nestedStruct) => total + nestedStruct.length, 0);
			} else {
				currentOffset += FieldTypeSize[fieldType as keyof Field];
			}

			schema.push({ type: fieldType, name: field, offset: offset });
		}

		this.fields = schema;
	}

	// public static new<T extends StructFields<T>>(): Struct<T> {
	// 	const instance = new Struct<T>();
	// 	const structPtr = Memory.alloc(instance.length);

	// 	const fieldDefinitions = Struct.FieldDefinitions;
	// 	for (const field of fieldDefinitions) {
	// 		const fieldName = field.name;
	// 		const fieldValue = instance[fieldName];
	// 		const fieldType = field.type;

	// 		if (fieldType instanceof Struct) {
	// 			instance[fieldName] = new (fieldType as Struct<any>)();
	// 		} else if (Array.isArray(fieldType) && fieldType.every(value => value instanceof Struct)) {
	// 			instance[fieldName] = fieldType.map(value => new value());
	// 		} else {
	// 			instance[fieldName] = fieldValue;
	// 		}
	// 	}

	// 	instance.write(structPtr);
	// 	return instance;
	// }



	public read(address: NativePointer): void {
		for (const field in this.fields) {
			const fieldDef = this.fields[field];
			const fieldType = fieldDef!.type;
			const fieldOffset = fieldDef!.offset;

			if (fieldType instanceof Struct) {
				this[field] = (fieldType as Struct<any>).read(address.add(fieldOffset))
			} else if (Array.isArray(fieldDef) && fieldDef.every(value => value instanceof Struct)) {
				for (const nestedStruct of fieldDef) {
					nestedStruct.write(address.add(fieldOffset));
				}
			} else {
				const fieldTypeCaps = field.charAt(0).toUpperCase() + field.slice(1);
				const readFunc = `read${fieldTypeCaps}`;
				this[field] = address.add(fieldOffset)[readFunc]();
			}
		}
	}

	public write(address: NativePointer): void {
		for (const field of this.fields) {
			const fieldName = field.name;
			const fieldValue = this[fieldName];
			const fieldType = field.type;

			if (fieldType instanceof Struct) {
				const nestedStruct = fieldValue as Struct<any>;
				nestedStruct.write(address.add(field.offset));
			} else if (Array.isArray(fieldValue) && fieldValue.every(value => value instanceof Struct)) {
				for (const nestedStruct of fieldValue) {
					nestedStruct.write(address.add(field.offset));
				}
			} else {
				const fieldTypeCaps = (fieldType as keyof Field).charAt(0).toUpperCase() + (fieldType as keyof Field).slice(1);
				const writeFunc = `write${fieldTypeCaps}`;
				this[field.name] = address.add(field.offset)[writeFunc](fieldValue);
			}
		}
	}

	public dump(address: NativePointer): ArrayBuffer | null {
		return address.readByteArray(this.length);
	}

	public get length(): number {
		const lastFieldDef = this.fields[this.fields.length - 1];

		if (lastFieldDef.type instanceof Struct) {
			return lastFieldDef.offset + lastFieldDef.type.length;
		// } else if (Array.isArray(lastFieldDef.type) && lastFieldDef.type.every(value => value instanceof Struct)) {
		// 	let totalLength = 0;

		// 	for (const nestedStruct of lastFieldDef.type) {
		// 		totalLength += nestedStruct.length;
		// 	}

		// 	return lastFieldDef.offset + totalLength;
		} else {
			return lastFieldDef.offset + FieldTypeSize[lastFieldDef.type as keyof Field];
		}
	}

	public toString(): string {
		let structString = typeof this + ':\n';

		for (const fieldDef of this.fields) {
			const fieldName = fieldDef.name;
			const fieldValue = this[fieldName];
			const fieldType = fieldDef.type;

			if (fieldType instanceof Struct) {
				structString += `\t${fieldName}: ${typeof fieldValue} {\n${fieldValue.toString().split('\n').map(line => `\t\t${line}`).join('\n')}\t}\n`;
			} else {
				structString += `\t${fieldName}: ${fieldValue} (${fieldType.toString()})\n`;
			}
		}

		return structString;
	}
}

// Utility to get the actual type of an array
type Flatten<T> = T extends any[] ? T[number] : T;
// The type returned by defineStruct constructor - it contains the fields and the methods of Struct
type StructSchemaTyped<T extends StructSchema<T>> = (
	{ [K in keyof T]?: unknown } & // allow unknown fields
	{ [K in keyof T as T[K] extends keyof Field ? K : never]: Field[T[K]] } & // case of `hello: 'u32'`
	{ [K in keyof T as T[K] extends (keyof Field)[] ? K : never]: Field[Flatten<T[K]>][] } & // case of `hello: ['u32']`
	{ [K in keyof T as T[K] extends StructCtor<any> ? K : never]: T[K] extends StructCtor<infer O> ? O : never } & // case of `hello: Struct.define({ ... })`
	{ [K in keyof T as T[K] extends StructCtor<any>[] ? K : never]: T[K] extends StructCtor<infer O>[] ? O[] : never } // case of `hello: [Struct.define({ ... })]`
) extends infer O ? (
	{ [K in keyof O]: O[K] } & // passthrough the above
	{ [K in keyof StructI<T>]: StructI<T>[K] } // Add the methods of Struct
) : never;

// Define a struct that has the fields of the `schema` and the methods of Struct
export function defineStruct<T extends StructSchema<T>>(schema: T) {
	class res extends Struct<T> {
		constructor() {
			super(schema);
			Object.entries(schema).forEach(([k, v]: [string, any]) => {
				// TODO: This shouldn't work
				// TODO: Handle arrays
				// TODO: Should we alloc here?
				if (typeof v === typeof Struct<T>)
					(this as any)[k] = new v();
			});
		}
	};

	return res as StructCtor<StructSchemaTyped<T>>;
}
