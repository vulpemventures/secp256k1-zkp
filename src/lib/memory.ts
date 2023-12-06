import Long from 'long';

import { CModule } from './cmodule';

interface MemoryI {
  charStarToUint8(ptr: number, size: number): Uint8Array;
  malloc(size: number): number;
  charStar(buffer: Uint8Array): number;
  charStarArray(buffers: Uint8Array[]): number;
  longIntStarArray(values: Long[]): number;
  free(): void;
}

export default class Memory implements MemoryI {
  private toFree: number[] = [];

  constructor(private cModule: CModule) {}

  charStarToUint8(ptr: number, size: number): Uint8Array {
    return new Uint8Array(this.cModule.HEAPU8.subarray(ptr, ptr + size));
  }

  malloc(size: number): number {
    const ret = this.cModule._malloc(size);
    this.toFree.push(ret);
    return ret;
  }

  charStar(buffer: Uint8Array): number {
    const ptr = this.malloc(buffer.length);
    for (let i = 0; i < buffer.length; i++) {
      this.cModule.setValue(ptr + i, buffer[i], 'i8');
    }
    return ptr;
  }

  charStarArray(buffers: Uint8Array[]): number {
    const arrayPtrs = this.malloc(4 * buffers.length);
    for (let i = 0; i < buffers.length; i++) {
      const ptr = this.charStar(buffers[i]);
      this.cModule.setValue(arrayPtrs + i * 4, ptr, 'i32');
    }
    return arrayPtrs;
  }

  longIntStarArray(values: Long[]): number {
    const ptr = this.malloc(8 * values.length);
    for (let i = 0; i < values.length; i++) {
      this.cModule.setValue(ptr + i * 8, values[i].low, 'i32');
      this.cModule.setValue(ptr + i * 8 + 4, values[i].high, 'i32');
    }
    return ptr;
  }

  readUint64Long(pointer: number): Long {
    return new Long(
      this.cModule.getValue(pointer, 'i32'),
      this.cModule.getValue(pointer + 4, 'i32'),
      true
    );
  }

  uint64Long(value: Long): number {
    const pointer = this.malloc(8);
    this.cModule.setValue(pointer, value.low, 'i32');
    this.cModule.setValue(pointer + 4, value.high, 'i32');
    return pointer;
  }

  free(): void {
    this.toFree.forEach((ptr) => this.cModule._free(ptr));
    this.toFree = [];
  }
}
