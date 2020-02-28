const Long = require("long");
const Module = require("../src");

module.exports = {
  malloc,
  freeMalloc,
  intStar,
  charStar,
  charStarArray,
  longIntStarArray,
  Uint64Long
};

/**
 *  @exports
*/
function Uint64Long(ptr) {
  return new Long(Module.getValue(ptr, "i32"), Module.getValue(ptr + 4, "i32"), true);
}

/**
 *  @exports
*/
function intStar(num) {
  const ptr = malloc(4);
  Module.setValue(ptr, num, "i32");
  return ptr;
}

/**
 *  @exports
*/
function charStar(buf) {
  const ptr = malloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    Module.setValue(ptr + i, buf[i], "i8");
  }
  return ptr;
}

/**
 *  @exports
*/
function charStarArray(array) {
  const arrayPtrs = malloc(4 * array.length);
  for (let i = 0; i < array.length; i++) {
    const ptr = charStar(array[i]);
    Module.setValue(arrayPtrs + i * 4, ptr, "i32");
  }
  return arrayPtrs;
}

function longIntStarArray(array) {
  const ptr = malloc(8 * array.length);
  for (let i = 0; i < array.length; i++) {
    Module.setValue(ptr + i * 8, array[i].low, "i32");
    Module.setValue(ptr + i * 8 + 4, array[i].high, "i32");
  }
  return ptr;
}

let free = [];

/**
 *  @return emscripten memory pointer
 *  @exports
*/
function malloc(size) {
  const ptr = Module._malloc(size);
  free.push(ptr);
  return ptr;
}

/**
 *  @exports
*/
function freeMalloc() {
  for (const ptr of free) {
    Module._free(ptr);
  }
  free = [];
}
