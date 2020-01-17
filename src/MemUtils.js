/** @see https://kripken.github.io/emscripten-site/docs/api_reference/preamble.js.html */

/** @typedef {number} int8 */
/** @typedef {number} uint8 */
/** @typedef {number} int16 */
/** @typedef {number} uint16 */
/** @typedef {number} int32 */
/** @typedef {number} uint32 */
/** @typedef {(number|string)} int64 */
/** @typedef {(number|string)} uint64 */

const Long = require('long')
const Module = require('./libsecp256k1')

/**
    @exports
*/
const Uint64Long = ptr => new Long(Module.getValue(ptr, 'i32'), Module.getValue(ptr + 4, 'i32'), true)

module.exports = {malloc, freeMalloc, intStar, charStar, charStarArray, Uint64Long}

/**
    @exports
*/
function intStar(num) {
    const ptr = malloc(4)
    Module.setValue(ptr, num, 'i32')
    return ptr
}

/**
    @exports
*/
function charStar(buf) {
    const ptr = malloc(buf.length)
    for(let i = 0; i < buf.length; i++) {
        Module.setValue(ptr + i, buf[i], 'i8')
    }
    return ptr
}

/**
    @exports
*/
function charStarArray(array) {
    const arrayPtrs = malloc(4 * array.length)
    for(let i = 0; i < array.length; i++) {
        const ptr = charStar(array[i])
        Module.setValue(arrayPtrs + (i * 4), ptr, 'i32')
    }
    return arrayPtrs
}

let free = []

/**
    Allocate emscripten memory and schedule to be garbage collected at the first
    possible opportunity.  If this memory pointer needs to be maintained across
    async calls, use Module._malloc and Module._free instead.

    @return emscripten memory pointer
    @exports
*/
function malloc(size) {
    const ptr = Module._malloc(size)
    free.push(ptr)
    return ptr
}

function freeMalloc() {
    for(const ptr of free) {
        Module._free(ptr)
    }
    free = []
}
