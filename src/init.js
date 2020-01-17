/** @module secp256k1 */

// emscripton re-assigns Module (use var)
var Module = {} // eslint-disable-line no-var

Module['initPromise'] = new Promise(resolve => {
    Module['onRuntimeInitialized'] = function() {
        resolve()
    }
})
