'use strict'

const multihash = require('multihashes')
const crypto = require('./crypto')

module.exports = Multihashing

function Multihashing (buf, func, length, callback) {
  if (typeof length === 'function') {
    callback = length
    length = undefined
  }

  Multihashing.digest(buf, func, length, (err, digest) => {
    if (err) {
      return callback(err)
    }

    callback(null, multihash.encode(digest, func, length))
  })
}

Multihashing.Buffer = Buffer // for browser things

// expose multihash itself, to avoid silly double requires.
Multihashing.multihash = multihash

Multihashing.digest = function (buf, func, length, callback) {
  if (typeof length === 'function') {
    callback = length
    length = undefined
  }

  if (!callback) {
    throw new Error('Missing callback')
  }

  let cb = callback
  if (length) {
    cb = (err, digest) => {
      if (err) {
        return callback(err)
      }

      callback(null, digest.slice(0, length))
    }
  }

  let hash
  try {
    hash = Multihashing.createHash(func)
  } catch (err) {
    return cb(err)
  }

  hash(buf, cb)
}

Multihashing.createHash = function (func) {
  func = multihash.coerceCode(func)
  if (!Multihashing.functions[func]) {
    throw new Error('multihash function ' + func + ' not yet supported')
  }

  return Multihashing.functions[func]
}

Multihashing.functions = {
  0x11: crypto.sha1,
  0x12: crypto.sha2256,
  0x13: crypto.sha2512,
  0x14: crypto.sha3
  // 0x40: blake2b, // not implemented yet
  // 0x41: blake2s, // not implemented yet
}
