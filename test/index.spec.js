/* eslint-env mocha */
'use strict'

const chai = require('chai')
const dirtyChai = require('dirty-chai')
chai.use(dirtyChai)
const expect = chai.expect
const multihashing = require('../src')

const tests = {
  sha1: [
    ['beep boop', '11147c8357577f51d4f0a8d393aa1aaafb28863d9421']
  ],
  'sha2-256': [
    ['beep boop', '122090ea688e275d580567325032492b597bc77221c62493e76330b85ddda191ef7c']
  ],
  'sha2-512': [
    ['beep boop', '134014f301f31be243f34c5668937883771fa381002f1aaa5f31b3f78e500b66ff2f4f8ea5e3c9f5a61bd073e2452c480484b02e030fb239315a2577f7ae156af177']
  ],
  'blake2b-512': [
    ['beep boop', 'c0e402400eac6255ba822373a0948122b8d295008419a8ab27842ee0d70eca39855621463c03ec75ac3610aacfdff89fa989d8d61fc00450148f289eb5b12ad1a954f659']
  ],
  'blake2b-160': [
    ['beep boop', '94e40214fe303247293e54e0a7ea48f9408ca68b36b08442']
  ],
  'blake2s-256': [
    ['beep boop', 'e0e402204542eaca484e4311def8af74b546edd7fceb49eeb3cdcfd8a4a72ed0dc81d4c0']
  ],
  'blake2s-40': [
    ['beep boop', 'c5e402059ada01bb57']
  ],
  'sha3-512': [
    ['beep bop', '144038122bf54c0e1eeff013e9b8c735af7c08ff8a7bb2b55b5abe9d97f9653e19f388cd9719ffb4ab8ccb9330a1fd27929b0a9ee6d7b8b9884c6f787f11088219bc']
  ],
  'sha3-384': [
    ['beep bop', '15302f0456d702d4cafa23c091f8da2dc878b1536fd592c47c2d239f5de67f0a306f36e0197dbbf1c5409292aa92e326b16e']
  ],
  'sha3-256': [
    ['beep bop', '16204de761fac0b163270f59056e1c5d1038348fcb960c03610bde24565473600dfe']
  ],
  'sha3-224': [
    ['beep bop', '171cda7cce25c2f6248dc88a2fdfca56bb97bf39b100089cacfdf68b7b50']
  ],
  'shake-128': [
    ['beep boop', '18205fe422311f770743c2e0d86bcca092111cbce85487212829739c3c3723776e5a']
  ],
  'shake-256': [
    ['beep boop', '194059feb5565e4f924baef74708649fed376d63948a862322ed763ecf093b63b38b0955908c099c63dda73ee469c31b1456cec95e325bd868d0ce0c0135f5a54411']
  ],
  'keccak-224': [
    ['beep bop', '1a1c45f2663794752c0a2292985b476a6aec407cfd78ad6f14f56d7060d9']
  ],
  'keccak-256': [
    ['beep bop', '1b209e7c2fee63c4065cbaa989bd2655a288f877aa788484fb0640d125417796b5e9']
  ],
  'keccak-384': [
    ['beep bop', '1c305a1da4b6e329884e88b66d82961d6518d9cec66eae6ff6900344a30a742a044b6eb584ab6e8a1c609e04f2f235f5cab3']
  ],
  'keccak-512': [
    ['beep bop', '1d403c22f68c98a6c8ea9fa7819721fba90f905d3c29390d4a94fefc4f8348ed04829a7521b44af4aeea707b32fe63e28322666ae26a59feb3493fafa11873383f6c']
  ]
}

describe('multihashing', () => {
  for (const algo in tests) {
    it(algo, () => {
      for (const test of tests[algo]) {
        const input = Buffer.from(test[0])
        const output = Buffer.from(test[1], 'hex')
        expect(multihashing(input, algo)).to.be.eql(output)
        expect(multihashing.verify(output, input)).to.be.eql(true)
      }
    })

    it(algo + ' stream', () => {
      for (const test of tests[algo]) {
        const input = Buffer.from(test[0])
        const output = Buffer.from(test[1], 'hex')
        const slices = test[0].split('').map(Buffer.from)
        const h = multihashing.createHash(algo)
        slices.forEach(h.update)
        expect(multihashing.verify(h.digest(), input)).to.be.eql(true)
      }
    })
  }

  it('cuts the length', () => {
    const buf = Buffer.from('beep boop')

    expect(
      multihashing(buf, 'sha2-256', 10)
    ).to.be.eql(
      Buffer.from('120a90ea688e275d58056732', 'hex')
    )
  })

  it('throws on non implemented func', () => {
    expect(
      () => multihashing(Buffer.from('beep boop'), 'sha3')
    ).to.throw(
      /Unrecognized hash function named:/
    )
  })
})
