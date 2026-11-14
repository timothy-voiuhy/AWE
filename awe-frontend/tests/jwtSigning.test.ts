import { createHmac, generateKeyPairSync, verify, constants, webcrypto } from 'node:crypto'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { jwtAlgorithms, signJwt } from '../src/features/utilities/jwtSigning'

beforeAll(() => { vi.stubGlobal('crypto', webcrypto) })
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
const pem = (key: typeof rsa.privateKey) => key.export({ type: 'pkcs8', format: 'pem' }).toString()
const header = JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: 'test-key' })
const payload = JSON.stringify({ sub: '研究者', role: 'reader', exp: 2000000000 })

describe('compact JWT signing interoperates with independent Node verification', () => {
  for (const algorithm of jwtAlgorithms) it(algorithm, async () => {
    const ec = algorithm.startsWith('ES') ? generateKeyPairSync('ec', { namedCurve: { ES256: 'prime256v1', ES384: 'secp384r1', ES512: 'secp521r1' }[algorithm as 'ES256' | 'ES384' | 'ES512'] }) : null
    const material = algorithm.startsWith('HS') ? 'shared-secret-for-interoperability' : pem((ec || rsa).privateKey)
    const result = await signJwt(header, payload, algorithm, material)
    const parts = result.token.split('.')
    expect(parts).toHaveLength(3)
    expect(result.token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
    expect(JSON.parse(Buffer.from(parts[0], 'base64url').toString())).toEqual({ alg: algorithm, typ: 'JWT', kid: 'test-key' })
    expect(JSON.parse(Buffer.from(parts[1], 'base64url').toString())).toEqual(JSON.parse(payload))
    const input = `${parts[0]}.${parts[1]}`
    const hash = `sha${algorithm.slice(2)}`
    if (algorithm.startsWith('HS')) expect(parts[2]).toBe(createHmac(hash, material).update(input).digest('base64url'))
    else expect(verify(hash, Buffer.from(input), { key: (ec || rsa).publicKey, ...(ec ? { dsaEncoding: 'ieee-p1363' as const } : algorithm.startsWith('PS') ? { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: Number(algorithm.slice(2)) / 8 } : { padding: constants.RSA_PKCS1_PADDING }) }, Buffer.from(parts[2], 'base64url'))).toBe(true)
  })
})

it('rejects malformed or non-object JSON, missing material, extensions, and mismatched keys', async () => {
  await expect(signJwt('{', payload, 'HS256', 'secret')).rejects.toThrow('Header must be valid JSON')
  await expect(signJwt(header, '[]', 'HS256', 'secret')).rejects.toThrow('Payload must be a JSON object')
  await expect(signJwt('null', payload, 'HS256', 'secret')).rejects.toThrow('Header must be a JSON object')
  await expect(signJwt(header, payload, 'HS256', '')).rejects.toThrow('signing secret')
  await expect(signJwt('{"b64":false}', payload, 'HS256', 'secret')).rejects.toThrow('not supported')
  await expect(signJwt(header, payload, 'RS256', 'public key')).rejects.toThrow('PKCS#8')
  await expect(signJwt(header, payload, 'ES256', pem(rsa.privateKey))).rejects.toThrow('could not be imported')
})
