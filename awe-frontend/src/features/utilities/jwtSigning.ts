export const jwtAlgorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'] as const
export type JwtAlgorithm = typeof jwtAlgorithms[number]

export function jsonObject(value: string, label: string): Record<string, unknown> {
  let parsed: unknown
  try { parsed = JSON.parse(value) } catch { throw new Error(`${label} must be valid JSON.`) }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(`${label} must be a JSON object.`)
  return parsed as Record<string, unknown>
}

function encode(value: Uint8Array) {
  let binary = ''
  value.forEach(byte => { binary += String.fromCharCode(byte) })
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export async function signJwt(headerText: string, payloadText: string, algorithm: JwtAlgorithm, material: string) {
  const header = { ...jsonObject(headerText, 'Header'), alg: algorithm }
  const payload = jsonObject(payloadText, 'Payload')
  if (!jwtAlgorithms.includes(algorithm)) throw new Error('Choose a supported signing algorithm.')
  if ('crit' in header || 'b64' in header || 'zip' in header) throw new Error('Critical extensions, unencoded payloads, and compression are not supported by this compact JWT signer.')
  if (!material.trim()) throw new Error(algorithm.startsWith('HS') ? 'Enter the HMAC signing secret.' : 'Enter a PKCS#8 private key PEM (BEGIN PRIVATE KEY).')
  if (!globalThis.crypto?.subtle) throw new Error('Signing requires HTTPS or localhost with browser cryptography enabled.')
  const hash = `SHA-${algorithm.slice(2)}`
  let key: CryptoKey
  let signing: AlgorithmIdentifier | RsaPssParams | EcdsaParams
  if (algorithm.startsWith('HS')) {
    key = await crypto.subtle.importKey('raw', new TextEncoder().encode(material), { name: 'HMAC', hash }, false, ['sign'])
    signing = 'HMAC'
  } else {
    const match = material.trim().match(/^-----BEGIN PRIVATE KEY-----\s*([A-Za-z0-9+/=\s]+)\s*-----END PRIVATE KEY-----$/)
    if (!match) throw new Error('Use an unencrypted PKCS#8 private key PEM (BEGIN PRIVATE KEY), not a public key or PKCS#1 key.')
    const isEc = algorithm.startsWith('ES')
    const name = isEc ? 'ECDSA' : algorithm.startsWith('PS') ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5'
    const curve = { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' }[algorithm as 'ES256' | 'ES384' | 'ES512']
    const parameters = isEc ? { name, namedCurve: curve } : { name, hash }
    try {
      const binary = atob(match[1].replace(/\s/g, ''))
      key = await crypto.subtle.importKey('pkcs8', Uint8Array.from(binary, char => char.charCodeAt(0)), parameters, false, ['sign'])
    } catch { throw new Error(`The private key could not be imported for ${algorithm}. Check its format and key type${isEc ? ` (${curve})` : ''}.`) }
    if (!isEc && (key.algorithm as RsaHashedKeyAlgorithm).modulusLength < 2048) throw new Error('RSA signing requires a key of at least 2048 bits.')
    signing = isEc ? { name, hash } : algorithm.startsWith('PS') ? { name, saltLength: Number(algorithm.slice(2)) / 8 } : name
  }
  const encoder = new TextEncoder()
  const input = `${encode(encoder.encode(JSON.stringify(header)))}.${encode(encoder.encode(JSON.stringify(payload)))}`
  const signature = await crypto.subtle.sign(signing, key, encoder.encode(input))
  return { token: `${input}.${encode(new Uint8Array(signature))}`, header: JSON.stringify(header, null, 2) }
}
