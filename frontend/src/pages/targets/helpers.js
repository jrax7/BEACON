export function verificationMethodLabel(method) {
  if (method === 'dns') return 'DNS TXT record'
  if (method === 'file') return 'Verification file'
  return '—'
}
