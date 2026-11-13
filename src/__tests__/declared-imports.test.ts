import { readFileSync, readdirSync, statSync } from 'node:fs'
import { builtinModules } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

// An image installs from package.json, not from what happens to sit in a developer's node_modules:
// every package the sources import must be declared (any section) in this package's own package.json.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as Record<string, Record<string, string> | string>
const declared = new Set(['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'].flatMap((k) => Object.keys((pkg[k] as Record<string, string>) ?? {})))
const builtins = new Set(builtinModules.flatMap((m) => [m, m.replace(/^node:/, '')]))

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f)
    return statSync(p).isDirectory() ? (f === 'node_modules' ? [] : files(p)) : /\.(ts|tsx|mjs|js)$/.test(f) ? [p] : []
  })
}

describe('every imported package is declared in package.json', () => {
  it('no source file imports a package this one does not declare', () => {
    const missing: string[] = []
    for (const file of files(join(root, 'src'))) {
      const text = readFileSync(file, 'utf8')
      for (const m of text.matchAll(/(?:^|\n)\s*(?:import|export)\s[^'"\n;]*?\sfrom\s+['"]([^'"]+)['"]|(?:^|\n)\s*import\s+['"]([^'"]+)['"]|\bimport\(\s*['"]([^'"]+)['"]\s*\)/g)) {
        const spec = m[1] ?? m[2] ?? m[3]!
        if (spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:')) continue
        const name = spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0]!
        if (builtins.has(name) || declared.has(name) || name === pkg['name']) continue
        missing.push(`${file.slice(root.length + 1)} imports ${name}`)
      }
    }
    expect(missing).toEqual([])
  })
})
