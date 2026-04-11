/**
 * Type stubs for packages that don't ship their own @types.
 */

declare module "simple-wappalyzer" {
  interface WapCategory {
    id: number;
    slug: string;
    name: string;
    groups: number[];
    priority: number;
  }

  interface WapResult {
    name: string;
    description: string;
    slug: string;
    categories: WapCategory[];
    confidence: number;
    version: string;
    icon: string;
    website: string;
    pricing: string[];
    cpe: string;
  }

  interface WapInput {
    url: string;
    headers: Record<string, string>;
    html?: string;
    js?: Record<string, string>;
    css?: string;
    robots?: string;
    dns?: Record<string, string[]>;
    certIssuer?: string;
  }

  function wappalyzer(input: WapInput): Promise<WapResult[]>;
  export = wappalyzer;
}

declare module "murmurhash-js" {
  function murmur2(str: string, seed?: number): number;
  function murmur3(str: string, seed?: number): number;
  export { murmur2, murmur3 };
}
