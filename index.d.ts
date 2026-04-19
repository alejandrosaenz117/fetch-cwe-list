// Type definitions for fetch-cwe-list

export interface ReferenceDetail {
  Reference_ID: string
  Author?: string
  Title?: string
  URL?: string
  URL_Date?: string
  Publication_Year?: number | string
}

export interface CWEReferences {
  Reference: { External_Reference_ID: string } | { External_Reference_ID: string }[]
  Full_Details: (ReferenceDetail | undefined)[]
}

export interface CWEHierarchyRelationship {
  nature: string
  cweId: string
  viewId: string
  ordinal?: string
}

export interface CWEHierarchy {
  parents: string[]
  relationships: CWEHierarchyRelationship[]
}

export interface KnownCVE {
  id: string
  description: string
}

export interface CWEMappingNotes {
  Usage: 'Allowed' | 'Prohibited' | 'Discouraged' | string
  Rationale?: string
  Comments?: string
}

export interface CWEEntry {
  /**
   * CWE identifier as a string (e.g. "79").
   * fast-xml-parser returns this as a number; enrichReferences() normalizes
   * it to a string so the public API is consistent.
   */
  ID: string
  Name: string
  Abstraction: string
  Status: string
  Description: string
  Extended_Description?: string | object
  /** Present if CWE has external references. */
  References?: CWEReferences
  /** Present if CWE has Related_Weaknesses. Absent otherwise. */
  Hierarchy?: CWEHierarchy
  /** Always present after enrichment. Empty array if no CAPEC mappings. */
  CAPEC_IDs: string[]
  /** Always present after enrichment. Empty array if no CVE examples. */
  Known_CVEs: KnownCVE[]
  Mapping_Notes?: CWEMappingNotes
  Applicable_Platforms?: object
  Common_Consequences?: object
  Potential_Mitigations?: object
  Observed_Examples?: object
  Related_Weaknesses?: object
  Related_Attack_Patterns?: object
  [key: string]: unknown
}

export interface FetchOptions {
  /** Set to false to bypass the in-memory cache. Default: true */
  cache?: boolean
}

/**
 * Fetches and parses the CWE list from MITRE.
 * Results are cached in memory for 1 hour by default.
 *
 * @param version - CWE version string (e.g. '4.13') or omit for latest
 * @param opts    - Options
 */
declare function fetchCweList(version?: string, opts?: FetchOptions): Promise<CWEEntry[]>

/**
 * Clears the in-memory cache.
 * The cache instance itself is not exposed to prevent external poisoning.
 */
export function clearCache(): void

/** Find a single CWE by its string ID. */
export function findById(cweList: CWEEntry[], id: string): CWEEntry | undefined

/**
 * Find all CWEs whose name contains the given string (case-insensitive).
 * RegExp is excluded to prevent ReDoS.
 * @throws {TypeError} if pattern is not a string
 */
export function findByName(cweList: CWEEntry[], pattern: string): CWEEntry[]

/** Find all CWEs that map to a given CAPEC ID string. */
export function findByCapec(cweList: CWEEntry[], capecId: string): CWEEntry[]

export default fetchCweList
