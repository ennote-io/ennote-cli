package onepassword

// SupportsVaultFilter reports true: a 1PUX export groups items into named
// vaults, so --vault selects a subset.
func (p *PUXImporter) SupportsVaultFilter() bool {
	return true
}

// SupportsVaultFilter reports false: 1Password CSV exports carry no vault or
// folder column, so a requested filter cannot be honored.
func (p *CSVImporter) SupportsVaultFilter() bool {
	return false
}
