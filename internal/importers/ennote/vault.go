package ennote

// SupportsVaultFilter reports false: the native Ennote CSV shape has no vault
// or folder column, so a requested filter cannot be honored.
func (p *CSVImporter) SupportsVaultFilter() bool {
	return false
}
