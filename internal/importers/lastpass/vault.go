package lastpass

// SupportsVaultFilter reports true: the grouping column carries LastPass's
// folder hierarchy, so --vault can filter rows.
func (p *CSVImporter) SupportsVaultFilter() bool {
	return true
}
