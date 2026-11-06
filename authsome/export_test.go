package authsome

// setPageSize lowers the page size for a test and returns the undo.
func setPageSize(n int) func() {
	old := pageSize
	pageSize = n
	return func() { pageSize = old }
}

// setMaxItems lowers the population cap for a test and returns the undo.
func setMaxItems(n int) func() {
	old := maxItems
	maxItems = n
	return func() { maxItems = old }
}
