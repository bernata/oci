package main

type Repository struct {
	RepositoryList RepositoryList `cmd:"" name:"list" help:"List contents of repository"`
}

type RepositoryList struct {
	RepositoryName string `help:"Repository name to enumerate images" required:""`
}

func (r *RepositoryList) Run() error {
	return nil
}
