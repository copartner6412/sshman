package sshman

type host struct {
	alias string
	users []string
	ipv4s []string
	ipv6s  []string
	domain []string
	hostname []string
	publicKeys [][]byte
}

func SaveAuthorizedHosts(authorizedHostsFilePath string, hosts []host) (error) {

}

func LoadAuthorizedHosts(authorizedHostsFilePath string) ([]host, error) {

}