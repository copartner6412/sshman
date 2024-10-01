package sshman

type requester struct{
	username	string
	publicKey	[]byte
}

func SaveAuthorizedRequesters(authorizedRequestersFilePath string, requesters []*requester) error {

}

func LoadAuthorizedRequesters(authorizedRequestersFilePath string) ([]*requester, error) {

}