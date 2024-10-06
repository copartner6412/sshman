package sshman

import "time"

type RevocationEntry struct {
	id             string
	Certificate_id []byte
	RevocationTime time.Time
}

func AddRevocationEntry(allEntries []RevocationEntry, entry RevocationEntry) ([]RevocationEntry, error) {

}

func DeleteRevocationEntry(allEntries []RevocationEntry, entry RevocationEntry) ([]RevocationEntry, error) {

}

func FindRevocationEntries(allEntries []RevocationEntry) {

}

func 
