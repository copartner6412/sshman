package sshman

import (
	"time"
)

type Certificate struct {
	ID				string		`json:"id"`
	Certificate 	[]byte		`json:"certificate"`
	PublicKey		[]byte		`json:"public_key"`
	RequesterID 	string		`json:"requester_id"`
	HostID 			string		`json:"host_id"`
	User			string		`json:"user"`
	ValidAfter		time.Time	`json:"valid_after"`
	ValidBefore		time.Time	`json:"valid_before"`
}

func LoadCertificates() error


func SaveCertificates() error

func AddCertificate() error

func DeleteCertificate()

func FindCertificates()

func IsRevoked(certificate Certificate, allRevocationEntriesByCertificateID map[string]RevocationEntry) bool {
	for _, 
}